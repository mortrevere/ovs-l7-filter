from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.topology import api

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, ofproto_v1_5
from ryu.lib.packet import ethernet, arp, packet, tcp, ipv4, in_proto, ether_types, packet
from ryu.utils import binary_str

from pktAnalyticsEngine import pktAnalyticsEngine
import hashlib

MISS_SEND_LENGTH = 200
BLOCK_IDLE_TIMEOUT = 30
SUPER_FAST_MODE = False

class FirewallSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def delete_flow(self, dp, table_id, match):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instructions = []
        flow_mod = parser.OFPFlowMod(dp, 0, 0, table_id, ofp.OFPFC_DELETE, 0, 0, 1, ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match, [])
        dp.send_msg(flow_mod)

    def fluxID(self, in_port, eth_dst, eth_src, eth_type, ip_proto = 0, tcp_dst = 0):
        el = [str(in_port), '/', eth_src, "<>", eth_dst, ":", str(tcp_dst), ",", str(ip_proto)]
        w = ''.join([c for c in el])
        return hashlib.md5(w.encode()).hexdigest()

    def getMatchAndFluxID(self, parser, in_port, eth_dst, eth_src, eth_type, ip_proto = 0, tcp_dst = 0):
        match_parameters = {'in_port' : in_port, 'eth_dst' : eth_dst, 'eth_src' : eth_src, 'eth_type' : eth_type, 'ip_proto' : ip_proto, 'tcp_dst' : tcp_dst}
        if tcp_dst == 0: del match_parameters['tcp_dst']
        if ip_proto == 0: del match_parameters['ip_proto']

        match = parser.OFPMatch(**match_parameters)
        flux_id = self.fluxID(in_port, eth_dst, eth_src, eth_type, ip_proto, tcp_dst)
        return match, flux_id

    def __init__(self, *args, **kwargs):
        super(FirewallSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flux = {}

        #TODO : move to config (REST, yaml ?)
        self.fastMode = True
        self.filtered_ports = ['all']
        self.blocked_ports = []
        self.unfiltered_ports = [22]

        self.pktAE = pktAnalyticsEngine();
        self.pktAE.lookFor('http')
        self.pktAE.lookFor('ftp')
        self.pktAE.lookFor('rar')
        self.pktAE.lookFor('ssh')

        #if SUPER_FAST_MODE: self.fastMode = False
        if self.fastMode: print('WARNING : fastMode is on, some packets may pass through')


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print('installing table-miss flows on switch #' + str(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.delete_flow(datapath, ofproto.OFPTT_ALL, parser.OFPMatch()) #delete all current flows
        #base rule is push to controller and resubmit to table 2
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if not SUPER_FAST_MODE: inst += [parser.OFPInstructionGotoTable(table_id=2)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=parser.OFPMatch(), instructions=inst, table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def datapath_change_handler(self, ev):
        if ev.enter: #new datapath registered to the controller
            datapath = ev.dp;
            parser = datapath.ofproto_parser
            print("switch #" + str(datapath.id) + " joined")
            switch = api.get_switch(self, datapath.id)[0]
            ports = switch.ports
            for port in ports:
                for p in self.blocked_ports:
                    block_match = parser.OFPMatch(in_port=int(port.port_no), eth_type=0x0800, ip_proto=6, tcp_dst=p)
                    self.add_flow(datapath,1,block_match, None, None, 0, None)
            miss_len_cfg = parser.OFPSetConfig(datapath, ofproto_v1_3.OFPC_FRAG_MASK,MISS_SEND_LENGTH)
            datapath.send_msg(miss_len_cfg)
            print("OK")


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id = 2, idle_timeout=60):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if SUPER_FAST_MODE and table_id == 2: table_id = 0

        if not actions: #drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else: #other kind of action
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod_parameters = {'datapath' : datapath,
                          'priority' : priority,
                          'match' : match,
                          'instructions' : inst,
                          'table_id' : table_id,
                          'idle_timeout' : idle_timeout,
                          'command' : ofproto.OFPFC_ADD,
                          'flags' : ofproto.OFPFF_SEND_FLOW_REM}

        if buffer_id: mod_parameters['buffer_id'] = buffer_id
        if idle_timeout is None: del mod_parameters['idle_timeout']

        mod = parser.OFPFlowMod(**mod_parameters)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #if ev.msg.msg_len < ev.msg.total_len:
        #    print("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        eth_type = eth.ethertype;
        dest_tcp_port = 0
        source_tcp_port = 0
        passed = True
        hasData = False
        protocols = [] #list of protocols encapsulated in the packet

        #list protocols inside packet and check if it has a payload
        for p in pkt.protocols:
            if not isinstance(p, (bytes, bytearray)):
                if p.protocol_name:
                    if p.protocol_name == 'ipv4':
                        ip_proto = p.proto
                    protocols.append(p.protocol_name);
            else: hasData = True

       	if 'tcp' in protocols: #packet has tcp
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            #determine if it should be analyzed based on port numbers
            dest_tcp_port = pkt_tcp.dst_port
            source_tcp_port = pkt_tcp.src_port
            passed = (dest_tcp_port not in self.filtered_ports)
            if 'all' in self.filtered_ports:
                passed = False
            if dest_tcp_port in self.blocked_ports:
                #this should not happen ever because flows handle it
                return
        else: passed = True #allow all non-tcp packets

        #pass the firewall if one of the tcp port is unfiltered or if the packet has no payload
        passed = passed or (source_tcp_port in self.unfiltered_ports) or (dest_tcp_port in self.unfiltered_ports) or not hasData

        #if we got there, analyze the packet payload
        if not passed and 'tcp' in protocols and hasData:
            pktdata = pkt.protocols[-1]
            AE = self.pktAE.detectProtocol(pktdata)
            if not AE['blocked']:
                passed = True

        #packet failed to be accepted, we install flows to block it
        if not passed:
            print("blocked", AE['protocol'], str(source_tcp_port) + '-->' + str(dest_tcp_port), ':', "|||--- ", protocols, ip_proto, eth_type, in_port, eth.src)
            #install drop rules in table 0 with higher priority than the base rule [controller, resubmit(,2)]
            #so every blocked flux is handled by the switch and we stop getting packet_in
            block_match = parser.OFPMatch(in_port=in_port,
                                          eth_src=eth.src,
                                          eth_dst=eth.dst,
                                          eth_type=eth.ethertype,
                                          ip_proto=ip_proto,
                                          tcp_dst=dest_tcp_port)

            self.add_flow(datapath, 12, block_match, None, None, 0, idle_timeout=BLOCK_IDLE_TIMEOUT)
            #if we know what in_port will handle the response (via the CAM table) we can block the returning flux
            if dpid in self.mac_to_port.keys() and eth.dst in self.mac_to_port[dpid].keys():
                block_match = parser.OFPMatch(in_port=self.mac_to_port[dpid][eth.dst],
                                              eth_src=eth.dst,
                                              eth_dst=eth.src,
                                              eth_type=eth.ethertype,
                                              ip_proto=ip_proto,
                                              tcp_dst=source_tcp_port)
                self.add_flow(datapath, 12, block_match, None, None, 0, idle_timeout=2*BLOCK_IDLE_TIMEOUT)
            return

        #CAM table learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid][eth.dst] if eth.dst in self.mac_to_port[dpid] else ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        if not passed:
            return

        if out_port != ofproto.OFPP_FLOOD:
            #create OFPMatch instance and fluxID depending on protocols used
            parameters = [parser, in_port, eth.dst, eth.src, eth.ethertype]
            if 'ipv4' in protocols and 'tcp' in protocols:
                parameters += [6, dest_tcp_port]
            elif 'ipv4' in protocols and 'icmp' in protocols:
                parameters += [1]
            match, flux_id = self.getMatchAndFluxID(*parameters)

            #throw the packet away if its already being handled by the switch
            if flux_id in self.flux.keys():
                return

            if not self.fastMode and 'tcp' in protocols and not hasData:
                #let tcp handshakes go trough the controller
                #and wait for the first packet with a payload to allow the route
                pass
            else:
                #push flow to switch and save its id
                #so that we can recompute its id anytime we get another packet_in
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    self.flux[flux_id] = match;
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
                    self.flux[flux_id] = match;

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        '''
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        '''

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            #drop flows have timeout to not block the route indefinitely
            #deleting the fluxID from self.flux allows us to check them again for blocked protocols
            m = msg.match
            tcp_dst = m['tcp_dst'] if 'tcp_dst' in m else 0
            ip_proto = m['ip_proto'] if 'ip_proto' in m else 0
            flux_id = self.fluxID(m['in_port'], m['eth_dst'], m['eth_src'], m['eth_type'], ip_proto, tcp_dst)
            if flux_id in self.flux.keys():
                del self.flux[flux_id]
            else:
                print('WARNING : Orphaned OFPFlowRemoved : ', flux_id)
