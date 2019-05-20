import glob
import re

class pktAnalyticsEngine:
    def __init__(self):
        self.all_protocols = {};
        self.protocols = {};
        protocol = ''
        match = ''
        flag = 0
        for filename in glob.glob('./pat_files/*.pat'):
            with open(filename) as f:
                for line in f:
                    if line[0] != '#' and line.strip() != '' and line.split(' ')[0] != 'userspace':
                        if flag == 0:
                            protocol = line.strip()
                            flag += 1
                        elif flag == 1:
                            match = line.strip()
                            self.all_protocols[protocol] = re.compile(match.encode('ascii'), re.I);
                            #self.all_protocols[protocol] = re.compile(match, re.I);
                            flag = 0
    def info(self, text):
        print('[pktAE] ' + text)

    def availableProtocols(self):
        return list(self.all_protocols.keys())

    def lookFor(self, protocol):
        if isinstance(protocol, list):
            for p in protocol:
                self.lookFor(p)
        else:
            if protocol in self.all_protocols.keys():
                self.protocols[protocol] = self.all_protocols[protocol]
                self.info('Added ' + protocol + ' to the watched protocols')
            else:
                self.info('Protocol [' + protocol + '] is not supported. Consider adding a .pat file to the db')

    def detectProtocol(self, pkt_payload):
        block = False;
        protocol = '';
        #pkt_payload = pkt_payload.decode('charmap')
        for p in self.protocols.keys():
            if self.protocols[p].match(pkt_payload):
                return {'blocked' : True, 'protocol' : p}
        return {'blocked' : False}


