# ovs-l7-filter

This is an OpenFlow controller, built using [Ryu](https://osrg.github.io/ryu/). It works with [Open vSwitch](https://www.openvswitch.org/) but could work with any switch supporting OpenFlow 1.3.

This controller implements layer 7 (application) filtering on any switch that references it as its controller. Protocol detection is based on a regex engine and the existing [l7-filter protocol files](http://l7-filter.sourceforge.net/protocols/)

# Use cases

Block *any application* protocol on *any port*, like OpenVPN, SSH, HTTP, FTP ... 

# Usage

```
ryu-manager ovs-l7-filter.py
```

Linking the switch to the controller can be done using `ovs-vsctl` if using OVS :

```
ovs-vsctl set-controller s1 tcp:<controller IP>:6633
```

# Logic

The controller installs a single table-miss flow on the switch : 

```
cookie=0x0, table=0, priority=0 actions=CONTROLLER:65535,resubmit(,2)
```

This flow means that every incoming packet reaching the bottom of `table 0` will be forwarded to the controller and then jumped to `table 2`. Packets reaching the controller are then analyzed for blocked protocols, and routing flows get added to `table 2` if no unauthorized protocol is found for this TCP connection.

If the controller recognizes some packets as from a blocked protocol, it will install drop flows on `table 0` with the corresponding TCP ports.

# .pat files

ovs-l7-filter uses pattern matching files (.pat) from [l7-filter](http://l7-filter.sourceforge.net/protocols). As l7-filter is getting a bit old and now requires heavy kernel patching to work, this was a nice base to start with.

These files are in the `pat_files` folder. The format is very simple (simple regex) and easy to comprehend. Many modern protocols are missing so feel free to contribute by adding anything to this folder. All .pat files are read by the controller on startup and translate into available protocols to filter.


