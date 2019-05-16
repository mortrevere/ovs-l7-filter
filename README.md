# ovs-l7-filter

This is an OpenFlow controller, built using [Ryu](https://osrg.github.io/ryu/). It works with [Open vSwitch](https://www.openvswitch.org/) but should work with any switch supporting OpenFlow 1.3.

This controller implements layer 7 (application) filtering on any switch that references it as its controller. Protocol detection is based on a regex engine and the existing [l7-filter protocol files](http://l7-filter.sourceforge.net/protocols/). 

## Use case

Block *any application* protocol on *any port*, like OpenVPN, SSH, HTTP, FTP ... at a switching level (no L3 routing)

## Usage

```
ryu-manager ovs-l7-filter.py
```

Linking the switch to the controller can be done using `ovs-vsctl` if using OVS :

```
ovs-vsctl set-controller s1 tcp:<controller IP>:6633
```

## Logic

The controller installs a single table-miss flow on the switch : 

```
cookie=0x0, table=0, priority=0 actions=CONTROLLER:65535,resubmit(,2)
```

This flow means that every incoming packet reaching the bottom of `table 0` will be forwarded to the controller and then jumped to `table 2`. Packets reaching the controller are then analyzed for blocked protocols, and routing flows get added to `table 2` if no unauthorized protocol is found for this TCP connection.

If the controller recognizes some packets as from a blocked protocol, it will install drop flows on `table 0` with the corresponding TCP ports.

## .pat files

ovs-l7-filter uses pattern matching files (.pat) from [l7-filter](http://l7-filter.sourceforge.net/protocols). As l7-filter is getting a bit old and now requires heavy kernel patching to work, this was a nice base to start with.

These files are in the `pat_files` folder. The format is very simple (simple regex) and easy to comprehend. Many modern protocols are missing so feel free to contribute by adding anything to this folder. All .pat files are read by the controller on startup and translate into available protocols to filter.

## Performances

Tests are using `iperf`.

- Normal mode: (*to fix* : sould not be that slow)
```
[  3]  0.0-10.3 sec  16.2 MBytes  13.3 Mbits/sec
```

- Fast mode :
```
[  3]  0.0-10.0 sec   421 MBytes   352 Mbits/sec
```

- Super fast mode :
```
[  3]  0.0-10.0 sec  38.3 GBytes  32.9 Gbits/sec
```

> Please note that **super fast mode** is not as safe as the other options : it allows hole-poking into the firewall. By initiating a valid connection on a given port, you could then pass any application protocol through that port. Timeouts mitigates this, and it should be safe in most common cases.

- Simple switch for reference : 
```
[  3]  0.0-10.0 sec  43.0 GBytes  36.9 Gbits/sec
```

## Todo

- file-based config and hot config (via config file and/or REST)


