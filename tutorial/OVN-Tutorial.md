OVN Tutorial
============

This tutorial is intended to give you a tour of the basic OVN features using
`ovs-sandbox` as a simulated test environment.  It’s assumed that you have an
understanding of OVS before going through this tutorial. Detail about OVN is
covered in [ovn-architecture(7)], but this tutorial lets you quickly see it in
action.

Getting Started
---------------

For some general information about `ovs-sandbox`, see the “Getting Started”
section of [Tutorial.md].

`ovs-sandbox` does not include OVN support by default.  To enable OVN, you must
pass the `--ovn` flag.  For example, if running it straight from the ovs git
tree you would run:

    $ make sandbox SANDBOXFLAGS=”--ovn”

Running the sandbox with OVN enabled does the following additional steps to the
environment:

  1. Creates the `OVN_Northbound` and `OVN_Southbound` databases as described in
     [ovn-nb(5)] and [ovn-sb(5)].

  2. Creates the `hardware_vtep` database as described in [vtep(5)].

  3. Runs the [ovn-northd(8)], [ovn-controller(8)], and [ovn-controller-vtep(8)]
     daemons.

  4. Makes OVN and VTEP utilities available for use in the environment,
     including [vtep-ctl(8)], [ovn-nbctl(8)], and [ovn-sbctl(8)].

Note that each of these demos assumes you start with a fresh sandbox
environment.  Re-run `ovs-sandbox` before starting each section.

1) Simple two-port setup
------------------------

This first environment is the simplest OVN example.  It demonstrates using OVN
with a single logical switch that has two logical ports, both residing on the
same hypervisor.

Start by running the setup script for this environment.

[View ovn/env1/setup.sh][env1setup].

    $ ovn/env1/setup.sh

You can use the `ovn-nbctl` utility to see an overview of the logical topology.

    $ ovn-nbctl show
    lswitch 78687d53-e037-4555-bcd3-f4f8eaf3f2aa (sw0)
        lport sw0-port1
            addresses: 00:00:00:00:00:01
        lport sw0-port2
            addresses: 00:00:00:00:00:02

The `ovn-sbctl` utility can be used to see into the state stored in the
`OVN_Southbound` database.  The `show` command shows that there is a single
chassis with two logical ports bound to it.  In a more realistic
multi-hypervisor environment, this would list all hypervisors and where all
logical ports are located.

    $ ovn-sbctl show
    Chassis “56b18105-5706-46ef-80c4-ff20979ab068”
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “sw0-port1”
        Port_Binding “sw0-port2”

OVN creates logical flows to describe how the network should behave in logical
space.  Each chassis then creates OpenFlow flows based on those logical flows
that reflect its own local view of the network.  The `ovn-sbctl` command can
show the logical flows.

    $ ovn-sbctl lflow-list
    Datapath: d3466847-2b3a-4f17-8eb2-34f5b0727a70  Pipeline: ingress
      table=0(port_sec), priority=  100, match=(eth.src[40]), action=(drop;)
      table=0(port_sec), priority=  100, match=(vlan.present), action=(drop;)
      table=0(port_sec), priority=   50, match=(inport == "sw0-port1" && eth.src == {00:00:00:00:00:01}), action=(next;)
      table=0(port_sec), priority=   50, match=(inport == "sw0-port2" && eth.src == {00:00:00:00:00:02}), action=(next;)
      table=1(     acl), priority=    0, match=(1), action=(next;)
      table=2( l2_lkup), priority=  100, match=(eth.dst[40]), action=(outport = "_MC_flood"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:01), action=(outport = "sw0-port1"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:02), action=(outport = "sw0-port2"; output;)
    Datapath: d3466847-2b3a-4f17-8eb2-34f5b0727a70  Pipeline: egress
      table=0(     acl), priority=    0, match=(1), action=(next;)
      table=1(port_sec), priority=  100, match=(eth.dst[40]), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw0-port1" && eth.dst == {00:00:00:00:00:01}), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw0-port2" && eth.dst == {00:00:00:00:00:02}), action=(output;)

Now we can start taking a closer look at how `ovn-controller` has programmed the
local switch.  Before looking at the flows, we can use `ovs-ofctl` to verify the
OpenFlow port numbers for each of the logical ports on the switch.  The output
shows that `lport1`, which corresponds with our logical port `sw0-port1`, has an
OpenFlow port number of `1`.  Similarly, `lport2` has an OpenFlow port number of
`2`.

    $ ovs-ofctl show br-int
    OFPT_FEATURES_REPLY (xid=0x2): dpid:00003e1ba878364d
    n_tables:254, n_buffers:256
    capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
    actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
     1(lport1): addr:aa:55:aa:55:00:07
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     2(lport2): addr:aa:55:aa:55:00:08
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     LOCAL(br-int): addr:3e:1b:a8:78:36:4d
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
    OFPT_GET_CONFIG_REPLY (xid=0x4): frags=normal miss_send_len=0

Finally, use `ovs-ofctl` to see the OpenFlow flows for `br-int`.  Note that some
fields have been omitted for brevity.

    $ ovs-ofctl -O OpenFlow13 dump-flows br-int
    OFPST_FLOW reply (OF1.3) (xid=0x2):
     table=0, priority=100,in_port=1 actions=set_field:0x1->metadata,set_field:0x1->reg6,resubmit(,16)
     table=0, priority=100,in_port=2 actions=set_field:0x1->metadata,set_field:0x2->reg6,resubmit(,16)
     table=16, priority=100,metadata=0x1,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
     table=16, priority=100,metadata=0x1,vlan_tci=0x1000/0x1000 actions=drop
     table=16, priority=50,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01 actions=resubmit(,17)
     table=16, priority=50,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02 actions=resubmit(,17)
     table=17, priority=0,metadata=0x1 actions=resubmit(,18)
     table=18, priority=100,metadata=0x1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=set_field:0xffff->reg7,resubmit(,32)
     table=18, priority=50,metadata=0x1,dl_dst=00:00:00:00:00:01 actions=set_field:0x1->reg7,resubmit(,32)
     table=18, priority=50,metadata=0x1,dl_dst=00:00:00:00:00:02 actions=set_field:0x2->reg7,resubmit(,32)
     table=32, priority=0 actions=resubmit(,33)
     table=33, priority=100,reg7=0x1,metadata=0x1 actions=resubmit(,34)
     table=33, priority=100,reg7=0xffff,metadata=0x1 actions=set_field:0x2->reg7,resubmit(,34),set_field:0x1->reg7,resubmit(,34)
     table=33, priority=100,reg7=0x2,metadata=0x1 actions=resubmit(,34)
     table=34, priority=100,reg6=0x1,reg7=0x1,metadata=0x1 actions=drop
     table=34, priority=100,reg6=0x2,reg7=0x2,metadata=0x1 actions=drop
     table=34, priority=0 actions=set_field:0->reg0,set_field:0->reg1,set_field:0->reg2,set_field:0->reg3,set_field:0->reg4,set_field:0->reg5,resubmit(,48)
     table=48, priority=0,metadata=0x1 actions=resubmit(,49)
     table=49, priority=100,metadata=0x1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=resubmit(,64)
     table=49, priority=50,reg7=0x1,metadata=0x1,dl_dst=00:00:00:00:00:01 actions=resubmit(,64)
     table=49, priority=50,reg7=0x2,metadata=0x1,dl_dst=00:00:00:00:00:02 actions=resubmit(,64)
     table=64, priority=100,reg7=0x1,metadata=0x1 actions=output:1
     table=64, priority=100,reg7=0x2,metadata=0x1 actions=output:2

The `ovs-appctl` command can be used to generate an OpenFlow trace of how a
packet would be processed in this configuration.  This first trace shows a
packet from `sw0-port1` to `sw0-port2`.  The packet arrives from port `1` and
should be output to port `2`.

[View ovn/env1/packet1.sh][env1packet1].

    $ ovn/env1/packet1.sh

Trace a broadcast packet from `sw0-port1`.  The packet arrives from port `1` and
should be output to port `2`.

[View ovn/env1/packet2.sh][env1packet2].

    $ ovn/env1/packet2.sh

You can extend this setup by adding additional ports.  For example, to add a
third port, run this command:

[View ovn/env1/add-third-port.sh][env1thirdport].

    $ ovn/env1/add-third-port.sh

Now if you do another trace of a broadcast packet from `sw0-port1`, you will see
that it is output to both ports `2` and `3`.

    $ ovn/env1/packet2.sh

2) 2 switches, 4 ports
----------------------

This environment is an extension of the last example.  The previous example
showed two ports on a single logical switch.  In this environment we add a
second logical switch that also has two ports.  This lets you start to see how
`ovn-controller` creates flows for isolated networks to co-exist on the same
switch.

[View ovn/env2/setup.sh][env2setup].

    $ ovn/env2/setup.sh

View the logical topology with `ovn-nbctl`.

    $ ovn-nbctl show
    lswitch e3190dc2-89d1-44ed-9308-e7077de782b3 (sw0)
        lport sw0-port1
            addresses: 00:00:00:00:00:01
        lport sw0-port2
            addresses: 00:00:00:00:00:02
    lswitch c8ed4c5f-9733-43f6-93da-795b1aabacb1 (sw1)
        lport sw1-port1
            addresses: 00:00:00:00:00:03
        lport sw1-port2
            addresses: 00:00:00:00:00:04

Physically, all ports reside on the same chassis.

    $ ovn-sbctl show
    Chassis “56b18105-5706-46ef-80c4-ff20979ab068”
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “sw1-port2”
        Port_Binding “sw0-port2”
        Port_Binding “sw0-port1”
        Port_Binding “sw1-port1”

OVN creates separate logical flows for each logical switch.

    $ ovn-sbctl lflow-list
    Datapath: 5aa8be0b-8369-49e2-a878-f68872a8d211  Pipeline: ingress
      table=0(port_sec), priority=  100, match=(eth.src[40]), action=(drop;)
      table=0(port_sec), priority=  100, match=(vlan.present), action=(drop;)
      table=0(port_sec), priority=   50, match=(inport == "sw0-port1" && eth.src == {00:00:00:00:00:01}), action=(next;)
      table=0(port_sec), priority=   50, match=(inport == "sw0-port2" && eth.src == {00:00:00:00:00:02}), action=(next;)
      table=1(     acl), priority=    0, match=(1), action=(next;)
      table=2( l2_lkup), priority=  100, match=(eth.dst[40]), action=(outport = "_MC_flood"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:01), action=(outport = "sw0-port1"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:02), action=(outport = "sw0-port2"; output;)
    Datapath: 5aa8be0b-8369-49e2-a878-f68872a8d211  Pipeline: egress
      table=0(     acl), priority=    0, match=(1), action=(next;)
      table=1(port_sec), priority=  100, match=(eth.dst[40]), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw0-port1" && eth.dst == {00:00:00:00:00:01}), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw0-port2" && eth.dst == {00:00:00:00:00:02}), action=(output;)
    Datapath: 631fb3c9-b0a3-4e56-bac3-1717c8cbb826  Pipeline: ingress
      table=0(port_sec), priority=  100, match=(eth.src[40]), action=(drop;)
      table=0(port_sec), priority=  100, match=(vlan.present), action=(drop;)
      table=0(port_sec), priority=   50, match=(inport == "sw1-port1" && eth.src == {00:00:00:00:00:03}), action=(next;)
      table=0(port_sec), priority=   50, match=(inport == "sw1-port2" && eth.src == {00:00:00:00:00:04}), action=(next;)
      table=1(     acl), priority=    0, match=(1), action=(next;)
      table=2( l2_lkup), priority=  100, match=(eth.dst[40]), action=(outport = "_MC_flood"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:03), action=(outport = "sw1-port1"; output;)
      table=2( l2_lkup), priority=   50, match=(eth.dst == 00:00:00:00:00:04), action=(outport = "sw1-port2"; output;)
    Datapath: 631fb3c9-b0a3-4e56-bac3-1717c8cbb826  Pipeline: egress
      table=0(     acl), priority=    0, match=(1), action=(next;)
      table=1(port_sec), priority=  100, match=(eth.dst[40]), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw1-port1" && eth.dst == {00:00:00:00:00:03}), action=(output;)
      table=1(port_sec), priority=   50, match=(outport == "sw1-port2" && eth.dst == {00:00:00:00:00:04}), action=(output;)

In this setup, `sw0-port1` and `sw0-port2` can send packets to each other, but
not to either of the ports on `sw1`.  This first trace shows a packet from
`sw0-port1` to `sw0-port2`.  You should see th packet arrive on OpenFlow port
`1` and output to OpenFlow port `2`.

[View ovn/env2/packet1.sh][env2packet1].

    $ ovn/env2/packet1.sh

This next example shows a packet from `sw0-port1` with a destination MAC address
of `00:00:00:00:00:03`, which is the MAC address for `sw1-port1`.  Since these
ports are not on the same logical switch, the packet should just be dropped.

[View ovn/env2/packet2.sh][env2packet2].

    $ ovn/env2/packet2.sh

3) Two Hypervisors
------------------

The first two examples started by showing OVN on a single hypervisor.  A more
realistic deployment of OVN would span multiple hypervisors.  This example
creates a single logical switch with 4 logical ports.  It then simulates having
two hypervisors with two of the logical ports bound to each hypervisor.

[View ovn/env3/setup.sh][env3setup].

    $ ovn/env3/setup.sh

You can start by viewing the logical topology with `ovn-nbctl`.

    $ ovn-nbctl show
    lswitch b977dc03-79a5-41ba-9665-341a80e1abfd (sw0)
        lport sw0-port1
            addresses: 00:00:00:00:00:01
        lport sw0-port2
            addresses: 00:00:00:00:00:02
        lport sw0-port4
            addresses: 00:00:00:00:00:04
        lport sw0-port3
            addresses: 00:00:00:00:00:03

Using `ovn-sbctl` to view the state of the system, we can see that there are two
chassis: one local that we can interact with, and a fake remote chassis. Two
logical ports are bound to each.  Both chassis have an IP address of localhost,
but in a realistic deployment that would be the IP address used for tunnels to
that chassis.

    $ ovn-sbctl show
    Chassis “56b18105-5706-46ef-80c4-ff20979ab068”
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “sw0-port2”
        Port_Binding “sw0-port1”
    Chassis fakechassis
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “sw0-port4”
        Port_Binding “sw0-port3”

Packets between `sw0-port1` and `sw0-port2` behave just like the previous
examples.  Packets to ports on a remote chassis are the interesting part of this
example.  You may have noticed before that OVN’s logical flows are broken up
into ingress and egress tables.  Given a packet from `sw0-port1` on the local
chassis to `sw0-port3` on the remote chassis, the ingress pipeline is executed
on the local switch.  OVN then determines that it must forward the packet over a
geneve tunnel.  When it arrives at the remote chassis, the egress pipeline will
be executed there.

This first packet trace shows the first part of this example.  It’s a packet
from `sw0-port1` to `sw0-port3` from the perspective of the local chassis.
`sw0-port1` is OpenFlow port `1`.  The tunnel to the fake remote chassis is
OpenFlow port `3`.  You should see the ingress pipeline being executed and then
the packet output to port `3`, the geneve tunnel.

[View ovn/env3/packet1.sh][env3packet1].

    $ ovn/env3/packet1.sh

To simulate what would happen when that packet arrives at the remote chassis we
can flip this example around.  Consider a packet from `sw0-port3` to
`sw0-port1`.  This trace shows what would happen when that packet arrives at the
local chassis.  The packet arrives on OpenFlow port `3` (the tunnel).  You should
then see the egress pipeline get executed and the packet output to OpenFlow port
`1`.

[View ovn/env3/packet2.sh][env3packet2].

    $ ovn/env3/packet2.sh

4) Locally attached networks
----------------------------

While OVN is generally focused on the implementation of logical networks using
overlays, it’s also possible to use OVN as a control plane to manage logically
direct connectivity to networks that are locally accessible to each chassis.

This example includes two hypervisors.  Both hypervisors have two ports on them.
We want to use OVN to manage the connectivity of these ports to a network
attached to each hypervisor that we will call “physnet1”.

This scenario requires some additional configuration of `ovn-controller`.  We
must configure a mapping between `physnet1` and a local OVS bridge that provides
connectivity to that network.  We call these “bridge mappings”.  For our
example, the following script creates a bridge called `br-eth1` and then
configures `ovn-controller` with a bridge mapping from `physnet1` to `br-eth1`.

[View ovn/env4/setup1.sh][env4setup1].

    $ ovn/env4/setup1.sh

At this point we should be able to see that `ovn-controller` has automatically
created patch ports between `br-int` and `br-eth1`.

    $ ovs-vsctl show
    aea39214-ebec-4210-aa34-1ae7d6921720
        Bridge br-int
            fail_mode: secure
            Port “patch-br-int-to-br-eth1”
                Interface “patch-br-int-to-br-eth1”
                    type: patch
                    options: {peer=”patch-br-eth1-to-br-int”}
            Port br-int
                Interface br-int
                    type: internal
        Bridge “br-eth1”
            Port “br-eth1”
                Interface “br-eth1”
                    type: internal
            Port “patch-br-eth1-to-br-int”
                Interface “patch-br-eth1-to-br-int”
                    type: patch
                    options: {peer=”patch-br-int-to-br-eth1”}

Now we can move on to the next setup phase for this example.  We want to create
a fake second chassis and then create the topology that tells OVN we want both
ports on both hypervisors connected to `physnet1`.  The way this is modeled in
OVN is by creating a logical switch for each port.  The logical switch has the
regular VIF port and a `localnet` port.

[View ovn/env4/setup2.sh][env4setup2].

    $ ovn/env4/setup2.sh

The logical topology from `ovn-nbctl` should look like this.

    $ ovn-nbctl show
        lswitch 5a652488-cfba-4f3e-929d-00010cdfde40 (provnet1-2)
            lport provnet1-2-physnet1
                addresses: unknown
            lport provnet1-2-port1
                addresses: 00:00:00:00:00:02
        lswitch 5829b60a-eda8-4d78-94f6-7017ff9efcf0 (provnet1-4)
            lport provnet1-4-port1
                addresses: 00:00:00:00:00:04
            lport provnet1-4-physnet1
                addresses: unknown
        lswitch 06cbbcb6-38e3-418d-a81e-634ec9b54ad6 (provnet1-1)
            lport provnet1-1-port1
                addresses: 00:00:00:00:00:01
            lport provnet1-1-physnet1
                addresses: unknown
        lswitch 9cba3b3b-59ae-4175-95f5-b6f1cd9c2afb (provnet1-3)
            lport provnet1-3-physnet1
                addresses: unknown
            lport provnet1-3-port1
                addresses: 00:00:00:00:00:03

`port1` on each logical switch represents a regular logical port for a VIF on a
hypervisor.  `physnet1` on each logical switch is the special `localnet` port.
You can use `ovn-nbctl` to see that this port has a `type` and `options` set.

    $ ovn-nbctl lport-get-type provnet1-1-physnet1
    localnet

    $ ovn-nbctl lport-get-options provnet1-1-physnet1
    network_name=physnet1

The physical topology should reflect that there are two regular ports on each
chassis.

    $ ovn-sbctl show
    Chassis fakechassis
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “provnet1-3-port1”
        Port_Binding “provnet1-4-port1”
    Chassis “56b18105-5706-46ef-80c4-ff20979ab068”
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “provnet1-2-port1”
        Port_Binding “provnet1-1-port1”

All four of our ports should be able to communicate with each other, but they do
so through `physnet1`.  A packet from any of these ports to any destination
should be output to the OpenFlow port number that corresponds to the patch port
to `br-eth1`.

This example assumes following OpenFlow port number mappings:

* 1 = patch port to `br-eth1`
* 2 = tunnel to the fake second chassis
* 3 = lport1, which is the logical port named `provnet1-1-port1`
* 4 = lport2, which is the logical port named `provnet1-2-port1`

We get those port numbers using `ovs-ofctl`:

    $ ovs-ofctl show br-int
    OFPT_FEATURES_REPLY (xid=0x2): dpid:0000765054700040
    n_tables:254, n_buffers:256
    capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
    actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src
    mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
     1(patch-br-int-to): addr:de:29:14:95:8a:b8
         config:     0
         state:      0
         speed: 0 Mbps now, 0 Mbps max
     2(ovn-fakech-0): addr:aa:55:aa:55:00:08
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     3(lport1): addr:aa:55:aa:55:00:09
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     4(lport2): addr:aa:55:aa:55:00:0a
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     LOCAL(br-int): addr:76:50:54:70:00:40
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
    OFPT_GET_CONFIG_REPLY (xid=0x4): frags=normal miss_send_len=0

This first trace shows a packet from `provnet1-1-port1` with a destination MAC
address of `provnet1-2-port1`.  Despite both of these ports being on the same
local switch (`lport1` and `lport2`), we expect all packets to be sent out to
`br-eth1` (OpenFlow port 1).  We then expect the network to handle getting the
packet to its destination.  In practice, this will be optimized at `br-eth1` and
the packet won’t actually go out and back on the network.

[View ovn/env4/packet1.sh][env4packet1].

    $ ovn/env4/packet1.sh

This next trace is a continuation of the previous one.  This shows the packet
coming back into `br-int` from `br-eth1`.  We now expect the packet to be output
to `provnet1-2-port1`, which is OpenFlow port 4.

[View ovn/env4/packet2.sh][env4packet2].

    $ ovn/env4/packet2.sh

This next trace shows an example of a packet being sent to a destination on
another hypervisor.  The source is `provnet1-2-port1`, but the destination is
`provnet1-3-port1`, which is on the other fake chassis.  As usual, we expect the
output to be to OpenFlow port 1, the patch port to `br-et1`.

[View ovn/env4/packet3.sh][env4packet3].

    $ ovn/env4/packet3.sh

This next test shows a broadcast packet.  The destination should still only be
OpenFlow port 1.

[View ovn/env4/packet4.sh][env4packet4]

    $ ovn/env4/packet4.sh

Finally, this last trace shows what happens when a broadcast packet arrives
from the network.  In this case, it simulates a broadcast that originated from a
port on the remote fake chassis and arrived at the local chassis via `br-eth1`.
We should see it output to both local ports that are attached to this network
(OpenFlow ports 3 and 4).

[View ovn/env4/packet5.sh][env4packet5]

    $ ovn/env4/packet5.sh

5) Locally attached networks with VLANs
---------------------------------------

This example is an extension of the previous one.  We take the same setup and
add two more ports to each hypervisor.  Instead of having the new ports directly
connected to `physnet1` as before, we indicate that we want them on VLAN 101 of
`physnet1`.  This shows how `localnet` ports can be used to provide connectivity
to either a flat network or a VLAN on that network.

[View ovn/env5/setup.sh][env5setup]

    $ ovn/env5/setup.sh

The logical topology shown by `ovn-nbctl` is similar to `env4`, except we now
have 8 regular VIF ports connected to `physnet1` instead of 4.  The additional 4
ports we have added are all on VLAN 101 of `physnet1`.  Note that the `localnet`
ports representing connectivity to VLAN 101 of `physnet1` have the `tag` field
set to `101`.

    $ ovn-nbctl show
        lswitch 12ea93d0-694b-48e9-adef-d0ddd3ec4ac9 (provnet1-7-101)
            lport provnet1-7-physnet1-101
                parent: , tag:101
                addresses: unknown
            lport provnet1-7-101-port1
                addresses: 00:00:00:00:00:07
        lswitch c9a5ce3a-15ec-48ea-a898-416013463589 (provnet1-4)
            lport provnet1-4-port1
                addresses: 00:00:00:00:00:04
            lport provnet1-4-physnet1
                addresses: unknown
        lswitch e07d4f7a-2085-4fbb-9937-d6192b79a397 (provnet1-1)
            lport provnet1-1-physnet1
                addresses: unknown
            lport provnet1-1-port1
                addresses: 00:00:00:00:00:01
        lswitch 6c098474-0509-4219-bc9b-eb4e28dd1aeb (provnet1-2)
            lport provnet1-2-physnet1
                addresses: unknown
            lport provnet1-2-port1
                addresses: 00:00:00:00:00:02
        lswitch 723c4684-5d58-4202-b8e3-4ba99ad5ed9e (provnet1-8-101)
            lport provnet1-8-101-port1
                addresses: 00:00:00:00:00:08
            lport provnet1-8-physnet1-101
                parent: , tag:101
                addresses: unknown
        lswitch 8444e925-ceb2-4b02-ac20-eb2e4cfb954d (provnet1-6-101)
            lport provnet1-6-physnet1-101
                parent: , tag:101
                addresses: unknown
            lport provnet1-6-101-port1
                addresses: 00:00:00:00:00:06
        lswitch e11e5605-7c46-4395-b28d-cff57451fc7e (provnet1-3)
            lport provnet1-3-port1
                addresses: 00:00:00:00:00:03
            lport provnet1-3-physnet1
                addresses: unknown
        lswitch 0706b697-6c92-4d54-bc0a-db5bababb74a (provnet1-5-101)
            lport provnet1-5-101-port1
                addresses: 00:00:00:00:00:05
            lport provnet1-5-physnet1-101
                parent: , tag:101
                addresses: unknown

The physical topology shows that we have 4 regular VIF ports on each simulated
hypervisor.

    $ ovn-sbctl show
    Chassis “56b18105-5706-46ef-80c4-ff20979ab068”
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “provnet1-6-101-port1”
        Port_Binding “provnet1-1-port1”
        Port_Binding “provnet1-2-port1”
        Port_Binding “provnet1-5-101-port1”
    Chassis fakechassis
        Encap geneve
            ip: “127.0.0.1”
        Port_Binding “provnet1-4-port1”
        Port_Binding “provnet1-3-port1”
        Port_Binding “provnet1-8-101-port1”
        Port_Binding “provnet1-7-101-port1”

All of the traces from the previous example, `env4`, should work in this
environment and provide the same result.  Now we can show what happens for the
ports connected to VLAN 101.  This first example shows a packet originating from
`provnet1-5-101-port1`, which is OpenFlow port 5.  We should see VLAN tag 101
pushed on the packet and then output to OpenFlow port 1, the patch port to
`br-eth1` (the bridge providing connectivity to `physnet1`).

[View ovn/env5/packet1.sh][env5packet1].

    $ ovn/env5/packet1.sh

If we look at a broadcast packet arriving on VLAN 101 of `physnet1`, we should
see it output to OpenFlow ports 5 and 6 only.

[View ovn/env5/packet2.sh][env5packet2].

    $ ovn/env5/packet2.sh


6) Stateful ACLs
----------------

ACLs provide a way to do distributed packet filtering for OVN networks.  One
example use of ACLs is that OpenStack Neutron uses them to implement security
groups.  ACLs are implemented using conntrack integration with OVS.

Start with a simple logical switch with 2 logical ports.

[View ovn/env6/setup.sh][env6setup].

    $ ovn/env6/setup.sh

A common use case would be the following policy applied for `sw0-port1`:

* Allow outbound IP traffic and associated return traffic.
* Allow incoming ICMP requests and associated return traffic.
* Allow incoming SSH connections and associated return traffic.
* Drop other incoming IP traffic.

The following script applies this policy to our environment.

[View ovn/env6/add-acls.sh][env6acls].

    $ ovn/env6/add-acls.sh

We can view the configured ACLs on this network using the `ovn-nbctl` command.

    $ ovn-nbctl acl-list sw0
    from-lport  1002 (inport == “sw0-port1” && ip) allow-related
      to-lport  1002 (outport == “sw0-port1” && ip && icmp) allow-related
      to-lport  1002 (outport == “sw0-port1” && ip && tcp && tcp.dst == 22) allow-related
      to-lport  1001 (outport == “sw0-port1” && ip) drop

Now that we have ACLs configured, there are new entries in the logical flow
table in the stages `switch_in_pre_acl`, switch_in_acl`, `switch_out_pre_acl`,
and `switch_out_acl`.

    $ ovn-sbctl lflow-list

Let’s look more closely at `switch_out_pre_acl` and `switch_out_acl`.

In `switch_out_pre_acl`, we match IP traffic and put it through the connection
tracker.  This populates the connection state fields so that we can apply policy
as appropriate.

    table=0(switch_out_pre_acl), priority=  100, match=(ip), action=(ct_next;)
    table=1(switch_out_pre_acl), priority=    0, match=(1), action=(next;)

In `switch_out_acl`, we allow packets associated with existing connections.  We
drop packets that are deemed to be invalid (such as non-SYN TCP packet not
associated with an existing connection).

    table=1(switch_out_acl), priority=65535, match=(!ct.est && ct.rel && !ct.new && !ct.inv), action=(next;)
    table=1(switch_out_acl), priority=65535, match=(ct.est && !ct.rel && !ct.new && !ct.inv), action=(next;)
    table=1(switch_out_acl), priority=65535, match=(ct.inv), action=(drop;)

For new connections, we apply our configured ACL policy to decide whether to
allow the connection or not.  In this case, we’ll allow ICMP or SSH.  Otherwise,
we’ll drop the packet.

    table=1(switch_out_acl), priority= 2002, match=(ct.new && (outport == “sw0-port1” && ip && icmp)), action=(ct_commit; next;)
    table=1(switch_out_acl), priority= 2002, match=(ct.new && (outport == “sw0-port1” && ip && tcp && tcp.dst == 22)), action=(ct_commit; next;)
    table=1(switch_out_acl), priority= 2001, match=(outport == “sw0-port1” && ip), action=(drop;)

When using ACLs, the default policy is to allow and track IP connections.  Based
on our above policy, IP traffic directed at `sw0-port1` will never hit this flow
at priority 1.

    table=1(switch_out_acl), priority=    1, match=(ip), action=(ct_commit; next;)
    table=1(switch_out_acl), priority=    0, match=(1), action=(next;)

Note that conntrack integration is not yet supported in ovs-sandbox, so the
OpenFlow flows will not represent what you’d see in a real environment.  The
logical flows described above give a very good idea of what the flows look like,
though.

[This blog post][openstack-ovn-acl-blog] discusses OVN ACLs from an OpenStack
perspective and also provides an example of what the resulting OpenFlow flows
look like.

[ovn-architecture(7)]:http://openvswitch.org/support/dist-docs/ovn-architecture.7.html
[Tutorial.md]:https://github.com/openvswitch/ovs/blob/master/tutorial/Tutorial.md
[ovn-nb(5)]:http://openvswitch.org/support/dist-docs/ovn-nb.5.html
[ovn-sb(5)]:http://openvswitch.org/support/dist-docs/ovn-sb.5.html
[vtep(5)]:http://openvswitch.org/support/dist-docs/vtep.5.html
[ovn-northd(8)]:http://openvswitch.org/support/dist-docs/ovn-northd
[ovn-controller(8)]:http://openvswitch.org/support/dist-docs/ovn-controller.8.html
[ovn-controller-vtep(8)]:http://openvswitch.org/support/dist-docs/ovn-controller-vtep.8.html
[vtep-ctl(8)]:http://openvswitch.org/support/dist-docs/vtep-ctl.8.html
[ovn-nbctl(8)]:http://openvswitch.org/support/dist-docs/ovn-nbctl.8.html
[ovn-sbctl(8)]:http://openvswitch.org/support/dist-docs/ovn-sbctl.8.html
[env1setup]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env1/setup.sh
[env1packet1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env1/packet1.sh
[env1packet2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env1/packet2.sh
[env1thirdport]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env1/add-third-port.sh
[env2setup]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env2/setup.sh
[env2packet1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env2/packet1.sh
[env2packet2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env2/packet2.sh
[env3setup]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env3/setup.sh
[env3packet1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env3/packet1.sh
[env3packet2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env3/packet2.sh
[env4setup1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/setup1.sh
[env4setup2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/setup2.sh
[env4packet1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/packet1.sh
[env4packet2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/packet2.sh
[env4packet3]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/packet3.sh
[env4packet4]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/packet4.sh
[env4packet5]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env4/packet5.sh
[env5setup]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env5/setup.sh
[env5packet1]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env5/packet1.sh
[env5packet2]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env5/packet2.sh
[env6setup]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env6/setup.sh
[env6acls]:https://github.com/openvswitch/ovs/blob/master/tutorial/ovn/env6/add-acls.sh
[openstack-ovn-acl-blog]:http://blog.russellbryant.net/2015/10/22/openstack-security-groups-using-ovn-acls/
