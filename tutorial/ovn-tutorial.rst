..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============
OVN Tutorial
============

This tutorial is intended to give you a tour of the basic OVN features using
``ovs-sandbox`` as a simulated test environment.  It's assumed that you have an
understanding of OVS before going through this tutorial. Detail about OVN is
covered in ovn-architecture_, but this tutorial lets you quickly see it in
action.

Getting Started
---------------

For some general information about ``ovs-sandbox``, see the "Getting Started"
section of the tutorial_.

``ovs-sandbox`` does not include OVN support by default.  To enable OVN, you
must pass the ``--ovn`` flag.  For example, if running it straight from the ovs
git tree you would run::

    $ make sandbox SANDBOXFLAGS="--ovn"

Running the sandbox with OVN enabled does the following additional steps to the
environment:

1. Creates the ``OVN_Northbound`` and ``OVN_Southbound`` databases as described in
   `ovn-nb(5)`_ and `ovn-sb(5)`_.

2. Creates a backup server for ``OVN_Southbond`` database. Sandbox launch
   screen provides the instructions on accessing the backup database.  However
   access to the backup server is not required to go through the tutorial.

3. Creates the ``hardware_vtep`` database as described in `vtep(5)`_.

4. Runs the `ovn-northd(8)`_, `ovn-controller(8)`_, and
   `ovn-controller-vtep(8)`_ daemons.

5. Makes OVN and VTEP utilities available for use in the environment, including
   `vtep-ctl(8)`_, `ovn-nbctl(8)`_, and `ovn-sbctl(8)`_.

Note that each of these demos assumes you start with a fresh sandbox
environment. **Re-run `ovs-sandbox` before starting each section.**

Using GDB
---------

GDB support is not required to go through the tutorial. See the "Using GDB"
section of the `tutorial`_ for more info. Additional flags exist for launching
the debugger for the OVN programs::

    --gdb-ovn-northd
    --gdb-ovn-controller
    --gdb-ovn-controller-vtep

Simple Two Port Setup
---------------------

This first environment is the simplest OVN example.  It demonstrates using OVN
with a single logical switch that has two logical ports, both residing on the
same hypervisor.

Start by running the setup script for this environment::

    $ ovn/env1/setup.sh

You can use the ``ovn-nbctl`` utility to see an overview of the logical
topology::

    $ ovn-nbctl show
    switch 78687d53-e037-4555-bcd3-f4f8eaf3f2aa (sw0)
        port sw0-port1
            addresses: ["00:00:00:00:00:01"]
        port sw0-port2
            addresses: ["00:00:00:00:00:02"]

The ``ovn-sbctl`` utility can be used to see into the state stored in the
``OVN_Southbound`` database.  The ``show`` command shows that there is a single
chassis with two logical ports bound to it.  In a more realistic
multi-hypervisor environment, this would list all hypervisors and where all
logical ports are located::

    $ ovn-sbctl show
    Chassis "56b18105-5706-46ef-80c4-ff20979ab068"
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "sw0-port1"
        Port_Binding "sw0-port2"

OVN creates logical flows to describe how the network should behave in logical
space.  Each chassis then creates OpenFlow flows based on those logical flows
that reflect its own local view of the network.  The ``ovn-sbctl`` command can
show the logical flows::

    $ ovn-sbctl lflow-list
    Datapath: 2503dd42-14b1-414a-abbf-33e554e09ddc  Pipeline: ingress
      table=0 (ls_in_port_sec_l2 ), priority=100   , match=(eth.src[40]), action=(drop;)
      table=0 (ls_in_port_sec_l2 ), priority=100   , match=(vlan.present), action=(drop;)
      table=0 (ls_in_port_sec_l2 ), priority=50    , match=(inport == "sw0-port1" && eth.src == {00:00:00:00:00:01}), action=(next;)
      table=0 (ls_in_port_sec_l2 ), priority=50    , match=(inport == "sw0-port2" && eth.src == {00:00:00:00:00:02}), action=(next;)
      table=1 (ls_in_port_sec_ip ), priority=0     , match=(1), action=(next;)
      table=2 (ls_in_port_sec_nd ), priority=90    , match=(inport == "sw0-port1" && eth.src == 00:00:00:00:00:01 && arp.sha == 00:00:00:00:00:01), action=(next;)
      table=2 (ls_in_port_sec_nd ), priority=90    , match=(inport == "sw0-port1" && eth.src == 00:00:00:00:00:01 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:01) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:01)))), action=(next;)
      table=2 (ls_in_port_sec_nd ), priority=90    , match=(inport == "sw0-port2" && eth.src == 00:00:00:00:00:02 && arp.sha == 00:00:00:00:00:02), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw0-port2" && eth.src == 00:00:00:00:00:02 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:02) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:02)))), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw0-port1" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw0-port2" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=0    , match=(1), action=(next;)
      table=3 (ls_in_pre_acl      ), priority=0    , match=(1), action=(next;)
      table=4 (ls_in_pre_lb       ), priority=0    , match=(1), action=(next;)
      table=5 (ls_in_pre_stateful ), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=5 (ls_in_pre_stateful ), priority=0    , match=(1), action=(next;)
      table=6 (ls_in_acl          ), priority=0    , match=(1), action=(next;)
      table=7 (ls_in_lb           ), priority=0    , match=(1), action=(next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=8 (ls_in_stateful     ), priority=0    , match=(1), action=(next;)
      table=9 (ls_in_arp_rsp      ), priority=0    , match=(1), action=(next;)
      table=10(ls_in_l2_lkup      ), priority=100  , match=(eth.mcast), action=(outport = "_MC_flood"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:01), action=(outport = "sw0-port1"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:02), action=(outport = "sw0-port2"; output;)
    Datapath: 2503dd42-14b1-414a-abbf-33e554e09ddc  Pipeline: egress
      table=0 (ls_out_pre_lb      ), priority=0    , match=(1), action=(next;)
      table=1 (ls_out_pre_acl     ), priority=0    , match=(1), action=(next;)
      table=2 (ls_out_pre_stateful), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=2 (ls_out_pre_stateful), priority=0    , match=(1), action=(next;)
      table=3 (ls_out_lb          ), priority=0    , match=(1), action=(next;)
      table=4 (ls_out_acl         ), priority=0    , match=(1), action=(next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=5 (ls_out_stateful    ), priority=0    , match=(1), action=(next;)
      table=6 (ls_out_port_sec_ip ), priority=0    , match=(1), action=(next;)
      table=7 (ls_out_port_sec_l2 ), priority=100  , match=(eth.mcast), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw0-port1" && eth.dst == {00:00:00:00:00:01}), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw0-port2" && eth.dst == {00:00:00:00:00:02}), action=(output;)

Now we can start taking a closer look at how ``ovn-controller`` has programmed
the local switch.  Before looking at the flows, we can use ``ovs-ofctl`` to
verify the OpenFlow port numbers for each of the logical ports on the switch.
The output shows that ``lport1``, which corresponds with our logical port
``sw0-port1``, has an OpenFlow port number of ``1``.  Similarly, ``lport2`` has
an OpenFlow port number of ``2``::

    $ ovs-ofctl show br-int
    OFPT_FEATURES_REPLY (xid=0x2): dpid:00003e1ba878364d
    n_tables:254, n_buffers:0
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

Finally, use ``ovs-ofctl`` to see the OpenFlow flows for ``br-int``.  Note that
some fields have been omitted for brevity::

    $ ovs-ofctl -O OpenFlow13 dump-flows br-int
    OFPST_FLOW reply (OF1.3) (xid=0x2):
     table=0, priority=100,in_port=1 actions=set_field:0x1->metadata,set_field:0x1->reg6,resubmit(,16)
     table=0, priority=100,in_port=2 actions=set_field:0x1->metadata,set_field:0x2->reg6,resubmit(,16)
     table=16, priority=100,metadata=0x1,vlan_tci=0x1000/0x1000 actions=drop
     table=16, priority=100,metadata=0x1,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
     table=16, priority=50,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01 actions=resubmit(,17)
     table=16, priority=50,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02 actions=resubmit(,17)
     table=17, priority=0,metadata=0x1 actions=resubmit(,18)
     table=18, priority=90,icmp6,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02,icmp_type=136,icmp_code=0,nd_tll=00:00:00:00:00:00 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02,icmp_type=136,icmp_code=0,nd_tll=00:00:00:00:00:02 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01,icmp_type=136,icmp_code=0,nd_tll=00:00:00:00:00:00 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01,icmp_type=136,icmp_code=0,nd_tll=00:00:00:00:00:01 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01,icmp_type=135,icmp_code=0,nd_sll=00:00:00:00:00:01 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01,icmp_type=135,icmp_code=0,nd_sll=00:00:00:00:00:00 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02,icmp_type=135,icmp_code=0,nd_sll=00:00:00:00:00:00 actions=resubmit(,19)
     table=18, priority=90,icmp6,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02,icmp_type=135,icmp_code=0,nd_sll=00:00:00:00:00:02 actions=resubmit(,19)
     table=18, priority=90,arp,reg6=0x1,metadata=0x1,dl_src=00:00:00:00:00:01,arp_sha=00:00:00:00:00:01 actions=resubmit(,19)
     table=18, priority=90,arp,reg6=0x2,metadata=0x1,dl_src=00:00:00:00:00:02,arp_sha=00:00:00:00:00:02 actions=resubmit(,19)
     table=18, priority=80,icmp6,reg6=0x2,metadata=0x1,icmp_type=136,icmp_code=0 actions=drop
     table=18, priority=80,icmp6,reg6=0x1,metadata=0x1,icmp_type=136,icmp_code=0 actions=drop
     table=18, priority=80,icmp6,reg6=0x1,metadata=0x1,icmp_type=135,icmp_code=0 actions=drop
     table=18, priority=80,icmp6,reg6=0x2,metadata=0x1,icmp_type=135,icmp_code=0 actions=drop
     table=18, priority=80,arp,reg6=0x2,metadata=0x1 actions=drop
     table=18, priority=80,arp,reg6=0x1,metadata=0x1 actions=drop
     table=18, priority=0,metadata=0x1 actions=resubmit(,19)
     table=19, priority=0,metadata=0x1 actions=resubmit(,20)
     table=20, priority=0,metadata=0x1 actions=resubmit(,21)
     table=21, priority=0,metadata=0x1 actions=resubmit(,22)
     table=22, priority=0,metadata=0x1 actions=resubmit(,23)
     table=23, priority=0,metadata=0x1 actions=resubmit(,24)
     table=24, priority=0,metadata=0x1 actions=resubmit(,25)
     table=25, priority=0,metadata=0x1 actions=resubmit(,26)
     table=26, priority=100,metadata=0x1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=set_field:0xffff->reg7,resubmit(,32)
     table=26, priority=50,metadata=0x1,dl_dst=00:00:00:00:00:01 actions=set_field:0x1->reg7,resubmit(,32)
     table=26, priority=50,metadata=0x1,dl_dst=00:00:00:00:00:02 actions=set_field:0x2->reg7,resubmit(,32)
     table=32, priority=0 actions=resubmit(,33)
     table=33, priority=100,reg7=0x1,metadata=0x1 actions=resubmit(,34)
     table=33, priority=100,reg7=0xffff,metadata=0x1 actions=set_field:0x2->reg7,resubmit(,34),set_field:0x1->reg7,resubmit(,34),set_field:0xffff->reg7
     table=33, priority=100,reg7=0x2,metadata=0x1 actions=resubmit(,34)
     table=34, priority=100,reg6=0x1,reg7=0x1,metadata=0x1 actions=drop
     table=34, priority=100,reg6=0x2,reg7=0x2,metadata=0x1 actions=drop
     table=34, priority=0 actions=set_field:0->reg0,set_field:0->reg1,set_field:0->reg2,resubmit(,48)
     table=48, priority=0,metadata=0x1 actions=resubmit(,49)
     table=49, priority=0,metadata=0x1 actions=resubmit(,50)
     table=50, priority=0,metadata=0x1 actions=resubmit(,51)
     table=51, priority=0,metadata=0x1 actions=resubmit(,52)
     table=52, priority=0,metadata=0x1 actions=resubmit(,53)
     table=53, priority=0,metadata=0x1 actions=resubmit(,54)
     table=54, priority=0,metadata=0x1 actions=resubmit(,55)
     table=55, priority=100,metadata=0x1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=resubmit(,64)
     table=55, priority=50,reg7=0x2,metadata=0x1,dl_dst=00:00:00:00:00:02 actions=resubmit(,64)
     table=55, priority=50,reg7=0x1,metadata=0x1,dl_dst=00:00:00:00:00:01 actions=resubmit(,64)
     table=64, priority=100,reg7=0x1,metadata=0x1 actions=output:1

The ``ovs-appctl`` command can be used to generate an OpenFlow trace of how a
packet would be processed in this configuration.  This first trace shows a
packet from ``sw0-port1`` to ``sw0-port2``.  The packet arrives from port ``1``
and should be output to port ``2``::

    $ ovn/env1/packet1.sh

Trace a broadcast packet from ``sw0-port1``.  The packet arrives from port
``1`` and should be output to port ``2``::

    $ ovn/env1/packet2.sh

You can extend this setup by adding additional ports.  For example, to add a
third port, run this command::

    $ ovn/env1/add-third-port.sh

Now if you do another trace of a broadcast packet from ``sw0-port1``, you will
see that it is output to both ports ``2`` and ``3``::

    $ ovn/env1/packet2.sh

The logical port may have an unknown set of Ethernet addresses.  When an OVN logical
switch processes a unicast Ethernet frame whose destination MAC address is not in any
logical port's addresses column, it delivers it to the port (or ports) whose addresses
columns include unknown::

    $ ovn/env1/add-unknown-ports.sh

This trace shows a packet from ``sw0-port1`` to ``sw0-port4``, ``sw0-port5``
whose addresses columns include unknown.  You will see that it is output to
both ports ``4`` and ``5``::

    $ ovn/env1/packet3.sh

The logical port would restrict the host to sending packets from and receiving
packets to the ethernet addresses defined in the logical port's
``port_security`` column.  In addition to the restrictions described for
Ethernet addresses above, such an element of port_security restricts the IPv4
or IPv6 addresses from which the host may send and to which it may receive
packets to the specified addresses::

    $ ovn/env1/add-security-ip-ports.sh

This trace shows a packet from ``sw0-port6`` to ``sw0-port7``::

    $ ovn/env1/packet4.sh

Two Switches, Four Ports
------------------------

This environment is an extension of the last example.  The previous example
showed two ports on a single logical switch.  In this environment we add a
second logical switch that also has two ports.  This lets you start to see how
``ovn-controller`` creates flows for isolated networks to co-exist on the same
switch::

    $ ovn/env2/setup.sh

View the logical topology with ``ovn-nbctl``::

    $ ovn-nbctl show
    switch e3190dc2-89d1-44ed-9308-e7077de782b3 (sw0)
        port sw0-port1
            addresses: 00:00:00:00:00:01
        port sw0-port2
            addresses: 00:00:00:00:00:02
    switch c8ed4c5f-9733-43f6-93da-795b1aabacb1 (sw1)
        port sw1-port1
            addresses: 00:00:00:00:00:03
        port sw1-port2
            addresses: 00:00:00:00:00:04

Physically, all ports reside on the same chassis::

    $ ovn-sbctl show
    Chassis "56b18105-5706-46ef-80c4-ff20979ab068"
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "sw1-port2"
        Port_Binding "sw0-port2"
        Port_Binding "sw0-port1"
        Port_Binding "sw1-port1"

OVN creates separate logical flows for each logical switch::

    $ ovn-sbctl lflow-list
    Datapath: 7ee908c1-b0d3-4d03-acc9-42cd7ef7f27d  Pipeline: ingress
      table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
      table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
      table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "sw1-port1" && eth.src == {00:00:00:00:00:03}), action=(next;)
      table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "sw1-port2" && eth.src == {00:00:00:00:00:04}), action=(next;)
      table=1 (ls_in_port_sec_ip  ), priority=0    , match=(1), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw1-port1" && eth.src == 00:00:00:00:00:03 && arp.sha == 00:00:00:00:00:03), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw1-port1" && eth.src == 00:00:00:00:00:03 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:03) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:03)))), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw1-port2" && eth.src == 00:00:00:00:00:04 && arp.sha == 00:00:00:00:00:04), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw1-port2" && eth.src == 00:00:00:00:00:04 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:04) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:04)))), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw1-port1" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw1-port2" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=0    , match=(1), action=(next;)
      table=3 (ls_in_pre_acl      ), priority=0    , match=(1), action=(next;)
      table=4 (ls_in_pre_lb       ), priority=0    , match=(1), action=(next;)
      table=5 (ls_in_pre_stateful ), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=5 (ls_in_pre_stateful ), priority=0    , match=(1), action=(next;)
      table=6 (ls_in_acl          ), priority=0    , match=(1), action=(next;)
      table=7 (ls_in_lb           ), priority=0    , match=(1), action=(next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=8 (ls_in_stateful     ), priority=0    , match=(1), action=(next;)
      table=9 (ls_in_arp_rsp      ), priority=0    , match=(1), action=(next;)
      table=10(ls_in_l2_lkup      ), priority=100  , match=(eth.mcast), action=(outport = "_MC_flood"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:03), action=(outport = "sw1-port1"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:04), action=(outport = "sw1-port2"; output;)
    Datapath: 7ee908c1-b0d3-4d03-acc9-42cd7ef7f27d  Pipeline: egress
      table=0 (ls_out_pre_lb      ), priority=0    , match=(1), action=(next;)
      table=1 (ls_out_pre_acl     ), priority=0    , match=(1), action=(next;)
      table=2 (ls_out_pre_stateful), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=2 (ls_out_pre_stateful), priority=0    , match=(1), action=(next;)
      table=3 (ls_out_lb          ), priority=0    , match=(1), action=(next;)
      table=4 (ls_out_acl         ), priority=0    , match=(1), action=(next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=5 (ls_out_stateful    ), priority=0    , match=(1), action=(next;)
      table=6 (ls_out_port_sec_ip ), priority=0    , match=(1), action=(next;)
      table=7 (ls_out_port_sec_l2 ), priority=100  , match=(eth.mcast), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw1-port1" && eth.dst == {00:00:00:00:00:03}), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw1-port2" && eth.dst == {00:00:00:00:00:04}), action=(output;)
    Datapath: 9ea0c8f9-4f82-4be3-a6c7-6e6f9c2de583  Pipeline: ingress
      table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
      table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
      table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "sw0-port1" && eth.src == {00:00:00:00:00:01}), action=(next;)
      table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "sw0-port2" && eth.src == {00:00:00:00:00:02}), action=(next;)
      table=1 (ls_in_port_sec_ip  ), priority=0    , match=(1), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw0-port1" && eth.src == 00:00:00:00:00:01 && arp.sha == 00:00:00:00:00:01), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw0-port1" && eth.src == 00:00:00:00:00:01 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:01) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:01)))), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw0-port2" && eth.src == 00:00:00:00:00:02 && arp.sha == 00:00:00:00:00:02), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=90   , match=(inport == "sw0-port2" && eth.src == 00:00:00:00:00:02 && ip6 && nd && ((nd.sll == 00:00:00:00:00:00 || nd.sll == 00:00:00:00:00:02) || ((nd.tll == 00:00:00:00:00:00 || nd.tll == 00:00:00:00:00:02)))), action=(next;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw0-port1" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=80   , match=(inport == "sw0-port2" && (arp || nd)), action=(drop;)
      table=2 (ls_in_port_sec_nd  ), priority=0    , match=(1), action=(next;)
      table=3 (ls_in_pre_acl      ), priority=0    , match=(1), action=(next;)
      table=4 (ls_in_pre_lb       ), priority=0    , match=(1), action=(next;)
      table=5 (ls_in_pre_stateful ), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=5 (ls_in_pre_stateful ), priority=0    , match=(1), action=(next;)
      table=6 (ls_in_acl          ), priority=0    , match=(1), action=(next;)
      table=7 (ls_in_lb           ), priority=0    , match=(1), action=(next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=8 (ls_in_stateful     ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=8 (ls_in_stateful     ), priority=0    , match=(1), action=(next;)
      table=9 (ls_in_arp_rsp      ), priority=0    , match=(1), action=(next;)
      table=10(ls_in_l2_lkup      ), priority=100  , match=(eth.mcast), action=(outport = "_MC_flood"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:01), action=(outport = "sw0-port1"; output;)
      table=10(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == 00:00:00:00:00:02), action=(outport = "sw0-port2"; output;)
    Datapath: 9ea0c8f9-4f82-4be3-a6c7-6e6f9c2de583  Pipeline: egress
      table=0 (ls_out_pre_lb      ), priority=0    , match=(1), action=(next;)
      table=1 (ls_out_pre_acl     ), priority=0    , match=(1), action=(next;)
      table=2 (ls_out_pre_stateful), priority=100  , match=(reg0[0] == 1), action=(ct_next;)
      table=2 (ls_out_pre_stateful), priority=0    , match=(1), action=(next;)
      table=3 (ls_out_lb          ), priority=0    , match=(1), action=(next;)
      table=4 (ls_out_acl         ), priority=0    , match=(1), action=(next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[1] == 1), action=(ct_commit; next;)
      table=5 (ls_out_stateful    ), priority=100  , match=(reg0[2] == 1), action=(ct_lb;)
      table=5 (ls_out_stateful    ), priority=0    , match=(1), action=(next;)
      table=6 (ls_out_port_sec_ip ), priority=0    , match=(1), action=(next;)
      table=7 (ls_out_port_sec_l2 ), priority=100  , match=(eth.mcast), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw0-port1" && eth.dst == {00:00:00:00:00:01}), action=(output;)
      table=7 (ls_out_port_sec_l2 ), priority=50   , match=(outport == "sw0-port2" && eth.dst == {00:00:00:00:00:02}), action=(output;)

In this setup, ``sw0-port1`` and ``sw0-port2`` can send packets to each other,
but not to either of the ports on ``sw1``.  This first trace shows a packet
from ``sw0-port1`` to ``sw0-port2``.  You should see th packet arrive on
OpenFlow port ``1`` and output to OpenFlow port ``2``::

    $ ovn/env2/packet1.sh

This next example shows a packet from ``sw0-port1`` with a destination MAC
address of ``00:00:00:00:00:03``, which is the MAC address for ``sw1-port1``.
Since these ports are not on the same logical switch, the packet should just be
dropped::

    $ ovn/env2/packet2.sh


Two Hypervisors
---------------

The first two examples started by showing OVN on a single hypervisor.  A more
realistic deployment of OVN would span multiple hypervisors.  This example
creates a single logical switch with 4 logical ports.  It then simulates having
two hypervisors with two of the logical ports bound to each hypervisor::

    $ ovn/env3/setup.sh

You can start by viewing the logical topology with ``ovn-nbctl``::

    $ ovn-nbctl show
    switch b977dc03-79a5-41ba-9665-341a80e1abfd (sw0)
        port sw0-port1
            addresses: 00:00:00:00:00:01
        port sw0-port2
            addresses: 00:00:00:00:00:02
        port sw0-port4
            addresses: 00:00:00:00:00:04
        port sw0-port3
            addresses: 00:00:00:00:00:03

Using ``ovn-sbctl`` to view the state of the system, we can see that there are
two chassis: one local that we can interact with, and a fake remote chassis.
Two logical ports are bound to each.  Both chassis have an IP address of
localhost, but in a realistic deployment that would be the IP address used for
tunnels to that chassis::

    $ ovn-sbctl show
    Chassis "56b18105-5706-46ef-80c4-ff20979ab068"
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "sw0-port2"
        Port_Binding "sw0-port1"
    Chassis fakechassis
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "sw0-port4"
        Port_Binding "sw0-port3"

Packets between ``sw0-port1`` and ``sw0-port2`` behave just like the previous
examples.  Packets to ports on a remote chassis are the interesting part of
this example.  You may have noticed before that OVN's logical flows are broken
up into ingress and egress tables.  Given a packet from ``sw0-port1`` on the
local chassis to ``sw0-port3`` on the remote chassis, the ingress pipeline is
executed on the local switch.  OVN then determines that it must forward the
packet over a geneve tunnel.  When it arrives at the remote chassis, the egress
pipeline will be executed there.

This first packet trace shows the first part of this example.  It's a packet
from ``sw0-port1`` to ``sw0-port3`` from the perspective of the local chassis.
``sw0-port1`` is OpenFlow port ``1``.  The tunnel to the fake remote chassis is
OpenFlow port ``3``.  You should see the ingress pipeline being executed and
then the packet output to port ``3``, the geneve tunnel::

    $ ovn/env3/packet1.sh

To simulate what would happen when that packet arrives at the remote chassis we
can flip this example around.  Consider a packet from ``sw0-port3`` to
``sw0-port1``.  This trace shows what would happen when that packet arrives at
the local chassis.  The packet arrives on OpenFlow port ``3`` (the tunnel).
You should then see the egress pipeline get executed and the packet output to
OpenFlow port ``1``::

    $ ovn/env3/packet2.sh

Locally Attached Networks
-------------------------

While OVN is generally focused on the implementation of logical networks using
overlays, it's also possible to use OVN as a control plane to manage logically
direct connectivity to networks that are locally accessible to each chassis.

This example includes two hypervisors.  Both hypervisors have two ports on
them.  We want to use OVN to manage the connectivity of these ports to a
network attached to each hypervisor that we will call "physnet1".

This scenario requires some additional configuration of ``ovn-controller``.  We
must configure a mapping between ``physnet1`` and a local OVS bridge that
provides connectivity to that network.  We call these "bridge mappings".  For
our example, the following script creates a bridge called ``br-eth1`` and then
configures ``ovn-controller`` with a bridge mapping from ``physnet1`` to
``br-eth1``.

We want to create a fake second chassis and then create the topology that tells
OVN we want both ports on both hypervisors connected to ``physnet1``.  The way
this is modeled in OVN is by creating a logical switch for each port.  The
logical switch has the regular VIF port and a ``localnet`` port::

    $ ovn/env4/setup.sh

At this point we should be able to see that ``ovn-controller`` has
automatically created patch ports between ``br-int`` and ``br-eth1``::

    $ ovs-vsctl show
    c0a06d85-d70a-4e11-9518-76a92588b34e
        Bridge "br-eth1"
            Port "patch-provnet1-1-physnet1-to-br-int"
                Interface "patch-provnet1-1-physnet1-to-br-int"
                    type: patch
                    options: {peer="patch-br-int-to-provnet1-1-physnet1"}
            Port "br-eth1"
                Interface "br-eth1"
                    type: internal
            Port "patch-provnet1-2-physnet1-to-br-int"
                Interface "patch-provnet1-2-physnet1-to-br-int"
                    type: patch
                    options: {peer="patch-br-int-to-provnet1-2-physnet1"}
        Bridge br-int
            fail_mode: secure
            Port "ovn-fakech-0"
                Interface "ovn-fakech-0"
                    type: geneve
                    options: {key=flow, remote_ip="127.0.0.1"}
            Port "patch-br-int-to-provnet1-2-physnet1"
                Interface "patch-br-int-to-provnet1-2-physnet1"
                    type: patch
                    options: {peer="patch-provnet1-2-physnet1-to-br-int"}
            Port br-int
                Interface br-int
                    type: internal
            Port "patch-br-int-to-provnet1-1-physnet1"
                Interface "patch-br-int-to-provnet1-1-physnet1"
                    type: patch
                    options: {peer="patch-provnet1-1-physnet1-to-br-int"}
            Port "lport2"
                Interface "lport2"
            Port "lport1"
                Interface "lport1


The logical topology from ``ovn-nbctl`` should look like this::

    $ ovn-nbctl show
        switch 9db81140-5504-4f60-be3d-2bee45b57e27 (provnet1-2)
        port provnet1-2-port1
            addresses: ["00:00:00:00:00:02"]
        port provnet1-2-physnet1
            addresses: ["unknown"]
        switch cf175cb9-35c5-41cf-8bc7-2d322cdbead0 (provnet1-3)
        port provnet1-3-physnet1
            addresses: ["unknown"]
        port provnet1-3-port1
            addresses: ["00:00:00:00:00:03"]
        switch b85f7af6-8055-4db2-ba93-efc7887cf38f (provnet1-1)
        port provnet1-1-port1
            addresses: ["00:00:00:00:00:01"]
        port provnet1-1-physnet1
            addresses: ["unknown"]
        switch 63a5e276-8807-417d-bbec-a7e907e106b1 (provnet1-4)
        port provnet1-4-port1
            addresses: ["00:00:00:00:00:04"]
        port provnet1-4-physnet1
            addresses: ["unknown"]

``port1`` on each logical switch represents a regular logical port for a VIF on
a hypervisor.  ``physnet1`` on each logical switch is the special ``localnet``
port.  You can use ``ovn-nbctl`` to see that this port has a ``type`` and
``options`` set::

    $ ovn-nbctl lsp-get-type provnet1-1-physnet1
    localnet

    $ ovn-nbctl lsp-get-options provnet1-1-physnet1
    network_name=physnet1

The physical topology should reflect that there are two regular ports on each
chassis::

    $ ovn-sbctl show
    Chassis "56b18105-5706-46ef-80c4-ff20979ab068"
        hostname: sandbox
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "provnet1-1-port1"
        Port_Binding "provnet1-2-port1"
    Chassis fakechassis
        Encap geneve
            ip: "127.0.0.1"
        Port_Binding "provnet1-3-port1"
        Port_Binding "provnet1-4-port1"

All four of our ports should be able to communicate with each other, but they
do so through ``physnet1``.  A packet from any of these ports to any
destination should be output to the OpenFlow port number that corresponds to
the patch port to ``br-eth1``.

This example assumes following OpenFlow port number mappings:

* ``1`` = tunnel to the fake second chassis
* ``2`` = ``lport1``, which is the logical port named ``provnet1-1-port1``
* ``3`` = ``patch-br-int-to-provnet1-1-physnet1``, patch port to ``br-eth1``
* ``4`` = ``lport2``, which is the logical port named ``provnet1-2-port1``
* ``5`` = ``patch-br-int-to-provnet1-2-physnet1``, patch port to ``br-eth1``

We get those port numbers using ``ovs-ofctl``::

    $ ovs-ofctl show br-int
    OFPT_FEATURES_REPLY (xid=0x2): dpid:00002a84824b0d40
    n_tables:254, n_buffers:0
    capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
    actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst
     1(ovn-fakech-0): addr:aa:55:aa:55:00:0e
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     2(lport1): addr:aa:55:aa:55:00:0f
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     3(patch-br-int-to): addr:7a:6f:8a:d5:69:2a
         config:     0
         state:      0
         speed: 0 Mbps now, 0 Mbps max
     4(lport2): addr:aa:55:aa:55:00:10
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
     5(patch-br-int-to): addr:4a:fd:c1:11:fc:a5
         config:     0
         state:      0
         speed: 0 Mbps now, 0 Mbps max
     LOCAL(br-int): addr:2a:84:82:4b:0d:40
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
    OFPT_GET_CONFIG_REPLY (xid=0x4): frags=normal miss_send_len=0

This first trace shows a packet from ``provnet1-1-port1`` with a destination
MAC address of ``provnet1-2-port1``.  We expect the packets from ``lport1``
(OpenFlow port 2) to be sent out to ``lport2`` (OpenFlow port 4).  For example,
the following topology illustrates how the packets travel from ``lport1`` to
``lport2``::

    `lport1` --> `patch-br-int-to-provnet1-1-physnet1`(OpenFlow port 3)
    --> `br-eth1` --> `patch-br-int-to-provnet1-2-physnet1` --> `lport2`(OpenFlow port 4)

Similarly, We expect the packets from ``provnet1-2-port1`` to be sent out to
``provnet1-1-port1``.  We then expect the network to handle getting the packet
to its destination.  In practice, this will be optimized at ``br-eth1`` and the
packet won't actually go out and back on the network::

    $ ovn/env4/packet1.sh

This next trace shows an example of a packet being sent to a destination on
another hypervisor.  The source is ``provnet1-1-port1``, but the destination is
``provnet1-3-port1``, which is on the other fake chassis.  As usual, we expect
the output to be to ``br-eth1`` (``patch-br-int-to-provnet1-1-physnet1``,
OpenFlow port 3)::

    $ ovn/env4/packet2.sh

This next test shows a broadcast packet.  The destination should still only be
OpenFlow port 3 and 4::

    $ ovn/env4/packet3.sh

Finally, this last trace shows what happens when a broadcast packet arrives
from the network.  In this case, it simulates a broadcast that originated from a
port on the remote fake chassis and arrived at the local chassis via ``br-eth1``.
We should see it output to both local ports that are attached to this network
(OpenFlow ports 2 and 4)::

    $ ovn/env4/packet4.sh

Locally Attached Networks with VLANs
------------------------------------

This example is an extension of the previous one.  We take the same setup and
add two more ports to each hypervisor.  Instead of having the new ports
directly connected to ``physnet1`` as before, we indicate that we want them on
VLAN 101 of ``physnet1``.  This shows how ``localnet`` ports can be used to
provide connectivity to either a flat network or a VLAN on that network::

    $ ovn/env5/setup.sh

The logical topology shown by ``ovn-nbctl`` is similar to ``env4``, except we
now have 8 regular VIF ports connected to ``physnet1`` instead of 4.  The
additional 4 ports we have added are all on VLAN 101 of ``physnet1``.  Note
that the ``localnet`` ports representing connectivity to VLAN 101 of
``physnet1`` have the ``tag`` field set to ``101``::

    $ ovn-nbctl show
        switch 3e60b940-00bf-44c6-9db6-04abf28d7e5f (provnet1-1)
        port provnet1-1-physnet1
            addresses: ["unknown"]
        port provnet1-1-port1
            addresses: ["00:00:00:00:00:01"]
        switch 87f6bea0-f74d-4f39-aa65-ca1f94670429 (provnet1-2)
        port provnet1-2-port1
            addresses: ["00:00:00:00:00:02"]
        port provnet1-2-physnet1
            addresses: ["unknown"]
        switch e6c9cb69-a056-428d-aa40-e903ce416dcd (provnet1-6-101)
        port provnet1-6-101-port1
            addresses: ["00:00:00:00:00:06"]
        port provnet1-6-physnet1-101
            parent:
            tag: 101
            addresses: ["unknown"]
        switch 5f8f72ca-6030-4f66-baea-fe6174eb54df (provnet1-4)
        port provnet1-4-port1
            addresses: ["00:00:00:00:00:04"]
        port provnet1-4-physnet1
            addresses: ["unknown"]
        switch 15d585eb-d2c1-45ea-a946-b08de0eb2f55 (provnet1-7-101)
        port provnet1-7-physnet1-101
            parent:
            tag: 101
            addresses: ["unknown"]
        port provnet1-7-101-port1
            addresses: ["00:00:00:00:00:07"]
        switch 7be4aabe-1bb0-4e16-a755-a1f6d81c1c2f (provnet1-5-101)
        port provnet1-5-101-port1
            addresses: ["00:00:00:00:00:05"]
        port provnet1-5-physnet1-101
            parent:
            tag: 101
            addresses: ["unknown"]
        switch 9bbdbf0e-50f3-4286-ba5a-29bf347531bb (provnet1-8-101)
        port provnet1-8-101-port1
            addresses: ["00:00:00:00:00:08"]
        port provnet1-8-physnet1-101
            parent:
            tag: 101
            addresses: ["unknown"]
        switch 70d053f7-2bca-4dff-96ae-bd728d3ba1d2 (provnet1-3)
        port provnet1-3-physnet1
            addresses: ["unknown"]
        port provnet1-3-port1
            addresses: ["00:00:00:00:00:03"]

The physical topology shows that we have 4 regular VIF ports on each simulated
hypervisor::

    $ ovn-sbctl show
    Chassis fakechassis
        Encap geneve
        ip: "127.0.0.1"
        Port_Binding "provnet1-3-port1"
        Port_Binding "provnet1-8-101-port1"
        Port_Binding "provnet1-7-101-port1"
        Port_Binding "provnet1-4-port1"
    Chassis "56b18105-5706-46ef-80c4-ff20979ab068"
        hostname: sandbox
        Encap geneve
        ip: "127.0.0.1"
        Port_Binding "provnet1-2-port1"
        Port_Binding "provnet1-5-101-port1"
        Port_Binding "provnet1-1-port1"
        Port_Binding "provnet1-6-101-port1"

All of the traces from the previous example, ``env4``, should work in this
environment and provide the same result.  Now we can show what happens for the
ports connected to VLAN 101.  This first example shows a packet originating
from ``provnet1-5-101-port1``, which is OpenFlow port 6.  We should see VLAN
tag 101 pushed on the packet and then output to OpenFlow port 7, the patch port
to ``br-eth1`` (the bridge providing connectivity to ``physnet1``), and finally
arrives on OpenFlow port 8.

    $ ovn/env5/packet1.sh

If we look at a broadcast packet arriving on VLAN 101 of ``physnet1``, we
should see it output to OpenFlow ports 6 and 8 only::

    $ ovn/env5/packet2.sh

Stateful ACLs
-------------

ACLs provide a way to do distributed packet filtering for OVN networks.  One
example use of ACLs is that OpenStack Neutron uses them to implement security
groups.  ACLs are implemented using conntrack integration with OVS.

Start with a simple logical switch with 2 logical ports::

    $ ovn/env6/setup.sh

A common use case would be the following policy applied for ``sw0-port1``:

* Allow outbound IP traffic and associated return traffic.
* Allow incoming ICMP requests and associated return traffic.
* Allow incoming SSH connections and associated return traffic.
* Drop other incoming IP traffic.

The following script applies this policy to our environment::

    $ ovn/env6/add-acls.sh

We can view the configured ACLs on this network using the ``ovn-nbctl``
command::

    $ ovn-nbctl acl-list sw0
    from-lport  1002 (inport == "sw0-port1" && ip) allow-related
      to-lport  1002 (outport == "sw0-port1" && ip && icmp) allow-related
      to-lport  1002 (outport == "sw0-port1" && ip && tcp && tcp.dst == 22) allow-related
      to-lport  1001 (outport == "sw0-port1" && ip) drop

Now that we have ACLs configured, there are new entries in the logical flow
table in the stages ``switch_in_pre_acl``, ``switch_in_acl``,
``switch_out_pre_acl``, and ``switch_out_acl``.

    $ ovn-sbctl lflow-list

Let's look more closely at ``switch_out_pre_acl`` and ``switch_out_acl``.

In ``switch_out_pre_acl``, we match IP traffic and put it through the
connection tracker.  This populates the connection state fields so that we can
apply policy as appropriate::

    table=0(switch_out_pre_acl), priority=  100, match=(ip), action=(ct_next;)
    table=1(switch_out_pre_acl), priority=    0, match=(1), action=(next;)

In ``switch_out_acl``, we allow packets associated with existing connections.
We drop packets that are deemed to be invalid (such as non-SYN TCP packet not
associated with an existing connection)::

    table=1(switch_out_acl), priority=65535, match=(!ct.est && ct.rel && !ct.new && !ct.inv), action=(next;)
    table=1(switch_out_acl), priority=65535, match=(ct.est && !ct.rel && !ct.new && !ct.inv), action=(next;)
    table=1(switch_out_acl), priority=65535, match=(ct.inv), action=(drop;)

For new connections, we apply our configured ACL policy to decide whether to
allow the connection or not.  In this case, we'll allow ICMP or SSH.
Otherwise, we'll drop the packet::

    table=1(switch_out_acl), priority= 2002, match=(ct.new && (outport == "sw0-port1" && ip && icmp)), action=(ct_commit; next;)
    table=1(switch_out_acl), priority= 2002, match=(ct.new && (outport == "sw0-port1" && ip && tcp && tcp.dst == 22)), action=(ct_commit; next;)
    table=1(switch_out_acl), priority= 2001, match=(outport == "sw0-port1" && ip), action=(drop;)

When using ACLs, the default policy is to allow and track IP connections.
Based on our above policy, IP traffic directed at ``sw0-port1`` will never hit
this flow at priority 1::

    table=1(switch_out_acl), priority=    1, match=(ip), action=(ct_commit; next;)
    table=1(switch_out_acl), priority=    0, match=(1), action=(next;)

Note that conntrack integration is not yet supported in ovs-sandbox, so the
OpenFlow flows will not represent what you'd see in a real environment.  The
logical flows described above give a very good idea of what the flows look
like, though.

`This blog post
<http://blog.russellbryant.net/2015/10/22/openstack-security-groups-using-ovn-acls/>`__
discusses OVN ACLs from an OpenStack perspective and also provides an example
of what the resulting OpenFlow flows look like.

Container Ports
---------------

OVN supports containers running directly on the hypervisors and running
containers inside VMs. This example shows how OVN supports network
virtualization to containers when run inside VMs. Details about how to use
docker containers in OVS can be found in the `Docker installlation guide
<../INSTALL.Docker.rst>`__.

To support container traffic created inside a VM and to distinguish network
traffic coming from different container vifs, for each container a logical port
needs to be created with parent name set to the VM's logical port and the tag
set to the vlan tag of the container vif.

Start with a simple logical switch with three logical ports::

    $ ovn/env7/setup.sh

Lets create a container vif attached to the logical port ``sw0-port1`` and
another container vif attached to the logical port ``sw0-port2``::

    $ ovn/env7/add-container-ports.sh

Run the ``ovn-nbctl`` command to see the logical ports::

    $ovn-nbctl show

As you can see a logical port ``csw0-cport1`` is created on a logical switch
'csw0' whose parent is ``sw0-port1`` and it has tag set to ``42``.  In
addition, a logical port ``csw0-cport2`` is created on the logical switch
``csw0`` whose parent is ``sw0-port2`` and it has tag set to ``43``.

Bridge ``br-vmport1`` represents the ovs bridge running inside the VM connected
to the logical port ``sw0-port1``. In this tutorial the ovs port to
``sw0-port1`` is created as a patch port with its peer connected to the ovs
bridge ``br-vmport1``. An ovs port ``cport1`` is added to ``br-vmport1`` which
represents the container interface connected to the ovs bridge and vlan tag set
to ``42``. Similarly ``br-vmport2`` represents the ovs bridge for the logical
port ``sw0-port2`` and ``cport2`` connected to ``br-vmport2`` with vlan tag set
to ``43``.

This first trace shows a packet from ``csw0-port1`` with a destination mac
address of ``csw0-port2``. You can see ovs bridge of the vm ``br-vmport1`` tags
the traffic with vlan id ``42`` and the traffic reaches to the br-int because
of the patch port. As you can see below ``ovn-controller`` has added a flow to
strip the vlan tag and set the reg6 and metadata appropriately::

    $ ovs-ofctl -O OpenFlow13 dump-flows br-int
    OFPST_FLOW reply (OF1.3) (xid=0x2):
    cookie=0x0, duration=2767.032s, table=0, n_packets=0, n_bytes=0, priority=150,in_port=3,dl_vlan=42 actions=pop_vlan,set_field:0x3->reg5,set_field:0x2->metadata,set_field:0x1->reg6,resubmit(,16)
    cookie=0x0, duration=2767.002s, table=0, n_packets=0, n_bytes=0, priority=150,in_port=4,dl_vlan=43 actions=pop_vlan,set_field:0x4->reg5,set_field:0x2->metadata,set_field:0x2->reg6,resubmit(,16)
    cookie=0x0, duration=2767.032s, table=0, n_packets=0, n_bytes=0, priority=100,in_port=3 actions=set_field:0x1->reg5,set_field:0x1->metadata,set_field:0x1->reg6,resubmit(,16)
    cookie=0x0, duration=2767.001s, table=0, n_packets=0, n_bytes=0, priority=100,in_port=4 actions=set_field:0x2->reg5,set_field:0x1->metadata,set_field:0x2->reg6,resubmit(,16)

::

    $ ovn/env7/packet1.sh

The second trace shows a packet from ``csw0-port2`` to ``csw0-port1``::

    $ ovn/env7/packet2.sh

You can extend this setup by adding additional container ports with two
hypervisors. Refer to tutorial three above.

L2Gateway Ports
---------------

L2Gateway provides a way to connect logical switch ports of type ``l2gateway``
to a physical network.  The difference between ``l2gateway`` ports and
``localnet`` ports is that an ``l2gateway`` port is bound to a specific
chassis.  A single chassis serves as the L2 gateway to the physical network and
all traffic between chassis continues to go over geneve tunnels.

Start with a simple logical switch with three logical ports::

    $ ovn/env8/setup.sh

This first example shows a packet originating from ``lport1``, which is
OpenFlow port 1.  We expect all packets from ``lport1`` to be sent out to
``br-eth1`` (``patch-br-int-to-sw0-port3``, OpenFlow port 3).  The patch port
to ``br-eth1`` provides connectivity to the physical network.

    $ ovn/env8/packet1.sh

The last trace shows what happens when a broadcast packet arrives from the
network.  In this case, it simulates a broadcast that originated from a port on
the physical network and arrived at the local chassis via ``br-eth1``. We
should see it output to the local ports ``lport1`` and ``lport2``::

    $ ovn/env8/packet2.sh

.. _ovn-architecture: http://openvswitch.org/support/dist-docs/ovn-architecture.7.html
.. _Tutorial: https://github.com/openvswitch/ovs/blob/master/tutorial/tutorial.rst
.. _ovn-nb(5): http://openvswitch.org/support/dist-docs/ovn-nb.5.html
.. _ovn-sb(5): http://openvswitch.org/support/dist-docs/ovn-sb.5.html
.. _vtep(5): http://openvswitch.org/support/dist-docs/vtep.5.html
.. _ovn-northd(8): http://openvswitch.org/support/dist-docs/ovn-northd.8.html
.. _ovn-controller(8): http://openvswitch.org/support/dist-docs/ovn-controller.8.html
.. _ovn-controller-vtep(8): http://openvswitch.org/support/dist-docs/ovn-controller-vtep.8.html
.. _vtep-ctl(8): http://openvswitch.org/support/dist-docs/vtep-ctl.8.html
.. _ovn-nbctl(8): http://openvswitch.org/support/dist-docs/ovn-nbctl.8.html
.. _ovn-sbctl(8): http://openvswitch.org/support/dist-docs/ovn-sbctl.8.html
