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

==================================
Visualizing flows with ovs-flowviz
==================================

When troubleshooting networking issues with OVS, it's common to end up looking
at OpenFlow or datapath flow dumps. These dumps tend to be quite dense and
difficult to reason about.

``ovs-flowviz`` is a utility script that helps visualizing OpenFlow and
datapath flows to make it easier to understand what is going on.

The `ovs-flowviz(8)`_ manpage describes its basic usage. In this document a few
of its advanced visualization formats will be expanded.


Installing ovs-flowviz
----------------------

``ovs-flowviz`` is part of the openvswitch python package but its
extra dependencies have to be installed explicitly by running:
::

    $ pip install openvswitch[flowviz]

Or, if you are working with the OVS tree:
::

    $ cd python && pip install .[flowviz]

Visualizing OpenFlow logical block
----------------------------------

When controllers such as OVN write OpenFlow flows, they typically organize
flows in functional blocks. These blocks can expand to multiple flows that
"look similar", in the sense that they match on the same fields and have
similar actions.

However, looking at a flow dump the number of flows can make it difficult
to perceive this logical functionality that the controller is trying to
implement using OpenFlow.

``ovs-flowviz openflow logic`` visualization can be used to understand an OVN
flow dump a bit better.

On a particular flow dump table 0 contains 23 flows:
::

   $ grep -c "table=0" flows.txt
   23

Looking at the first few lines, the amount of information can be
overwhelming and difficult our analysis:

::

    $ head flows.txt
      cookie=0xf76b4b20, duration=765.107s, table=0, n_packets=0, n_bytes=0, priority=180,vlan_tci=0x0000/0x1000 actions=conjunction(100,2/2)
      cookie=0xf76b4b20, duration=765.107s, table=0, n_packets=0, n_bytes=0, priority=180,conj_id=100,in_port="patch-br-int-to",vlan_tci=0x0000/0x1000 actions=load:0xa->NXM_NX_REG13[],load:0xc->NXM_NX_REG11[],load:0xb->NXM_NX_REG12[],load:0xb->OXM_OF_METADATA[],load:0x1->NXM_NX_REG14[],mod_dl_src:02:42:ac:12:00:03,resubmit(,8)
      cookie=0x0, duration=765.388s, table=0, n_packets=0, n_bytes=0, priority=100,in_port="ovn-6bb3b3-0" actions=move:NXM_NX_TUN_ID[0..23]->OXM_OF_METADATA[0..23],move:NXM_NX_TUN_METADATA0[16..30]->NXM_NX_REG14[0..14],move:NXM_NX_TUN_METADATA0[0..15]->NXM_NX_REG15[0..15],resubmit(,40)
      cookie=0x0, duration=765.388s, table=0, n_packets=0, n_bytes=0, priority=100,in_port="ovn-a6ff98-0" actions=move:NXM_NX_TUN_ID[0..23]->OXM_OF_METADATA[0..23],move:NXM_NX_TUN_METADATA0[16..30]->NXM_NX_REG14[0..14],move:NXM_NX_TUN_METADATA0[0..15]->NXM_NX_REG15[0..15],resubmit(,40)
      cookie=0xf2ca6195, duration=765.107s, table=0, n_packets=6, n_bytes=636, priority=100,in_port="ovn-k8s-mp0" actions=load:0x1->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x2->NXM_NX_REG14[],resubmit(,8)
      cookie=0x236e941d, duration=408.874s, table=0, n_packets=11, n_bytes=846, priority=100,in_port=aceac9829941d11 actions=load:0x11->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x3->NXM_NX_REG14[],resubmit(,8)
      cookie=0x3facf689, duration=405.581s, table=0, n_packets=11, n_bytes=846, priority=100,in_port="363ba22029cd92b" actions=load:0x12->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x4->NXM_NX_REG14[],resubmit(,8)
      cookie=0xe7c8c4bb, duration=405.570s, table=0, n_packets=11, n_bytes=846, priority=100,in_port="6a62cde0d50ef44" actions=load:0x13->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x5->NXM_NX_REG14[],resubmit(,8)
      cookie=0x99a0ffc1, duration=59.391s, table=0, n_packets=8, n_bytes=636, priority=100,in_port="5ff3bfaaa4eb622" actions=load:0x14->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x6->NXM_NX_REG14[],resubmit(,8)
      cookie=0xe1b5c263, duration=59.365s, table=0, n_packets=8, n_bytes=636, priority=100,in_port="8d9e0bc76347e59" actions=load:0x15->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x7->NXM_NX_REG14[],resubmit(,8)


However, table 0 can be better understood by looking at its logical
representation:
::

   $ ovs-flowviz -i flows.txt -f "table=0" openflow logic
    Ofproto Flows (logical)
    └── ** TABLE 0 **
        ├── priority=180 priority,vlan_tci  --->  conjunction ( x 1 )
        ├── priority=180 priority,conj_id,in_port,vlan_tci  --->  load,load,load,load,load,mod_dl_src resubmit(,8), ( x 1 )
        ├── priority=100 priority,in_port  --->  move,move,move resubmit(,40), ( x 2 )
        ├── priority=100 priority,in_port  --->  load,load,load,load,load resubmit(,8), ( x 16 )
        ├── priority=100 priority,in_port,vlan_tci  --->  load,load,load,load,load resubmit(,8), ( x 1 )
        ├── priority=100 priority,in_port,dl_vlan  --->  strip_vlan,load,load,load,load,load resubmit(,8), ( x 1 )
        └── priority=0 priority  --->   drop, ( x 1 )


In only a few logical blocks, there is a good overview of what this table is
doing. It looks like it's adding metadata based on input ports and vlan
IDs and mainly sending traffic to table 8.

A possible next step might be to look at table 8, and in this case, filter out
the flows that have not been hit by actual traffic.
This is quite easy to do with the arithmetic filtering expressions:
::

   $ ovs-flowviz -i flows.txt -f "table=8 and n_packets>0" openflow logic

    Ofproto Flows (logical)
    └── ** TABLE 8 **
        ├── priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 3 )
        └── priority=50 priority,metadata  --->  load,move resubmit(,73),resubmit(,9), ( x 2 )

At this point, understanding the output might be difficult without relating it
to the matadata OVN stored in the previous table. This is where
``ovs-flowviz``'s OVN integration is useful:
::

    $ export OVN_NB_DB=tcp:172.18.0.4:6641
    $ export OVN_SB_DB=tcp:172.18.0.4:6642
    $ ovs-flowviz -i flows.txt -f "table=8 and n_packets>0" openflow logic --ovn-detrace
    Ofproto Flows (logical)
    └── ** TABLE 8 **
        ├── cookie=0xe10c34ee priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "ovn_cluster_router" (366e1c41-0f3d-4420-b796-10692b64e3e4)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.mcast && inport == "rtos-ovn-worker2), actions=(xreg0[0..47] = 0a:58:0a:f4:01:01; next;)
        │       └── *  Logical Router Port: rtos-ovn-worker2 mac 0a:58:0a:f4:01:01 networks ['10.244.1.1/24'] ipv6_ra_configs {}
        ├── cookie=0x11e1adbc priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "GR_ovn-worker2" (c07f8387-6479-4e81-9304-9f8e54f81c56)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.mcast && inport == "rtoe-GR_ovn-worker2), actions=(xreg0[0..47] = 02:42:ac:12:00:03; next;)
        │       └── *  Logical Router Port: rtoe-GR_ovn-worker2 mac 02:42:ac:12:00:03 networks ['172.18.0.3/16'] ipv6_ra_configs {}
        ├── cookie=0xf42133f  priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "GR_ovn-worker2" (c07f8387-6479-4e81-9304-9f8e54f81c56)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.dst == 02:42:ac:12:00:03 && inport == "rtoe-GR_ovn-worker2), actions=(xreg0[0..47] = 02:42:ac:12:00:03; next;)
        │       └── *  Logical Router Port: rtoe-GR_ovn-worker2 mac 02:42:ac:12:00:03 networks ['172.18.0.3/16'] ipv6_ra_configs {}
        └── cookie=0x43a0327  priority=50 priority,metadata  --->  load,move resubmit(,73),resubmit(,9), ( x 2 )
            └── OVN Info
                ├── *  Logical datapaths:
                ├── *      "ovn-worker" (24280d0b-fee0-4f8e-ba4f-036a9b9af921)
                ├── *      "ovn-control-plane" (3262a782-8961-416b-805e-08233e8fda72)
                ├── *      "ext_ovn-worker2" (3f88dcd2-c56d-478f-a3b1-c7aee2efe967)
                ├── *      "ext_ovn-worker" (5facbaf0-485d-4cf5-8940-eff9678ef7bb)
                ├── *      "ext_ovn-control-plane" (8b0aecb6-b05a-48a7-ad09-72524bb91d40)
                ├── *      "join" (e2dc230e-2f2a-4b93-93fa-0fe495163514)
                ├── *      "ovn-worker2" (f7709fbf-d728-4cff-9b9b-150461cc75d2)
                └── *  Logical flow: table=0 (ls_in_check_port_sec), priority=50, match=(1), actions=(reg0[15] = check_in_port_sec(); next;)

``ovs-flowviz`` has automatically added the `cookie` to the logical block key
so more blocks have been printed. In exchange, it has looked up each cookie on
the running OVN databases and inserted the known information on each
block.

The logical flow that generated each OpenFlow flow and the logical datapath
it belongs to are now printed, making OVN's pipeline clearer.

Visualizing datapath flow trees
-------------------------------

Another typical usecase that can lead to eyestrain is understanding datapath
conntrack recirculations.

OVS makes heavy use of connection tracking and the ``recirc()`` action
to build complex datapaths. Typically, OVS will insert a flow that,
when matched, will send the packet through conntrack (using the ``ct`` action)
and recirculate it with a particular recirculation id (``recirc_id``). Then,
flows matching on that ``recirc_id`` will be matched and further process the
packet. This can happen more than once for a given packet.

This sequential set of events is, however, difficult to visualize when you
look at a datapath flow dump. Flows are unordered so recirculations need to
be followed manually (typically, with heavy use of "grep").

For this use-case, ``ovs-flowviz datapath tree`` format can be extremely
useful. It builds a hierarchical tree based on the ``recirc_id``, ``in_port``
and ``recirc()`` actions.

Furthermore, it is common to end up with multiple flows that have the same
list of actions. An example of this is a number flows that perform mac/vlan
checks for a given port and send the traffic though the same conntrack zone.
In order to better visualize this and reduce the amount of duplicated flows
that are printed in this view, these flows are combined into a block, and the
match keys that are equal for all flows are removed.

For example:
::

  Datapath Flows (logical)
  └── ╭────────────────────────────────╮
      │ [recirc_id(0x0) in_port(eth0)] │
      ╰────────────────────────────────╯
      └── ╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
          │ recirc_id(0),dp_hash(0/0),skb_priority(0/0),in_port(eth0),skb_mark(0/0),ct_state(0/0),ct_zone(0/0),ct_mark(0/0),ct_label(0/0),eth(src=0a:58:0a:84:00:07,dst=22:a1:5d:dc:95:50),eth_type(0x0800),ipv4(src=10.132.0.7,dst=1 │
          │ 0.128.0.0/255.128.0.0,proto=6,tos=0/0,ttl=0/0,frag=no),tcp(src=0/0,dst=0/0),tcp_flags(0/0), packets:4924, bytes:468961,                                                                                                   │
          │ recirc_id(0),dp_hash(...),skb_priority(...),in_port(eth0),skb_mark(...),ct_state(...),ct_zone(...),ct_mark(...),ct_label(...),eth(src=0a:58:0a:84:00:07,dst=0a:58:0a:84:00:01),eth_type(......),ipv4(src=10.132.0.7,dst=1 │
          │ 0.0.0.0/255.255.128.0,proto=17,tos=0/0,ttl=0/0,frag=no),udp(src=32768/0x8000,dst=0/0), packets:711, bytes:114236,                                                                                                         │
          │ recirc_id(0),dp_hash(...),skb_priority(...),in_port(eth0),skb_mark(...),ct_state(...),ct_zone(...),ct_mark(...),ct_label(...),eth(src=0a:58:0a:84:00:07,dst=0a:58:0a:84:00:14),eth_type(......),ipv4(src=10.132.0.7,dst=1 │
          │ 0.128.0.0/255.128.0.0,proto=17,tos=0/0,ttl=0/0,frag=no),udp(src=4096/0xf000,dst=0/0), packets:140, bytes:114660,                                                                                                          │
          │ recirc_id(0),dp_hash(...),skb_priority(...),in_port(eth0),skb_mark(...),ct_state(...),ct_zone(...),ct_mark(...),ct_label(...),eth(src=0a:58:0a:84:00:07,dst=0a:58:0a:84:00:22),eth_type(......),ipv4(src=10.132.0.7,dst=1 │
          │ 0.128.0.0/255.128.0.0,proto=6,tos=0/0,ttl=0/0,frag=no),tcp(src=0/0,dst=0/0),tcp_flags(0/0), packets:1, bytes:66,                                                                                                          │
          │ recirc_id(0),dp_hash(...),skb_priority(...),in_port(eth0),skb_mark(...),ct_state(...),ct_zone(...),ct_mark(...),ct_label(...),eth(src=0a:58:0a:84:00:07,dst=0a:58:0a:84:00:09),eth_type(......),ipv4(src=10.132.0.7,dst=1 │
          │ 0.128.0.0/255.128.0.0,proto=17,tos=0/0,ttl=0/0,frag=no),udp(src=4096/0xf000,dst=0/0), packets:0, bytes:0,                                                                                                                 │
          ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
          └── ╭───────────────────────────────────────╮
              │ actions: ct(zone=32,nat),recirc(0xc1) │
              ╰───────────────────────────────────────╯
              └── ╭─────────────────────────────────╮
                  │ [recirc_id(0xc1) in_port(eth0)] │
                  ╰─────────────────────────────────╯
                  ├── ╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
                  │   │ recirc_id(0xc1),dp_hash(0/0),skb_priority(0/0),in_port(eth0),skb_mark(0/0),ct_state(0x2a/0x3f),ct_zone(0/0),ct_mark(0/0xf),ct_label(0/0),eth(src=0a:58:0a:84:00:07,dst=22:a1:5d:dc:95:50),eth_type(0x0800),ip │
                  │   │ v4(src=0.0.0.0/0.0.0.0,dst=0.0.0.0/0.0.0.0,proto=6,tos=0/0,ttl=0/0,frag=no),tcp(src=0/0,dst=0/0),tcp_flags(0/0), packets:4924, bytes:468961,                                                                  │
                  │   ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                  │   └── ╭───────────────────────────────────────╮
                  │       │ actions: ct(zone=14,nat),recirc(0xc2) │
                  │       ╰───────────────────────────────────────╯
                  │       └── ╭─────────────────────────────────╮
                  │           │ [recirc_id(0xc2) in_port(eth0)] │
                  │           ╰─────────────────────────────────╯
                  │           └── ╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
                  │               │ recirc_id(0xc2),dp_hash(0/0),skb_priority(0/0),in_port(eth0),skb_mark(0/0),ct_state(0x2a/0x3f),ct_zone(0/0),ct_mark(0/0x1),ct_label(0/0),eth(src=00:00:00:00:00:00/00:00:00:00:00:00,dst=00:00:00 │
                  │               │ :00:00:00/01:00:00:00:00:00),eth_type(0x0800),ipv4(src=0.0.0.0/0.0.0.0,dst=0.0.0.0/0.0.0.0,proto=0/0,tos=0/0,ttl=0/0,frag=no), packets:4924, bytes:468961,                                        │
                  │               ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                  │               └── ╭──────────────────────╮
                  │                   │ actions: ovn-k8s-mp0 │
                  │                   ╰──────────────────────╯
                  ├── ╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
                  │   │ recirc_id(0xc1),dp_hash(0/0),skb_priority(0/0),in_port(eth0),skb_mark(0/0),ct_state(0x2a/0x3f),ct_zone(0/0),ct_mark(0/0xf),ct_label(0/0),eth(src=0a:58:0a:84:00:07,dst=0a:58:0a:84:00:14),eth_type(0x0800),ip │
                  │   │ v4(src=0.0.0.0/0.0.0.0,dst=0.0.0.0/0.0.0.0,proto=17,tos=0/0,ttl=0/0,frag=no),udp(src=4096/0xf000,dst=0/0), packets:140, bytes:114660                                                                          │
                  │   ╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯


The above shows a part of a bigger tree with an initial block of flows
at ``recirc_id(0)`` which match on different destination Ethernet
addresses and protocols, and send traffic through conntrack (zone 32).

Then some additional flows at ``recirc_id(0xc1)`` process each
connection independently. One of them, shown in the example, sends packets
through conntrack zone 14, and after another recirculation the packet is
ultimately sent through a port.

This is a truly complex multi-zone conntrack pipeline that is now significantly
clearer thanks to this visualization.

Also note, the flows in the block are conveniently sorted by sent packets.

This example shows only a single "subtree". Even though the combination of
flows with the same action helps, if we use this command to display a large
dump, the output can be verbose. There are two, combinable, mechanisms that
can help.


Plotting datapath trees
~~~~~~~~~~~~~~~~~~~~~~~

By using the ``ovs-flowviz datapath html`` format, long datapath trees can
be displayed in an interactive HTML table. The resulting web page allows
subtrees to be expanded and collapsed, allowing focus on the desired
information.

The ``ovs-flowviz datapath graph`` format generates a graphviz
graph definition where blocks of flows with the same ``recirc_id`` match
are arranged together, and edges are created to represent recirculations.
This format comes with further features such as displaying the conntrack
zones, which are key to understanding what the datapath is really doing with a
packet.

The ``html`` and ``graph`` can also be combined.
``ovs-flowviz datapath graph --html`` command will output an interactive
HTML table alongside a SVG graphical representation of the flows. Flows in the
SVG representation link to the corresponding entry in the HTML table.


Filtering
~~~~~~~~~

As well as allowing expanding and collapsing subtrees, filtering can be used.

However, filtering works in a slightly different way than it does with OpenFlow
flows. Instead of just removing non-matching flows, the output of a filtered
datapath flow tree will show full sub-trees containing at least one flow that
satisfies the filter.

For example, the following command allows understanding the flows in the above
example in the context of traffic going out on port ``ovn-k8s-mp0``:
::

   $ ovs-appctl dpctl/dump-flows | ovs-flowviz -f "output.port=ovn-k8s-mp0" datapath tree

The resulting flow tree will contain all of the flows above, including those
with ``recirc_id(0)`` and ``recirc_id(0xc1)`` that don't actually output
traffic to port ``ovn-k8s-mp0``. This is because they are part of a subtree
that contains flows that output packets on port ``ovn-k8s-mp0``

This provides a "full picture" of how traffic, ending up in a particular
port, is being processed.

.. _ovs-flowviz(8): https://docs.openvswitch.org/en/latest/ref/ovs-flowviz.8
