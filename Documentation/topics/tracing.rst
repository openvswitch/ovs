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

===================================
Tracing packets inside Open vSwitch
===================================

Open vSwitch (OVS) is a programmable software switch that can execute actions
at per packet level. This document explains how to use the tracing tool
to know what is happening with packets as they go through the data plane
processing.

The `ovs-vswitchd(8)`_ manpage describes basic usage of the
ofproto/trace command used for tracing in Open vSwitch.

Packet Tracing
--------------

In order to understand the tool, let's use the following flows as an
example::

    table=3,ip,tcp,tcp_dst=80,action=output:2
    table=2,ip,tcp,tcp_dst=22,action=output:1
    table=0,in_port=3,ip,nw_src=192.0.2.0/24,action=resubmit(,2)
    table=0,in_port=3,ip,nw_src=198.51.100.0/24,action=resubmit(,3)

.. note::
    If you can't use a "real" OVS setup you can use ``ovs-sandbox``,
    as described in :doc:`/tutorials/ovs-advanced`, which also provides
    additional tracing examples.

The first line adds a rule in table 3 matching on TCP/IP packet with
destination port 80 (HTTP). If a packet matches, the action is to output the
packet on OpenFlow port 2.

The second line is similar but matches on destination port 22. If a packet
matches, the action is to output the packet on OpenFlow port 1.

The next two lines matches on source IP addresses. If there is a match, the
packet is submitted to table indicated as parameter to the resubmit() action.

Now let's see if a packet from IP address 192.0.2.1 and destination
port 22 would really go to OpenFlow port 1::

    $ ovs-appctl ofproto/trace br0 in_port=3,tcp,nw_src=192.0.2.2,tcp_dst=22
    Flow: tcp,in_port=3,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,nw_src=192.0.2.2,nw_dst=0.0.0.0,nw_tos=0,nw_ecn=0,nw_ttl=0,tp_src=0,tp_dst=22,tcp_flags=0

    bridge("br0")
    -------------
     0. ip,in_port=3,nw_src=192.0.2.0/24, priority 32768
        resubmit(,2)
     2. tcp,tp_dst=22, priority 32768
        output:1

    Final flow: unchanged
    Megaflow: recirc_id=0,tcp,in_port=3,nw_src=192.0.2.0/24,nw_frag=no,tp_dst=22
    Datapath actions: 1

The first line is the trace command. The br0 is the bridge where the packet is
going through. The next arguments describe the packet itself. For instance,
the nw_src matches with the IP source address. All the packet fields are well
documented in the `ovs-fields(7)`_ man-page.

The second line shows the flow extracted from the packet described in the
command line. Unspecified packet fields are zeroed.

The second group of lines shows the packet's trip through bridge br0. We see,
in table 0, the OpenFlow flow that the fields matched, along with its
priority, followed by its actions, one per line. In this case, we see that
this packet matches the flow that resubmit those packets to table 2.
The "resubmit" causes a second lookup in OpenFlow table 2, described by the
block of text that starts with "2.". In the second lookup we see that this
packet matches the rule that outputs those packets to OpenFlow port #1.

In summary, it is possible to follow the flow entries and actions until the
final decision is made. At the end, the trace tool shows the Megaflow which
matches on all relevant fields followed by the data path actions.

Let's see what happens with the same packet but with another TCP destination
port::

    $ ovs-appctl ofproto/trace br0 in_port=3,tcp,nw_src=192.0.2.2,tcp_dst=80
    Flow: tcp,in_port=3,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,nw_src=192.0.2.2,nw_dst=0.0.0.0,nw_tos=0,nw_ecn=0,nw_ttl=0,tp_src=0,tp_dst=80,tcp_flags=0

    bridge("br0")
    -------------
     0. ip,in_port=3,nw_src=192.0.2.0/24, priority 32768
        resubmit(,2)
     2. No match.
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,tcp,in_port=3,nw_src=192.0.2.0/24,nw_frag=no,tp_dst=0x40/0xffc0
    Datapath actions: drop

In the second group of lines, in table 0, you can see that the packet matches
with the rule because of the source IP address, so it is resubmitted to the
table 2 as before. However, it doesn't match any rule there. When the packet
doesn't match any rule in the flow tables, it is called a table miss. The
virtual switch table miss behavior can be configured and it depends on the
OpenFlow version being used. In this example the default action was to drop the
packet.

Credits
-------

This document is heavily based on content from Flavio Bruno Leitner at Red Hat:

- https://developers.redhat.com/blog/2016/10/12/tracing-packets-inside-open-vswitch/

.. _ovs-vswitchd(8): http://openvswitch.org/support/dist-docs/ovs-vswitchd.8.html
.. _ovs-fields(7): http://openvswitch.org/support/dist-docs/ovs-fields.7.pdf
