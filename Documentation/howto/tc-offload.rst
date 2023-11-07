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

==========================================
Flow Hardware offload with Linux TC flower
==========================================

This document describes how to offload flows with TC flower.

Flow Hardware Offload
---------------------

The flow hardware offload is disabled by default and can be enabled by::

    $ ovs-vsctl set Open_vSwitch . other_config:hw-offload=true

TC flower has one additional configuration option caled ``tc-policy``.
For more details see ``man ovs-vswitchd.conf.db``.

TC Meter Offload
----------------

Offloading meters to TC does not require any additional configuration and is
enabled automatically when possible. Offloading with meters does require the
tc-police action to be available in the Linux kernel. For more details on the
tc-police action, see ``man tc-police``.


Configuration
~~~~~~~~~~~~~

There is no parameter change in ovs-ofctl command, to configue a meter and use
it for a flow in the offload way. Usually the commands are like::

    $ ovs-ofctl -O OpenFlow13 add-meter br0 "meter=1 pktps bands=type=drop rate=1"
    $ ovs-ofctl -O OpenFlow13 add-flow br0 "priority=10,in_port=ovs-p0,udp actions=meter:1,normal"

For more details, see ``man ovs-ofctl``.

.. note::
  Each meter is mapped to one TC police action. To avovid the conflicton, the
  police action index of 0x10000000-0x1fffffff are resevered for the mapping.
  You can check the police actions by the command ``tc action ls action police``
  in Linux system.


Known TC flow offload limitations
---------------------------------

General
~~~~~~~

These sections describe limitations to the general TC flow offload
implementation.

Flow bytes count
++++++++++++++++

Flows that are offloaded with TC do not include the L2 bytes in the packet
byte count. Take the datapath flow dump below as an example. The first one
is from the none-offloaded case the second one is from a TC offloaded flow::

    in_port(2),eth(macs),eth_type(0x0800),ipv4(proto=17,frag=no), packets:10, bytes:470, used:0.001s, actions:outputmeter(0),3

    in_port(2),eth(macs),eth_type(0x0800),ipv4(proto=17,frag=no), packets:10, bytes:330, used:0.001s, actions:outputmeter(0),3

As you can see above the none-offload case reports 140 bytes more, which is 14
bytes per packet. This represents the L2 header, in this case, 2 * *Ethernet
address* + *Ethertype*.

TC Meter Offload
~~~~~~~~~~~~~~~~

These sections describe limitations related to the TC meter offload
implementation.

Missing byte count drop statistics
++++++++++++++++++++++++++++++++++

The kernel's TC infrastructure is only counting the number of dropped packet,
not their byte size. This results in the meter statistics always showing 0
for byte_count. Here is an example::

    $ ovs-ofctl -O OpenFlow13 meter-stats br0
    OFPST_METER reply (OF1.3) (xid=0x2):
    meter:1 flow_count:1 packet_in_count:11 byte_in_count:377 duration:3.199s bands:
    0: packet_count:9 byte_count:0

First flow packet not processed by meter
++++++++++++++++++++++++++++++++++++++++

Packets that are received by ovs-vswitchd through an upcall before the actual
meter flow is installed, are not passing TC police action and therefore are
not considered for policing.

Conntrack Application Layer Gateways (ALG)
++++++++++++++++++++++++++++++++++++++++++

TC does not support conntrack helpers, i.e., ALGs. TC will not offload flows if
the ALG keyword is present within the ct() action. However, this will not allow
ALGs to work within the datapath, as the return traffic without the ALG keyword
might run through a TC rule, which internally will not call the conntrack
helper required.

So if ALG support is required, tc offload must be disabled.
