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

========================
Quality of Service (QoS)
========================

It is possible to apply both ingress and egress limiting when using the DPDK
datapath. These are referred to as *QoS* and *Rate Limiting*, respectively.

.. versionadded:: 2.7.0

QoS (Egress Policing)
---------------------

Single Queue Policer
~~~~~~~~~~~~~~~~~~~~

Assuming you have a :doc:`vhost-user port <vhost-user>` transmitting traffic
consisting of packets of size 64 bytes, the following command would limit the
egress transmission rate of the port to ~1,000,000 packets per second::

    $ ovs-vsctl set port vhost-user0 qos=@newqos -- \
        --id=@newqos create qos type=egress-policer other-config:cir=46000000 \
        other-config:cbs=2048`

To examine the QoS configuration of the port, run::

    $ ovs-appctl -t ovs-vswitchd qos/show vhost-user0

To clear the QoS configuration from the port and ovsdb, run::

    $ ovs-vsctl destroy QoS vhost-user0 -- clear Port vhost-user0 qos


Multi Queue Policer
~~~~~~~~~~~~~~~~~~~

In addition to the egress-policer OVS-DPDK also has support for a RFC
4115's Two-Rate, Three-Color marker meter. It's a two-level hierarchical
policer which first does a color-blind marking of the traffic at the queue
level, followed by a color-aware marking at the port level. At the end
traffic marked as Green or Yellow is forwarded, Red is dropped. For
details on how traffic is marked, see RFC 4115.

This egress policer can be used to limit traffic at different rated
based on the queues the traffic is in. In addition, it can also be used
to prioritize certain traffic over others at a port level.

For example, the following configuration will limit the traffic rate at a
port level to a maximum of 2000 packets a second (64 bytes IPv4 packets).
1000pps as CIR (Committed Information Rate) and 1000pps as EIR (Excess
Information Rate). CIR and EIR are measured in bytes without Ethernet header.
As a result, 1000pps means (64-byte - 14-byte) * 1000 = 50,000 in the
configuration below. High priority traffic is routed to queue 10, which marks
all traffic as CIR, i.e. Green. All low priority traffic, queue 20, is
marked as EIR, i.e. Yellow::

    $ ovs-vsctl --timeout=5 set port dpdk1 qos=@myqos -- \
        --id=@myqos create qos type=trtcm-policer \
        other-config:cir=50000 other-config:cbs=2048 \
        other-config:eir=50000 other-config:ebs=2048  \
        queues:10=@dpdk1Q10 queues:20=@dpdk1Q20 -- \
         --id=@dpdk1Q10 create queue \
          other-config:cir=100000 other-config:cbs=2048 \
          other-config:eir=0 other-config:ebs=0 -- \
         --id=@dpdk1Q20 create queue \
           other-config:cir=0 other-config:cbs=0 \
           other-config:eir=50000 other-config:ebs=2048

This configuration accomplishes that the high priority traffic has a
guaranteed bandwidth egressing the ports at CIR (1000pps), but it can also
use the EIR, so a total of 2000pps at max. These additional 1000pps is
shared with the low priority traffic. The low priority traffic can use at
maximum 1000pps.

Refer to ``vswitch.xml`` for more details on egress policer.

Rate Limiting (Ingress Policing)
--------------------------------

Assuming you have a :doc:`vhost-user port <vhost-user>` receiving traffic
consisting of packets of size 64 bytes, the following command would limit the
reception rate of the port to ~1,000,000 packets per second::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=368000 \
        ingress_policing_burst=1000`

To examine the ingress policer configuration of the port::

    $ ovs-vsctl list interface vhost-user0

To clear the ingress policer configuration from the port::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=0

Refer to ``vswitch.xml`` for more details on ingress policer.

Flow Control
------------

Flow control is available for :doc:`DPDK physical ports <phy>`. For more
information, refer to :ref:`dpdk-phy-flow-control`.
