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
