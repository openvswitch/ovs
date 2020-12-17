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

=======
Bareudp
=======

Q: What is Bareudp?

    A: There are various L3 encapsulation standards using UDP being discussed
       to leverage the UDP based load balancing capability of different
       networks. MPLSoUDP (__ https://tools.ietf.org/html/rfc7510) is one among
       them.

       The Bareudp tunnel provides a generic L3 encapsulation support for
       tunnelling different L3 protocols like MPLS, IP, NSH etc. inside a UDP
       tunnel.

       An example to create bareudp device to tunnel MPLS unicast traffic is
       given below.::

           $ ovs-vsctl add-port br0 mpls_udp_port -- set interface udp_port \
             type=bareudp options:remote_ip=2.1.1.3 options:local_ip=2.1.1.2 \
             options:payload_type=0x8847 options:dst_port=6635

       The option payload_type specifies the ethertype of the l3 protocol which
       the bareudp device will be tunnelling.

       The bareudp device supports special handling for MPLS & IP as they can
       have multiple ethertypes.
       MPLS procotcol can have ethertypes ETH_P_MPLS_UC (unicast) &
       ETH_P_MPLS_MC (multicast). IP protocol can have ethertypes ETH_P_IP (v4)
       & ETH_P_IPV6 (v6).

       The bareudp device to tunnel L3 traffic with multiple ethertypes
       (MPLS & IP) can be created by passing the L3 protocol name as string in
       the field payload_type.

       An example to create bareudp device to tunnel
       MPLS unicast & multicast traffic is given below.::

           $ ovs-vsctl add-port  br0 mpls_udp_port -- set interface udp_port \
             type=bareudp options:remote_ip=2.1.1.3 options:local_ip=2.1.1.2 \
             options:payload_type=mpls options:dst_port=6635

       The below example ovs rule shows how a bareudp tunnel port is used to
       tunnel an MPLS packet inside a UDP tunnel.::

          $ ovs-ofctl -O OpenFlow13 add-flow br0 "in_port=10,dl_type=0x0800,\
            actions=push_mpls:0x8847,set_field:3->mpls_label,\
            output:mpls_udp_port"

       This rule does MPLS encapsulation on IP packets and sends the l3 MPLS
       packets on a bareudp tunnel port which has its payload_type configured
       to 0x8847.

       An example to create bareudp device to tunnel
       IPv4 & IPv6 traffic is given below.::

           $ ovs-vsctl add-port  br0 ip_udp_port -- set interface udp_port \
             type=bareudp options:remote_ip=2.1.1.3 options:local_ip=2.1.1.2 \
             options:payload_type=ip options:dst_port=6636
