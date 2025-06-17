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

========================================
Userspace Datapath - Checksum Offloading
========================================

This document explains the internals of Open vSwitch support for checksum
offloading in the userspace datapath.

Design
------

Open vSwitch strives to forward packets as they arrive regardless of whether
the checksum is correct or not. OVS is not responsible for fixing external
checksum issues.

The interface (internally referred to as a netdev) can set flags indicating
whether each packet's checksum is good or bad upon receipt. If this flag is not
set, OVS will consider the validity of the packet's checksum to be unknown.

OVS will not re-calculate or update the packet's checksum if the checksum is
already known to be correct, known to be explicitly incorrect, or destined for
an egress interface that will recalculate the checksum anyways.

If OVS does invalidate the checksum, and the packet ingresses the datapath with
a checksum that is not known to be incorrect, OVS postpones checksum updates
until the packet egresses the datapath. This recalculation can either be
performed by OVS or, be offloaded onto the NIC if the egress NIC supports
checksum offloading.

When a packet egress the datapath, the packet flags and the egress interface
flags are verified to make sure all required offload features to send out the
packet are available on the egress interface. If not, the data path will fall
back to equivalent software implementation.


Interface (a.k.a. Netdev)
-------------------------

When the interface initiates, it should set the flags to tell the datapath
which offload features are supported. For example, if the driver supports IP
checksum offloading, then ``netdev->ol_flags`` should set the flag
``NETDEV_TX_OFFLOAD_IPV4_CKSUM``.


Rules
-----

1) OVS should strive to forward all packets regardless of checksum.

2) OVS must not correct a known bad packet checksum.

3) Packet with only flag ``DP_PACKET_OL_RX_IP_CKSUM_GOOD`` means that the IP
   checksum is present in the packet and it is good.

4) Packet with only flag ``DP_PACKET_OL_RX_IP_CKSUM_BAD`` means that the IP
   checksum is present in the packet and it is bad. Extra care should be taken
   to not fix the packet during data path processing.

5) Packet with both ``DP_PACKET_OL_RX_IP_CKSUM_GOOD`` and
   ``DP_PACKET_OL_RX_IP_CKSUM_BAD`` means that the IP header is valid, but the
   checksum may not be set in the packet data. This is basically encountered
   with some virtual drivers, or after OVS modified the IPv4 header content
   of a not bad ("bad" as defined in 4)) packet.

6) Packet with neither ``DP_PACKET_OL_RX_IP_CKSUM_GOOD`` nor
   ``DP_PACKET_OL_RX_IP_CKSUM_BAD`` means that the IP header status is unknown.
   It may be a IPv4 packet, or not. It may have a valid IPv4 cheksum, or not.
   This situation is encountered with virtual drivers that provide no
   information about the IP header, and for IPv6 packets.
