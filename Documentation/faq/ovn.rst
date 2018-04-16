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

===
OVN
===

Q: Why does OVN use STT and Geneve instead of VLANs or VXLAN (or GRE)?

    A: OVN implements a fairly sophisticated packet processing pipeline in
    "logical datapaths" that can implement switching or routing functionality.
    A logical datapath has an ingress pipeline and an egress pipeline, and each
    of these pipelines can include logic based on packet fields as well as
    packet metadata such as the logical ingress and egress ports (the latter
    only in the egress pipeline).

    The processing for a logical datapath can be split across hypervisors.  In
    particular, when a logical ingress pipeline executes an "output" action,
    OVN passes the packet to the egress pipeline on the hypervisor (or, in the
    case of output to a logical multicast group, hypervisors) on which the
    logical egress port is located.  If this hypervisor is not the same as the
    ingress hypervisor, then the packet has to be transmitted across a physical
    network.

    This situation is where tunneling comes in.  To send the packet to another
    hypervisor, OVN encapsulates it with a tunnel protocol and sends the
    encapsulated packet across the physical network.  When the remote
    hypervisor receives the tunnel packet, it decapsulates it and passes it
    through the logical egress pipeline.  To do so, it also needs the metadata,
    that is, the logical ingress and egress ports.

    Thus, to implement OVN logical packet processing, at least the following
    metadata must pass across the physical network:

    * Logical datapath ID, a 24-bit identifier.  In Geneve, OVN uses the VNI to
      hold the logical datapath ID; in STT, OVN uses 24 bits of STT's 64-bit
      context ID.

    * Logical ingress port, a 15-bit identifier.  In Geneve, OVN uses an option
      to hold the logical ingress port; in STT, 15 bits of the context ID.

    * Logical egress port, a 16-bit identifier.  In Geneve, OVN uses an option
      to hold the logical egress port; in STT, 16 bits of the context ID.

    See ``ovn-architecture(7)``, under "Tunnel Encapsulations", for details.

    Together, these metadata require 24 + 15 + 16 = 55 bits.  GRE provides 32
    bits, VXLAN provides 24, and VLAN only provides 12.  Most notably, if
    logical egress pipelines do not match on the logical ingress port, thereby
    restricting the class of ACLs available to users, then this eliminates 15
    bits, bringing the requirement down to 40 bits.  At this point, one can
    choose to limit the size of the OVN logical network in various ways, e.g.:

    * 16 bits of logical datapaths + 16 bits of logical egress ports.  This
      combination fits within a 32-bit GRE tunnel key.

    * 12 bits of logical datapaths + 12 bits of logical egress ports.  This
      combination fits within a 24-bit VXLAN VNI.

    * It's difficult to identify an acceptable compromise for a VLAN-based
      deployment.

    These compromises wouldn't suit every site, since some deployments
    may need to allocate more bits to the datapath or egress port
    identifiers.

    As a side note, OVN does support VXLAN for use with ASIC-based top of rack
    switches, using ``ovn-controller-vtep(8)`` and the OVSDB VTEP schema
    described in ``vtep(5)``, but this limits the features available from OVN
    to the subset available from the VTEP schema.
