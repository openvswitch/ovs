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
Bonding
=======

Bonding allows two or more interfaces (the "slaves") to share network traffic.
From a high-level point of view, bonded interfaces act like a single port, but
they have the bandwidth of multiple network devices, e.g. two 1 GB physical
interfaces act like a single 2 GB interface.  Bonds also increase robustness:
the bonded port does not go down as long as at least one of its slaves is up.

In vswitchd, a bond always has at least two slaves (and may have more).  If a
configuration error, etc. would cause a bond to have only one slave, the port
becomes an ordinary port, not a bonded port, and none of the special features
of bonded ports described in this section apply.

There are many forms of bonding of which ovs-vswitchd implements only a few.
The most complex bond ovs-vswitchd implements is called "source load balancing"
or SLB bonding.  SLB bonding divides traffic among the slaves based on the
Ethernet source address.  This is useful only if the traffic over the bond has
multiple Ethernet source addresses, for example if network traffic from
multiple VMs are multiplexed over the bond.

.. note::

   Most of the ovs-vswitchd implementation is in ``vswitchd/bridge.c``, so code
   references below should be assumed to refer to that file except as otherwise
   specified.


Enabling and Disabling Slaves
-----------------------------

When a bond is created, a slave is initially enabled or disabled based on
whether carrier is detected on the NIC (see ``iface_create()``).  After that, a
slave is disabled if its carrier goes down for a period of time longer than the
downdelay, and it is enabled if carrier comes up for longer than the updelay
(see ``bond_link_status_update()``).  There is one exception where the updelay
is skipped: if no slaves at all are currently enabled, then the first slave on
which carrier comes up is enabled immediately.

The updelay should be set to a time longer than the STP forwarding delay of the
physical switch to which the bond port is connected (if STP is enabled on that
switch).  Otherwise, the slave will be enabled, and load may be shifted to it,
before the physical switch starts forwarding packets on that port, which can
cause some data to be "blackholed" for a time.  The exception for a single
enabled slave does not cause any problem in this regard because when no slaves
are enabled all output packets are blackholed anyway.

When a slave becomes disabled, the vswitch immediately chooses a new output
port for traffic that was destined for that slave (see
``bond_enable_slave()``).  It also sends a "gratuitous learning packet",
specifically a RARP, on the bond port (on the newly chosen slave) for each MAC
address that the vswitch has learned on a port other than the bond (see
``bundle_send_learning_packets()``), to teach the physical switch that the new
slave should be used in place of the one that is now disabled.  (This behavior
probably makes sense only for a vswitch that has only one port (the bond)
connected to a physical switch; vswitchd should probably provide a way to
disable or configure it in other scenarios.)

Bond Packet Input
-----------------

Bonding accepts unicast packets on any bond slave.  This can occasionally cause
packet duplication for the first few packets sent to a given MAC, if the
physical switch attached to the bond is flooding packets to that MAC because it
has not yet learned the correct slave for that MAC.

Bonding only accepts multicast (and broadcast) packets on a single bond slave
(the "active slave") at any given time.  Multicast packets received on other
slaves are dropped.  Otherwise, every multicast packet would be duplicated,
once for every bond slave, because the physical switch attached to the bond
will flood those packets.

Bonding also drops received packets when the vswitch has learned that the
packet's MAC is on a port other than the bond port itself.  This is because it
is likely that the vswitch itself sent the packet out the bond port on a
different slave and is now receiving the packet back.  This occurs when the
packet is multicast or the physical switch has not yet learned the MAC and is
flooding it.  However, the vswitch makes an exception to this rule for
broadcast ARP replies, which indicate that the MAC has moved to another switch,
probably due to VM migration.  (ARP replies are normally unicast, so this
exception does not match normal ARP replies.  It will match the learning
packets sent on bond fail-over.)

The active slave is simply the first slave to be enabled after the bond is
created (see ``bond_choose_active_slave()``).  If the active slave is disabled,
then a new active slave is chosen among the slaves that remain active.
Currently due to the way that configuration works, this tends to be the
remaining slave whose interface name is first alphabetically, but this is by no
means guaranteed.

Bond Packet Output
------------------

When a packet is sent out a bond port, the bond slave actually used is selected
based on the packet's source MAC and VLAN tag (see ``bond_choose_output_slave()``).
In particular, the source MAC and VLAN tag are hashed into one of 256 values,
and that value is looked up in a hash table (the "bond hash") kept in the
``bond_hash`` member of struct port.  The hash table entry identifies a bond
slave.  If no bond slave has yet been chosen for that hash table entry,
vswitchd chooses one arbitrarily.

Every 10 seconds, vswitchd rebalances the bond slaves (see
``bond_rebalance()``).  To rebalance, vswitchd examines the statistics for
the number of bytes transmitted by each slave over approximately the past
minute, with data sent more recently weighted more heavily than data sent less
recently.  It considers each of the slaves in order from most-loaded to
least-loaded.  If highly loaded slave H is significantly more heavily loaded
than the least-loaded slave L, and slave H carries at least two hashes, then
vswitchd shifts one of H's hashes to L.  However, vswitchd will only shift a
hash from H to L if it will decrease the ratio of the load between H and L by
at least 0.1.

Currently, "significantly more loaded" means that H must carry at least 1 Mbps
more traffic, and that traffic must be at least 3% greater than L's.

Bond Balance Modes
------------------

Each bond balancing mode has different considerations, described below.

LACP Bonding
~~~~~~~~~~~~

LACP bonding requires the remote switch to implement LACP, but it is otherwise
very simple in that, after LACP negotiation is complete, there is no need for
special handling of received packets.

Several of the physical switches that support LACP block all traffic for ports
that are configured to use LACP, until LACP is negotiated with the host. When
configuring a LACP bond on a OVS host (eg: XenServer), this means that there
will be an interruption of the network connectivity between the time the ports
on the physical switch and the bond on the OVS host are configured. The
interruption may be relatively long, if different people are responsible for
managing the switches and the OVS host.

Such network connectivity failure can be avoided if LACP can be configured on
the OVS host before configuring the physical switch, and having the OVS host
fall back to a bond mode (active-backup) till the physical switch LACP
configuration is complete. An option "lacp-fallback-ab" exists to provide such
behavior on Open vSwitch.

Active Backup Bonding
~~~~~~~~~~~~~~~~~~~~~

Active Backup bonds send all traffic out one "active" slave until that slave
becomes unavailable.  Since they are significantly less complicated than SLB
bonds, they are preferred when LACP is not an option.  Additionally, they are
the only bond mode which supports attaching each slave to a different upstream
switch.

SLB Bonding
~~~~~~~~~~~

SLB bonding allows a limited form of load balancing without the remote switch's
knowledge or cooperation.  The basics of SLB are simple.  SLB assigns each
source MAC+VLAN pair to a link and transmits all packets from that MAC+VLAN
through that link.  Learning in the remote switch causes it to send packets to
that MAC+VLAN through the same link.

SLB bonding has the following complications:

0. When the remote switch has not learned the MAC for the destination of a
   unicast packet and hence floods the packet to all of the links on the SLB
   bond, Open vSwitch will forward duplicate packets, one per link, to each
   other switch port.

   Open vSwitch does not solve this problem.

1. When the remote switch receives a multicast or broadcast packet from a port
   not on the SLB bond, it will forward it to all of the links in the SLB bond.
   This would cause packet duplication if not handled specially.

   Open vSwitch avoids packet duplication by accepting multicast and broadcast
   packets on only the active slave, and dropping multicast and broadcast
   packets on all other slaves.

2. When Open vSwitch forwards a multicast or broadcast packet to a link in the
   SLB bond other than the active slave, the remote switch will forward it to
   all of the other links in the SLB bond, including the active slave.  Without
   special handling, this would mean that Open vSwitch would forward a second
   copy of the packet to each switch port (other than the bond), including the
   port that originated the packet.

   Open vSwitch deals with this case by dropping packets received on any SLB
   bonded link that have a source MAC+VLAN that has been learned on any other
   port.  (This means that SLB as implemented in Open vSwitch relies critically
   on MAC learning.  Notably, SLB is incompatible with the "flood_vlans"
   feature.)

3. Suppose that a MAC+VLAN moves to an SLB bond from another port (e.g. when a
   VM is migrated from this hypervisor to a different one).  Without additional
   special handling, Open vSwitch will not notice until the MAC learning entry
   expires, up to 60 seconds later as a consequence of rule #2.

   Open vSwitch avoids a 60-second delay by listening for gratuitous ARPs,
   which VMs commonly emit upon migration.  As an exception to rule #2, a
   gratuitous ARP received on an SLB bond is not dropped and updates the MAC
   learning table in the usual way.  (If a move does not trigger a gratuitous
   ARP, or if the gratuitous ARP is lost in the network, then a 60-second delay
   still occurs.)

4. Suppose that a MAC+VLAN moves from an SLB bond to another port (e.g. when a
   VM is migrated from a different hypervisor to this one), that the MAC+VLAN
   emits a gratuitous ARP, and that Open vSwitch forwards that gratuitous ARP
   to a link in the SLB bond other than the active slave.  The remote switch
   will forward the gratuitous ARP to all of the other links in the SLB bond,
   including the active slave.  Without additional special handling, this would
   mean that Open vSwitch would learn that the MAC+VLAN was located on the SLB
   bond, as a consequence of rule #3.

   Open vSwitch avoids this problem by "locking" the MAC learning table entry
   for a MAC+VLAN from which a gratuitous ARP was received from a non-SLB bond
   port.  For 5 seconds, a locked MAC learning table entry will not be updated
   based on a gratuitous ARP received on a SLB bond.
