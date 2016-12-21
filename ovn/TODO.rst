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

==============
OVN To-do List
==============

* Work out database for clustering or HA properly.

* Compromised chassis mitigation.

  Possibly depends on database solution.

  Latest discussion:

  http://openvswitch.org/pipermail/dev/2016-August/078106.html

* Get incremental updates in ovn-controller and ovn-northd in some
  sensible way.

* Testing improvements, possibly heavily based on ovn-trace.

  Justin Pettit: "I'm planning to write some ovn-trace tests for IPv6.
  Hopefully we can get those into 2.6."

* Self-managing HA for ovn-northd (avoiding the need to set up
  independent tooling for fail-over).

  Russell Bryant: "For bonus points, increasing N would scale out ovn-northd if
  it was under too much load, but that's a secondary concern."

* Live migration.

  Russell Bryant: "When you're ready to have the destination take over, you
  have to remove the iface-id from the source and add it at the destination and
  I think it'd typically be configured on both ends, since it's a clone of the
  source VM (and it's config)."

* VLAN trunk ports.

  Russell Bryant: "Today that would require creating 4096 ports for the VM and
  attach to 4096 OVN networks, so doable, but not quite ideal."

* Native DNS support

  Russell Bryant: "This is an OpenStack requirement to fully eliminate the DHCP
  agent."

* Service function chaining.

* MAC learning.

  Han Zhou: "To support VMs that hosts workloads with their own macs, e.g.
  containers, if not using OVN native container support."

* Finish up ARP/ND support: re-checking bindings, expiring bindings.

* Hitless upgrade, especially for data plane.

* Use OpenFlow "bundles" for transactional data plane updates.

* L3 support

  * Logical routers should send RST replies to TCP packets.

  * IPv6 router ports should periodically send ND Router Advertisements.

* Dynamic IP to MAC binding enhancements.

  OVN has basic support for establishing IP to MAC bindings dynamically, using
  ARP.

  * Ratelimiting.

    From casual observation, Linux appears to generate at most one ARP per
    second per destination.

    This might be supported by adding a new OVN logical action for
    rate-limiting.

  * Tracking queries

     It's probably best to only record in the database responses to queries
     actually issued by an L3 logical router, so somehow they have to be
     tracked, probably by putting a tentative binding without a MAC address
     into the database.

  * Renewal and expiration.

    Something needs to make sure that bindings remain valid and expire those
    that become stale.

    One way to do this might be to add some support for time to the database
    server itself.

  * Table size limiting.

    The table of MAC bindings must not be allowed to grow unreasonably large.

  * MTU handling (fragmentation on output)

* Security

  * Limiting the impact of a compromised chassis.

    Every instance of ovn-controller has the same full access to the central
    OVN_Southbound database.  This means that a compromised chassis can
    interfere with the normal operation of the rest of the deployment.  Some
    specific examples include writing to the logical flow table to alter
    traffic handling or updating the port binding table to claim ports that are
    actually present on a different chassis.  In practice, the compromised host
    would be fighting against ovn-northd and other instances of ovn-controller
    that would be trying to restore the correct state.  The impact could
    include at least temporarily redirecting traffic (so the compromised host
    could receive traffic that it shouldn't) and potentially a more general
    denial of service.

    There are different potential improvements to this area.  The first would
    be to add some sort of ACL scheme to ovsdb-server.  A proposal for this
    should first include an ACL scheme for ovn-controller.  An example policy
    would be to make Logical_Flow read-only.  Table-level control is needed,
    but is not enough.  For example, ovn-controller must be able to update the
    Chassis and Encap tables, but should only be able to modify the rows
    associated with that chassis and no others.

    A more complex example is the Port_Binding table.  Currently,
    ovn-controller is the source of truth of where a port is located.  There
    seems to be  no policy that can prevent malicious behavior of a compromised
    host with this table.

    An alternative scheme for port bindings would be to provide an optional
    mode where an external entity controls port bindings and make them
    read-only to ovn-controller.  This is actually how OpenStack works today,
    for example.  The part of OpenStack that manages VMs (Nova) tells the
    networking component (Neutron) where a port will be located, as opposed to
    the networking component discovering it.

* ovsdb-server

  ovsdb-server should have adequate features for OVN but it probably needs work
  for scale and possibly for availability as deployments grow.  Here are some
  thoughts.

  * Multithreading.

    If it turns out that other changes don't let ovsdb-server scale
    adequately, we can multithread ovsdb-server.  Initially one might
    only break protocol handling into separate threads, leaving the
    actual database work serialized through a lock.

  * Increasing availability.

    Database availability might become an issue.  The OVN system shouldn't
    grind to a halt if the database becomes unavailable, but it would become
    impossible to bring VIFs up or down, etc.

    My current thought on how to increase availability is to add clustering to
    ovsdb-server, probably via the Raft consensus algorithm.  As an experiment,
    I wrote an implementation of Raft for Open vSwitch that you can clone from:

       https://github.com/blp/ovs-reviews.git raft

  * Reducing startup time.

    As-is, if ovsdb-server restarts, every client will fetch a fresh copy of
    the part of the database that it cares about.  With hundreds of clients,
    this could cause heavy CPU load on ovsdb-server and use excessive network
    bandwidth.  It would be better to allow incremental updates even across
    connection loss.  One way might be to use "Difference Digests" as described
    in Epstein et al., "What's the Difference? Efficient Set Reconciliation
    Without Prior Context".  (I'm not yet aware of previous non-academic use of
    this technique.)

  * Support multiple tunnel encapsulations in Chassis.

    So far, both ovn-controller and ovn-controller-vtep only allow chassis to
    have one tunnel encapsulation entry.  We should extend the implementation
    to support multiple tunnel encapsulations.

  * Update learned MAC addresses from VTEP to OVN

    The VTEP gateway stores all MAC addresses learned from its physical
    interfaces in the 'Ucast_Macs_Local' and the 'Mcast_Macs_Local' tables.
    ovn-controller-vtep should be able to update that information back to
    ovn-sb database, so that other chassis know where to send packets destined
    to the extended external network instead of broadcasting.

  * Translate ovn-sb Multicast_Group table into VTEP config

    The ovn-controller-vtep daemon should be able to translate the
    Multicast_Group table entry in ovn-sb database into Mcast_Macs_Remote table
    configuration in VTEP database.

* Consider the use of BFD as tunnel monitor.

  The use of BFD for hypervisor-to-hypervisor tunnels is probably not worth it,
  since there's no alternative to switch to if a tunnel goes down.  It could
  make sense at a slow rate if someone does OVN monitoring system integration,
  but not otherwise.

  When OVN gets to supporting HA for gateways (see ovn/OVN-GW-HA.rst), BFD is
  likely needed as a part of that solution.

  There's more commentary in this ML post:
  http://openvswitch.org/pipermail/dev/2015-November/062385.html

* ACL

  * Support FTP ALGs.

  * Support reject action.

  * Support log option.
