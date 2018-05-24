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

* Get incremental updates in ovn-controller and ovn-northd in some
  sensible way.

* Live migration.

  Russell Bryant: "When you're ready to have the destination take over, you
  have to remove the iface-id from the source and add it at the destination and
  I think it'd typically be configured on both ends, since it's a clone of the
  source VM (and it's config)."

* VLAN trunk ports.

  Russell Bryant: "Today that would require creating 4096 ports for the VM and
  attach to 4096 OVN networks, so doable, but not quite ideal."

* Service function chaining.

* MAC learning.

  Han Zhou: "To support VMs that hosts workloads with their own macs, e.g.
  containers, if not using OVN native container support."

* Finish up ARP/ND support: re-checking bindings, expiring bindings.

* Hitless upgrade, especially for data plane.

* Use OpenFlow "bundles" for transactional data plane updates.

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

* ovsdb-server

  ovsdb-server should have adequate features for OVN but it probably needs work
  for scale and possibly for availability as deployments grow.  Here are some
  thoughts.

  * Multithreading.

    If it turns out that other changes don't let ovsdb-server scale
    adequately, we can multithread ovsdb-server.  Initially one might
    only break protocol handling into separate threads, leaving the
    actual database work serialized through a lock.

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

  * OVN OCF pacemaker script to support Active / Passive HA for OVN dbs provides
    the option to configure the inactivity_probe value. The default 5 seconds
    inactivity_probe value is not sufficient and ovsdb-server drops the client
    IDL connections for openstack deployments when the neutron server is heavily
    loaded.

    We need to find a proper solution to solve this issue instead of increasing
    the inactivity_probe value.

* ACL

  * Support FTP ALGs.

  * Support reject action.
