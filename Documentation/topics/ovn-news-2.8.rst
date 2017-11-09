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

===============================
What's New with OVS and OVN 2.8
===============================

This document is about what was added in Open vSwitch 2.8, which was released
at the end of August 2017, concentrating on the new features in OVN.  It also
covers some of what is coming up in Open vSwitch and OVN 2.9, which is due to
be released in February 2018.  OVN has many features, and this document does
not cover every new or enhanced feature (but contributions are welcome).

This document assumes a basic familiarity with Open vSwitch, OVN, and their
associated tools.  For more information, please refer to the Open vSwitch and
OVN documentation, such as the ``ovn-architecture``\(7) manpage.

Debugging and Troubleshooting
-----------------------------

Before version 2.8, Open vSwitch command-line tools were far more painful to
use than they needed to be.  This section covers the improvements made to the
CLI in the 2.8 release.

User-Hostile UUIDs
~~~~~~~~~~~~~~~~~~

The OVN CLI, through ``ovn-nbctl``, ``ovn-nbctl``, and ``ovn-trace``, used
full-length UUIDs almost everywhere.  It didn't even provide any assistance
with completion, etc., which in practice meant always cutting and pasting UUIDs
from one command or window to another.  This problem wasn't limited to the
places where one would expect to have to see or use a UUID, either.  In many
places where one would expect to be able to use a network, router, or port
name, a UUID was required instead.  In many places where one would want to see
a name, the UUID was displayed instead.  More than anything else, these
shortcomings made the CLI user-hostile.

There was an underlying problem that the southbound database didn't actually
contain all the information needed to provide a decent user interface.  In some
cases, for example, the human-friendly names that one would want to use for
entities simply weren't part of the database.  These names weren't necessary
for correctness, only for usability.

OVN 2.8 eased many of these problems.  Most parts of the CLI now allow the user
to abbreviate UUIDs, as long as the abbreviations are unique within the
database.  Some parts of the CLI where full-length UUIDs make output hard to
read now abbreviate them themselves.  Perhaps more importantly, in many places
the OVN CLI now displays and accepts human-friendly names for networks,
routers, ports, and other entities.  In the places where the names were not
previously available, OVN (through ``ovn-northd``) now copies the names into
the southbound database.

The CLIs for layers below OVN, at the OpenFlow and datapath layers with
``ovs-ofctl`` and ``ovs-dpctl``, respectively, had some similar problems in
which numbers were used for entities that had human-friendly names.  Open
vSwitch 2.8 also solves some of those problems.  Other than that, the most
notable enhancement in this area was the ``--no-stats`` option to ``ovs-ofctl
dump-flows``, which made that command's output more readable for the cases
where per-flow statistics were not interesting to the reader.

Connections Between Levels
~~~~~~~~~~~~~~~~~~~~~~~~~~

OVN and Open vSwitch work almost like a stack of compilers: the OVN Neutron
plugin translates Neutron configuration into OVN northbound configuration,
which ``ovn-northd`` translates into logical flows, which ``ovn-controller``
translates into OpenFlow flows, which ``ovs-vswitchd`` translates into datapath
flows.  For debugging and troubleshooting it is often necessary to understand
exactly how these translations work.  The relationship from a logical flow to
its OpenFlow flows, or in the other direction, from an OpenFlow flow back to
the logical flow that produced it, was often of particular interest, but OVN
didn't provide good tools for the job.

OVN 2.8 added some new features that ease these jobs.  ``ovn-sbctl lflow-list``
has a new option ``--ovs`` that lists the OpenFlow flows on a particular
chassis that were generated from the logical flows that it lists.
``ovn-trace`` also added a similar ``--ovs`` option that applies to the logical
flows it traces.

In the other direction, OVN 2.8 added a new utility ``ovn-detrace`` that, given
an Open vSwitch trace of OpenFlow flows, annotates it with the logical flows
that yielded those OpenFlow flows.

Distributed Firewall
~~~~~~~~~~~~~~~~~~~~

OVN supports a distributed firewall with stateful connection tracking to ensure
that only packets for established connections, or those that the configuration
explicitly allows, can ingress a given VM or container.  Neutron uses this
feature by default.  Most packets in an OpenStack environment pass through it
twice, once after egress from the packet's source VM and once before ingress
into its destination VM.  Before OVN 2.8, the ``ovn-trace`` program, which
shows the path of a packet through an OVN logical network, did not support the
logical firewall, which in practice made it almost useless for Neutron.

In OVN 2.8, ``ovn-trace`` adds support for the logical firewall.  By default it
assumes that packets are part of an established connection, which is usually
what the user wants as part of the trace.  It also accepts command-line options
to override that assumption, which allows the user to discover the treatment of
packets that the firewall should drop.

At the next level deeper, prior to Open vSwitch 2.8, the OpenFlow tracing
command ``ofproto/trace`` also supported neither the connection tracking
feature underlying the OVN distributed firewall nor the "recirculation" feature
that accompanied it.  This meant that, even if the user tried to look deeper
into the distributed firewall mechanism, he or she would encounter a further
roadblock.  Open vSwitch 2.8 added support for both of these features as well.

Summary Display
~~~~~~~~~~~~~~~

``ovn-nbctl show`` and ``ovn-sbctl show``, for showing an overview of the OVN
configuration, didn't show a lot of important information.  OVN adds some more
useful information here.

DNS, and IPAM
-------------

OVN 2.8 adds a built-in DNS server designed for assigning names to VMs and
containers within an OVN logical network.  DNS names are assigned using records
in the OVN northbound database and, like other OVN features, translated into
logical flows at the OVN southbound layer.  DNS requests directed to the OVN
DNS server never leave the hypervisor from which the request is sent; instead,
OVN processes and replies to the request from its ``ovn-controller`` local
agent.  The OVN DNS server is not a general-purpose DNS server and cannot be
used for that purpose.

OVN includes simple built-in support for IP address management (IPAM), in which
OVN assigns IP addresses to VMs or containers from a pool or pools of IP
addresses delegated to it by the administrator.  Before OVN 2.8, OVN IPAM only
supported IPv4 addresses; OVN 2.8 adds support for IPv6.  OVN 2.8 also enhances
the address pool support to allow specific addresses to be excluded.  Neutron
assigns IP addresses itself and does not use OVN IPAM.

High Availability
-----------------

As a distributed system, in OVN a lot can go wrong.  As OVN advances, it adds
redundancy in places where currently a single failure could disrupt the
functioning of the system as a whole.  OVN 2.8 adds two new kinds of high
availability.

ovn-northd HA
~~~~~~~~~~~~~

The ``ovn-northd`` program sits between the OVN northbound and southbound
databases and translates from a logical network configuration into logical
flows.  If ``ovn-northd`` itself or the host on which it runs fails, then
updates to the OVN northbound configuration will not propagate to the
hypervisors and the OVN configuration freezes in place until ``ovn-northd``
restarts.

OVN 2.8 adds support for active-backup HA to ``ovn-northd``.  When more than
one ``ovn-northd`` instance runs, it uses an OVSDB locking feature to
automatically choose a single active instance.  When that instance dies or
becomes nonresponsive, the OVSDB server automatically choose one of the
remaining instance(s) to take over.

L3 Gateway HA
~~~~~~~~~~~~~

In OVN 2.8, multiple chassis may now be specified for L3 gateways.  When more
than one chassis is specified, OVN manages high availability for that gateway.
Each hypervisor uses the BFD protocol to keep track of the gateway nodes that
are currently up.  At any given time, a hypervisor uses the highest-priority
gateway node that is currently up.

OVSDB
-----

The OVN architecture relies heavily on OVSDB, the Open vSwitch database, for
hosting the northbound and southbound databases.  OVSDB was originally selected
for this purpose because it was already used in Open vSwitch for configuring
OVS itself and, thus, it was well integrated with OVS and well supported in C
and Python, the two languages that are used in Open vSwitch.

OVSDB was well designed for its original purpose of configuring Open vSwitch.
It supports ACID transactions, has a small, efficient server, a flexible schema
system, and good support for troubleshooting and debugging.  However, it lacked
several features that are important for OVN but not for Open vSwitch.  As OVN
advances, these missing features have become more and more of a problem.  One
option would be to switch to a different database that already has many of
these features, but despite a careful search, no ideal existing database was
identified, so the project chose instead to improve OVSDB where necessary to
bring it up to speed.  The following sections talk more about recent and future
improvements.

High Availability
~~~~~~~~~~~~~~~~~

When ``ovsdb-server`` was only used for OVS configuration, high availability
was not important.  ``ovsdb-server`` was capable of restarting itself
automatically if it crashed, and if the whole system went down then Open
vSwitch itself was dead too, so the database server's failure was not
important.

In contrast, the northbound and southbound databases are centralized components
of a distributed system, so it is important that they not be a single point of
failure for the system as a whole.  In released versions of OVN,
``ovsdb-server`` supports only "active-backup replication" across a pair of
servers.  This means that if one server goes down, the other can pick it back
up approximately where the other one left off.  The servers do not have
built-in support for deciding at any given time which is the active and which
the backup, so the administrator must configure an external agent to do this
management.

Active-backup replication is not entirely satisfactory, for multiple reasons.
Replication is only approximate.  Configuring the external agent requires extra
work.  There is no benefit from the backup server except when the active server
fails.  At most two servers can be used.

A new form of high availability for OVSDB is under development for the OVN 2.9
release, based on the Raft algorithm for distributed consensus.  Whereas
replication uses two servers, clustering using Raft requires three or more
(typically an odd number) and continues functioning as long as more than half
of the servers are up.  The clustering implementation is built into
``ovsdb-server`` and does not require an external agent.  Clustering preserves
the ACID properties of the database, so that a transaction that commits is
guaranteed to persist.  Finally, reads (which are the bulk of the OVN workload)
scale with the size of the cluster, so that adding more servers should improve
performance as the number of hypervisors in an OVN deployment increases.  As of
this writing, OVSDB support for clustering is undergoing development and early
deployment testing.

RBAC security
~~~~~~~~~~~~~

Until Open vSwitch 2.8, ``ovsdb-server`` had little support for access control
within a database.  If an OVSDB client could modify the database at all, it
could make arbitrary changes.  This was sufficient for most uses case to that
point.

Hypervisors in an OVN deployment need access to the OVN southbound database.
Most of their access is reads, to find out about the OVN configuration.
Hypervisors do need some write access to the southbound database, primarily to
let the other hypervisors know what VMs and containers they are running and how
to reach them.  Thus, OVN gives all of the hypervisors in the OVN deployment
write access to the OVN southbound database.  This is fine when all is well,
but if any of the hypervisors were compromised then they could disrupt the
entire OVN deployment by corrupting the database.

The OVN developers considered a few ways to solve this problem.  One way would
be to introduce a new central service (perhaps in ``ovn-northd``) that provided
only the kinds of writes that the hypervisors legitimately need, and then grant
hypervisors direct access to the southbound database only for reads.  But
ultimately the developers decided to introduce a new form of more access
control for OVSDB, called the OVSDB RBAC (role-based access control) feature.
OVSDB RBAC allows for granular enough control over access that hypervisors can
be granted only the ability to add, modify, and delete the records that relate
to themselves, preventing them from corrupting the database as a whole.

Further Directions
------------------

For more information about new features in OVN and Open vSwitch, please refer
to the NEWS file distributed with the source tree.  If you have questions about
Open vSwitch or OVN features, please feel free to write to the Open vSwitch
discussion mailing list at ovs-discuss@openvswitch.org.
