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

==================================
OVN Gateway High Availability Plan
==================================

::

    OVN Gateway

         +---------------------------+
         |                           |
         |     External Network      |
         |                           |
         +-------------^-------------+
                       |
                       |
                 +-----------+
                 |           |
                 |  Gateway  |
                 |           |
                 +-----------+
                       ^
                       |
                       |
         +-------------v-------------+
         |                           |
         |    OVN Virtual Network    |
         |                           |
         +---------------------------+

The OVN gateway is responsible for shuffling traffic between the tunneled
overlay network (governed by ovn-northd), and the legacy physical network.  In
a naive implementation, the gateway is a single x86 server, or hardware VTEP.
For most deployments, a single system has enough forwarding capacity to service
the entire virtualized network, however, it introduces a single point of
failure.  If this system dies, the entire OVN deployment becomes unavailable.
To mitigate this risk, an HA solution is critical -- by spreading
responsibility across multiple systems, no single server failure can take down
the network.

An HA solution is both critical to the manageability of the system, and
extremely difficult to get right.  The purpose of this document, is to propose
a plan for OVN Gateway High Availability which takes into account our past
experience building similar systems.  It should be considered a fluid changing
proposal, not a set-in-stone decree.

.. note::
    This document describes a range of options OVN could take to provide
    high availability for gateways.  The current implementation provides L3
    gateway high availability by the "Router Specific Active/Backup"
    approach described in this document.

Basic Architecture
------------------

In an OVN deployment, the set of hypervisors and network elements operating
under the guidance of ovn-northd are in what's called "logical space".  These
servers use VXLAN, STT, or Geneve to communicate, oblivious to the details of
the underlying physical network.  When these systems need to communicate with
legacy networks, traffic must be routed through a Gateway which translates from
OVN controlled tunnel traffic, to raw physical network traffic.

Since the gateway is typically the only system with a connection to the
physical network all traffic between logical space and the WAN must travel
through it.  This makes it a critical single point of failure -- if the gateway
dies, communication with the WAN ceases for all systems in logical space.

To mitigate this risk, multiple gateways should be run in a "High Availability
Cluster" or "HA Cluster".  The HA cluster will be responsible for performing
the duties of a gateways,  while being able to recover gracefully from
individual member failures.

::

    OVN Gateway HA Cluster

             +---------------------------+
             |                           |
             |     External Network      |
             |                           |
             +-------------^-------------+
                           |
                           |
    +----------------------v----------------------+
    |                                             |
    |          High Availability Cluster          |
    |                                             |
    | +-----------+  +-----------+  +-----------+ |
    | |           |  |           |  |           | |
    | |  Gateway  |  |  Gateway  |  |  Gateway  | |
    | |           |  |           |  |           | |
    | +-----------+  +-----------+  +-----------+ |
    +----------------------^----------------------+
                           |
                           |
             +-------------v-------------+
             |                           |
             |    OVN Virtual Network    |
             |                           |
             +---------------------------+

L2 vs L3 High Availability
~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to achieve this goal, there are two broad approaches one can take.
The HA cluster can appear to the network like a giant Layer 2 Ethernet Switch,
or like a giant IP Router. These approaches are called L2HA, and L3HA
respectively.  L2HA allows ethernet broadcast domains to extend into logical
space, a significant advantage, but this comes at a cost.  The need to avoid
transient L2 loops during failover significantly complicates their design.  On
the other hand, L3HA works for most use cases, is simpler, and fails more
gracefully.  For these reasons, it is suggested that OVN supports an L3HA
model, leaving L2HA for future work (or third party VTEP providers).  Both
models are discussed further below.

L3HA
----

In this section, we'll work through a basic simple L3HA implementation, on top
of which we'll gradually build more sophisticated features explaining their
motivations and implementations as we go.

Naive active-backup
~~~~~~~~~~~~~~~~~~~

Let's assume that there are a collection of logical routers which a tenant has
asked for, our task is to schedule these logical routers on one of N gateways,
and gracefully redistribute the routers on gateways which have failed.  The
absolute simplest way to achieve this is what we'll call "naive-active-backup".

::

    Naive Active Backup HA Implementation

    +----------------+   +----------------+
    | Leader         |   | Backup         |
    |                |   |                |
    |      A B C     |   |                |
    |                |   |                |
    +----+-+-+-+----++   +-+--------------+
         ^ ^ ^ ^    |      |
         | | | |    |      |
         | | | |  +-+------+---+
         + + + +  | ovn-northd |
         Traffic  +------------+

In a naive active-backup, one of the Gateways is chosen (arbitrarily) as a
leader.  All logical routers (A, B, C in the figure), are scheduled on this
leader gateway and all traffic flows through it.  ovn-northd monitors this
gateway via OpenFlow echo requests (or some equivalent), and if the gateway
dies, it recreates the routers on one of the backups.

This approach basically works in most cases and should likely be the starting
point for OVN -- it's strictly better than no HA solution and is a good
foundation for more sophisticated solutions.  That said, it's not without it's
limitations. Specifically, this approach doesn't coordinate with the physical
network to minimize disruption during failures, and it tightly couples failover
to ovn-northd (we'll discuss why this is bad in a bit), and wastes resources by
leaving backup gateways completely unutilized.

Router Failover
+++++++++++++++

When ovn-northd notices the leader has died and decides to migrate routers to a
backup gateway, the physical network has to be notified to direct traffic to
the new gateway.  Otherwise, traffic could be blackholed for longer than
necessary making failovers worse than they need to be.

For now, let's assume that OVN requires all gateways to be on the same IP
subnet on the physical network.  If this isn't the case, gateways would need to
participate in routing protocols to orchestrate failovers, something which is
difficult and out of scope of this document.

Since all gateways are on the same IP subnet, we simply need to worry about
updating the MAC learning tables of the Ethernet switches on that subnet.
Presumably, they all have entries for each logical router pointing to the old
leader.  If these entries aren't updated, all traffic will be sent to the (now
defunct) old leader, instead of the new one.

In order to mitigate this issue, it's recommended that the new gateway sends a
Reverse ARP (RARP) onto the physical network for each logical router it now
controls.  A Reverse ARP is a benign protocol used by many hypervisors when
virtual machines migrate to update L2 forwarding tables.  In this case, the
ethernet source address of the RARP is that of the logical router it
corresponds to, and its destination is the broadcast address.  This causes the
RARP to travel to every L2 switch in the broadcast domain, updating forwarding
tables accordingly.  This strategy is recommended in all failover mechanisms
discussed in this document -- when a router newly boots on a new leader, it
should RARP its MAC address.

Controller Independent Active-backup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    Controller Independent Active-Backup Implementation

    +----------------+   +----------------+
    | Leader         |   | Backup         |
    |                |   |                |
    |      A B C     |   |                |
    |                |   |                |
    +----------------+   +----------------+
         ^ ^ ^ ^
         | | | |
         | | | |
         + + + +
         Traffic

The fundamental problem with naive active-backup, is it tightly couples the
failover solution to ovn-northd.  This can significantly increase downtime in
the event of a failover as the (often already busy) ovn-northd controller has
to recompute state for the new leader. Worse, if ovn-northd goes down, we can't
perform gateway failover at all.  This violates the principle that control
plane outages should have no impact on dataplane functionality.

In a controller independent active-backup configuration, ovn-northd is
responsible for initial configuration while the HA cluster is responsible for
monitoring the leader, and failing over to a backup if necessary.  ovn-northd
sets HA policy, but doesn't actively participate when failovers occur.

Of course, in this model, ovn-northd is not without some responsibility.  Its
role is to pre-plan what should happen in the event of a failure, leaving it to
the individual switches to execute this plan.  It does this by assigning each
gateway a unique leadership priority.  Once assigned, it communicates this
priority to each node it controls.  Nodes use the leadership priority to
determine which gateway in the cluster is the active leader by using a simple
metric: the leader is the gateway that is healthy, with the highest priority.
If that gateway goes down, leadership falls to the next highest priority, and
conversely, if a new gateway comes up with a higher priority, it takes over
leadership.

Thus, in this model, leadership of the HA cluster is determined simply by the
status of its members.  Therefore if we can communicate the status of each
gateway to each transport node, they can individually figure out which is the
leader, and direct traffic accordingly.

Tunnel Monitoring
+++++++++++++++++

Since in this model leadership is determined exclusively by the health status
of member gateways, a key problem is how do we communicate this information to
the relevant transport nodes.  Luckily, we can do this fairly cheaply using
tunnel monitoring protocols like BFD.

The basic idea is pretty straightforward.  Each transport node maintains a
tunnel to every gateway in the HA cluster (not just the leader).  These tunnels
are monitored using the BFD protocol to see which are alive.  Given this
information, hypervisors can trivially compute the highest priority live
gateway, and thus the leader.

In practice, this leadership computation can be performed trivially using the
bundle or group action.  Rather than using OpenFlow to simply output to the
leader, all gateways could be listed in an active-backup bundle action ordered
by their priority.  The bundle action will automatically take into account the
tunnel monitoring status to output the packet to the highest priority live
gateway.

Inter-Gateway Monitoring
++++++++++++++++++++++++

One somewhat subtle aspect of this model, is that failovers are not globally
atomic.  When a failover occurs, it will take some time for all hypervisors to
notice and adjust accordingly.  Similarly, if a new high priority Gateway comes
up, it may take some time for all hypervisors to switch over to the new leader.
In order to avoid confusing the physical network, under these circumstances
it's important for the backup gateways to drop traffic they've received
erroneously.  In order to do this, each Gateway must know whether or not it is,
in fact active.  This can be achieved by creating a mesh of tunnels between
gateways.  Each gateway monitors the other gateways its cluster to determine
which are alive, and therefore whether or not that gateway happens to be the
leader.  If leading, the gateway forwards traffic normally, otherwise it drops
all traffic.

We should note that this method works well under the assumption that there
are no inter-gateway connectivity failures, in such case this method would fail
to elect a single master. The simplest example is two gateways which stop seeing
each other but can still reach the hypervisors. Protocols like VRRP or CARP
have the same issue. A mitigation for this type of failure mode could be
achieved by having all network elements (hypervisors and gateways) periodically
share their link status to other endpoints.

Gateway Leadership Resignation
++++++++++++++++++++++++++++++

Sometimes a gateway may be healthy, but still may not be suitable to lead the
HA cluster.  This could happen for several reasons including:

* The physical network is unreachable

* BFD (or ping) has detected the next hop router is unreachable

* The Gateway recently booted and isn't fully configured

In this case, the Gateway should resign leadership by holding its tunnels down
using the ``other_config:cpath_down`` flag.  This indicates to participating
hypervisors and Gateways that this gateway should be treated as if it's down,
even though its tunnels are still healthy.

Router Specific Active-Backup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    Router Specific Active-Backup

    +----------------+ +----------------+
    |                | |                |
    |      A C       | |     B D E      |
    |                | |                |
    +----------------+ +----------------+
                  ^ ^   ^ ^
                  | |   | |
                  | |   | |
                  + +   + +
                   Traffic

Controller independent active-backup is a great advance over naive
active-backup, but it still has one glaring problem -- it under-utilizes the
backup gateways.  In ideal scenario, all traffic would split evenly among the
live set of gateways.  Getting all the way there is somewhat tricky, but as a
step in the direction, one could use the "Router Specific Active-Backup"
algorithm.  This algorithm looks a lot like active-backup on a per logical
router basis, with one twist.  It chooses a different active Gateway for each
logical router.  Thus, in situations where there are several logical routers,
all with somewhat balanced load, this algorithm performs better.

Implementation of this strategy is quite straightforward if built on top of
basic controller independent active-backup.  On a per logical router basis, the
algorithm is the same, leadership is determined by the liveness of the
gateways.  The key difference here is that the gateways must have a different
leadership priority for each logical router.  These leadership priorities can
be computed by ovn-northd just as they had been in the controller independent
active-backup model.

Once we have these per logical router priorities, they simply need be
communicated to the members of the gateway cluster and the hypervisors.  The
hypervisors in particular, need simply have an active-backup bundle action (or
group action) per logical router listing the gateways in priority order for
*that router*, rather than having a single bundle action shared for all the
routers.

Additionally, the gateways need to be updated to take into account individual
router priorities.  Specifically, each gateway should drop traffic of backup
routers it's running, and forward traffic of active gateways, instead of simply
dropping or forwarding everything.  This should likely be done by having
ovn-controller recompute OpenFlow for the gateway, though other options exist.

The final complication is that ovn-northd's logic must be updated to choose
these per logical router leadership priorities in a more sophisticated manner.
It doesn't matter much exactly what algorithm it chooses to do this, beyond
that it should provide good balancing in the common case.  I.E. each logical
routers priorities should be different enough that routers balance to different
gateways even when failures occur.

Preemption
++++++++++

In an active-backup setup, one issue that users will run into is that of
gateway leader preemption.  If a new Gateway is added to a cluster, or for some
reason an existing gateway is rebooted, we could end up in a situation where
the newly activated gateway has higher priority than any other in the HA
cluster.  In this case, as soon as that gateway appears, it will preempt
leadership from the currently active leader causing an unnecessary failover.
Since failover can be quite expensive, this preemption may be undesirable.

The controller can optionally avoid preemption by cleverly tweaking the
leadership priorities.  For each router, new gateways should be assigned
priorities that put them second in line or later when they eventually come up.
Furthermore, if a gateway goes down for a significant period of time, its old
leadership priorities should be revoked and new ones should be assigned as if
it's a brand new gateway.  Note that this should only happen if a gateway has
been down for a while (several minutes), otherwise a flapping gateway could
have wide ranging, unpredictable, consequences.

Note that preemption avoidance should be optional depending on the deployment.
One necessarily sacrifices optimal load balancing to satisfy these requirements
as new gateways will get no traffic on boot.  Thus, this feature represents a
trade-off which must be made on a per installation basis.

Fully Active-Active HA
~~~~~~~~~~~~~~~~~~~~~~

::

    Fully Active-Active HA

    +----------------+ +----------------+
    |                | |                |
    |   A B C D E    | |    A B C D E   |
    |                | |                |
    +----------------+ +----------------+
                  ^ ^   ^ ^
                  | |   | |
                  | |   | |
                  + +   + +
                   Traffic

The final step in L3HA is to have true active-active HA.  In this scenario each
router has an instance on each Gateway, and a mechanism similar to ECMP is used
to distribute traffic evenly among all instances.  This mechanism would require
Gateways to participate in routing protocols with the physical network to
attract traffic and alert of failures.  It is out of scope of this document,
but may eventually be necessary.

L2HA
----

L2HA is very difficult to get right.  Unlike L3HA, where the consequences of
problems are minor, in L2HA if two gateways are both transiently active, an L2
loop triggers and a broadcast storm results.  In practice to get around this,
gateways end up implementing an overly conservative "when in doubt drop all
traffic" policy, or they implement something like MLAG.

MLAG has multiple gateways work together to pretend to be a single L2 switch
with a large LACP bond.  In principle, it's the right solution to the problem
as it solves the broadcast storm problem, and has been deployed successfully in
other contexts.  That said, it's difficult to get right and not recommended.
