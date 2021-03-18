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

===========
PMD Threads
===========

Poll Mode Driver (PMD) threads are the threads that do the heavy lifting for
userspace switching.  They perform tasks such as continuous polling of
input ports for packets, classifying packets once received, and executing
actions on the packets once they are classified.

PMD threads utilize Receive (Rx) and Transmit (Tx) queues, commonly known as
*rxq*\s and *txq*\s. While Tx queue configuration happens automatically, Rx
queues can be configured by the user. This can happen in one of two ways:

- For physical interfaces, configuration is done using the
  :program:`ovs-appctl` utility.

- For virtual interfaces, configuration is done using the :program:`ovs-appctl`
  utility, but this configuration must be reflected in the guest configuration
  (e.g. QEMU command line arguments).

The :program:`ovs-appctl` utility also provides a number of commands for
querying PMD threads and their respective queues. This, and all of the above,
is discussed here.

.. todo::

   Add an overview of Tx queues including numbers created, how they relate to
   PMD threads, etc.

PMD Thread Statistics
---------------------

To show current stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

To clear previous stats::

    $ ovs-appctl dpif-netdev/pmd-stats-clear

Port/Rx Queue Assigment to PMD Threads
--------------------------------------

.. todo::

   This needs a more detailed overview of *why* this should be done, along with
   the impact on things like NUMA affinity.

Correct configuration of PMD threads and the Rx queues they utilize is a
requirement in order to achieve maximum performance. This is particularly true
for enabling things like multiqueue for :ref:`physical <dpdk-phy-multiqueue>`
and :ref:`vhost-user <dpdk-vhost-user>` interfaces.

To show port/Rx queue assignment::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

Rx queues may be manually pinned to cores. This will change the default Rx
queue assignment to PMD threads::

    $ ovs-vsctl set Interface <iface> \
        other_config:pmd-rxq-affinity=<rxq-affinity-list>

where:

- ``<rxq-affinity-list>`` is a CSV list of ``<queue-id>:<core-id>`` values

For example::

    $ ovs-vsctl set interface dpdk-p0 options:n_rxq=4 \
        other_config:pmd-rxq-affinity="0:3,1:7,3:8"

This will ensure there are *4* Rx queues and that these queues are configured
like so:

- Queue #0 pinned to core 3
- Queue #1 pinned to core 7
- Queue #2 not pinned
- Queue #3 pinned to core 8

PMD threads on cores where Rx queues are *pinned* will become *isolated*. This
means that this thread will only poll the *pinned* Rx queues.

.. warning::

   If there are no *non-isolated* PMD threads, *non-pinned* RX queues will not
   be polled. Also, if the provided ``<core-id>`` is not available (e.g. the
   ``<core-id>`` is not in ``pmd-cpu-mask``), the RX queue will not be polled
   by any PMD thread.

If ``pmd-rxq-affinity`` is not set for Rx queues, they will be assigned to PMDs
(cores) automatically.

The algorithm used to automatically assign Rxqs to PMDs can be set by::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-rxq-assign=<assignment>

By default, ``cycles`` assignment is used where the Rxqs will be ordered by
their measured processing cycles, and then be evenly assigned in descending
order to PMDs based on an up/down walk of the PMDs. For example, where there
are five Rx queues and three cores - 3, 7, and 8 - available and the measured
usage of core cycles per Rx queue over the last interval is seen to be:

- Queue #0: 30%
- Queue #1: 80%
- Queue #3: 60%
- Queue #4: 70%
- Queue #5: 10%

The Rx queues will be assigned to the cores in the following order::

    Core 3: Q1 (80%) |
    Core 7: Q4 (70%) | Q5 (10%)
    Core 8: Q3 (60%) | Q0 (30%)

Alternatively, ``roundrobin`` assignment can be used, where the Rxqs are
assigned to PMDs in a round-robined fashion. This algorithm was used by
default prior to OVS 2.9. For example, given the following ports and queues:

- Port #0 Queue #0 (P0Q0)
- Port #0 Queue #1 (P0Q1)
- Port #1 Queue #0 (P1Q0)
- Port #1 Queue #1 (P1Q1)
- Port #1 Queue #2 (P1Q2)

The Rx queues may be assigned to the cores in the following order::

    Core 3: P0Q0 | P1Q1
    Core 7: P0Q1 | P1Q2
    Core 8: P1Q0 |

To see the current measured usage history of PMD core cycles for each Rx
queue::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

.. note::

   A history of one minute is recorded and shown for each Rx queue to allow for
   traffic pattern spikes. Any changes in the Rx queue's PMD core cycles usage,
   due to traffic pattern or reconfig changes, will take one minute to be fully
   reflected in the stats.

Rx queue to PMD assignment takes place whenever there are configuration changes
or can be triggered by using::

    $ ovs-appctl dpif-netdev/pmd-rxq-rebalance

.. versionchanged:: 2.6.0

   The ``pmd-rxq-show`` command was added in OVS 2.6.0.

.. versionchanged:: 2.9.0

   Utilization-based allocation of Rx queues to PMDs and the
   ``pmd-rxq-rebalance`` command were added in OVS 2.9.0. Prior to this,
   allocation was round-robin and processing cycles were not taken into
   consideration.

   In addition, the output of ``pmd-rxq-show`` was modified to include
   Rx queue utilization of the PMD as a percentage. Prior to this, tracking of
   stats was not available.

Automatic assignment of Port/Rx Queue to PMD Threads (experimental)
-------------------------------------------------------------------

Cycle or utilization based allocation of Rx queues to PMDs gives efficient
load distribution but it is not adaptive to change in traffic pattern
occurring over the time. This causes uneven load among the PMDs which results
in overall lower throughput.

To address this automatic load balancing of PMDs can be set by::

    $ ovs-vsctl set open_vswitch . other_config:pmd-auto-lb="true"

If pmd-auto-lb is set to true AND cycle based assignment is enabled then auto
load balancing of PMDs is enabled provided there are 2 or more non-isolated
PMDs and at least one of these PMDs is polling more than one RX queue. So,
following conditions need to be met to have Auto Load balancing enabled:

1. cycle based assignment of RX queues to PMD is enabled.
2. pmd-auto-lb is set to true.
3. There are two or more non-isolated PMDs present.
4. And at least one of the non-isolated PMD has more than one queue polling.

If any of above is not met PMD Auto Load Balancing is disabled.

Once auto load balancing is set, each non-isolated PMD measures the processing
load for each of its associated queues every 10 seconds. If the aggregated PMD
load reaches the load threshold for 6 consecutive intervals then PMD considers
itself to be overloaded.

For example, to set the load threshold to 70%::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-load-threshold="70"

If not set, the default load threshold is 95%.

If any PMD is overloaded, a dry-run of the PMD assignment algorithm is
performed by OVS main thread. The dry-run does NOT change the existing queue
to PMD assignments.

If the resultant mapping of dry-run indicates an improved distribution of the
load by at least the variance improvement threshold then the actual
reassignment will be performed.

For example, to set the variance improvement threshold to 40%::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-improvement-threshold="40"

If not set, the default variance improvement threshold is 25%.

.. note::

    PMD Auto Load Balancing doesn't currently work if queues are assigned
    cross NUMA as actual processing load could get worse after assignment
    as compared to what dry run predicts. The only exception is when all
    PMD threads are running on cores from a single NUMA node.  In this case
    Auto Load Balancing is still possible.

The minimum time between 2 consecutive PMD auto load balancing iterations can
also be configured by::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-rebal-interval="<interval>"

where ``<interval>`` is a value in minutes. The default interval is 1 minute
and setting it to 0 will also result in default value i.e. 1 min.

A user can use this option to avoid frequent trigger of Auto Load Balancing of
PMDs. For e.g. set this (in min) such that it occurs once in few hours or a day
or a week.

.. note::
    In some scenarios it may not be desired to have Auto Load Balancing
    triggerred. For example, if traffic profile for specific RX queue is
    changing dramatically very frequently which in turn thrashes CPU cache
    due to changes required in dpctl flows and EMC for newly added flows.
    In such scenarios user should configure rebalance interval accordingly
    to avoid frequent rebalancing happening.
