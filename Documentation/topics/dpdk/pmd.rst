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
*rxq*\s and *txq*\s to receive and send packets from/to an interface.

- For physical interfaces, the number of Tx Queues is automatically configured
  based on the number of PMD thread cores. The number of Rx queues can be
  configured with::

        $ ovs-vsctl set Interface <interface_name> options:n_rxq=N

- For virtual interfaces, the number of Tx and Rx queues are configured by
  libvirt/QEMU and enabled/disabled in the guest. Refer to :doc:'vhost-user'
  for more information.

The :program:`ovs-appctl` utility provides a number of commands for
querying PMD threads and their respective queues. This, and all of the above,
is discussed here.

.. todo::

   Add an overview of Tx queues including numbers created, how they relate to
   PMD threads, etc.

PMD Thread Statistics
---------------------

To show current stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

or::

    $ ovs-appctl dpif-netdev/pmd-perf-show

Detailed performance metrics for ``pmd-perf-show`` can also be enabled::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-perf-metrics=true

See the `ovs-vswitchd(8)`_ manpage for more information.

To clear previous stats::

    $ ovs-appctl dpif-netdev/pmd-stats-clear

.. note::

    PMD stats are cumulative so they should be cleared in order to see how the
    PMDs are being used with current traffic.

Port/Rx Queue Assignment to PMD Threads
---------------------------------------

.. todo::

   This needs a more detailed overview of *why* this should be done, along with
   the impact on things like NUMA affinity.

Correct configuration of PMD threads and the Rx queues they utilize is a
requirement in order to achieve maximum performance. This is particularly true
for enabling things like multiqueue for :ref:`physical <dpdk-phy-multiqueue>`
and :ref:`vhost-user <dpdk-vhost-user>` interfaces.

Rx queues will be assigned to PMD threads by OVS, or they can be manually
pinned to PMD threads by the user.

To see the port/Rx queue assignment and current measured usage history of PMD
core cycles for each Rx queue::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

.. note::

   By default a history of one minute is recorded and shown for each Rx queue
   to allow for traffic pattern spikes. Any changes in the Rx queue's PMD core
   cycles usage, due to traffic pattern or reconfig changes, will take one
   minute to be fully reflected in the stats by default.

PMD thread usage of an Rx queue can be displayed for a shorter period of time,
from the last 5 seconds up to the default 60 seconds in 5 second steps.

To see the port/Rx queue assignment and the last 5 secs of measured usage
history of PMD core cycles for each Rx queue::

    $ ovs-appctl dpif-netdev/pmd-rxq-show -secs 5

.. versionchanged:: 2.6.0

      The ``pmd-rxq-show`` command was added in OVS 2.6.0.

.. versionchanged:: 2.16.0

   A ``overhead`` statistics is shown per PMD: it represents the number of
   cycles inherently consumed by the OVS PMD processing loop.

.. versionchanged:: 3.1.0

      The ``-secs`` parameter was added to the dpif-netdev/pmd-rxq-show
      command.

Rx queue to PMD assignment takes place whenever there are configuration changes
or can be triggered by using::

    $ ovs-appctl dpif-netdev/pmd-rxq-rebalance

.. versionchanged:: 2.9.0

   Utilization-based allocation of Rx queues to PMDs and the
   ``pmd-rxq-rebalance`` command were added in OVS 2.9.0. Prior to this,
   allocation was round-robin and processing cycles were not taken into
   consideration.

   In addition, the output of ``pmd-rxq-show`` was modified to include
   Rx queue utilization of the PMD as a percentage.

Port/Rx Queue assignment to PMD threads by manual pinning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rx queues may be manually pinned to cores. This will change the default Rx
queue assignment to PMD threads::

    $ ovs-vsctl set Interface <iface> \
        other_config:pmd-rxq-affinity=<rxq-affinity-list>

where:

- ``<rxq-affinity-list>`` is a CSV list of ``<queue-id>:<core-id>`` values

For example::

    $ ovs-vsctl set interface dpdk-p0 options:n_rxq=4 \
        other_config:pmd-rxq-affinity="0:3,1:7,3:8"

This will ensure there are *4* Rx queues for dpdk-p0 and that these queues are
configured like so:

- Queue #0 pinned to core 3
- Queue #1 pinned to core 7
- Queue #2 not pinned
- Queue #3 pinned to core 8

PMD threads on cores where Rx queues are *pinned* will become *isolated* by
default. This means that these threads will only poll the *pinned* Rx queues.

If using ``pmd-rxq-assign=group`` PMD threads with *pinned* Rxqs can be
*non-isolated* by setting::

  $ ovs-vsctl set Open_vSwitch . other_config:pmd-rxq-isolate=false

.. warning::

   If there are no *non-isolated* PMD threads, *non-pinned* RX queues will not
   be polled. If the provided ``<core-id>`` is not available (e.g. the
   ``<core-id>`` is not in ``pmd-cpu-mask``), the RX queue will be assigned to
   a *non-isolated* PMD, that will remain *non-isolated*.

Automatic Port/Rx Queue assignment to PMD threads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If ``pmd-rxq-affinity`` is not set for Rx queues, they will be assigned to PMDs
(cores) automatically.

The algorithm used to automatically assign Rxqs to PMDs can be set by::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-rxq-assign=<assignment>

By default, ``cycles`` assignment is used where the Rxqs will be ordered by
their measured processing cycles, and then be evenly assigned in descending
order to PMDs. The PMD that will be selected for a given Rxq will be the next
one in alternating ascending/descending order based on core id. For example,
where there are five Rx queues and three cores - 3, 7, and 8 - available and
the measured usage of core cycles per Rx queue over the last interval is seen
to be:

- Queue #0: 30%
- Queue #1: 80%
- Queue #3: 60%
- Queue #4: 70%
- Queue #5: 10%

The Rx queues will be assigned to the cores in the following order::

    Core 3: Q1 (80%) |
    Core 7: Q4 (70%) | Q5 (10%)
    Core 8: Q3 (60%) | Q0 (30%)

``group`` assignment is similar to ``cycles`` in that the Rxqs will be
ordered by their measured processing cycles before being assigned to PMDs.
It differs from ``cycles`` in that it uses a running estimate of the cycles
that will be on each PMD to select the PMD with the lowest load for each Rxq.

This means that there can be a group of low traffic Rxqs on one PMD, while a
high traffic Rxq may have a PMD to itself. Where ``cycles`` kept as close to
the same number of Rxqs per PMD as possible, with ``group`` this restriction is
removed for a better balance of the workload across PMDs.

For example, where there are five Rx queues and three cores - 3, 7, and 8 -
available and the measured usage of core cycles per Rx queue over the last
interval is seen to be:

- Queue #0: 10%
- Queue #1: 80%
- Queue #3: 50%
- Queue #4: 70%
- Queue #5: 10%

The Rx queues will be assigned to the cores in the following order::

    Core 3: Q1 (80%) |
    Core 7: Q4 (70%) |
    Core 8: Q3 (50%) | Q0 (10%) | Q5 (10%)

Alternatively, ``roundrobin`` assignment can be used, where the Rxqs are
assigned to PMDs in a round-robin fashion. This algorithm was used by
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

PMD Automatic Load Balance
--------------------------

Cycle or utilization based allocation of Rx queues to PMDs is done to give an
efficient load distribution based at the time of assignment. However, over time
it may become less efficient due to changes in traffic. This may cause an
uneven load among the PMDs, which in the worst case may result in packet drops
and lower throughput.

To address this, automatic load balancing of PMDs can be enabled by::

    $ ovs-vsctl set open_vswitch . other_config:pmd-auto-lb="true"

The following are minimum configuration pre-requisites needed for PMD Auto
Load Balancing to operate:

1. ``pmd-auto-lb`` is enabled.
2. ``cycle`` (default) or ``group`` based Rx queue assignment is selected.
3. There are two or more non-isolated PMDs present.
4. At least one non-isolated PMD is polling more than one Rx queue.

When PMD Auto Load Balance is enabled, a PMD core's CPU utilization percentage
is measured. The PMD is considered above the threshold if that percentage
utilization is greater than the load threshold every 10 secs for 1 minute.

The load threshold can be set by the user. For example, to set the load
threshold to 70% utilization of a PMD core::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-load-threshold="70"

If not set, the default load threshold is 95%.

If a PMD core is detected to be above the load threshold and the minimum
pre-requisites are met, a dry-run using the current PMD assignment algorithm is
performed.

For each numa node, the current variance of load between the PMD cores and
estimated variance from the dry-run are both calculated. If any numa's
estimated dry-run variance is improved from the current one by the variance
threshold, a new Rx queue to PMD assignment will be performed.

For example, to set the variance improvement threshold to 40%::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-improvement-threshold="40"

If not set, the default variance improvement threshold is 25%.

.. note::

    PMD Auto Load Balancing will not operate if Rx queues are assigned to PMD
    cores on a different NUMA. This is because the processing load could change
    after a new assignment due to differing cross-NUMA datapaths, making it
    difficult to estimate the loads during a dry-run. The only exception is
    when all PMD threads are running on cores from a single NUMA node. In this
    case cross-NUMA datapaths will not change after reassignment.

The minimum time between 2 consecutive PMD auto load balancing iterations can
also be configured by::

    $ ovs-vsctl set open_vswitch .\
        other_config:pmd-auto-lb-rebal-interval="<interval>"

where ``<interval>`` is a value in minutes. The default interval is 1 minute.

A user can use this option to set a minimum frequency of Rx queue to PMD
reassignment due to PMD Auto Load Balance. For example, this could be set
(in min) such that a reassignment is triggered at most every few hours.

PMD load based sleeping
-----------------------

PMD threads constantly poll Rx queues which are assigned to them. In order to
reduce the CPU cycles they use, they can sleep for small periods of time
when there is no load or very-low load on all the Rx queues they poll.

This can be enabled by setting the max requested sleep time (in microseconds)
for a PMD thread::

    $ ovs-vsctl set open_vswitch . other_config:pmd-sleep-max=50

.. note::

    Previous config name 'pmd-maxsleep' is deprecated and will be removed in a
    future release.

With a non-zero max value a PMD may request to sleep by an incrementing amount
of time up to the maximum time. If at any point the threshold of at least half
a batch of packets (i.e. 16) is received from an Rx queue that the PMD is
polling is met, the requested sleep time will be reset to 0. At that point no
sleeps will occur until the no/low load conditions return.

Sleeping in a PMD thread will mean there is a period of time when the PMD
thread will not process packets. Sleep times requested are not guaranteed
and can differ significantly depending on system configuration. The actual
time not processing packets will be determined by the sleep and processor
wake-up times and should be tested with each system configuration.

Sleep time statistics for 10 secs can be seen with::

    $ ovs-appctl dpif-netdev/pmd-stats-clear \
        && sleep 10 && ovs-appctl dpif-netdev/pmd-perf-show

Example output, showing that during the last 10 seconds, 74.5% of iterations
had a sleep of some length. The total amount of sleep time was 9.06 seconds
and the average sleep time where a sleep was requested was 9 microseconds::

   - sleep iterations:       977037  ( 74.5 % of iterations)
   Sleep time (us):         9068841  (  9 us/iteration avg.)

Any potential power saving from PMD load based sleeping is dependent on the
system configuration (e.g. enabling processor C-states) and workloads.

.. note::

    If there is a sudden spike of packets while the PMD thread is sleeping and
    the processor is in a low-power state it may result in some lost packets or
    extra latency before the PMD thread returns to processing packets at full
    rate.

Maximum sleep values can also be set for individual PMD threads using
key:value pairs in the form of core:max_sleep. Any PMD thread that has been
assigned a specified value will use that. Any PMD thread that does not have
a specified value will use the current global value.

Specified values for individual PMD threads can be added or removed at
any time.

For example, to set PMD threads on cores 8 and 9 to never request a load based
sleep and all others PMD threads to be able to request a max sleep of
50 microseconds (us)::

    $ ovs-vsctl set open_vswitch . other_config:pmd-sleep-max=50,8:0,9:0

The max sleep value for each PMD thread can be checked in the logs or with::

    $ ovs-appctl dpif-netdev/pmd-sleep-show
    pmd thread numa_id 0 core_id 8:
      max sleep:    0 us
    pmd thread numa_id 1 core_id 9:
      max sleep:    0 us
    pmd thread numa_id 0 core_id 10:
      max sleep:   50 us
    pmd thread numa_id 1 core_id 11:
      max sleep:   50 us
    pmd thread numa_id 0 core_id 12:
      max sleep:   50 us
    pmd thread numa_id 1 core_id 13:
      max sleep:   50 us

.. _ovs-vswitchd(8):
    http://openvswitch.org/support/dist-docs/ovs-vswitchd.8.html
