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

============
DPDK Bridges
============

Bridge must be specially configured to utilize DPDK-backed
:doc:`physical <phy>` and :doc:`virtual <vhost-user>` ports.

Quick Example
-------------

This example demonstrates how to add a bridge that will take advantage
of DPDK::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

This assumes Open vSwitch has been built with DPDK support. Refer to
:doc:`/intro/install/dpdk` for more information.

.. _extended-statistics:

Extended & Custom Statistics
----------------------------

The DPDK Extended Statistics API allows PMDs to expose a unique set of
statistics.  The Extended Statistics are implemented and supported only for
DPDK physical and vHost ports. Custom statistics are a dynamic set of counters
which can vary depending on the driver. Those statistics are implemented for
DPDK physical ports and contain all "dropped", "error" and "management"
counters from ``XSTATS``.  A list of all ``XSTATS`` counters can be found
`here`__.

__ https://wiki.opnfv.org/display/fastpath/Collectd+Metrics+and+Events

.. note::

    vHost ports only support RX packet size-based counters. TX packet size
    counters are not available.

To enable statistics, you have to enable OpenFlow 1.4 support for OVS. To
configure a bridge, ``br0``, to support OpenFlow version 1.4, run::

    $ ovs-vsctl set bridge br0 datapath_type=netdev \
      protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14

Once configured, check the OVSDB protocols column in the bridge table to ensure
OpenFlow 1.4 support is enabled::

    $ ovsdb-client dump Bridge protocols

You can also query the port statistics by explicitly specifying the ``-O
OpenFlow14`` option::

    $ ovs-ofctl -O OpenFlow14 dump-ports br0

There are custom statistics that OVS accumulates itself and these stats has
``ovs_`` as prefix. These custom stats are shown along with other stats
using the following command::

    $ ovs-vsctl get Interface <iface> statistics

EMC Insertion Probability
-------------------------

By default 1 in every 100 flows is inserted into the Exact Match Cache (EMC).
It is possible to change this insertion probability by setting the
``emc-insert-inv-prob`` option::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:emc-insert-inv-prob=N

where:

``N``
  A positive integer representing the inverse probability of insertion, i.e. on
  average 1 in every ``N`` packets with a unique flow will generate an EMC
  insertion.

If ``N`` is set to 1, an insertion will be performed for every flow. If set to
0, no insertions will be performed and the EMC will effectively be disabled.

With default ``N`` set to 100, higher megaflow hits will occur initially as
observed with pmd stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

For certain traffic profiles with many parallel flows, it's recommended to set
``N`` to '0' to achieve higher forwarding performance.

It is also possible to enable/disable EMC on per-port basis using::

    $ ovs-vsctl set interface <iface> other_config:emc-enable={true,false}

.. note::

   This could be useful for cases where different number of flows expected on
   different ports. For example, if one of the VMs encapsulates traffic using
   additional headers, it will receive large number of flows but only few flows
   will come out of this VM. In this scenario it's much faster to use EMC
   instead of classifier for traffic from the VM, but it's better to disable
   EMC for the traffic which flows to the VM.

For more information on the EMC refer to :doc:`/intro/install/dpdk` .


SMC cache
---------

SMC cache or signature match cache is a new cache level after EMC cache.
The difference between SMC and EMC is SMC only stores a signature of a flow
thus it is much more memory efficient. With same memory space, EMC can store 8k
flows while SMC can store 1M flows. When traffic flow count is much larger than
EMC size, it is generally beneficial to turn off EMC and turn on SMC. It is
currently turned off by default.

To turn on SMC::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:smc-enable=true

Datapath Classifier Performance
-------------------------------

The datapath classifier (dpcls) performs wildcard rule matching, a compute
intensive process of matching a packet ``miniflow`` to a rule ``miniflow``. The
code that does this compute work impacts datapath performance, and optimizing
it can provide higher switching performance.

Modern CPUs provide extensive SIMD instructions which can be used to get higher
performance. The CPU OVS is being deployed on must be capable of running these
SIMD instructions in order to take advantage of the performance benefits.
In OVS v2.14 runtime CPU detection was introduced to enable identifying if
these CPU ISA additions are available, and to allow the user to enable them.

OVS provides multiple implementations of dpcls. The following command enables
the user to check what implementations are available in a running instance ::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-get
    Available lookup functions (priority : name)
            0 : autovalidator
            1 : generic
            0 : avx512_gather

To set the priority of a lookup function, run the ``prio-set`` command ::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-set avx512_gather 5
    Lookup priority change affected 1 dpcls ports and 1 subtables.

The highest priority lookup function is used for classification, and the output
above indicates that one subtable of one DPCLS port is has changed its lookup
function due to the command being run. To verify the prioritization, re-run the
get command, note the updated priority of the ``avx512_gather`` function ::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-get
    Available lookup functions (priority : name)
            0 : autovalidator
            1 : generic
            5 : avx512_gather

If two lookup functions have the same priority, the first one in the list is
chosen, and the 2nd occurance of that priority is not used. Put in logical
terms, a subtable is chosen if its priority is greater than the previous
best candidate.

CPU ISA Testing and Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As multiple versions of DPCLS can co-exist, each with different CPU ISA
optimizations, it is important to validate that they all give the exact same
results. To easily test all DPCLS implementations, an ``autovalidator``
implementation of the DPCLS exists. This implementation runs all other
available DPCLS implementations, and verifies that the results are identical.

Running the OVS unit tests with the autovalidator enabled ensures all
implementations provide the same results. Note that the performance of the
autovalidator is lower than all other implementations, as it tests the scalar
implementation against itself, and against all other enabled DPCLS
implementations.

To adjust the DPCLS autovalidator priority, use this command ::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-set autovalidator 7

Running Unit Tests with Autovalidator
+++++++++++++++++++++++++++++++++++++

To run the OVS unit test suite with the DPCLS autovalidator as the default
implementation, it is required to recompile OVS. During the recompilation,
the default priority of the `autovalidator` implementation is set to the
maximum priority, ensuring every test will be run with every lookup
implementation ::

    $ ./configure --enable-autovalidator

Compile OVS in debug mode to have `ovs_assert` statements error out if
there is a mis-match in the DPCLS lookup implementation.
