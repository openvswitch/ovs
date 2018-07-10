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

The DPDK datapath requires specially configured bridge(s) in order to utilize
DPDK-backed :doc:`physical <phy>` and `virtual <vhost-user>` ports.

Quick Example
-------------

This example demonstrates how to add a bridge using the DPDK datapath::

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

For more information on the EMC refer to :doc:`/intro/install/dpdk` .


SMC cache (experimental)
-------------------------

SMC cache or signature match cache is a new cache level after EMC cache.
The difference between SMC and EMC is SMC only stores a signature of a flow
thus it is much more memory efficient. With same memory space, EMC can store 8k
flows while SMC can store 1M flows. When traffic flow count is much larger than
EMC size, it is generally beneficial to turn off EMC and turn on SMC. It is
currently turned off by default and an experimental feature.

To turn on SMC::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:smc-enable=true
