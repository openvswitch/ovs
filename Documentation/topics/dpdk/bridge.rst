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

Simple Match Lookup
-------------------

There are cases where users might want simple forwarding or drop rules for all
packets received from a specific port, e.g ::

    in_port=1,actions=2
    in_port=2,actions=IN_PORT
    in_port=3,vlan_tci=0x1234/0x1fff,actions=drop
    in_port=4,actions=push_vlan:0x8100,set_field:4196->vlan_vid,output:3

There are also cases where complex OpenFlow rules can be simplified down to
datapath flows with very simple match criteria.

In theory, for very simple forwarding, OVS doesn't need to parse packets at all
in order to follow these rules.  In practice, due to various implementation
constraints, userspace datapath has to match at least on a small set of packet
fields.  Some matching criteria (for example, ingress port) are not related to
the packet itself and others (for example, VLAN tag or Ethernet type) can be
extracted without fully parsing the packet.  This allows OVS to significantly
speed up packet forwarding for these flows with simple match criteria.
Statistics on the number of packets matched in this way can be found in a
`simple match hits` counter of `ovs-appctl dpif-netdev/pmd-stats-show` command.

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
the user to check what implementations are available in a running instance::

    $ ovs-appctl dpif-netdev/subtable-lookup-info-get
    Available dpcls implementations:
            autovalidator (Use count: 1, Priority: 5)
            generic (Use count: 0, Priority: 1)
            avx512_gather (Use count: 0, Priority: 3)

To set the priority of a lookup function, run the ``prio-set`` command::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-set avx512_gather 5
    Lookup priority change affected 1 dpcls ports and 1 subtables.

The highest priority lookup function is used for classification, and the output
above indicates that one subtable of one DPCLS port is has changed its lookup
function due to the command being run. To verify the prioritization, re-run the
get command, note the updated priority of the ``avx512_gather`` function::

    $ ovs-appctl dpif-netdev/subtable-lookup-info-get
    Available dpcls implementations:
            autovalidator (Use count: 1, Priority: 5)
            generic (Use count: 0, Priority: 1)
            avx512_gather (Use count: 0, Priority: 3)

If two lookup functions have the same priority, the first one in the list is
chosen, and the 2nd occurrence of that priority is not used. Put in logical
terms, a subtable is chosen if its priority is greater than the previous
best candidate.

Note that the ``avx512_gather`` implementation uses instructions which may be
affected by the Gather Data Sampling (GDS) vulnerability, aka Downfall,
mitigation (see documentation for CVE-2022-40982 for details). This could
result in lower performance when these mitigations are enabled.

Optimizing Specific Subtable Search
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

During the packet classification, the datapath can use specialized lookup
tables to optimize the search.  However, not all situations are optimized.  If
you see a message like the following one in the OVS logs, it means that there
is no specialized implementation available for the current network traffic::

  Using non-specialized AVX512 lookup for subtable (X,Y) and possibly others.

In this case, OVS will continue to process the traffic normally using a more
generic lookup table.

Additional specialized lookups can be added to OVS if the user provides that
log message along with the command output as show below to the OVS mailing
list.  Note that the numbers in the log message (``subtable (X,Y)``) need to
match with the numbers in the provided command output
(``dp-extra-info:miniflow_bits(X,Y)``).

``ovs-appctl dpctl/dump-flows -m``, which results in output like this::

    ufid:82770b5d-ca38-44ff-8283-74ba36bd1ca5, skb_priority(0/0),skb_mark(0/0)
    ,ct_state(0/0),ct_zone(0/0),ct_mark(0/0),ct_label(0/0),recirc_id(0),
    dp_hash(0/0),in_port(pcap0),packet_type(ns=0,id=0),eth(src=00:00:00:00:00:
    00/00:00:00:00:00:00,dst=ff:ff:ff:ff:ff:ff/00:00:00:00:00:00),eth_type(
    0x8100),vlan(vid=1,pcp=0),encap(eth_type(0x0800),ipv4(src=127.0.0.1/0.0.0.0
    ,dst=127.0.0.1/0.0.0.0,proto=17/0,tos=0/0,ttl=64/0,frag=no),udp(src=53/0,
    dst=53/0)), packets:77072681, bytes:3545343326, used:0.000s, dp:ovs,
    actions:vhostuserclient0, dp-extra-info:miniflow_bits(4,1)

Please send an email to the OVS mailing list ovs-dev@openvswitch.org with
the output of the ``dp-extra-info:miniflow_bits(4,1)`` values.

Datapath Interface Performance
------------------------------

The datapath interface (DPIF) is responsible for taking packets through the
major components of the userspace datapath; such as packet parsing, caches and
datapath classifier lookups.

Just like with the datapath classifier, SIMD instructions can be applied to the
datapath interface implementation to improve performance.

OVS provides multiple implementations of the userspace datapath interface.
Available implementations can be listed with the following command::

    $ ovs-appctl dpif-netdev/dpif-impl-get
    Available DPIF implementations:
      dpif_scalar (pmds: none)
      dpif_avx512 (pmds: 1,2,6,7)

By default, ``dpif_scalar`` is used.  Implementations can be selected by
name::

    $ ovs-appctl dpif-netdev/dpif-impl-set dpif_avx512
    DPIF implementation set to dpif_avx512.

    $ ovs-appctl dpif-netdev/dpif-impl-set dpif_scalar
    DPIF implementation set to dpif_scalar.

Packet parsing performance
--------------------------

Open vSwitch performs parsing of the raw packets and extracts the important
header information into a compressed miniflow structure.  This miniflow is
composed of bits and blocks where the bits signify which blocks are set or have
values where as the blocks hold the metadata, ip, udp, vlan, etc.  These values
are used by the datapath for switching decisions later.

Most modern CPUs have some SIMD (single instruction, multiple data)
capabilities.  These SIMD instructions are able to process a vector rather than
act on one variable.  OVS provides multiple implementations of packet parsing
functions.  This allows the user to take advantage of SIMD instructions like
AVX512 to gain additional performance.

A list of implementations can be obtained by the following command.  The
command also shows whether the CPU supports each implementation::

    $ ovs-appctl dpif-netdev/miniflow-parser-get
        Available Optimized Miniflow Extracts:
            autovalidator (available: True, pmds: none)
            scalar (available: True, pmds: 1,15)
            study (available: True, pmds: none)

An implementation can be selected manually by the following command::

    $ ovs-appctl dpif-netdev/miniflow-parser-set [-pmd core_id] name \
      [study_cnt]

The above command has two optional parameters: ``study_cnt`` and ``core_id``.
The ``core_id`` sets a particular packet parsing function to a specific
PMD thread on the core.  The third parameter ``study_cnt``, which is specific
to ``study`` and ignored by other implementations, means how many packets
are needed to choose the best implementation.

Also user can select the ``study`` implementation which studies the traffic for
a specific number of packets by applying all available implementations of
the packet parsing function and then chooses the one with the most optimal
result for that traffic pattern.  The user can optionally provide a packet
count ``study_cnt`` parameter which is the minimum number of packets that OVS
must study before choosing an optimal implementation.  If no packet count is
provided, then the default value, ``128`` is chosen.

``study`` can be selected with packet count by the following command::

    $ ovs-appctl dpif-netdev/miniflow-parser-set study 1024

``study`` can be selected with packet count and explicit PMD selection by the
following command::

    $ ovs-appctl dpif-netdev/miniflow-parser-set -pmd 3 study 1024

``scalar`` can be selected on core ``3`` by the following command::

    $ ovs-appctl dpif-netdev/miniflow-parser-set -pmd 3 scalar


Actions Implementations (Experimental)
--------------------------------------

Actions describe what processing or modification should be performed on a
packet when it matches a given flow. Similar to the datapath interface,
DPCLS and MFEX (see above), the implementation of these actions can be
accelerated using SIMD instructions, resulting in improved performance.

OVS provides multiple implementations of the actions, however some
implementations requiring a CPU capable of executing the required SIMD
instructions.

Available implementations can be listed with the following command::

    $ ovs-appctl odp-execute/action-impl-show
        Available Actions implementations:
            scalar (available: Yes, active: Yes)
            autovalidator (available: Yes, active: No)
            avx512 (available: Yes, active: No)

By default, ``scalar`` is used.  Implementations can be selected by
name::

    $ ovs-appctl odp-execute/action-impl-set avx512
    Action implementation set to avx512.

    $ ovs-appctl odp-execute/action-impl-set scalar
    Action implementation set to scalar.
