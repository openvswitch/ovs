..
      Copyright (c) 2018 Intel Corporation

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

=========================
DPDK Device Memory Models
=========================

DPDK device memory can be allocated in one of two ways in OVS DPDK,
**shared memory** or **per port memory**. The specifics of both are
detailed below.

Shared Memory
-------------

By default OVS DPDK uses a shared memory model. This means that multiple
ports can share the same mempool. For example when a port is added it will
have a given MTU and socket ID associated with it. If a mempool has been
created previously for an existing port that has the same MTU and socket ID,
that mempool is used for both ports. If there is no existing mempool
supporting these parameters then a new mempool is created.

Per Port Memory
---------------

In the per port memory model, mempools are created per device and are not
shared. The benefit of this is a more transparent memory model where mempools
will not be exhausted by other DPDK devices. However this comes at a potential
increase in cost for memory dimensioning for a given deployment. Users should
be aware of the memory requirements for their deployment before using this
model and allocate the required hugepage memory.

Per port mempool support may be enabled via a global config value,
```per-port-memory```. Setting this to true enables the per port memory
model for all DPDK devices in OVS::

   $ ovs-vsctl set Open_vSwitch . other_config:per-port-memory=true

.. important::

    This value should be set before setting dpdk-init=true. If set after
    dpdk-init=true then the daemon must be restarted to use per-port-memory.

Calculating Memory Requirements
-------------------------------

The amount of memory required for a given mempool can be calculated by the
**number mbufs in the mempool \* mbuf size**.

Users should be aware of the following:

* The **number of mbufs** per mempool will differ between memory models.

* The **size of each mbuf** will be affected by the requested **MTU** size.

.. important::

   An mbuf size in bytes is always larger than the requested MTU size due to
   alignment and rounding needed in OVS DPDK.

Below are a number of examples of memory requirement calculations for both
shared and per port memory models.

Shared Memory Calculations
~~~~~~~~~~~~~~~~~~~~~~~~~~

In the shared memory model the number of mbufs requested is directly
affected by the requested MTU size as described in the table below.

+--------------------+-------------+
|      MTU Size      |  Num MBUFS  |
+====================+=============+
| 1500 or greater    |   262144    |
+--------------------+-------------+
| Less than 1500     |   16384     |
+------------+-------+-------------+

.. Important::

   If a deployment does not have enough memory to provide 262144 mbufs then
   the requested amount is halved up until 16384.

Example 1
+++++++++
::

 MTU = 1500 Bytes
 Number of mbufs = 262144
 Mbuf size = 3008 Bytes
 Memory required = 262144 * 3008 = 788 MB

Example 2
+++++++++
::

 MTU = 1800 Bytes
 Number of mbufs = 262144
 Mbuf size = 3008 Bytes
 Memory required = 262144 * 3008 = 788 MB

.. note::

   Assuming the same socket is in use for example 1 and 2 the same mempool
   would be shared.

Example 3
+++++++++
::

 MTU = 6000 Bytes
 Number of mbufs = 262144
 Mbuf size = 8128 Bytes
 Memory required = 262144 * 8128 = 2130 MB

Example 4
+++++++++
::

 MTU = 9000 Bytes
 Number of mbufs = 262144
 Mbuf size = 10176 Bytes
 Memory required = 262144 * 10176 = 2667 MB

Per Port Memory Calculations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The number of mbufs requested in the per port model is more complicated and
accounts for multiple dynamic factors in the datapath and device
configuration.

A rough estimation of the number of mbufs required for a port is:
::

 packets required to fill the device rxqs +
 packets that could be stuck on other ports txqs +
 packets on the pmd threads +
 additional corner case memory.

The algorithm in OVS used to calculate this is as follows:
::

 requested number of rxqs * requested rxq size +
 requested number of txqs * requested txq size +
 min(RTE_MAX_LCORE, requested number of rxqs) * netdev_max_burst +
 MIN_NB_MBUF.

where:

* **requested number of rxqs**: Number of requested receive queues for a
  device.
* **requested rxq size**: The number of descriptors requested for a rx queue.
* **requested number of txqs**: Number of requested transmit queues for a
  device. Calculated as the number of PMDs configured +1.
* **requested txq size**: the number of descriptors requested for a tx queue.
* **min(RTE_MAX_LCORE,  requested number of rxqs)**: Compare the maximum
  number of lcores supported by DPDK to the number of requested receive
  queues for the device and use the variable of lesser value.
* **NETDEV_MAX_BURST**: Maximum number of of packets in a burst, defined as
  32.
* **MIN_NB_MBUF**: Additional memory for corner case, defined as 16384.

For all examples below assume the following values:

* requested_rxq_size = 2048
* requested_txq_size = 2048
* RTE_MAX_LCORE = 128
* netdev_max_burst = 32
* MIN_NB_MBUF = 16384

Example 1: (1 rxq, 1 PMD, 1500 MTU)
+++++++++++++++++++++++++++++++++++
::

 MTU = 1500
 Number of mbufs = (1 * 2048) + (2 * 2048) + (1 * 32) + (16384) = 22560
 Mbuf size = 3008 Bytes
 Memory required = 22560 * 3008 = 67 MB

Example 2: (1 rxq, 2 PMD, 6000 MTU)
+++++++++++++++++++++++++++++++++++
::

 MTU = 6000
 Number of mbufs = (1 * 2048) + (3 * 2048) + (1 * 32) + (16384) = 24608
 Mbuf size = 8128 Bytes
 Memory required = 24608 * 8128 = 200 MB

Example 3: (2 rxq, 2 PMD, 9000 MTU)
+++++++++++++++++++++++++++++++++++
::

 MTU = 9000
 Number of mbufs = (2 * 2048) + (3 * 2048) + (1 * 32) + (16384) = 26656
 Mbuf size = 10176 Bytes
 Memory required = 26656 * 10176 = 271 MB
