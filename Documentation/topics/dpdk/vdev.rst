..
      Copyright 2018, Red Hat, Inc.

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

====================
DPDK Virtual Devices
====================

DPDK provides drivers for both physical and virtual devices. Physical DPDK
devices are added to OVS by specifying a valid PCI address in ``dpdk-devargs``.
Virtual DPDK devices which do not have PCI addresses can be added using a
different format for ``dpdk-devargs``.

.. important::

   To use any DPDK-backed interface, you must ensure your bridge is configured
   correctly. For more information, refer to :doc:`bridge`.

.. note::

    Not all DPDK virtual PMD drivers have been tested and verified to work.

.. versionadded:: 2.7.0

Quick Example
-------------

To add a virtual ``dpdk`` devices, the ``dpdk-devargs`` argument should be of
the format ``eth_<driver_name><x>``, where ``x``' is a unique identifier of
your choice for the given port. For example to add a ``dpdk`` port that uses
the ``null`` DPDK PMD driver, run::

   $ ovs-vsctl add-port br0 null0 -- set Interface null0 type=dpdk \
       options:dpdk-devargs=eth_null0

Similarly, to add a ``dpdk`` port that uses the ``af_packet`` DPDK PMD driver,
run::

   $ ovs-vsctl add-port br0 myeth0 -- set Interface myeth0 type=dpdk \
       options:dpdk-devargs=eth_af_packet0,iface=eth0

More information on the different types of virtual DPDK PMDs can be found in
the `DPDK documentation`__.

__ http://dpdk.org/doc/guides/nics/overview.html
