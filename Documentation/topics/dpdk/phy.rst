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

===================
DPDK Physical Ports
===================

The netdev datapath allows attaching of DPDK-backed physical interfaces in
order to provide high-performance ingress/egress from the host.

.. important::

   To use any DPDK-backed interface, you must ensure your bridge is configured
   correctly. For more information, refer to :doc:`bridge`.

.. versionchanged:: 2.7.0

   Before Open vSwitch 2.7.0, it was necessary to prefix port names with a
   ``dpdk`` prefix. Starting with 2.7.0, this is no longer necessary.

.. todo::

   Add an example for multiple ports share the same bus slot function.

Quick Example
-------------

This example demonstrates how to bind two ``dpdk`` ports, bound to physical
interfaces identified by hardware IDs ``0000:01:00.0`` and ``0000:01:00.1``, to
an existing bridge called ``br0``::

    $ ovs-vsctl add-port br0 dpdk-p0 \
       -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:01:00.0
    $ ovs-vsctl add-port br0 dpdk-p1 \
       -- set Interface dpdk-p1 type=dpdk options:dpdk-devargs=0000:01:00.1

For the above example to work, the two physical interfaces must be bound to
the DPDK poll-mode drivers in userspace rather than the traditional kernel
drivers. See the `binding NIC drivers <dpdk-binding-nics>` section for details.

.. _dpdk-binding-nics:

Binding NIC Drivers
-------------------

DPDK operates entirely in userspace and, as a result, requires use of its own
poll-mode drivers in user space for physical interfaces and a passthrough-style
driver for the devices in kernel space.

There are two different tools for binding drivers: :command:`driverctl` which
is a generic tool for persistently configuring alternative device drivers, and
:command:`dpdk-devbind` which is a DPDK-specific tool and whose changes do not
persist across reboots. In addition, there are two options available for this
kernel space driver - VFIO (Virtual Function I/O) and UIO (Userspace I/O) -
along with a number of drivers for each option. We will demonstrate examples of
both tools and will use the ``vfio-pci`` driver, which is the more secure,
robust driver of those available. More information can be found in the `DPDK
documentation <dpdk-drivers>`__.

To list devices using :command:`driverctl`, run::

    $ driverctl -v list-devices | grep -i net
    0000:07:00.0 igb (I350 Gigabit Network Connection (Ethernet Server Adapter I350-T2))
    0000:07:00.1 igb (I350 Gigabit Network Connection (Ethernet Server Adapter I350-T2))

You can then bind one or more of these devices using the same tool::

    $ driverctl set-override 0000:07:00.0 vfio-pci

Alternatively, to list devices using :command:`dpdk-devbind`, run::

    $ dpdk-devbind --status
    Network devices using DPDK-compatible driver
    ============================================
    <none>

    Network devices using kernel driver
    ===================================
    0000:07:00.0 'I350 Gigabit Network Connection 1521' if=enp7s0f0 drv=igb unused=igb_uio
    0000:07:00.1 'I350 Gigabit Network Connection 1521' if=enp7s0f1 drv=igb unused=igb_uio

    Other Network devices
    =====================
    ...

Once again, you can then bind one or more of these devices using the same
tool::

    $ dpdk-devbind --bind=vfio-pci 0000:07:00.0

.. versionchanged:: 2.6.0

   Open vSwitch 2.6.0 added support for DPDK 16.07, which in turn renamed the
   former ``dpdk_nic_bind`` tool to ``dpdk-devbind``.

For more information, refer to the `DPDK documentation <dpdk-drivers>`__.

.. _dpdk-drivers: http://dpdk.org/doc/guides/linux_gsg/linux_drivers.html

.. _dpdk-phy-multiqueue:

Multiqueue
----------

Poll Mode Driver (PMD) threads are the threads that do the heavy lifting for
the DPDK datapath. Correct configuration of PMD threads and the Rx queues they
utilize is a requirement in order to deliver the high-performance possible with
DPDK acceleration. It is possible to configure multiple Rx queues for ``dpdk``
ports, thus ensuring this is not a bottleneck for performance. For information
on configuring PMD threads, refer to :doc:`pmd`.

.. _dpdk-phy-flow-control:

Flow Control
------------

Flow control can be enabled only on DPDK physical ports. To enable flow control
support at Tx side while adding a port, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:tx-flow-ctrl=true

Similarly, to enable Rx flow control, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:rx-flow-ctrl=true

To enable flow control auto-negotiation, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:flow-ctrl-autoneg=true

To turn on the Tx flow control at run time for an existing port, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=true

The flow control parameters can be turned off by setting ``false`` to the
respective parameter. To disable the flow control at Tx side, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=false

Rx Checksum Offload
-------------------

By default, DPDK physical ports are enabled with Rx checksum offload.

Rx checksum offload can offer performance improvement only for tunneling
traffic in OVS-DPDK because the checksum validation of tunnel packets is
offloaded to the NIC. Also enabling Rx checksum may slightly reduce the
performance of non-tunnel traffic, specifically for smaller size packet.

.. _port-hotplug:

Hotplugging
-----------

OVS supports port hotplugging, allowing the use of physical ports that were not
bound to DPDK when ovs-vswitchd was started.

.. warning::

    This feature is not compatible with all NICs. Refer to vendor documentation
    for more information.

.. important::

   Ports must be bound to DPDK. Refer to :ref:`dpdk-binding-nics` for more
   information.

To *hotplug* a port, simply add it like any other port::

    $ ovs-vsctl add-port br0 dpdkx -- set Interface dpdkx type=dpdk \
        options:dpdk-devargs=0000:01:00.0

Ports can be detached using the ``del-port`` command::

    $ ovs-vsctl del-port dpdkx

This should both delete the port and detach the device. If successful, you
should see an ``INFO`` log. For example::

    INFO|Device '0000:04:00.1' has been detached

If the log is not seen then the port can be detached like so::

    $ ovs-appctl netdev-dpdk/detach 0000:01:00.0

.. warning::

    Detaching should not be done if a device is known to be non-detachable, as
    this may cause the device to behave improperly when added back with
    add-port. The Chelsio Terminator adapters which use the cxgbe driver seem
    to be an example of this behavior; check the driver documentation if this
    is suspected.

For more information please refer to the `DPDK Port Hotplug Framework`__.

__ http://dpdk.org/doc/guides/prog_guide/port_hotplug_framework.html#hotplug

Jumbo Frames
------------

DPDK physical ports can be configured to use Jumbo Frames. For more
information, refer to :doc:`jumbo-frames`.
