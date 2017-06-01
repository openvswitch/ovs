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

========================================
Connecting VMs Using Tunnels (Userspace)
========================================

This document describes how to use Open vSwitch to allow VMs on two different
hosts to communicate over VXLAN tunnels. Unlike :doc:`tunneling`, this
configuration works entirely in userspace.

.. note::

   This guide covers the steps required to configure VXLAN tunneling. The same
   approach can be used for any of the other tunneling protocols supported by
   Open vSwitch.

.. TODO(stephenfin): Convert this to a (prettier) PNG with same styling as the
   rest of the document

::

    +--------------+
    |     vm0      | 192.168.1.1/24
    +--------------+
       (vm_port0)
           |
           |
           |
    +--------------+
    |    br-int    |                                    192.168.1.2/24
    +--------------+                                   +--------------+
    |    vxlan0    |                                   |    vxlan0    |
    +--------------+                                   +--------------+
           |                                                  |
           |                                                  |
           |                                                  |
     172.168.1.1/24                                           |
    +--------------+                                          |
    |    br-phy    |                                   172.168.1.2/24
    +--------------+                                  +---------------+
    |  dpdk0/eth1  |----------------------------------|      eth1     |
    +--------------+                                  +---------------+
    Host A with OVS.                                     Remote host.

Setup
-----

This guide assumes the environment is configured as described below.

Two Physical Hosts
~~~~~~~~~~~~~~~~~~

The environment assumes the use of two hosts, named `host1` and `host2`. We
only detail the configuration of `host1` but a similar configuration can be
used for `host2`. Both hosts should be configured with Open vSwitch (with or
without the DPDK datapath), QEMU/KVM and suitable VM images. Open vSwitch
should be running before proceeding.

Configuration Steps
-------------------

Perform the folowing configuration on `host1`:

#. Create a ``br-int`` bridge::

       $ ovs-vsctl --may-exist add-br br-int \
         -- set Bridge br-int datapath_type=netdev \
         -- br-set-external-id br-int bridge-id br-int \
         -- set bridge br-int fail-mode=standalone

#. Add a port to this bridge. If using tap ports, first boot a VM and then add
   the port to the bridge::

       $ ovs-vsctl add-port br0 tap0

   If using DPDK vhost-user ports, add the port and then boot the VM
   accordingly, using ``vm_port0`` as the interface name::

       $ ovs-vsctl add-port br-int vm_port0 \
           -- set Interface vm_port0 type=dpdkvhostuser

#. Configure the IP address of the VM interface *in the VM itself*::

       $ ip addr add 192.168.1.1/24 dev eth0
       $ ip link set eth0 up

#. On `host1`, add a port for the VXLAN tunnel::

       $ ovs-vsctl add-port br-int vxlan0 \
         -- set interface vxlan0 type=vxlan options:remote_ip=172.168.1.2

   .. note::

      ``172.168.1.2`` is the remote tunnel end point address. On the remote
      host this will be ``172.168.1.1``

#. Create a ``br-phy`` bridge::

       $ ovs-vsctl --may-exist add-br br-phy \
           -- set Bridge br-phy datapath_type=netdev \
           -- br-set-external-id br-phy bridge-id br-phy \
           -- set bridge br-phy fail-mode=standalone \
                other_config:hwaddr=<mac address of eth1 interface>

   .. note::

      This additional bridge is required when running Open vSwitch in userspace
      rather than kernel-based Open vSwitch. The purpose of this bridge is to
      allow use of the kernel network stack for routing and ARP resolution.
      The datapath needs to look-up the routing table and ARP table to prepare
      the tunnel header and transmit data to the output port.

   .. note::

      ``eth1`` is used rather than ``eth0``. This is to ensure network
      connectivity is retained.

#. Attach ``eth1``/``dpdk0`` to the ``br-phy`` bridge.

   If the physical port ``eth1`` is operating as a kernel network interface,
   run::

       $ ovs-vsctl --timeout 10 add-port br-phy eth1
       $ ip addr add 172.168.1.1/24 dev br-phy
       $ ip link set br-phy up
       $ ip addr flush dev eth1 2>/dev/null
       $ ip link set eth1 up
       $ iptables -F

   If instead the interface is a DPDK interface and bound to the ``igb_uio`` or
   ``vfio`` driver, run::

       $ ovs-vsctl --timeout 10 add-port br-phy dpdk0 \
         -- set Interface dpdk0 type=dpdk options:dpdk-devargs=0000:06:00.0
       $ ip addr add 172.168.1.1/24 dev br-phy
       $ ip link set br-phy up
       $ iptables -F

   The commands are different as DPDK interfaces are not managed by the kernel,
   thus, the port details are not visible to any ``ip`` commands.

   .. important::

      Attempting to use the kernel network commands for a DPDK interface will
      result in a loss of connectivity through ``eth1``. Refer to
      :doc:`/faq/configuration` for more details.

Once complete, check the cached routes using ovs-appctl command::

    $ ovs-appctl ovs/route/show

If the tunnel route is missing, adding it now::

    $ ovs-appctl ovs/route/add 172.168.1.1/24 br-eth1

Repeat these steps if necessary for `host2`, but using ``192.168.1.1`` and
``172.168.1.2`` for the VM and tunnel interface IP addresses, respectively.

Testing
-------

With this setup, ping to VXLAN target device (``192.168.1.2``) should work.
Traffic will be VXLAN encapsulated and sent over the ``eth1``/``dpdk0``
interface.

Tunneling-related Commands
--------------------------

Tunnel routing table
~~~~~~~~~~~~~~~~~~~~

To add route::

    $ ovs-appctl ovs/route/add <IP address>/<prefix length> <output-bridge-name> <gw>

To see all routes configured::

    $ ovs-appctl ovs/route/show

To delete route::

    $ ovs-appctl ovs/route/del <IP address>/<prefix length>

To look up and display the route for a destination::

    $ ovs-appctl ovs/route/lookup <IP address>

ARP
~~~

To see arp cache content::

    $ ovs-appctl tnl/arp/show

To flush arp cache::

    $ ovs-appctl tnl/arp/flush

To set a specific arp entry::

    $ ovs-appctl tnl/arp/set <bridge> <IP address> <MAC address>

Ports
~~~~~

To check tunnel ports listening in ovs-vswitchd::

    $ ovs-appctl tnl/ports/show

To set range for VxLan UDP source port::

    $ ovs-appctl tnl/egress_port_range <num1> <num2>

To show current range::

    $ ovs-appctl tnl/egress_port_range

Datapath
~~~~~~~~

To check datapath ports::

    $ ovs-appctl dpif/show

To check datapath flows::

    $ ovs-appctl dpif/dump-flows
