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

============================
Connecting VMs Using Tunnels
============================

This document describes how to use Open vSwitch to allow VMs on two different
hosts to communicate over port-based GRE tunnels.

.. note::

   This guide covers the steps required to configure GRE tunneling. The same
   approach can be used for any of the other tunneling protocols supported by
   Open vSwitch.

.. image:: tunneling.png
   :align: center

Setup
-----

This guide assumes the environment is configured as described below.

Two Physical Networks
~~~~~~~~~~~~~~~~~~~~~

- Transport Network

  Ethernet network for tunnel traffic between hosts running OVS. Depending on
  the tunneling protocol being used (this cookbook uses GRE), some
  configuration of the physical switches may be required (for example, it may
  be necessary to adjust the MTU). Configuration of the physical switching
  hardware is outside the scope of this cookbook entry.

- Management Network

  Strictly speaking this network is not required, but it is a simple way to
  give the physical host an IP address for remote access since an IP address
  cannot be assigned directly to a physical interface that is part of an OVS
  bridge.

Two Physical Hosts
~~~~~~~~~~~~~~~~~~

The environment assumes the use of two hosts, named `host1` and `host2`. Both
hosts are hypervisors running Open vSwitch. Each host has two NICs, `eth0` and
`eth1`, which are configured as follows:

- `eth0` is connected to the Transport Network. `eth0` has an IP address that
  is used to communicate with Host2 over the Transport Network.

- `eth1` is connected to the Management Network. `eth1` has an IP address that
  is used to reach the physical host for management.

Four Virtual Machines
~~~~~~~~~~~~~~~~~~~~~

Each host will run two virtual machines (VMs). `vm1` and `vm2` are running on
`host1`, while `vm3` and `vm4` are running on `host2`.

Each VM has a single interface that appears as a Linux device (e.g., ``tap0``)
on the physical host.

.. note::
  For Xen/XenServer, VM interfaces appears as Linux devices with names like
  ``vif1.0``. Other Linux systems may present these interfaces as ``vnet0``,
  ``vnet1``, etc.

Configuration Steps
-------------------

Before you begin, you'll want to ensure that you know the IP addresses assigned
to `eth0` on both `host1` and `host2`, as they will be needed during the
configuration.

Perform the following configuration on `host1`.

#. Create an OVS bridge::

       $ ovs-vsctl add-br br0

   .. note::

      You will *not* add `eth0` to the OVS bridge.

#. Boot `vm1` and `vm2` on `host1`. If the VMs are not automatically attached
   to OVS, add them to the OVS bridge you just created (the commands below
   assume ``tap0`` is for `vm1` and ``tap1`` is for `vm2`)::

       $ ovs-vsctl add-port br0 tap0
       $ ovs-vsctl add-port br0 tap1

#. Add a port for the GRE tunnel::

       $ ovs-vsctl add-port br0 gre0 \
           -- set interface gre0 type=gre options:remote_ip=<IP of eth0 on host2>

Create a mirrored configuration on `host2` using the same basic steps:

#. Create an OVS bridge, but do not add any physical interfaces to the bridge::

       $ ovs-vsctl add-br br0

#. Launch `vm3` and `vm4` on `host2`, adding them to the OVS bridge if needed
   (again, ``tap0`` is assumed to be for `vm3` and ``tap1`` is assumed to be
   for `vm4`)::

       $ ovs-vsctl add-port br0 tap0
       $ ovs-vsctl add-port br0 tap1

#. Create the GRE tunnel on `host2`, this time using the IP address for
   ``eth0`` on `host1` when specifying the ``remote_ip`` option::

       $ ovs-vsctl add-port br0 gre0 \
         -- set interface gre0 type=gre options:remote_ip=<IP of eth0 on host1>

Testing
-------

Pings between any of the VMs should work, regardless of whether the VMs are
running on the same host or different hosts.

Using ``ip route show`` (or equivalent command), the routing table of the
operating system running inside the VM should show no knowledge of the IP
subnets used by the hosts, only the IP subnet(s) configured within the VM's
operating system. To help illustrate this point, it may be preferable to use
very different IP subnet assignments within the guest VMs than what is used on
the hosts.

Troubleshooting
---------------

If connectivity between VMs on different hosts isn't working, check the
following items:

- Make sure that `host1` and `host2` have full network connectivity over
  ``eth0`` (the NIC attached to the Transport Network). This may necessitate
  the use of additional IP routes or IP routing rules.

- Make sure that ``gre0`` on `host1` points to ``eth0`` on `host2`, and that
  ``gre0`` on `host2` points to ``eth0`` on `host1`.

- Ensure that all the VMs are assigned IP addresses on the same subnet; there
  is no IP routing functionality in this configuration.
