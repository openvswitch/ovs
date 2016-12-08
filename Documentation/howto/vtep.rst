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
How to Use the VTEP Emulator
============================

This document explains how to use ovs-vtep, a VXLAN Tunnel Endpoint (VTEP)
emulator that uses Open vSwitch for forwarding. VTEPs are the entities that
handle VXLAN frame encapsulation and decapsulation in a network.

Requirements
------------

The VTEP emulator is a Python script that invokes calls to tools like vtep-ctl
and ovs-vsctl. It is only useful when Open vSwitch daemons like ovsdb-server
and ovs-vswitchd are running and installed. To do this, either:

- Follow the instructions in :doc:`/intro/install/general` (don't start any
  daemons yet).

- Follow the instructions in :doc:`/intro/install/debian` and then install the
  ``openvswitch-vtep`` package (if operating on a debian based machine).  This
  will automatically start the daemons.

Design
------

At the end of this process, you should have the following setup:

::

    Architecture

    +---------------------------------------------------+
    | Host Machine                                      |
    |                                                   |
    |                                                   |
    |       +---------+ +---------+                     |
    |       |         | |         |                     |
    |       |   VM1   | |   VM2   |                     |
    |       |         | |         |                     |
    |       +----o----+ +----o----+                     |
    |            |           |                          |
    | br0 +------o-----------o--------------------o--+  |
    |            p0          p1                  br0    |
    |                                                   |
    |                                                   |
    |                              +------+   +------+  |
    +------------------------------| eth0 |---| eth1 |--+
                                   +------+   +------+
                                   10.1.1.1   10.2.2.1
                      MANAGEMENT      |          |
                    +-----------------o----+     |
                                                 |
                                 DATA/TUNNEL     |
                               +-----------------o---+

Some important points.

- We will use Open vSwitch to create our "physical" switch labeled ``br0``

- Our "physical" switch ``br0`` will have one internal port also named ``br0``
  and two "physical" ports, namely ``p0`` and ``p1``.

- The host machine may have two external interfaces. We will use ``eth0`` for
  management traffic and ``eth1`` for tunnel traffic (One can use a single
  interface to achieve both). Please take note of their IP addresses in the
  diagram. You do not have to use exactly the same IP addresses. Just know that
  the above will be used in the steps below.

- You can optionally connect physical machines instead of virtual machines to
  switch ``br0``. In that case:

  - Make sure you have two extra physical interfaces in your host machine,
    ``eth2`` and ``eth3``.

  - In the rest of this doc, replace ``p0`` with ``eth2`` and ``p1`` with
    ``eth3``.

5. In addition to implementing ``p0`` and ``p1`` as physical interfaces, you
   can also optionally implement them as standalone TAP devices, or VM
   interfaces for simulation.

6. Creating and attaching the VMs is outside the scope of this document and is
   included in the diagram for reference purposes only.

Startup
-------

These instructions describe how to run with a single ovsdb-server instance that
handles both the OVS and VTEP schema. You can skip steps 1-3 if you installed
using the debian packages as mentioned in step 2 of the "Requirements" section.

1. Create the initial OVS and VTEP schemas:

   ::

       $ ovsdb-tool create /etc/openvswitch/ovs.db vswitchd/vswitch.ovsschema
       $ ovsdb-tool create /etc/openvswitch/vtep.db vtep/vtep.ovsschema
      ```

2. Start ovsdb-server and have it handle both databases:

   ::

       $ ovsdb-server --pidfile --detach --log-file \
           --remote punix:/var/run/openvswitch/db.sock \
           --remote=db:hardware_vtep,Global,managers \
           /etc/openvswitch/ovs.db /etc/openvswitch/vtep.db

3. Start ovs-vswitchd as normal:

   ::

       $ ovs-vswitchd --log-file --detach --pidfile \
           unix:/var/run/openvswitch/db.sock

4. Create a "physical" switch and its ports in OVS:

   ::

       $ ovs-vsctl add-br br0
       $ ovs-vsctl add-port br0 p0
       $ ovs-vsctl add-port br0 p1

5. Configure the physical switch in the VTEP database:

   ::

       $ vtep-ctl add-ps br0
       $ vtep-ctl set Physical_Switch br0 tunnel_ips=10.2.2.1

6. Start the VTEP emulator. If you installed the components following
   :doc:`/intro/install/general`, run the following from the ``vtep``
   directory:

   ::

       $ ./ovs-vtep --log-file=/var/log/openvswitch/ovs-vtep.log \
           --pidfile=/var/run/openvswitch/ovs-vtep.pid \
           --detach br0

   If the installation was done by installing the openvswitch-vtep package, you
   can find ovs-vtep at ``/usr/share/openvswitch/scripts``.

7. Configure the VTEP database's manager to point at an NVC:

   ::

       $ vtep-ctl set-manager tcp:<CONTROLLER IP>:6640

   Where ``<CONTROLLER IP>`` is your controller's IP address that is accessible
   via the Host Machine's eth0 interface.

Simulating an NVC
-----------------

A VTEP implementation expects to be driven by a Network Virtualization
Controller (NVC), such as NSX.  If one does not exist, it's possible to use
vtep-ctl to simulate one:

1. Create a logical switch:

   ::

       $ vtep-ctl add-ls ls0

2. Bind the logical switch to a port:

   ::

       $ vtep-ctl bind-ls br0 p0 0 ls0
       $ vtep-ctl set Logical_Switch ls0 tunnel_key=33

3. Direct unknown destinations out a tunnel.

   For handling L2 broadcast, multicast and unknown unicast traffic, packets
   can be sent to all members of a logical switch referenced by a physical
   switch.  The "unknown-dst" address below is used to represent these packets.
   There are different modes to replicate the packets.  The default mode of
   replication is to send the traffic to a service node, which can be a
   hypervisor, server or appliance, and let the service node handle replication
   to other transport nodes (hypervisors or other VTEP physical switches).
   This mode is called *service node* replication.  An alternate mode of
   replication, called *source node* replication, involves the source node
   sending to all other transport nodes.  Hypervisors are always responsible
   for doing their own replication for locally attached VMs in both modes.
   Service node mode is the default.  Service node replication mode is
   considered a basic requirement because it only requires sending the packet
   to a single transport node.  The following configuration is for service node
   replication mode as only a single transport node destination is specified
   for the unknown-dst address:

   ::

       $ vtep-ctl add-mcast-remote ls0 unknown-dst 10.2.2.2

4. Optionally, change the replication mode from a default of ``service_node``
   to ``source_node``, which can be done at the logical switch level:

   ::

       $ vtep-ctl set-replication-mode ls0 source_node

5. Direct unicast destinations out a different tunnel:

   ::

       $ vtep-ctl add-ucast-remote ls0 00:11:22:33:44:55 10.2.2.3
