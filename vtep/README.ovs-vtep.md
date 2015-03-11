How to Use the VTEP Emulator
============================

This document explains how to use ovs-vtep, a VTEP emulator that uses
Open vSwitch for forwarding.

Requirements
------------

The VTEP emulator is a Python script that invokes calls to tools like
vtep-ctl and ovs-vsctl and is useful only when OVS daemons like ovsdb-server
and ovs-vswitchd are running. So those components should be installed. This
can be done by either of the following methods.

1. Follow the instructions in the INSTALL.md file of the Open vSwitch repository
(don't start any daemons yet).

2. Follow the instructions in INSTALL.Debian.md file and then install the
"openvswitch-vtep" package (if operating on a debian based machine). This
will automatically start the daemons.

Design
======

At the end of this process, you should have the following setup:


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

Notes:

1. We will use Open vSwitch to create our "physical" switch labeled br0

2. Our "physical" switch br0 will have one internal port also named br0
   and two "physical" ports, namely p0 and p1.

3. The host machine may have two external interfaces. We will use eth0
   for management traffic and eth1 for tunnel traffic (One can use
   a single interface to achieve both). Please take note of their IP
   addresses in the diagram. You do not have to use exactly
   the same IP addresses. Just know that the above will be used in the
   steps below.

4. You can optionally connect physical machines instead of virtual
   machines to switch br0. In that case:

   4.1. Make sure you have two extra physical interfaces in your host
        machine, eth2 and eth3.

   4.2. In the rest of this doc, replace p0 with eth2 and p1 with eth3.

5. In addition to implementing p0 and p1 as physical interfaces, you can
   also optionally implement them as standalone TAP devices, or VM
   interfaces for simulation.

6. Creating and attaching the VMs is outside the scope of this document
   and is included in the diagram for reference purposes only.

Startup
-------

These instructions describe how to run with a single ovsdb-server
instance that handles both the OVS and VTEP schema. You can skip
steps 1-3 if you installed using the debian packages as mentioned in
step 2 of the "Requirements" section.

1. Create the initial OVS and VTEP schemas:

      ```
ovsdb-tool create /etc/openvswitch/ovs.db vswitchd/vswitch.ovsschema
ovsdb-tool create /etc/openvswitch/vtep.db vtep/vtep.ovsschema
      ```

2. Start ovsdb-server and have it handle both databases:

      ```
ovsdb-server --pidfile --detach --log-file \
--remote punix:/var/run/openvswitch/db.sock \
--remote=db:hardware_vtep,Global,managers \
/etc/openvswitch/ovs.db /etc/openvswitch/vtep.db
      ```

3. Start OVS as normal:

      ```
ovs-vswitchd --log-file --detach --pidfile \
unix:/var/run/openvswitch/db.sock
      ```

4. Create a "physical" switch and its ports in OVS:

      ```
ovs-vsctl add-br br0
ovs-vsctl add-port br0 p0
ovs-vsctl add-port br0 p1
      ```

5. Configure the physical switch in the VTEP database:

      ```
vtep-ctl add-ps br0
vtep-ctl set Physical_Switch br0 tunnel_ips=10.2.2.1
      ```
      
6. Start the VTEP emulator. If you installed the components by reading the
   INSTALL.md file, run the following from the same directory as this
   README.md:

      ```
./ovs-vtep --log-file=/var/log/openvswitch/ovs-vtep.log \
--pidfile=/var/run/openvswitch/ovs-vtep.pid \
--detach br0
      ```

  If the installation was done by installing the openvswitch-vtep
  package, you can find ovs-vtep at /usr/share/openvswitch/scripts.

7. Configure the VTEP database's manager to point at an NVC:

      ```
vtep-ctl set-manager tcp:<CONTROLLER IP>:6640
      ```

   Where CONTROLLER IP is your controller's IP address that is accessible
   via the Host Machine's eth0 interface.

Simulating an NVC
-----------------

A VTEP implementation expects to be driven by a Network Virtualization
Controller (NVC), such as NSX.  If one does not exist, it's possible to
use vtep-ctl to simulate one:

1. Create a logical switch:

      ```
vtep-ctl add-ls ls0
      ```

2. Bind the logical switch to a port:

      ```
vtep-ctl bind-ls br0 p0 0 ls0
vtep-ctl set Logical_Switch ls0 tunnel_key=33
      ```

3. Direct unknown destinations out a tunnel:

      ```
vtep-ctl add-mcast-remote ls0 unknown-dst 10.2.2.2
      ```

4. Direct unicast destinations out a different tunnel:
      ```
vtep-ctl add-ucast-remote ls0 00:11:22:33:44:55 10.2.2.3
      ```
