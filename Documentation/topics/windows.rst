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

=====================
OVS-on-Hyper-V Design
=====================

This document provides details of the effort to develop Open vSwitch on
Microsoft Hyper-V. This document should give enough information to understand
the overall design.

.. note::
  The userspace portion of the OVS has been ported to Hyper-V in a separate
  effort, and committed to the openvswitch repo. This document will mostly
  emphasize on the kernel driver, though we touch upon some of the aspects of
  userspace as well.

Background Info
---------------

Microsoft’s hypervisor solution - Hyper-V [1]_ implements a virtual switch
that is extensible and provides opportunities for other vendors to implement
functional extensions [2]_. The extensions need to be implemented as NDIS
drivers that bind within the extensible switch driver stack provided. The
extensions can broadly provide the functionality of monitoring, modifying and
forwarding packets to destination ports on the Hyper-V extensible switch.
Correspondingly, the extensions can be categorized into the following types and
provide the functionality noted:

* Capturing extensions: monitoring packets

* Filtering extensions: monitoring, modifying packets

* Forwarding extensions: monitoring, modifying, forwarding packets

As can be expected, the kernel portion (datapath) of OVS on Hyper-V solution
will be implemented as a forwarding extension.

In Hyper-V, the virtual machine is called the Child Partition. Each VIF or
physical NIC on the Hyper-V extensible switch is attached via a port. Each port
is both on the ingress path or the egress path of the switch. The ingress path
is used for packets being sent out of a port, and egress is used for packet
being received on a port. By design, NDIS provides a layered interface. In this
layered interface, higher level layers call into lower level layers, in the
ingress path. In the egress path, it is the other way round. In addition, there
is a object identifier (OID) interface for control operations Eg. addition of a
port. The workflow for the calls is similar in nature to the packets, where
higher level layers call into the lower level layers. A good representational
diagram of this architecture is in [4]_.

Windows Filtering Platform (WFP) [5]_ is a platform implemented on Hyper-V that
provides APIs and services for filtering packets. WFP has been utilized to
filter on some of the packets that OVS is not equipped to handle directly. More
details in later sections.

IP Helper [6]_ is a set of API available on Hyper-V to retrieve information
related to the network configuration information on the host machine. IP Helper
has been used to retrieve some of the configuration information that OVS needs.

Design
------

::

    Various blocks of the OVS Windows implementation

                                      +-------------------------------+
                                      |                               |
                                      |        CHILD PARTITION        |
                                      |                               |
      +------+ +--------------+       | +-----------+  +------------+ |
      |      | |              |       | |           |  |            | |
      | ovs- | |     OVS-     |       | | Virtual   |  | Virtual    | |
      | *ctl | |  USERSPACE   |       | | Machine #1|  | Machine #2 | |
      |      | |    DAEMON    |       | |           |  |            | |
      +------+-++---+---------+       | +--+------+-+  +----+------++ | +--------+
      |  dpif-  |   | netdev- |       |    |VIF #1|         |VIF #2|  | |Physical|
      | netlink |   | windows |       |    +------+         +------+  | |  NIC   |
      +---------+   +---------+       |      ||                   /\  | +--------+
    User     /\         /\            |      || *#1*         *#4* ||  |     /\
    =========||=========||============+------||-------------------||--+     ||
    Kernel   ||         ||                   \/                   ||  ||=====/
             \/         \/                +-----+                 +-----+ *#5*
     +-------------------------------+    |     |                 |     |
     |   +----------------------+    |    |     |                 |     |
     |   |   OVS Pseudo Device  |    |    |     |                 |     |
     |   +----------------------+    |    |     |                 |     |
     |      | Netlink Impl. |        |    |     |                 |     |
     |      -----------------        |    |  I  |                 |     |
     | +------------+                |    |  N  |                 |  E  |
     | |  Flowtable | +------------+ |    |  G  |                 |  G  |
     | +------------+ |  Packet    | |*#2*|  R  |                 |  R  |
     |   +--------+   | Processing | |<=> |  E  |                 |  E  |
     |   |   WFP  |   |            | |    |  S  |                 |  S  |
     |   | Driver |   +------------+ |    |  S  |                 |  S  |
     |   +--------+                  |    |     |                 |     |
     |                               |    |     |                 |     |
     |   OVS FORWARDING EXTENSION    |    |     |                 |     |
     +-------------------------------+    +-----+-----------------+-----+
                                          |HYPER-V Extensible Switch *#3|
                                          +-----------------------------+
                                                   NDIS STACK

This diagram shows the various blocks involved in the OVS Windows
implementation, along with some of the components available in the NDIS stack,
and also the virtual machines. The workflow of a packet being transmitted from
a VIF out and into another VIF and to a physical NIC is also shown. Later on in
this section, we will discuss the flow of a packet at a high level.

The figure gives a general idea of where the OVS userspace and the kernel
components fit in, and how they interface with each other.

The kernel portion (datapath) of OVS on Hyper-V solution has be implemented as
a forwarding extension roughly implementing the following
sub-modules/functionality. Details of each of these sub-components in the
kernel are contained in later sections:

* Interfacing with the NDIS stack

* Netlink message parser

* Netlink sockets

* Switch/Datapath management

* Interfacing with userspace portion of the OVS solution to implement the
  necessary functionality that userspace needs

* Port management

* Flowtable/Actions/packet forwarding

* Tunneling

* Event notifications

The datapath for the OVS on Linux is a kernel module, and cannot be directly
ported since there are significant differences in architecture even though the
end functionality provided would be similar. Some examples of the differences
are:

* Interfacing with the NDIS stack to hook into the NDIS callbacks for
  functionality such as receiving and sending packets, packet completions, OIDs
  used for events such as a new port appearing on the virtual switch.

* Interface between the userspace and the kernel module.

* Event notifications are significantly different.

* The communication interface between DPIF and the kernel module need not be
  implemented in the way OVS on Linux does. That said, it would be advantageous
  to have a similar interface to the kernel module for reasons of readability
  and maintainability.

* Any licensing issues of using Linux kernel code directly.

Due to these differences, it was a straightforward decision to develop the
datapath for OVS on Hyper-V from scratch rather than porting the one on Linux.
A re-development focused on the following goals:

* Adhere to the existing requirements of userspace portion of OVS (such as
  ovs-vswitchd), to minimize changes in the userspace workflow.

* Fit well into the typical workflow of a Hyper-V extensible switch forwarding
  extension.

The userspace portion of the OVS solution is mostly POSIX code, and not very
Linux specific. Majority of the userspace code does not interface directly with
the kernel datapath and was ported independently of the kernel datapath effort.

As explained in the OVS porting design document [7]_, DPIF is the portion of
userspace that interfaces with the kernel portion of the OVS. The interface
that each DPIF provider has to implement is defined in ``dpif-provider.h``
[3]_.  Though each platform is allowed to have its own implementation of the
DPIF provider, it was found, via community feedback, that it is desired to
share code whenever possible. Thus, the DPIF provider for OVS on Hyper-V shares
code with the DPIF provider on Linux. This interface is implemented in
``dpif-netlink.c``.

We'll elaborate more on kernel-userspace interface in a dedicated section
below. Here it suffices to say that the DPIF provider implementation for
Windows is netlink-based and shares code with the Linux one.

Kernel Module (Datapath)
------------------------

Interfacing with the NDIS Stack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For each virtual switch on Hyper-V, the OVS extensible switch extension can be
enabled/disabled. We support enabling the OVS extension on only one switch.
This is consistent with using a single datapath in the kernel on Linux. All the
physical adapters are connected as external adapters to the extensible switch.

When the OVS switch extension registers itself as a filter driver, it also
registers callbacks for the switch/port management and datapath functions. In
other words, when a switch is created on the Hyper-V root partition (host), the
extension gets an activate callback upon which it can initialize the data
structures necessary for OVS to function. Similarly, there are callbacks for
when a port gets added to the Hyper-V switch, and an External Network adapter
or a VM Network adapter is connected/disconnected to the port. There are also
callbacks for when a VIF (NIC of a child partition) send out a packet, or a
packet is received on an external NIC.

As shown in the figures, an extensible switch extension gets to see a packet
sent by the VM (VIF) twice - once on the ingress path and once on the egress
path. Forwarding decisions are to be made on the ingress path. Correspondingly,
we will be hooking onto the following interfaces:

* Ingress send indication: intercept packets for performing flow based
  forwarding.This includes straight forwarding to output ports. Any packet
  modifications needed to be performed are done here either inline or by
  creating a new packet. A forwarding action is performed as the flow actions
  dictate.

* Ingress completion indication: cleanup and free packets that we generated on
  the ingress send path, pass-through for packets that we did not generate.

* Egress receive indication: pass-through.

* Egress completion indication: pass-through.

Interfacing with OVS Userspace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We have implemented a pseudo device interface for letting OVS userspace talk to
the OVS kernel module. This is equivalent to the typical character device
interface on POSIX platforms where we can register custom functions for read,
write and ioctl functionality. The pseudo device supports a whole bunch of
ioctls that netdev and DPIF on OVS userspace make use of.

Netlink Message Parser
~~~~~~~~~~~~~~~~~~~~~~

The communication between OVS userspace and OVS kernel datapath is in the form
of Netlink messages [1]_, [8]_. More details about this are provided below.  In the
kernel, a full fledged netlink message parser has been implemented along the
lines of the netlink message parser in OVS userspace. In fact, a lot of the
code is ported code.

On the lines of ``struct ofpbuf`` in OVS userspace, a managed buffer has been
implemented in the kernel datapath to make it easier to parse and construct
netlink messages.

Netlink Sockets
~~~~~~~~~~~~~~~

On Linux, OVS userspace utilizes netlink sockets to pass back and forth netlink
messages. Since much of userspace code including DPIF provider in
dpif-netlink.c (formerly dpif-linux.c) has been reused, pseudo-netlink sockets
have been implemented in OVS userspace. As it is known, Windows lacks native
netlink socket support, and also the socket family is not extensible either.
Hence it is not possible to provide a native implementation of netlink socket.
We emulate netlink sockets in lib/netlink-socket.c and support all of the nl_*
APIs to higher levels. The implementation opens a handle to the pseudo device
for each netlink socket. Some more details on this topic are provided in the
userspace section on netlink sockets.

Typical netlink semantics of read message, write message, dump, and transaction
have been implemented so that higher level layers are not affected by the
netlink implementation not being native.

Switch/Datapath Management
~~~~~~~~~~~~~~~~~~~~~~~~~~

As explained above, we hook onto the management callback functions in the NDIS
interface for when to initialize the OVS data structures, flow tables etc. Some
of this code is also driven by OVS userspace code which sends down ioctls for
operations like creating a tunnel port etc.

Port Management
~~~~~~~~~~~~~~~

As explained above, we hook onto the management callback functions in the NDIS
interface to know when a port is added/connected to the Hyper-V switch. We use
these callbacks to initialize the port related data structures in OVS. Also,
some of the ports are tunnel ports that don’t exist on the Hyper-V switch and
get added from OVS userspace.

In order to identify a Hyper-V port, we use the value of 'FriendlyName' field
in each Hyper-V port. We call this the "OVS-port-name". The idea is that OVS
userspace sets 'OVS-port-name' in each Hyper-V port to the same value as the
'name' field of the 'Interface' table in OVSDB. When OVS userspace calls into
the kernel datapath to add a port, we match the name of the port with the
'OVS-port-name' of a Hyper-V port.

We maintain separate hash tables, and separate counters for ports that have
been added from the Hyper-V switch, and for ports that have been added from OVS
userspace.

Flowtable/Actions/Packet Forwarding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The flowtable and flow actions based packet forwarding is the core of the OVS
datapath functionality. For each packet on the ingress path, we consult the
flowtable and execute the corresponding actions. The actions can be limited to
simple forwarding to a particular destination port(s), or more commonly
involves modifying the packet to insert a tunnel context or a VLAN ID, and
thereafter forwarding to the external port to send the packet to a destination
host.

Tunneling
~~~~~~~~~

We make use of the Internal Port on a Hyper-V switch for implementing
tunneling. The Internal Port is a virtual adapter that is exposed on the Hyper-
V host, and connected to the Hyper-V switch. Basically, it is an interface
between the host and the virtual switch. The Internal Port acts as the Tunnel
end point for the host (aka VTEP), and holds the VTEP IP address.

Tunneling ports are not actual ports on the Hyper-V switch. These are virtual
ports that OVS maintains and while executing actions, if the outport is a
tunnel port, we short circuit by performing the encapsulation action based on
the tunnel context. The encapsulated packet gets forwarded to the external
port, and appears to the outside world as though it was set from the VTEP.

Similarly, when a tunneled packet enters the OVS from the external port bound
to the internal port (VTEP), and if yes, we short circuit the path, and
directly forward the inner packet to the destination port (mostly a VIF, but
dictated by the flow). We leverage the Windows Filtering Platform (WFP)
framework to be able to receive tunneled packets that cannot be decapsulated by
OVS right away. Currently, fragmented IP packets fall into that category, and
we leverage the code in the host IP stack to reassemble the packet, and
performing decapsulation on the reassembled packet.

We'll also be using the IP helper library to provide us IP address and other
information corresponding to the Internal port.

Event Notifications
~~~~~~~~~~~~~~~~~~~

The pseudo device interface described above is also used for providing event
notifications back to OVS userspace. A shared memory/overlapped IO model is
used.

Userspace Components
~~~~~~~~~~~~~~~~~~~~

The userspace portion of the OVS solution is mostly POSIX code, and not very
Linux specific. Majority of the userspace code does not interface directly with
the kernel datapath and was ported independently of the kernel datapath effort.

In this section, we cover the userspace components that interface with the
kernel datapath.

As explained earlier, OVS on Hyper-V shares the DPIF provider implementation
with Linux. The DPIF provider on Linux uses netlink sockets and netlink
messages. Netlink sockets and messages are extensively used on Linux to
exchange information between userspace and kernel. In order to satisfy these
dependencies, netlink socket (pseudo and non-native) and netlink messages are
implemented on Hyper-V.

The following are the major advantages of sharing DPIF provider code:

1. Maintenance is simpler:

   Any change made to the interface defined in dpif-provider.h need not be
   propagated to multiple implementations. Also, developers familiar with the
   Linux implementation of the DPIF provider can easily ramp on the Hyper-V
   implementation as well.

2. Netlink messages provides inherent advantages:

   Netlink messages are known for their extensibility. Each message is
   versioned, so the provided data structures offer a mechanism to perform
   version checking and forward/backward compatibility with the kernel module.

Netlink Sockets
~~~~~~~~~~~~~~~

As explained in other sections, an emulation of netlink sockets has been
implemented in ``lib/netlink-socket.c`` for Windows. The implementation creates
a handle to the OVS pseudo device, and emulates netlink socket semantics of
receive message, send message, dump, and transact. Most of the ``nl_*``
functions are supported.

The fact that the implementation is non-native manifests in various ways.  One
example is that PID for the netlink socket is not automatically assigned in
userspace when a handle is created to the OVS pseudo device. There's an extra
command (defined in ``OvsDpInterfaceExt.h``) that is used to grab the PID
generated in the kernel.

DPIF Provider
~~~~~~~~~~~~~

As has been mentioned in earlier sections, the netlink socket and netlink
message based DPIF provider on Linux has been ported to Windows.

Most of the code is common. Some divergence is in the code to receive packets.
The Linux implementation uses epoll() [9]_ which is not natively supported on
Windows.

netdev-windows
~~~~~~~~~~~~~~

We have a Windows implementation of the interface defined in
``lib/netdev-provider.h``. The implementation provides functionality to get
extended information about an interface. It is limited in functionality
compared to the Linux implementation of the netdev provider and cannot be used
to add any interfaces in the kernel such as a tap interface or to send/receive
packets. The netdev-windows implementation uses the datapath interface
extensions defined in ``datapath-windows/include/OvsDpInterfaceExt.h``.

Powershell Extensions to Set ``OVS-port-name``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As explained in the section on "Port management", each Hyper-V port has a
'FriendlyName' field, which we call as the "OVS-port-name" field. We have
implemented powershell command extensions to be able to set the "OVS-port-name"
of a Hyper-V port.

Kernel-Userspace Interface
--------------------------

openvswitch.h and OvsDpInterfaceExt.h
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since the DPIF provider is shared with Linux, the kernel datapath provides the
same interface as the Linux datapath. The interface is defined in
``datapath/linux/compat/include/linux/openvswitch.h``. Derivatives of this
interface file are created during OVS userspace compilation. The derivative for
the kernel datapath on Hyper-V is provided in
``datapath-windows/include/OvsDpInterface.h``.

That said, there are Windows specific extensions that are defined in the
interface file ``datapath-windows/include/OvsDpInterfaceExt.h``.

Flow of a Packet
----------------

Figure 2 shows the numbered steps in which a packets gets sent out of a VIF and
is forwarded to another VIF or a physical NIC. As mentioned earlier, each VIF
is attached to the switch via a port, and each port is both on the ingress and
egress path of the switch, and depending on whether a packet is being
transmitted or received, one of the paths gets used. In the figure, each step n
is annotated as ``#n``

The steps are as follows:

1. When a packet is sent out of a VIF or an physical NIC or an internal port,
   the packet is part of the ingress path.

2. The OVS kernel driver gets to intercept this packet.

   a. OVS looks up the flows in the flowtable for this packet, and executes the
      corresponding action.

   b. If there is not action, the packet is sent up to OVS userspace to examine
      the packet and figure out the actions.

   c. Userspace executes the packet by specifying the actions, and might also
      insert a flow for such a packet in the future.

   d. The destination ports are added to the packet and sent down to the Hyper-
      V switch.

3. The Hyper-V forwards the packet to the destination ports specified in the
   packet, and sends it out on the egress path.

4. The packet gets forwarded to the destination VIF.

5. It might also get forwarded to a physical NIC as well, if the physical NIC
   has been added as a destination port by OVS.

Build/Deployment
----------------

The userspace components added as part of OVS Windows implementation have been
integrated with autoconf, and can be built using the steps mentioned in the
BUILD.Windows file. Additional targets need to be specified to make.

The OVS kernel code is part of a Visual Studio 2013 solution, and is compiled
from the IDE. There are plans in the future to move this to a compilation mode
such that we can compile it without an IDE as well.

Once compiled, we have an install script that can be used to load the kernel
driver.

References
----------

.. [1] Hyper-V Extensible Switch https://msdn.microsoft.com/windows/hardware/drivers/network/hyper-v-extensible-switch
.. [2] Hyper-V Extensible Switch Extensions https://msdn.microsoft.com/windows/hardware/drivers/network/hyper-v-extensible-switch-extensions
.. [3] DPIF Provider http://openvswitch.sourcearchive.com/documentation/1.1.0-1/dpif-provider_8h_source.html
.. [4] Hyper-V Extensible Switch Components https://msdn.microsoft.com/windows/hardware/drivers/network/hyper-v-extensible-switch-components
.. [5] Windows Filtering Platform https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx
.. [6] IP Helper https://msdn.microsoft.com/windows/hardware/drivers/network/ip-helper
.. [7] How to Port Open vSwitch to New Software or Hardware :doc:`porting`
.. [8] Netlink https://en.wikipedia.org/wiki/Netlink
.. [9] epoll https://en.wikipedia.org/wiki/Epoll
