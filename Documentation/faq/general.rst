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

=======
General
=======

Q: What is Open vSwitch?

    A: Open vSwitch is a production quality open source software switch
    designed to be used as a vswitch in virtualized server environments.  A
    vswitch forwards traffic between different VMs on the same physical host
    and also forwards traffic between VMs and the physical network.  Open
    vSwitch supports standard management interfaces (e.g. sFlow, NetFlow,
    IPFIX, RSPAN, CLI), and is open to programmatic extension and control using
    OpenFlow and the OVSDB management protocol.

    Open vSwitch as designed to be compatible with modern switching chipsets.
    This means that it can be ported to existing high-fanout switches allowing
    the same flexible control of the physical infrastructure as the virtual
    infrastructure.  It also means that Open vSwitch will be able to take
    advantage of on-NIC switching chipsets as their functionality matures.

Q: What virtualization platforms can use Open vSwitch?

    A: Open vSwitch can currently run on any Linux-based virtualization
    platform (kernel 3.10 and newer), including: KVM, VirtualBox, Xen, Xen
    Cloud Platform, XenServer. As of Linux 3.3 it is part of the mainline
    kernel.  The bulk of the code is written in platform- independent C and is
    easily ported to other environments.  We welcome inquires about integrating
    Open vSwitch with other virtualization platforms.

Q: How can I try Open vSwitch?

    A: The Open vSwitch source code can be built on a Linux system.  You can
    build and experiment with Open vSwitch on any Linux machine.  Packages for
    various Linux distributions are available on many platforms, including:
    Debian, Ubuntu, Fedora.

    You may also download and run a virtualization platform that already has
    Open vSwitch integrated.  For example, download a recent ISO for XenServer
    or Xen Cloud Platform.  Be aware that the version integrated with a
    particular platform may not be the most recent Open vSwitch release.

Q: Does Open vSwitch only work on Linux?

    A: No, Open vSwitch has been ported to a number of different operating
    systems and hardware platforms.  Most of the development work occurs on
    Linux, but the code should be portable to any POSIX system.  We've seen
    Open vSwitch ported to a number of different platforms, including FreeBSD,
    Windows, and even non-POSIX embedded systems.

    By definition, the Open vSwitch Linux kernel module only works on Linux and
    will provide the highest performance.  However, a userspace datapath is
    available that should be very portable.

Q: What's involved with porting Open vSwitch to a new platform or switching ASIC?

    A: :doc:`/topics/porting` describes how one would go about porting Open
    vSwitch to a new operating system or hardware platform.

Q: Why would I use Open vSwitch instead of the Linux bridge?

    A: Open vSwitch is specially designed to make it easier to manage VM
    network configuration and monitor state spread across many physical hosts
    in dynamic virtualized environments.  Refer to :doc:`/intro/why-ovs` for a
    more detailed description of how Open vSwitch relates to the Linux Bridge.

Q: How is Open vSwitch related to distributed virtual switches like the VMware
vNetwork distributed switch or the Cisco Nexus 1000V?

    A: Distributed vswitch applications (e.g., VMware vNetwork distributed
    switch, Cisco Nexus 1000V) provide a centralized way to configure and
    monitor the network state of VMs that are spread across many physical
    hosts.  Open vSwitch is not a distributed vswitch itself, rather it runs on
    each physical host and supports remote management in a way that makes it
    easier for developers of virtualization/cloud management platforms to offer
    distributed vswitch capabilities.

    To aid in distribution, Open vSwitch provides two open protocols that are
    specially designed for remote management in virtualized network
    environments: OpenFlow, which exposes flow-based forwarding state, and the
    OVSDB management protocol, which exposes switch port state.  In addition to
    the switch implementation itself, Open vSwitch includes tools (ovs-ofctl,
    ovs-vsctl) that developers can script and extend to provide distributed
    vswitch capabilities that are closely integrated with their virtualization
    management platform.

Q: Why doesn't Open vSwitch support distribution?

    A: Open vSwitch is intended to be a useful component for building flexible
    network infrastructure. There are many different approaches to distribution
    which balance trade-offs between simplicity, scalability, hardware
    compatibility, convergence times, logical forwarding model, etc. The goal
    of Open vSwitch is to be able to support all as a primitive building block
    rather than choose a particular point in the distributed design space.

Q: How can I contribute to the Open vSwitch Community?

    A: You can start by joining the mailing lists and helping to answer
    questions.  You can also suggest improvements to documentation.  If you
    have a feature or bug you would like to work on, send a mail to one of the
    :doc:`mailing lists </internals/mailing-lists>`.

Q: Why can I no longer connect to my OpenFlow controller or OVSDB manager?

    A: Starting in OVS 2.4, we switched the default ports to the IANA-specified
    port numbers for OpenFlow (6633->6653) and OVSDB (6632->6640).  We
    recommend using these port numbers, but if you cannot, all the programs
    allow overriding the default port.  See the appropriate man page.
