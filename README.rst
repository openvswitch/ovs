============
Open vSwitch
============

Build Status
------------

.. image:: https://travis-ci.org/openvswitch/ovs.png
    :target: https://travis-ci.org/openvswitch/ovs

What is Open vSwitch?
---------------------

Open vSwitch is a multilayer software switch licensed under the open source
Apache 2 license.  Our goal is to implement a production quality switch
platform that supports standard management interfaces and opens the forwarding
functions to programmatic extension and control.

Open vSwitch is well suited to function as a virtual switch in VM environments.
In addition to exposing standard control and visibility interfaces to the
virtual networking layer, it was designed to support distribution across
multiple physical servers.  Open vSwitch supports multiple Linux-based
virtualization technologies including Xen/XenServer, KVM, and VirtualBox.

The bulk of the code is written in platform-independent C and is easily ported
to other environments.  The current release of Open vSwitch supports the
following features:

- Standard 802.1Q VLAN model with trunk and access ports
- NIC bonding with or without LACP on upstream switch
- NetFlow, sFlow(R), and mirroring for increased visibility
- QoS (Quality of Service) configuration, plus policing
- Geneve, GRE, VXLAN, STT, and LISP tunneling
- 802.1ag connectivity fault management
- OpenFlow 1.0 plus numerous extensions
- Transactional configuration database with C and Python bindings
- High-performance forwarding using a Linux kernel module

The included Linux kernel module supports Linux 3.10 and up.

Open vSwitch can also operate, at a cost in performance, entirely in userspace,
without assistance from a kernel module.  This userspace implementation should
be easier to port than the kernel-based switch.  It is considered experimental.

What's here?
------------

The main components of this distribution are:

- ovs-vswitchd, a daemon that implements the switch, along with a companion
  Linux kernel module for flow-based switching.
- ovsdb-server, a lightweight database server that ovs-vswitchd queries to
  obtain its configuration.
- ovs-dpctl, a tool for configuring the switch kernel module.
- Scripts and specs for building RPMs for Citrix XenServer and Red Hat
  Enterprise Linux.  The XenServer RPMs allow Open vSwitch to be installed on a
  Citrix XenServer host as a drop-in replacement for its switch, with
  additional functionality.
- ovs-vsctl, a utility for querying and updating the configuration of
  ovs-vswitchd.
- ovs-appctl, a utility that sends commands to running Open vSwitch daemons.

Open vSwitch also provides some tools:

- ovs-ofctl, a utility for querying and controlling OpenFlow switches and
  controllers.
- ovs-pki, a utility for creating and managing the public-key infrastructure
  for OpenFlow switches.
- ovs-testcontroller, a simple OpenFlow controller that may be useful for
  testing (though not for production).
- A patch to tcpdump that enables it to parse OpenFlow messages.

What other documentation is available?
--------------------------------------

To install Open vSwitch on a regular Linux or FreeBSD host, please read the
`installation guide <INSTALL.rst>`__. For specifics around installation on a
specific platform, please see one of the below installation guides:

- `Debian <INSTALL.Debian.rst>`__
- `Fedora <INSTALL.Fedora.rst>`__
- `RHEL <INSTALL.RHEL.rst>`__
- `XenServer <INSTALL.XenServer.rst>`__
- `Windows <INSTALL.Windows.rst>`__

To use Open vSwitch...

- ...with Docker on Linux, see `here <INSTALL.Docker.rst>`__.

- ...with KVM on Linux, see `here <INSTALL.rst>`__ and `here
  <INSTALL.KVM.rst>`__.

- ...with Libvirt, see `here <INSTALL.Libvirt.rst>`__.

- ...without using a kernel module, see `here <INSTALL.userspace.rst>`__.

- ...with DPDK, see `here <INSTALL.DPDK.rst>`__.

- ...with SELinux, see `here <INSTALL.SELinux.rst>`__.

For answers to common questions, refer to the `FAQ <FAQ.rst>`__.

To learn how to set up SSL support for Open vSwitch, see `here
<INSTALL.SSL.rst>`__.

To learn about some advanced features of the Open vSwitch software switch, read
the `tutorial <tutorial/tutorial.rst>`__.

Each Open vSwitch userspace program is accompanied by a manpage.  Many of the
manpages are customized to your configuration as part of the build process, so
we recommend building Open vSwitch before reading the manpages.

Contact
-------

bugs@openvswitch.org
