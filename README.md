Open vSwitch
============

Build Status:
-------------

[![Build Status](https://travis-ci.org/openvswitch/ovs.png)](https://travis-ci.org/openvswitch/ovs)

What is Open vSwitch?
---------------------

Open vSwitch is a multilayer software switch licensed under the open
source Apache 2 license.  Our goal is to implement a production
quality switch platform that supports standard management interfaces
and opens the forwarding functions to programmatic extension and
control.

Open vSwitch is well suited to function as a virtual switch in VM
environments.  In addition to exposing standard control and visibility
interfaces to the virtual networking layer, it was designed to support
distribution across multiple physical servers.  Open vSwitch supports
multiple Linux-based virtualization technologies including
Xen/XenServer, KVM, and VirtualBox.

The bulk of the code is written in platform-independent C and is
easily ported to other environments.  The current release of Open
vSwitch supports the following features:

* Standard 802.1Q VLAN model with trunk and access ports
* NIC bonding with or without LACP on upstream switch
* NetFlow, sFlow(R), and mirroring for increased visibility
* QoS (Quality of Service) configuration, plus policing
* Geneve, GRE, GRE over IPSEC, VXLAN, and LISP tunneling
* 802.1ag connectivity fault management
* OpenFlow 1.0 plus numerous extensions
* Transactional configuration database with C and Python bindings
* High-performance forwarding using a Linux kernel module

The included Linux kernel module supports Linux 2.6.32 and up, with
testing focused on 2.6.32 with Centos and Xen patches.  Open vSwitch
also has special support for Citrix XenServer and Red Hat Enterprise
Linux hosts.

Open vSwitch can also operate, at a cost in performance, entirely in
userspace, without assistance from a kernel module.  This userspace
implementation should be easier to port than the kernel-based switch.
It is considered experimental.

What's here?
------------

The main components of this distribution are:

* ovs-vswitchd, a daemon that implements the switch, along with
  a companion Linux kernel module for flow-based switching.
* ovsdb-server, a lightweight database server that ovs-vswitchd
  queries to obtain its configuration.
* ovs-dpctl, a tool for configuring the switch kernel module.
* Scripts and specs for building RPMs for Citrix XenServer and Red
  Hat Enterprise Linux.  The XenServer RPMs allow Open vSwitch to
  be installed on a Citrix XenServer host as a drop-in replacement
  for its switch, with additional functionality.
* ovs-vsctl, a utility for querying and updating the configuration
  of ovs-vswitchd.
* ovs-appctl, a utility that sends commands to running Open
      vSwitch daemons.

Open vSwitch also provides some tools:

* ovs-ofctl, a utility for querying and controlling OpenFlow
  switches and controllers.
* ovs-pki, a utility for creating and managing the public-key
  infrastructure for OpenFlow switches.
* ovs-testcontroller, a simple OpenFlow controller that may be useful
  for testing (though not for production).
* A patch to tcpdump that enables it to parse OpenFlow messages.

What other documentation is available?
--------------------------------------

To install Open vSwitch on a regular Linux or FreeBSD host, please
read [INSTALL.md]. For specifics around installation on a specific
platform, please see one of these files:

- [INSTALL.Debian.md]
- [INSTALL.Fedora.md]
- [INSTALL.RHEL.md]
- [INSTALL.XenServer.md]

To use Open vSwitch...

- ...with Docker on Linux, read [INSTALL.Docker.md]

- ...with KVM on Linux, read [INSTALL.md], read [INSTALL.KVM.md]

- ...with Libvirt, read [INSTALL.Libvirt.md].

- ...without using a kernel module, read [INSTALL.userspace.md].

For answers to common questions, read [FAQ.md].

To learn how to set up SSL support for Open vSwitch, read [INSTALL.SSL.md].

To learn about some advanced features of the Open vSwitch software
switch, read the [tutorial/Tutorial.md].

Each Open vSwitch userspace program is accompanied by a manpage.  Many
of the manpages are customized to your configuration as part of the
build process, so we recommend building Open vSwitch before reading
the manpages.

Contact
-------

bugs@openvswitch.org

[INSTALL.md]:INSTALL.md
[INSTALL.Debian.md]:INSTALL.Debian.md
[INSTALL.Docker.md]:INSTALL.Docker.md
[INSTALL.Fedora.md]:INSTALL.Fedora.md
[INSTALL.KVM.md]:INSTALL.KVM.md
[INSTALL.Libvirt.md]:INSTALL.Libvirt.md
[INSTALL.RHEL.md]:INSTALL.RHEL.md
[INSTALL.SSL.md]:INSTALL.SSL.md
[INSTALL.userspace.md]:INSTALL.userspace.md
[INSTALL.XenServer.md]:INSTALL.XenServer.md
[FAQ.md]:FAQ.md
[tutorial/Tutorial.md]:tutorial/Tutorial.md
