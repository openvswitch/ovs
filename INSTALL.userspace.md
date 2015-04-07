Using Open vSwitch without kernel support
=========================================

Open vSwitch can operate, at a cost in performance, entirely in
userspace, without assistance from a kernel module.  This file
explains how to install Open vSwitch in such a mode.

The userspace-only mode of Open vSwitch is considered experimental.
It has not been thoroughly tested.

This version of Open vSwitch should be built manually with `configure`
and `make`.  Debian packaging for Open vSwitch is also included, but
it has not been recently tested, and so Debian packages are not a
recommended way to use this version of Open vSwitch.

Building and Installing
-----------------------

The requirements and procedure for building, installing, and
configuring Open vSwitch are the same as those given in [INSTALL.md].
You may omit configuring, building, and installing the kernel module,
and the related requirements.

On Linux, the userspace switch additionally requires the kernel
TUN/TAP driver to be available, either built into the kernel or loaded
as a module.  If you are not sure, check for a directory named
/sys/class/misc/tun.  If it does not exist, then attempt to load the
module with `modprobe tun`.

The tun device must also exist as `/dev/net/tun`.  If it does not exist,
then create /dev/net (if necessary) with `mkdir /dev/net`, then create
`/dev/net/tun` with `mknod /dev/net/tun c 10 200`.

On FreeBSD and NetBSD, the userspace switch additionally requires the
kernel tap(4) driver to be available, either built into the kernel or
loaded as a module.

Using the Userspace Datapath with ovs-vswitchd
----------------------------------------------

To use ovs-vswitchd in userspace mode, create a bridge with datapath_type
"netdev" in the configuration database.  For example:

    ovs-vsctl add-br br0
    ovs-vsctl set bridge br0 datapath_type=netdev
    ovs-vsctl add-port br0 eth0
    ovs-vsctl add-port br0 eth1
    ovs-vsctl add-port br0 eth2

ovs-vswitchd will create a TAP device as the bridge's local interface,
named the same as the bridge, as well as for each configured internal
interface.

Currently, on FreeBSD, the functionality required for in-band control
support is not implemented.  To avoid related errors, you can disable
the in-band support with the following command.

    ovs-vsctl set bridge br0 other_config:disable-in-band=true

Firewall Rules
--------------

On Linux, when a physical interface is in use by the userspace
datapath, packets received on the interface still also pass into the
kernel TCP/IP stack.  This can cause surprising and incorrect
behavior.  You can use "iptables" to avoid this behavior, by using it
to drop received packets.  For example, to drop packets received on
eth0:

    iptables -A INPUT -i eth0 -j DROP
    iptables -A FORWARD -i eth0 -j DROP

Other settings
--------------

On NetBSD, depending on your network topology and applications, the
following configuration might help.  See sysctl(7).

    sysctl -w net.inet.ip.checkinterface=1

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.

[INSTALL.md]:INSTALL.md
