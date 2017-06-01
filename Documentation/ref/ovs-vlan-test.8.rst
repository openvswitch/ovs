=============
ovs-vlan-test
=============

Synopsis
========

**ovs-vlan-test** [**-s** | **--server**] *control_ip* *vlan_ip*

Description
===========

The :program:`ovs-vlan-test` utility has some limitations, for example, it does
not use TCP in its tests. Also it does not take into account MTU to detect
potential edge cases. To overcome those limitations a new tool was developed -
:program:`ovs-test`. :program:`ovs-test` is currently supported only on Debian
so, if possible, try to use that on instead of :program:`ovs-vlan-test`.

The :program:`ovs-vlan-test` program may be used to check for problems sending
802.1Q traffic which may occur when running Open vSwitch. These problems can
occur when Open vSwitch is used to send 802.1Q traffic through physical
interfaces running certain drivers of certain Linux kernel versions. To run a
test, configure Open vSwitch to tag traffic originating from `vlan_ip` and
forward it out the target interface. Then run the :program:`ovs-vlan-test` in
client mode connecting to an :program:`ovs-vlan-test` server.
:program:`ovs-vlan-test` will display "OK" if it did not detect problems.

Some examples of the types of problems that may be encountered are:

- When NICs use VLAN stripping on receive they must pass a pointer to a
  `vlan_group` when reporting the stripped tag to the networking core. If no
  `vlan_group` is in use then some drivers just drop the extracted tag.
  Drivers are supposed to only enable stripping if a `vlan_group` is registered
  but not all of them do that.

- On receive, some drivers handle priority tagged packets specially and don't
  pass the tag onto the network stack at all, so Open vSwitch never has a
  chance to see it.

- Some drivers size their receive buffers based on whether a `vlan_group` is
  enabled, meaning that a maximum size packet with a VLAN tag will not fit if
  no `vlan_group` is configured.

- On transmit, some drivers expect that VLAN acceleration will be used if it is
  available, which can only be done if a `vlan_group` is configured. In these
  cases, the driver may fail to parse the packet and correctly setup checksum
  offloading or TSO.

Client Mode
  An :program:`ovs-vlan-test` client may be run on a host to check for VLAN
  connectivity problems. The client must be able to establish HTTP connections
  with an :program:`ovs-vlan-test` server located at the specified `control_ip`
  address. UDP traffic sourced at `vlan_ip` should be tagged and directed out
  the interface whose connectivity is being tested.

Server Mode
  To conduct tests, an :program:`ovs-vlan-test` server must be running on a
  host known not to have VLAN connectivity problems. The server must have a
  `control_ip` on a non-VLAN network which clients can establish connectivity
  with. It must also have a `vlan_ip` address on a VLAN network which clients
  will use to test their VLAN connectivity. Multiple clients may test against a
  single :program:`ovs-vlan-test` server concurrently.

Options
=======

.. program:: ovs-vlan-test

.. option:: -s, --server

    Run in server mode.

.. option:: -h, --help

    Prints a brief help message to the console.

.. option:: -V, --version

    Prints version information to the console.

Examples
========

Display the Linux kernel version and driver of `eth1`::

   uname -r
   ethtool -i eth1

Set up a bridge which forwards traffic originating from `1.2.3.4` out `eth1`
with VLAN tag 10::

    ovs-vsctl -- add-br vlan-br \
      -- add-port vlan-br eth1 \
      -- add-port vlan-br vlan-br-tag tag=10 \
      -- set Interface vlan-br-tag type=internal
    ip addr add 1.2.3.4/8 dev vlan-br-tag
    ip link set vlan-br-tag up

Run an :program:`ovs-vlan-test` server listening for client control traffic on
`172.16.0.142` port `8080` and VLAN traffic on the default port of `1.2.3.3`::

    ovs-vlan-test -s 172.16.0.142:8080 1.2.3.3

Run an :program:`ovs-vlan-test` client with a control server located at
`172.16.0.142` port `8080` and a local VLAN IP of `1.2.3.4`::

    ovs-vlan-test 172.16.0.142:8080 1.2.3.4

See Also
========

`ovs-vswitchd(8)`, `ovs-ofctl(8)`, `ovs-vsctl(8)`, :program:`ovs-test`,
`ethtool(8)`, `uname(1)`
