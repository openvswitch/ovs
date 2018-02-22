===================================
Red Hat network scripts integration
===================================

The RPM packages for Open vSwitch provide some integration with Red Hat's
network scripts.  Using this integration is optional.

To use the integration for a Open vSwitch bridge or interface named ``<name>``,
create or edit ``/etc/sysconfig/network-scripts/ifcfg-<name>``.  This is a
shell script that consists of a series of ``VARIABLE=VALUE`` assignments.  The
following OVS-specific variable names are supported:

DEVICETYPE
  Always set to "ovs".

TYPE
  If this is "OVSBridge", then this file represents an OVS bridge named <name>.
  Otherwise, it represents a port on an OVS bridge and TYPE must have one of
  the following values:

  * ``OVSPort``, if ``<name>`` is a physical port (e.g. eth0) or
    virtual port (e.g. vif1.0).

  * ``OVSIntPort``, if ``<name>`` is an internal port (e.g. a tagged
    VLAN).

  * ``OVSBond``, if ``<name>`` is an OVS bond.

  * ``OVSTunnel``, if ``<name>`` is an OVS tunnel.

  * ``OVSPatchPort``, if ``<name>`` is a patch port

  Additionally the following DPDK port types may be available, depends on OVS
  build- and runtime configuration:

  * ``OVSDPDKPort``, if ``<name>`` is a physical DPDK NIC port (name must start
    with ``dpdk`` and end with portid, eg ``dpdk0``)

  * ``OVSDPDKRPort``, if ``<name>`` is a DPDK ring port (name must start with
    ``dpdkr`` and end with portid, e.g. ``dpdkr0``)

  * ``OVSDPDKVhostUserPort`` if ``<name>`` is a DPDK vhost-user port

  * ``OVSDPDKBond`` if ``<name>`` is an OVS DPDK bond.

OVS_BRIDGE
  If TYPE is anything other than "OVSBridge", set to the name of the OVS bridge
  to which the port should be attached.

OVS_OPTIONS
  Optionally, extra options to set in the "Port" table when adding the port to
  the bridge, as a sequence of column[:key]=value options.  For example,
  "tag=100" to make the port an access port for VLAN 100.  See the
  documentation of "add-port" in ovs-vsctl(8) for syntax and the section on the
  Port table in ovs-vswitchd.conf.db(5) for available options.

OVS_EXTRA
  Optionally, additional ovs-vsctl commands, separated by ``--`` (double dash).

BOND_IFACES
  For "OVSBond" and "OVSDPDKBond" interfaces, a list of physical interfaces to
  bond together.

OVS_TUNNEL_TYPE
  For "OVSTunnel" interfaces, the type of the tunnel.  For example, "gre",
  "vxlan", etc.

OVS_TUNNEL_OPTIONS
  For "OVSTunnel" interfaces, this field should be used to specify the tunnel
  options like remote_ip, key, etc.

OVS_PATCH_PEER
  For "OVSPatchPort" devices, this field specifies the patch's peer on the
  other bridge.

OVS_PORT_MODE
  For "OVSDPDKVhostUserPort" devices, this field can be set to "client" which
  indicates that the port will be used in client mode.

OVS_PORT_PATH
  For "OVSDPDKVhostUserPort" devices, this field specifies the path to the
  vhost-user server socket.  It will only be used if OVS_PORT_MODE is set to
  "client".

Note
----

* ``ifdown`` on a bridge will not bring individual ports on the bridge down.
  "ifup" on a bridge will not add ports to the bridge.  This behavior should be
  compatible with standard bridges (with ``TYPE=Bridge``).

* If ``ifup`` on an interface is called multiple times, one can see ``RTNETLINK
  answers: File exists`` printed on the console. This comes from ifup-eth
  trying to add zeroconf route multiple times and is harmless.

* ``ifup`` on OVSDPDKPort or OVSDPDKBond may result in change of bridge mac address.
  Since OVS changes the device state to DOWN before changing its mac address this
  result in loss of bridge configuration (e.g. routes). ``ifup-ovs`` perform post-up
  operation on the bridge again to restore configuration.

Examples
--------

Standalone bridge:

::

    ==> ifcfg-ovsbridge0 <==
    DEVICE=ovsbridge0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSBridge
    BOOTPROTO=static
    IPADDR=A.B.C.D
    NETMASK=X.Y.Z.0
    HOTPLUG=no

Enable DHCP on the bridge:

* Needs ``OVSBOOTPROTO`` instead of ``BOOTPROTO``.
* All the interfaces that can reach the DHCP server as a space separated list
  in ``OVSDHCPINTERFACES``.

::

    DEVICE=ovsbridge0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSBridge
    OVSBOOTPROTO="dhcp"
    OVSDHCPINTERFACES="eth0"
    HOTPLUG=no


Adding Internal Port to ovsbridge0:

::

    ==> ifcfg-intbr0 <==
    DEVICE=intbr0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSIntPort
    OVS_BRIDGE=ovsbridge0
    HOTPLUG=no

Internal Port with fixed IP address:

::

    DEVICE=intbr0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSIntPort
    OVS_BRIDGE=ovsbridge0
    BOOTPROTO=static
    IPADDR=A.B.C.D
    NETMASK=X.Y.Z.0
    HOTPLUG=no

Internal Port with DHCP:

* Needs ``OVSBOOTPROTO`` or ``BOOTPROTO``.
* All the interfaces that can reach the DHCP server as a space separated list
  in ``OVSDHCPINTERFACES``.

::

    DEVICE=intbr0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSIntPort
    OVS_BRIDGE=ovsbridge0
    OVSBOOTPROTO="dhcp"
    OVSDHCPINTERFACES="eth0"
    HOTPLUG=no

Adding physical ``eth0`` to ``ovsbridge0`` described above:

::

     ==> ifcfg-eth0 <==
     DEVICE=eth0
     ONBOOT=yes
     DEVICETYPE=ovs
     TYPE=OVSPort
     OVS_BRIDGE=ovsbridge0
     BOOTPROTO=none
     HOTPLUG=no

Tagged VLAN interface on top of ``ovsbridge0``:

::

    ==> ifcfg-vlan100 <==
    DEVICE=vlan100
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSIntPort
    BOOTPROTO=static
    IPADDR=A.B.C.D
    NETMASK=X.Y.Z.0
    OVS_BRIDGE=ovsbridge0
    OVS_OPTIONS="tag=100"
    OVS_EXTRA="set Interface $DEVICE external-ids:iface-id=$(hostname -s)-$DEVICE-vif"
    HOTPLUG=no

Bonding:

::

    ==> ifcfg-bond0 <==
    DEVICE=bond0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSBond
    OVS_BRIDGE=ovsbridge0
    BOOTPROTO=none
    BOND_IFACES="gige-1b-0 gige-1b-1 gige-21-0 gige-21-1"
    OVS_OPTIONS="bond_mode=balance-tcp lacp=active"
    HOTPLUG=no

::

    ==> ifcfg-gige-* <==
    DEVICE=gige-*
    ONBOOT=yes
    HOTPLUG=no

An Open vSwitch Tunnel:

::

    ==> ifcfg-gre0 <==
    DEVICE=ovs-gre0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSTunnel
    OVS_BRIDGE=ovsbridge0
    OVS_TUNNEL_TYPE=gre
    OVS_TUNNEL_OPTIONS="options:remote_ip=A.B.C.D"

Patch Ports:

::

    ==> ifcfg-patch-ovs-0 <==
    DEVICE=patch-ovs-0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSPatchPort
    OVS_BRIDGE=ovsbridge0
    OVS_PATCH_PEER=patch-ovs-1

::

    ==> ifcfg-patch-ovs-1 <==
    DEVICE=patch-ovs-1
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSPatchPort
    OVS_BRIDGE=ovsbridge1
    OVS_PATCH_PEER=patch-ovs-0

User bridge:

::

    ==> ifcfg-obr0 <==
    DEVICE=obr0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSUserBridge
    BOOTPROTO=static
    IPADDR=A.B.C.D
    NETMASK=X.Y.Z.0
    HOTPLUG=no

DPDK NIC port:

::

    ==> ifcfg-dpdk0 <==
    DPDK vhost-user port:
    DEVICE=dpdk0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSDPDKPort
    OVS_BRIDGE=obr0

::

    ==> ifcfg-vhu0 <==
    DEVICE=vhu0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSDPDKVhostUserPort
    OVS_BRIDGE=obr0

::

    ==> ifcfg-bond0 <==
    DEVICE=bond0
    ONBOOT=yes
    DEVICETYPE=ovs
    TYPE=OVSDPDKBond
    OVS_BRIDGE=ovsbridge0
    BOOTPROTO=none
    BOND_IFACES="dpdk0 dpdk1"
    OVS_OPTIONS="bond_mode=active-backup"
    HOTPLUG=no


Red Hat systemd integration
---------------------------

The RPM packages for Open vSwitch provide support for systemd integration. It's
recommended to use the openvswitch.service to start and stop the Open vSwitch
daemons. The below table shows systemd's behavior:

=============================== ============== ============== ============== =============== ===============
              -                 Process Status                systemctl <> status
------------------------------- ----------------------------- ----------------------------------------------
Action                          ovs-vswitch     ovsdb-server  openvswitch    ovs-vswitchd    ovsdb-server
=============================== ============== ============== ============== =============== ===============
systemctl start openvswitch*    started        started        active, exited active, running active, running
crash of vswitchd               crash, started re-started     active, exited active, running active, running
crash of ovsdb                  re-started     crash, started active, exited active, running active, running
systemctl restart openvswitch   re-started     re-started     active, exited active, running active, running
systemctl restart ovs-vswitchd  re-started     re-started     active, exited active, running active, running
systemctl restart ovsdb-server  re-started     re-started     active, exited active, running active, running
systemctl stop openvswitch      stopped        stopped        inactive, dead inactive, dead  inactive, dead
systemctl stop ovs-vswitchd     stopped        stopped        inactive, dead inactive, dead  inactive, dead
systemctl stop ovsdb-server     stopped        stopped        inactive, dead inactive, dead  inactive, dead
systemctl start ovs-vswitchd*   started        started        inactive, dead active, running active, running
systemctl start ovsdb-server*   not started    started        inactive, dead inactive, dead  active, running
=============================== ============== ============== ============== =============== ===============


\* These commands where executed when no Open vSwitch related processes where
running. All other commands where executed when Open vSwitch was successfully
running.


Non-root User Support
-----------------------
Fedora and RHEL support running the Open vSwitch daemons as a non-root user.
By default, a fresh installation will create an *openvswitch* user, along
with any additional support groups needed (such as *hugetlbfs* for DPDK
support).

This is controlled by modifying the ``OVS_USER_ID`` option.  Setting this
to 'root:root', or commenting the variable out will revert this behavior.


Reporting Bugs
--------------

Please report problems to bugs@openvswitch.org.
