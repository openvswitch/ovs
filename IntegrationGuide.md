Integration Guide for Centralized Control
=========================================

This document describes how to integrate Open vSwitch onto a new
platform to expose the state of the switch and attached devices for
centralized control.  (If you are looking to port the switching
components of Open vSwitch to a new platform, please see the PORTING
document.)  The focus of this guide is on hypervisors, but many of the
interfaces are useful for hardware switches, as well.  The XenServer
integration is the most mature implementation, so most of the examples
are drawn from it.

The externally visible interface to this integration is
platform-agnostic.  We encourage anyone who integrates Open vSwitch to
use the same interface, because keeping a uniform interface means that
controllers require less customization for individual platforms (and
perhaps no customization at all).

Integration centers around the Open vSwitch database and mostly involves
the 'external_ids' columns in several of the tables.  These columns are
not interpreted by Open vSwitch itself.  Instead, they provide
information to a controller that permits it to associate a database
record with a more meaningful entity.  In contrast, the 'other_config'
column is used to configure behavior of the switch.  The main job of the
integrator, then, is to ensure that these values are correctly populated
and maintained.

An integrator sets the columns in the database by talking to the
ovsdb-server daemon.  A few of the columns can be set during startup by
calling the ovs-ctl tool from inside the startup scripts.  The
'xenserver/etc_init.d_openvswitch' script provides examples of its use,
and the ovs-ctl(8) manpage contains complete documentation.  At runtime,
ovs-vsctl can be be used to set columns in the database.  The script
'xenserver/etc_xensource_scripts_vif' contains examples of its use, and
ovs-vsctl(8) manpage contains complete documentation.

Python and C bindings to the database are provided if deeper integration
with a program are needed.  The XenServer ovs-xapi-sync daemon
('xenserver/usr_share_openvswitch_scripts_ovs-xapi-sync') provides an
example of using the Python bindings.  More information on the python
bindings is available at 'python/ovs/db/idl.py'.  Information on the C
bindings is available at 'lib/ovsdb-idl.h'.

The following diagram shows how integration scripts fit into the Open vSwitch
architecture:

                +----------------------------------------+
                |           Controller Cluster           +
                +----------------------------------------+
                                    |
                                    |
       +----------------------------------------------------------+
       |                            |                             |
       |             +--------------+---------------+             |
       |             |                              |             |
       |   +-------------------+           +------------------+   |
       |   |   ovsdb-server    |-----------|   ovs-vswitchd   |   |
       |   +-------------------+           +------------------+   |
       |             |                              |             |
       |  +---------------------+                   |             |
       |  | Integration scripts |                   |             |
       |  | (ex: ovs-xapi-sync) |                   |             |
       |  +---------------------+                   |             |
       |                                            |   Userspace |
       |----------------------------------------------------------|
       |                                            |      Kernel |
       |                                            |             |
       |                                 +---------------------+  |
       |                                 |  OVS Kernel Module  |  |
       |                                 +---------------------+  |
       +----------------------------------------------------------+


A description of the most relevant fields for integration follows.  By
setting these values, controllers are able to understand the network and
manage it more dynamically and precisely.  For more details about the
database and each individual column, please refer to the
ovs-vswitchd.conf.db(5) manpage.


Open_vSwitch table
------------------
The Open_vSwitch table describes the switch as a whole.  The
'system_type' and 'system_version' columns identify the platform to the
controller.  The 'external_ids:system-id' key uniquely identifies the
physical host.  In XenServer, the system-id will likely be the same as
the UUID returned by 'xe host-list'. This key allows controllers to
distinguish between multiple hypervisors.

Most of this configuration can be done with the ovs-ctl command at
startup.  For example:

    ovs-ctl --system-type="XenServer" --system-version="6.0.0-50762p" \
            --system-id="${UUID}" "${other_options}" start

Alternatively, the ovs-vsctl command may be used to set a particular
value at runtime.  For example:

    ovs-vsctl set open_vswitch . external-ids:system-id='"${UUID}"'

The 'other_config:enable-statistics' key may be set to "true" to have OVS
populate the database with statistics (e.g., number of CPUs, memory,
system load) for the controller's use.


Bridge table
------------
The Bridge table describes individual bridges within an Open vSwitch
instance.  The 'external-ids:bridge-id' key uniquely identifies a
particular bridge.  In XenServer, this will likely be the same as the
UUID returned by 'xe network-list' for that particular bridge.

For example, to set the identifier for bridge "br0", the following
command can be used:

    ovs-vsctl set Bridge br0 external-ids:bridge-id='"${UUID}"'

The MAC address of the bridge may be manually configured by setting it
with the "other_config:hwaddr" key.  For example:

    ovs-vsctl set Bridge br0 other_config:hwaddr="12:34:56:78:90:ab"


Interface table
---------------
The Interface table describes an interface under the control of Open
vSwitch.  The 'external_ids' column contains keys that are used to
provide additional information about the interface:

    attached-mac

        This field contains the MAC address of the device attached to
        the interface.  On a hypervisor, this is the MAC address of the
        interface as seen inside a VM.  It does not necessarily
        correlate to the host-side MAC address.  For example, on
        XenServer, the MAC address on a VIF in the hypervisor is always
        FE:FF:FF:FF:FF:FF, but inside the VM a normal MAC address is
        seen.

    iface-id

        This field uniquely identifies the interface.  In hypervisors,
        this allows the controller to follow VM network interfaces as
        VMs migrate.  A well-chosen identifier should also allow an
        administrator or a controller to associate the interface with
        the corresponding object in the VM management system.  For
        example, the Open vSwitch integration with XenServer by default
        uses the XenServer assigned UUID for a VIF record as the
        iface-id.

    iface-status

        In a hypervisor, there are situations where there are multiple
        interface choices for a single virtual ethernet interface inside
        a VM.  Valid values are "active" and "inactive".  A complete
        description is available in the ovs-vswitchd.conf.db(5) manpage.

    vm-id

        This field uniquely identifies the VM to which this interface
        belongs.  A single VM may have multiple interfaces attached to
        it.

As in the previous tables, the ovs-vsctl command may be used to
configure the values.  For example, to set the 'iface-id' on eth0, the
following command can be used:

    ovs-vsctl set Interface eth0 external-ids:iface-id='"${UUID}"'

