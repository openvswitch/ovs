# Copyright (c) 2008,2009 Citrix Systems, Inc.
# Copyright (c) 2009,2010 Nicira Networks.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; version 2.1 only. with the special
# exception on linking described in file LICENSE.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
from InterfaceReconfigure import *

#
# Bare Network Devices -- network devices without IP configuration
#

def netdev_down(netdev):
    """Bring down a bare network device"""
    if not netdev_exists(netdev):
        log("netdev: down: device %s does not exist, ignoring" % netdev)
        return
    run_command(["/sbin/ifconfig", netdev, 'down'])

def netdev_up(netdev, mtu=None):
    """Bring up a bare network device"""
    if not netdev_exists(netdev):
        raise Error("netdev: up: device %s does not exist" % netdev)

    if mtu:
        mtu = ["mtu", mtu]
    else:
        mtu = []

    run_command(["/sbin/ifconfig", netdev, 'up'] + mtu)

#
# Bridges
#

def pif_bridge_name(pif):
    """Return the bridge name of a pif.

    PIF must not be a VLAN and must be a bridged PIF."""

    pifrec = db().get_pif_record(pif)

    if pif_is_vlan(pif):
        raise Error("PIF %(uuid)s cannot be a bridge, VLAN is %(VLAN)s" % pifrec)

    nwrec = db().get_network_record(pifrec['network'])

    if nwrec['bridge']:
        return nwrec['bridge']
    else:
        raise Error("PIF %(uuid)s does not have a bridge name" % pifrec)

#
# PIF miscellanea
#

def pif_currently_in_use(pif):
    """Determine if a PIF is currently in use.

    A PIF is determined to be currently in use if
    - PIF.currently-attached is true
    - Any bond master is currently attached
    - Any VLAN master is currently attached
    """
    rec = db().get_pif_record(pif)
    if rec['currently_attached']:
        log("configure_datapath: %s is currently attached" % (pif_netdev_name(pif)))
        return True
    for b in pif_get_bond_masters(pif):
        if pif_currently_in_use(b):
            log("configure_datapath: %s is in use by BOND master %s" % (pif_netdev_name(pif),pif_netdev_name(b)))
            return True
    for v in pif_get_vlan_masters(pif):
        if pif_currently_in_use(v):
            log("configure_datapath: %s is in use by VLAN master %s" % (pif_netdev_name(pif),pif_netdev_name(v)))
            return True
    return False

#
# Datapath Configuration
#

def pif_datapath(pif):
    """Return the datapath PIF associated with PIF.
For a non-VLAN PIF, the datapath name is the bridge name.
For a VLAN PIF, the datapath name is the bridge name for the PIF's VLAN slave.
"""
    if pif_is_vlan(pif):
        return pif_datapath(pif_get_vlan_slave(pif))

    pifrec = db().get_pif_record(pif)
    nwrec = db().get_network_record(pifrec['network'])
    if not nwrec['bridge']:
        return None
    else:
        return pif

def datapath_get_physical_pifs(pif):
    """Return the PIFs for the physical network device(s) associated with a datapath PIF.
For a bond master PIF, these are the bond slave PIFs.
For a non-VLAN, non-bond master PIF, the PIF is its own physical device PIF.

A VLAN PIF cannot be a datapath PIF.
"""
    if pif_is_vlan(pif):
        # Seems like overkill...
        raise Error("get-physical-pifs should not get passed a VLAN")
    elif pif_is_bond(pif):
        return pif_get_bond_slaves(pif)
    else:
        return [pif]

def datapath_deconfigure_physical(netdev):
    return ['--', '--if-exists', 'del-port', netdev]

def datapath_configure_bond(pif,slaves):
    bridge = pif_bridge_name(pif)
    pifrec = db.get_pif_record(pif)
    interface = pif_netdev_name(pif)

    argv = ['--', '--fake-iface', 'add-bond', bridge, interface]
    for slave in slaves:
        argv += [pif_netdev_name(slave)]

    # XXX need ovs-vsctl support
    #if pifrec['MAC'] != "":
    #    argv += ['--add=port.%s.mac=%s' % (interface, pifrec['MAC'])]

    # Bonding options.
    bond_options = {
        "mode":   "balance-slb",
        "miimon": "100",
        "downdelay": "200",
        "updelay": "31000",
        "use_carrier": "1",
        }
    # override defaults with values from other-config whose keys
    # being with "bond-"
    oc = pifrec['other_config']
    overrides = filter(lambda (key,val):
                           key.startswith("bond-"), oc.items())
    overrides = map(lambda (key,val): (key[5:], val), overrides)
    bond_options.update(overrides)
    for (name,val) in bond_options.items():
        # XXX need ovs-vsctl support for bond options
        #argv += ["--add=bonding.%s.%s=%s" % (interface, name, val)]
        pass
    return argv

def datapath_deconfigure_bond(netdev):
    return ['--', '--if-exists', 'del-port', netdev]

def datapath_deconfigure_ipdev(interface):
    return ['--', '--if-exists', 'del-port', interface]

def datapath_modify_config(commands):
    #log("modifying configuration:")
    #for c in commands:
    #    log("  %s" % c)
            
    rc = run_command(['/usr/bin/ovs-vsctl'] + ['--timeout=20']
                     + [c for c in commands if not c.startswith('#')])
    if not rc:       
        raise Error("Failed to modify vswitch configuration")
    return True

#
# Toplevel Datapath Configuration.
#

def configure_datapath(pif, parent=None, vlan=None):
    """Bring up the datapath configuration for PIF.

    Should be careful not to glitch existing users of the datapath, e.g. other VLANs etc.

    Should take care of tearing down other PIFs which encompass common physical devices.

    Returns a tuple containing
    - A list containing the necessary vsctl command line arguments
    - A list of additional devices which should be brought up after
      the configuration is applied.
    """

    vsctl_argv = []
    extra_up_ports = []

    bridge = pif_bridge_name(pif)

    physical_devices = datapath_get_physical_pifs(pif)

    # Determine additional devices to deconfigure.
    #
    # Given all physical devices which are part of this PIF we need to
    # consider:
    # - any additional bond which a physical device is part of.
    # - any additional physical devices which are part of an additional bond.
    #
    # Any of these which are not currently in use should be brought
    # down and deconfigured.
    extra_down_bonds = []
    extra_down_ports = []
    for p in physical_devices:
        for bond in pif_get_bond_masters(p):
            if bond == pif:
                log("configure_datapath: leaving bond %s up" % pif_netdev_name(bond))
                continue
            if bond in extra_down_bonds:
                continue
            if db().get_pif_record(bond)['currently_attached']:
                log("configure_datapath: implicitly tearing down currently-attached bond %s" % pif_netdev_name(bond))

            extra_down_bonds += [bond]

            for s in pif_get_bond_slaves(bond):
                if s in physical_devices:
                    continue
                if s in extra_down_ports:
                    continue
                if pif_currently_in_use(s):
                    continue
                extra_down_ports += [s]

    log("configure_datapath: bridge      - %s" % bridge)
    log("configure_datapath: physical    - %s" % [pif_netdev_name(p) for p in physical_devices])
    log("configure_datapath: extra ports - %s" % [pif_netdev_name(p) for p in extra_down_ports])
    log("configure_datapath: extra bonds - %s" % [pif_netdev_name(p) for p in extra_down_bonds])

    # Need to fully deconfigure any bridge which any of the:
    # - physical devices
    # - bond devices
    # - sibling devices
    # refers to
    for brpif in physical_devices + extra_down_ports + extra_down_bonds:
        if brpif == pif:
            continue
        b = pif_bridge_name(brpif)
        #ifdown(b)
        # XXX
        netdev_down(b)
        vsctl_argv += ['# remove bridge %s' % b]
        vsctl_argv += ['--', '--if-exists', 'del-br', b]

    for n in extra_down_ports:
        dev = pif_netdev_name(n)
        vsctl_argv += ['# deconfigure sibling physical device %s' % dev]
        vsctl_argv += datapath_deconfigure_physical(dev)
        netdev_down(dev)

    for n in extra_down_bonds:
        dev = pif_netdev_name(n)
        vsctl_argv += ['# deconfigure bond device %s' % dev]
        vsctl_argv += datapath_deconfigure_bond(dev)
        netdev_down(dev)

    for p in physical_devices:
        dev = pif_netdev_name(p)
        vsctl_argv += ['# deconfigure physical port %s' % dev]
        vsctl_argv += datapath_deconfigure_physical(dev)

    if parent and datapath:
        vsctl_argv += ['--', '--may-exist', 'add-br', bridge, parent, vlan]
    else:
        vsctl_argv += ['--', '--may-exist', 'add-br', bridge]

    if len(physical_devices) > 1:
        vsctl_argv += ['# deconfigure bond %s' % pif_netdev_name(pif)]
        vsctl_argv += datapath_deconfigure_bond(pif_netdev_name(pif))
        vsctl_argv += ['# configure bond %s' % pif_netdev_name(pif)]
        vsctl_argv += datapath_configure_bond(pif, physical_devices)
        extra_up_ports += [pif_netdev_name(pif)]
    else:
        iface = pif_netdev_name(physical_devices[0])
        vsctl_argv += ['# add physical device %s' % iface]
        vsctl_argv += ['--', '--may-exist', 'add-port', bridge, iface]

    return vsctl_argv,extra_up_ports

def deconfigure_datapath(pif):
    vsctl_argv = []

    bridge = pif_bridge_name(pif)

    physical_devices = datapath_get_physical_pifs(pif)

    log("deconfigure_datapath: bridge           - %s" % bridge)
    log("deconfigure_datapath: physical devices - %s" % [pif_netdev_name(p) for p in physical_devices])

    for p in physical_devices:
        dev = pif_netdev_name(p)
        vsctl_argv += ['# deconfigure physical port %s' % dev]
        vsctl_argv += datapath_deconfigure_physical(dev)
        netdev_down(dev)

    if len(physical_devices) > 1:
        vsctl_argv += ['# deconfigure bond %s' % pif_netdev_name(pif)]
        vsctl_argv += datapath_deconfigure_bond(pif_netdev_name(pif))

    vsctl_argv += ['# deconfigure bridge %s' % bridge]
    vsctl_argv += ['--', '--if-exists', 'del-br', bridge]

    return vsctl_argv

#
#
#

class DatapathVswitch(Datapath):
    def __init__(self, pif):
        Datapath.__init__(self, pif)
        self._dp = pif_datapath(pif)
        self._ipdev = pif_ipdev_name(pif)

        if pif_is_vlan(pif) and not self._dp:
            raise Error("Unbridged VLAN devices not implemented yet")
        
        log("Configured for Vswitch datapath")

    def configure_ipdev(self, cfg):
        cfg.write("TYPE=Ethernet\n")

    def preconfigure(self, parent):
        vsctl_argv = []
        extra_ports = []

        pifrec = db().get_pif_record(self._pif)

        ipdev = self._ipdev
        bridge = pif_bridge_name(self._dp)
        if pif_is_vlan(self._pif):
            datapath = pif_datapath(self._pif)
            c,e = configure_datapath(self._dp, datapath, pifrec['VLAN'])
        else:
            c,e = configure_datapath(self._dp)
        vsctl_argv += c
        extra_ports += e

        xs_network_uuids = []
        for nwpif in db().get_pifs_by_device(db().get_pif_record(self._pif)['device']):
            rec = db().get_pif_record(nwpif)

            # When state is read from dbcache PIF.currently_attached
            # is always assumed to be false... Err on the side of
            # listing even detached networks for the time being.
            #if nwpif != pif and not rec['currently_attached']:
            #    log("Network PIF %s not currently attached (%s)" % (rec['uuid'],pifrec['uuid']))
            #    continue
            nwrec = db().get_network_record(rec['network'])
            xs_network_uuids += [nwrec['uuid']]

        vsctl_argv += ['# configure xs-network-uuids']
        vsctl_argv += ['--', 'br-set-external-id', bridge,
                'xs-network-uuids', ';'.join(xs_network_uuids)]

        if ipdev != bridge:
            vsctl_argv += ["# deconfigure ipdev %s" % ipdev]
            vsctl_argv += datapath_deconfigure_ipdev(ipdev)
            vsctl_argv += ["# reconfigure ipdev %s" % ipdev]
            vsctl_argv += ['--', 'add-port', bridge, ipdev]

        # XXX Needs support in ovs-vsctl
        #if bridge == ipdev:
        #    vsctl_argv += ['--add=bridge.%s.mac=%s' % (bridge, pifrec['MAC'])]
        #else:
        #    vsctl_argv += ['--add=iface.%s.mac=%s' % (ipdev, pifrec['MAC'])]

        self._vsctl_argv = vsctl_argv
        self._extra_ports = extra_ports

    def bring_down_existing(self):
        pass

    def configure(self):
        # Bring up physical devices. ovs-vswitchd initially enables or
        # disables bond slaves based on whether carrier is detected
        # when they are added, and a network device that is down
        # always reports "no carrier".
        physical_devices = datapath_get_physical_pifs(self._dp)
        
        for p in physical_devices:
            oc = db().get_pif_record(p)['other_config']

            dev = pif_netdev_name(p)

            mtu = mtu_setting(oc)

            netdev_up(dev, mtu)

            settings, offload = ethtool_settings(oc)
            if len(settings):
                run_command(['/sbin/ethtool', '-s', dev] + settings)
            if len(offload):
                run_command(['/sbin/ethtool', '-K', dev] + offload)

        datapath_modify_config(self._vsctl_argv)

    def post(self):
        for p in self._extra_ports:
            log("action_up: bring up %s" % p)
            netdev_up(p)

    def bring_down(self):
        vsctl_argv = []

        dp = self._dp
        ipdev = self._ipdev
        
        bridge = pif_bridge_name(dp)

        #nw = db().get_pif_record(self._pif)['network']
        #nwrec = db().get_network_record(nw)
        #vsctl_argv += ['# deconfigure xs-network-uuids']
        #vsctl_argv += ['--del-entry=bridge.%s.xs-network-uuids=%s' % (bridge,nwrec['uuid'])]

        log("deconfigure ipdev %s on %s" % (ipdev,bridge))
        vsctl_argv += ["# deconfigure ipdev %s" % ipdev]
        vsctl_argv += datapath_deconfigure_ipdev(ipdev)

        if pif_is_vlan(self._pif):
            # If the VLAN's slave is attached, leave datapath setup.
            slave = pif_get_vlan_slave(self._pif)
            if db().get_pif_record(slave)['currently_attached']:
                log("action_down: vlan slave is currently attached")
                dp = None

            # If the VLAN's slave has other VLANs that are attached, leave datapath setup.
            for master in pif_get_vlan_masters(slave):
                if master != self._pif and db().get_pif_record(master)['currently_attached']:
                    log("action_down: vlan slave has other master: %s" % pif_netdev_name(master))
                    dp = None

            # Otherwise, take down the datapath too (fall through)
            if dp:
                log("action_down: no more masters, bring down slave %s" % bridge)
        else:
            # Stop here if this PIF has attached VLAN masters.
            masters = [db().get_pif_record(m)['VLAN'] for m in pif_get_vlan_masters(self._pif) if db().get_pif_record(m)['currently_attached']]
            if len(masters) > 0:
                log("Leaving datapath %s up due to currently attached VLAN masters %s" % (bridge, masters))
                dp = None

        if dp:
            vsctl_argv += deconfigure_datapath(dp)
            datapath_modify_config(vsctl_argv)
