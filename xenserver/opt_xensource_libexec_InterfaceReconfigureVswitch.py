# Copyright (c) 2008,2009 Citrix Systems, Inc.
# Copyright (c) 2009 Nicira Networks.
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
    # The use of [!0-9] keeps an interface of 'eth0' from matching
    # VLANs attached to eth0 (such as 'eth0.123'), which are distinct
    # interfaces.
    return ['--del-match=bridge.*.port=%s' % netdev,
            '--del-match=port.%s.[!0-9]*' % netdev,
            '--del-match=bonding.*.slave=%s' % netdev,
            '--del-match=iface.%s.[!0-9]*' % netdev]

def datapath_configure_bond(pif,slaves):
    pifrec = db().get_pif_record(pif)
    interface = pif_netdev_name(pif)

    argv = ['--del-match=bonding.%s.[!0-9]*' % interface]
    argv += ["--add=bonding.%s.slave=%s" % (interface, pif_netdev_name(slave))
             for slave in slaves]
    argv += ['--add=bonding.%s.fake-iface=true' % interface]

    if pifrec['MAC'] != "":
        argv += ['--add=port.%s.mac=%s' % (interface, pifrec['MAC'])]

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
        argv += ["--add=bonding.%s.%s=%s" % (interface, name, val)]
    return argv

def datapath_deconfigure_bond(netdev):
    # The use of [!0-9] keeps an interface of 'eth0' from matching
    # VLANs attached to eth0 (such as 'eth0.123'), which are distinct
    # interfaces.
    return ['--del-match=bonding.%s.[!0-9]*' % netdev,
            '--del-match=port.%s.[!0-9]*' % netdev]

def datapath_deconfigure_ipdev(interface):
    # The use of [!0-9] keeps an interface of 'eth0' from matching
    # VLANs attached to eth0 (such as 'eth0.123'), which are distinct
    # interfaces.
    return ['--del-match=bridge.*.port=%s' % interface,
            '--del-match=port.%s.[!0-9]*' % interface,
            '--del-match=iface.%s.[!0-9]*' % interface,
            '--del-match=vlan.%s.trunks=*' % interface,
            '--del-match=vlan.%s.tag=*' % interface]

def datapath_modify_config(commands):
    #log("modifying configuration:")
    #for c in commands:
    #    log("  %s" % c)

    rc = run_command(['/usr/bin/ovs-cfg-mod', '-vANY:console:emer',
                 '-F', '/etc/ovs-vswitchd.conf']
                + [c for c in commands if c[0] != '#'] + ['-c'])
    if not rc:
        raise Error("Failed to modify vswitch configuration")
    run_command(['/sbin/service', 'vswitch', 'reload'])
    return True

#
# Toplevel Datapath Configuration.
#

def configure_datapath(pif):
    """Bring up the datapath configuration for PIF.

    Should be careful not to glitch existing users of the datapath, e.g. other VLANs etc.

    Should take care of tearing down other PIFs which encompass common physical devices.

    Returns a tuple containing
    - A list containing the necessary cfgmod command line arguments
    - A list of additional devices which should be brought up after
      the configuration is applied.
    """

    cfgmod_argv = []
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
        cfgmod_argv += ['# remove bridge %s' % b]
        cfgmod_argv += ['--del-match=bridge.%s.*' % b]

    for n in extra_down_ports:
        dev = pif_netdev_name(n)
        cfgmod_argv += ['# deconfigure sibling physical device %s' % dev]
        cfgmod_argv += datapath_deconfigure_physical(dev)
        netdev_down(dev)

    for n in extra_down_bonds:
        dev = pif_netdev_name(n)
        cfgmod_argv += ['# deconfigure bond device %s' % dev]
        cfgmod_argv += datapath_deconfigure_bond(dev)
        netdev_down(dev)

    for p in physical_devices:
        dev = pif_netdev_name(p)
        cfgmod_argv += ['# deconfigure physical port %s' % dev]
        cfgmod_argv += datapath_deconfigure_physical(dev)
    if len(physical_devices) > 1:
        cfgmod_argv += ['# deconfigure bond %s' % pif_netdev_name(pif)]
        cfgmod_argv += datapath_deconfigure_bond(pif_netdev_name(pif))
        cfgmod_argv += ['--del-entry=bridge.%s.port=%s' % (bridge,pif_netdev_name(pif))]
        cfgmod_argv += ['# configure bond %s' % pif_netdev_name(pif)]
        cfgmod_argv += datapath_configure_bond(pif, physical_devices)
        cfgmod_argv += ['--add=bridge.%s.port=%s' % (bridge,pif_netdev_name(pif)) ]
        extra_up_ports += [pif_netdev_name(pif)]
    else:
        iface = pif_netdev_name(physical_devices[0])
        cfgmod_argv += ['# add physical device %s' % iface]
        cfgmod_argv += ['--add=bridge.%s.port=%s' % (bridge,iface) ]

    return cfgmod_argv,extra_up_ports

def deconfigure_datapath(pif):
    cfgmod_argv = []

    bridge = pif_bridge_name(pif)

    physical_devices = datapath_get_physical_pifs(pif)

    log("deconfigure_datapath: bridge           - %s" % bridge)
    log("deconfigure_datapath: physical devices - %s" % [pif_netdev_name(p) for p in physical_devices])

    for p in physical_devices:
        dev = pif_netdev_name(p)
        cfgmod_argv += ['# deconfigure physical port %s' % dev]
        cfgmod_argv += datapath_deconfigure_physical(dev)
        netdev_down(dev)

    if len(physical_devices) > 1:
        cfgmod_argv += ['# deconfigure bond %s' % pif_netdev_name(pif)]
        cfgmod_argv += datapath_deconfigure_bond(pif_netdev_name(pif))

    cfgmod_argv += ['# deconfigure bridge %s' % bridge]
    cfgmod_argv += ['--del-match=bridge.%s.*' % bridge]

    return cfgmod_argv

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
        cfgmod_argv = []
        extra_ports = []

        pifrec = db().get_pif_record(self._pif)

        ipdev = self._ipdev
        bridge = pif_bridge_name(self._dp)
        c,e = configure_datapath(self._dp)
        cfgmod_argv += c
        extra_ports += e

        cfgmod_argv += ['# configure xs-network-uuids']
        cfgmod_argv += ['--del-match=bridge.%s.xs-network-uuids=*' % bridge]

        for nwpif in db().get_pifs_by_device(db().get_pif_record(self._pif)['device']):
            rec = db().get_pif_record(nwpif)

            # When state is read from dbcache PIF.currently_attached
            # is always assumed to be false... Err on the side of
            # listing even detached networks for the time being.
            #if nwpif != pif and not rec['currently_attached']:
            #    log("Network PIF %s not currently attached (%s)" % (rec['uuid'],pifrec['uuid']))
            #    continue
            nwrec = db().get_network_record(rec['network'])
            cfgmod_argv += ['--add=bridge.%s.xs-network-uuids=%s' % (bridge, nwrec['uuid'])]

        cfgmod_argv += ["# deconfigure ipdev %s" % ipdev]
        cfgmod_argv += datapath_deconfigure_ipdev(ipdev)
        cfgmod_argv += ["# reconfigure ipdev %s" % ipdev]
        cfgmod_argv += ['--add=bridge.%s.port=%s' % (bridge, ipdev)]
        if bridge == ipdev:
            cfgmod_argv += ['--add=bridge.%s.mac=%s' % (bridge, pifrec['MAC'])]
        else:
            cfgmod_argv += ['--add=iface.%s.mac=%s' % (ipdev, pifrec['MAC'])]
            
        if pif_is_vlan(self._pif):
            cfgmod_argv += ['--add=vlan.%s.tag=%s' % (ipdev, pifrec['VLAN'])]
            cfgmod_argv += ['--add=iface.%s.internal=true' % (ipdev)]
            cfgmod_argv += ['--add=iface.%s.fake-bridge=true' % (ipdev)]

        self._cfgmod_argv = cfgmod_argv
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

        datapath_modify_config(self._cfgmod_argv)

    def post(self):
        for p in self._extra_ports:
            log("action_up: bring up %s" % p)
            netdev_up(p)

    def bring_down(self):
        cfgmod_argv = []

        dp = self._dp
        ipdev = self._ipdev
        
        bridge = pif_bridge_name(dp)

        #nw = db().get_pif_record(self._pif)['network']
        #nwrec = db().get_network_record(nw)
        #cfgmod_argv += ['# deconfigure xs-network-uuids']
        #cfgmod_argv += ['--del-entry=bridge.%s.xs-network-uuids=%s' % (bridge,nwrec['uuid'])]

        log("deconfigure ipdev %s on %s" % (ipdev,bridge))
        cfgmod_argv += ["# deconfigure ipdev %s" % ipdev]
        cfgmod_argv += datapath_deconfigure_ipdev(ipdev)

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
            cfgmod_argv += deconfigure_datapath(dp)
            datapath_modify_config(cfgmod_argv)
