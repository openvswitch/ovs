# Copyright (c) 2008,2009,2011 Citrix Systems, Inc.
# Copyright (c) 2009,2010,2011,2012,2013,2017 Nicira, Inc.
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
import os
import re
import subprocess

#
# Bare Network Devices -- network devices without IP configuration
#

def netdev_down(netdev):
    """Bring down a bare network device"""
    if not netdev_exists(netdev):
        log("netdev: down: device %s does not exist, ignoring" % netdev)
        return
    run_command(["/sbin/ip", "link", "set", netdev, 'down'])

def netdev_up(netdev, mtu=None):
    """Bring up a bare network device"""
    if not netdev_exists(netdev):
        raise Error("netdev: up: device %s does not exist" % netdev)

    if mtu:
        mtu = ["mtu", mtu]
    else:
        mtu = []

    run_command(["/sbin/ip", "link", "set", netdev, 'up'] + mtu)

# This is a list of drivers that do support VLAN tx or rx acceleration, but
# to which the VLAN bug workaround should not be applied.  This could be
# because these are known-good drivers (that is, they do not have any of
# the bugs that the workaround avoids) or because the VLAN bug workaround
# will not work for them and may cause other problems.
#
# This is a very short list because few drivers have been tested.
NO_VLAN_WORKAROUND_DRIVERS = (
    "bonding",
)
def netdev_get_driver_name(netdev):
    """Returns the name of the driver for network device 'netdev'"""
    symlink = '%s/sys/class/net/%s/device/driver' % (root_prefix(), netdev)
    try:
        target = os.readlink(symlink)
    except OSError as e:
        log("%s: could not read netdev's driver name (%s)" % (netdev, e))
        return None

    slash = target.rfind('/')
    if slash < 0:
        log("target %s of symbolic link %s does not contain slash"
            % (target, symlink))
        return None

    return target[slash + 1:]

def netdev_get_features(netdev):
    """Returns the features bitmap for the driver for 'netdev'.
    The features bitmap is a set of NETIF_F_ flags supported by its driver."""
    try:
        features = open("%s/sys/class/net/%s/features" % (root_prefix(), netdev)).read().strip()
        return int(features, 0)
    except:
        return 0 # interface prolly doesn't exist

def netdev_has_vlan_accel(netdev):
    """Returns True if 'netdev' supports VLAN acceleration, False otherwise."""
    NETIF_F_HW_VLAN_TX = 128
    NETIF_F_HW_VLAN_RX = 256
    NETIF_F_VLAN = NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX
    return (netdev_get_features(netdev) & NETIF_F_VLAN) != 0

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
A non-VLAN PIF is its own datapath PIF, except that a bridgeless PIF has
no datapath PIF at all.
A VLAN PIF's datapath PIF is its VLAN slave's datapath PIF.
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
    if pif_is_tunnel(pif):
        return []
    elif pif_is_vlan(pif):
        # Seems like overkill...
        raise Error("get-physical-pifs should not get passed a VLAN")
    elif pif_is_bond(pif):
        return pif_get_bond_slaves(pif)
    else:
        return [pif]

def datapath_deconfigure_physical(netdev):
    return ['--', '--with-iface', '--if-exists', 'del-port', netdev]

def vsctl_escape(s):
    if s.isalnum():
        return s

    def escape(match):
        c = match.group(0)
        if c == '\0':
            raise Error("strings may not contain null bytes")
        elif c == '\\':
            return r'\\'
        elif c == '\n':
            return r'\n'
        elif c == '\r':
            return r'\r'
        elif c == '\t':
            return r'\t'
        elif c == '\b':
            return r'\b'
        elif c == '\a':
            return r'\a'
        else:
            return r'\x%02x' % ord(c)
    return '"' + re.sub(r'["\\\000-\037]', escape, s) + '"'

def datapath_configure_tunnel(pif):
    pass

def datapath_configure_bond(pif,slaves):
    bridge = pif_bridge_name(pif)
    pifrec = db().get_pif_record(pif)
    interface = pif_netdev_name(pif)

    argv = ['--', '--fake-iface', 'add-bond', bridge, interface]
    for slave in slaves:
        argv += [pif_netdev_name(slave)]

    # Bonding options.
    bond_options = {
        "mode":   "balance-slb",
        "miimon": "100",
        "downdelay": "200",
        "updelay": "31000",
        "use_carrier": "1",
        "hashing-algorithm": "src_mac",
        }
    # override defaults with values from other-config whose keys
    # being with "bond-"
    oc = pifrec['other_config']
    overrides = filter(lambda key_val:
                           key_val[0].startswith("bond-"), oc.items())
    overrides = map(lambda key_val: (key_val[0][5:], key_val[1]), overrides)
    bond_options.update(overrides)
    mode = None
    halgo = None

    argv += ['--', 'set', 'Port', interface]
    if pifrec['MAC'] != "":
        argv += ['MAC=%s' % vsctl_escape(pifrec['MAC'])]
    for (name,val) in sorted(bond_options.items()):
        if name in ['updelay', 'downdelay']:
            # updelay and downdelay have dedicated schema columns.
            # The value must be a nonnegative integer.
            try:
                value = int(val)
                if value < 0:
                    raise ValueError

                argv += ['bond_%s=%d' % (name, value)]
            except ValueError:
                log("bridge %s has invalid %s '%s'" % (bridge, name, value))
        elif name in ['miimon', 'use_carrier']:
            try:
                value = int(val)
                if value < 0:
                    raise ValueError

                if name == 'use_carrier':
                    if value:
                        value = "carrier"
                    else:
                        value = "miimon"
                    argv += ["other-config:bond-detect-mode=%s" % value]
                else:
                    argv += ["other-config:bond-miimon-interval=%d" % value]
            except ValueError:
                log("bridge %s has invalid %s '%s'" % (bridge, name, value))
        elif name == "mode":
            mode = val
        elif name == "hashing-algorithm":
            halgo = val
        else:
            # Pass other bond options into other_config.
            argv += ["other-config:%s=%s" % (vsctl_escape("bond-%s" % name),
                                             vsctl_escape(val))]

    if mode == 'lacp':
        argv += ['lacp=active']

        if halgo == 'src_mac':
            argv += ['bond_mode=balance-slb']
        elif halgo == "tcpudp_ports":
            argv += ['bond_mode=balance-tcp']
        else:
            log("bridge %s has invalid bond-hashing-algorithm '%s'" % (bridge, halgo))
            argv += ['bond_mode=balance-slb']
    elif mode in ['balance-slb', 'active-backup']:
        argv += ['lacp=off', 'bond_mode=%s' % mode]
    else:
        log("bridge %s has invalid bond-mode '%s'" % (bridge, mode))
        argv += ['lacp=off', 'bond_mode=balance-slb']

    return argv

def datapath_deconfigure_bond(netdev):
    return ['--', '--with-iface', '--if-exists', 'del-port', netdev]

def datapath_deconfigure_ipdev(interface):
    return ['--', '--with-iface', '--if-exists', 'del-port', interface]

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

def configure_datapath(pif):
    """Bring up the configuration for 'pif', which must not be a VLAN PIF, by:
    - Tearing down other PIFs that use the same physical devices as 'pif'.
    - Ensuring that 'pif' itself is set up.
    - *Not* tearing down any PIFs that are stacked on top of 'pif' (i.e. VLANs
      on top of 'pif'.

    Returns a tuple containing
    - A list containing the necessary vsctl command line arguments
    - A list of additional devices which should be brought up after
      the configuration is applied.
    - A list containing flows to apply to the pif bridge, note that
      port numbers may need to be substituted once ofport is known
    """

    vsctl_argv = []
    extra_up_ports = []
    bridge_flows = []

    assert not pif_is_vlan(pif)
    bridge = pif_bridge_name(pif)

    physical_devices = datapath_get_physical_pifs(pif)

    vsctl_argv += ['## configuring datapath %s' % bridge]

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

    vsctl_argv += ['--', '--may-exist', 'add-br', bridge]

    if len(physical_devices) > 1:
        vsctl_argv += ['# deconfigure bond %s' % pif_netdev_name(pif)]
        vsctl_argv += datapath_deconfigure_bond(pif_netdev_name(pif))
        vsctl_argv += ['# configure bond %s' % pif_netdev_name(pif)]
        vsctl_argv += datapath_configure_bond(pif, physical_devices)
        extra_up_ports += [pif_netdev_name(pif)]
    elif len(physical_devices) == 1:
        iface = pif_netdev_name(physical_devices[0])
        vsctl_argv += ['# add physical device %s' % iface]
        vsctl_argv += ['--', '--may-exist', 'add-port', bridge, iface]
    elif pif_is_tunnel(pif):
        datapath_configure_tunnel(pif)

    vsctl_argv += ['# configure Bridge MAC']
    vsctl_argv += ['--', 'set', 'Bridge', bridge,
                   'other-config:hwaddr=%s' % vsctl_escape(db().get_pif_record(pif)['MAC'])]

    pool = db().get_pool_record()
    network = db().get_network_by_bridge(bridge)
    network_rec = None
    fail_mode = None
    valid_fail_modes = ['standalone', 'secure']

    if network:
        network_rec = db().get_network_record(network)
        fail_mode = network_rec['other_config'].get('vswitch-controller-fail-mode')

    if (fail_mode not in valid_fail_modes) and pool:
        fail_mode = pool['other_config'].get('vswitch-controller-fail-mode')
        # Add default flows to allow management traffic if fail-mode
        # transitions to secure based on pool fail-mode setting
        if fail_mode == 'secure' and db().get_pif_record(pif).get('management', False):
            prev_fail_mode = vswitchCfgQuery(['get-fail-mode', bridge])
            if prev_fail_mode != 'secure':
                tp = 'idle_timeout=0,priority=0'
                host_mgmt_mac = db().get_pif_record(pif)['MAC']
                # account for bond as management interface
                if len(physical_devices) > 1:
                    bridge_flows += ['%s,in_port=local,arp,dl_src=%s,actions=NORMAL' % (tp, host_mgmt_mac)]
                    bridge_flows += ['%s,in_port=local,dl_src=%s,actions=NORMAL' % (tp, host_mgmt_mac)]
                    # we don't know slave ofports yet, substitute later
                    bridge_flows += ['%s,in_port=%%s,arp,nw_proto=1,actions=local' % (tp)]
                    bridge_flows += ['%s,in_port=%%s,dl_dst=%s,actions=local' % (tp, host_mgmt_mac)]
                else:
                    bridge_flows += ['%s,in_port=%%s,arp,nw_proto=1,actions=local' % (tp)]
                    bridge_flows += ['%s,in_port=local,arp,dl_src=%s,actions=%%s' % (tp, host_mgmt_mac)]
                    bridge_flows += ['%s,in_port=%%s,dl_dst=%s,actions=local' % (tp, host_mgmt_mac)]
                    bridge_flows += ['%s,in_port=local,dl_src=%s,actions=%%s' % (tp, host_mgmt_mac)]

    if fail_mode not in valid_fail_modes:
        fail_mode = 'standalone'

    vsctl_argv += ['--', 'set', 'Bridge', bridge, 'fail_mode=%s' % fail_mode]

    if network_rec:
        dib = network_rec['other_config'].get('vswitch-disable-in-band')
        if not dib:
            vsctl_argv += ['--', 'remove', 'Bridge', bridge, 'other_config', 'disable-in-band']
        elif dib in ['true', 'false']:
            vsctl_argv += ['--', 'set', 'Bridge', bridge, 'other_config:disable-in-band=' + dib]
        else:
            log('"' + dib + '"' "isn't a valid setting for other_config:disable-in-band on " + bridge)

    vsctl_argv += set_br_external_ids(pif)
    vsctl_argv += ['## done configuring datapath %s' % bridge]

    return vsctl_argv,extra_up_ports,bridge_flows

def deconfigure_bridge(pif):
    vsctl_argv = []

    bridge = pif_bridge_name(pif)

    log("deconfigure_bridge: bridge           - %s" % bridge)

    vsctl_argv += ['# deconfigure bridge %s' % bridge]
    vsctl_argv += ['--', '--if-exists', 'del-br', bridge]

    return vsctl_argv

def set_br_external_ids(pif):
    pifrec = db().get_pif_record(pif)
    dp = pif_datapath(pif)
    dprec = db().get_pif_record(dp)

    xs_network_uuids = []
    for nwpif in db().get_pifs_by_device(pifrec['device']):
        rec = db().get_pif_record(nwpif)

        # When state is read from dbcache PIF.currently_attached
        # is always assumed to be false... Err on the side of
        # listing even detached networks for the time being.
        #if nwpif != pif and not rec['currently_attached']:
        #    log("Network PIF %s not currently attached (%s)" % (rec['uuid'],pifrec['uuid']))
        #    continue
        nwrec = db().get_network_record(rec['network'])

        uuid = nwrec['uuid']
        if pif_is_vlan(nwpif):
            xs_network_uuids.append(uuid)
        else:
            xs_network_uuids.insert(0, uuid)

    vsctl_argv = []
    vsctl_argv += ['# configure xs-network-uuids']
    vsctl_argv += ['--', 'br-set-external-id', pif_bridge_name(pif),
            'xs-network-uuids', ';'.join(xs_network_uuids)]

    return vsctl_argv

#
#
#

class DatapathVswitch(Datapath):
    def __init__(self, pif):
        Datapath.__init__(self, pif)
        self._dp = pif_datapath(pif)
        self._ipdev = pif_ipdev_name(pif)
        self._bridge_flows = []

        if pif_is_vlan(pif) and not self._dp:
            raise Error("Unbridged VLAN devices not implemented yet")
        
        log("Configured for Vswitch datapath")

    @classmethod
    def rewrite(cls):
        if not os.path.exists("/var/run/openvswitch/db.sock"):
            # ovsdb-server is not running, so we can't update the database.
            # Probably we are being called as part of system shutdown.  Just
            # skip the update, since the external-ids will be updated on the
            # next boot anyhow.
            return

        vsctl_argv = []
        for pif in db().get_all_pifs():
            pifrec = db().get_pif_record(pif)
            if not pif_is_vlan(pif) and pifrec['currently_attached']:
                vsctl_argv += set_br_external_ids(pif)

        if vsctl_argv != []:
            datapath_modify_config(vsctl_argv)

    def configure_ipdev(self, cfg):
        cfg.write("TYPE=Ethernet\n")

    def preconfigure(self, parent):
        vsctl_argv = []
        extra_ports = []
        bridge_flows = []

        pifrec = db().get_pif_record(self._pif)
        dprec = db().get_pif_record(self._dp)

        ipdev = self._ipdev
        c,e,f = configure_datapath(self._dp)
        bridge = pif_bridge_name(self._pif)
        vsctl_argv += c
        extra_ports += e
        bridge_flows += f

        dpname = pif_bridge_name(self._dp)
        
        if pif_is_vlan(self._pif):
            # In some cases XAPI may misguidedly leave an instance of
            # 'bridge' which should be deleted.
            vsctl_argv += ['--', '--if-exists', 'del-br', bridge]

            # configure_datapath() set up the underlying datapath bridge.
            # Stack a VLAN bridge on top of it.
            vsctl_argv += ['--', '--may-exist', 'add-br',
                           bridge, dpname, pifrec['VLAN']]

            vsctl_argv += set_br_external_ids(self._pif)

        if ipdev != bridge:
            vsctl_argv += ["# deconfigure ipdev %s" % ipdev]
            vsctl_argv += datapath_deconfigure_ipdev(ipdev)
            vsctl_argv += ["# reconfigure ipdev %s" % ipdev]
            vsctl_argv += ['--', 'add-port', bridge, ipdev]

        if ipdev != dpname:
            vsctl_argv += ['# configure Interface MAC']
            vsctl_argv += ['--', 'set', 'Interface', pif_ipdev_name(self._pif),
                           'MAC=%s' % vsctl_escape(dprec['MAC'])]

        self._vsctl_argv = vsctl_argv
        self._extra_ports = extra_ports
        self._bridge_flows = bridge_flows

    def bring_down_existing(self):
        # interface-reconfigure is never explicitly called to down a
        # bond master.  However, when we are called to up a slave it
        # is implicit that we are destroying the master.  Conversely,
        # when we are called to up a bond is is implicit that we are
        # taking down the slaves.
        #
        # This is (only) important in the case where the device being
        # implicitly taken down uses DHCP.  We need to kill the
        # dhclient process, otherwise performing the inverse operation
        # later later will fail because ifup will refuse to start a
        # duplicate dhclient.
        bond_masters = pif_get_bond_masters(self._pif)
        for master in bond_masters:
            log("action_up: bring down bond master %s" % (pif_netdev_name(master)))
            run_command(["/sbin/ifdown", pif_bridge_name(master)])

        bond_slaves = pif_get_bond_slaves(self._pif)
        for slave in bond_slaves:
            log("action_up: bring down bond slave %s" % (pif_netdev_name(slave)))
            run_command(["/sbin/ifdown", pif_bridge_name(slave)])

    def configure(self):
        # Bring up physical devices. ovs-vswitchd initially enables or
        # disables bond slaves based on whether carrier is detected
        # when they are added, and a network device that is down
        # always reports "no carrier".
        physical_devices = datapath_get_physical_pifs(self._dp)

        if pif_is_bond(self._dp):
            brec = db().get_pif_record(self._dp)
            bond_mtu = mtu_setting(brec['network'], "PIF", brec['other_config'])
        else:
            bond_mtu = None
        
        for p in physical_devices:
            prec = db().get_pif_record(p)
            oc = prec['other_config']

            dev = pif_netdev_name(p)

            if bond_mtu:
                mtu = bond_mtu
            else:
                mtu = mtu_setting(prec['network'], "PIF", oc)

            netdev_up(dev, mtu)

            settings, offload = ethtool_settings(oc, PIF_OTHERCONFIG_DEFAULTS)
            if len(settings):
                run_command(['/sbin/ethtool', '-s', dev] + settings)
            if len(offload):
                run_command(['/sbin/ethtool', '-K', dev] + offload)

            driver = netdev_get_driver_name(dev)
            if 'vlan-bug-workaround' in oc:
                vlan_bug_workaround = oc['vlan-bug-workaround'] == 'true'
            elif driver in NO_VLAN_WORKAROUND_DRIVERS:
                vlan_bug_workaround = False
            else:
                vlan_bug_workaround = netdev_has_vlan_accel(dev)

        datapath_modify_config(self._vsctl_argv)
        if self._bridge_flows:
            ofports = []
            physical_devices = datapath_get_physical_pifs(self._dp)
            if len(physical_devices) > 1:
                for slave in physical_devices:
                    name = pif_netdev_name(slave)
                    ofport = vswitchCfgQuery(['get', 'interface', name, 'ofport'])
                    ofports.append(ofport)
            else:
                name = pif_netdev_name(self._dp)
                ofport = vswitchCfgQuery(['get', 'interface', name, 'ofport'])
                ofports.append(ofport)
            dpname = pif_bridge_name(self._dp)
            for flow in self._bridge_flows:
                if flow.find('in_port=%s') != -1 or flow.find('actions=%s') != -1:
                    for port in ofports:
                        f = flow % (port.decode())
                        run_command(['/usr/bin/ovs-ofctl', 'add-flow', dpname, f])
                else:
                    run_command(['/usr/bin/ovs-ofctl', 'add-flow', dpname, flow])

    def post(self):
        for p in self._extra_ports:
            log("action_up: bring up %s" % p)
            netdev_up(p)

    def bring_down(self):
        vsctl_argv = []

        dp = self._dp
        ipdev = self._ipdev
        
        bridge = pif_bridge_name(dp)

        log("deconfigure ipdev %s on %s" % (ipdev,bridge))
        vsctl_argv += ["# deconfigure ipdev %s" % ipdev]
        vsctl_argv += datapath_deconfigure_ipdev(ipdev)

        if pif_is_vlan(self._pif):
            # Delete the VLAN bridge.
            vsctl_argv += deconfigure_bridge(self._pif)

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
            vsctl_argv += deconfigure_bridge(dp)

            physical_devices = [pif_netdev_name(p) for p in datapath_get_physical_pifs(dp)]

            log("action_down: bring down physical devices - %s" % physical_devices)
        
            for p in physical_devices:
                netdev_down(p)

        datapath_modify_config(vsctl_argv)

#
# utility methods
#

def vswitchCfgQuery(action_args):
    cmd = ['%s/usr/bin/ovs-vsctl' % root_prefix(),
           '-vconsole:off'] + action_args
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()
    if len(output) == 0 or output[0] == None:
        output = ""
    else:
        output = output[0].strip()
    return output
