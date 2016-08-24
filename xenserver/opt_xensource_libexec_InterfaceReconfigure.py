# Copyright (c) 2008,2009 Citrix Systems, Inc.
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
import sys
import syslog
import os

from xml.dom.minidom import getDOMImplementation
from xml.dom.minidom import parse as parseXML

the_root_prefix = ""
def root_prefix():
    """Returns a string to prefix to all file name references, which
    is useful for testing."""
    return the_root_prefix
def set_root_prefix(prefix):
    global the_root_prefix
    the_root_prefix = prefix

log_destination = "syslog"
def get_log_destination():
    """Returns the current log destination.
    'syslog' means "log to syslog".
    'stderr' means "log to stderr"."""
    return log_destination
def set_log_destination(dest):
    global log_destination
    log_destination = dest

#
# Logging.
#

def log(s):
    if get_log_destination() == 'syslog':
        syslog.syslog(s)
    else:
        sys.stderr.write(s + '\n')
        sys.stderr.flush()

#
# Exceptions.
#

class Error(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

#
# Run external utilities
#

def run_command(command):
    log("Running command: " + ' '.join(command))
    rc = os.spawnl(os.P_WAIT, root_prefix() + command[0], *command)
    if rc != 0:
        log("Command failed %d: " % rc + ' '.join(command))
        return False
    return True

#
# Configuration File Handling.
#

class ConfigurationFile(object):
    """Write a file, tracking old and new versions.

    Supports writing a new version of a file and applying and
    reverting those changes.
    """

    __STATE = {"OPEN":"OPEN",
               "NOT-APPLIED":"NOT-APPLIED", "APPLIED":"APPLIED",
               "REVERTED":"REVERTED", "COMMITTED": "COMMITTED"}

    def __init__(self, path):
        dirname,basename = os.path.split(path)

        self.__state = self.__STATE['OPEN']
        self.__children = []

        self.__path    = os.path.join(dirname, basename)
        self.__oldpath = os.path.join(dirname, "." + basename + ".xapi-old")
        self.__newpath = os.path.join(dirname, "." + basename + ".xapi-new")

        self.__f = open(self.__newpath, "w")

    def attach_child(self, child):
        self.__children.append(child)

    def path(self):
        return self.__path

    def readlines(self):
        try:
            return open(self.path()).readlines()
        except:
            return ""

    def write(self, args):
        if self.__state != self.__STATE['OPEN']:
            raise Error("Attempt to write to file in state %s" % self.__state)
        self.__f.write(args)

    def close(self):
        if self.__state != self.__STATE['OPEN']:
            raise Error("Attempt to close file in state %s" % self.__state)

        self.__f.close()
        self.__state = self.__STATE['NOT-APPLIED']

    def changed(self):
        if self.__state != self.__STATE['NOT-APPLIED']:
            raise Error("Attempt to compare file in state %s" % self.__state)

        return True

    def apply(self):
        if self.__state != self.__STATE['NOT-APPLIED']:
            raise Error("Attempt to apply configuration from state %s" % self.__state)

        for child in self.__children:
            child.apply()

        log("Applying changes to %s configuration" % self.__path)

        # Remove previous backup.
        if os.access(self.__oldpath, os.F_OK):
            os.unlink(self.__oldpath)

        # Save current configuration.
        if os.access(self.__path, os.F_OK):
            os.link(self.__path, self.__oldpath)
            os.unlink(self.__path)

        # Apply new configuration.
        assert(os.path.exists(self.__newpath))
        os.link(self.__newpath, self.__path)

        # Remove temporary file.
        os.unlink(self.__newpath)

        self.__state = self.__STATE['APPLIED']

    def revert(self):
        if self.__state != self.__STATE['APPLIED']:
            raise Error("Attempt to revert configuration from state %s" % self.__state)

        for child in self.__children:
            child.revert()

        log("Reverting changes to %s configuration" % self.__path)

        # Remove existing new configuration
        if os.access(self.__newpath, os.F_OK):
            os.unlink(self.__newpath)

        # Revert new configuration.
        if os.access(self.__path, os.F_OK):
            os.link(self.__path, self.__newpath)
            os.unlink(self.__path)

        # Revert to old configuration.
        if os.access(self.__oldpath, os.F_OK):
            os.link(self.__oldpath, self.__path)
            os.unlink(self.__oldpath)

        # Leave .*.xapi-new as an aid to debugging.

        self.__state = self.__STATE['REVERTED']

    def commit(self):
        if self.__state != self.__STATE['APPLIED']:
            raise Error("Attempt to commit configuration from state %s" % self.__state)

        for child in self.__children:
            child.commit()

        log("Committing changes to %s configuration" % self.__path)

        if os.access(self.__oldpath, os.F_OK):
            os.unlink(self.__oldpath)
        if os.access(self.__newpath, os.F_OK):
            os.unlink(self.__newpath)

        self.__state = self.__STATE['COMMITTED']

#
# Helper functions for encoding/decoding database attributes to/from XML.
#

def _str_to_xml(xml, parent, tag, val):
    e = xml.createElement(tag)
    parent.appendChild(e)
    v = xml.createTextNode(val)
    e.appendChild(v)
def _str_from_xml(n):
    def getText(nodelist):
        rc = ""
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rc = rc + node.data
        return rc
    return getText(n.childNodes).strip()

def _bool_to_xml(xml, parent, tag, val):
    if val:
        _str_to_xml(xml, parent, tag, "True")
    else:
        _str_to_xml(xml, parent, tag, "False")
def _bool_from_xml(n):
    s = _str_from_xml(n)
    if s == "True":
        return True
    elif s == "False":
        return False
    else:
        raise Error("Unknown boolean value %s" % s)

def _strlist_to_xml(xml, parent, ltag, itag, val):
    e = xml.createElement(ltag)
    parent.appendChild(e)
    for v in val:
        c = xml.createElement(itag)
        e.appendChild(c)
        cv = xml.createTextNode(v)
        c.appendChild(cv)
def _strlist_from_xml(n, ltag, itag):
    ret = []
    for n in n.childNodes:
        if n.nodeName == itag:
            ret.append(_str_from_xml(n))
    return ret

def _map_to_xml(xml, parent, tag, val, attrs):
    e = xml.createElement(tag)
    parent.appendChild(e)
    for n,v in val.items():
        if n in attrs:
            _str_to_xml(xml, e, n, v)
        else:
            log("Unknown other-config attribute: %s" % n)

def _map_from_xml(n, attrs):
    ret = {}
    for n in n.childNodes:
        if n.nodeName in attrs:
            ret[n.nodeName] = _str_from_xml(n)
    return ret

def _otherconfig_to_xml(xml, parent, val, attrs):
    return _map_to_xml(xml, parent, "other_config", val, attrs)
def _otherconfig_from_xml(n, attrs):
    return _map_from_xml(n, attrs)

#
# Definitions of the database objects (and their attributes) used by interface-reconfigure.
#
# Each object is defined by a dictionary mapping an attribute name in
# the xapi database to a tuple containing two items:
#  - a function which takes this attribute and encodes it as XML.
#  - a function which takes XML and decocdes it into a value.
#
# other-config attributes are specified as a simple array of strings

_PIF_XML_TAG = "pif"
_VLAN_XML_TAG = "vlan"
_TUNNEL_XML_TAG = "tunnel"
_BOND_XML_TAG = "bond"
_NETWORK_XML_TAG = "network"
_POOL_XML_TAG = "pool"

_ETHTOOL_OTHERCONFIG_ATTRS = ['ethtool-%s' % x for x in ['autoneg', 'speed', 'duplex', 'rx', 'tx', 'sg', 'tso', 'ufo', 'gso', 'gro', 'lro'] ]

_PIF_OTHERCONFIG_ATTRS = [ 'domain', 'peerdns', 'defaultroute', 'mtu', 'static-routes' ] + \
                        [ 'bond-%s' % x for x in ['mode', 'miimon', 'downdelay', 'updelay', 'use_carrier', 'hashing-algorithm'] ] + \
                        [ 'vlan-bug-workaround' ] + \
                        _ETHTOOL_OTHERCONFIG_ATTRS

_PIF_ATTRS = { 'uuid': (_str_to_xml,_str_from_xml),
               'management': (_bool_to_xml,_bool_from_xml),
               'network': (_str_to_xml,_str_from_xml),
               'device': (_str_to_xml,_str_from_xml),
               'bond_master_of': (lambda x, p, t, v: _strlist_to_xml(x, p, 'bond_master_of', 'slave', v),
                                  lambda n: _strlist_from_xml(n, 'bond_master_of', 'slave')),
               'bond_slave_of': (_str_to_xml,_str_from_xml),
               'VLAN': (_str_to_xml,_str_from_xml),
               'VLAN_master_of': (_str_to_xml,_str_from_xml),
               'VLAN_slave_of': (lambda x, p, t, v: _strlist_to_xml(x, p, 'VLAN_slave_of', 'master', v),
                                 lambda n: _strlist_from_xml(n, 'VLAN_slave_Of', 'master')),
               'tunnel_access_PIF_of': (lambda x, p, t, v: _strlist_to_xml(x, p, 'tunnel_access_PIF_of', 'pif', v),
                                        lambda n: _strlist_from_xml(n, 'tunnel_access_PIF_of', 'pif')),
               'tunnel_transport_PIF_of':  (lambda x, p, t, v: _strlist_to_xml(x, p, 'tunnel_transport_PIF_of', 'pif', v),
                                            lambda n: _strlist_from_xml(n, 'tunnel_transport_PIF_of', 'pif')),
               'ip_configuration_mode': (_str_to_xml,_str_from_xml),
               'IP': (_str_to_xml,_str_from_xml),
               'netmask': (_str_to_xml,_str_from_xml),
               'gateway': (_str_to_xml,_str_from_xml),
               'DNS': (_str_to_xml,_str_from_xml),
               'MAC': (_str_to_xml,_str_from_xml),
               'other_config': (lambda x, p, t, v: _otherconfig_to_xml(x, p, v, _PIF_OTHERCONFIG_ATTRS),
                                lambda n: _otherconfig_from_xml(n, _PIF_OTHERCONFIG_ATTRS)),

               # Special case: We write the current value
               # PIF.currently-attached to the cache but since it will
               # not be valid when we come to use the cache later
               # (i.e. after a reboot) we always read it as False.
               'currently_attached': (_bool_to_xml, lambda n: False),
             }

_VLAN_ATTRS = { 'uuid': (_str_to_xml,_str_from_xml),
                'tagged_PIF': (_str_to_xml,_str_from_xml),
                'untagged_PIF': (_str_to_xml,_str_from_xml),
              }

_TUNNEL_ATTRS = { 'uuid': (_str_to_xml,_str_from_xml),
                  'access_PIF': (_str_to_xml,_str_from_xml),
                  'transport_PIF': (_str_to_xml,_str_from_xml),
                }
_BOND_ATTRS = { 'uuid': (_str_to_xml,_str_from_xml),
               'master': (_str_to_xml,_str_from_xml),
               'slaves': (lambda x, p, t, v: _strlist_to_xml(x, p, 'slaves', 'slave', v),
                          lambda n: _strlist_from_xml(n, 'slaves', 'slave')),
              }

_NETWORK_OTHERCONFIG_ATTRS = [ 'mtu',
                               'static-routes',
                               'vswitch-controller-fail-mode',
                               'vswitch-disable-in-band' ] \
                               + _ETHTOOL_OTHERCONFIG_ATTRS

_NETWORK_ATTRS = { 'uuid': (_str_to_xml,_str_from_xml),
                   'bridge': (_str_to_xml,_str_from_xml),
                   'MTU': (_str_to_xml,_str_from_xml),
                   'PIFs': (lambda x, p, t, v: _strlist_to_xml(x, p, 'PIFs', 'PIF', v),
                            lambda n: _strlist_from_xml(n, 'PIFs', 'PIF')),
                   'other_config': (lambda x, p, t, v: _otherconfig_to_xml(x, p, v, _NETWORK_OTHERCONFIG_ATTRS),
                                    lambda n: _otherconfig_from_xml(n, _NETWORK_OTHERCONFIG_ATTRS)),
                 }

_POOL_OTHERCONFIG_ATTRS = ['vswitch-controller-fail-mode']

_POOL_ATTRS = { 'other_config': (lambda x, p, t, v: _otherconfig_to_xml(x, p, v, _POOL_OTHERCONFIG_ATTRS),
                                 lambda n: _otherconfig_from_xml(n, _POOL_OTHERCONFIG_ATTRS)),
              }

#
# Database Cache object
#

_db = None

def db():
    assert(_db is not None)
    return _db

def db_init_from_cache(cache):
    global _db
    assert(_db is None)
    _db = DatabaseCache(cache_file=cache)
    
def db_init_from_xenapi(session):
    global _db 
    assert(_db is None)
    _db  = DatabaseCache(session_ref=session)
    
class DatabaseCache(object):
    def __read_xensource_inventory(self):
        filename = root_prefix() + "/etc/xensource-inventory"
        f = open(filename, "r")
        lines = [x.strip("\n") for x in f.readlines()]
        f.close()

        defs = [ (l[:l.find("=")], l[(l.find("=") + 1):]) for l in lines ]
        defs = [ (a, b.strip("'")) for (a,b) in defs ]

        return dict(defs)

    def __pif_on_host(self,pif):
        return pif in self.__pifs

    def __get_pif_records_from_xapi(self, session, host):
        self.__pifs = {}
        for (p,rec) in session.xenapi.PIF.get_all_records().items():
            if rec['host'] != host:
                continue
            self.__pifs[p] = {}
            for f in _PIF_ATTRS:
                self.__pifs[p][f] = rec[f]
            self.__pifs[p]['other_config'] = {}
            for f in _PIF_OTHERCONFIG_ATTRS:
                if f not in rec['other_config']: continue
                self.__pifs[p]['other_config'][f] = rec['other_config'][f]

    def __get_vlan_records_from_xapi(self, session):
        self.__vlans = {}
        for (v,rec) in session.xenapi.VLAN.get_all_records().items():
            if not self.__pif_on_host(rec['untagged_PIF']):
                continue
            self.__vlans[v] = {}
            for f in _VLAN_ATTRS:
                self.__vlans[v][f] = rec[f]

    def __get_tunnel_records_from_xapi(self, session):
        self.__tunnels = {}
        for t in session.xenapi.tunnel.get_all():
            rec = session.xenapi.tunnel.get_record(t)
            if not self.__pif_on_host(rec['transport_PIF']):
                continue
            self.__tunnels[t] = {}
            for f in _TUNNEL_ATTRS:
                self.__tunnels[t][f] = rec[f]

    def __get_bond_records_from_xapi(self, session):
        self.__bonds = {}
        for (b,rec) in session.xenapi.Bond.get_all_records().items():
            if not self.__pif_on_host(rec['master']):
                continue
            self.__bonds[b] = {}
            for f in _BOND_ATTRS:
                self.__bonds[b][f] = rec[f]

    def __get_network_records_from_xapi(self, session):
        self.__networks = {}
        for (n,rec) in session.xenapi.network.get_all_records().items():
            self.__networks[n] = {}
            for f in _NETWORK_ATTRS:
                if f == "PIFs":
                    # drop PIFs on other hosts
                    self.__networks[n][f] = [p for p in rec[f] if self.__pif_on_host(p)]
                elif f == "MTU" and f not in rec:
                    # XenServer 5.5 network records did not have an
                    # MTU field, so allow this to be missing.
                    pass
                else:
                    self.__networks[n][f] = rec[f]
            self.__networks[n]['other_config'] = {}
            for f in _NETWORK_OTHERCONFIG_ATTRS:
                if f not in rec['other_config']: continue
                self.__networks[n]['other_config'][f] = rec['other_config'][f]

    def __get_pool_records_from_xapi(self, session):
        self.__pools = {}
        for p in session.xenapi.pool.get_all():
            rec = session.xenapi.pool.get_record(p)

            self.__pools[p] = {}

            for f in _POOL_ATTRS:
                self.__pools[p][f] = rec[f]

            for f in _POOL_OTHERCONFIG_ATTRS:
                if f in rec['other_config']:
                    self.__pools[p]['other_config'][f] = rec['other_config'][f]

    def __to_xml(self, xml, parent, key, ref, rec, attrs):
        """Encode a database object as XML"""
        e = xml.createElement(key)
        parent.appendChild(e)
        if ref:
            e.setAttribute('ref', ref)

        for n,v in rec.items():
            if n in attrs:
                h,_ = attrs[n]
                h(xml, e, n, v)
            else:
                raise Error("Unknown attribute %s" % n)
    def __from_xml(self, e, attrs):
        """Decode a database object from XML"""
        ref = e.attributes['ref'].value
        rec = {}
        for n in e.childNodes:
            if n.nodeName in attrs:
                _,h = attrs[n.nodeName]
                rec[n.nodeName] = h(n)
        return (ref,rec)

    def __init__(self, session_ref=None, cache_file=None):
        if session_ref and cache_file:
            raise Error("can't specify session reference and cache file")
        if cache_file == None:
            import XenAPI
            session = XenAPI.xapi_local()

            if not session_ref:
                log("No session ref given on command line, logging in.")
                session.xenapi.login_with_password("root", "")
            else:
                session._session = session_ref

            try:

                inventory = self.__read_xensource_inventory()
                assert('INSTALLATION_UUID' in inventory)
                log("host uuid is %s" % inventory['INSTALLATION_UUID'])

                host = session.xenapi.host.get_by_uuid(inventory['INSTALLATION_UUID'])

                self.__get_pif_records_from_xapi(session, host)
                self.__get_pool_records_from_xapi(session)
                self.__get_tunnel_records_from_xapi(session)
                self.__get_vlan_records_from_xapi(session)
                self.__get_bond_records_from_xapi(session)
                self.__get_network_records_from_xapi(session)
            finally:
                if not session_ref:
                    session.xenapi.session.logout()
        else:
            log("Loading xapi database cache from %s" % cache_file)

            xml = parseXML(root_prefix() + cache_file)

            self.__pifs = {}
            self.__bonds = {}
            self.__vlans = {}
            self.__pools = {}
            self.__tunnels = {}
            self.__networks = {}

            assert(len(xml.childNodes) == 1)
            toplevel = xml.childNodes[0]

            assert(toplevel.nodeName == "xenserver-network-configuration")

            for n in toplevel.childNodes:
                if n.nodeName == "#text":
                    pass
                elif n.nodeName == _PIF_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _PIF_ATTRS)
                    self.__pifs[ref] = rec
                elif n.nodeName == _BOND_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _BOND_ATTRS)
                    self.__bonds[ref] = rec
                elif n.nodeName == _VLAN_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _VLAN_ATTRS)
                    self.__vlans[ref] = rec
                elif n.nodeName == _TUNNEL_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _TUNNEL_ATTRS)
                    self.__vlans[ref] = rec
                elif n.nodeName == _NETWORK_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _NETWORK_ATTRS)
                    self.__networks[ref] = rec
                elif n.nodeName == _POOL_XML_TAG:
                    (ref,rec) = self.__from_xml(n, _POOL_ATTRS)
                    self.__pools[ref] = rec
                else:
                    raise Error("Unknown XML element %s" % n.nodeName)

    def save(self, cache_file):

        xml = getDOMImplementation().createDocument(
            None, "xenserver-network-configuration", None)
        for (ref,rec) in self.__pifs.items():
            self.__to_xml(xml, xml.documentElement, _PIF_XML_TAG, ref, rec, _PIF_ATTRS)
        for (ref,rec) in self.__bonds.items():
            self.__to_xml(xml, xml.documentElement, _BOND_XML_TAG, ref, rec, _BOND_ATTRS)
        for (ref,rec) in self.__vlans.items():
            self.__to_xml(xml, xml.documentElement, _VLAN_XML_TAG, ref, rec, _VLAN_ATTRS)
        for (ref,rec) in self.__tunnels.items():
            self.__to_xml(xml, xml.documentElement, _TUNNEL_XML_TAG, ref, rec, _TUNNEL_ATTRS)
        for (ref,rec) in self.__networks.items():
            self.__to_xml(xml, xml.documentElement, _NETWORK_XML_TAG, ref, rec,
                          _NETWORK_ATTRS)
        for (ref,rec) in self.__pools.items():
            self.__to_xml(xml, xml.documentElement, _POOL_XML_TAG, ref, rec, _POOL_ATTRS)

        temp_file = cache_file + ".%d" % os.getpid()
        f = open(temp_file, 'w')
        f.write(xml.toprettyxml())
        f.close()
        os.rename(temp_file, cache_file)

    def get_pif_by_uuid(self, uuid):
        pifs = map(lambda ref_rec: ref_rec[0],
                  filter(lambda ref_rec: uuid == ref_rec[1]['uuid'],
                         self.__pifs.items()))
        if len(pifs) == 0:
            raise Error("Unknown PIF \"%s\"" % uuid)
        elif len(pifs) > 1:
            raise Error("Non-unique PIF \"%s\"" % uuid)

        return pifs[0]

    def get_pifs_by_device(self, device):
        return list(map(lambda ref_rec: ref_rec[0],
                   list(filter(lambda ref_rec: ref_rec[1]['device'] == device,
                          self.__pifs.items()))))

    def get_networks_with_bridge(self, bridge):
        return list(map(lambda ref_rec: ref_rec[0],
                  list(filter(lambda ref_rec: ref_rec[1]['bridge'] == bridge,
                         self.__networks.items()))))

    def get_network_by_bridge(self, bridge):
        #Assumes one network has bridge.
        try:
            return self.get_networks_with_bridge(bridge)[0]
        except KeyError:
            return None

    def get_pif_by_bridge(self, bridge):
        networks = self.get_networks_with_bridge(bridge)

        if len(networks) == 0:
            raise Error("No matching network \"%s\"" % bridge)

        answer = None
        for network in networks:
            nwrec = self.get_network_record(network)
            for pif in nwrec['PIFs']:
                pifrec = self.get_pif_record(pif)
                if answer:
                    raise Error("Multiple PIFs on host for network %s" % (bridge))
                answer = pif
        if not answer:
            raise Error("No PIF on host for network %s" % (bridge))
        return answer

    def get_pif_record(self, pif):
        if pif in self.__pifs:
            return self.__pifs[pif]
        raise Error("Unknown PIF \"%s\"" % pif)
    def get_all_pifs(self):
        return self.__pifs
    def pif_exists(self, pif):
        return pif in self.__pifs

    def get_management_pif(self):
        """ Returns the management pif on host
        """
        all = self.get_all_pifs()
        for pif in all:
            pifrec = self.get_pif_record(pif)
            if pifrec['management']: return pif
        return None

    def get_network_record(self, network):
        if network in self.__networks:
            return self.__networks[network]
        raise Error("Unknown network \"%s\"" % network)

    def get_bond_record(self, bond):
        if bond in self.__bonds:
            return self.__bonds[bond]
        else:
            return None

    def get_vlan_record(self, vlan):
        if vlan in self.__vlans:
            return self.__vlans[vlan]
        else:
            return None

    def get_pool_record(self):
        if len(self.__pools) > 0:
            return list(self.__pools.values())[0]

#
#
#
PIF_OTHERCONFIG_DEFAULTS = {'gro': 'off', 'lro': 'off'}

def ethtool_settings(oc, defaults = {}):
    settings = []
    if 'ethtool-speed' in oc:
        val = oc['ethtool-speed']
        if val in ["10", "100", "1000"]:
            settings += ['speed', val]
        else:
            log("Invalid value for ethtool-speed = %s. Must be 10|100|1000." % val)
    if 'ethtool-duplex' in oc:
        val = oc['ethtool-duplex']
        if val in ["half", "full"]:
            settings += ['duplex', val]
        else:
            log("Invalid value for ethtool-duplex = %s. Must be half|full." % val)
    if 'ethtool-autoneg' in oc:
        val = oc['ethtool-autoneg']
        if val in ["true", "on"]:
            settings += ['autoneg', 'on']
        elif val in ["false", "off"]:
            settings += ['autoneg', 'off']
        else:
            log("Invalid value for ethtool-autoneg = %s. Must be on|true|off|false." % val)
    offload = []
    for opt in ("rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro"):
        if "ethtool-" + opt in oc:
            val = oc["ethtool-" + opt]
            if val in ["true", "on"]:
                offload += [opt, 'on']
            elif val in ["false", "off"]:
                offload += [opt, 'off']
            else:
                log("Invalid value for ethtool-%s = %s. Must be on|true|off|false." % (opt, val))
        elif opt in defaults:
            offload += [opt, defaults[opt]]
    return settings,offload

# By default the MTU is taken from the Network.MTU setting for VIF,
# PIF and Bridge. However it is possible to override this by using
# {VIF,PIF,Network}.other-config:mtu.
#
# type parameter is a string describing the object that the oc parameter
# is from. e.g. "PIF", "Network" 
def mtu_setting(nw, type, oc):
    mtu = None

    nwrec = db().get_network_record(nw)
    if 'MTU' in nwrec:
        mtu = nwrec['MTU']
    else:
        mtu = "1500"
        
    if 'mtu' in oc:
        log("Override Network.MTU setting on bridge %s from %s.MTU is %s" % \
            (nwrec['bridge'], type, mtu))
        mtu = oc['mtu']

    if mtu is not None:
        try:
            int(mtu)      # Check that the value is an integer
            return mtu
        except ValueError as x:
            log("Invalid value for mtu = %s" % mtu)

    return None

#
# IP Network Devices -- network devices with IP configuration
#
def pif_ipdev_name(pif):
    """Return the ipdev name associated with pif"""
    pifrec = db().get_pif_record(pif)
    nwrec = db().get_network_record(pifrec['network'])

    if nwrec['bridge']:
        # TODO: sanity check that nwrec['bridgeless'] != 'true'
        return nwrec['bridge']
    else:
        # TODO: sanity check that nwrec['bridgeless'] == 'true'
        return pif_netdev_name(pif)

#
# Bare Network Devices -- network devices without IP configuration
#

def netdev_exists(netdev):
    return os.path.exists(root_prefix() + "/sys/class/net/" + netdev)


def unicode_2to3(string):
    if sys.version_info < (3,):
        return string.encode()
    return string


def pif_netdev_name(pif):
    """Get the netdev name for a PIF."""

    pifrec = db().get_pif_record(pif)

    if pif_is_vlan(pif):
        return unicode_2to3("%(device)s.%(VLAN)s" % pifrec)
    else:
        return unicode_2to3(pifrec['device'])

#
# Bridges
#

def pif_is_bridged(pif):
    pifrec = db().get_pif_record(pif)
    nwrec = db().get_network_record(pifrec['network'])

    if nwrec['bridge']:
        # TODO: sanity check that nwrec['bridgeless'] != 'true'
        return True
    else:
        # TODO: sanity check that nwrec['bridgeless'] == 'true'
        return False

def pif_bridge_name(pif):
    """Return the bridge name of a pif.

    PIF must be a bridged PIF."""
    pifrec = db().get_pif_record(pif)

    nwrec = db().get_network_record(pifrec['network'])

    if nwrec['bridge']:
        return nwrec['bridge']
    else:
        raise Error("PIF %(uuid)s does not have a bridge name" % pifrec)

#
# Bonded PIFs
#
def pif_is_bond(pif):
    pifrec = db().get_pif_record(pif)

    return len(pifrec['bond_master_of']) > 0

def pif_get_bond_masters(pif):
    """Returns a list of PIFs which are bond masters of this PIF"""

    pifrec = db().get_pif_record(pif)

    bso = pifrec['bond_slave_of']

    # bond-slave-of is currently a single reference but in principle a
    # PIF could be a member of several bonds which are not
    # concurrently attached. Be robust to this possibility.
    if not bso or bso == "OpaqueRef:NULL":
        bso = []
    elif not type(bso) == list:
        bso = [bso]

    bondrecs = [db().get_bond_record(bond) for bond in bso]
    bondrecs = [rec for rec in bondrecs if rec]

    return [bond['master'] for bond in bondrecs]

def pif_get_bond_slaves(pif):
    """Returns a list of PIFs which make up the given bonded pif."""

    pifrec = db().get_pif_record(pif)

    bmo = pifrec['bond_master_of']
    if len(bmo) > 1:
        raise Error("Bond-master-of contains too many elements")

    if len(bmo) == 0:
        return []

    bondrec = db().get_bond_record(bmo[0])
    if not bondrec:
        raise Error("No bond record for bond master PIF")

    return bondrec['slaves']

#
# VLAN PIFs
#

def pif_is_vlan(pif):
    return db().get_pif_record(pif)['VLAN'] != '-1'

def pif_get_vlan_slave(pif):
    """Find the PIF which is the VLAN slave of pif.

Returns the 'physical' PIF underneath the a VLAN PIF @pif."""

    pifrec = db().get_pif_record(pif)

    vlan = pifrec['VLAN_master_of']
    if not vlan or vlan == "OpaqueRef:NULL":
        raise Error("PIF is not a VLAN master")

    vlanrec = db().get_vlan_record(vlan)
    if not vlanrec:
        raise Error("No VLAN record found for PIF")

    return vlanrec['tagged_PIF']

def pif_get_vlan_masters(pif):
    """Returns a list of PIFs which are VLANs on top of the given pif."""

    pifrec = db().get_pif_record(pif)
    vlans = [db().get_vlan_record(v) for v in pifrec['VLAN_slave_of']]
    return [v['untagged_PIF'] for v in vlans if v and db().pif_exists(v['untagged_PIF'])]

#
# Tunnel PIFs
#
def pif_is_tunnel(pif):
    return len(db().get_pif_record(pif)['tunnel_access_PIF_of']) > 0

#
# Datapath base class
#

class Datapath(object):
    """Object encapsulating the actions necessary to (de)configure the
       datapath for a given PIF. Does not include configuration of the
       IP address on the ipdev.
    """
    
    def __init__(self, pif):
        self._pif = pif

    @classmethod
    def rewrite(cls):
        """Class method called when write action is called. Can be used
           to update any backend specific configuration."""
        pass

    def configure_ipdev(self, cfg):
        """Write ifcfg TYPE field for an IPdev, plus any type specific
           fields to cfg
        """
        raise NotImplementedError        

    def preconfigure(self, parent):
        """Prepare datapath configuration for PIF, but do not actually
           apply any changes.

           Any configuration files should be attached to parent.
        """
        raise NotImplementedError
    
    def bring_down_existing(self):
        """Tear down any existing network device configuration which
           needs to be undone in order to bring this PIF up.
        """
        raise NotImplementedError

    def configure(self):
        """Apply the configuration prepared in the preconfigure stage.

           Should assume any configuration files changed attached in
           the preconfigure stage are applied and bring up the
           necessary devices to provide the datapath for the
           PIF.

           Should not bring up the IPdev.
        """
        raise NotImplementedError
    
    def post(self):
        """Called after the IPdev has been brought up.

           Should do any final setup, including reinstating any
           devices which were taken down in the bring_down_existing
           hook.
        """
        raise NotImplementedError

    def bring_down(self):
        """Tear down and deconfigure the datapath. Should assume the
           IPdev has already been brought down.
        """
        raise NotImplementedError
        
def DatapathFactory():
    # XXX Need a datapath object for bridgeless PIFs

    try:
        network_conf = open(root_prefix() + "/etc/xensource/network.conf", 'r')
        network_backend = network_conf.readline().strip()
        network_conf.close()                
    except Exception as e:
        raise Error("failed to determine network backend:" + e)
    
    if network_backend == "bridge":
        from InterfaceReconfigureBridge import DatapathBridge
        return DatapathBridge
    elif network_backend in ["openvswitch", "vswitch"]:
        from InterfaceReconfigureVswitch import DatapathVswitch
        return DatapathVswitch
    else:
        raise Error("unknown network backend %s" % network_backend)
