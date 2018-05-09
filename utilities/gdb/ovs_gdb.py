#
#  Copyright (c) 2018 Eelco Chaudron
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version
#  2 of the License, or (at your option) any later version.
#
#  Files name:
#    ovs_gdb.py
#
#  Description:
#    GDB commands and functions for Open vSwitch debugging
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    23 April 2018
#
#  Notes:
#    It implements the following GDB commands:
#    - ovs_dump_bridge [ports|wanted]
#    - ovs_dump_bridge_ports <struct bridge *>
#    - ovs_dump_dp_netdev [ports]
#    - ovs_dump_dp_netdev_ports <struct dp_netdev *>
#    - ovs_dump_netdev
#
#  Example:
#    $ gdb $(which ovs-vswitchd) $(pidof ovs-vswitchd)
#    (gdb) source ./utilities/gdb/ovs_gdb.py
#
#    (gdb) ovs_dump_<TAB>
#    ovs_dump_bridge           ovs_dump_bridge_ports     ovs_dump_dp_netdev
#    ovs_dump_dp_netdev_ports  ovs_dump_netdev
#
#    (gdb) ovs_dump_bridge
#    (struct bridge *) 0x5615471ed2e0: name = br2, type = system
#    (struct bridge *) 0x561547166350: name = br0, type = system
#    (struct bridge *) 0x561547216de0: name = ovs_pvp_br0, type = netdev
#    (struct bridge *) 0x5615471d0420: name = br1, type = system
#
#    (gdb) p *(struct bridge *) 0x5615471d0420
#    $1 = {node = {hash = 24776443, next = 0x0}, name = 0x5615471cca90 "br1",
#    type = 0x561547163bb0 "system",
#    ...
#    ...
#

import gdb


#
# The container_of code below is a copied from the Linux kernel project file,
# scripts/gdb/linux/utils.py. It has the following copyright header:
#
# # gdb helper commands and functions for Linux kernel debugging
# #
# #  common utilities
# #
# # Copyright (c) Siemens AG, 2011-2013
# #
# # Authors:
# #  Jan Kiszka <jan.kiszka@siemens.com>
# #
# # This work is licensed under the terms of the GNU GPL version 2.
#
class CachedType:
    def __init__(self, name):
        self._type = None
        self._name = name

    def _new_objfile_handler(self, event):
        self._type = None
        gdb.events.new_objfile.disconnect(self._new_objfile_handler)

    def get_type(self):
        if self._type is None:
            self._type = gdb.lookup_type(self._name)
            if self._type is None:
                raise gdb.GdbError(
                    "cannot resolve type '{0}'".format(self._name))
            if hasattr(gdb, 'events') and hasattr(gdb.events, 'new_objfile'):
                gdb.events.new_objfile.connect(self._new_objfile_handler)
        return self._type


long_type = CachedType("long")


def get_long_type():
    global long_type
    return long_type.get_type()


def offset_of(typeobj, field):
    element = gdb.Value(0).cast(typeobj)
    return int(str(element[field].address).split()[0], 16)


def container_of(ptr, typeobj, member):
    return (ptr.cast(get_long_type()) -
            offset_of(typeobj, member)).cast(typeobj)


#
# Class that will provide an iterator over an OVS hmap.
#
class ForEachHMAP(object):
    def __init__(self, hmap, typeobj=None, member='node'):
        self.hmap = hmap
        self.node = None
        self.first = True
        self.typeobj = typeobj
        self.member = member

    def __iter__(self):
        return self

    def __next(self, start):
        for i in range(start, (self.hmap['mask'] + 1)):
            self.node = self.hmap['buckets'][i]
            if self.node != 0:
                return

        raise StopIteration

    def next(self):
        #
        # In the real implementation the n values is never checked,
        # however when debugging we do, as we might try to access
        # a hmap that has been cleared/hmap_destroy().
        #
        if self.hmap['n'] <= 0:
            raise StopIteration

        if self.first:
            self.first = False
            self.__next(0)
        elif self.node['next'] != 0:
            self.node = self.node['next']
        else:
            self.__next((self.node['hash'] & self.hmap['mask']) + 1)

        if self.typeobj is None:
            return self.node

        return container_of(self.node,
                            gdb.lookup_type(self.typeobj).pointer(),
                            self.member)


#
# Class that will provide an iterator over an OVS shash.
#
class ForEachSHASH(ForEachHMAP):
    def __init__(self, shash, typeobj=None):

        self.data_typeobj = typeobj

        super(ForEachSHASH, self).__init__(shash['map'],
                                           "struct shash_node", "node")

    def next(self):
        node = super(ForEachSHASH, self).next()

        if self.data_typeobj is None:
            return node

        return node['data'].cast(gdb.lookup_type(self.data_typeobj).pointer())


#
# Class that will provide an iterator over an OVS list.
#
class ForEachLIST():
    def __init__(self, list, typeobj=None, member='node'):
        self.list = list
        self.node = list
        self.typeobj = typeobj
        self.member = member

    def __iter__(self):
        return self

    def next(self):
        if self.list.address == self.node['next']:
            raise StopIteration

        self.node = self.node['next']

        if self.typeobj is None:
            return self.node

        return container_of(self.node,
                            gdb.lookup_type(self.typeobj).pointer(),
                            self.member)


#
# Implements the GDB "ovs_dump_bridges" command
#
class CmdDumpBridge(gdb.Command):
    """Dump all configured bridges.
    Usage: ovs_dump_bridge [ports|wanted]
    """
    def __init__(self):
        super(CmdDumpBridge, self).__init__("ovs_dump_bridge",
                                            gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        ports = False
        wanted = False
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) > 1 or \
           (len(arg_list) == 1 and arg_list[0] != "ports" and
           arg_list[0] != "wanted"):
            print("usage: ovs_dump_bridge [ports|wanted]")
            return
        elif len(arg_list) == 1:
            if arg_list[0] == "ports":
                ports = True
            else:
                wanted = True

        dp_netdevs = gdb.lookup_symbol('all_bridges')[0]
        if dp_netdevs is None or not dp_netdevs.is_variable:
            print("Can't find all_bridges global variable, are you sure "
                  "your debugging OVS?")
            return
        all_bridges = gdb.parse_and_eval('all_bridges')
        for node in ForEachHMAP(all_bridges,
                                "struct bridge", "node"):
            print("(struct bridge *) {}: name = {}, type = {}".
                  format(node, node['name'].string(),
                         node['type'].string()))

            if ports:
                for port in ForEachHMAP(node['ports'],
                                        "struct port", "hmap_node"):
                    CmdDumpBridgePorts.display_single_port(port, 4)

            if wanted:
                for port in ForEachSHASH(node['wanted_ports'],
                                         typeobj="struct ovsrec_port"):
                    print("    (struct ovsrec_port *) {}: name = {}".
                          format(port, port['name'].string()))
                    # print port.dereference()


#
# Implements the GDB "ovs_dump_bridge_ports" command
#
class CmdDumpBridgePorts(gdb.Command):
    """Dump all ports added to a specific struct bridge*.
    Usage: ovs_dump_bridge_ports <struct bridge *>
    """
    def __init__(self):
        super(CmdDumpBridgePorts, self).__init__("ovs_dump_bridge_ports",
                                                 gdb.COMMAND_DATA)

    @staticmethod
    def display_single_port(port, indent=0):
        indent = " " * indent
        port = port.cast(gdb.lookup_type('struct port').pointer())
        print("{}(struct port *) {}: name = {}, brige = (struct bridge *) {}".
              format(indent, port, port['name'].string(),
                     port['bridge']))

        indent += " " * 4
        for iface in ForEachLIST(port['ifaces'], "struct iface", "port_elem"):
            print("{}(struct iface *) {}: name = {}, ofp_port = {}, "
                  "netdev = (struct netdev *) {}".
                  format(indent, iface, iface['name'],
                         iface['ofp_port'], iface['netdev']))

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) != 1:
            print("usage: ovs_dump_bridge_ports <struct bridge *>")
            return
        bridge = gdb.parse_and_eval(arg_list[0]).cast(
            gdb.lookup_type('struct bridge').pointer())
        for node in ForEachHMAP(bridge['ports'],
                                "struct port", "hmap_node"):
            self.display_single_port(node)


#
# Implements the GDB "ovs_dump_dp_netdev" command
#
class CmdDumpDpNetdev(gdb.Command):
    """Dump all registered dp_netdev structures.
    Usage: ovs_dump_dp_netdev [ports]
    """
    def __init__(self):
        super(CmdDumpDpNetdev, self).__init__("ovs_dump_dp_netdev",
                                              gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        ports = False
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) > 1 or \
           (len(arg_list) == 1 and arg_list[0] != "ports"):
            print("usage: ovs_dump_dp_netdev [ports]")
            return
        elif len(arg_list) == 1:
            ports = True

        dp_netdevs = gdb.lookup_symbol('dp_netdevs')[0]
        if dp_netdevs is None or not dp_netdevs.is_variable:
            print("Can't find dp_netdevs global variable, are you sure "
                  "your debugging OVS?")
            return
        dp_netdevs = gdb.parse_and_eval('dp_netdevs')
        for node in ForEachSHASH(dp_netdevs):
            dp = node['data'].cast(
                gdb.lookup_type('struct dp_netdev').pointer())

            print("(struct dp_netdev *) {}: name = {}, class = "
                  "(struct dpif_class *) {}".
                  format(dp, dp['name'], dp['class']))

            if ports:
                for node in ForEachHMAP(dp['ports'],
                                        "struct dp_netdev_port", "node"):
                    CmdDumpDpNetdevPorts.display_single_port(node, 4)


#
# Implements the GDB "ovs_dump_dp_netdev_ports" command
#
class CmdDumpDpNetdevPorts(gdb.Command):
    """Dump all ports added to a specific struct dp_netdev*.
    Usage: ovs_dump_dp_netdev_ports <struct dp_netdev *>
    """
    def __init__(self):
        super(CmdDumpDpNetdevPorts, self).__init__("ovs_dump_dp_netdev_ports",
                                                   gdb.COMMAND_DATA)

    @staticmethod
    def display_single_port(port, indent=0):
        indent = " " * indent
        print("{}(struct dp_netdev_port *) {}:".format(indent, port))
        print("{}    port_no = {}, n_rxq = {}, type = {}".
              format(indent, port['port_no'], port['n_rxq'],
                     port['type'].string()))
        print("{}    netdev = (struct netdev *) {}: name = {}, "
              "n_txq/rxq = {}/{}".
              format(indent, port['netdev'],
                     port['netdev']['name'].string(),
                     port['netdev']['n_txq'],
                     port['netdev']['n_rxq']))

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) != 1:
            print("usage: ovs_dump_dp_netdev_ports <struct dp_netdev *>")
            return
        dp_netdev = gdb.parse_and_eval(arg_list[0]).cast(
            gdb.lookup_type('struct dp_netdev').pointer())
        for node in ForEachHMAP(dp_netdev['ports'],
                                "struct dp_netdev_port", "node"):
            # print node.dereference()
            self.display_single_port(node)


#
# Implements the GDB "ovs_dump_netdev" command
#
class CmdDumpNetdev(gdb.Command):
    """Dump all registered netdev structures.
    Usage: ovs_dump_netdev
    """
    def __init__(self):
        super(CmdDumpNetdev, self).__init__("ovs_dump_netdev",
                                            gdb.COMMAND_DATA)

    @staticmethod
    def display_single_netdev(netdev, indent=0):
        indent = " " * indent
        print("{}(struct netdev *) {}: name = {:15}, auto_classified = {:5}, "
              "netdev_class = {}".
              format(indent, netdev, netdev['name'].string(),
                     netdev['auto_classified'], netdev['netdev_class']))

    def invoke(self, arg, from_tty):
        netdev_shash = gdb.lookup_symbol('netdev_shash')[0]
        if netdev_shash is None or not netdev_shash.is_variable:
            print("Can't find netdev_shash global variable, are you sure "
                  "your debugging OVS?")
            return
        netdev_shash = gdb.parse_and_eval('netdev_shash')
        for netdev in ForEachSHASH(netdev_shash, "struct netdev"):
            self.display_single_netdev(netdev)


#
# Initialize all GDB commands
#
CmdDumpBridge()
CmdDumpBridgePorts()
CmdDumpDpNetdev()
CmdDumpDpNetdevPorts()
CmdDumpNetdev()
