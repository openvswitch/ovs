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
#    - ovs_dump_bridge {ports|wanted}
#    - ovs_dump_bridge_ports <struct bridge *>
#    - ovs_dump_dp_netdev [ports]
#    - ovs_dump_dp_netdev_poll_threads <struct dp_netdev *>
#    - ovs_dump_dp_netdev_ports <struct dp_netdev *>
#    - ovs_dump_dp_provider
#    - ovs_dump_netdev
#    - ovs_dump_netdev_provider
#    - ovs_dump_ovs_list <struct ovs_list *> {[<structure>] [<member>] {dump}]}
#    - ovs_dump_simap <struct simap *>
#    - ovs_dump_udpif_keys {<udpif_name>|<udpif_address>} {short}
#    - ovs_show_fdb {[<bridge_name>] {dbg} {hash}}
#    - ovs_show_upcall {dbg}
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
import uuid


#
# Global #define's from OVS which might need updating based on a version.
#
N_UMAPS = 512


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


def get_global_variable(name):
    var = gdb.lookup_symbol(name)[0]
    if var is None or not var.is_variable:
        print("Can't find {} global variable, are you sure "
              "your debugging OVS?".format(name))
        return None
    return gdb.parse_and_eval(name)


def get_time_msec():
    # There is no variable that stores the current time each iteration,
    # to get a decent time time_now() value. For now we take the global
    # "coverage_run_time" value, which is the current time + max 5 seconds
    # (COVERAGE_RUN_INTERVAL)
    return long(get_global_variable("coverage_run_time")), -5000


def get_time_now():
    # See get_time_msec() above
    return long(get_global_variable("coverage_run_time"))/1000, -5


def eth_addr_to_string(eth_addr):
    return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        long(eth_addr['ea'][0]),
        long(eth_addr['ea'][1]),
        long(eth_addr['ea'][2]),
        long(eth_addr['ea'][3]),
        long(eth_addr['ea'][4]),
        long(eth_addr['ea'][5]))


#
# Class that will provide an iterator over an OVS cmap.
#
class ForEachCMAP(object):
    def __init__(self, cmap, typeobj=None, member='node'):
        self.cmap = cmap
        self.first = True
        self.typeobj = typeobj
        self.member = member
        # Cursor values
        self.node = 0
        self.bucket_idx = 0
        self.entry_idx = 0

    def __iter__(self):
        return self

    def __get_CMAP_K(self):
        ptr_type = gdb.lookup_type("void").pointer()
        return (64 - 4) / (4 + ptr_type.sizeof)

    def __next(self):
        ipml = self.cmap['impl']['p']

        if self.node != 0:
            self.node = self.node['next']['p']
            if self.node != 0:
                return

        while self.bucket_idx <= ipml['mask']:
            buckets = ipml['buckets'][self.bucket_idx]
            while self.entry_idx < self.__get_CMAP_K():
                self.node = buckets['nodes'][self.entry_idx]['next']['p']
                self.entry_idx += 1
                if self.node != 0:
                    return

            self.bucket_idx += 1
            self.entry_idx = 0

        raise StopIteration

    def next(self):
        ipml = self.cmap['impl']['p']
        if ipml['n'] == 0:
            raise StopIteration

        self.__next()

        if self.typeobj is None:
            return self.node

        return container_of(self.node,
                            gdb.lookup_type(self.typeobj).pointer(),
                            self.member)


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
# Class that will provide an iterator over an Netlink attributes
#
class ForEachNL():
    def __init__(self, nlattrs, nlattrs_len):
        self.attr = nlattrs.cast(gdb.lookup_type('struct nlattr').pointer())
        self.attr_len = long(nlattrs_len)

    def __iter__(self):
        return self

    def round_up(self, val, round_to):
        return int(val) + (round_to - int(val)) % round_to

    def next(self):
        if self.attr is None or \
           self.attr_len < 4 or self.attr['nla_len'] < 4 or  \
           self.attr['nla_len'] > self.attr_len:
            #
            # Invalid attr set, maybe we should raise an exception?
            #
            raise StopIteration

        attr = self.attr
        self.attr_len -= self.round_up(attr['nla_len'], 4)

        self.attr = self.attr.cast(gdb.lookup_type('void').pointer()) \
            + self.round_up(attr['nla_len'], 4)
        self.attr = self.attr.cast(gdb.lookup_type('struct nlattr').pointer())

        return attr


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
# Class that will provide an iterator over an OVS simap.
#
class ForEachSIMAP(ForEachHMAP):
    def __init__(self, shash):
        super(ForEachSIMAP, self).__init__(shash['map'],
                                           "struct simap_node", "node")

    def next(self):
        node = super(ForEachSIMAP, self).next()
        return node['name'], node['data']


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
    Usage: ovs_dump_bridge {ports|wanted}
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
            print("usage: ovs_dump_bridge {ports|wanted}")
            return
        elif len(arg_list) == 1:
            if arg_list[0] == "ports":
                ports = True
            else:
                wanted = True

        all_bridges = get_global_variable('all_bridges')
        if all_bridges is None:
            return

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

        dp_netdevs = get_global_variable('dp_netdevs')
        if dp_netdevs is None:
            return

        for dp in ForEachSHASH(dp_netdevs, typeobj=('struct dp_netdev')):

            print("(struct dp_netdev *) {}: name = {}, class = "
                  "(struct dpif_class *) {}".
                  format(dp, dp['name'].string(), dp['class']))

            if ports:
                for node in ForEachHMAP(dp['ports'],
                                        "struct dp_netdev_port", "node"):
                    CmdDumpDpNetdevPorts.display_single_port(node, 4)


#
# Implements the GDB "ovs_dump_dp_netdev_poll_threads" command
#
class CmdDumpDpNetdevPollThreads(gdb.Command):
    """Dump all poll_thread info added to a specific struct dp_netdev*.
    Usage: ovs_dump_dp_netdev_poll_threads <struct dp_netdev *>
    """
    def __init__(self):
        super(CmdDumpDpNetdevPollThreads, self).__init__(
            "ovs_dump_dp_netdev_poll_threads",
            gdb.COMMAND_DATA)

    @staticmethod
    def display_single_poll_thread(pmd_thread, indent=0):
        indent = " " * indent
        print("{}(struct dp_netdev_pmd_thread *) {}: core_id = {:s}, "
              "numa_id {}".format(indent,
                                  pmd_thread, pmd_thread['core_id'],
                                  pmd_thread['numa_id']))

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        if len(arg_list) != 1:
            print("usage: ovs_dump_dp_netdev_poll_threads "
                  "<struct dp_netdev *>")
            return
        dp_netdev = gdb.parse_and_eval(arg_list[0]).cast(
            gdb.lookup_type('struct dp_netdev').pointer())
        for node in ForEachCMAP(dp_netdev['poll_threads'],
                                "struct dp_netdev_pmd_thread", "node"):
            self.display_single_poll_thread(node)


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
# Implements the GDB "ovs_dump_dp_provider" command
#
class CmdDumpDpProvider(gdb.Command):
    """Dump all registered registered_dpif_class structures.
    Usage: ovs_dump_dp_provider
    """
    def __init__(self):
        super(CmdDumpDpProvider, self).__init__("ovs_dump_dp_provider",
                                                gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        dp_providers = get_global_variable('dpif_classes')
        if dp_providers is None:
            return

        for dp_class in ForEachSHASH(dp_providers,
                                     typeobj="struct registered_dpif_class"):

            print("(struct registered_dpif_class *) {}: "
                  "(struct dpif_class *) 0x{:x} = {{type = {}, ...}}, "
                  "refcount = {}".
                  format(dp_class,
                         long(dp_class['dpif_class']),
                         dp_class['dpif_class']['type'].string(),
                         dp_class['refcount']))


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
        netdev_shash = get_global_variable('netdev_shash')
        if netdev_shash is None:
            return

        for netdev in ForEachSHASH(netdev_shash, "struct netdev"):
            self.display_single_netdev(netdev)


#
# Implements the GDB "ovs_dump_netdev_provider" command
#
class CmdDumpNetdevProvider(gdb.Command):
    """Dump all registered netdev providers.
    Usage: ovs_dump_netdev_provider
    """
    def __init__(self):
        super(CmdDumpNetdevProvider, self).__init__("ovs_dump_netdev_provider",
                                                    gdb.COMMAND_DATA)

    @staticmethod
    def is_class_vport_class(netdev_class):
        netdev_class = netdev_class.cast(
            gdb.lookup_type('struct netdev_class').pointer())

        vport_construct = gdb.lookup_symbol('netdev_vport_construct')[0]

        if netdev_class['construct'] == vport_construct.value():
            return True
        return False

    @staticmethod
    def display_single_netdev_provider(reg_class, indent=0):
        indent = " " * indent
        print("{}(struct netdev_registered_class *) {}: refcnt = {},".
              format(indent, reg_class, reg_class['refcnt']))

        print("{}    (struct netdev_class *) 0x{:x} = {{type = {}, "
              "is_pmd = {}, ...}}, ".
              format(indent, long(reg_class['class']),
                     reg_class['class']['type'].string(),
                     reg_class['class']['is_pmd']))

        if CmdDumpNetdevProvider.is_class_vport_class(reg_class['class']):
            vport = container_of(
                reg_class['class'],
                gdb.lookup_type('struct vport_class').pointer(),
                'netdev_class')

            if vport['dpif_port'] != 0:
                dpif_port = vport['dpif_port'].string()
            else:
                dpif_port = "\"\""

            print("{}    (struct vport_class *) 0x{:x} = "
                  "{{ dpif_port = {}, ... }}".
                  format(indent, long(vport), dpif_port))

    def invoke(self, arg, from_tty):
        netdev_classes = get_global_variable('netdev_classes')
        if netdev_classes is None:
            return

        for reg_class in ForEachCMAP(netdev_classes,
                                     "struct netdev_registered_class",
                                     "cmap_node"):
            self.display_single_netdev_provider(reg_class)


#
# Implements the GDB "ovs_dump_ovs_list" command
#
class CmdDumpOvsList(gdb.Command):
    """Dump all nodes of an ovs_list give
    Usage: ovs_dump_ovs_list <struct ovs_list *> {[<structure>] [<member>] {dump}]}

    For example dump all the none quiescent OvS RCU threads:

      (gdb) ovs_dump_ovs_list &ovsrcu_threads
      (struct ovs_list *) 0x7f2a14000900
      (struct ovs_list *) 0x7f2acc000900
      (struct ovs_list *) 0x7f2a680668d0

    This is not very useful, so please use this with the container_of mode:

      (gdb) ovs_dump_ovs_list &ovsrcu_threads 'struct ovsrcu_perthread' list_node
      (struct ovsrcu_perthread *) 0x7f2a14000900
      (struct ovsrcu_perthread *) 0x7f2acc000900
      (struct ovsrcu_perthread *) 0x7f2a680668d0

    Now you can manually use the print command to show the content, or use the
    dump option to dump the structure for all nodes:

      (gdb) ovs_dump_ovs_list &ovsrcu_threads 'struct ovsrcu_perthread' list_node dump
      (struct ovsrcu_perthread *) 0x7f2a14000900 =
        {list_node = {prev = 0xf48e80 <ovsrcu_threads>, next = 0x7f2acc000900}, mutex...

      (struct ovsrcu_perthread *) 0x7f2acc000900 =
        {list_node = {prev = 0x7f2a14000900, next = 0x7f2a680668d0}, mutex ...

      (struct ovsrcu_perthread *) 0x7f2a680668d0 =
        {list_node = {prev = 0x7f2acc000900, next = 0xf48e80 <ovsrcu_threads>}, ...
    """
    def __init__(self):
        super(CmdDumpOvsList, self).__init__("ovs_dump_ovs_list",
                                             gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        typeobj = None
        member = None
        dump = False

        if len(arg_list) != 1 and len(arg_list) != 3 and len(arg_list) != 4:
            print("usage: ovs_dump_ovs_list <struct ovs_list *> "
                  "{[<structure>] [<member>] {dump}]}")
            return

        header = gdb.parse_and_eval(arg_list[0]).cast(
            gdb.lookup_type('struct ovs_list').pointer())

        if len(arg_list) >= 3:
            typeobj = arg_list[1]
            member = arg_list[2]
            if len(arg_list) == 4 and arg_list[3] == "dump":
                dump = True

        for node in ForEachLIST(header.dereference()):
            if typeobj is None or member is None:
                print("(struct ovs_list *) {}".format(node))
            else:
                print("({} *) {} =".format(
                    typeobj,
                    container_of(node,
                                 gdb.lookup_type(typeobj).pointer(), member)))
                if dump:
                    print("  {}\n".format(container_of(
                        node,
                        gdb.lookup_type(typeobj).pointer(),
                        member).dereference()))


#
# Implements the GDB "ovs_dump_simap" command
#
class CmdDumpSimap(gdb.Command):
    """Dump all nodes of an ovs_list give
    Usage: ovs_dump_ovs_list <struct simap *>
    """

    def __init__(self):
        super(CmdDumpSimap, self).__init__("ovs_dump_simap",
                                           gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)

        if len(arg_list) != 1:
            print("ERROR: Missing argument!\n")
            print(self.__doc__)
            return

        simap = gdb.parse_and_eval(arg_list[0]).cast(
            gdb.lookup_type('struct simap').pointer())

        values = dict()
        max_name_len = 0
        for name, value in ForEachSIMAP(simap.dereference()):
            values[name.string()] = long(value)
            if len(name.string()) > max_name_len:
                max_name_len = len(name.string())

        for name in sorted(values.iterkeys()):
            print("{}: {} / 0x{:x}".format(name.ljust(max_name_len),
                                           values[name], values[name]))


#
# Implements the GDB "ovs_dump_simap" command
#
class CmdDumpUdpifKeys(gdb.Command):
    """Dump all nodes of an ovs_list give
    Usage: ovs_dump_udpif_keys {<udpif_name>|<udpif_address>} {short}

      <udpif_name>    : Full name of the udpif's dpif to dump
      <udpif_address> : Address of the udpif structure to dump. If both the
                        <udpif_name> and <udpif_address> are omitted the
                        available udpif structures are displayed.
      short           : Only dump ukey structure addresses, no content details
    """

    def __init__(self):
        super(CmdDumpUdpifKeys, self).__init__("ovs_dump_udpif_keys",
                                               gdb.COMMAND_DATA)

    def count_all_ukeys(self, udpif):
        count = 0
        for j in range(0, N_UMAPS):
            count += udpif['ukeys'][j]['cmap']['impl']['p']['n']
        return count

    def dump_all_ukeys(self, udpif, indent=0, short=False):
        indent = " " * indent
        for j in range(0, N_UMAPS):
            if udpif['ukeys'][j]['cmap']['impl']['p']['n'] != 0:
                print("{}(struct umap *) {}:".
                      format(indent, udpif['ukeys'][j].address))
                for ukey in ForEachCMAP(udpif['ukeys'][j]['cmap'],
                                        "struct udpif_key", "cmap_node"):

                    base_str = "{}  (struct udpif_key *) {}: ". \
                        format(indent, ukey)
                    if short:
                        print(base_str)
                        continue

                    print("{}key_len = {}, mask_len = {}".
                          format(base_str, ukey['key_len'], ukey['mask_len']))

                    indent_b = " " * len(base_str)
                    if ukey['ufid_present']:
                        print("{}ufid = {}".
                              format(
                                  indent_b, str(uuid.UUID(
                                      "{:08x}{:08x}{:08x}{:08x}".
                                      format(long(ukey['ufid']['u32'][3]),
                                             long(ukey['ufid']['u32'][2]),
                                             long(ukey['ufid']['u32'][1]),
                                             long(ukey['ufid']['u32'][0]))))))

                    print("{}hash = 0x{:8x}, pmd_id = {}".
                          format(indent_b, long(ukey['hash']), ukey['pmd_id']))
                    print("{}state = {}".format(indent_b, ukey['state']))
                    print("{}n_packets = {}, n_bytes = {}".
                          format(indent_b,
                                 ukey['stats']['n_packets'],
                                 ukey['stats']['n_bytes']))
                    print("{}used = {}, tcp_flags = 0x{:04x}".
                          format(indent_b,
                                 ukey['stats']['used'],
                                 long(ukey['stats']['tcp_flags'])))

                    #
                    # TODO: Would like to add support for dumping key, mask
                    #       actions, and xlate_cache
                    #
                    # key = ""
                    # for nlattr in ForEachNL(ukey['key'], ukey['key_len']):
                    #     key += "{}{}".format(
                    #         "" if len(key) == 0 else ", ",
                    #         nlattr['nla_type'].cast(
                    #             gdb.lookup_type('enum ovs_key_attr')))
                    # print("{}key attributes = {}".format(indent_b, key))

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)
        all_udpifs = get_global_variable('all_udpifs')
        if all_udpifs is None:
            return

        udpifs = dict()
        for udpif in ForEachLIST(all_udpifs, "struct udpif", "list_node"):
            udpifs[udpif['dpif']['full_name'].string()] = udpif

            if len(arg_list) == 0:
                print("(struct udpif *) {}: name = {}, total keys = {}".
                      format(udpif, udpif['dpif']['full_name'].string(),
                             self.count_all_ukeys(udpif)))

        if len(arg_list) == 0:
            return

        if arg_list[0] in udpifs:
            udpif = udpifs[arg_list[0]]
        else:
            try:
                udpif = gdb.parse_and_eval(arg_list[0]).cast(
                    gdb.lookup_type('struct udpif').pointer())
            except Exception:
                udpif = None

        if udpif is None:
            print("Can't find provided udpif address!")
            return

        self.dump_all_ukeys(udpif, 0, "short" in arg_list[1:])


#
# Implements the GDB "ovs_show_fdb" command
#
class CmdShowFDB(gdb.Command):
    """Show FDB information
    Usage: ovs_show_fdb {<bridge_name> {dbg} {hash}}

       <bridge_name> : Optional bridge name, if not supplied FDB summary
                       information is displayed for all bridges.
       dbg           : Will show structure address information
       hash          : Will display the forwarding table using the hash
                       table, rather than the rlu list.
    """

    def __init__(self):
        super(CmdShowFDB, self).__init__("ovs_show_fdb",
                                         gdb.COMMAND_DATA)

    @staticmethod
    def __get_port_name_num(mac_entry):
        if mac_entry['mlport'] is not None:
            port = mac_entry['mlport']['port'].cast(
                gdb.lookup_type('struct ofbundle').pointer())

            port_name = port['name'].string()
            port_no = long(container_of(
                port['ports']['next'],
                gdb.lookup_type('struct ofport_dpif').pointer(),
                'bundle_node')['up']['ofp_port'])

            if port_no == 0xfff7:
                port_no = "UNSET"
            elif port_no == 0xfff8:
                port_no = "IN_PORT"
            elif port_no == 0xfff9:
                port_no = "TABLE"
            elif port_no == 0xfffa:
                port_no = "NORMAL"
            elif port_no == 0xfffb:
                port_no = "FLOOD"
            elif port_no == 0xfffc:
                port_no = "ALL"
            elif port_no == 0xfffd:
                port_no = "CONTROLLER"
            elif port_no == 0xfffe:
                port_no = "LOCAL"
            elif port_no == 0xffff:
                port_no = "NONE"
            else:
                port_no = str(port_no)
        else:
            port_name = "-"
            port_no = "?"

        return port_name, port_no

    @staticmethod
    def display_ml_summary(ml, indent=0, dbg=False):
        indent = " " * indent
        if ml is None:
            return

        if dbg:
            print("[(struct mac_learning *) {}]".format(ml))

        print("{}table.n         : {}".format(indent, ml['table']['n']))
        print("{}secret          : 0x{:x}".format(indent, long(ml['secret'])))
        print("{}idle_time       : {}".format(indent, ml['idle_time']))
        print("{}max_entries     : {}".format(indent, ml['max_entries']))
        print("{}ref_count       : {}".format(indent, ml['ref_cnt']['count']))
        print("{}need_revalidate : {}".format(indent, ml['need_revalidate']))
        print("{}ports_by_ptr.n  : {}".format(indent, ml['ports_by_ptr']['n']))
        print("{}ports_by_usage.n: {}".format(indent,
                                              ml['ports_by_usage']['n']))
        print("{}total_learned   : {}".format(indent, ml['total_learned']))
        print("{}total_expired   : {}".format(indent, ml['total_expired']))
        print("{}total_evicted   : {}".format(indent, ml['total_evicted']))
        print("{}total_moved     : {}".format(indent, ml['total_moved']))

    @staticmethod
    def display_mac_entry(mac_entry, indent=0, dbg=False):
        port_name, port_no = CmdShowFDB.__get_port_name_num(mac_entry)

        line = "{}{:16.16}  {:-4}  {}  {:-9}".format(
            indent,
            "{}[{}]".format(port_no, port_name),
            long(mac_entry['vlan']),
            eth_addr_to_string(mac_entry['mac']),
            long(mac_entry['expires']))

        if dbg:
            line += " [(struct mac_entry *) {}]".format(mac_entry)

        print(line)

    @staticmethod
    def display_ml_entries(ml, indent=0, hash=False, dbg=False):
        indent = " " * indent
        if ml is None:
            return

        print("\n{}FDB \"{}\" table:".format(indent,
                                             "lrus" if not hash else "hash"))
        print("{}port               VLAN  MAC                Age out @".
              format(indent))
        print("{}-----------------  ----  -----------------  ---------".
              format(indent))

        mac_entries = 0

        if hash:
            for mac_entry in ForEachHMAP(ml['table'],
                                         "struct mac_entry",
                                         "hmap_node"):
                CmdShowFDB.display_mac_entry(mac_entry, len(indent), dbg)
                mac_entries += 1
        else:
            for mac_entry in ForEachLIST(ml['lrus'],
                                         "struct mac_entry",
                                         "lru_node"):
                CmdShowFDB.display_mac_entry(mac_entry, len(indent), dbg)
                mac_entries += 1

        print("\nTotal MAC entries: {}".format(mac_entries))
        time_now = list(get_time_now())
        time_now[1] = time_now[0] + time_now[1]
        print("\n{}Current time is between {} and {} seconds.\n".
              format(indent, min(time_now[0], time_now[1]),
                     max(time_now[0], time_now[1])))

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)

        all_ofproto_dpifs_by_name = get_global_variable(
            'all_ofproto_dpifs_by_name')
        if all_ofproto_dpifs_by_name is None:
            return

        all_name = dict()
        max_name_len = 0
        for node in ForEachHMAP(all_ofproto_dpifs_by_name,
                                "struct ofproto_dpif",
                                "all_ofproto_dpifs_by_name_node"):

            all_name[node['up']['name'].string()] = node
            if len(node['up']['name'].string()) > max_name_len:
                max_name_len = len(node['up']['name'].string())

        if len(arg_list) == 0:
            for name in sorted(all_name.iterkeys()):
                print("{}: (struct mac_learning *) {}".
                      format(name.ljust(max_name_len),
                             all_name[name]['ml']))

                self.display_ml_summary(all_name[name]['ml'], 4)
        else:
            if not arg_list[0] in all_name:
                print("ERROR: Given bridge name is not known!")
                return

            ml = all_name[arg_list[0]]['ml']
            self.display_ml_summary(ml, 0, "dbg" in arg_list[1:])
            self.display_ml_entries(ml, 0, "hash" in arg_list[1:],
                                    "dbg" in arg_list[1:])


#
# Implements the GDB "ovs_show_fdb" command
#
class CmdShowUpcall(gdb.Command):
    """Show upcall information
    Usage: ovs_show_upcall {dbg}

      dbg  : Will show structure address information
    """

    def __init__(self):
        super(CmdShowUpcall, self).__init__("ovs_show_upcall",
                                            gdb.COMMAND_DATA)

    @staticmethod
    def display_udpif_upcall(udpif, indent=0, dbg=False):
        indent = " " * indent

        enable_ufid = get_global_variable('enable_ufid')
        if enable_ufid is None:
            return

        dbg_str = ""
        if dbg:
            dbg_str = ", ((struct udpif *) {})".format(udpif)

        print("{}{}{}:".format(
            indent, udpif['dpif']['full_name'].string(),
            dbg_str))

        print("{}  flows         : (current {}) (avg {}) (max {}) (limit {})".
              format(indent, udpif['n_flows'], udpif['avg_n_flows'],
                     udpif['max_n_flows'], udpif['flow_limit']))
        print("{}  dump duration : {}ms".
              format(indent, udpif['dump_duration']))
        print("{}  ufid enabled  : {}\n".
              format(indent, enable_ufid &
                     udpif['backer']['rt_support']['ufid']))

        for i in range(0, int(udpif['n_revalidators'])):
            revalidator = udpif['revalidators'][i]

            dbg_str = ""
            if dbg:
                dbg_str = ", ((struct revalidator *) {})".\
                    format(revalidator.address)

            count = 0
            j = i
            while j < N_UMAPS:
                count += udpif['ukeys'][j]['cmap']['impl']['p']['n']
                j += int(udpif['n_revalidators'])

            print("{}  {}: (keys {}){}".
                  format(indent, revalidator['id'], count, dbg_str))

        print("")

    def invoke(self, arg, from_tty):
        arg_list = gdb.string_to_argv(arg)

        all_udpifs = get_global_variable('all_udpifs')
        if all_udpifs is None:
            return

        for udpif in ForEachLIST(all_udpifs, "struct udpif", "list_node"):
            self.display_udpif_upcall(udpif, 0, "dbg" in arg_list)


#
# Initialize all GDB commands
#
CmdDumpBridge()
CmdDumpBridgePorts()
CmdDumpDpNetdev()
CmdDumpDpNetdevPollThreads()
CmdDumpDpNetdevPorts()
CmdDumpDpProvider()
CmdDumpNetdev()
CmdDumpNetdevProvider()
CmdDumpOvsList()
CmdDumpSimap()
CmdDumpUdpifKeys()
CmdShowFDB()
CmdShowUpcall()
