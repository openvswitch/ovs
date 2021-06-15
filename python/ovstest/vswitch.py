# Copyright (c) 2012 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
vswitch module allows its callers to interact with OVS DB.
"""
from . import util


def ovs_vsctl_add_bridge(bridge):
    """
    This function creates an OVS bridge.
    """
    ret, _out, _err = util.start_process(["ovs-vsctl", "add-br", bridge])
    return ret


def ovs_vsctl_del_bridge(bridge):
    """
    This function deletes the OVS bridge.
    """
    ret, _out, _err = util.start_process(["ovs-vsctl", "del-br", bridge])
    return ret


def ovs_vsctl_del_pbridge(bridge, iface):
    """
    This function deletes the OVS bridge and assigns the bridge IP address
    back to the iface.
    """
    (ip_addr, mask) = util.interface_get_ip(bridge)
    util.interface_assign_ip(iface, ip_addr, mask)
    util.interface_up(iface)
    util.move_routes(bridge, iface)
    return ovs_vsctl_del_bridge(bridge)


def ovs_vsctl_is_ovs_bridge(bridge):
    """
    This function verifies whether given port is an OVS bridge. If it is an
    OVS bridge then it will return True.
    """
    ret, _out, _err = util.start_process(["ovs-vsctl", "br-exists", bridge])
    return ret == 0


def ovs_vsctl_add_port_to_bridge(bridge, iface):
    """
    This function adds given interface to the bridge.
    """
    ret, _out, _err = util.start_process(["ovs-vsctl", "add-port", bridge,
                                          iface])
    return ret


def ovs_vsctl_del_port_from_bridge(port):
    """
    This function removes given port from a OVS bridge.
    """
    ret, _out, _err = util.start_process(["ovs-vsctl", "del-port", port])
    return ret


def ovs_vsctl_set(table, record, column, key, value):
    """
    This function allows to alter the OVS database. If column is a map, then
    caller should also set the key, otherwise the key should be left as an
    empty string.
    """
    if key is None:
        index = column
    else:
        index = "%s:%s" % (column, key)
    index_value = "%s=%s" % (index, value)
    ret, _out, _err = util.start_process(["ovs-vsctl", "set", table, record,
                                          index_value])
    return ret


def ovs_get_physical_interface(bridge):
    """
    This function tries to figure out which is the physical interface that
    belongs to the bridge. If there are multiple physical interfaces assigned
    to this bridge then it will return the first match.
    """
    ret, out, _err = util.start_process(["ovs-vsctl", "list-ifaces", bridge])

    if ret == 0:
        ifaces = out.splitlines()
        for iface in ifaces:
            ret, out, _err = util.start_process(["ovs-vsctl", "get",
                                                 "Interface", iface, "type"])
            if ret == 0:
                if ('""' in out) or ('system' in out):
                    return iface  # this should be the physical interface
    return None
