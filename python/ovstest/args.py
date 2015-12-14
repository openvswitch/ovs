# Copyright (c) 2011, 2012 Nicira, Inc.
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
ovsargs provide argument parsing for ovs-test utility
"""

import argparse
import re
import socket
import sys

CONTROL_PORT = 15531
DATA_PORT = 15532


def ip_address(string):
    """Verifies if string is a valid IP address"""
    try:
        socket.inet_aton(string)
    except socket.error:
        raise argparse.ArgumentTypeError("Not a valid IPv4 address")
    return string


def ip_optional_mask(string):
    """
    Verifies if string contains a valid IP address and an optional mask in
    CIDR notation.
    """
    token = string.split("/")
    if len(token) > 2:
        raise argparse.ArgumentTypeError("IP address and netmask must be "
                                         "separated by a single slash")
    elif len(token) == 2:
        try:
            mask = int(token[1])
        except ValueError:
            raise argparse.ArgumentTypeError("Netmask is not a valid integer")
        if mask < 0 or mask > 31:
            raise argparse.ArgumentTypeError("Netmask must be in range 0..31")
    ip_address(token[0])
    return string


def port(string):
    """Convert a string into a TCP/UDP Port (integer)"""
    try:
        port_number = int(string)
        if port_number < 1 or port_number > 65535:
            raise argparse.ArgumentTypeError("Port is out of range")
    except ValueError:
        raise argparse.ArgumentTypeError("Port is not an integer")
    return port_number


def ip_optional_port(string, default_port, ip_callback):
    """Convert a string into IP and Port pair. If port was absent then use
    default_port as the port. The third argument is a callback that verifies
    whether IP address is given in correct format."""
    value = string.split(':')
    if len(value) == 1:
        return (ip_callback(value[0]), default_port)
    elif len(value) == 2:
        return (ip_callback(value[0]), port(value[1]))
    else:
        raise argparse.ArgumentTypeError("IP address from the optional Port "
                                         "must be colon-separated")


def ip_optional_port_port(string, default_port1, default_port2, ip_callback):
    """Convert a string into IP, Port1, Port2 tuple. If any of ports were
     missing, then default ports will be used. The fourth argument is a
     callback that verifies whether IP address is given in the expected
     format."""
    value = string.split(':')
    if len(value) == 1:
        return (ip_callback(value[0]), default_port1, default_port2)
    elif len(value) == 2:
        return (ip_callback(value[0]), port(value[1]), default_port2)
    elif len(value) == 3:
        return (ip_callback(value[0]), port(value[1]), port(value[2]))
    else:
        raise argparse.ArgumentTypeError("Expected IP address and at most "
                                         "two colon-separated ports")


def vlan_tag(string):
    """
    This function verifies whether given string is a correct VLAN tag.
    """
    try:
        value = int(string)
    except ValueError:
        raise argparse.ArgumentTypeError("VLAN tag is not a valid integer")
    if value < 1 or value > 4094:
        raise argparse.ArgumentTypeError("Not a valid VLAN tag. "
                                         "VLAN tag should be in the "
                                         "range 1..4094.")
    return string


def server_endpoint(string):
    """Converts a string OuterIP[:OuterPort],InnerIP[/Mask][:InnerPort]
    into a 4-tuple, where:
    1. First element is OuterIP
    2. Second element is OuterPort (if omitted will use default value 15531)
    3  Third element is InnerIP with optional mask
    4. Fourth element is InnerPort (if omitted will use default value 15532)
    """
    value = string.split(',')
    if len(value) == 2:
        ret1 = ip_optional_port(value[0], CONTROL_PORT, ip_address)
        ret2 = ip_optional_port(value[1], DATA_PORT, ip_optional_mask)
        return (ret1[0], ret1[1], ret2[0], ret2[1])
    else:
        raise argparse.ArgumentTypeError("OuterIP:OuterPort and InnerIP/Mask:"
                                         "InnerPort must be comma separated")


class UniqueServerAction(argparse.Action):
    """
    This custom action class will prevent user from entering multiple ovs-test
    servers with the same OuterIP. If there is an server with 127.0.0.1 outer
    IP address then it will be inserted in the front of the list.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        outer_ips = set()
        endpoints = []
        for server in values:
            try:
                endpoint = server_endpoint(server)
            except argparse.ArgumentTypeError:
                raise argparse.ArgumentError(self, str(sys.exc_info()[1]))
            if endpoint[0] in outer_ips:
                raise argparse.ArgumentError(self, "Duplicate OuterIPs found")
            else:
                outer_ips.add(endpoint[0])
                if endpoint[0] == "127.0.0.1":
                    endpoints.insert(0, endpoint)
                else:
                    endpoints.append(endpoint)
        setattr(namespace, self.dest, endpoints)


def bandwidth(string):
    """Convert a string (given in bits/second with optional magnitude for
    units) into a long (bytes/second)"""
    if re.match("^[1-9][0-9]*[MK]?$", string) is None:
        raise argparse.ArgumentTypeError("Not a valid target bandwidth")
    bwidth = string.replace("M", "000000")
    bwidth = bwidth.replace("K", "000")
    return int(bwidth) / 8  # Convert from bits to bytes


def tunnel_types(string):
    """
    This function converts a string into a list that contains all tunnel types
    that user intended to test.
    """
    return string.split(',')


def l3_endpoint_client(string):
    """
    This function parses command line argument string in
    remoteIP,localInnerIP[/mask][:ControlPort[:TestPort]],remoteInnerIP[:
    ControlPort[:TestPort]] format.
    """
    try:
        remote_ip, me, he = string.split(',')
    except ValueError:
        raise argparse.ArgumentTypeError("All 3 IP addresses must be comma "
                                         "separated.")
    r = (ip_address(remote_ip),
         ip_optional_port_port(me, CONTROL_PORT, DATA_PORT, ip_optional_mask),
         ip_optional_port_port(he, CONTROL_PORT, DATA_PORT, ip_address))
    return r


def l3_endpoint_server(string):
    """
    This function parses a command line argument string in
    remoteIP,localInnerIP[/mask][:ControlPort] format.
    """
    try:
        remote_ip, me = string.split(',')
    except ValueError:
        raise argparse.ArgumentTypeError("Both IP addresses must be comma "
                                         "separated.")
    return (ip_address(remote_ip),
            ip_optional_port(me, CONTROL_PORT, ip_optional_mask))


def ovs_initialize_args():
    """
    Initialize argument parsing for ovs-test utility.
    """
    parser = argparse.ArgumentParser(description='Test connectivity '
                                                'between two Open vSwitches.')

    parser.add_argument('-v', '--version', action='version',
                version='ovs-test (Open vSwitch) @VERSION@')

    parser.add_argument("-b", "--bandwidth", action='store',
                dest="targetBandwidth", default="1M", type=bandwidth,
                help='Target bandwidth for UDP tests in bits/second. Use '
                'postfix M or K to alter unit magnitude.')
    parser.add_argument("-i", "--interval", action='store',
                dest="testInterval", default=5, type=int,
                help='Interval for how long to run each test in seconds.')

    parser.add_argument("-t", "--tunnel-modes", action='store',
                dest="tunnelModes", default=(), type=tunnel_types,
                help='Do L3 tests with the given tunnel modes.')
    parser.add_argument("-l", "--vlan-tag", action='store',
                dest="vlanTag", default=None, type=vlan_tag,
                help='Do VLAN tests and use the given VLAN tag.')
    parser.add_argument("-d", "--direct", action='store_true',
                dest="direct", default=None,
                help='Do direct tests between both ovs-test servers.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--server", action="store", dest="port",
                type=port,
                help='Run in server mode and wait for the client to '
                'connect to this port.')
    group.add_argument('-c', "--client", nargs=2,
                dest="servers", action=UniqueServerAction,
                metavar=("SERVER1", "SERVER2"),
                help='Run in client mode and do tests between these '
                'two ovs-test servers. Each server must be specified in '
                'following format - OuterIP:OuterPort,InnerIP[/mask] '
                ':InnerPort. It is possible to start local instance of '
                'ovs-test server in the client mode by using 127.0.0.1 as '
                'OuterIP.')
    return parser.parse_args()


def l3_initialize_args():
    """
    Initialize argument parsing for ovs-l3ping utility.
    """
    parser = argparse.ArgumentParser(description='Test L3 tunnel '
                        'connectivity between two Open vSwitch instances.')

    parser.add_argument('-v', '--version', action='version',
                version='ovs-l3ping (Open vSwitch) @VERSION@')

    parser.add_argument("-b", "--bandwidth", action='store',
                dest="targetBandwidth", default="1M", type=bandwidth,
                help='Target bandwidth for UDP tests in bits/second. Use '
                'postfix M or K to alter unit magnitude.')
    parser.add_argument("-i", "--interval", action='store',
                dest="testInterval", default=5, type=int,
                help='Interval for how long to run each test in seconds.')

    parser.add_argument("-t", "--tunnel-mode", action='store',
                dest="tunnelMode", required=True,
                help='Do L3 tests with this tunnel type.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--server", action="store", dest="server",
                metavar="TUNNELIP,SERVER",
                type=l3_endpoint_server,
                help='Run in server mode and wait for the client to '
                'connect.')
    group.add_argument('-c', "--client", action="store", dest="client",
                metavar="TUNNELIP,CLIENT,SERVER",
                type=l3_endpoint_client,
                help='Run in client mode and connect to the server.')
    return parser.parse_args()
