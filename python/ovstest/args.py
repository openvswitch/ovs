# Copyright (c) 2011 Nicira Networks
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
import socket
import re


def ip(string):
    """Verifies if string is a valid IP address"""
    try:
        socket.inet_aton(string)
    except socket.error:
        raise argparse.ArgumentTypeError("Not a valid IPv4 address")
    return string


def port(string):
    """Convert a string into a Port (integer)"""
    try:
        port_number = int(string)
        if port_number < 1 or port_number > 65535:
            raise argparse.ArgumentTypeError("Port is out of range")
    except ValueError:
        raise argparse.ArgumentTypeError("Port is not an integer")
    return port_number


def ip_optional_port(string, default_port):
    """Convert a string into IP and Port pair. If port was absent then use
    default_port as the port"""
    value = string.split(':')
    if len(value) == 1:
        return (ip(value[0]), default_port)
    elif len(value) == 2:
        return (ip(value[0]), port(value[1]))
    else:
        raise argparse.ArgumentTypeError("IP address from the optional Port "
                                         "must be colon-separated")



def server_endpoint(string):
    """Converts a string in ControlIP[:ControlPort][,TestIP[:TestPort]] format
    into a 4-tuple, where:
    1. First element is ControlIP
    2. Second element is ControlPort (if omitted will use default value 15531)
    3  Third element is TestIP (if omitted will be the same as ControlIP)
    4. Fourth element is TestPort (if omitted will use default value 15532)"""
    value = string.split(',')
    if len(value) == 1: #  TestIP and TestPort are not present
        ret = ip_optional_port(value[0], 15531)
        return (ret[0], ret[1], ret[0], 15532)
    elif len(value) == 2:
        ret1 = ip_optional_port(value[0], 15531)
        ret2 = ip_optional_port(value[1], 15532)
        return (ret1[0], ret1[1], ret2[0], ret2[1])
    else:
        raise argparse.ArgumentTypeError("ControlIP:ControlPort and TestIP:"
                                         "TestPort must be comma "
                                         "separated")


def bandwidth(string):
    """Convert a string (given in bits/second with optional magnitude for
    units) into a long (bytes/second)"""
    if re.match("^[1-9][0-9]*[MK]?$", string) == None:
        raise argparse.ArgumentTypeError("Not a valid target bandwidth")
    bwidth = string.replace("M", "000000")
    bwidth = bwidth.replace("K", "000")
    return long(bwidth) / 8 #  Convert from bits to bytes


def ovs_initialize_args():
    """Initialize args for ovstest utility"""
    parser = argparse.ArgumentParser(description = 'Test ovs connectivity')
    parser.add_argument('-v', '--version', action = 'version',
                version = 'ovs-test (Open vSwitch) @VERSION@')
    parser.add_argument("-b", "--bandwidth", action = 'store',
                dest = "targetBandwidth", default = "1M", type = bandwidth,
                help = 'target bandwidth for UDP tests in bits/second. Use '
                'postfix M or K to alter unit magnitude.')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument("-s", "--server", action = "store", dest = "port",
                type = port,
                help = 'run in server mode and wait client to connect to this '
                'port')
    group.add_argument('-c', "--client", action = "store", nargs = 2,
                dest = "servers", type = server_endpoint,
                metavar = ("SERVER1", "SERVER2"),
                help = 'run in client mode and do tests between these '
                'two servers. Each server must be specified in following '
                'format - ControlIP[:ControlPort][,TestIP[:TestPort]]. If '
                'TestIP is omitted then ovs-test server will also use the '
                'ControlIP for testing purposes. ControlPort is TCP port '
                'where server will listen for incoming XML/RPC control '
                'connections to schedule tests (by default 15531). TestPort '
                'is port which will be used by server to send test traffic '
                '(by default 15532)')
    return parser.parse_args()
