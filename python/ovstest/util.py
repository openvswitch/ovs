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
util module contains some helper function
"""
import array
import exceptions
import fcntl
import os
import select
import socket
import struct
import signal
import subprocess
import re
import xmlrpclib


def str_ip(ip_address):
    """
    Converts an IP address from binary format to a string.
    """
    (x1, x2, x3, x4) = struct.unpack("BBBB", ip_address)
    return ("%u.%u.%u.%u") % (x1, x2, x3, x4)


def get_interface_mtu(iface):
    """
    Returns MTU of the given interface.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    indata = iface + ('\0' * (32 - len(iface)))
    try:
        outdata = fcntl.ioctl(s.fileno(), 0x8921, indata) #  socket.SIOCGIFMTU
        mtu = struct.unpack("16si12x", outdata)[1]
    except:
        return 0

    return mtu


def get_interface(address):
    """
    Finds first interface that has given address
    """
    bytes = 256 * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912, # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()

    for i in range(0, outbytes, 40):
        name = namestr[i:i + 16].split('\0', 1)[0]
        if address == str_ip(namestr[i + 20:i + 24]):
            return name
    return None  # did not find interface we were looking for


def uname():
    os_info = os.uname()
    return os_info[2]  # return only the kernel version number


def start_process(args):
    try:
        p = subprocess.Popen(args,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE)
        out, err = p.communicate()
        return (p.returncode, out, err)
    except exceptions.OSError:
        return (-1, None, None)


def get_driver(iface):
    ret, out, _err = start_process(["ethtool", "-i", iface])
    if ret == 0:
        lines = out.splitlines()
        driver = "%s(%s)" % (lines[0], lines[1])  # driver name + version
    else:
        driver = None
    return driver


def interface_up(iface):
    """
    This function brings given iface up.
    """
    ret, _out, _err = start_process(["ifconfig", iface, "up"])
    return ret


def interface_assign_ip(iface, ip_addr, mask):
    """
    This function allows to assign IP address to an interface. If mask is an
    empty string then ifconfig will decide what kind of mask to use. The
    caller can also specify the mask by using CIDR notation in ip argument by
    leaving the mask argument as an empty string. In case of success this
    function returns 0.
    """
    args = ["ifconfig", iface, ip_addr]
    if mask is not None:
        args.append("netmask")
        args.append(mask)
    ret, _out, _err = start_process(args)
    return ret


def interface_get_ip(iface):
    """
    This function returns tuple - ip and mask that was assigned to the
    interface.
    """
    args = ["ifconfig", iface]
    ret, out, _err = start_process(args)

    if ret == 0:
        ip = re.search(r'inet addr:(\S+)', out)
        mask = re.search(r'Mask:(\S+)', out)
        if ip is not None and mask is not None:
            return (ip.group(1), mask.group(1))
    else:
        return ret


def move_routes(iface1, iface2):
    """
    This function moves routes from iface1 to iface2.
    """
    args = ["ip", "route", "show", "dev", iface1]
    ret, out, _err = start_process(args)
    if ret == 0:
        for route in out.splitlines():
            args = ["ip", "route", "replace", "dev", iface2] + route.split()
            start_process(args)


def get_interface_from_routing_decision(ip):
    """
    This function returns the interface through which the given ip address
    is reachable.
    """
    args = ["ip", "route", "get", ip]
    ret, out, _err = start_process(args)
    if ret == 0:
        iface = re.search(r'dev (\S+)', out)
        if iface:
            return iface.group(1)
    return None


def rpc_client(ip, port):
    return xmlrpclib.Server("http://%s:%u/" % (ip, port), allow_none=True)


def sigint_intercept():
    """
    Intercept SIGINT from child (the local ovs-test server process).
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def start_local_server(port):
    """
    This function spawns an ovs-test server that listens on specified port
    and blocks till the spawned ovs-test server is ready to accept XML RPC
    connections.
    """
    p = subprocess.Popen(["ovs-test", "-s", str(port)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         preexec_fn=sigint_intercept)
    fcntl.fcntl( p.stdout.fileno(),fcntl.F_SETFL,
        fcntl.fcntl(p.stdout.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)

    while p.poll() is None:
        fd = select.select([p.stdout.fileno()], [], [])[0]
        if fd:
            out = p.stdout.readline()
            if out.startswith("Starting RPC server"):
                break
    if p.poll() is not None:
        raise RuntimeError("Couldn't start local instance of ovs-test server")
    return p


def get_datagram_sizes(mtu1, mtu2):
    """
    This function calculates all the "interesting" datagram sizes so that
    we test both - receive and send side with different packets sizes.
    """
    s1 = set([8, mtu1 - 100, mtu1 - 28, mtu1])
    s2 = set([8, mtu2 - 100, mtu2 - 28, mtu2])
    return sorted(s1.union(s2))


def ip_from_cidr(string):
    """
    This function removes the netmask (if present) from the given string and
    returns the IP address.
    """
    token = string.split("/")
    return token[0]


def bandwidth_to_string(bwidth):
    """Convert bandwidth from long to string and add units."""
    bwidth = bwidth * 8  # Convert back to bits/second
    if bwidth >= 10000000:
        return str(int(bwidth / 1000000)) + "Mbps"
    elif bwidth > 10000:
        return str(int(bwidth / 1000)) + "Kbps"
    else:
        return str(int(bwidth)) + "bps"
