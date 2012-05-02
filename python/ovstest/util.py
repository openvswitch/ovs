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
import socket
import struct
import subprocess
import re


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
