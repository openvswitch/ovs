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
util module contains some helper function
"""
import socket, struct, fcntl, array, os, subprocess, exceptions

def str_ip(ip):
    (x1, x2, x3, x4) = struct.unpack("BBBB", ip)
    return ("%u.%u.%u.%u") % (x1, x2, x3, x4)

def get_interface_mtu(iface):
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
    return "" #  did not find interface we were looking for

def uname():
    os_info = os.uname()
    return os_info[2] #return only the kernel version number

def get_driver(iface):
    try:
        p = subprocess.Popen(
            ["ethtool", "-i", iface],
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode == 0:
            lines = out.split("\n")
            driver = "%s(%s)" % (lines[0], lines[1]) #driver name + version
        else:
            driver = "no support for ethtool"
    except exceptions.OSError:
        driver = ""
    return driver
