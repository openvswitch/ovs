#! /usr/bin/env python

# Copyright (c) 2018 VMware, Inc.
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


# This program can be used send L2-L7 protocol messages using the hex bytes
# of the packet, to test simple protocol scenarios. (e.g. generate simple
# nsh packets to test nsh match fields/actions)
#
# Currently, the script supports sending the packets starting from the
# Ethernet header. As a part of future enchancement, raw ip packet support
# can also be added, and that's why there is "-t"/"--type" option
#


import socket
import sys
from optparse import OptionParser


usage = "usage: %prog [OPTIONS] OUT-INTERFACE HEX-BYTES \n \
         bytes in HEX-BYTES must be separated by space(s)"
parser = OptionParser(usage=usage)
parser.add_option("-t", "--type", type="string", dest="packet_type",
                  help="packet type ('eth' is the default PACKET_TYPE)",
                  default="eth")

(options, args) = parser.parse_args()

# validate the arguments
if len(args) < 2:
    parser.print_help()
    sys.exit(1)

# validate the "-t" or "--type" option
if options.packet_type != "eth":
    parser.error('invalid argument to "-t"/"--type". Allowed value is "eth".')

# store the hex bytes with 0x appended at the beginning
# if not present in the user input and validate the hex bytes
hex_list = []
for a in args[1:]:
    if a[:2] != "0x":
        hex_byte = "0x" + a
    else:
        hex_byte = a
    try:
        temp = int(hex_byte, 0)
    except:
        parser.error("invalid hex byte " + a)

    if temp > 0xff:
        parser.error("hex byte " + a + " cannot be greater than 0xff!")

    hex_list.append(temp)

pkt = "".join(map(chr, hex_list))

try:
    sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
except socket.error as msg:
    print('unable to create socket! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

try:
    sockfd.bind((args[0], 0))
except socket.error as msg:
    print('unable to bind socket! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

try:
    sockfd.send(pkt)
except socket.error as msg:
    print('unable to send packet! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

print('send success!')
sys.exit(0)
