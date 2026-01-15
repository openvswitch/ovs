#!/usr/bin/env python3

# Copyright (c) 2018, 2020 VMware, Inc.
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
parser.add_option("-c", "--count", type="int", dest="packet_count",
                  help="number of packets to send (default: 1)",
                  default=1)

(options, args) = parser.parse_args()

# validate the arguments
if len(args) < 2:
    parser.print_help()
    sys.exit(1)

# validate the options
if options.packet_type != "eth":
    parser.error('invalid argument to "-t"/"--type". Allowed value is "eth".')
if options.packet_count < 1:
    parser.error('invalid argument to "-c"/"--count". '
                  'Allowed value must be 1 or higher.')


# Strip '0x' prefixes from hex input, combine into a single string and
# convert to bytes.
hex_str = "".join([a[2:] if a.startswith("0x") else a for a in args[1:]])
pkt = bytes.fromhex(hex_str)

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
    for i in range(options.packet_count):
        sockfd.send(pkt)
except socket.error as msg:
    print('unable to send packet! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

print('send success!')
sys.exit(0)
