#! /usr/bin/env python3

# Copyright (c) 2009, 2010, 2011, 2012, 2015, 2017 Nicira, Inc.
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

import socket
import struct


def pack_ethaddr(ea):
    octets = ea.split(':')
    assert len(octets) == 6
    return b''.join([struct.pack('B', int(octet, 16)) for octet in octets])


def output(attrs):
    # Compose flow.

    flow = {}
    flow['DL_SRC'] = "00:02:e3:0f:80:a4"
    flow['DL_DST'] = "00:1a:92:40:ac:05"
    flow['NW_PROTO'] = 0
    flow['NW_TOS'] = 0
    flow['NW_SRC'] = '0.0.0.0'
    flow['NW_DST'] = '0.0.0.0'
    flow['TP_SRC'] = 0
    flow['TP_DST'] = 0
    if 'DL_VLAN' in attrs:
        flow['DL_VLAN'] = {'none': 0xffff,
                           'zero': 0,
                           'nonzero': 0x0123}[attrs['DL_VLAN']]
    else:
        flow['DL_VLAN'] = 0xffff  # OFP_VLAN_NONE
    if attrs['DL_HEADER'] == '802.2':
        flow['DL_TYPE'] = 0x5ff  # OFP_DL_TYPE_NOT_ETH_TYPE
    elif attrs['DL_TYPE'] == 'ip':
        flow['DL_TYPE'] = 0x0800  # ETH_TYPE_IP
        flow['NW_SRC'] = '10.0.2.15'
        flow['NW_DST'] = '192.168.1.20'
        flow['NW_TOS'] = 44
        if attrs['TP_PROTO'] == 'other':
            flow['NW_PROTO'] = 42
        elif attrs['TP_PROTO'] in ('TCP', 'TCP+options'):
            flow['NW_PROTO'] = 6  # IPPROTO_TCP
            flow['TP_SRC'] = 6667
            flow['TP_DST'] = 9998
        elif attrs['TP_PROTO'] == 'UDP':
            flow['NW_PROTO'] = 17  # IPPROTO_UDP
            flow['TP_SRC'] = 1112
            flow['TP_DST'] = 2223
        elif attrs['TP_PROTO'] == 'ICMP':
            flow['NW_PROTO'] = 1  # IPPROTO_ICMP
            flow['TP_SRC'] = 8    # echo request
            flow['TP_DST'] = 0    # code
        else:
            assert False
        if attrs['IP_FRAGMENT'] not in ('no', 'first'):
            flow['TP_SRC'] = flow['TP_DST'] = 0
    elif attrs['DL_TYPE'] == 'non-ip':
        flow['DL_TYPE'] = 0x5678
    else:
        assert False

    # Compose packet
    packet = b''
    wildcards = 1 << 5 | 1 << 6 | 1 << 7 | 32 << 8 | 32 << 14 | 1 << 21

    packet += pack_ethaddr(flow['DL_DST'])
    packet += pack_ethaddr(flow['DL_SRC'])
    if flow['DL_VLAN'] != 0xffff:
        packet += struct.pack('>HH', 0x8100, flow['DL_VLAN'])
    len_ofs = len(packet)
    if attrs['DL_HEADER'].startswith('802.2'):
        packet += struct.pack('>H', 0)
    if attrs['DL_HEADER'] == '802.2':
        packet += struct.pack('BBB', 0x42, 0x42, 0x03)  # LLC for 802.1D STP
    else:
        if attrs['DL_HEADER'] == '802.2+SNAP':
            packet += struct.pack('BBB', 0xaa, 0xaa, 0x03)  # LLC for SNAP
            packet += struct.pack('BBB', 0, 0, 0)           # SNAP OUI
        packet += struct.pack('>H', flow['DL_TYPE'])
        if attrs['DL_TYPE'] == 'ip':
            ip = struct.pack('>BBHHHBBHLL',
                             (4 << 4) | 5,      # version, hdrlen
                             flow['NW_TOS'],    # type of service
                             0,                 # total length, filled in later
                             65432,             # id
                             0,                 # frag offset
                             64,                # ttl
                             flow['NW_PROTO'],  # protocol
                             0,                 # checksum
                             0x0a00020f,        # source
                             0xc0a80114)        # dest
            wildcards &= ~(1 << 5 | 63 << 8 | 63 << 14 | 1 << 21)
            if attrs['IP_OPTIONS'] == 'yes':
                ip = struct.pack('B', (4 << 4) | 8) + ip[1:]
                ip += struct.pack('>BBHHHBBBx',
                                  130,       # type
                                  11,        # length
                                  0x6bc5,    # top secret
                                  0xabcd,
                                  0x1234,
                                  1,
                                  2,
                                  3)
            if attrs['IP_FRAGMENT'] != 'no':
                frag_map = {'first': 0x2000,   # more frags, ofs 0
                            'middle': 0x2111,  # more frags, ofs 0x888
                            'last': 0x0222}    # last frag, ofs 0x1110
                ip = (ip[:6]
                      + struct.pack('>H', frag_map[attrs['IP_FRAGMENT']])
                      + ip[8:])
            if attrs['IP_FRAGMENT'] in ('no', 'first'):
                if attrs['TP_PROTO'].startswith('TCP'):
                    tcp = struct.pack('>HHLLHHHH',
                                      flow['TP_SRC'],  # source port
                                      flow['TP_DST'],  # dest port
                                      87123455,        # seqno
                                      712378912,       # ackno
                                      (5 << 12) | 0x02 | 0x10,
                                           # hdrlen, SYN, ACK
                                      5823,   # window size
                                      18923,  # checksum
                                      12893)  # urgent pointer
                    if attrs['TP_PROTO'] == 'TCP+options':
                        tcp = (tcp[:12]
                               + struct.pack('H', (6 << 12) | 0x02 | 0x10)
                               + tcp[14:])
                        tcp += struct.pack('>BBH', 2, 4, 1975)  # MSS option
                    tcp += b'payload'
                    ip += tcp
                    wildcards &= ~(1 << 6 | 1 << 7)
                elif attrs['TP_PROTO'] == 'UDP':
                    udp_len = 15
                    udp = struct.pack('>HHHH',
                                      flow['TP_SRC'],
                                      flow['TP_DST'],
                                      udp_len, 0)
                    while len(udp) < udp_len:
                        udp += struct.pack('B', udp_len)
                    ip += udp
                    wildcards &= ~(1 << 6 | 1 << 7)
                elif attrs['TP_PROTO'] == 'ICMP':
                    ip += struct.pack('>BBHHH',
                                      8,        # echo request
                                      0,        # code
                                      0,        # checksum
                                      736,      # identifier
                                      931)      # sequence number
                    wildcards &= ~(1 << 6 | 1 << 7)
                elif attrs['TP_PROTO'] == 'other':
                    ip += b'other header'
                else:
                    assert False
            ip = ip[:2] + struct.pack('>H', len(ip)) + ip[4:]
            packet += ip
    if attrs['DL_HEADER'].startswith('802.2'):
        packet_len = len(packet)
        if flow['DL_VLAN'] != 0xffff:
            packet_len -= 4
        packet = (packet[:len_ofs]
                  + struct.pack('>H', packet_len)
                  + packet[len_ofs + 2:])

    print(' '.join(['%s=%s' for k, v in attrs.items()]))
    print(' '.join(['%s=%s' for k, v in flow.items()]))
    print()

    flows.write(struct.pack('>LH',
                            wildcards,  # wildcards
                            1))         # in_port
    flows.write(pack_ethaddr(flow['DL_SRC']))
    flows.write(pack_ethaddr(flow['DL_DST']))
    flows.write(struct.pack('>HBxHBBxx',
                            flow['DL_VLAN'],
                            0,  # DL_VLAN_PCP
                            flow['DL_TYPE'],
                            flow['NW_TOS'],
                            flow['NW_PROTO']))
    flows.write(socket.inet_aton(flow['NW_SRC']))
    flows.write(socket.inet_aton(flow['NW_DST']))
    flows.write(struct.pack('>HH', flow['TP_SRC'], flow['TP_DST']))

    packets.write(struct.pack('>LLLL',
                              0,                # timestamp seconds
                              0,                # timestamp microseconds
                              len(packet),      # bytes saved
                              len(packet)))     # total length
    packets.write(packet)


flows = open('flows', 'wb')
packets = open('pcap', 'wb')

# Print pcap file header.
packets.write(struct.pack('>LHHLLLL',
                          0xa1b2c3d4,  # magic number
                          2,           # major version
                          4,           # minor version
                          0,           # time zone offset
                          0,           # time stamp accuracy
                          1518,        # snaplen
                          1))          # Ethernet

output({'DL_HEADER': '802.2'})

for dl_header in ('802.2+SNAP', 'Ethernet'):
    a = {'DL_HEADER': dl_header}
    for dl_vlan in ('none', 'zero', 'nonzero'):
        b = a.copy()
        b['DL_VLAN'] = dl_vlan

        # Non-IP case.
        c = b.copy()
        c['DL_TYPE'] = 'non-ip'
        output(c)

        for ip_options in ('no', 'yes'):
            c = b.copy()
            c['DL_TYPE'] = 'ip'
            c['IP_OPTIONS'] = ip_options
            for ip_fragment in ('no', 'first', 'middle', 'last'):
                d = c.copy()
                d['IP_FRAGMENT'] = ip_fragment
                for tp_proto in ('TCP', 'TCP+options', 'UDP', 'ICMP', 'other'):
                    e = d.copy()
                    e['TP_PROTO'] = tp_proto
                    output(e)
