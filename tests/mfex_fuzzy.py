#!/usr/bin/python3

import sys
import warnings

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
    message=r"(blowfish|cast5)",
)

# flake8: noqa: E402
from scapy.all import RandMAC, RandIP, PcapWriter, RandIP6, RandShort, fuzz
from scapy.all import IPv6, Dot1Q, IP, Ether, UDP, TCP, random

# Path for the pcap file location.
path = str(sys.argv[1])
# The number of packets generated will be size * 8.
size = int(sys.argv[2])
# Traffic option is used to choose between fuzzy or simple packet type.
if len(sys.argv) > 3:
    traffic_opt = str(sys.argv[3])
else:
    traffic_opt = ""

pktdump = PcapWriter(path, append=False, sync=True)

pkt = []

for i in range(0, size):
    if traffic_opt == "fuzzy":

        eth = Ether(src=RandMAC(), dst=RandMAC())
        vlan = Dot1Q()
        udp = UDP(dport=RandShort(), sport=RandShort())
        ipv4 = IP(src=RandIP(), dst=RandIP(), len=random.randint(0, 100))
        ipv6 = IPv6(src=RandIP6(), dst=RandIP6(), plen=random.randint(0, 100))
        tcp = TCP(dport=RandShort(), sport=RandShort(), flags='S',
                  dataofs=random.randint(0, 15))

        # IPv4 packets with fuzzing
        pkt.append(fuzz(eth / ipv4 / udp))
        pkt.append(fuzz(eth / ipv4 / tcp))
        pkt.append(fuzz(eth / vlan / ipv4 / udp))
        pkt.append(fuzz(eth / vlan / ipv4 / tcp))

        # IPv6 packets with fuzzing
        pkt.append(fuzz(eth / ipv6 / udp))
        pkt.append(fuzz(eth / ipv6 / tcp))
        pkt.append(fuzz(eth / vlan / ipv6 / udp))
        pkt.append(fuzz(eth / vlan / ipv6 / tcp))

    else:
        mac_addr_src = "52:54:00:FF:FF:{:02X}".format(i % 0xff)
        mac_addr_dst = "80:FF:FF:FF:FF:{:02X}".format(i % 0xff)
        src_port = 200 + (i % 20)
        dst_port = 1000 + (i % 20)
        eth = Ether(src=mac_addr_src, dst=mac_addr_dst)
        vlan = Dot1Q(vlan=(i % 10))
        udp = UDP(dport=src_port, sport=dst_port)
        # IPv4 address range limits to 255 and IPv6 limit to 65535
        ipv4_addr_src = "192.168.150." + str((i % 255))
        ipv4_addr_dst = "200.100.198." + str((i % 255))
        ipv6_addr_src = "2001:0db8:85a3:0000:0000:8a2e:0370:{:04x}" \
                        .format(i % 0xffff)
        ipv6_addr_dst = "3021:ffff:85a3:ffff:0000:8a2e:0480:{:04x}" \
                        .format(i % 0xffff)
        ipv4 = IP(src=ipv4_addr_src, dst=ipv4_addr_dst)
        ipv6 = IPv6(src=ipv6_addr_src, dst=ipv6_addr_dst)
        tcp = TCP(dport=src_port, sport=dst_port, flags='S')

        # IPv4 packets
        pkt.append(eth / ipv4 / udp)
        pkt.append(eth / ipv4 / tcp)
        pkt.append(eth / vlan / ipv4 / udp)
        pkt.append(eth / vlan / ipv4 / tcp)

        # IPv6 packets
        pkt.append(eth / ipv6 / udp)
        pkt.append(eth / ipv6 / tcp)
        pkt.append(eth / vlan / ipv6 / udp)
        pkt.append(eth / vlan / ipv6 / tcp)

pktdump.write(pkt)
