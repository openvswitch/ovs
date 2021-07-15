#!/usr/bin/python3
try:
    from scapy.all import RandMAC, RandIP, PcapWriter, RandIP6, RandShort, fuzz
    from scapy.all import IPv6, Dot1Q, IP, Ether, UDP, TCP
except ModuleNotFoundError as err:
    print(err + ": Scapy")
import sys

path = str(sys.argv[1]) + "/pcap/fuzzy.pcap"
pktdump = PcapWriter(path, append=False, sync=True)

for i in range(0, 2000):

    # Generate random protocol bases, use a fuzz() over the combined packet
    # for full fuzzing.
    eth = Ether(src=RandMAC(), dst=RandMAC())
    vlan = Dot1Q()
    ipv4 = IP(src=RandIP(), dst=RandIP())
    ipv6 = IPv6(src=RandIP6(), dst=RandIP6())
    udp = UDP(dport=RandShort(), sport=RandShort())
    tcp = TCP(dport=RandShort(), sport=RandShort())

    # IPv4 packets with fuzzing
    pktdump.write(fuzz(eth / ipv4 / udp))
    pktdump.write(fuzz(eth / ipv4 / tcp))
    pktdump.write(fuzz(eth / vlan / ipv4 / udp))
    pktdump.write(fuzz(eth / vlan / ipv4 / tcp))

    # IPv6 packets with fuzzing
    pktdump.write(fuzz(eth / ipv6 / udp))
    pktdump.write(fuzz(eth / ipv6 / tcp))
    pktdump.write(fuzz(eth / vlan / ipv6 / udp))
    pktdump.write(fuzz(eth / vlan / ipv6 / tcp))
