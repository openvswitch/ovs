/* Generated automatically from <include/odp-netlink.h> -- do not modify! */
#ifndef ODP_NETLINK_MACROS_H
#define ODP_NETLINK_MACROS_H


#define OVS_KEY_ETHERNET_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_ethernet, eth_src), sizeof(struct eth_addr)}, \
    {offsetof(struct ovs_key_ethernet, eth_dst), sizeof(struct eth_addr)}, \
    {0, 0}}


#define OVS_KEY_IPV4_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_ipv4, ipv4_src), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_ipv4, ipv4_dst), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_ipv4, ipv4_proto), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv4, ipv4_tos), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv4, ipv4_ttl), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv4, ipv4_frag), sizeof(uint8_t)}, \
    {0, 0}}


#define OVS_KEY_IPV6_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_ipv6, ipv6_src), sizeof(struct in6_addr)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_dst), sizeof(struct in6_addr)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_label), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_proto), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_tclass), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_hlimit), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_ipv6, ipv6_frag), sizeof(uint8_t)}, \
    {0, 0}}


#define OVS_KEY_TCP_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_tcp, tcp_src), sizeof(ovs_be16)}, \
    {offsetof(struct ovs_key_tcp, tcp_dst), sizeof(ovs_be16)}, \
    {0, 0}}


#define OVS_KEY_UDP_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_udp, udp_src), sizeof(ovs_be16)}, \
    {offsetof(struct ovs_key_udp, udp_dst), sizeof(ovs_be16)}, \
    {0, 0}}


#define OVS_KEY_SCTP_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_sctp, sctp_src), sizeof(ovs_be16)}, \
    {offsetof(struct ovs_key_sctp, sctp_dst), sizeof(ovs_be16)}, \
    {0, 0}}


#define OVS_KEY_ICMP_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_icmp, icmp_type), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_icmp, icmp_code), sizeof(uint8_t)}, \
    {0, 0}}


#define OVS_KEY_ICMPV6_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_icmpv6, icmpv6_type), sizeof(uint8_t)}, \
    {offsetof(struct ovs_key_icmpv6, icmpv6_code), sizeof(uint8_t)}, \
    {0, 0}}


#define OVS_KEY_ARP_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_arp, arp_sip), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_arp, arp_tip), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_arp, arp_op), sizeof(ovs_be16)}, \
    {offsetof(struct ovs_key_arp, arp_sha), sizeof(struct eth_addr)}, \
    {offsetof(struct ovs_key_arp, arp_tha), sizeof(struct eth_addr)}, \
    {0, 0}}


#define OVS_KEY_ND_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_nd, nd_target), sizeof(struct in6_addr)}, \
    {offsetof(struct ovs_key_nd, nd_sll), sizeof(struct eth_addr)}, \
    {offsetof(struct ovs_key_nd, nd_tll), sizeof(struct eth_addr)}, \
    {0, 0}}


#define OVS_KEY_ND_EXTENSIONS_OFFSETOF_SIZEOF_ARR { \
    {offsetof(struct ovs_key_nd_extensions, nd_reserved), sizeof(ovs_be32)}, \
    {offsetof(struct ovs_key_nd_extensions, nd_options_type), sizeof(uint8_t)}, \
    {0, 0}}



#endif
