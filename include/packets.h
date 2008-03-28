#ifndef PACKETS_H
#define PACKETS_H 1

#include <stdint.h>
#include "util.h"

#define ETH_ADDR_LEN           6

static inline bool eth_addr_is_broadcast(const uint8_t ea[6])
{
    return (ea[0] & ea[1] & ea[2] & ea[3] & ea[4] & ea[5]) == 0xff;
}
static inline bool eth_addr_is_multicast(const uint8_t ea[6])
{
    return ea[0] & 1;
}
static inline bool eth_addr_is_local(const uint8_t ea[6]) 
{
    return ea[0] & 2;
}

#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_VLAN          0x8100

#define ETH_HEADER_LEN 14
#define ETH_PAYLOAD_MIN 46
#define ETH_TOTAL_MIN (ETH_HEADER_LEN + ETH_PAYLOAD_MIN)
#define ETH_TOTAL_MAX (ETH_HEADER_LEN + VLAN_HEADER_LEN + 1500)
struct eth_header {
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
};
BUILD_ASSERT_DECL(ETH_HEADER_LEN == sizeof(struct eth_header));

#define LLC_DSAP_SNAP 0xaa
#define LLC_SSAP_SNAP 0xaa
#define LLC_CNTL_SNAP 3

#define LLC_HEADER_LEN 3
struct llc_header {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_cntl;
};
BUILD_ASSERT_DECL(LLC_HEADER_LEN == sizeof(struct llc_header));

#define SNAP_ORG_ETHERNET "\0\0" /* The compiler adds a null byte, so
                                    sizeof(SNAP_ORG_ETHERNET) == 3. */
#define SNAP_HEADER_LEN 5
struct snap_header {
    uint8_t snap_org[3];
    uint16_t snap_type;
} __attribute__((packed));
BUILD_ASSERT_DECL(SNAP_HEADER_LEN == sizeof(struct snap_header));

#define LLC_SNAP_HEADER_LEN (LLC_HEADER_LEN + SNAP_HEADER_LEN)
struct llc_snap_header {
    struct llc_header llc;
    struct snap_header snap;
};
BUILD_ASSERT_DECL(LLC_SNAP_HEADER_LEN == sizeof(struct llc_snap_header));

#define VLAN_VID 0x0fff

#define VLAN_HEADER_LEN 4
struct vlan_header {
    uint16_t vlan_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t vlan_next_type;
};
BUILD_ASSERT_DECL(VLAN_HEADER_LEN == sizeof(struct vlan_header));

#define VLAN_ETH_HEADER_LEN (ETH_HEADER_LEN + VLAN_HEADER_LEN)
struct vlan_eth_header {
    uint8_t veth_dst[ETH_ADDR_LEN];
    uint8_t veth_src[ETH_ADDR_LEN];
    uint16_t veth_type;         /* Always htons(ETH_TYPE_VLAN). */
    uint16_t veth_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t veth_next_type;
};
BUILD_ASSERT_DECL(VLAN_ETH_HEADER_LEN == sizeof(struct vlan_eth_header));

#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)

#define IP_TYPE_TCP 6
#define IP_TYPE_UDP 17

#define IP_HEADER_LEN 20
struct ip_header {
    uint8_t ip_ihl_ver;
    uint8_t ip_tos;
    uint16_t ip_tot_len;
    uint16_t ip_id;
    uint16_t ip_frag_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    uint32_t ip_src;
    uint32_t ip_dst;
};
BUILD_ASSERT_DECL(IP_HEADER_LEN == sizeof(struct ip_header));

#define UDP_HEADER_LEN 8
struct udp_header {
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_csum;
};
BUILD_ASSERT_DECL(UDP_HEADER_LEN == sizeof(struct udp_header));

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define TCP_FLAGS(tcp_ctl) (htons(tcp_ctl) & 0x003f)
#define TCP_OFFSET(tcp_ctl) (htons(tcp_ctl) >> 12)

#define TCP_HEADER_LEN 20
struct tcp_header {
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_ctl;
    uint16_t tcp_winsz;
    uint16_t tcp_csum;
    uint16_t tcp_urg;
};
BUILD_ASSERT_DECL(TCP_HEADER_LEN == sizeof(struct tcp_header));

#define ARP_HRD_ETHERNET 1
#define ARP_PRO_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_ETH_HEADER_LEN 28
struct arp_eth_header {
    /* Generic members. */
    uint16_t ar_hrd;           /* Hardware type. */
    uint16_t ar_pro;           /* Protocol type. */
    uint8_t ar_hln;            /* Hardware address length. */
    uint8_t ar_pln;            /* Protocol address length. */
    uint16_t ar_op;            /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    uint8_t ar_sha[ETH_ADDR_LEN]; /* Sender hardware address. */
    uint32_t ar_spa;           /* Sender protocol address. */
    uint8_t ar_tha[ETH_ADDR_LEN]; /* Target hardware address. */
    uint32_t ar_tpa;           /* Target protocol address. */
} __attribute__((packed));
BUILD_ASSERT_DECL(ARP_ETH_HEADER_LEN == sizeof(struct arp_eth_header));

#endif /* packets.h */
