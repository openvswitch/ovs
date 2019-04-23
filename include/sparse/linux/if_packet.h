#ifndef FIX_LINUX_IF_PACKET_H
#define FIX_LINUX_IF_PACKET_H

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#include_next <linux/if_packet.h>

/* Fix endianness of 'spkt_protocol' and 'sll_protocol' members. */

#define sockaddr_pkt rpl_sockaddr_pkt
struct sockaddr_pkt {
        unsigned short spkt_family;
        unsigned char spkt_device[14];
        ovs_be16 spkt_protocol;
};

#define sockaddr_ll rpl_sockaddr_ll
struct sockaddr_ll {
        unsigned short  sll_family;
        ovs_be16        sll_protocol;
        int             sll_ifindex;
        unsigned short  sll_hatype;
        unsigned char   sll_pkttype;
        unsigned char   sll_halen;
        unsigned char   sll_addr[8];
};

#endif
