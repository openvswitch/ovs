#ifndef FLOW_H
#define FLOW_H 1

#include <stdint.h>
#include "util.h"

struct buffer;

/* Identification data for a flow.
   All fields are in network byte order.
   In decreasing order by size, so that flow structures can be hashed or
   compared bytewise. */
struct flow {
    uint32_t nw_src;            /* IP source address. */
    uint32_t nw_dst;            /* IP destination address. */
    uint16_t in_port;           /* Input switch port. */
    uint16_t dl_vlan;           /* Input VLAN. */
    uint16_t dl_type;           /* Ethernet frame type. */
    uint16_t tp_src;            /* TCP/UDP source port. */
    uint16_t tp_dst;            /* TCP/UDP destination port. */
    uint8_t dl_src[6];          /* Ethernet source address. */
    uint8_t dl_dst[6];          /* Ethernet destination address. */
    uint8_t nw_proto;           /* IP protocol. */
    uint8_t reserved;           /* One byte of padding. */
};
BUILD_ASSERT_DECL(sizeof (struct flow) == 32);

void flow_extract(const struct buffer *, uint16_t in_port, struct flow *);
void flow_print(FILE *, const struct flow *);
int flow_compare(const struct flow *, const struct flow *);
unsigned long int flow_hash(const struct flow *, uint32_t basis);

#endif /* flow.h */
