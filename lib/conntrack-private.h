/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "conntrack.h"
#include "ct-dpif.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"

struct ct_addr {
    union {
        ovs_16aligned_be32 ipv4;
        union ovs_16aligned_in6_addr ipv6;
        ovs_be32 ipv4_aligned;
        struct in6_addr ipv6_aligned;
    };
};

struct ct_endpoint {
    struct ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Changes to this structure need to be reflected in conn_key_hash() */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint8_t nw_proto;
    uint16_t zone;
};

struct conn {
    struct conn_key key;
    struct conn_key rev_key;
    long long expiration;
    struct ovs_list exp_node;
    struct hmap_node node;
    uint32_t mark;
    ovs_u128 label;
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
};

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack_bucket *, struct dp_packet *pkt,
                             long long now);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conn *conn,
                                      struct conntrack_bucket *,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

extern long long ct_timeout_val[];

static inline void
conn_init_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                        enum ct_timeout tm, long long now)
{
    conn->expiration = now + ct_timeout_val[tm];
    ovs_list_push_back(&ctb->exp_lists[tm], &conn->exp_node);
}

static inline void
conn_update_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                       enum ct_timeout tm, long long now)
{
    ovs_list_remove(&conn->exp_node);
    conn_init_expiration(ctb, conn, tm, now);
}

#endif /* conntrack-private.h */
