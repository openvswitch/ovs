/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef CT_DPIF_H
#define CT_DPIF_H

#include "openvswitch/types.h"
#include "packets.h"

union ct_dpif_inet_addr {
    ovs_be32 ip;
    ovs_be32 ip6[4];
    struct in_addr in;
    struct in6_addr in6;
};

struct ct_dpif_tuple {
    uint16_t l3_type; /* Address family. */
    uint8_t  ip_proto;
    union ct_dpif_inet_addr src;
    union ct_dpif_inet_addr dst;
    union {
        ovs_be16 src_port;
        ovs_be16 icmp_id;
    };
    union {
        ovs_be16 dst_port;
        struct {
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};
BUILD_ASSERT_DECL(sizeof(struct ct_dpif_tuple) % 8 == 0);

struct ct_dpif_counters {
    uint64_t packets;
    uint64_t bytes;
};

/* Nanoseconds from January 1, 1970 */
struct ct_dpif_timestamp {
    /* When the entry was created */
    uint64_t start;
    /* When the entry was deleted */
    uint64_t stop;
};

#define CT_DPIF_TCP_STATES \
    CT_DPIF_TCP_STATE(CLOSED) \
    CT_DPIF_TCP_STATE(LISTEN) \
    CT_DPIF_TCP_STATE(SYN_SENT) \
    CT_DPIF_TCP_STATE(SYN_RECV) \
    CT_DPIF_TCP_STATE(ESTABLISHED) \
    CT_DPIF_TCP_STATE(CLOSE_WAIT) \
    CT_DPIF_TCP_STATE(FIN_WAIT_1) \
    CT_DPIF_TCP_STATE(CLOSING) \
    CT_DPIF_TCP_STATE(LAST_ACK) \
    CT_DPIF_TCP_STATE(FIN_WAIT_2) \
    CT_DPIF_TCP_STATE(TIME_WAIT) \
    CT_DPIF_TCP_STATE(MAX_NUM)

enum ct_dpif_tcp_state {
#define CT_DPIF_TCP_STATE(STATE) CT_DPIF_TCPS_##STATE,
    CT_DPIF_TCP_STATES
#undef CT_DPIF_TCP_STATE
};

extern const char *ct_dpif_tcp_state_string[];

#define CT_DPIF_TCP_FLAGS \
    CT_DPIF_TCP_FLAG(WINDOW_SCALE) \
    CT_DPIF_TCP_FLAG(SACK_PERM) \
    CT_DPIF_TCP_FLAG(CLOSE_INIT) \
    CT_DPIF_TCP_FLAG(BE_LIBERAL) \
    CT_DPIF_TCP_FLAG(DATA_UNACKNOWLEDGED) \
    CT_DPIF_TCP_FLAG(MAXACK_SET) \

enum ct_dpif_tcp_flags_count_ {
#define CT_DPIF_TCP_FLAG(FLAG) FLAG##_COUNT_,
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_TCP_FLAG
};

enum ct_dpif_tcp_flags {
#define CT_DPIF_TCP_FLAG(FLAG) CT_DPIF_TCPF_##FLAG = (1 << FLAG##_COUNT_),
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_TCP_FLAG
};

struct ct_dpif_protoinfo {
    uint16_t proto; /* IPPROTO_* */
    union {
        struct {
            uint8_t state_orig;
            uint8_t state_reply;
            uint8_t wscale_orig;
            uint8_t wscale_reply;
            uint8_t flags_orig;
            uint8_t flags_reply;
        } tcp;
    };
};

struct ct_dpif_helper {
    char *name;
};

#define CT_DPIF_STATUS_FLAGS \
    CT_DPIF_STATUS_FLAG(EXPECTED) \
    CT_DPIF_STATUS_FLAG(SEEN_REPLY) \
    CT_DPIF_STATUS_FLAG(ASSURED) \
    CT_DPIF_STATUS_FLAG(CONFIRMED) \
    CT_DPIF_STATUS_FLAG(SRC_NAT) \
    CT_DPIF_STATUS_FLAG(DST_NAT) \
    CT_DPIF_STATUS_FLAG(SEQ_ADJUST) \
    CT_DPIF_STATUS_FLAG(SRC_NAT_DONE) \
    CT_DPIF_STATUS_FLAG(DST_NAT_DONE) \
    CT_DPIF_STATUS_FLAG(DYING) \
    CT_DPIF_STATUS_FLAG(FIXED_TIMEOUT) \
    CT_DPIF_STATUS_FLAG(TEMPLATE) \
    CT_DPIF_STATUS_FLAG(UNTRACKED) \

enum ct_dpif_status_flags_count_ {
#define CT_DPIF_STATUS_FLAG(FLAG) FLAG##_COUNT_,
    CT_DPIF_STATUS_FLAGS
#undef CT_DPIF_STATUS_FLAG
};

enum ct_dpif_status_flags {
#define CT_DPIF_STATUS_FLAG(FLAG) CT_DPIF_STATUS_##FLAG = (1 << FLAG##_COUNT_),
    CT_DPIF_STATUS_FLAGS
#undef CT_DPIF_STATUS_FLAG
};

struct ct_dpif_entry {
    /* Const members. */
    struct ct_dpif_tuple tuple_orig;
    struct ct_dpif_tuple tuple_reply;
    struct ct_dpif_tuple tuple_master;
    struct ct_dpif_helper helper;
    uint32_t id;
    uint16_t zone;

    /* Modifiable members. */

    struct ct_dpif_counters counters_orig;
    struct ct_dpif_counters counters_reply;

    struct ct_dpif_timestamp timestamp;
    struct ct_dpif_protoinfo protoinfo;

    ovs_u128 labels;
    bool have_labels;
    uint32_t status;
    /* Timeout for this entry in seconds */
    uint32_t timeout;
    uint32_t mark;
    uint32_t bkt;       /* CT bucket number. */
};

enum {
    CT_STATS_UDP,
    CT_STATS_TCP,
    CT_STATS_SCTP,
    CT_STATS_ICMP,
    CT_STATS_ICMPV6,
    CT_STATS_UDPLITE,
    CT_STATS_DCCP,
    CT_STATS_IGMP,
    CT_STATS_OTHER,
    CT_STATS_MAX,
};

struct dpif;

struct ct_dpif_dump_state {
    struct dpif *dpif;
};

struct ct_dpif_zone_limit {
    uint16_t zone;
    uint32_t limit;       /* Limit on number of entries. */
    uint32_t count;       /* Current number of entries. */
    struct ovs_list node;
};

int ct_dpif_dump_start(struct dpif *, struct ct_dpif_dump_state **,
                       const uint16_t *zone, int *);
int ct_dpif_dump_next(struct ct_dpif_dump_state *, struct ct_dpif_entry *);
int ct_dpif_dump_done(struct ct_dpif_dump_state *);
int ct_dpif_flush(struct dpif *, const uint16_t *zone,
                  const struct ct_dpif_tuple *);
int ct_dpif_set_maxconns(struct dpif *dpif, uint32_t maxconns);
int ct_dpif_get_maxconns(struct dpif *dpif, uint32_t *maxconns);
int ct_dpif_get_nconns(struct dpif *dpif, uint32_t *nconns);
int ct_dpif_set_limits(struct dpif *dpif, const uint32_t *default_limit,
                       const struct ovs_list *);
int ct_dpif_get_limits(struct dpif *dpif, uint32_t *default_limit,
                       const struct ovs_list *, struct ovs_list *);
int ct_dpif_del_limits(struct dpif *dpif, const struct ovs_list *);
void ct_dpif_entry_uninit(struct ct_dpif_entry *);
void ct_dpif_format_entry(const struct ct_dpif_entry *, struct ds *,
                          bool verbose, bool print_stats);
void ct_dpif_format_tuple(struct ds *, const struct ct_dpif_tuple *);
uint8_t ct_dpif_coalesce_tcp_state(uint8_t state);
void ct_dpif_format_tcp_stat(struct ds *, int, int);
bool ct_dpif_parse_tuple(struct ct_dpif_tuple *, const char *s, struct ds *);
void ct_dpif_push_zone_limit(struct ovs_list *, uint16_t zone, uint32_t limit,
                             uint32_t count);
void ct_dpif_free_zone_limits(struct ovs_list *);

#endif /* CT_DPIF_H */
