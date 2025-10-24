/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#include "cmap.h"
#include "conntrack.h"
#include "ct-dpif.h"
#include "ipf.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "rculist.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

enum key_dir {
    CT_DIR_FWD = 0,
    CT_DIR_REV,
    CT_DIRS,
};

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

/* Verify that nw_proto stays uint8_t as it's used to index into l4_protos[] */
BUILD_ASSERT_DECL(MEMBER_SIZEOF(struct conn_key, nw_proto) == sizeof(uint8_t));

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key parent_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the parent control
     * connection label and mark. */
    ovs_u128 parent_label;
    uint32_t parent_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET) \
    CT_TIMEOUT(TCP_OPENING) \
    CT_TIMEOUT(TCP_ESTABLISHED) \
    CT_TIMEOUT(TCP_CLOSING) \
    CT_TIMEOUT(TCP_FIN_WAIT) \
    CT_TIMEOUT(TCP_CLOSED) \
    CT_TIMEOUT(OTHER_FIRST) \
    CT_TIMEOUT(OTHER_MULTIPLE) \
    CT_TIMEOUT(OTHER_BIDIR) \
    CT_TIMEOUT(ICMP_FIRST) \
    CT_TIMEOUT(ICMP_REPLY)

enum ct_timeout {
#define CT_TIMEOUT(NAME) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

#define N_EXP_LISTS 100

struct conn_key_node {
    enum key_dir dir;
    struct conn_key key;
    struct cmap_node cm_node;
};

struct conn {
    /* Immutable data. */
    struct conn_key_node key_node[CT_DIRS];
    struct conn_key parent_key; /* Only used for orig_tuple support. */
    uint16_t nat_action;
    char *alg;
    atomic_flag reclaimed; /* False during the lifetime of the connection,
                            * True as soon as a thread has started freeing
                            * its memory. */

    /* Inserted once by a PMD, then managed by the 'ct_clean' thread. */
    struct rculist node;

    /* Mutable data. */
    struct ovs_mutex lock; /* Guards all mutable fields. */
    ovs_u128 label;
    atomic_llong expiration;
    uint32_t mark;
    int seq_skew;

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */

    /* Immutable data. */
    bool alg_related; /* True if alg data connection. */

    uint32_t tp_id; /* Timeout policy ID. */
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
    CT_UPDATE_VALID_NEW,
};

#define NAT_ACTION_SNAT_ALL (NAT_ACTION_SRC | NAT_ACTION_SRC_PORT)
#define NAT_ACTION_DNAT_ALL (NAT_ACTION_DST | NAT_ACTION_DST_PORT)

enum ct_ephemeral_range {
    MIN_NAT_EPHEMERAL_PORT = 1024,
    MAX_NAT_EPHEMERAL_PORT = 65535
};

#define IN_RANGE(curr, min, max) \
    (curr >= min && curr <= max)

#define NEXT_PORT_IN_RANGE(curr, min, max) \
    (curr = (!IN_RANGE(curr, min, max) || curr == max) ? min : curr + 1)

/* If the current port is out of range increase the attempts by
 * one so that in the worst case scenario the current out of
 * range port plus all the in-range ports get tested.
 * Note that curr can be an out of range port only in case of
 * source port (SNAT with port range unspecified or DNAT),
 * furthermore the source port in the packet has to be less than
 * MIN_NAT_EPHEMERAL_PORT. */
#define N_PORT_ATTEMPTS(curr, min, max) \
    ((!IN_RANGE(curr, min, max)) ? (max - min) + 2 : (max - min) + 1)

/* Loose in-range check, the first curr port can be any port out of
 * the range. */
#define FOR_EACH_PORT_IN_RANGE__(curr, min, max, INAME) \
    for (uint16_t INAME = N_PORT_ATTEMPTS(curr, min, max); \
        INAME > 0; INAME--, NEXT_PORT_IN_RANGE(curr, min, max))

#define FOR_EACH_PORT_IN_RANGE(curr, min, max) \
    FOR_EACH_PORT_IN_RANGE__(curr, min, max, OVS_JOIN(idx, __COUNTER__))

#define ZONE_LIMIT_CONN_DEFAULT -1

struct conntrack_zone_limit {
    int32_t zone;
    atomic_int64_t limit;
    atomic_count count;
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
};

struct conntrack {
    struct ovs_mutex ct_lock; /* Protects the following fields. */
    struct cmap conns[UINT16_MAX + 1];
    struct rculist exp_lists[N_EXP_LISTS];
    struct cmap zone_limits;
    struct cmap timeout_policies;
    uint32_t zone_limit_seq OVS_GUARDED; /* Used to disambiguate zone limit
                                          * counts. */
    atomic_uint32_t default_zone_limit;

    uint32_t hash_basis; /* Salt for hashing a connection key. */
    pthread_t clean_thread; /* Periodically cleans up connection tracker. */
    struct latch clean_thread_exit; /* To destroy the 'clean_thread'. */
    unsigned int next_list; /* Next list where the newly created connection
                             * gets inserted. */
    unsigned int next_sweep; /* List from which the gc thread will resume
                              * the sweeping. */

    /* Counting connections. */
    atomic_count n_conn; /* Number of connections currently tracked. */
    atomic_uint n_conn_limit; /* Max connections tracked. */

    /* Expectations for application level gateways (created by control
     * connections to help create data connections, e.g. for FTP). */
    struct ovs_rwlock resources_lock; /* Protects fields below. */
    struct hmap alg_expectations OVS_GUARDED; /* Holds struct
                                               * alg_exp_nodes. */
    struct hindex alg_expectation_refs OVS_GUARDED; /* For lookup from
                                                     * control context.  */

    struct ipf *ipf; /* Fragmentation handling context. */
    atomic_bool tcp_seq_chk; /* Check TCP sequence numbers. */
    atomic_uint32_t sweep_ms; /* Next sweep interval. */
};

/* Lock acquisition order:
 *    1. 'conn->lock'
 *    2. 'ct_lock'
 *    3. 'resources_lock'
 */

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now, uint32_t tp_id);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

#endif /* conntrack-private.h */
