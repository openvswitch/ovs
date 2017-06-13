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

#include <config.h>
#include "conntrack.h"

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "bitmap.h"
#include "conntrack-private.h"
#include "coverage.h"
#include "csum.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "flow.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "random.h"
#include "timeval.h"


VLOG_DEFINE_THIS_MODULE(conntrack);

COVERAGE_DEFINE(conntrack_full);
COVERAGE_DEFINE(conntrack_long_cleanup);

struct conn_lookup_ctx {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool related;
};

static bool conn_key_extract(struct conntrack *, struct dp_packet *,
                             ovs_be16 dl_type, struct conn_lookup_ctx *,
                             uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
static void conn_key_reverse(struct conn_key *);
static void conn_key_lookup(struct conntrack_bucket *ctb,
                            struct conn_lookup_ctx *ctx,
                            long long now);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct conntrack_bucket *, struct dp_packet *pkt,
                             struct conn_key *, long long now);
static void delete_conn(struct conn *);
static enum ct_update_res conn_update(struct conn *,
                                      struct conntrack_bucket *ctb,
                                      struct dp_packet *, bool reply,
                                      long long now);
static bool conn_expired(struct conn *, long long now);
static void set_mark(struct dp_packet *, struct conn *,
                     uint32_t val, uint32_t mask);
static void set_label(struct dp_packet *, struct conn *,
                      const struct ovs_key_ct_labels *val,
                      const struct ovs_key_ct_labels *mask);
static void *clean_thread_main(void *f_);

static struct nat_conn_key_node *
nat_conn_keys_lookup(struct hmap *nat_conn_keys,
                     const struct conn_key *key,
                     uint32_t basis);

static void
nat_conn_keys_remove(struct hmap *nat_conn_keys,
                     const struct conn_key *key,
                     uint32_t basis);

static bool
nat_select_range_tuple(struct conntrack *ct, const struct conn *conn,
                       struct conn *nat_conn);

static uint8_t
reverse_icmp_type(uint8_t type);
static uint8_t
reverse_icmp6_type(uint8_t type);
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data, bool validate_checksum);
static inline bool
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_icmp4,
    [IPPROTO_ICMPV6] = &ct_proto_icmp6,
};

long long ct_timeout_val[] = {
#define CT_TIMEOUT(NAME, VAL) [CT_TM_##NAME] = VAL,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

/* If the total number of connections goes above this value, no new connections
 * are accepted; this is for CT_CONN_TYPE_DEFAULT connections. */
#define DEFAULT_N_CONN_LIMIT 3000000

/* Initializes the connection tracker 'ct'.  The caller is responsible for
 * calling 'conntrack_destroy()', when the instance is not needed anymore */
void
conntrack_init(struct conntrack *ct)
{
    unsigned i, j;
    long long now = time_msec();

    ct_rwlock_init(&ct->nat_resources_lock);
    ct_rwlock_wrlock(&ct->nat_resources_lock);
    hmap_init(&ct->nat_conn_keys);
    ct_rwlock_unlock(&ct->nat_resources_lock);

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];

        ct_lock_init(&ctb->lock);
        ct_lock_lock(&ctb->lock);
        hmap_init(&ctb->connections);
        for (j = 0; j < ARRAY_SIZE(ctb->exp_lists); j++) {
            ovs_list_init(&ctb->exp_lists[j]);
        }
        ct_lock_unlock(&ctb->lock);
        ovs_mutex_init(&ctb->cleanup_mutex);
        ovs_mutex_lock(&ctb->cleanup_mutex);
        ctb->next_cleanup = now + CT_TM_MIN;
        ovs_mutex_unlock(&ctb->cleanup_mutex);
    }
    ct->hash_basis = random_uint32();
    atomic_count_init(&ct->n_conn, 0);
    atomic_init(&ct->n_conn_limit, DEFAULT_N_CONN_LIMIT);
    latch_init(&ct->clean_thread_exit);
    ct->clean_thread = ovs_thread_create("ct_clean", clean_thread_main, ct);
}

/* Destroys the connection tracker 'ct' and frees all the allocated memory. */
void
conntrack_destroy(struct conntrack *ct)
{
    unsigned i;

    latch_set(&ct->clean_thread_exit);
    pthread_join(ct->clean_thread, NULL);
    latch_destroy(&ct->clean_thread_exit);
    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];
        struct conn *conn;

        ovs_mutex_destroy(&ctb->cleanup_mutex);
        ct_lock_lock(&ctb->lock);
        HMAP_FOR_EACH_POP(conn, node, &ctb->connections) {
            if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
                atomic_count_dec(&ct->n_conn);
            }
            delete_conn(conn);
        }
        hmap_destroy(&ctb->connections);
        ct_lock_unlock(&ctb->lock);
        ct_lock_destroy(&ctb->lock);
    }
    ct_rwlock_wrlock(&ct->nat_resources_lock);
    struct nat_conn_key_node *nat_conn_key_node;
    HMAP_FOR_EACH_POP (nat_conn_key_node, node, &ct->nat_conn_keys) {
        free(nat_conn_key_node);
    }
    hmap_destroy(&ct->nat_conn_keys);
    ct_rwlock_unlock(&ct->nat_resources_lock);
    ct_rwlock_destroy(&ct->nat_resources_lock);
}

static unsigned hash_to_bucket(uint32_t hash)
{
    /* Extracts the most significant bits in hash. The least significant bits
     * are already used internally by the hmap implementation. */
    BUILD_ASSERT(CONNTRACK_BUCKETS_SHIFT < 32 && CONNTRACK_BUCKETS_SHIFT >= 1);

    return (hash >> (32 - CONNTRACK_BUCKETS_SHIFT)) % CONNTRACK_BUCKETS;
}

static void
write_ct_md(struct dp_packet *pkt, uint16_t zone, const struct conn *conn,
            const struct conn_key *key)
{
    pkt->md.ct_state |= CS_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = conn ? conn->mark : 0;
    pkt->md.ct_label = conn ? conn->label : OVS_U128_ZERO;

    /* Use the original direction tuple if we have it. */
    if (conn) {
        key = &conn->key;
    }
    pkt->md.ct_orig_tuple_ipv6 = false;
    if (key) {
        if (key->dl_type == htons(ETH_TYPE_IP)) {
            pkt->md.ct_orig_tuple.ipv4 = (struct ovs_key_ct_tuple_ipv4) {
                key->src.addr.ipv4_aligned,
                key->dst.addr.ipv4_aligned,
                key->nw_proto != IPPROTO_ICMP
                ? key->src.port : htons(key->src.icmp_type),
                key->nw_proto != IPPROTO_ICMP
                ? key->dst.port : htons(key->src.icmp_code),
                key->nw_proto,
            };
        } else {
            pkt->md.ct_orig_tuple_ipv6 = true;
            pkt->md.ct_orig_tuple.ipv6 = (struct ovs_key_ct_tuple_ipv6) {
                key->src.addr.ipv6_aligned,
                key->dst.addr.ipv6_aligned,
                key->nw_proto != IPPROTO_ICMPV6
                ? key->src.port : htons(key->src.icmp_type),
                key->nw_proto != IPPROTO_ICMPV6
                ? key->dst.port : htons(key->src.icmp_code),
                key->nw_proto,
            };
        }
    } else {
        memset(&pkt->md.ct_orig_tuple, 0, sizeof pkt->md.ct_orig_tuple);
    }

}

static void
pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->rev_key.dst.port, th->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->rev_key.dst.port, uh->udp_dst);
        }
    } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th->tcp_src, conn->rev_key.src.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh->udp_src, conn->rev_key.src.port);
        }
    }
}

static void
nat_packet(struct dp_packet *pkt, const struct conn *conn, bool related)
{
    if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
        pkt->md.ct_state |= CS_SRC_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_src,
                                 conn->rev_key.dst.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_src.be32,
                                 &conn->rev_key.dst.addr.ipv6_aligned,
                                 true);
        }
        if (!related) {
            pat_packet(pkt, conn);
        }
    } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
        pkt->md.ct_state |= CS_DST_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_dst,
                                 conn->rev_key.src.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_dst.be32,
                                 &conn->rev_key.src.addr.ipv6_aligned,
                                 true);
        }
        if (!related) {
            pat_packet(pkt, conn);
        }
    }
}

static void
un_pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th->tcp_src, conn->key.src.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh->udp_src, conn->key.src.port);
        }
    } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->key.dst.port, th->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->key.dst.port, uh->udp_dst);
        }
    }
}

static void
reverse_pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th_in = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->key.src.port,
                                th_in->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh_in = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->key.src.port,
                                uh_in->udp_dst);
        }
    } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th_in = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th_in->tcp_src,
                                conn->key.dst.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh_in = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh_in->udp_src,
                                conn->key.dst.port);
        }
    }
}

static void
reverse_nat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    char *tail = dp_packet_tail(pkt);
    char pad = dp_packet_l2_pad_size(pkt);
    struct conn_key inner_key;
    const char *inner_l4 = NULL;
    uint16_t orig_l3_ofs = pkt->l3_ofs;
    uint16_t orig_l4_ofs = pkt->l4_ofs;

    if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *nh = dp_packet_l3(pkt);
        struct icmp_header *icmp = dp_packet_l4(pkt);
        struct ip_header *inner_l3 = (struct ip_header *) (icmp + 1);
        extract_l3_ipv4(&inner_key, inner_l3, tail - ((char *)inner_l3)
                        -pad, &inner_l4, false);

        pkt->l3_ofs += (char *) inner_l3 - (char *) nh;
        pkt->l4_ofs += inner_l4 - (char *) icmp;

        if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
            packet_set_ipv4_addr(pkt, &inner_l3->ip_src,
                                 conn->key.src.addr.ipv4_aligned);
        } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
            packet_set_ipv4_addr(pkt, &inner_l3->ip_dst,
                                 conn->key.dst.addr.ipv4_aligned);
        }
        reverse_pat_packet(pkt, conn);
        icmp->icmp_csum = 0;
        icmp->icmp_csum = csum(icmp, tail - (char *) icmp - pad);
    } else {
        struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
        struct icmp6_error_header *icmp6 = dp_packet_l4(pkt);
        struct ovs_16aligned_ip6_hdr *inner_l3_6 =
            (struct ovs_16aligned_ip6_hdr *) (icmp6 + 1);
        extract_l3_ipv6(&inner_key, inner_l3_6,
                        tail - ((char *)inner_l3_6) - pad,
                        &inner_l4);
        pkt->l3_ofs += (char *) inner_l3_6 - (char *) nh6;
        pkt->l4_ofs += inner_l4 - (char *) icmp6;

        if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 inner_l3_6->ip6_src.be32,
                                 &conn->key.src.addr.ipv6_aligned,
                                 true);
        } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 inner_l3_6->ip6_dst.be32,
                                 &conn->key.dst.addr.ipv6_aligned,
                                 true);
        }
        reverse_pat_packet(pkt, conn);
        uint32_t icmp6_csum = packet_csum_pseudoheader6(nh6);
        icmp6->icmp6_base.icmp6_cksum = 0;
        icmp6->icmp6_base.icmp6_cksum = csum_finish(
            csum_continue(icmp6_csum, icmp6, tail - (char *) icmp6 - pad));
    }
    pkt->l3_ofs = orig_l3_ofs;
    pkt->l4_ofs = orig_l4_ofs;
}

static void
un_nat_packet(struct dp_packet *pkt, const struct conn *conn,
              bool related)
{
    if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
        pkt->md.ct_state |= CS_DST_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_dst,
                                 conn->key.src.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_dst.be32,
                                 &conn->key.src.addr.ipv6_aligned, true);
        }

        if (OVS_UNLIKELY(related)) {
            reverse_nat_packet(pkt, conn);
        } else {
            un_pat_packet(pkt, conn);
        }
    } else if (conn->nat_info->nat_action & NAT_ACTION_DST) {
        pkt->md.ct_state |= CS_SRC_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_src,
                                 conn->key.dst.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_src.be32,
                                 &conn->key.dst.addr.ipv6_aligned, true);
        }

        if (OVS_UNLIKELY(related)) {
            reverse_nat_packet(pkt, conn);
        } else {
            un_pat_packet(pkt, conn);
        }
    }
}

/* Typical usage of this helper is in non per-packet code;
 * this is because the bucket lock needs to be held for lookup
 * and a hash would have already been needed. Hence, this function
 * is just intended for code clarity. */
static struct conn *
conn_lookup(struct conntrack *ct, struct conn_key *key, long long now)
{
    struct conn_lookup_ctx ctx;
    ctx.conn = NULL;
    ctx.key = *key;
    ctx.hash = conn_key_hash(key, ct->hash_basis);
    unsigned bucket = hash_to_bucket(ctx.hash);
    conn_key_lookup(&ct->buckets[bucket], &ctx, now);
    return ctx.conn;
}

static void
nat_clean(struct conntrack *ct, struct conn *conn,
          struct conntrack_bucket *ctb)
    OVS_REQUIRES(ctb->lock)
{
    long long now = time_msec();
    ct_rwlock_wrlock(&ct->nat_resources_lock);
    nat_conn_keys_remove(&ct->nat_conn_keys, &conn->rev_key, ct->hash_basis);
    ct_rwlock_unlock(&ct->nat_resources_lock);
    ct_lock_unlock(&ctb->lock);

    uint32_t hash_rev_conn = conn_key_hash(&conn->rev_key, ct->hash_basis);
    unsigned bucket_rev_conn = hash_to_bucket(hash_rev_conn);

    ct_lock_lock(&ct->buckets[bucket_rev_conn].lock);
    ct_rwlock_wrlock(&ct->nat_resources_lock);

    struct conn *rev_conn = conn_lookup(ct, &conn->rev_key, now);

    struct nat_conn_key_node *nat_conn_key_node =
        nat_conn_keys_lookup(&ct->nat_conn_keys, &conn->rev_key,
                             ct->hash_basis);

    /* In the unlikely event, rev conn was recreated, then skip
     * rev_conn cleanup. */
    if (rev_conn && (!nat_conn_key_node ||
                     memcmp(&nat_conn_key_node->value, &rev_conn->rev_key,
                            sizeof nat_conn_key_node->value))) {
        hmap_remove(&ct->buckets[bucket_rev_conn].connections,
                    &rev_conn->node);
        free(rev_conn);
    }
    delete_conn(conn);

    ct_rwlock_unlock(&ct->nat_resources_lock);
    ct_lock_unlock(&ct->buckets[bucket_rev_conn].lock);
    ct_lock_lock(&ctb->lock);
}

static void
conn_clean(struct conntrack *ct, struct conn *conn,
           struct conntrack_bucket *ctb)
    OVS_REQUIRES(ctb->lock)
{
    ovs_list_remove(&conn->exp_node);
    hmap_remove(&ctb->connections, &conn->node);
    atomic_count_dec(&ct->n_conn);
    if (conn->nat_info) {
        nat_clean(ct, conn, ctb);
    } else {
        delete_conn(conn);
    }
}

static struct conn *
conn_not_found(struct conntrack *ct, struct dp_packet *pkt,
               struct conn_lookup_ctx *ctx, bool commit, long long now,
               const struct nat_action_info_t *nat_action_info,
               struct conn *conn_for_un_nat_copy)
{
    unsigned bucket = hash_to_bucket(ctx->hash);
    struct conn *nc = NULL;

    if (!valid_new(pkt, &ctx->key)) {
        pkt->md.ct_state = CS_INVALID;
        return nc;
    }
    pkt->md.ct_state = CS_NEW;

    if (commit) {
        unsigned int n_conn_limit;

        atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);

        if (atomic_count_get(&ct->n_conn) >= n_conn_limit) {
            COVERAGE_INC(conntrack_full);
            return nc;
        }

        nc = new_conn(&ct->buckets[bucket], pkt, &ctx->key, now);
        ctx->conn = nc;
        nc->rev_key = nc->key;
        conn_key_reverse(&nc->rev_key);

        if (nat_action_info) {
            nc->nat_info = xmemdup(nat_action_info, sizeof *nc->nat_info);
            ct_rwlock_wrlock(&ct->nat_resources_lock);

            bool nat_res = nat_select_range_tuple(ct, nc,
                                                  conn_for_un_nat_copy);

            if (!nat_res) {
                free(nc->nat_info);
                nc->nat_info = NULL;
                free (nc);
                ct_rwlock_unlock(&ct->nat_resources_lock);
                return NULL;
            }

            if (conn_for_un_nat_copy &&
                nc->conn_type == CT_CONN_TYPE_DEFAULT) {
                *nc = *conn_for_un_nat_copy;
                conn_for_un_nat_copy->conn_type = CT_CONN_TYPE_UN_NAT;
                conn_for_un_nat_copy->nat_info = NULL;
            }
            ct_rwlock_unlock(&ct->nat_resources_lock);

            nat_packet(pkt, nc, ctx->related);
        }
        hmap_insert(&ct->buckets[bucket].connections, &nc->node, ctx->hash);
        atomic_count_inc(&ct->n_conn);
    }
    return nc;
}

static bool
conn_update_state(struct conntrack *ct, struct dp_packet *pkt,
                  struct conn_lookup_ctx *ctx, struct conn **conn,
                  long long now, unsigned bucket)
    OVS_REQUIRES(ct->buckets[bucket].lock)
{
    bool create_new_conn = false;

    if (ctx->related) {
        pkt->md.ct_state |= CS_RELATED;
        if (ctx->reply) {
            pkt->md.ct_state |= CS_REPLY_DIR;
        }
    } else {
        enum ct_update_res res = conn_update(*conn, &ct->buckets[bucket],
                                             pkt, ctx->reply, now);

        switch (res) {
        case CT_UPDATE_VALID:
            pkt->md.ct_state |= CS_ESTABLISHED;
            pkt->md.ct_state &= ~CS_NEW;
            if (ctx->reply) {
                pkt->md.ct_state |= CS_REPLY_DIR;
            }
            break;
        case CT_UPDATE_INVALID:
            pkt->md.ct_state = CS_INVALID;
            break;
        case CT_UPDATE_NEW:
            conn_clean(ct, *conn, &ct->buckets[bucket]);
            create_new_conn = true;
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
    return create_new_conn;
}

static void
create_un_nat_conn(struct conntrack *ct, struct conn *conn_for_un_nat_copy,
                   long long now)
{
    struct conn *nc = xmemdup(conn_for_un_nat_copy, sizeof *nc);
    nc->key = conn_for_un_nat_copy->rev_key;
    nc->rev_key = conn_for_un_nat_copy->key;
    uint32_t un_nat_hash = conn_key_hash(&nc->key, ct->hash_basis);
    unsigned un_nat_conn_bucket = hash_to_bucket(un_nat_hash);
    ct_lock_lock(&ct->buckets[un_nat_conn_bucket].lock);
    ct_rwlock_rdlock(&ct->nat_resources_lock);

    struct conn *rev_conn = conn_lookup(ct, &nc->key, now);

    struct nat_conn_key_node *nat_conn_key_node =
        nat_conn_keys_lookup(&ct->nat_conn_keys, &nc->key, ct->hash_basis);
    if (nat_conn_key_node
        && !memcmp(&nat_conn_key_node->value, &nc->rev_key,
                   sizeof nat_conn_key_node->value)
        && !rev_conn) {
        hmap_insert(&ct->buckets[un_nat_conn_bucket].connections,
                    &nc->node, un_nat_hash);
    } else {
        free(nc);
    }
    ct_rwlock_unlock(&ct->nat_resources_lock);
    ct_lock_unlock(&ct->buckets[un_nat_conn_bucket].lock);
}

static void
handle_nat(struct dp_packet *pkt, struct conn *conn,
           uint16_t zone, bool reply, bool related)
{
    if (conn->nat_info &&
        (!(pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) ||
          (pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT) &&
           zone != pkt->md.ct_zone))) {
        if (pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) {
            pkt->md.ct_state &= ~(CS_SRC_NAT | CS_DST_NAT);
        }
        if (reply) {
            un_nat_packet(pkt, conn, related);
        } else {
            nat_packet(pkt, conn, related);
        }
    }
}

static bool
check_orig_tuple(struct conntrack *ct, struct dp_packet *pkt,
                 struct conn_lookup_ctx *ctx_in, long long now,
                 unsigned *bucket, struct conn **conn,
                 const struct nat_action_info_t *nat_action_info)
    OVS_REQUIRES(ct->buckets[*bucket].lock)
{
    if ((ctx_in->key.dl_type == htons(ETH_TYPE_IP) &&
         !pkt->md.ct_orig_tuple.ipv4.ipv4_proto) ||
        (ctx_in->key.dl_type == htons(ETH_TYPE_IPV6) &&
         !pkt->md.ct_orig_tuple.ipv6.ipv6_proto) ||
        !(pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) ||
        nat_action_info) {
        return false;
    }

    ct_lock_unlock(&ct->buckets[*bucket].lock);
    struct conn_lookup_ctx ctx;
    memset(&ctx, 0 , sizeof ctx);
    ctx.conn = NULL;

    if (ctx_in->key.dl_type == htons(ETH_TYPE_IP)) {
        ctx.key.src.addr.ipv4_aligned = pkt->md.ct_orig_tuple.ipv4.ipv4_src;
        ctx.key.dst.addr.ipv4_aligned = pkt->md.ct_orig_tuple.ipv4.ipv4_dst;

        if (ctx_in->key.nw_proto == IPPROTO_ICMP) {
            ctx.key.src.icmp_id = ctx_in->key.src.icmp_id;
            ctx.key.dst.icmp_id = ctx_in->key.dst.icmp_id;
            uint16_t src_port = ntohs(pkt->md.ct_orig_tuple.ipv4.src_port);
            ctx.key.src.icmp_type = (uint8_t) src_port;
            ctx.key.dst.icmp_type = reverse_icmp_type(ctx.key.src.icmp_type);
        } else {
            ctx.key.src.port = pkt->md.ct_orig_tuple.ipv4.src_port;
            ctx.key.dst.port = pkt->md.ct_orig_tuple.ipv4.dst_port;
        }
        ctx.key.nw_proto = pkt->md.ct_orig_tuple.ipv4.ipv4_proto;
    } else {
        ctx.key.src.addr.ipv6_aligned = pkt->md.ct_orig_tuple.ipv6.ipv6_src;
        ctx.key.dst.addr.ipv6_aligned = pkt->md.ct_orig_tuple.ipv6.ipv6_dst;

        if (ctx_in->key.nw_proto == IPPROTO_ICMPV6) {
            ctx.key.src.icmp_id = ctx_in->key.src.icmp_id;
            ctx.key.dst.icmp_id = ctx_in->key.dst.icmp_id;
            uint16_t src_port = ntohs(pkt->md.ct_orig_tuple.ipv6.src_port);
            ctx.key.src.icmp_type = (uint8_t) src_port;
            ctx.key.dst.icmp_type = reverse_icmp6_type(ctx.key.src.icmp_type);
        } else {
            ctx.key.src.port = pkt->md.ct_orig_tuple.ipv6.src_port;
            ctx.key.dst.port = pkt->md.ct_orig_tuple.ipv6.dst_port;
        }
        ctx.key.nw_proto = pkt->md.ct_orig_tuple.ipv6.ipv6_proto;
    }

    ctx.key.dl_type = ctx_in->key.dl_type;
    ctx.key.zone = pkt->md.ct_zone;

    ctx.hash = conn_key_hash(&ctx.key, ct->hash_basis);
    *bucket = hash_to_bucket(ctx.hash);
    ct_lock_lock(&ct->buckets[*bucket].lock);
    conn_key_lookup(&ct->buckets[*bucket], &ctx, now);
    *conn = ctx.conn;

    return *conn ? true : false;
}

static void
process_one(struct conntrack *ct, struct dp_packet *pkt,
            struct conn_lookup_ctx *ctx, uint16_t zone,
            bool force, bool commit, long long now, const uint32_t *setmark,
            const struct ovs_key_ct_labels *setlabel,
            const struct nat_action_info_t *nat_action_info)
{
    struct conn *conn;
    unsigned bucket = hash_to_bucket(ctx->hash);
    ct_lock_lock(&ct->buckets[bucket].lock);
    conn_key_lookup(&ct->buckets[bucket], ctx, now);
    conn = ctx->conn;

    /* Delete found entry if in wrong direction. 'force' implies commit. */
    if (conn && force && ctx->reply) {
        conn_clean(ct, conn, &ct->buckets[bucket]);
        conn = NULL;
    }

    if (OVS_LIKELY(conn)) {
        if (conn->conn_type == CT_CONN_TYPE_UN_NAT) {

            ctx->reply = true;

            struct conn_lookup_ctx ctx2;
            ctx2.conn = NULL;
            ctx2.key = conn->rev_key;
            ctx2.hash = conn_key_hash(&conn->rev_key, ct->hash_basis);

            ct_lock_unlock(&ct->buckets[bucket].lock);
            bucket = hash_to_bucket(ctx2.hash);

            ct_lock_lock(&ct->buckets[bucket].lock);
            conn_key_lookup(&ct->buckets[bucket], &ctx2, now);

            if (ctx2.conn) {
                conn = ctx2.conn;
            } else {
                /* It is a race condition where conn has timed out and removed
                 * between unlock of the rev_conn and lock of the forward conn;
                 * nothing to do. */
                pkt->md.ct_state |= CS_TRACKED | CS_INVALID;
                ct_lock_unlock(&ct->buckets[bucket].lock);
                return;
            }
        }
    }

    bool create_new_conn = false;
    struct conn conn_for_un_nat_copy;
    conn_for_un_nat_copy.conn_type = CT_CONN_TYPE_DEFAULT;
    if (OVS_LIKELY(conn)) {
        create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now, bucket);
        if (nat_action_info && !create_new_conn) {
            handle_nat(pkt, conn, zone, ctx->reply, ctx->related);
        }
    } else if (check_orig_tuple(ct, pkt, ctx, now, &bucket, &conn,
                                nat_action_info)) {
        create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now, bucket);
    } else {
        if (ctx->related) {
            pkt->md.ct_state = CS_INVALID;
        } else {
            create_new_conn = true;
        }
    }

    if (OVS_UNLIKELY(create_new_conn)) {
        conn = conn_not_found(ct, pkt, ctx, commit, now, nat_action_info,
                              &conn_for_un_nat_copy);
    }

    write_ct_md(pkt, zone, conn, &ctx->key);
    if (conn && setmark) {
        set_mark(pkt, conn, setmark[0], setmark[1]);
    }

    if (conn && setlabel) {
        set_label(pkt, conn, &setlabel[0], &setlabel[1]);
    }

    ct_lock_unlock(&ct->buckets[bucket].lock);

    if (conn_for_un_nat_copy.conn_type == CT_CONN_TYPE_UN_NAT) {
        create_un_nat_conn(ct, &conn_for_un_nat_copy, now);
    }
}

/* Sends the packets in '*pkt_batch' through the connection tracker 'ct'.  All
 * the packets should have the same 'dl_type' (IPv4 or IPv6) and should have
 * the l3 and and l4 offset properly set.
 *
 * If 'commit' is true, the packets are allowed to create new entries in the
 * connection tables.  'setmark', if not NULL, should point to a two
 * elements array containing a value and a mask to set the connection mark.
 * 'setlabel' behaves similarly for the connection label.*/
int
conntrack_execute(struct conntrack *ct, struct dp_packet_batch *pkt_batch,
                  ovs_be16 dl_type, bool force, bool commit, uint16_t zone,
                  const uint32_t *setmark,
                  const struct ovs_key_ct_labels *setlabel,
                  const char *helper,
                  const struct nat_action_info_t *nat_action_info)
{
    struct dp_packet **pkts = pkt_batch->packets;
    size_t cnt = pkt_batch->count;
    long long now = time_msec();
    struct conn_lookup_ctx ctx;

    if (helper) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

        VLOG_WARN_RL(&rl, "ALG helper \"%s\" not supported", helper);
        /* Continue without the helper */
    }

    for (size_t i = 0; i < cnt; i++) {
        if (!conn_key_extract(ct, pkts[i], dl_type, &ctx, zone)) {
            pkts[i]->md.ct_state = CS_INVALID;
            write_ct_md(pkts[i], zone, NULL, NULL);
            continue;
        }
        process_one(ct, pkts[i], &ctx, zone, force, commit,
                    now, setmark, setlabel, nat_action_info);
    }

    return 0;
}

static void
set_mark(struct dp_packet *pkt, struct conn *conn, uint32_t val, uint32_t mask)
{
    pkt->md.ct_mark = val | (pkt->md.ct_mark & ~(mask));
    conn->mark = pkt->md.ct_mark;
}

static void
set_label(struct dp_packet *pkt, struct conn *conn,
          const struct ovs_key_ct_labels *val,
          const struct ovs_key_ct_labels *mask)
{
    ovs_u128 v, m;

    memcpy(&v, val, sizeof v);
    memcpy(&m, mask, sizeof m);

    pkt->md.ct_label.u64.lo = v.u64.lo
                              | (pkt->md.ct_label.u64.lo & ~(m.u64.lo));
    pkt->md.ct_label.u64.hi = v.u64.hi
                              | (pkt->md.ct_label.u64.hi & ~(m.u64.hi));
    conn->label = pkt->md.ct_label;
}


/* Delete the expired connections from 'ctb', up to 'limit'. Returns the
 * earliest expiration time among the remaining connections in 'ctb'.  Returns
 * LLONG_MAX if 'ctb' is empty.  The return value might be smaller than 'now',
 * if 'limit' is reached */
static long long
sweep_bucket(struct conntrack *ct, struct conntrack_bucket *ctb, long long now,
             size_t limit)
    OVS_REQUIRES(ctb->lock)
{
    struct conn *conn, *next;
    long long min_expiration = LLONG_MAX;
    unsigned i;
    size_t count = 0;

    for (i = 0; i < N_CT_TM; i++) {
        LIST_FOR_EACH_SAFE (conn, next, exp_node, &ctb->exp_lists[i]) {
            if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
                if (!conn_expired(conn, now) || count >= limit) {
                    min_expiration = MIN(min_expiration, conn->expiration);
                    if (count >= limit) {
                        /* Do not check other lists. */
                        COVERAGE_INC(conntrack_long_cleanup);
                        return min_expiration;
                    }
                    break;
                }
                conn_clean(ct, conn, ctb);
                count++;
            }
        }
    }

    return min_expiration;
}

/* Cleans up old connection entries from 'ct'.  Returns the time when the
 * next expiration might happen.  The return value might be smaller than
 * 'now', meaning that an internal limit has been reached, and some expired
 * connections have not been deleted. */
static long long
conntrack_clean(struct conntrack *ct, long long now)
{
    long long next_wakeup = now + CT_TM_MIN;
    unsigned int n_conn_limit;
    size_t clean_count = 0;
    unsigned i;

    atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];
        size_t prev_count;
        long long min_exp;

        ovs_mutex_lock(&ctb->cleanup_mutex);
        if (ctb->next_cleanup > now) {
            goto next_bucket;
        }

        ct_lock_lock(&ctb->lock);
        prev_count = hmap_count(&ctb->connections);
        /* If the connections are well distributed among buckets, we want to
         * limit to 10% of the global limit equally split among buckets. If
         * the bucket is busier than the others, we limit to 10% of its
         * current size. */
        min_exp = sweep_bucket(ct, ctb, now,
                MAX(prev_count/10, n_conn_limit/(CONNTRACK_BUCKETS*10)));
        clean_count += prev_count - hmap_count(&ctb->connections);

        if (min_exp > now) {
            /* We call hmap_shrink() only if sweep_bucket() managed to delete
             * every expired connection. */
            hmap_shrink(&ctb->connections);
        }

        ct_lock_unlock(&ctb->lock);

        ctb->next_cleanup = MIN(min_exp, now + CT_TM_MIN);

next_bucket:
        next_wakeup = MIN(next_wakeup, ctb->next_cleanup);
        ovs_mutex_unlock(&ctb->cleanup_mutex);
    }

    VLOG_DBG("conntrack cleanup %"PRIuSIZE" entries in %lld msec",
             clean_count, time_msec() - now);

    return next_wakeup;
}

/* Cleanup:
 *
 * We must call conntrack_clean() periodically.  conntrack_clean() return
 * value gives an hint on when the next cleanup must be done (either because
 * there is an actual connection that expires, or because a new connection
 * might be created with the minimum timeout).
 *
 * The logic below has two goals:
 *
 * - We want to reduce the number of wakeups and batch connection cleanup
 *   when the load is not very high.  CT_CLEAN_INTERVAL ensures that if we
 *   are coping with the current cleanup tasks, then we wait at least
 *   5 seconds to do further cleanup.
 *
 * - We don't want to keep the buckets locked too long, as we might prevent
 *   traffic from flowing.  CT_CLEAN_MIN_INTERVAL ensures that if cleanup is
 *   behind, there is at least some 200ms blocks of time when buckets will be
 *   left alone, so the datapath can operate unhindered.
 */
#define CT_CLEAN_INTERVAL 5000 /* 5 seconds */
#define CT_CLEAN_MIN_INTERVAL 200  /* 0.2 seconds */

static void *
clean_thread_main(void *f_)
{
    struct conntrack *ct = f_;

    while (!latch_is_set(&ct->clean_thread_exit)) {
        long long next_wake;
        long long now = time_msec();

        next_wake = conntrack_clean(ct, now);

        if (next_wake < now) {
            poll_timer_wait_until(now + CT_CLEAN_MIN_INTERVAL);
        } else {
            poll_timer_wait_until(MAX(next_wake, now + CT_CLEAN_INTERVAL));
        }
        latch_wait(&ct->clean_thread_exit);
        poll_block();
    }

    return NULL;
}

/* Key extraction */

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks.  If 'validate_checksum' is true, the function returns
 * false if the IPv4 checksum is invalid. */
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data, bool validate_checksum)
{
    const struct ip_header *ip = data;
    size_t ip_len;

    if (new_data) {
        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            return false;
        }
    }

    ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

    if (new_data) {
        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            return false;
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            return false;
        }

        *new_data = (char *) data + ip_len;
    }

    if (IP_IS_FRAGMENT(ip->ip_frag_off)) {
        return false;
    }

    if (validate_checksum && csum(data, ip_len) != 0) {
        return false;
    }

    key->src.addr.ipv4 = ip->ip_src;
    key->dst.addr.ipv4 = ip->ip_dst;
    key->nw_proto = ip->ip_proto;

    return true;
}

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks. */
static inline bool
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ovs_16aligned_ip6_hdr *ip6 = data;

    if (new_data) {
        if (OVS_UNLIKELY(size < sizeof *ip6)) {
            return false;
        }
    }

    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag = 0;

    data = ip6 + 1;
    size -=  sizeof *ip6;

    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
        return false;
    }

    if (new_data) {
        *new_data = data;
    }

    if (nw_frag) {
        return false;
    }

    key->src.addr.ipv6 = ip6->ip6_src;
    key->dst.addr.ipv6 = ip6->ip6_dst;
    key->nw_proto = nw_proto;

    return true;
}

static inline bool
checksum_valid(const struct conn_key *key, const void *data, size_t size,
               const void *l3)
{
    uint32_t csum = 0;

    if (key->dl_type == htons(ETH_TYPE_IP)) {
        csum = packet_csum_pseudoheader(l3);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        csum = packet_csum_pseudoheader6(l3);
    } else {
        return false;
    }

    csum = csum_continue(csum, data, size);

    return csum_finish(csum) == 0;
}

static inline bool
check_l4_tcp(const struct conn_key *key, const void *data, size_t size,
             const void *l3)
{
    const struct tcp_header *tcp = data;
    if (size < sizeof *tcp) {
        return false;
    }

    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
    if (OVS_UNLIKELY(tcp_len < TCP_HEADER_LEN || tcp_len > size)) {
        return false;
    }

    return checksum_valid(key, data, size, l3);
}

static inline bool
check_l4_udp(const struct conn_key *key, const void *data, size_t size,
             const void *l3)
{
    const struct udp_header *udp = data;
    if (size < sizeof *udp) {
        return false;
    }

    size_t udp_len = ntohs(udp->udp_len);
    if (OVS_UNLIKELY(udp_len < UDP_HEADER_LEN || udp_len > size)) {
        return false;
    }

    /* Validation must be skipped if checksum is 0 on IPv4 packets */
    return (udp->udp_csum == 0 && key->dl_type == htons(ETH_TYPE_IP))
           || checksum_valid(key, data, size, l3);
}

static inline bool
check_l4_icmp(const void *data, size_t size)
{
    return csum(data, size) == 0;
}

static inline bool
check_l4_icmp6(const struct conn_key *key, const void *data, size_t size,
               const void *l3)
{
    return checksum_valid(key, data, size, l3);
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *data, size_t size)
{
    const struct tcp_header *tcp = data;

    if (OVS_UNLIKELY(size < TCP_HEADER_LEN)) {
        return false;
    }

    key->src.port = tcp->tcp_src;
    key->dst.port = tcp->tcp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool
extract_l4_udp(struct conn_key *key, const void *data, size_t size)
{
    const struct udp_header *udp = data;

    if (OVS_UNLIKELY(size < UDP_HEADER_LEN)) {
        return false;
    }

    key->src.port = udp->udp_src;
    key->dst.port = udp->udp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related, const void *l3);

static uint8_t
reverse_icmp_type(uint8_t type)
{
    switch (type) {
    case ICMP4_ECHO_REQUEST:
        return ICMP4_ECHO_REPLY;
    case ICMP4_ECHO_REPLY:
        return ICMP4_ECHO_REQUEST;

    case ICMP4_TIMESTAMP:
        return ICMP4_TIMESTAMPREPLY;
    case ICMP4_TIMESTAMPREPLY:
        return ICMP4_TIMESTAMP;

    case ICMP4_INFOREQUEST:
        return ICMP4_INFOREPLY;
    case ICMP4_INFOREPLY:
        return ICMP4_INFOREQUEST;
    default:
        OVS_NOT_REACHED();
    }
}

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline int
extract_l4_icmp(struct conn_key *key, const void *data, size_t size,
                bool *related)
{
    const struct icmp_header *icmp = data;

    if (OVS_UNLIKELY(size < ICMP_HEADER_LEN)) {
        return false;
    }

    switch (icmp->icmp_type) {
    case ICMP4_ECHO_REQUEST:
    case ICMP4_ECHO_REPLY:
    case ICMP4_TIMESTAMP:
    case ICMP4_TIMESTAMPREPLY:
    case ICMP4_INFOREQUEST:
    case ICMP4_INFOREPLY:
        if (icmp->icmp_code != 0) {
            return false;
        }
        /* Separate ICMP connection: identified using id */
        key->src.icmp_id = key->dst.icmp_id = icmp->icmp_fields.echo.id;
        key->src.icmp_type = icmp->icmp_type;
        key->dst.icmp_type = reverse_icmp_type(icmp->icmp_type);
        break;
    case ICMP4_DST_UNREACH:
    case ICMP4_TIME_EXCEEDED:
    case ICMP4_PARAM_PROB:
    case ICMP4_SOURCEQUENCH:
    case ICMP4_REDIRECT: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) (icmp + 1);
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
        ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4, false);
        if (!ok) {
            return false;
        }

        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned
            || inner_key.dst.addr.ipv4_aligned != key->src.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

static uint8_t
reverse_icmp6_type(uint8_t type)
{
    switch (type) {
    case ICMP6_ECHO_REQUEST:
        return ICMP6_ECHO_REPLY;
    case ICMP6_ECHO_REPLY:
        return ICMP6_ECHO_REQUEST;
    default:
        OVS_NOT_REACHED();
    }
}

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline bool
extract_l4_icmp6(struct conn_key *key, const void *data, size_t size,
                 bool *related)
{
    const struct icmp6_header *icmp6 = data;

    /* All the messages that we support need at least 4 bytes after
     * the header */
    if (size < sizeof *icmp6 + 4) {
        return false;
    }

    switch (icmp6->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        if (icmp6->icmp6_code != 0) {
            return false;
        }
        /* Separate ICMP connection: identified using id */
        key->src.icmp_id = key->dst.icmp_id = *(ovs_be16 *) (icmp6 + 1);
        key->src.icmp_type = icmp6->icmp6_type;
        key->dst.icmp_type = reverse_icmp6_type(icmp6->icmp6_type);
        break;
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) icmp6 + 8;
        const char *tail = (const char *) data + size;
        const char *l4 = NULL;
        bool ok;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IPV6);
        ok = extract_l3_ipv6(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (!ipv6_addr_equals(&inner_key.src.addr.ipv6_aligned,
                              &key->dst.addr.ipv6_aligned)
            || !ipv6_addr_equals(&inner_key.dst.addr.ipv6_aligned,
                                 &key->src.addr.ipv6_aligned)) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

/* Extract l4 fields into 'key', which must already contain valid l3
 * members.
 *
 * If 'related' is not NULL and an ICMP error packet is being
 * processed, the function will extract the key from the packet nested
 * in the ICMP paylod and set '*related' to true.
 *
 * If 'related' is NULL, it means that we're already parsing a header nested
 * in an ICMP error.  In this case, we skip checksum and length validation. */
static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related,
           const void *l3)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return (!related || check_l4_tcp(key, data, size, l3))
               && extract_l4_tcp(key, data, size);
    } else if (key->nw_proto == IPPROTO_UDP) {
        return (!related || check_l4_udp(key, data, size, l3))
               && extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return (!related || check_l4_icmp(data, size))
               && extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return (!related || check_l4_icmp6(key, data, size, l3))
               && extract_l4_icmp6(key, data, size, related);
    } else {
        return false;
    }
}

static bool
conn_key_extract(struct conntrack *ct, struct dp_packet *pkt, ovs_be16 dl_type,
                 struct conn_lookup_ctx *ctx, uint16_t zone)
{
    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);
    const char *tail = dp_packet_tail(pkt);
    bool ok;

    memset(ctx, 0, sizeof *ctx);

    if (!l2 || !l3 || !l4) {
        return false;
    }

    ctx->key.zone = zone;

    /* XXX In this function we parse the packet (again, it has already
     * gone through miniflow_extract()) for two reasons:
     *
     * 1) To extract the l3 addresses and l4 ports.
     *    We already have the l3 and l4 headers' pointers.  Extracting
     *    the l3 addresses and the l4 ports is really cheap, since they
     *    can be found at fixed locations.
     * 2) To extract the l4 type.
     *    Extracting the l4 types, for IPv6 can be quite expensive, because
     *    it's not at a fixed location.
     *
     * Here's a way to avoid (2) with the help of the datapath.
     * The datapath doesn't keep the packet's extracted flow[1], so
     * using that is not an option.  We could use the packet's matching
     * megaflow, but we have to make sure that the l4 type (nw_proto)
     * is unwildcarded.  This means either:
     *
     * a) dpif-netdev unwildcards the l4 type when a new flow is installed
     *    if the actions contains ct().
     *
     * b) ofproto-dpif-xlate unwildcards the l4 type when translating a ct()
     *    action.  This is already done in different actions, but it's
     *    unnecessary for the kernel.
     *
     * ---
     * [1] The reasons for this are that keeping the flow increases
     *     (slightly) the cache footprint and increases computation
     *     time as we move the packet around. Most importantly, the flow
     *     should be updated by the actions and this can be slow, as
     *     we use a sparse representation (miniflow).
     *
     */
    ctx->key.dl_type = dl_type;
    if (ctx->key.dl_type == htons(ETH_TYPE_IP)) {
        ok = extract_l3_ipv4(&ctx->key, l3, tail - (char *) l3, NULL, true);
    } else if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&ctx->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        if (extract_l4(&ctx->key, l4, tail - l4, &ctx->related, l3)) {
            ctx->hash = conn_key_hash(&ctx->key, ct->hash_basis);
            return true;
        }
    }

    return false;
}

static uint32_t
ct_addr_hash_add(uint32_t hash, const struct ct_addr *addr)
{
    BUILD_ASSERT_DECL(sizeof *addr % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) addr, sizeof *addr);
}

static uint32_t
ct_endpoint_hash_add(uint32_t hash, const struct ct_endpoint *ep)
{
    BUILD_ASSERT_DECL(sizeof *ep % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) ep, sizeof *ep);
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;

    hsrc = hdst = basis;
    hsrc = ct_endpoint_hash_add(hsrc, &key->src);
    hdst = ct_endpoint_hash_add(hdst, &key->dst);

    /* Even if source and destination are swapped the hash will be the same. */
    hash = hsrc ^ hdst;

    /* Hash the rest of the key(L3 and L4 types and zone). */
    hash = hash_words((uint32_t *) (&key->dst + 1),
                      (uint32_t *) (key + 1) - (uint32_t *) (&key->dst + 1),
                      hash);

    return hash_finish(hash, 0);
}

static void
conn_key_reverse(struct conn_key *key)
{
    struct ct_endpoint tmp;

    tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static uint32_t
nat_ipv6_addrs_delta(struct in6_addr *ipv6_aligned_min,
                     struct in6_addr *ipv6_aligned_max)
{
    uint8_t *ipv6_min_hi = &ipv6_aligned_min->s6_addr[0];
    uint8_t *ipv6_min_lo = &ipv6_aligned_min->s6_addr[0] +  sizeof(uint64_t);
    uint8_t *ipv6_max_hi = &ipv6_aligned_max->s6_addr[0];
    uint8_t *ipv6_max_lo = &ipv6_aligned_max->s6_addr[0] + sizeof(uint64_t);

    ovs_be64 addr6_64_min_hi;
    ovs_be64 addr6_64_min_lo;
    memcpy(&addr6_64_min_hi, ipv6_min_hi, sizeof addr6_64_min_hi);
    memcpy(&addr6_64_min_lo, ipv6_min_lo, sizeof addr6_64_min_lo);

    ovs_be64 addr6_64_max_hi;
    ovs_be64 addr6_64_max_lo;
    memcpy(&addr6_64_max_hi, ipv6_max_hi, sizeof addr6_64_max_hi);
    memcpy(&addr6_64_max_lo, ipv6_max_lo, sizeof addr6_64_max_lo);

    uint64_t diff;
    if (addr6_64_min_hi == addr6_64_max_hi &&
        ntohll(addr6_64_min_lo) <= ntohll(addr6_64_max_lo)) {
        diff = ntohll(addr6_64_max_lo) - ntohll(addr6_64_min_lo);
    } else if (ntohll(addr6_64_min_hi) + 1 == ntohll(addr6_64_max_hi) &&
               ntohll(addr6_64_min_lo) > ntohll(addr6_64_max_lo)) {
        diff = UINT64_MAX - (ntohll(addr6_64_min_lo) -
                             ntohll(addr6_64_max_lo) - 1);
    } else {
        /* Limit address delta supported to 32 bits or 4 billion approximately.
         * Possibly, this should be visible to the user through a datapath
         * support check, however the practical impact is probably nil. */
        diff = 0xfffffffe;
    }
    if (diff > 0xfffffffe) {
        diff = 0xfffffffe;
    }
    return diff;
}

/* This function must be used in tandem with nat_ipv6_addrs_delta(), which
 * restricts the input parameters. */
static void
nat_ipv6_addr_increment(struct in6_addr *ipv6_aligned, uint32_t increment)
{
    uint8_t *ipv6_hi = &ipv6_aligned->s6_addr[0];
    uint8_t *ipv6_lo = &ipv6_aligned->s6_addr[0] + sizeof(ovs_be64);
    ovs_be64 addr6_64_hi;
    ovs_be64 addr6_64_lo;
    memcpy(&addr6_64_hi, ipv6_hi, sizeof addr6_64_hi);
    memcpy(&addr6_64_lo, ipv6_lo, sizeof addr6_64_lo);

    if (UINT64_MAX - increment >= ntohll(addr6_64_lo)) {
        addr6_64_lo = htonll(increment + ntohll(addr6_64_lo));
    } else if (addr6_64_hi != OVS_BE64_MAX) {
        addr6_64_hi = htonll(1 + ntohll(addr6_64_hi));
        addr6_64_lo = htonll(increment - (UINT64_MAX -
                                          ntohll(addr6_64_lo) + 1));
    } else {
        OVS_NOT_REACHED();
    }

    memcpy(ipv6_hi, &addr6_64_hi, sizeof addr6_64_hi);
    memcpy(ipv6_lo, &addr6_64_lo, sizeof addr6_64_lo);

    return;
}

static uint32_t
nat_range_hash(const struct conn *conn, uint32_t basis)
{
    uint32_t hash = basis;

    hash = ct_addr_hash_add(hash, &conn->nat_info->min_addr);
    hash = ct_addr_hash_add(hash, &conn->nat_info->max_addr);
    hash = hash_add(hash,
                    (conn->nat_info->max_port << 16)
                    | conn->nat_info->min_port);

    hash = ct_endpoint_hash_add(hash, &conn->key.src);
    hash = ct_endpoint_hash_add(hash, &conn->key.dst);

    hash = hash_add(hash, (OVS_FORCE uint32_t) conn->key.dl_type);
    hash = hash_add(hash, conn->key.nw_proto);
    hash = hash_add(hash, conn->key.zone);

    /* The purpose of the second parameter is to distinguish hashes of data of
     * different length; our data always has the same length so there is no
     * value in counting. */
    return hash_finish(hash, 0);
}

static bool
nat_select_range_tuple(struct conntrack *ct, const struct conn *conn,
                       struct conn *nat_conn)
{
#define MIN_NAT_EPHEMERAL_PORT 1024
#define MAX_NAT_EPHEMERAL_PORT 65535

    uint16_t min_port;
    uint16_t max_port;
    uint16_t first_port;

    uint32_t hash = nat_range_hash(conn, ct->hash_basis);

    if ((conn->nat_info->nat_action & NAT_ACTION_SRC) &&
        (!(conn->nat_info->nat_action & NAT_ACTION_SRC_PORT))) {
        min_port = ntohs(conn->key.src.port);
        max_port = ntohs(conn->key.src.port);
        first_port = min_port;
    } else if ((conn->nat_info->nat_action & NAT_ACTION_DST) &&
               (!(conn->nat_info->nat_action & NAT_ACTION_DST_PORT))) {
        min_port = ntohs(conn->key.dst.port);
        max_port = ntohs(conn->key.dst.port);
        first_port = min_port;
    } else {
        uint16_t deltap = conn->nat_info->max_port - conn->nat_info->min_port;
        uint32_t port_index = hash % (deltap + 1);
        first_port = conn->nat_info->min_port + port_index;
        min_port = conn->nat_info->min_port;
        max_port = conn->nat_info->max_port;
    }

    uint32_t deltaa = 0;
    uint32_t address_index;
    struct ct_addr ct_addr;
    memset(&ct_addr, 0, sizeof ct_addr);
    struct ct_addr max_ct_addr;
    memset(&max_ct_addr, 0, sizeof max_ct_addr);
    max_ct_addr = conn->nat_info->max_addr;

    if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
        deltaa = ntohl(conn->nat_info->max_addr.ipv4_aligned) -
                 ntohl(conn->nat_info->min_addr.ipv4_aligned);
        address_index = hash % (deltaa + 1);
        ct_addr.ipv4_aligned = htonl(
            ntohl(conn->nat_info->min_addr.ipv4_aligned) + address_index);
    } else {
        deltaa = nat_ipv6_addrs_delta(&conn->nat_info->min_addr.ipv6_aligned,
                                      &conn->nat_info->max_addr.ipv6_aligned);
        /* deltaa must be within 32 bits for full hash coverage. A 64 or
         * 128 bit hash is unnecessary and hence not used here. Most code
         * is kept common with V4; nat_ipv6_addrs_delta() will do the
         * enforcement via max_ct_addr. */
        max_ct_addr = conn->nat_info->min_addr;
        nat_ipv6_addr_increment(&max_ct_addr.ipv6_aligned, deltaa);

        address_index = hash % (deltaa + 1);
        ct_addr.ipv6_aligned = conn->nat_info->min_addr.ipv6_aligned;
        nat_ipv6_addr_increment(&ct_addr.ipv6_aligned, address_index);
    }

    uint16_t port = first_port;
    bool all_ports_tried = false;
    bool original_ports_tried = false;
    struct ct_addr first_addr = ct_addr;
    *nat_conn = *conn;

    while (true) {
        if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
            nat_conn->rev_key.dst.addr = ct_addr;
        } else {
            nat_conn->rev_key.src.addr = ct_addr;
        }

        if ((conn->key.nw_proto == IPPROTO_ICMP) ||
            (conn->key.nw_proto == IPPROTO_ICMPV6)) {
            all_ports_tried = true;
        } else if (conn->nat_info->nat_action & NAT_ACTION_SRC) {
            nat_conn->rev_key.dst.port = htons(port);
        } else {
            nat_conn->rev_key.src.port = htons(port);
        }

        struct nat_conn_key_node *nat_conn_key_node =
            nat_conn_keys_lookup(&ct->nat_conn_keys, &nat_conn->rev_key,
                                 ct->hash_basis);

        if (!nat_conn_key_node) {
            struct nat_conn_key_node *nat_conn_key =
                xzalloc(sizeof *nat_conn_key);
            nat_conn_key->key = nat_conn->rev_key;
            nat_conn_key->value = nat_conn->key;
            uint32_t nat_conn_key_hash = conn_key_hash(&nat_conn_key->key,
                                                       ct->hash_basis);
            hmap_insert(&ct->nat_conn_keys, &nat_conn_key->node,
                        nat_conn_key_hash);
            return true;
        } else if (!all_ports_tried) {
            if (min_port == max_port) {
                all_ports_tried = true;
            } else if (port == max_port) {
                port = min_port;
            } else {
                port++;
            }
            if (port == first_port) {
                all_ports_tried = true;
            }
        } else {
            if (memcmp(&ct_addr, &max_ct_addr, sizeof ct_addr)) {
                if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
                    ct_addr.ipv4_aligned = htonl(
                        ntohl(ct_addr.ipv4_aligned) + 1);
                } else {
                    nat_ipv6_addr_increment(&ct_addr.ipv6_aligned, 1);
                }
            } else {
                ct_addr = conn->nat_info->min_addr;
            }
            if (!memcmp(&ct_addr, &first_addr, sizeof ct_addr)) {
                if (!original_ports_tried) {
                    original_ports_tried = true;
                    ct_addr = conn->nat_info->min_addr;
                    min_port = MIN_NAT_EPHEMERAL_PORT;
                    max_port = MAX_NAT_EPHEMERAL_PORT;
                } else {
                    break;
                }
            }
            first_port = min_port;
            port = first_port;
            all_ports_tried = false;
        }
    }
    return false;
}

static struct nat_conn_key_node *
nat_conn_keys_lookup(struct hmap *nat_conn_keys,
                     const struct conn_key *key,
                     uint32_t basis)
{
    struct nat_conn_key_node *nat_conn_key_node;
    uint32_t nat_conn_key_hash = conn_key_hash(key, basis);

    HMAP_FOR_EACH_WITH_HASH (nat_conn_key_node, node, nat_conn_key_hash,
                             nat_conn_keys) {
        if (!memcmp(&nat_conn_key_node->key, key,
                    sizeof nat_conn_key_node->key)) {
            return nat_conn_key_node;
        }
    }
    return NULL;
}

static void
nat_conn_keys_remove(struct hmap *nat_conn_keys, const struct conn_key *key,
                     uint32_t basis)
{
    struct nat_conn_key_node *nat_conn_key_node;
    uint32_t nat_conn_key_hash = conn_key_hash(key, basis);

    HMAP_FOR_EACH_WITH_HASH (nat_conn_key_node, node, nat_conn_key_hash,
                             nat_conn_keys) {
        if (!memcmp(&nat_conn_key_node->key, key,
                    sizeof nat_conn_key_node->key)) {
            hmap_remove(nat_conn_keys, &nat_conn_key_node->node);
            free(nat_conn_key_node);
            return;
        }
    }
}

static void
conn_key_lookup(struct conntrack_bucket *ctb, struct conn_lookup_ctx *ctx,
                long long now)
{
    uint32_t hash = ctx->hash;
    struct conn *conn;

    ctx->conn = NULL;

    HMAP_FOR_EACH_WITH_HASH (conn, node, hash, &ctb->connections) {
        if (!memcmp(&conn->key, &ctx->key, sizeof conn->key)
                && !conn_expired(conn, now)) {
            ctx->conn = conn;
            ctx->reply = false;
            break;
        }
        if (!memcmp(&conn->rev_key, &ctx->key, sizeof conn->rev_key)
                && !conn_expired(conn, now)) {
            ctx->conn = conn;
            ctx->reply = true;
            break;
        }
    }
}

static enum ct_update_res
conn_update(struct conn *conn, struct conntrack_bucket *ctb,
            struct dp_packet *pkt, bool reply, long long now)
{
    return l4_protos[conn->key.nw_proto]->conn_update(conn, ctb, pkt,
                                                      reply, now);
}

static bool
conn_expired(struct conn *conn, long long now)
{
    if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
        return now >= conn->expiration;
    }
    return false;
}

static bool
valid_new(struct dp_packet *pkt, struct conn_key *key)
{
    return l4_protos[key->nw_proto]->valid_new(pkt);
}

static struct conn *
new_conn(struct conntrack_bucket *ctb, struct dp_packet *pkt,
         struct conn_key *key, long long now)
{
    struct conn *newconn;

    newconn = l4_protos[key->nw_proto]->new_conn(ctb, pkt, now);

    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static void
delete_conn(struct conn *conn)
{
    free(conn->nat_info);
    free(conn);
}

static void
ct_endpoint_to_ct_dpif_inet_addr(const struct ct_addr *a,
                                 union ct_dpif_inet_addr *b,
                                 ovs_be16 dl_type)
{
    if (dl_type == htons(ETH_TYPE_IP)) {
        b->ip = a->ipv4_aligned;
    } else if (dl_type == htons(ETH_TYPE_IPV6)){
        b->in6 = a->ipv6_aligned;
    }
}

static void
conn_key_to_tuple(const struct conn_key *key, struct ct_dpif_tuple *tuple)
{
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        tuple->l3_type = AF_INET;
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        tuple->l3_type = AF_INET6;
    }
    tuple->ip_proto = key->nw_proto;
    ct_endpoint_to_ct_dpif_inet_addr(&key->src.addr, &tuple->src,
                                     key->dl_type);
    ct_endpoint_to_ct_dpif_inet_addr(&key->dst.addr, &tuple->dst,
                                     key->dl_type);

    if (key->nw_proto == IPPROTO_ICMP || key->nw_proto == IPPROTO_ICMPV6) {
        tuple->icmp_id = key->src.icmp_id;
        tuple->icmp_type = key->src.icmp_type;
        tuple->icmp_code = key->src.icmp_code;
    } else {
        tuple->src_port = key->src.port;
        tuple->dst_port = key->dst.port;
    }
}

static void
conn_to_ct_dpif_entry(const struct conn *conn, struct ct_dpif_entry *entry,
                      long long now)
{
    struct ct_l4_proto *class;
    long long expiration;
    memset(entry, 0, sizeof *entry);
    conn_key_to_tuple(&conn->key, &entry->tuple_orig);
    conn_key_to_tuple(&conn->rev_key, &entry->tuple_reply);

    entry->zone = conn->key.zone;
    entry->mark = conn->mark;

    memcpy(&entry->labels, &conn->label, sizeof entry->labels);
    /* Not implemented yet */
    entry->timestamp.start = 0;
    entry->timestamp.stop = 0;

    expiration = conn->expiration - now;
    entry->timeout = (expiration > 0) ? expiration / 1000 : 0;

    class = l4_protos[conn->key.nw_proto];
    if (class->conn_get_protoinfo) {
        class->conn_get_protoinfo(conn, &entry->protoinfo);
    }
}

int
conntrack_dump_start(struct conntrack *ct, struct conntrack_dump *dump,
                     const uint16_t *pzone)
{
    memset(dump, 0, sizeof(*dump));
    if (pzone) {
        dump->zone = *pzone;
        dump->filter_zone = true;
    }
    dump->ct = ct;

    return 0;
}

int
conntrack_dump_next(struct conntrack_dump *dump, struct ct_dpif_entry *entry)
{
    struct conntrack *ct = dump->ct;
    long long now = time_msec();

    while (dump->bucket < CONNTRACK_BUCKETS) {
        struct hmap_node *node;

        ct_lock_lock(&ct->buckets[dump->bucket].lock);
        for (;;) {
            struct conn *conn;

            node = hmap_at_position(&ct->buckets[dump->bucket].connections,
                                    &dump->bucket_pos);
            if (!node) {
                break;
            }
            INIT_CONTAINER(conn, node, node);
            if ((!dump->filter_zone || conn->key.zone == dump->zone) &&
                 (conn->conn_type != CT_CONN_TYPE_UN_NAT)) {
                conn_to_ct_dpif_entry(conn, entry, now);
                break;
            }
            /* Else continue, until we find an entry in the appropriate zone
             * or the bucket has been scanned completely. */
        }
        ct_lock_unlock(&ct->buckets[dump->bucket].lock);

        if (!node) {
            memset(&dump->bucket_pos, 0, sizeof dump->bucket_pos);
            dump->bucket++;
        } else {
            return 0;
        }
    }
    return EOF;
}

int
conntrack_dump_done(struct conntrack_dump *dump OVS_UNUSED)
{
    return 0;
}

int
conntrack_flush(struct conntrack *ct, const uint16_t *zone)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conn *conn, *next;

        ct_lock_lock(&ct->buckets[i].lock);
        HMAP_FOR_EACH_SAFE(conn, next, node, &ct->buckets[i].connections) {
            if ((!zone || *zone == conn->key.zone) &&
                (conn->conn_type == CT_CONN_TYPE_DEFAULT)) {
                conn_clean(ct, conn, &ct->buckets[i]);
            }
        }
        ct_lock_unlock(&ct->buckets[i].lock);
    }
    return 0;
}
