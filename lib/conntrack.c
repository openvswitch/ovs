/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <string.h>

#include "bitmap.h"
#include "conntrack.h"
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
#include "openvswitch/poll-loop.h"
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
    bool icmp_related;
};

enum ftp_ctl_pkt {
    /* Control packets with address and/or port specifiers. */
    CT_FTP_CTL_INTEREST,
    /* Control packets without address and/or port specifiers. */
    CT_FTP_CTL_OTHER,
    CT_FTP_CTL_INVALID,
};

enum ct_alg_mode {
    CT_FTP_MODE_ACTIVE,
    CT_FTP_MODE_PASSIVE,
    CT_TFTP_MODE,
};

enum ct_alg_ctl_type {
    CT_ALG_CTL_NONE,
    CT_ALG_CTL_FTP,
    CT_ALG_CTL_TFTP,
    /* SIP is not enabled through Openflow and presently only used as
     * an example of an alg that allows a wildcard src ip. */
    CT_ALG_CTL_SIP,
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

static bool
nat_conn_keys_insert(struct hmap *nat_conn_keys,
                     const struct conn *nat_conn,
                     uint32_t hash_basis);

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

static struct alg_exp_node *
expectation_lookup(struct hmap *alg_expectations, const struct conn_key *key,
                   uint32_t basis, bool src_ip_wc);

static int
repl_ftp_v4_addr(struct dp_packet *pkt, ovs_be32 v4_addr_rep,
                 char *ftp_data_v4_start,
                 size_t addr_offset_from_ftp_data_start);

static enum ftp_ctl_pkt
process_ftp_ctl_v4(struct conntrack *ct,
                   struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   ovs_be32 *v4_addr_rep,
                   char **ftp_data_v4_start,
                   size_t *addr_offset_from_ftp_data_start);

static enum ftp_ctl_pkt
detect_ftp_ctl_type(const struct conn_lookup_ctx *ctx,
                    struct dp_packet *pkt);

static void
expectation_clean(struct conntrack *ct, const struct conn_key *master_key,
                  uint32_t basis);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_icmp4,
    [IPPROTO_ICMPV6] = &ct_proto_icmp6,
};

static void
handle_ftp_ctl(struct conntrack *ct, const struct conn_lookup_ctx *ctx,
               struct dp_packet *pkt,
               const struct conn *conn_for_expectation,
               long long now, enum ftp_ctl_pkt ftp_ctl, bool nat);

static void
handle_tftp_ctl(struct conntrack *ct,
                const struct conn_lookup_ctx *ctx OVS_UNUSED,
                struct dp_packet *pkt,
                const struct conn *conn_for_expectation,
                long long now OVS_UNUSED,
                enum ftp_ctl_pkt ftp_ctl OVS_UNUSED, bool nat OVS_UNUSED);

typedef void (*alg_helper)(struct conntrack *ct,
                           const struct conn_lookup_ctx *ctx,
                           struct dp_packet *pkt,
                           const struct conn *conn_for_expectation,
                           long long now, enum ftp_ctl_pkt ftp_ctl,
                           bool nat);

static alg_helper alg_helpers[] = {
    [CT_ALG_CTL_NONE] = NULL,
    [CT_ALG_CTL_FTP] = handle_ftp_ctl,
    [CT_ALG_CTL_TFTP] = handle_tftp_ctl,
};

long long ct_timeout_val[] = {
#define CT_TIMEOUT(NAME, VAL) [CT_TM_##NAME] = VAL,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

/* The maximum TCP or UDP port number. */
#define CT_MAX_L4_PORT 65535
/* String buffer used for parsing FTP string messages.
 * This is sized about twice what is needed to leave some
 * margin of error. */
#define LARGEST_FTP_MSG_OF_INTEREST 128
/* FTP port string used in active mode. */
#define FTP_PORT_CMD "PORT"
/* FTP pasv string used in passive mode. */
#define FTP_PASV_REPLY_CODE "227"
/* Maximum decimal digits for port in FTP command.
 * The port is represented as two 3 digit numbers with the
 * high part a multiple of 256. */
#define MAX_FTP_PORT_DGTS 3

/* FTP extension EPRT string used for active mode. */
#define FTP_EPRT_CMD "EPRT"
/* FTP extension EPSV string used for passive mode. */
#define FTP_EPSV_REPLY "EXTENDED PASSIVE"
/* Maximum decimal digits for port in FTP extended command. */
#define MAX_EXT_FTP_PORT_DGTS 5
/* FTP extended command code for IPv6. */
#define FTP_AF_V6 '2'
/* Used to indicate a wildcard L4 source port number for ALGs.
 * This is used for port numbers that we cannot predict in
 * expectations. */
#define ALG_WC_SRC_PORT 0

/* If the total number of connections goes above this value, no new connections
 * are accepted; this is for CT_CONN_TYPE_DEFAULT connections. */
#define DEFAULT_N_CONN_LIMIT 3000000

/* Does a member by member comparison of two conn_keys; this
 * function must be kept in sync with struct conn_key; returns 0
 * if the keys are equal or 1 if the keys are not equal. */
static int
conn_key_cmp(const struct conn_key *key1, const struct conn_key *key2)
{
    if (!memcmp(&key1->src.addr, &key2->src.addr, sizeof key1->src.addr) &&
        !memcmp(&key1->dst.addr, &key2->dst.addr, sizeof key1->dst.addr) &&
        (key1->src.icmp_id == key2->src.icmp_id) &&
        (key1->src.icmp_type == key2->src.icmp_type) &&
        (key1->src.icmp_code == key2->src.icmp_code) &&
        (key1->dst.icmp_id == key2->dst.icmp_id) &&
        (key1->dst.icmp_type == key2->dst.icmp_type) &&
        (key1->dst.icmp_code == key2->dst.icmp_code) &&
        (key1->dl_type == key2->dl_type) &&
        (key1->zone == key2->zone) &&
        (key1->nw_proto == key2->nw_proto)) {

        return 0;
    }
    return 1;
}

static void
ct_print_conn_info(const struct conn *c, const char *log_msg,
                   enum vlog_level vll, bool force, bool rl_on)
{
#define CT_VLOG(RL_ON, LEVEL, ...)                                          \
    do {                                                                    \
        if (RL_ON) {                                                        \
            static struct vlog_rate_limit rl_ = VLOG_RATE_LIMIT_INIT(5, 5); \
            vlog_rate_limit(&this_module, LEVEL, &rl_, __VA_ARGS__);        \
        } else {                                                            \
            vlog(&this_module, LEVEL, __VA_ARGS__);                         \
        }                                                                   \
    } while (0)

    if (OVS_UNLIKELY(force || vlog_is_enabled(&this_module, vll))) {
        if (c->key.dl_type == htons(ETH_TYPE_IP)) {
            CT_VLOG(rl_on, vll, "%s: src ip "IP_FMT" dst ip "IP_FMT" rev src "
                    "ip "IP_FMT" rev dst ip "IP_FMT" src/dst ports "
                    "%"PRIu16"/%"PRIu16" rev src/dst ports "
                    "%"PRIu16"/%"PRIu16" zone/rev zone "
                    "%"PRIu16"/%"PRIu16" nw_proto/rev nw_proto "
                    "%"PRIu8"/%"PRIu8, log_msg,
                    IP_ARGS(c->key.src.addr.ipv4_aligned),
                    IP_ARGS(c->key.dst.addr.ipv4_aligned),
                    IP_ARGS(c->rev_key.src.addr.ipv4_aligned),
                    IP_ARGS(c->rev_key.dst.addr.ipv4_aligned),
                    ntohs(c->key.src.port), ntohs(c->key.dst.port),
                    ntohs(c->rev_key.src.port), ntohs(c->rev_key.dst.port),
                    c->key.zone, c->rev_key.zone, c->key.nw_proto,
                    c->rev_key.nw_proto);
        } else {
            char ip6_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->key.src.addr.ipv6, ip6_s, sizeof ip6_s);
            char ip6_d[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->key.dst.addr.ipv6, ip6_d, sizeof ip6_d);
            char ip6_rs[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->rev_key.src.addr.ipv6, ip6_rs,
                      sizeof ip6_rs);
            char ip6_rd[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->rev_key.dst.addr.ipv6, ip6_rd,
                      sizeof ip6_rd);

            CT_VLOG(rl_on, vll, "%s: src ip %s dst ip %s rev src ip %s"
                    " rev dst ip %s src/dst ports %"PRIu16"/%"PRIu16
                    " rev src/dst ports %"PRIu16"/%"PRIu16" zone/rev zone "
                    "%"PRIu16"/%"PRIu16" nw_proto/rev nw_proto "
                    "%"PRIu8"/%"PRIu8, log_msg, ip6_s, ip6_d, ip6_rs,
                    ip6_rd, ntohs(c->key.src.port), ntohs(c->key.dst.port),
                    ntohs(c->rev_key.src.port), ntohs(c->rev_key.dst.port),
                    c->key.zone, c->rev_key.zone, c->key.nw_proto,
                    c->rev_key.nw_proto);
        }
    }
}

/* Initializes the connection tracker 'ct'.  The caller is responsible for
 * calling 'conntrack_destroy()', when the instance is not needed anymore */
void
conntrack_init(struct conntrack *ct)
{
    long long now = time_msec();

    ct_rwlock_init(&ct->resources_lock);
    ct_rwlock_wrlock(&ct->resources_lock);
    hmap_init(&ct->nat_conn_keys);
    hmap_init(&ct->alg_expectations);
    hindex_init(&ct->alg_expectation_refs);
    ovs_list_init(&ct->alg_exp_list);
    ct_rwlock_unlock(&ct->resources_lock);

    for (unsigned i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];

        ct_lock_init(&ctb->lock);
        ct_lock_lock(&ctb->lock);
        hmap_init(&ctb->connections);
        for (unsigned j = 0; j < ARRAY_SIZE(ctb->exp_lists); j++) {
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
    latch_set(&ct->clean_thread_exit);
    pthread_join(ct->clean_thread, NULL);
    latch_destroy(&ct->clean_thread_exit);
    for (unsigned i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conntrack_bucket *ctb = &ct->buckets[i];
        struct conn *conn;

        ovs_mutex_destroy(&ctb->cleanup_mutex);
        ct_lock_lock(&ctb->lock);
        HMAP_FOR_EACH_POP (conn, node, &ctb->connections) {
            if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
                atomic_count_dec(&ct->n_conn);
            }
            delete_conn(conn);
        }
        hmap_destroy(&ctb->connections);
        ct_lock_unlock(&ctb->lock);
        ct_lock_destroy(&ctb->lock);
    }
    ct_rwlock_wrlock(&ct->resources_lock);
    struct nat_conn_key_node *nat_conn_key_node;
    HMAP_FOR_EACH_POP (nat_conn_key_node, node, &ct->nat_conn_keys) {
        free(nat_conn_key_node);
    }
    hmap_destroy(&ct->nat_conn_keys);

    struct alg_exp_node *alg_exp_node;
    HMAP_FOR_EACH_POP (alg_exp_node, node, &ct->alg_expectations) {
        free(alg_exp_node);
    }

    ovs_list_poison(&ct->alg_exp_list);
    hmap_destroy(&ct->alg_expectations);
    hindex_destroy(&ct->alg_expectation_refs);
    ct_rwlock_unlock(&ct->resources_lock);
    ct_rwlock_destroy(&ct->resources_lock);
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
            const struct conn_key *key, const struct alg_exp_node *alg_exp)
{
    pkt->md.ct_state |= CS_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = conn ? conn->mark : 0;
    pkt->md.ct_label = conn ? conn->label : OVS_U128_ZERO;

    /* Use the original direction tuple if we have it. */
    if (conn) {
        if (conn->alg_related) {
            key = &conn->master_key;
        } else {
            key = &conn->key;
        }
    } else if (alg_exp) {
        pkt->md.ct_mark = alg_exp->master_mark;
        pkt->md.ct_label = alg_exp->master_label;
        key = &alg_exp->master_key;
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

static uint8_t
get_ip_proto(const struct dp_packet *pkt)
{
    uint8_t ip_proto;
    struct eth_header *l2 = dp_packet_eth(pkt);
    if (l2->eth_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
        ip_proto = nh6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else {
        struct ip_header *l3_hdr = dp_packet_l3(pkt);
        ip_proto = l3_hdr->ip_proto;
    }

    return ip_proto;
}

static bool
is_ftp_ctl(const enum ct_alg_ctl_type ct_alg_ctl)
{
    return ct_alg_ctl == CT_ALG_CTL_FTP;
}

static enum ct_alg_ctl_type
get_alg_ctl_type(const struct dp_packet *pkt, ovs_be16 tp_src, ovs_be16 tp_dst,
                 const char *helper)
{
    /* CT_IPPORT_FTP/TFTP is used because IPPORT_FTP/TFTP in not defined
     * in OSX, at least in in.h. Since these values will never change, remove
     * the external dependency. */
    enum { CT_IPPORT_FTP = 21 };
    enum { CT_IPPORT_TFTP = 69 };
    uint8_t ip_proto = get_ip_proto(pkt);
    struct udp_header *uh = dp_packet_l4(pkt);
    struct tcp_header *th = dp_packet_l4(pkt);
    ovs_be16 ftp_src_port = htons(CT_IPPORT_FTP);
    ovs_be16 ftp_dst_port = htons(CT_IPPORT_FTP);
    ovs_be16 tftp_dst_port = htons(CT_IPPORT_TFTP);

    if (OVS_UNLIKELY(tp_dst)) {
        if (helper && !strncmp(helper, "ftp", strlen("ftp"))) {
            ftp_dst_port = tp_dst;
        } else if (helper && !strncmp(helper, "tftp", strlen("tftp"))) {
            tftp_dst_port = tp_dst;
        }
    } else if (OVS_UNLIKELY(tp_src)) {
        if (helper && !strncmp(helper, "ftp", strlen("ftp"))) {
            ftp_src_port = tp_src;
        }
    }

    if (ip_proto == IPPROTO_UDP && uh->udp_dst == tftp_dst_port) {
        return CT_ALG_CTL_TFTP;
    } else if (ip_proto == IPPROTO_TCP &&
               (th->tcp_src == ftp_src_port || th->tcp_dst == ftp_dst_port)) {
        return CT_ALG_CTL_FTP;
    }
    return CT_ALG_CTL_NONE;
}

static bool
alg_src_ip_wc(enum ct_alg_ctl_type alg_ctl_type)
{
    if (alg_ctl_type == CT_ALG_CTL_SIP) {
        return true;
    }
    return false;
}

static void
handle_alg_ctl(struct conntrack *ct, const struct conn_lookup_ctx *ctx,
               struct dp_packet *pkt, enum ct_alg_ctl_type ct_alg_ctl,
               const struct conn *conn, long long now, bool nat,
               const struct conn *conn_for_expectation)
{
    /* ALG control packet handling with expectation creation. */
    if (OVS_UNLIKELY(alg_helpers[ct_alg_ctl] && conn && conn->alg)) {
        alg_helpers[ct_alg_ctl](ct, ctx, pkt, conn_for_expectation, now,
                                CT_FTP_CTL_INTEREST, nat);
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
        extract_l3_ipv4(&inner_key, inner_l3, tail - ((char *)inner_l3) - pad,
                        &inner_l4, false);
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
conn_lookup(struct conntrack *ct, const struct conn_key *key, long long now)
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
conn_seq_skew_set(struct conntrack *ct, const struct conn_key *key,
                  long long now, int seq_skew, bool seq_skew_dir)
{
    unsigned bucket = hash_to_bucket(conn_key_hash(key, ct->hash_basis));
    ct_lock_lock(&ct->buckets[bucket].lock);
    struct conn *conn = conn_lookup(ct, key, now);
    if (conn && seq_skew) {
        conn->seq_skew = seq_skew;
        conn->seq_skew_dir = seq_skew_dir;
    }
    ct_lock_unlock(&ct->buckets[bucket].lock);
}

static void
nat_clean(struct conntrack *ct, struct conn *conn,
          struct conntrack_bucket *ctb)
    OVS_REQUIRES(ctb->lock)
{
    ct_rwlock_wrlock(&ct->resources_lock);
    nat_conn_keys_remove(&ct->nat_conn_keys, &conn->rev_key, ct->hash_basis);
    ct_rwlock_unlock(&ct->resources_lock);
    ct_lock_unlock(&ctb->lock);
    unsigned bucket_rev_conn =
        hash_to_bucket(conn_key_hash(&conn->rev_key, ct->hash_basis));
    ct_lock_lock(&ct->buckets[bucket_rev_conn].lock);
    ct_rwlock_wrlock(&ct->resources_lock);
    long long now = time_msec();
    struct conn *rev_conn = conn_lookup(ct, &conn->rev_key, now);
    struct nat_conn_key_node *nat_conn_key_node =
        nat_conn_keys_lookup(&ct->nat_conn_keys, &conn->rev_key,
                             ct->hash_basis);

    /* In the unlikely event, rev conn was recreated, then skip
     * rev_conn cleanup. */
    if (rev_conn && (!nat_conn_key_node ||
                     conn_key_cmp(&nat_conn_key_node->value,
                                  &rev_conn->rev_key))) {
        hmap_remove(&ct->buckets[bucket_rev_conn].connections,
                    &rev_conn->node);
        free(rev_conn);
    }

    delete_conn(conn);
    ct_rwlock_unlock(&ct->resources_lock);
    ct_lock_unlock(&ct->buckets[bucket_rev_conn].lock);
    ct_lock_lock(&ctb->lock);
}

static void
conn_clean(struct conntrack *ct, struct conn *conn,
           struct conntrack_bucket *ctb)
    OVS_REQUIRES(ctb->lock)
{
    if (conn->alg) {
        expectation_clean(ct, &conn->key, ct->hash_basis);
    }
    ovs_list_remove(&conn->exp_node);
    hmap_remove(&ctb->connections, &conn->node);
    atomic_count_dec(&ct->n_conn);
    if (conn->nat_info) {
        nat_clean(ct, conn, ctb);
    } else {
        delete_conn(conn);
    }
}

static bool
ct_verify_helper(const char *helper, enum ct_alg_ctl_type ct_alg_ctl)
{
    if (ct_alg_ctl == CT_ALG_CTL_NONE) {
        return true;
    } else if (helper) {
        if ((ct_alg_ctl == CT_ALG_CTL_FTP) &&
             !strncmp(helper, "ftp", strlen("ftp"))) {
            return true;
        } else if ((ct_alg_ctl == CT_ALG_CTL_TFTP) &&
                   !strncmp(helper, "tftp", strlen("tftp"))) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

/* This function is called with the bucket lock held. */
static struct conn *
conn_not_found(struct conntrack *ct, struct dp_packet *pkt,
               struct conn_lookup_ctx *ctx, bool commit, long long now,
               const struct nat_action_info_t *nat_action_info,
               struct conn *conn_for_un_nat_copy,
               const char *helper,
               const struct alg_exp_node *alg_exp,
               enum ct_alg_ctl_type ct_alg_ctl)
{
    struct conn *nc = NULL;

    if (!valid_new(pkt, &ctx->key)) {
        pkt->md.ct_state = CS_INVALID;
        return nc;
    }

    pkt->md.ct_state = CS_NEW;

    if (alg_exp) {
        pkt->md.ct_state |= CS_RELATED;
    }

    if (commit) {
        unsigned int n_conn_limit;
        atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);

        if (atomic_count_get(&ct->n_conn) >= n_conn_limit) {
            COVERAGE_INC(conntrack_full);
            return nc;
        }

        unsigned bucket = hash_to_bucket(ctx->hash);
        nc = new_conn(&ct->buckets[bucket], pkt, &ctx->key, now);
        ctx->conn = nc;
        nc->rev_key = nc->key;
        conn_key_reverse(&nc->rev_key);

        if (ct_verify_helper(helper, ct_alg_ctl)) {
            nc->alg = nullable_xstrdup(helper);
        }

        if (alg_exp) {
            nc->alg_related = true;
            nc->mark = alg_exp->master_mark;
            nc->label = alg_exp->master_label;
            nc->master_key = alg_exp->master_key;
        }

        if (nat_action_info) {
            nc->nat_info = xmemdup(nat_action_info, sizeof *nc->nat_info);

            if (alg_exp) {
                if (alg_exp->nat_rpl_dst) {
                    nc->rev_key.dst.addr = alg_exp->alg_nat_repl_addr;
                    nc->nat_info->nat_action = NAT_ACTION_SRC;
                } else {
                    nc->rev_key.src.addr = alg_exp->alg_nat_repl_addr;
                    nc->nat_info->nat_action = NAT_ACTION_DST;
                }
                *conn_for_un_nat_copy = *nc;
                ct_rwlock_wrlock(&ct->resources_lock);
                bool new_insert = nat_conn_keys_insert(&ct->nat_conn_keys,
                                                       conn_for_un_nat_copy,
                                                       ct->hash_basis);
                ct_rwlock_unlock(&ct->resources_lock);
                if (!new_insert) {
                    char *log_msg = xasprintf("Pre-existing alg "
                                              "nat_conn_key");
                    ct_print_conn_info(conn_for_un_nat_copy, log_msg, VLL_INFO,
                                       true, false);
                    free(log_msg);
                }
            } else {
                *conn_for_un_nat_copy = *nc;
                ct_rwlock_wrlock(&ct->resources_lock);
                bool nat_res = nat_select_range_tuple(ct, nc,
                                                      conn_for_un_nat_copy);

                if (!nat_res) {
                    goto nat_res_exhaustion;
                }

                /* Update nc with nat adjustments made to
                 * conn_for_un_nat_copy by nat_select_range_tuple(). */
                *nc = *conn_for_un_nat_copy;
                ct_rwlock_unlock(&ct->resources_lock);
            }
            conn_for_un_nat_copy->conn_type = CT_CONN_TYPE_UN_NAT;
            conn_for_un_nat_copy->nat_info = NULL;
            conn_for_un_nat_copy->alg = NULL;
            nat_packet(pkt, nc, ctx->icmp_related);
        }
        hmap_insert(&ct->buckets[bucket].connections, &nc->node, ctx->hash);
        atomic_count_inc(&ct->n_conn);
    }

    return nc;

    /* This would be a user error or a DOS attack.
     * A user error is prevented by allocating enough
     * combinations of NAT addresses when combined with
     * ephemeral ports.  A DOS attack should be protected
     * against with firewall rules or a separate firewall.
     * Also using zone partitioning can limit DoS impact. */
nat_res_exhaustion:
    ovs_list_remove(&nc->exp_node);
    delete_conn(nc);
    /* conn_for_un_nat_copy is a local variable in process_one; this
     * memset() serves to document that conn_for_un_nat_copy is from
     * this point on unused. */
    memset(conn_for_un_nat_copy, 0, sizeof *conn_for_un_nat_copy);
    ct_rwlock_unlock(&ct->resources_lock);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    VLOG_WARN_RL(&rl, "Unable to NAT due to tuple space exhaustion - "
                 "if DoS attack, use firewalling and/or zone partitioning.");
    return NULL;
}

static bool
conn_update_state(struct conntrack *ct, struct dp_packet *pkt,
                  struct conn_lookup_ctx *ctx, struct conn **conn,
                  long long now, unsigned bucket)
    OVS_REQUIRES(ct->buckets[bucket].lock)
{
    bool create_new_conn = false;

    if (ctx->icmp_related) {
        pkt->md.ct_state |= CS_RELATED;
        if (ctx->reply) {
            pkt->md.ct_state |= CS_REPLY_DIR;
        }
    } else {
        if ((*conn)->alg_related) {
            pkt->md.ct_state |= CS_RELATED;
        }

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
                   long long now, bool alg_un_nat)
{
    struct conn *nc = xmemdup(conn_for_un_nat_copy, sizeof *nc);
    nc->key = conn_for_un_nat_copy->rev_key;
    nc->rev_key = conn_for_un_nat_copy->key;
    uint32_t un_nat_hash = conn_key_hash(&nc->key, ct->hash_basis);
    unsigned un_nat_conn_bucket = hash_to_bucket(un_nat_hash);
    ct_lock_lock(&ct->buckets[un_nat_conn_bucket].lock);
    struct conn *rev_conn = conn_lookup(ct, &nc->key, now);

    if (alg_un_nat) {
        if (!rev_conn) {
            hmap_insert(&ct->buckets[un_nat_conn_bucket].connections,
                        &nc->node, un_nat_hash);
        } else {
            char *log_msg = xasprintf("Unusual condition for un_nat conn "
                                      "create for alg: rev_conn %p", rev_conn);
            ct_print_conn_info(nc, log_msg, VLL_INFO, true, false);
            free(log_msg);
            free(nc);
        }
    } else {
        ct_rwlock_rdlock(&ct->resources_lock);

        struct nat_conn_key_node *nat_conn_key_node =
            nat_conn_keys_lookup(&ct->nat_conn_keys, &nc->key, ct->hash_basis);
        if (nat_conn_key_node && !conn_key_cmp(&nat_conn_key_node->value,
            &nc->rev_key) && !rev_conn) {
            hmap_insert(&ct->buckets[un_nat_conn_bucket].connections,
                        &nc->node, un_nat_hash);
        } else {
            char *log_msg = xasprintf("Unusual condition for un_nat conn "
                                      "create: nat_conn_key_node/rev_conn "
                                      "%p/%p", nat_conn_key_node, rev_conn);
            ct_print_conn_info(nc, log_msg, VLL_INFO, true, false);
            free(log_msg);
            free(nc);
        }
        ct_rwlock_unlock(&ct->resources_lock);
    }
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

static bool
is_un_nat_conn_valid(const struct conn *un_nat_conn)
{
    return un_nat_conn->conn_type == CT_CONN_TYPE_UN_NAT;
}

static bool
conn_update_state_alg(struct conntrack *ct, struct dp_packet *pkt,
                      struct conn_lookup_ctx *ctx, struct conn *conn,
                      const struct nat_action_info_t *nat_action_info,
                      enum ct_alg_ctl_type ct_alg_ctl, long long now,
                      unsigned bucket, bool *create_new_conn)
    OVS_REQUIRES(ct->buckets[bucket].lock)
{
    if (is_ftp_ctl(ct_alg_ctl)) {
        /* Keep sequence tracking in sync with the source of the
         * sequence skew. */
        if (ctx->reply != conn->seq_skew_dir) {
            handle_ftp_ctl(ct, ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                           !!nat_action_info);
            *create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now,
                                                bucket);
        } else {
            *create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now,
                                                bucket);
            handle_ftp_ctl(ct, ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                           !!nat_action_info);
        }
        return true;
    }
    return false;
}

static void
process_one(struct conntrack *ct, struct dp_packet *pkt,
            struct conn_lookup_ctx *ctx, uint16_t zone,
            bool force, bool commit, long long now, const uint32_t *setmark,
            const struct ovs_key_ct_labels *setlabel,
            const struct nat_action_info_t *nat_action_info,
            ovs_be16 tp_src, ovs_be16 tp_dst, const char *helper)
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

    enum ct_alg_ctl_type ct_alg_ctl = get_alg_ctl_type(pkt, tp_src, tp_dst,
                                                       helper);

    if (OVS_LIKELY(conn)) {
        if (OVS_LIKELY(!conn_update_state_alg(ct, pkt, ctx, conn,
                                              nat_action_info,
                                              ct_alg_ctl, now, bucket,
                                              &create_new_conn))) {
            create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now,
                                                bucket);
        }
        if (nat_action_info && !create_new_conn) {
            handle_nat(pkt, conn, zone, ctx->reply, ctx->icmp_related);
        }

    } else if (check_orig_tuple(ct, pkt, ctx, now, &bucket, &conn,
                               nat_action_info)) {
        create_new_conn = conn_update_state(ct, pkt, ctx, &conn, now, bucket);
    } else {
        if (ctx->icmp_related) {
            /* An icmp related conn should always be found; no new
               connection is created based on an icmp related packet. */
            pkt->md.ct_state = CS_INVALID;
        } else {
            create_new_conn = true;
        }
    }

    const struct alg_exp_node *alg_exp = NULL;

    if (OVS_UNLIKELY(create_new_conn)) {
        struct alg_exp_node alg_exp_entry;

        ct_rwlock_rdlock(&ct->resources_lock);
        alg_exp = expectation_lookup(&ct->alg_expectations, &ctx->key,
                                     ct->hash_basis,
                                     alg_src_ip_wc(ct_alg_ctl));
        if (alg_exp) {
            alg_exp_entry = *alg_exp;
            alg_exp = &alg_exp_entry;
        }
        ct_rwlock_unlock(&ct->resources_lock);

        conn = conn_not_found(ct, pkt, ctx, commit, now, nat_action_info,
                              &conn_for_un_nat_copy, helper, alg_exp,
                              ct_alg_ctl);
    }

    write_ct_md(pkt, zone, conn, &ctx->key, alg_exp);

    if (conn && setmark) {
        set_mark(pkt, conn, setmark[0], setmark[1]);
    }

    if (conn && setlabel) {
        set_label(pkt, conn, &setlabel[0], &setlabel[1]);
    }

    struct conn conn_for_expectation;
    if (OVS_UNLIKELY((ct_alg_ctl != CT_ALG_CTL_NONE) && conn)) {
        conn_for_expectation = *conn;
    }

    ct_lock_unlock(&ct->buckets[bucket].lock);

    if (is_un_nat_conn_valid(&conn_for_un_nat_copy)) {
        create_un_nat_conn(ct, &conn_for_un_nat_copy, now, !!alg_exp);
    }

    handle_alg_ctl(ct, ctx, pkt, ct_alg_ctl, conn, now, !!nat_action_info,
                   &conn_for_expectation);
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
                  ovs_be16 tp_src, ovs_be16 tp_dst, const char *helper,
                  const struct nat_action_info_t *nat_action_info,
                  long long now)
{

    struct dp_packet *packet;
    struct conn_lookup_ctx ctx;

    DP_PACKET_BATCH_FOR_EACH (i, packet, pkt_batch) {
        if (!conn_key_extract(ct, packet, dl_type, &ctx, zone)) {
            packet->md.ct_state = CS_INVALID;
            write_ct_md(packet, zone, NULL, NULL, NULL);
            continue;
        }
        process_one(ct, packet, &ctx, zone, force, commit, now, setmark,
                    setlabel, nat_action_info, tp_src, tp_dst, helper);
    }

    return 0;
}

void
conntrack_clear(struct dp_packet *packet)
{
    /* According to pkt_metadata_init(), ct_state == 0 is enough to make all of
     * the conntrack fields invalid. */
    packet->md.ct_state = 0;
}

static void
set_mark(struct dp_packet *pkt, struct conn *conn, uint32_t val, uint32_t mask)
{
    if (conn->alg_related) {
        pkt->md.ct_mark = conn->mark;
    } else {
        pkt->md.ct_mark = val | (pkt->md.ct_mark & ~(mask));
        conn->mark = pkt->md.ct_mark;
    }
}

static void
set_label(struct dp_packet *pkt, struct conn *conn,
          const struct ovs_key_ct_labels *val,
          const struct ovs_key_ct_labels *mask)
{
    if (conn->alg_related) {
        pkt->md.ct_label = conn->label;
    } else {
        ovs_u128 v, m;

        memcpy(&v, val, sizeof v);
        memcpy(&m, mask, sizeof m);

        pkt->md.ct_label.u64.lo = v.u64.lo
                              | (pkt->md.ct_label.u64.lo & ~(m.u64.lo));
        pkt->md.ct_label.u64.hi = v.u64.hi
                              | (pkt->md.ct_label.u64.hi & ~(m.u64.hi));
        conn->label = pkt->md.ct_label;
    }
}


/* Delete the expired connections from 'ctb', up to 'limit'. Returns the
 * earliest expiration time among the remaining connections in 'ctb'.  Returns
 * LLONG_MAX if 'ctb' is empty.  The return value might be smaller than 'now',
 * if 'limit' is reached */
static long long
sweep_bucket(struct conntrack *ct, struct conntrack_bucket *ctb,
             long long now, size_t limit)
    OVS_REQUIRES(ctb->lock)
{
    struct conn *conn, *next;
    long long min_expiration = LLONG_MAX;
    size_t count = 0;

    for (unsigned i = 0; i < N_CT_TM; i++) {
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

    atomic_read_relaxed(&ct->n_conn_limit, &n_conn_limit);

    for (unsigned i = 0; i < CONNTRACK_BUCKETS; i++) {
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
    if (new_data) {
        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            return false;
        }
    }

    const struct ip_header *ip = data;
    size_t ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

    if (new_data) {
        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            return false;
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            return false;
        }

        if (IP_IS_FRAGMENT(ip->ip_frag_off)) {
            return false;
        }

        *new_data = (char *) data + ip_len;
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

    data = ip6 + 1;
    size -=  sizeof *ip6;
    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag = 0;

    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
        return false;
    }

    if (nw_frag) {
        return false;
    }

    if (new_data) {
        *new_data = data;
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
             const void *l3, bool validate_checksum)
{
    const struct tcp_header *tcp = data;
    if (size < sizeof *tcp) {
        return false;
    }

    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
    if (OVS_UNLIKELY(tcp_len < TCP_HEADER_LEN || tcp_len > size)) {
        return false;
    }

    return validate_checksum ? checksum_valid(key, data, size, l3) : true;
}

static inline bool
check_l4_udp(const struct conn_key *key, const void *data, size_t size,
             const void *l3, bool validate_checksum)
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
           || (validate_checksum ? checksum_valid(key, data, size, l3) : true);
}

static inline bool
check_l4_icmp(const void *data, size_t size, bool validate_checksum)
{
    return validate_checksum ? csum(data, size) == 0 : true;
}

static inline bool
check_l4_icmp6(const struct conn_key *key, const void *data, size_t size,
               const void *l3, bool validate_checksum)
{
    return validate_checksum ? checksum_valid(key, data, size, l3) : true;
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *data, size_t size)
{
    if (OVS_UNLIKELY(size < TCP_HEADER_LEN)) {
        return false;
    }

    const struct tcp_header *tcp = data;
    key->src.port = tcp->tcp_src;
    key->dst.port = tcp->tcp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool
extract_l4_udp(struct conn_key *key, const void *data, size_t size)
{
    if (OVS_UNLIKELY(size < UDP_HEADER_LEN)) {
        return false;
    }

    const struct udp_header *udp = data;
    key->src.port = udp->udp_src;
    key->dst.port = udp->udp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related, const void *l3,
                              bool validate_checksum);

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
    if (OVS_UNLIKELY(size < ICMP_HEADER_LEN)) {
        return false;
    }

    const struct icmp_header *icmp = data;

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

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
        bool ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4, false);
        if (!ok) {
            return false;
        }

        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3, false);
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

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IPV6);
        bool ok = extract_l3_ipv6(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (!ipv6_addr_equals(&inner_key.src.addr.ipv6_aligned,
                              &key->dst.addr.ipv6_aligned)) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3, false);
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
 * in the ICMP payload and set '*related' to true.
 *
 * If 'related' is NULL, it means that we're already parsing a header nested
 * in an ICMP error.  In this case, we skip checksum and length validation. */
static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related,
           const void *l3, bool validate_checksum)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return (!related || check_l4_tcp(key, data, size, l3,
                validate_checksum)) && extract_l4_tcp(key, data, size);
    } else if (key->nw_proto == IPPROTO_UDP) {
        return (!related || check_l4_udp(key, data, size, l3,
                validate_checksum)) && extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return (!related || check_l4_icmp(data, size, validate_checksum))
               && extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return (!related || check_l4_icmp6(key, data, size, l3,
                validate_checksum)) && extract_l4_icmp6(key, data, size,
                related);
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
    const char *tail = dp_packet_tail(pkt);
    bool ok;
    ctx->key.dl_type = dl_type;

    if (ctx->key.dl_type == htons(ETH_TYPE_IP)) {
        bool hwol_bad_l3_csum = dp_packet_ip_checksum_bad(pkt);
        if (hwol_bad_l3_csum) {
            ok = false;
        } else {
            bool hwol_good_l3_csum = dp_packet_ip_checksum_valid(pkt);
            /* Validate the checksum only when hwol is not supported. */
            ok = extract_l3_ipv4(&ctx->key, l3, tail - (char *) l3, NULL,
                                 !hwol_good_l3_csum);
        }
    } else if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&ctx->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        bool hwol_bad_l4_csum = dp_packet_l4_checksum_bad(pkt);
        if (!hwol_bad_l4_csum) {
            bool  hwol_good_l4_csum = dp_packet_l4_checksum_valid(pkt);
            /* Validate the checksum only when hwol is not supported. */
            if (extract_l4(&ctx->key, l4, tail - l4, &ctx->icmp_related, l3,
                           !hwol_good_l4_csum)) {
                ctx->hash = conn_key_hash(&ctx->key, ct->hash_basis);
                return true;
            }
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
    struct ct_endpoint tmp = key->src;
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
    enum { MIN_NAT_EPHEMERAL_PORT = 1024,
           MAX_NAT_EPHEMERAL_PORT = 65535 };

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

        bool new_insert = nat_conn_keys_insert(&ct->nat_conn_keys, nat_conn,
                                               ct->hash_basis);
        if (new_insert) {
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

/* This function must be called with the ct->resources lock taken. */
static struct nat_conn_key_node *
nat_conn_keys_lookup(struct hmap *nat_conn_keys,
                     const struct conn_key *key,
                     uint32_t basis)
{
    struct nat_conn_key_node *nat_conn_key_node;

    HMAP_FOR_EACH_WITH_HASH (nat_conn_key_node, node,
                             conn_key_hash(key, basis), nat_conn_keys) {
        if (!conn_key_cmp(&nat_conn_key_node->key, key)) {
            return nat_conn_key_node;
        }
    }
    return NULL;
}

/* This function must be called with the ct->resources lock taken. */
static bool
nat_conn_keys_insert(struct hmap *nat_conn_keys, const struct conn *nat_conn,
                     uint32_t basis)
{
    struct nat_conn_key_node *nat_conn_key_node =
        nat_conn_keys_lookup(nat_conn_keys, &nat_conn->rev_key, basis);

    if (!nat_conn_key_node) {
        struct nat_conn_key_node *nat_conn_key = xzalloc(sizeof *nat_conn_key);
        nat_conn_key->key = nat_conn->rev_key;
        nat_conn_key->value = nat_conn->key;
        hmap_insert(nat_conn_keys, &nat_conn_key->node,
                    conn_key_hash(&nat_conn_key->key, basis));
        return true;
    }
    return false;
}

/* This function must be called with the ct->resources write lock taken. */
static void
nat_conn_keys_remove(struct hmap *nat_conn_keys,
                     const struct conn_key *key,
                     uint32_t basis)
{
    struct nat_conn_key_node *nat_conn_key_node;

    HMAP_FOR_EACH_WITH_HASH (nat_conn_key_node, node,
                             conn_key_hash(key, basis), nat_conn_keys) {
        if (!conn_key_cmp(&nat_conn_key_node->key, key)) {
            hmap_remove(nat_conn_keys, &nat_conn_key_node->node);
            free(nat_conn_key_node);
            return;
        }
    }
}

static void
conn_key_lookup(struct conntrack_bucket *ctb, struct conn_lookup_ctx *ctx,
                long long now)
    OVS_REQUIRES(ctb->lock)
{
    uint32_t hash = ctx->hash;
    struct conn *conn;

    ctx->conn = NULL;

    HMAP_FOR_EACH_WITH_HASH (conn, node, hash, &ctb->connections) {
        if (!conn_key_cmp(&conn->key, &ctx->key)
                && !conn_expired(conn, now)) {
            ctx->conn = conn;
            ctx->reply = false;
            break;
        }
        if (!conn_key_cmp(&conn->rev_key, &ctx->key)
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
    struct conn *newconn = l4_protos[key->nw_proto]->new_conn(ctb, pkt, now);
    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static void
delete_conn(struct conn *conn)
{
    free(conn->nat_info);
    free(conn->alg);
    free(conn);
}

/* Convert a conntrack address 'a' into an IP address 'b' based on 'dl_type'.
 *
 * Note that 'dl_type' should be either "ETH_TYPE_IP" or "ETH_TYPE_IPv6"
 * in network-byte order. */
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

/* Convert an IP address 'a' into a conntrack address 'b' based on 'dl_type'.
 *
 * Note that 'dl_type' should be either "ETH_TYPE_IP" or "ETH_TYPE_IPv6"
 * in network-byte order. */
static void
ct_dpif_inet_addr_to_ct_endpoint(const union ct_dpif_inet_addr *a,
                                 struct ct_addr *b,
                                 ovs_be16 dl_type)
{
    if (dl_type == htons(ETH_TYPE_IP)) {
        b->ipv4_aligned = a->ip;
    } else if (dl_type == htons(ETH_TYPE_IPV6)){
        b->ipv6_aligned = a->in6;
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
tuple_to_conn_key(const struct ct_dpif_tuple *tuple, uint16_t zone,
                  struct conn_key *key)
{
    if (tuple->l3_type == AF_INET) {
        key->dl_type = htons(ETH_TYPE_IP);
    } else if (tuple->l3_type == AF_INET6) {
        key->dl_type = htons(ETH_TYPE_IPV6);
    }
    key->nw_proto = tuple->ip_proto;
    ct_dpif_inet_addr_to_ct_endpoint(&tuple->src, &key->src.addr,
                                     key->dl_type);
    ct_dpif_inet_addr_to_ct_endpoint(&tuple->dst, &key->dst.addr,
                                     key->dl_type);

    if (tuple->ip_proto == IPPROTO_ICMP || tuple->ip_proto == IPPROTO_ICMPV6) {
        key->src.icmp_id = tuple->icmp_id;
        key->src.icmp_type = tuple->icmp_type;
        key->src.icmp_code = tuple->icmp_code;
        key->dst.icmp_id = tuple->icmp_id;
        key->dst.icmp_type = reverse_icmp_type(tuple->icmp_type);
        key->dst.icmp_code = tuple->icmp_code;
    } else {
        key->src.port = tuple->src_port;
        key->dst.port = tuple->dst_port;
    }
    key->zone = zone;
}

static void
conn_to_ct_dpif_entry(const struct conn *conn, struct ct_dpif_entry *entry,
                      long long now, int bkt)
{
    memset(entry, 0, sizeof *entry);
    conn_key_to_tuple(&conn->key, &entry->tuple_orig);
    conn_key_to_tuple(&conn->rev_key, &entry->tuple_reply);

    entry->zone = conn->key.zone;
    entry->mark = conn->mark;

    memcpy(&entry->labels, &conn->label, sizeof entry->labels);
    /* Not implemented yet */
    entry->timestamp.start = 0;
    entry->timestamp.stop = 0;

    long long expiration = conn->expiration - now;
    entry->timeout = (expiration > 0) ? expiration / 1000 : 0;

    struct ct_l4_proto *class = l4_protos[conn->key.nw_proto];
    if (class->conn_get_protoinfo) {
        class->conn_get_protoinfo(conn, &entry->protoinfo);
    }

    entry->bkt = bkt;

    if (conn->alg) {
        /* Caller is responsible for freeing. */
        entry->helper.name = xstrdup(conn->alg);
    }
}

int
conntrack_dump_start(struct conntrack *ct, struct conntrack_dump *dump,
                     const uint16_t *pzone, int *ptot_bkts)
{
    memset(dump, 0, sizeof(*dump));

    if (pzone) {
        dump->zone = *pzone;
        dump->filter_zone = true;
    }

    dump->ct = ct;
    *ptot_bkts = CONNTRACK_BUCKETS;
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
                conn_to_ct_dpif_entry(conn, entry, now, dump->bucket);
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
    for (unsigned i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conn *conn, *next;

        ct_lock_lock(&ct->buckets[i].lock);
        HMAP_FOR_EACH_SAFE (conn, next, node, &ct->buckets[i].connections) {
            if ((!zone || *zone == conn->key.zone) &&
                (conn->conn_type == CT_CONN_TYPE_DEFAULT)) {
                conn_clean(ct, conn, &ct->buckets[i]);
            }
        }
        ct_lock_unlock(&ct->buckets[i].lock);
    }

    return 0;
}

int
conntrack_flush_tuple(struct conntrack *ct, const struct ct_dpif_tuple *tuple,
                      uint16_t zone)
{
    struct conn_lookup_ctx ctx;
    int error = 0;

    memset(&ctx, 0, sizeof(ctx));
    tuple_to_conn_key(tuple, zone, &ctx.key);
    ctx.hash = conn_key_hash(&ctx.key, ct->hash_basis);
    unsigned bucket = hash_to_bucket(ctx.hash);

    ct_lock_lock(&ct->buckets[bucket].lock);
    conn_key_lookup(&ct->buckets[bucket], &ctx, time_msec());
    if (ctx.conn) {
        conn_clean(ct, ctx.conn, &ct->buckets[bucket]);
    } else {
        error = ENOENT;
    }
    ct_lock_unlock(&ct->buckets[bucket].lock);
    return error;
}

int
conntrack_set_maxconns(struct conntrack *ct, uint32_t maxconns)
{
    atomic_store_relaxed(&ct->n_conn_limit, maxconns);
    return 0;
}

int
conntrack_get_maxconns(struct conntrack *ct, uint32_t *maxconns)
{
    atomic_read_relaxed(&ct->n_conn_limit, maxconns);
    return 0;
}

int
conntrack_get_nconns(struct conntrack *ct, uint32_t *nconns)
{
    *nconns = atomic_count_get(&ct->n_conn);
    return 0;
}

/* This function must be called with the ct->resources read lock taken. */
static struct alg_exp_node *
expectation_lookup(struct hmap *alg_expectations, const struct conn_key *key,
                   uint32_t basis, bool src_ip_wc)
{
    struct conn_key check_key = *key;
    check_key.src.port = ALG_WC_SRC_PORT;

    if (src_ip_wc) {
        memset(&check_key.src.addr, 0, sizeof check_key.src.addr);
    }

    struct alg_exp_node *alg_exp_node;

    HMAP_FOR_EACH_WITH_HASH (alg_exp_node, node,
                             conn_key_hash(&check_key, basis),
                             alg_expectations) {
        if (!conn_key_cmp(&alg_exp_node->key, &check_key)) {
            return alg_exp_node;
        }
    }
    return NULL;
}

/* This function must be called with the ct->resources write lock taken. */
static void
expectation_remove(struct hmap *alg_expectations,
                   const struct conn_key *key, uint32_t basis)
{
    struct alg_exp_node *alg_exp_node;

    HMAP_FOR_EACH_WITH_HASH (alg_exp_node, node, conn_key_hash(key, basis),
                             alg_expectations) {
        if (!conn_key_cmp(&alg_exp_node->key, key)) {
            hmap_remove(alg_expectations, &alg_exp_node->node);
            break;
        }
    }
}

/* This function must be called with the ct->resources read lock taken. */
static struct alg_exp_node *
expectation_ref_lookup_unique(const struct hindex *alg_expectation_refs,
                              const struct conn_key *master_key,
                              const struct conn_key *alg_exp_key,
                              uint32_t basis)
{
    struct alg_exp_node *alg_exp_node;

    HINDEX_FOR_EACH_WITH_HASH (alg_exp_node, node_ref,
                               conn_key_hash(master_key, basis),
                               alg_expectation_refs) {
        if (!conn_key_cmp(&alg_exp_node->master_key, master_key) &&
            !conn_key_cmp(&alg_exp_node->key, alg_exp_key)) {
            return alg_exp_node;
        }
    }
    return NULL;
}

/* This function must be called with the ct->resources write lock taken. */
static void
expectation_ref_create(struct hindex *alg_expectation_refs,
                       struct alg_exp_node *alg_exp_node,
                       uint32_t basis)
{
    if (!expectation_ref_lookup_unique(alg_expectation_refs,
                                       &alg_exp_node->master_key,
                                       &alg_exp_node->key, basis)) {
        hindex_insert(alg_expectation_refs, &alg_exp_node->node_ref,
                      conn_key_hash(&alg_exp_node->master_key, basis));
    }
}

static void
expectation_clean(struct conntrack *ct, const struct conn_key *master_key,
                  uint32_t basis)
{
    ct_rwlock_wrlock(&ct->resources_lock);

    struct alg_exp_node *node, *next;
    HINDEX_FOR_EACH_WITH_HASH_SAFE (node, next, node_ref,
                                    conn_key_hash(master_key, basis),
                                    &ct->alg_expectation_refs) {
        if (!conn_key_cmp(&node->master_key, master_key)) {
            expectation_remove(&ct->alg_expectations, &node->key, basis);
            hindex_remove(&ct->alg_expectation_refs, &node->node_ref);
            free(node);
        }
    }

    ct_rwlock_unlock(&ct->resources_lock);
}

static void
expectation_create(struct conntrack *ct, ovs_be16 dst_port,
                   const struct conn *master_conn, bool reply, bool src_ip_wc,
                   bool skip_nat)
{
    struct ct_addr src_addr;
    struct ct_addr dst_addr;
    struct ct_addr alg_nat_repl_addr;
    struct alg_exp_node *alg_exp_node = xzalloc(sizeof *alg_exp_node);

    if (reply) {
        src_addr = master_conn->key.src.addr;
        dst_addr = master_conn->key.dst.addr;
        if (skip_nat) {
            alg_nat_repl_addr = dst_addr;
        } else {
            alg_nat_repl_addr = master_conn->rev_key.dst.addr;
        }
        alg_exp_node->nat_rpl_dst = true;
    } else {
        src_addr = master_conn->rev_key.src.addr;
        dst_addr = master_conn->rev_key.dst.addr;
        if (skip_nat) {
            alg_nat_repl_addr = src_addr;
        } else {
            alg_nat_repl_addr = master_conn->key.src.addr;
        }
        alg_exp_node->nat_rpl_dst = false;
    }
    if (src_ip_wc) {
        memset(&src_addr, 0, sizeof src_addr);
    }

    alg_exp_node->key.dl_type = master_conn->key.dl_type;
    alg_exp_node->key.nw_proto = master_conn->key.nw_proto;
    alg_exp_node->key.zone = master_conn->key.zone;
    alg_exp_node->key.src.addr = src_addr;
    alg_exp_node->key.dst.addr = dst_addr;
    alg_exp_node->key.src.port = ALG_WC_SRC_PORT;
    alg_exp_node->key.dst.port = dst_port;
    alg_exp_node->master_mark = master_conn->mark;
    alg_exp_node->master_label = master_conn->label;
    alg_exp_node->master_key = master_conn->key;
    /* Take the write lock here because it is almost 100%
     * likely that the lookup will fail and
     * expectation_create() will be called below. */
    ct_rwlock_wrlock(&ct->resources_lock);
    struct alg_exp_node *alg_exp = expectation_lookup(
        &ct->alg_expectations, &alg_exp_node->key, ct->hash_basis, src_ip_wc);
    if (alg_exp) {
        free(alg_exp_node);
        ct_rwlock_unlock(&ct->resources_lock);
        return;
    }

    alg_exp_node->alg_nat_repl_addr = alg_nat_repl_addr;
    hmap_insert(&ct->alg_expectations, &alg_exp_node->node,
                conn_key_hash(&alg_exp_node->key, ct->hash_basis));
    expectation_ref_create(&ct->alg_expectation_refs, alg_exp_node,
                           ct->hash_basis);
    ct_rwlock_unlock(&ct->resources_lock);
}

static uint8_t
get_v4_byte_be(ovs_be32 v4_addr, uint8_t index)
{
    uint8_t *byte_ptr = (OVS_FORCE uint8_t *) &v4_addr;
    return byte_ptr[index];
}

static void
replace_substring(char *substr, uint8_t substr_size,
                  uint8_t total_size, char *rep_str,
                  uint8_t rep_str_size)
{
    memmove(substr + rep_str_size, substr + substr_size,
            total_size - substr_size);
    memcpy(substr, rep_str, rep_str_size);
}

/* Replace IPV4 address in FTP message with NATed address. */
static int
repl_ftp_v4_addr(struct dp_packet *pkt, ovs_be32 v4_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start)
{
    enum { MAX_FTP_V4_NAT_DELTA = 8 };

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    uint16_t allocated_size = dp_packet_get_allocated(pkt);
    if (orig_used_size + MAX_FTP_V4_NAT_DELTA > allocated_size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP",
                     allocated_size);
        return 0;
    }

    size_t remain_size = tcp_payload_length(pkt) -
                             addr_offset_from_ftp_data_start;
    int overall_delta = 0;
    char *byte_str = ftp_data_start + addr_offset_from_ftp_data_start;

    /* Replace the existing IPv4 address by the new one. */
    for (uint8_t i = 0; i < 4; i++) {
        /* Find the end of the string for this octet. */
        char *next_delim = memchr(byte_str, ',', 4);
        ovs_assert(next_delim);
        int substr_size = next_delim - byte_str;
        remain_size -= substr_size;

        /* Compose the new string for this octet, and replace it. */
        char rep_str[4];
        uint8_t rep_byte = get_v4_byte_be(v4_addr_rep, i);
        int replace_size = sprintf(rep_str, "%d", rep_byte);
        replace_substring(byte_str, substr_size, remain_size,
                          rep_str, replace_size);
        overall_delta += replace_size - substr_size;

        /* Advance past the octet and the following comma. */
        byte_str += replace_size + 1;
    }

    dp_packet_set_size(pkt, orig_used_size + overall_delta);
    return overall_delta;
}

static char *
skip_non_digits(char *str)
{
    while (!isdigit(*str) && *str != 0) {
        str++;
    }
    return str;
}

static char *
terminate_number_str(char *str, uint8_t max_digits)
{
    uint8_t digits_found = 0;
    while (isdigit(*str) && digits_found <= max_digits) {
        str++;
        digits_found++;
    }

    *str = 0;
    return str;
}


static void
get_ftp_ctl_msg(struct dp_packet *pkt, char *ftp_msg)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    char *tcp_hdr = (char *) th;
    uint32_t tcp_payload_len = tcp_payload_length(pkt);
    size_t tcp_payload_of_interest = MIN(tcp_payload_len,
                                         LARGEST_FTP_MSG_OF_INTEREST);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;

    ovs_strlcpy(ftp_msg, tcp_hdr + tcp_hdr_len,
                tcp_payload_of_interest);
}

static enum ftp_ctl_pkt
detect_ftp_ctl_type(const struct conn_lookup_ctx *ctx,
                    struct dp_packet *pkt)
{
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);

    if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        if (strncasecmp(ftp_msg, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD)) &&
            !strcasestr(ftp_msg, FTP_EPSV_REPLY)) {
            return CT_FTP_CTL_OTHER;
        }
    } else {
        if (strncasecmp(ftp_msg, FTP_PORT_CMD, strlen(FTP_PORT_CMD)) &&
            strncasecmp(ftp_msg, FTP_PASV_REPLY_CODE,
                        strlen(FTP_PASV_REPLY_CODE))) {
            return CT_FTP_CTL_OTHER;
        }
    }

    return CT_FTP_CTL_INTEREST;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v4(struct conntrack *ct,
                   struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   ovs_be32 *v4_addr_rep,
                   char **ftp_data_v4_start,
                   size_t *addr_offset_from_ftp_data_start)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    *ftp_data_v4_start = tcp_hdr + tcp_hdr_len;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    char *ftp = ftp_msg;
    enum ct_alg_mode mode;

    if (!strncasecmp(ftp, FTP_PORT_CMD, strlen(FTP_PORT_CMD))) {
        ftp = ftp_msg + strlen(FTP_PORT_CMD);
        mode = CT_FTP_MODE_ACTIVE;
    } else {
        ftp = ftp_msg + strlen(FTP_PASV_REPLY_CODE);
        mode = CT_FTP_MODE_PASSIVE;
    }

    /* Find first space. */
    ftp = strchr(ftp, ' ');
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    /* Find the first digit, after space. */
    ftp = skip_non_digits(ftp);
    if (*ftp == 0) {
        return CT_FTP_CTL_INVALID;
    }

    char *ip_addr_start = ftp;
    *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;

    uint8_t comma_count = 0;
    while (comma_count < 4 && *ftp) {
        if (*ftp == ',') {
            comma_count++;
            if (comma_count == 4) {
                *ftp = 0;
            } else {
                *ftp = '.';
            }
        }
        ftp++;
    }
    if (comma_count != 4) {
        return CT_FTP_CTL_INVALID;
    }

    struct in_addr ip_addr;
    int rc2 = inet_pton(AF_INET, ip_addr_start, &ip_addr);
    if (rc2 != 1) {
        return CT_FTP_CTL_INVALID;
    }

    char *save_ftp = ftp;
    ftp = terminate_number_str(ftp, MAX_FTP_PORT_DGTS);
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }
    int value;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }

    /* This is derived from the L4 port maximum is 65535. */
    if (value > 255) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_hs = value;
    port_hs <<= 8;

    /* Skip over comma. */
    ftp++;
    save_ftp = ftp;
    bool digit_found = false;
    while (isdigit(*ftp)) {
        ftp++;
        digit_found = true;
    }
    if (!digit_found) {
        return CT_FTP_CTL_INVALID;
    }
    *ftp = 0;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }

    if (value > 255) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_lo_hs = value;
    if (65535 - port_hs < port_lo_hs) {
        return CT_FTP_CTL_INVALID;
    }

    port_hs |= port_lo_hs;
    ovs_be16 port = htons(port_hs);
    ovs_be32 conn_ipv4_addr;

    switch (mode) {
    case CT_FTP_MODE_ACTIVE:
        *v4_addr_rep = conn_for_expectation->rev_key.dst.addr.ipv4_aligned;
        conn_ipv4_addr = conn_for_expectation->key.src.addr.ipv4_aligned;
        break;
    case CT_FTP_MODE_PASSIVE:
        *v4_addr_rep = conn_for_expectation->key.dst.addr.ipv4_aligned;
        conn_ipv4_addr = conn_for_expectation->rev_key.src.addr.ipv4_aligned;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    ovs_be32 ftp_ipv4_addr;
    ftp_ipv4_addr = ip_addr.s_addr;
    /* Although most servers will block this exploit, there may be some
     * less well managed. */
    if (ftp_ipv4_addr != conn_ipv4_addr && ftp_ipv4_addr != *v4_addr_rep) {
        return CT_FTP_CTL_INVALID;
    }

    expectation_create(ct, port, conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static char *
skip_ipv6_digits(char *str)
{
    while (isxdigit(*str) || *str == ':' || *str == '.') {
        str++;
    }
    return str;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v6(struct conntrack *ct,
                   struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   struct ct_addr *v6_addr_rep,
                   char **ftp_data_start,
                   size_t *addr_offset_from_ftp_data_start,
                   size_t *addr_size, enum ct_alg_mode *mode)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    *ftp_data_start = tcp_hdr + tcp_hdr_len;
    char *ftp = ftp_msg;
    struct in6_addr ip6_addr;

    if (!strncasecmp(ftp, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD))) {
        ftp = ftp_msg + strlen(FTP_EPRT_CMD);
        ftp = skip_non_digits(ftp);
        if (*ftp != FTP_AF_V6 || isdigit(ftp[1])) {
            return CT_FTP_CTL_INVALID;
        }
        /* Jump over delimiter. */
        ftp += 2;

        memset(&ip6_addr, 0, sizeof ip6_addr);
        char *ip_addr_start = ftp;
        *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;
        ftp = skip_ipv6_digits(ftp);
        *ftp = 0;
        *addr_size = ftp - ip_addr_start;
        int rc2 = inet_pton(AF_INET6, ip_addr_start, &ip6_addr);
        if (rc2 != 1) {
            return CT_FTP_CTL_INVALID;
        }
        ftp++;
        *mode = CT_FTP_MODE_ACTIVE;
    } else {
        ftp = ftp_msg + strcspn(ftp_msg, "(");
        ftp = skip_non_digits(ftp);
        if (!isdigit(*ftp)) {
            return CT_FTP_CTL_INVALID;
        }

        /* Not used for passive mode. */
        *addr_offset_from_ftp_data_start = 0;
        *addr_size = 0;

        *mode = CT_FTP_MODE_PASSIVE;
    }

    char *save_ftp = ftp;
    ftp = terminate_number_str(ftp, MAX_EXT_FTP_PORT_DGTS);
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    int value;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }
    if (value > CT_MAX_L4_PORT) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_hs = value;
    ovs_be16 port = htons(port_hs);

    switch (*mode) {
    case CT_FTP_MODE_ACTIVE:
        *v6_addr_rep = conn_for_expectation->rev_key.dst.addr;
        /* Although most servers will block this exploit, there may be some
         * less well managed. */
        if (memcmp(&ip6_addr, &v6_addr_rep->ipv6_aligned, sizeof ip6_addr) &&
            memcmp(&ip6_addr, &conn_for_expectation->key.src.addr.ipv6_aligned,
                   sizeof ip6_addr)) {
            return CT_FTP_CTL_INVALID;
        }
        break;
    case CT_FTP_MODE_PASSIVE:
        *v6_addr_rep = conn_for_expectation->key.dst.addr;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    expectation_create(ct, port, conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static int
repl_ftp_v6_addr(struct dp_packet *pkt, struct ct_addr v6_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start,
                 size_t addr_size, enum ct_alg_mode mode)
{
    /* This is slightly bigger than really possible. */
    enum { MAX_FTP_V6_NAT_DELTA = 45 };

    if (mode == CT_FTP_MODE_PASSIVE) {
        return 0;
    }

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    uint16_t allocated_size = dp_packet_get_allocated(pkt);
    if (orig_used_size + MAX_FTP_V6_NAT_DELTA > allocated_size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP",
                     allocated_size);
        return 0;
    }

    char v6_addr_str[IPV6_SCAN_LEN] = {0};
    ovs_assert(inet_ntop(AF_INET6, &v6_addr_rep.ipv6_aligned, v6_addr_str,
                         IPV6_SCAN_LEN - 1));

    size_t replace_addr_size = strlen(v6_addr_str);

    size_t remain_size = tcp_payload_length(pkt) -
                             addr_offset_from_ftp_data_start;

    char *pkt_addr_str = ftp_data_start + addr_offset_from_ftp_data_start;
    replace_substring(pkt_addr_str, addr_size, remain_size,
                      v6_addr_str, replace_addr_size);

    int overall_delta = (int) replace_addr_size - (int) addr_size;

    dp_packet_set_size(pkt, orig_used_size + overall_delta);
    return overall_delta;
}

static void
handle_ftp_ctl(struct conntrack *ct, const struct conn_lookup_ctx *ctx,
               struct dp_packet *pkt,
               const struct conn *conn_for_expectation,
               long long now, enum ftp_ctl_pkt ftp_ctl, bool nat)
{
    struct ip_header *l3_hdr = dp_packet_l3(pkt);
    ovs_be32 v4_addr_rep = 0;
    struct ct_addr v6_addr_rep;
    size_t addr_offset_from_ftp_data_start;
    size_t addr_size = 0;
    char *ftp_data_start;
    bool do_seq_skew_adj = true;
    enum ct_alg_mode mode = CT_FTP_MODE_ACTIVE;

    if (detect_ftp_ctl_type(ctx, pkt) != ftp_ctl) {
        return;
    }

    if (!nat || !conn_for_expectation->seq_skew) {
        do_seq_skew_adj = false;
    }

    struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
    int64_t seq_skew = 0;

    if (ftp_ctl == CT_FTP_CTL_OTHER) {
        seq_skew = conn_for_expectation->seq_skew;
    } else if (ftp_ctl == CT_FTP_CTL_INTEREST) {
        enum ftp_ctl_pkt rc;
        if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
            rc = process_ftp_ctl_v6(ct, pkt, conn_for_expectation,
                                    &v6_addr_rep, &ftp_data_start,
                                    &addr_offset_from_ftp_data_start,
                                    &addr_size, &mode);
        } else {
            rc = process_ftp_ctl_v4(ct, pkt, conn_for_expectation,
                                    &v4_addr_rep, &ftp_data_start,
                                    &addr_offset_from_ftp_data_start);
        }
        if (rc == CT_FTP_CTL_INVALID) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "Invalid FTP control packet format");
            pkt->md.ct_state |= CS_TRACKED | CS_INVALID;
            return;
        } else if (rc == CT_FTP_CTL_INTEREST) {
            uint16_t ip_len;

            if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
                seq_skew = repl_ftp_v6_addr(pkt, v6_addr_rep, ftp_data_start,
                                            addr_offset_from_ftp_data_start,
                                            addr_size, mode);
                if (seq_skew) {
                    ip_len = ntohs(nh6->ip6_ctlun.ip6_un1.ip6_un1_plen);
                    ip_len += seq_skew;
                    nh6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(ip_len);
                    conn_seq_skew_set(ct, &conn_for_expectation->key, now,
                                      seq_skew, ctx->reply);
                }
            } else {
                seq_skew = repl_ftp_v4_addr(pkt, v4_addr_rep, ftp_data_start,
                                            addr_offset_from_ftp_data_start);
                ip_len = ntohs(l3_hdr->ip_tot_len);
                if (seq_skew) {
                    ip_len += seq_skew;
                    l3_hdr->ip_csum = recalc_csum16(l3_hdr->ip_csum,
                                          l3_hdr->ip_tot_len, htons(ip_len));
                    l3_hdr->ip_tot_len = htons(ip_len);
                    conn_seq_skew_set(ct, &conn_for_expectation->key, now,
                                      seq_skew, ctx->reply);
                }
            }
        } else {
            OVS_NOT_REACHED();
        }
    } else {
        OVS_NOT_REACHED();
    }

    struct tcp_header *th = dp_packet_l4(pkt);

    if (do_seq_skew_adj && seq_skew != 0) {
        if (ctx->reply != conn_for_expectation->seq_skew_dir) {

            uint32_t tcp_ack = ntohl(get_16aligned_be32(&th->tcp_ack));

            if ((seq_skew > 0) && (tcp_ack < seq_skew)) {
                /* Should not be possible; will be marked invalid. */
                tcp_ack = 0;
            } else if ((seq_skew < 0) && (UINT32_MAX - tcp_ack < -seq_skew)) {
                tcp_ack = (-seq_skew) - (UINT32_MAX - tcp_ack);
            } else {
                tcp_ack -= seq_skew;
            }
            ovs_be32 new_tcp_ack = htonl(tcp_ack);
            put_16aligned_be32(&th->tcp_ack, new_tcp_ack);
        } else {
            uint32_t tcp_seq = ntohl(get_16aligned_be32(&th->tcp_seq));
            if ((seq_skew > 0) && (UINT32_MAX - tcp_seq < seq_skew)) {
                tcp_seq = seq_skew - (UINT32_MAX - tcp_seq);
            } else if ((seq_skew < 0) && (tcp_seq < -seq_skew)) {
                /* Should not be possible; will be marked invalid. */
                tcp_seq = 0;
            } else {
                tcp_seq += seq_skew;
            }
            ovs_be32 new_tcp_seq = htonl(tcp_seq);
            put_16aligned_be32(&th->tcp_seq, new_tcp_seq);
        }
    }

    th->tcp_csum = 0;
    uint32_t tcp_csum;
    if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        tcp_csum = packet_csum_pseudoheader6(nh6);
    } else {
        tcp_csum = packet_csum_pseudoheader(l3_hdr);
    }
    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    th->tcp_csum = csum_finish(
        csum_continue(tcp_csum, th, tail - (char *) th - pad));
    return;
}

static void
handle_tftp_ctl(struct conntrack *ct,
                const struct conn_lookup_ctx *ctx OVS_UNUSED,
                struct dp_packet *pkt,
                const struct conn *conn_for_expectation,
                long long now OVS_UNUSED,
                enum ftp_ctl_pkt ftp_ctl OVS_UNUSED, bool nat OVS_UNUSED)
{
    expectation_create(ct, conn_for_expectation->key.src.port,
                       conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return;
}
