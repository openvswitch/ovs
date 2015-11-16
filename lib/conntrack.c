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

#include <config.h>
#include "conntrack.h"

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "bitmap.h"
#include "conntrack-private.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "flow.h"
#include "hmap.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "random.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(conntrack);

struct conn_lookup_ctx {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool related;
};

static bool conn_key_extract(struct conntrack *, struct dp_packet *,
                             struct conn_lookup_ctx *, uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
static void conn_key_reverse(struct conn_key *);
static void conn_keys_lookup(struct conntrack *, struct conn_lookup_ctx *,
                             unsigned long maps, unsigned bucket,
                             long long now);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct dp_packet *pkt, struct conn_key *,
                             long long now);
static void delete_conn(struct conn *);
static enum ct_update_res conn_update(struct conn *, struct dp_packet*,
                                      bool reply, long long now);
static bool conn_expired(struct conn *, long long now);
static void set_mark(struct dp_packet *, struct conn *,
                     uint32_t val, uint32_t mask);
static void set_label(struct dp_packet *, struct conn *,
                      const struct ovs_key_ct_labels *val,
                      const struct ovs_key_ct_labels *mask);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_other,
};

/* Initializes the connection tracker 'ct'.  The caller is responbile for
 * calling 'conntrack_destroy()', when the instance is not needed anymore */
void
conntrack_init(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        ct_lock_init(&ct->locks[i]);
        ct_lock_lock(&ct->locks[i]);
        hmap_init(&ct->connections[i]);
        ct_lock_unlock(&ct->locks[i]);
    }
    ct->hash_basis = random_uint32();
    ct->purge_bucket = 0;
    ct->purge_inner_bucket = 0;
    ct->purge_inner_offset = 0;
}

/* Destroys the connection tracker 'ct' and frees all the allocated memory. */
void
conntrack_destroy(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conn *conn, *next;

        ct_lock_lock(&ct->locks[i]);
        HMAP_FOR_EACH_SAFE(conn, next, node, &ct->connections[i]) {
            hmap_remove(&ct->connections[i], &conn->node);
            delete_conn(conn);
        }
        hmap_destroy(&ct->connections[i]);
        ct_lock_unlock(&ct->locks[i]);
        ct_lock_destroy(&ct->locks[i]);
    }
}

static unsigned hash_to_bucket(uint32_t hash)
{
    /* Extract the most significant bits in hash. The least significant bits
     * are already used internally by the hmap implementation. */
    BUILD_ASSERT(CONNTRACK_BUCKETS_SHIFT < 32 && CONNTRACK_BUCKETS_SHIFT >= 1);

    return (hash >> (32 - CONNTRACK_BUCKETS_SHIFT)) % CONNTRACK_BUCKETS;
}

static void
write_ct_md(struct dp_packet *pkt, uint8_t state, uint16_t zone,
            uint32_t mark, ovs_u128 label)
{
    pkt->md.ct_state = state | CS_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = mark;
    pkt->md.ct_label = label;
}

static struct conn *
conn_not_found(struct conntrack *ct, struct dp_packet *pkt,
               struct conn_lookup_ctx *ctx, uint8_t *state, bool commit,
               long long now)
{
    unsigned bucket = hash_to_bucket(ctx->hash);
    struct conn *nc = NULL;

    if (!valid_new(pkt, &ctx->key)) {
        *state |= CS_INVALID;
        return nc;
    }

    *state |= CS_NEW;

    if (commit) {
        nc = new_conn(pkt, &ctx->key, now);

        memcpy(&nc->rev_key, &ctx->key, sizeof nc->rev_key);

        conn_key_reverse(&nc->rev_key);
        hmap_insert(&ct->connections[bucket], &nc->node, ctx->hash);
    }

    return nc;
}

static struct conn *
process_one(struct conntrack *ct, struct dp_packet *pkt,
            struct conn_lookup_ctx *ctx, uint16_t zone,
            bool commit, long long now)
{
    unsigned bucket = hash_to_bucket(ctx->hash);
    struct conn *conn = ctx->conn;
    uint8_t state = 0;

    if (conn) {
        if (ctx->related) {
            state |= CS_RELATED;
            if (ctx->reply) {
                state |= CS_REPLY_DIR;
            }
        } else {
            enum ct_update_res res;

            res = conn_update(conn, pkt, ctx->reply, now);

            switch (res) {
            case CT_UPDATE_VALID:
                state |= CS_ESTABLISHED;
                if (ctx->reply) {
                    state |= CS_REPLY_DIR;
                }
                break;
            case CT_UPDATE_INVALID:
                state |= CS_INVALID;
                break;
            case CT_UPDATE_NEW:
                hmap_remove(&ct->connections[bucket], &conn->node);
                delete_conn(conn);
                conn = conn_not_found(ct, pkt, ctx, &state, commit, now);
                break;
            }
        }

        pkt->md.ct_label = conn->label;
        pkt->md.ct_mark = conn->mark;
        write_ct_md(pkt, state, zone, conn->mark, conn->label);
    } else {
        conn = conn_not_found(ct, pkt, ctx, &state, commit, now);
        write_ct_md(pkt, state, zone, 0, (ovs_u128) {{0}});
    }

    return conn;
}

/* Sends a group of 'cnt' packets ('pkts') through the connection tracker
 * 'ct'.  If 'commit' is true, the packets are allowed to create new entries
 * in the connection tables.  'setmark', if not NULL, should point to a two
 * elements array containing a value and a mask to set the connection mark.
 * 'setlabel' behaves similarly for the connection label.*/
int
conntrack_execute(struct conntrack *ct, struct dp_packet **pkts, size_t cnt,
                  bool commit, uint16_t zone, const uint32_t *setmark,
                  const struct ovs_key_ct_labels *setlabel,
                  const char *helper)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t KEY_ARRAY_SIZE = cnt;
#else
    enum { KEY_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct conn_lookup_ctx ctxs[KEY_ARRAY_SIZE];
    int8_t bucket_list[CONNTRACK_BUCKETS];
    struct {
        unsigned bucket;
        unsigned long maps;
    } arr[KEY_ARRAY_SIZE];
    long long now = time_msec();
    size_t i = 0;
    uint8_t arrcnt = 0;

    BUILD_ASSERT_DECL(sizeof arr[0].maps * CHAR_BIT >= NETDEV_MAX_BURST);

    if (helper) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

        VLOG_WARN_RL(&rl, "ALG helper \"%s\" not supported", helper);
        /* Continue without the helper */
    }

    memset(bucket_list, INT8_C(-1), sizeof bucket_list);
    for (i = 0; i < cnt; i++) {
        unsigned bucket;

        if (!conn_key_extract(ct, pkts[i], &ctxs[i], zone)) {
            write_ct_md(pkts[i], CS_INVALID, zone, 0, (ovs_u128){{0}});
            continue;
        }

        bucket = hash_to_bucket(ctxs[i].hash);
        if (bucket_list[bucket] == INT8_C(-1)) {
            bucket_list[bucket] = arrcnt;

            arr[arrcnt].maps = 0;
            ULLONG_SET1(arr[arrcnt].maps, i);
            arr[arrcnt++].bucket = bucket;
        } else {
            ULLONG_SET1(arr[bucket_list[bucket]].maps, i);
            arr[bucket_list[bucket]].maps |= 1UL << i;
        }
    }

    for (i = 0; i < arrcnt; i++) {
        size_t j;

        ct_lock_lock(&ct->locks[arr[i].bucket]);
        conn_keys_lookup(ct, ctxs, arr[i].maps, arr[i].bucket, now);

        ULLONG_FOR_EACH_1(j, arr[i].maps) {
            struct conn *conn;

            conn = process_one(ct, pkts[j], &ctxs[j], zone, commit, now);

            if (conn && setmark) {
                set_mark(pkts[j], conn, setmark[0], setmark[1]);
            }

            if (conn && setlabel) {
                set_label(pkts[j], conn, &setlabel[0], &setlabel[1]);
            }
        }
        ct_lock_unlock(&ct->locks[arr[i].bucket]);
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

#define CONNTRACK_PURGE_NUM 256

static void
sweep_bucket(struct hmap *bucket, uint32_t *inner_bucket,
             uint32_t *inner_offset, unsigned *left, long long now)
{
    while (*left != 0) {
        struct hmap_node *node;
        struct conn *conn;

        node = hmap_at_position(bucket, inner_bucket, inner_offset);

        if (!node) {
            hmap_shrink(bucket);
            break;
        }

        INIT_CONTAINER(conn, node, node);
        if (conn_expired(conn, now)) {
            hmap_remove(bucket, &conn->node);
            delete_conn(conn);
            (*left)--;
        }
    }
}

/* Cleans up old connection entries.  Should be called periodically. */
void
conntrack_run(struct conntrack *ct)
{
    unsigned bucket = hash_to_bucket(ct->purge_bucket);
    uint32_t inner_bucket = ct->purge_inner_bucket,
             inner_offset = ct->purge_inner_offset;
    unsigned left = CONNTRACK_PURGE_NUM;
    long long now = time_msec();

    while (bucket < CONNTRACK_BUCKETS) {
        ct_lock_lock(&ct->locks[bucket]);
        sweep_bucket(&ct->connections[bucket],
                     &inner_bucket, &inner_offset,
                     &left, now);
        ct_lock_unlock(&ct->locks[bucket]);

        if (left == 0) {
            break;
        } else {
            bucket++;
        }
    }

    ct->purge_bucket = bucket;
    ct->purge_inner_bucket = inner_bucket;
    ct->purge_inner_offset = inner_offset;
}

/* Key extraction */

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks. */
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ip_header *ip = data;

    if (new_data) {
        size_t ip_len;

        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            return false;
        }
        ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

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
    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag = 0;

    if (new_data) {
        if (OVS_UNLIKELY(size < sizeof *ip6)) {
            return false;
        }
    }

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
check_l4_tcp(const void *data, size_t size)
{
    const struct tcp_header *tcp = data;
    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

    if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= size)) {
        return true;
    }

    return false;
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

    return true;
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

    return true;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related);

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
    case ICMP_ECHO_REQUEST:
    case ICMP_ECHO_REPLY:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFOREQUEST:
    case ICMP_INFOREPLY:
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = icmp->icmp_fields.echo.id;
        break;
    case ICMP_DST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAM_PROB:
    case ICMP_SOURCEQUENCH:
    case ICMP_REDIRECT: {
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
        *related = true;

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
        ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned
            || inner_key.dst.addr.ipv4_aligned != key->src.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL);
        if (ok) {
            conn_key_reverse(key);
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
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
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = *(ovs_be16 *) (icmp6 + 1);
        break;
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB:{
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
        *related = true;

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

        ok = extract_l4(key, l4, tail - l4, NULL);
        if (ok) {
            conn_key_reverse(key);
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

/* Extract l4 fields into 'key', which must already contain valid l3
 * members.  If 'related' is not NULL and an ICMP error packet is being
 * processed, the function will extract the key from the packet nested
 * in the ICMP paylod and set '*related' to true.  If 'related' is NULL,
 * nested parsing isn't allowed.  This is necessary to limit the
 * recursion level. */
static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return extract_l4_tcp(key, data, size)
               && (!related || check_l4_tcp(data, size));
    } else if (key->nw_proto == IPPROTO_UDP) {
        return extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return extract_l4_icmp6(key, data, size, related);
    } else {
        return false;
    }
}

static bool
conn_key_extract(struct conntrack *ct, struct dp_packet *pkt,
                 struct conn_lookup_ctx *ctx, uint16_t zone)
{
    const struct eth_header *l2 = dp_packet_l2(pkt);
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
     * 2) To extract the l3 and l4 types.
     *    Extracting the l3 and l4 types (especially the l3[1]) on the
     *    other hand is quite expensive, because they're not at a
     *    fixed location.
     *
     * Here's a way to avoid (2) with the help of the datapath.
     * The datapath doesn't keep the packet's extracted flow[2], so
     * using that is not an option.  We could use the packet's matching
     * megaflow, but we have to make sure that the l3 and l4 types
     * are unwildcarded.  This means either:
     *
     * a) dpif-netdev unwildcards the l3 (and l4) types when a new flow
     *    is installed if the actions contains ct().  This is what the
     *    kernel datapath does.  It is not so straightforward, though.
     *
     * b) ofproto-dpif-xlate unwildcards the l3 (and l4) types when
     *    translating a ct() action.  This is already done in different
     *    actions and since both the userspace and the kernel datapath
     *    would benefit from it, it seems an appropriate place to do
     *    it.
     *
     * ---
     * [1] A simple benchmark (running only the connection tracker
     *     over and over on the same packets) shows that if the
     *     l3 type is already provided we are 15% faster (running the
     *     connection tracker over a couple of DPDK devices with a
     *     stream of UDP 64-bytes packets shows that we are 4% faster).
     *
     * [2] The reasons for this are that keeping the flow increases
     *     (slightly) the cache footprint and increases computation
     *     time as we move the packet around. Most importantly, the flow
     *     should be updated by the actions and this can be slow, as
     *     we use a sparse representation (miniflow).
     *
     */
    ctx->key.dl_type = parse_dl_type(l2, (char *) l3 - (char *) l2);
    if (ctx->key.dl_type == htons(ETH_TYPE_IP)) {
        ok = extract_l3_ipv4(&ctx->key, l3, tail - (char *) l3, NULL);
    } else if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&ctx->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        if (extract_l4(&ctx->key, l4, tail - l4, &ctx->related)) {
            ctx->hash = conn_key_hash(&ctx->key, ct->hash_basis);
            return true;
        }
    }

    return false;
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;
    int i;

    hsrc = hdst = basis;

    for (i = 0; i < sizeof(key->src) / sizeof(uint32_t); i++) {
        hsrc = hash_add(hsrc, ((uint32_t *) &key->src)[i]);
        hdst = hash_add(hdst, ((uint32_t *) &key->dst)[i]);
    }

    hash = hsrc ^ hdst;

    hash = hash_words((uint32_t *) &key->dst + 1,
                      (uint32_t *) (key + 1) - (uint32_t *) (&key->dst + 1),
                      hash);

    return hash;
}

static void
conn_key_reverse(struct conn_key *key)
{
    struct ct_endpoint tmp;
    tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static void
conn_keys_lookup(struct conntrack *ct,
                 struct conn_lookup_ctx *keys,
                 unsigned long maps,
                 unsigned bucket,
                 long long now)
{
    size_t i;

    ULLONG_FOR_EACH_1(i, maps) {
        struct conn *conn, *found = NULL;
        uint32_t hash = keys[i].hash;
        bool reply;

        HMAP_FOR_EACH_WITH_HASH(conn, node, hash, &ct->connections[bucket]) {
            if (!memcmp(&conn->key, &keys[i].key, sizeof(conn->key))) {
                found = conn;
                reply = false;
                break;
            }
            if (!memcmp(&conn->rev_key, &keys[i].key, sizeof(conn->rev_key))) {
                found = conn;
                reply = true;
                break;
            }
        }

        if (found) {
            if (conn_expired(found, now)) {
                found = NULL;
            } else {
                keys[i].reply = reply;
            }
        }

        keys[i].conn = found;
    }
}

static enum ct_update_res
conn_update(struct conn *conn, struct dp_packet *pkt, bool reply,
            long long now)
{
    return l4_protos[conn->key.nw_proto]->conn_update(conn, pkt, reply, now);
}

static bool
conn_expired(struct conn *conn, long long now)
{
    return now >= conn->expiration;
}

static bool
valid_new(struct dp_packet *pkt, struct conn_key *key)
{
    return l4_protos[key->nw_proto]->valid_new(pkt);
}

static struct conn *
new_conn(struct dp_packet *pkt, struct conn_key *key, long long now)
{
    struct conn *newconn;

    newconn = l4_protos[key->nw_proto]->new_conn(pkt, now);

    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static void
delete_conn(struct conn *conn)
{
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

    if (key->nw_proto == IPPROTO_ICMP) {
        tuple->icmp_id = key->src.port;
        /* ICMP type and code are not tracked */
        tuple->icmp_type = 0;
        tuple->icmp_code = 0;
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

    memcpy(&entry->labels, &conn->label, sizeof(entry->labels));
    /* Not implemented yet */
    entry->timestamp.start = 0;
    entry->timestamp.stop = 0;

    expiration = conn->expiration - now;
    entry->timeout = (expiration > 0) ? expiration / 1000: 0;

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

        ct_lock_lock(&ct->locks[dump->bucket]);
        for (;;) {
            struct conn *conn;

            node = hmap_at_position(&ct->connections[dump->bucket],
                                    &dump->inner_bucket,
                                    &dump->inner_offset);
            if (!node) {
                break;
            }
            INIT_CONTAINER(conn, node, node);
            if (!dump->filter_zone || conn->key.zone == dump->zone) {
                conn_to_ct_dpif_entry(conn, entry, now);
                break;
            }
            /* Else continue, until we find an entry in the appropriate zone
             * or the bucket has been scanned completely. */
        }
        ct_lock_unlock(&ct->locks[dump->bucket]);

        if (!node) {
            dump->inner_bucket = 0;
            dump->inner_offset = 0;
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

        ct_lock_lock(&ct->locks[i]);
        HMAP_FOR_EACH_SAFE(conn, next, node, &ct->connections[i]) {
            if (!zone || *zone == conn->key.zone) {
                hmap_remove(&ct->connections[i], &conn->node);
                delete_conn(conn);
            }
        }
        ct_lock_unlock(&ct->locks[i]);
    }

    return 0;
}
