/*
 * Copyright (c) 2018 Nicira, Inc.
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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <string.h>

#include "coverage.h"
#include "csum.h"
#include "ipf.h"
#include "latch.h"
#include "openvswitch/hmap.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ipf);
COVERAGE_DEFINE(ipf_stuck_frag_list_purged);

enum {
    IPV4_PACKET_MAX_HDR_SIZE = 60,
    IPV4_PACKET_MAX_SIZE = 65535,
    IPV6_PACKET_MAX_DATA = 65535,
};

enum ipf_list_state {
    IPF_LIST_STATE_UNUSED,
    IPF_LIST_STATE_REASS_FAIL,
    IPF_LIST_STATE_OTHER_SEEN,
    IPF_LIST_STATE_FIRST_SEEN,
    IPF_LIST_STATE_LAST_SEEN,
    IPF_LIST_STATE_FIRST_LAST_SEEN,
    IPF_LIST_STATE_COMPLETED,
    IPF_LIST_STATE_NUM,
};

enum ipf_list_type {
    IPF_FRAG_COMPLETED_LIST,
    IPF_FRAG_EXPIRY_LIST,
};

enum {
    IPF_INVALID_IDX = -1,
    IPF_V4_FRAG_SIZE_LBOUND = 400,
    IPF_V4_FRAG_SIZE_MIN_DEF = 1200,
    IPF_V6_FRAG_SIZE_LBOUND = 400, /* Useful for testing. */
    IPF_V6_FRAG_SIZE_MIN_DEF = 1280,
    IPF_MAX_FRAGS_DEFAULT = 1000,
    IPF_NFRAG_UBOUND = 5000,
};

enum ipf_counter_type {
    IPF_COUNTER_NFRAGS,
    IPF_COUNTER_NFRAGS_ACCEPTED,
    IPF_COUNTER_NFRAGS_COMPL_SENT,
    IPF_COUNTER_NFRAGS_EXPD_SENT,
    IPF_COUNTER_NFRAGS_TOO_SMALL,
    IPF_COUNTER_NFRAGS_OVERLAP,
    IPF_COUNTER_NFRAGS_PURGED,
};

struct ipf_addr {
    union {
        ovs_16aligned_be32 ipv4;
        union ovs_16aligned_in6_addr ipv6;
        ovs_be32 ipv4_aligned;
        struct in6_addr ipv6_aligned;
    };
};

struct ipf_frag {
    struct dp_packet *pkt;
    uint16_t start_data_byte;
    uint16_t end_data_byte;
};

struct ipf_list_key {
    struct ipf_addr src_addr;
    struct ipf_addr dst_addr;
    uint32_t recirc_id;
    ovs_be32 ip_id;   /* V6 is 32 bits. */
    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

struct ipf_list {
    struct hmap_node node;
    struct ovs_list list_node;
    struct ipf_frag *frag_list;
    struct ipf_list_key key;
    struct dp_packet *reass_execute_ctx; /* Reassembled packet. */
    long long expiration;          /* In milliseconds. */
    int last_sent_idx;             /* Last sent fragment idx. */
    int last_inuse_idx;            /* Last inuse fragment idx. */
    int size;                      /* Fragment list size. */
    uint8_t state;                 /* Frag list state; see ipf_list_state. */
};

struct reassembled_pkt {
    struct ovs_list rp_list_node;
    struct dp_packet *pkt;
    struct ipf_list *list;
};

struct OVS_LOCKABLE ipf_lock {
    struct ovs_mutex lock;
};

static struct ipf_lock ipf_lock;

static int max_v4_frag_list_size;

static pthread_t ipf_clean_thread;
static struct latch ipf_clean_thread_exit;

static struct hmap frag_lists OVS_GUARDED_BY(ipf_lock);
static struct ovs_list frag_exp_list OVS_GUARDED_BY(ipf_lock);
static struct ovs_list frag_complete_list OVS_GUARDED_BY(ipf_lock);
static struct ovs_list reassembled_pkt_list OVS_GUARDED_BY(ipf_lock);

static atomic_bool ifp_v4_enabled;
static atomic_bool ifp_v6_enabled;
static atomic_uint nfrag_max;
/* Will be clamped above 400 bytes; the value chosen should handle
 * alg control packets of interest that use string encoding of mutable
 * IP fields; meaning, the control packets should not be fragmented. */
static atomic_uint min_v4_frag_size;
static atomic_uint min_v6_frag_size;

static atomic_count nfrag;

static atomic_uint64_t n4frag_accepted;
static atomic_uint64_t n4frag_completed_sent;
static atomic_uint64_t n4frag_expired_sent;
static atomic_uint64_t n4frag_too_small;
static atomic_uint64_t n4frag_overlap;
static atomic_uint64_t n4frag_purged;
static atomic_uint64_t n6frag_accepted;
static atomic_uint64_t n6frag_completed_sent;
static atomic_uint64_t n6frag_expired_sent;
static atomic_uint64_t n6frag_too_small;
static atomic_uint64_t n6frag_overlap;
static atomic_uint64_t n6frag_purged;

static void
ipf_print_reass_packet(char *es, void *pkt)
{
    const unsigned char *b = (const unsigned char *) pkt;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    VLOG_WARN_RL(&rl, "%s 91 bytes from specified part of packet "
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                 "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                 es, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8],
                 b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16],
                 b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24],
                 b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32],
                 b[33], b[34], b[35], b[36], b[37], b[38], b[39], b[40],
                 b[41], b[42], b[43], b[44], b[45], b[46], b[47], b[48],
                 b[49], b[50], b[51], b[52], b[53], b[54], b[55], b[56],
                 b[57], b[58], b[59], b[60], b[61], b[62], b[63], b[64],
                 b[65], b[66], b[67], b[68], b[69], b[70], b[71], b[72],
                 b[73], b[74], b[75], b[76], b[77], b[77], b[79], b[80],
                 b[81], b[82], b[83], b[84], b[85], b[86], b[87], b[88],
                 b[89], b[90]);
}

static void ipf_lock_init(struct ipf_lock *lock)
{
    ovs_mutex_init_adaptive(&lock->lock);
}

static void ipf_lock_lock(struct ipf_lock *lock)
    OVS_ACQUIRES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_lock(&lock->lock);
}

static void ipf_lock_unlock(struct ipf_lock *lock)
    OVS_RELEASES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_unlock(&lock->lock);
}

static void ipf_lock_destroy(struct ipf_lock *lock)
{
    ovs_mutex_destroy(&lock->lock);
}

static void
ipf_count(bool v6, enum ipf_counter_type cntr)
{
    switch (cntr) {
    case IPF_COUNTER_NFRAGS_ACCEPTED:
        atomic_count_inc64(v6 ? &n6frag_accepted : &n4frag_accepted);
        break;
    case IPF_COUNTER_NFRAGS_COMPL_SENT:
        atomic_count_inc64(v6 ? &n6frag_completed_sent
                         : &n4frag_completed_sent);
        break;
    case IPF_COUNTER_NFRAGS_EXPD_SENT:
        atomic_count_inc64(v6 ? &n6frag_expired_sent
                         : &n4frag_expired_sent);
        break;
    case IPF_COUNTER_NFRAGS_TOO_SMALL:
        atomic_count_inc64(v6 ? &n6frag_too_small : &n4frag_too_small);
        break;
    case IPF_COUNTER_NFRAGS_OVERLAP:
        atomic_count_inc64(v6 ? &n6frag_overlap : &n4frag_overlap);
        break;
    case IPF_COUNTER_NFRAGS_PURGED:
        atomic_count_inc64(v6 ? &n6frag_purged : &n4frag_purged);
        break;
    case IPF_COUNTER_NFRAGS:
    default:
        OVS_NOT_REACHED();
    }
}

static bool
ipf_get_v4_enabled(void)
{
    bool ifp_v4_enabled_;
    atomic_read_relaxed(&ifp_v4_enabled, &ifp_v4_enabled_);
    return ifp_v4_enabled_;
}

static bool
ipf_get_v6_enabled(void)
{
    bool ifp_v6_enabled_;
    atomic_read_relaxed(&ifp_v6_enabled, &ifp_v6_enabled_);
    return ifp_v6_enabled_;
}

static bool
ipf_get_enabled(void)
{
    return ipf_get_v4_enabled() || ipf_get_v6_enabled();
}

static uint32_t
ipf_addr_hash_add(uint32_t hash, const struct ipf_addr *addr)
{
    BUILD_ASSERT_DECL(sizeof *addr % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) addr, sizeof *addr);
}

static void
ipf_expiry_list_add(struct ipf_list *ipf_list, long long now)
    OVS_REQUIRES(ipf_lock)
{
    enum {
        IPF_FRAG_LIST_TIMEOUT = 15000,
    };

    ipf_list->expiration = now + IPF_FRAG_LIST_TIMEOUT;
    ovs_list_push_back(&frag_exp_list, &ipf_list->list_node);
}

static void
ipf_completed_list_add(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    ovs_list_push_back(&frag_complete_list, &ipf_list->list_node);
}

static void
ipf_reassembled_list_add(struct reassembled_pkt *rp)
    OVS_REQUIRES(ipf_lock)
{
    ovs_list_push_back(&reassembled_pkt_list, &rp->rp_list_node);
}

static void
ipf_list_clean(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    ovs_list_remove(&ipf_list->list_node);
    hmap_remove(&frag_lists, &ipf_list->node);
    free(ipf_list->frag_list);
    free(ipf_list);
}

static void
ipf_expiry_list_clean(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    ipf_list_clean(ipf_list);
}

static void
ipf_completed_list_clean(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    ipf_list_clean(ipf_list);
}

static void
ipf_expiry_list_remove(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    ovs_list_remove(&ipf_list->list_node);
}

static void
ipf_reassembled_list_remove(struct reassembled_pkt *rp)
    OVS_REQUIRES(ipf_lock)
{
    ovs_list_remove(&rp->rp_list_node);
}

/* Symmetric */
static uint32_t
ipf_list_key_hash(const struct ipf_list_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;
    hsrc = hdst = basis;
    hsrc = ipf_addr_hash_add(hsrc, &key->src_addr);
    hdst = ipf_addr_hash_add(hdst, &key->dst_addr);
    hash = hsrc ^ hdst;

    /* Hash the rest of the key. */
    hash = hash_words((uint32_t *) (&key->dst_addr + 1),
                      (uint32_t *) (key + 1) -
                          (uint32_t *) (&key->dst_addr + 1),
                      hash);

    return hash_finish(hash, 0);
}

static bool
ipf_is_first_v4_frag(const struct dp_packet *pkt)
{
    const struct ip_header *l3 = dp_packet_l3(pkt);
    if (!(l3->ip_frag_off & htons(IP_FRAG_OFF_MASK)) &&
        l3->ip_frag_off & htons(IP_MORE_FRAGMENTS)) {
        return true;
    }
    return false;
}

static bool
ipf_is_last_v4_frag(const struct dp_packet *pkt)
{
    const struct ip_header *l3 = dp_packet_l3(pkt);
    if (l3->ip_frag_off & htons(IP_FRAG_OFF_MASK) &&
        !(l3->ip_frag_off & htons(IP_MORE_FRAGMENTS))) {
        return true;
    }
    return false;
}

static bool
ipf_is_v6_frag(ovs_be16 ip6f_offlg)
{
    if (ip6f_offlg & (IP6F_OFF_MASK | IP6F_MORE_FRAG)) {
        return true;
    }
    return false;
}

static bool
ipf_is_first_v6_frag(ovs_be16 ip6f_offlg)
{
    if (!(ip6f_offlg & IP6F_OFF_MASK) &&
        ip6f_offlg & IP6F_MORE_FRAG) {
        return true;
    }
    return false;
}

static bool
ipf_is_last_v6_frag(ovs_be16 ip6f_offlg)
{
    if ((ip6f_offlg & IP6F_OFF_MASK) &&
        !(ip6f_offlg & IP6F_MORE_FRAG)) {
        return true;
    }
    return false;
}

static bool
ipf_list_complete(const struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    for (int i = 0; i < ipf_list->last_inuse_idx; i++) {
        if (ipf_list->frag_list[i].end_data_byte + 1
            != ipf_list->frag_list[i + 1].start_data_byte) {
            return false;
        }
    }
    return true;
}

/* Runs O(n) for a sorted or almost sorted list. */
static void
ipf_sort(struct ipf_frag *frag_list, size_t last_idx)
    OVS_REQUIRES(ipf_lock)
{
    int running_last_idx = 1;
    struct ipf_frag ipf_frag;
    while (running_last_idx <= last_idx) {
        ipf_frag = frag_list[running_last_idx];
        int frag_list_idx = running_last_idx - 1;
        while (frag_list_idx >= 0 &&
               frag_list[frag_list_idx].start_data_byte >
                   ipf_frag.start_data_byte) {
            frag_list[frag_list_idx + 1] = frag_list[frag_list_idx];
            frag_list_idx -= 1;
        }
        frag_list[frag_list_idx + 1] = ipf_frag;
        running_last_idx++;
    }
}

/* Called on a sorted complete list of fragments. */
static struct dp_packet *
ipf_reassemble_v4_frags(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    struct ipf_frag *frag_list = ipf_list->frag_list;
    struct dp_packet *pkt = dp_packet_clone(frag_list[0].pkt);
    struct ip_header *l3 = dp_packet_l3(pkt);
    int len = ntohs(l3->ip_tot_len);
    size_t add_len;
    size_t ip_hdr_len = IP_IHL(l3->ip_ihl_ver) * 4;

    for (int i = 1; i <= ipf_list->last_inuse_idx; i++) {
        add_len = frag_list[i].end_data_byte -
                         frag_list[i].start_data_byte + 1;
        len += add_len;
        if (len > IPV4_PACKET_MAX_SIZE) {
            ipf_print_reass_packet(
                "Unsupported big reassembled v4 packet; v4 hdr:", l3);
            dp_packet_delete(pkt);
            return NULL;
        }
        l3 = dp_packet_l3(frag_list[i].pkt);
        dp_packet_put(pkt, (char *)l3 + ip_hdr_len, add_len);
    }
    l3 = dp_packet_l3(pkt);
    ovs_be16 new_ip_frag_off = l3->ip_frag_off & ~htons(IP_MORE_FRAGMENTS);
    l3->ip_csum = recalc_csum16(l3->ip_csum, l3->ip_frag_off,
                                new_ip_frag_off);
    l3->ip_csum = recalc_csum16(l3->ip_csum, l3->ip_tot_len, htons(len));
    l3->ip_tot_len = htons(len);
    l3->ip_frag_off = new_ip_frag_off;

    return pkt;
}

/* Called on a sorted complete list of fragments. */
static struct dp_packet *
ipf_reassemble_v6_frags(struct ipf_list *ipf_list)
    OVS_REQUIRES(ipf_lock)
{
    struct ipf_frag *frag_list = ipf_list->frag_list;
    struct dp_packet *pkt = dp_packet_clone(frag_list[0].pkt);
    struct  ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    int pl = ntohs(l3->ip6_plen) - sizeof(struct ovs_16aligned_ip6_frag);
    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    const char *l4 = dp_packet_l4(pkt);
    size_t l3_size = tail - (char *)l3 - pad;
    size_t l4_size = tail - (char *)l4 - pad;
    size_t l3_hlen = l3_size - l4_size;
    size_t add_len;

    for (int i = 1; i <= ipf_list->last_inuse_idx; i++) {
        add_len = frag_list[i].end_data_byte -
                          frag_list[i].start_data_byte + 1;
        pl += add_len;
        if (pl > IPV6_PACKET_MAX_DATA) {
            ipf_print_reass_packet(
                "Unsupported big reassembled v6 packet; v6 hdr:", l3);
            dp_packet_delete(pkt);
            return NULL;
        }
        l3 = dp_packet_l3(frag_list[i].pkt);
        dp_packet_put(pkt, (char *)l3 + l3_hlen, add_len);
    }
    l3 = dp_packet_l3(pkt);
    l4 = dp_packet_l4(pkt);
    tail = dp_packet_tail(pkt);
    pad = dp_packet_l2_pad_size(pkt);
    l3_size = tail - (char *)l3 - pad;

    uint8_t nw_proto = l3->ip6_nxt;
    uint8_t nw_frag = 0;
    const void *data = l3 + 1;
    size_t datasize = l3_size - sizeof *l3;

    const struct ovs_16aligned_ip6_frag *frag_hdr = NULL;
    if (!parse_ipv6_ext_hdrs(&data, &datasize, &nw_proto, &nw_frag, &frag_hdr)
        || !nw_frag || !frag_hdr) {

        ipf_print_reass_packet("Unparsed reassembled v6 packet; v6 hdr:", l3);
        dp_packet_delete(pkt);
        return NULL;
    }

    struct ovs_16aligned_ip6_frag *fh =
        CONST_CAST(struct ovs_16aligned_ip6_frag *, frag_hdr);
    fh->ip6f_offlg = 0;
    l3->ip6_plen = htons(pl);
    l3->ip6_ctlun.ip6_un1.ip6_un1_nxt = nw_proto;
    return pkt;
}

/* Called when a valid fragment is added. */
static void
ipf_list_state_transition(struct ipf_list *ipf_list, bool ff, bool lf,
                          bool v6)
    OVS_REQUIRES(ipf_lock)
{
    enum ipf_list_state curr_state = ipf_list->state;
    enum ipf_list_state next_state;
    switch (curr_state) {
    case IPF_LIST_STATE_UNUSED:
    case IPF_LIST_STATE_OTHER_SEEN:
        if (ff) {
            next_state = IPF_LIST_STATE_FIRST_SEEN;
        } else if (lf) {
            next_state = IPF_LIST_STATE_LAST_SEEN;
        } else {
            next_state = IPF_LIST_STATE_OTHER_SEEN;
        }
        break;
    case IPF_LIST_STATE_FIRST_SEEN:
        if (ff) {
            next_state = IPF_LIST_STATE_FIRST_SEEN;
        } else if (lf) {
            next_state = IPF_LIST_STATE_FIRST_LAST_SEEN;
        } else {
            next_state = IPF_LIST_STATE_FIRST_SEEN;
        }
        break;
    case IPF_LIST_STATE_LAST_SEEN:
        if (ff) {
            next_state = IPF_LIST_STATE_FIRST_LAST_SEEN;
        } else if (lf) {
            next_state = IPF_LIST_STATE_LAST_SEEN;
        } else {
            next_state = IPF_LIST_STATE_LAST_SEEN;
        }
        break;
    case IPF_LIST_STATE_FIRST_LAST_SEEN:
        next_state = IPF_LIST_STATE_FIRST_LAST_SEEN;
        break;
    case IPF_LIST_STATE_COMPLETED:
    case IPF_LIST_STATE_REASS_FAIL:
    case IPF_LIST_STATE_NUM:
    default:
        OVS_NOT_REACHED();
    }

    if (next_state == IPF_LIST_STATE_FIRST_LAST_SEEN) {
        ipf_sort(ipf_list->frag_list, ipf_list->last_inuse_idx);
        if (ipf_list_complete(ipf_list)) {
            struct dp_packet *reass_pkt = v6
                ? ipf_reassemble_v6_frags(ipf_list)
                : ipf_reassemble_v4_frags(ipf_list);
            if (reass_pkt) {
                struct reassembled_pkt *rp = xzalloc(sizeof *rp);
                rp->pkt = reass_pkt;
                rp->list = ipf_list;
                ipf_reassembled_list_add(rp);
                ipf_expiry_list_remove(ipf_list);
                next_state = IPF_LIST_STATE_COMPLETED;
            } else {
                next_state = IPF_LIST_STATE_REASS_FAIL;
            }
        }
    }
    ipf_list->state = next_state;
}

static bool
ipf_is_valid_v4_frag(struct dp_packet *pkt)
{
    if (OVS_UNLIKELY(dp_packet_ip_checksum_bad(pkt))) {
        goto invalid_pkt;
    }

    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);

    if (OVS_UNLIKELY(!l2 || !l3)) {
        goto invalid_pkt;
    }

    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    size_t size = tail - (char *)l3 - pad;
    if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
        goto invalid_pkt;
    }

    if (!(IP_IS_FRAGMENT(l3->ip_frag_off))) {
        return false;
    }

    uint16_t ip_tot_len = ntohs(l3->ip_tot_len);
    if (OVS_UNLIKELY(ip_tot_len != size)) {
        goto invalid_pkt;
    }

    size_t ip_hdr_len = IP_IHL(l3->ip_ihl_ver) * 4;
    if (OVS_UNLIKELY(ip_hdr_len < IP_HEADER_LEN)) {
        goto invalid_pkt;
    }
    if (OVS_UNLIKELY(size < ip_hdr_len)) {
        goto invalid_pkt;
    }

    if (OVS_UNLIKELY(!dp_packet_ip_checksum_valid(pkt)
                     && csum(l3, ip_hdr_len) != 0)) {
        goto invalid_pkt;
    }

    uint32_t min_v4_frag_size_;
    atomic_read_relaxed(&min_v4_frag_size, &min_v4_frag_size_);
    bool lf = ipf_is_last_v4_frag(pkt);
    if (OVS_UNLIKELY(!lf && dp_packet_size(pkt) < min_v4_frag_size_)) {
        ipf_count(false, IPF_COUNTER_NFRAGS_TOO_SMALL);
        goto invalid_pkt;
    }
    return true;

invalid_pkt:
    pkt->md.ct_state = CS_INVALID;
    return false;

}

static bool
ipf_v4_key_extract(struct dp_packet *pkt, ovs_be16 dl_type, uint16_t zone,
                   struct ipf_list_key *key, uint16_t *start_data_byte,
                   uint16_t *end_data_byte, bool *ff, bool *lf)
{
    const struct ip_header *l3 = dp_packet_l3(pkt);
    uint16_t ip_tot_len = ntohs(l3->ip_tot_len);
    size_t ip_hdr_len = IP_IHL(l3->ip_ihl_ver) * 4;

    *start_data_byte = ntohs(l3->ip_frag_off & htons(IP_FRAG_OFF_MASK)) * 8;
    *end_data_byte = *start_data_byte + ip_tot_len - ip_hdr_len - 1;
    *ff = ipf_is_first_v4_frag(pkt);
    *lf = ipf_is_last_v4_frag(pkt);
    memset(key, 0, sizeof *key);
    key->ip_id = be16_to_be32(l3->ip_id);
    key->dl_type = dl_type;
    key->src_addr.ipv4 = l3->ip_src;
    key->dst_addr.ipv4 = l3->ip_dst;
    key->nw_proto = l3->ip_proto;
    key->zone = zone;
    key->recirc_id = pkt->md.recirc_id;
    return true;
}

static bool
ipf_is_valid_v6_frag(struct dp_packet *pkt OVS_UNUSED)
{
    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct  ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);

    if (OVS_UNLIKELY(!l2 || !l3 || !l4)) {
        goto invalid_pkt;
    }

    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    size_t l3_size = tail - (char *)l3 - pad;
    size_t l3_hdr_size = sizeof *l3;

    if (OVS_UNLIKELY(l3_size < l3_hdr_size)) {
        goto invalid_pkt;
    }

    uint8_t nw_frag = 0;
    uint8_t nw_proto = l3->ip6_nxt;
    const void *data = l3 + 1;
    size_t datasize = l3_size - l3_hdr_size;
    const struct ovs_16aligned_ip6_frag *frag_hdr = NULL;
    if (!parse_ipv6_ext_hdrs(&data, &datasize, &nw_proto, &nw_frag,
                             &frag_hdr) || !nw_frag || !frag_hdr) {
        return false;
    }

    int pl = ntohs(l3->ip6_plen);
    if (OVS_UNLIKELY(pl + l3_hdr_size != l3_size)) {
        goto invalid_pkt;
    }

    ovs_be16 ip6f_offlg = frag_hdr->ip6f_offlg;
    if (OVS_UNLIKELY(!ipf_is_v6_frag(ip6f_offlg))) {
        return false;
    }

    uint32_t min_v6_frag_size_;
    atomic_read_relaxed(&min_v6_frag_size, &min_v6_frag_size_);
    bool lf = ipf_is_last_v6_frag(ip6f_offlg);

    if (OVS_UNLIKELY(!lf && dp_packet_size(pkt) < min_v6_frag_size_)) {
        ipf_count(true, IPF_COUNTER_NFRAGS_TOO_SMALL);
        goto invalid_pkt;
    }

    return true;

invalid_pkt:
    pkt->md.ct_state = CS_INVALID;
    return false;

}

static void
ipf_v6_key_extract(struct dp_packet *pkt, ovs_be16 dl_type, uint16_t zone,
                   struct ipf_list_key *key, uint16_t *start_data_byte,
                   uint16_t *end_data_byte, bool *ff, bool *lf)
{
    const struct  ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);
    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    size_t l3_size = tail - (char *)l3 - pad;
    size_t l4_size = tail - (char *)l4 - pad;
    size_t l3_hdr_size = sizeof *l3;
    uint8_t nw_frag = 0;
    uint8_t nw_proto = l3->ip6_nxt;
    const void *data = l3 + 1;
    size_t datasize = l3_size - l3_hdr_size;
    const struct ovs_16aligned_ip6_frag *frag_hdr = NULL;

    parse_ipv6_ext_hdrs(&data, &datasize, &nw_proto, &nw_frag, &frag_hdr);
    ovs_assert(nw_frag && frag_hdr);
    ovs_be16 ip6f_offlg = frag_hdr->ip6f_offlg;
    *start_data_byte = ntohs(ip6f_offlg & IP6F_OFF_MASK) +
        sizeof (struct ovs_16aligned_ip6_frag);
    *end_data_byte = *start_data_byte + l4_size - 1;
    *ff = ipf_is_first_v6_frag(ip6f_offlg);
    *lf = ipf_is_last_v6_frag(ip6f_offlg);
    memset(key, 0, sizeof *key);
    key->ip_id = get_16aligned_be32(&frag_hdr->ip6f_ident);
    key->dl_type = dl_type;
    key->src_addr.ipv6 = l3->ip6_src;
    /* We are not supporting parsing of the routing header to use as the
     * dst address part of the key. */
    key->dst_addr.ipv6 = l3->ip6_dst;
    key->nw_proto = 0;   /* Not used for key for V6. */
    key->zone = zone;
    key->recirc_id = pkt->md.recirc_id;
}

static int
ipf_list_key_cmp(const struct ipf_list_key *key1,
                 const struct ipf_list_key *key2)
    OVS_REQUIRES(ipf_lock)
{
    if (!memcmp(&key1->src_addr, &key2->src_addr, sizeof key1->src_addr) &&
        !memcmp(&key1->dst_addr, &key2->dst_addr, sizeof key1->dst_addr) &&
        (key1->dl_type == key2->dl_type) &&
        (key1->ip_id == key2->ip_id) &&
        (key1->zone == key2->zone) &&
        (key1->nw_proto == key2->nw_proto) &&
        (key1->recirc_id == key2->recirc_id)) {
        return 0;
    }
    return 1;
}

static struct ipf_list *
ipf_list_key_lookup(const struct ipf_list_key *key,
                    uint32_t hash)
    OVS_REQUIRES(ipf_lock)
{
    struct ipf_list *ipf_list;
    HMAP_FOR_EACH_WITH_HASH (ipf_list, node, hash, &frag_lists) {
        if (!ipf_list_key_cmp(&ipf_list->key, key)) {
            return ipf_list;
        }
    }
    return NULL;
}

static bool
ipf_is_frag_duped(const struct ipf_frag *frag_list, int last_inuse_idx,
                  size_t start_data_byte, size_t end_data_byte)
    OVS_REQUIRES(ipf_lock)
{
    for (int i = 0; i <= last_inuse_idx; i++) {
        if (((start_data_byte >= frag_list[i].start_data_byte) &&
            (start_data_byte <= frag_list[i].end_data_byte)) ||
            ((end_data_byte >= frag_list[i].start_data_byte) &&
             (end_data_byte <= frag_list[i].end_data_byte))) {
            return true;
        }
    }
    return false;
}

static bool
ipf_process_frag(struct ipf_list *ipf_list, struct dp_packet *pkt,
                 uint16_t start_data_byte, uint16_t end_data_byte,
                 bool ff, bool lf, bool v6)
    OVS_REQUIRES(ipf_lock)
{
    bool duped_frag = ipf_is_frag_duped(ipf_list->frag_list,
        ipf_list->last_inuse_idx, start_data_byte, end_data_byte);
    int last_inuse_idx = ipf_list->last_inuse_idx;

    if (!duped_frag) {
        if (last_inuse_idx < ipf_list->size - 1) {
            /* In the case of dpdk, it would be unfortunate if we had
             * to create a clone fragment outside the dpdk mp due to the
             * mempool size being too limited. We will otherwise need to
             * recommend not setting the mempool number of buffers too low
             * and also clamp the number of fragments. */
            ipf_list->frag_list[last_inuse_idx + 1].pkt = pkt;
            ipf_list->frag_list[last_inuse_idx + 1].start_data_byte =
                start_data_byte;
            ipf_list->frag_list[last_inuse_idx + 1].end_data_byte =
                end_data_byte;
            ipf_list->last_inuse_idx++;
            atomic_count_inc(&nfrag);
            ipf_count(v6, IPF_COUNTER_NFRAGS_ACCEPTED);
            ipf_list_state_transition(ipf_list, ff, lf, v6);
        } else {
            OVS_NOT_REACHED();
        }
    } else {
        ipf_count(v6, IPF_COUNTER_NFRAGS_OVERLAP);
        pkt->md.ct_state = CS_INVALID;
        return false;
    }
    return true;
}

static bool
ipf_handle_frag(struct dp_packet *pkt, ovs_be16 dl_type, uint16_t zone,
                long long now, uint32_t hash_basis)
    OVS_REQUIRES(ipf_lock)
{
    struct ipf_list_key key;
    /* Initialize 4 variables for some versions of GCC. */
    uint16_t start_data_byte = 0;
    uint16_t end_data_byte = 0;
    bool ff = false;
    bool lf = false;
    bool v6 = dl_type == htons(ETH_TYPE_IPV6);

    if (v6 && ipf_get_v6_enabled()) {
        ipf_v6_key_extract(pkt, dl_type, zone, &key, &start_data_byte,
                           &end_data_byte, &ff, &lf);
    } else if (!v6 && ipf_get_v4_enabled()) {
        ipf_v4_key_extract(pkt, dl_type, zone, &key, &start_data_byte,
                           &end_data_byte, &ff, &lf);
    } else {
        OVS_NOT_REACHED();
    }

    unsigned int nfrag_max_;
    atomic_read_relaxed(&nfrag_max, &nfrag_max_);
    if (atomic_count_get(&nfrag) >= nfrag_max_) {
        return false;
    }

    uint32_t hash = ipf_list_key_hash(&key, hash_basis);
    struct ipf_list *ipf_list = ipf_list_key_lookup(&key, hash);
    enum {
        IPF_FRAG_LIST_MIN_INCREMENT = 4,
        IPF_IPV6_MAX_FRAG_LIST_SIZE = 65535,
    };

    int max_frag_list_size;
    if (v6) {
        /* Because the calculation with extension headers is variable,
         * we don't calculate a hard maximum fragment list size upfront.  The
         * fragment list size is practically limited by the code, however. */
        max_frag_list_size = IPF_IPV6_MAX_FRAG_LIST_SIZE;
    } else {
        max_frag_list_size = max_v4_frag_list_size;
    }

    if (!ipf_list) {
        ipf_list = xzalloc(sizeof *ipf_list);
        ipf_list->key = key;
        ipf_list->last_inuse_idx = IPF_INVALID_IDX;
        ipf_list->last_sent_idx = IPF_INVALID_IDX;
        ipf_list->size =
            MIN(max_frag_list_size, IPF_FRAG_LIST_MIN_INCREMENT);
        ipf_list->frag_list =
            xzalloc(ipf_list->size * sizeof *ipf_list->frag_list);
        hmap_insert(&frag_lists, &ipf_list->node, hash);
        ipf_expiry_list_add(ipf_list, now);
    } else if (ipf_list->state == IPF_LIST_STATE_REASS_FAIL) {
        /* Bail out as early as possible. */
        return false;
    } else if (ipf_list->last_inuse_idx + 1 >= ipf_list->size) {
        int increment = MIN(IPF_FRAG_LIST_MIN_INCREMENT,
                            max_frag_list_size - ipf_list->size);
        /* Enforce limit. */
        if (increment > 0) {
            ipf_list->frag_list =
                xrealloc(ipf_list->frag_list, (ipf_list->size + increment) *
                  sizeof *ipf_list->frag_list);
            ipf_list->size += increment;
        } else {
            return false;
        }
    }

    return ipf_process_frag(ipf_list, pkt, start_data_byte, end_data_byte, ff,
                            lf, v6);
}

static void
ipf_extract_frags_from_batch(struct dp_packet_batch *pb, ovs_be16 dl_type,
                             uint16_t zone, long long now, uint32_t hash_basis)
{
    const size_t pb_cnt = dp_packet_batch_size(pb);
    int pb_idx; /* Index in a packet batch. */
    struct dp_packet *pkt;

    DP_PACKET_BATCH_REFILL_FOR_EACH (pb_idx, pb_cnt, pkt, pb) {

        if (OVS_UNLIKELY((dl_type == htons(ETH_TYPE_IP) &&
                          ipf_is_valid_v4_frag(pkt)) ||
                         (dl_type == htons(ETH_TYPE_IPV6) &&
                          ipf_is_valid_v6_frag(pkt)))) {

            ipf_lock_lock(&ipf_lock);
            if (!ipf_handle_frag(pkt, dl_type, zone, now, hash_basis)) {
                dp_packet_batch_refill(pb, pkt, pb_idx);
            }
            ipf_lock_unlock(&ipf_lock);
        } else {
            dp_packet_batch_refill(pb, pkt, pb_idx);
        }

    }
}

/* In case of DPDK, a memory source check is done, as DPDK memory pool
 * management has trouble dealing with multiple source types.  The
 * check_source paramater is used to indicate when this check is needed. */
static bool
ipf_dp_packet_batch_add(struct dp_packet_batch *pb , struct dp_packet *pkt,
                        bool check_source OVS_UNUSED)
    OVS_REQUIRES(ipf_lock)
{
#ifdef DPDK_NETDEV
    if ((pb->count >= NETDEV_MAX_BURST) ||
        /* DPDK cannot handle multiple sources in a batch. */
        (check_source && pb->count && pb->packets[0]->source != pkt->source)) {
#else
    if (pb->count >= NETDEV_MAX_BURST) {
#endif
        return false;
    }

    dp_packet_batch_add(pb, pkt);
    return true;
}

/* This would be used in rare cases where a list cannot be sent. One rare
 * reason known right now is a mempool source check, which exists due to DPDK
 * support, where packets are no longer being received on any port with a
 * source matching the fragment.  Another reason is a race where all
 * conntrack rules are unconfigured when some fragments are yet to be
 * flushed.
 *
 * Returns true if the list was purged. */
static bool
ipf_purge_list_check(struct ipf_list *ipf_list, long long now)
    OVS_REQUIRES(ipf_lock)
{
    enum {
        IPF_FRAG_LIST_PURGE_TIME_ADJ = 10000
    };

    if (now < ipf_list->expiration + IPF_FRAG_LIST_PURGE_TIME_ADJ) {
        return false;
    }

    struct dp_packet *pkt;
    while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
        pkt = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
        dp_packet_delete(pkt);
        atomic_count_dec(&nfrag);
        COVERAGE_INC(ipf_stuck_frag_list_purged);
        ipf_count(ipf_list->key.dl_type == htons(ETH_TYPE_IPV6),
                  IPF_COUNTER_NFRAGS_PURGED);
        ipf_list->last_sent_idx++;
    }

    return true;
}

static bool
ipf_send_frags_in_list(struct ipf_list *ipf_list, struct dp_packet_batch *pb,
                       enum ipf_list_type list_type, bool v6, long long now)
    OVS_REQUIRES(ipf_lock)
{
    if (ipf_purge_list_check(ipf_list, now)) {
        return true;
    }

    struct dp_packet *pkt;
    while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
        pkt = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
        if (ipf_dp_packet_batch_add(pb, pkt, true)) {

            ipf_list->last_sent_idx++;
            atomic_count_dec(&nfrag);

            if (list_type == IPF_FRAG_COMPLETED_LIST) {
                ipf_count(v6, IPF_COUNTER_NFRAGS_COMPL_SENT);
            } else {
                ipf_count(v6, IPF_COUNTER_NFRAGS_EXPD_SENT);
                pkt->md.ct_state = CS_INVALID;
            }

            if (ipf_list->last_sent_idx == ipf_list->last_inuse_idx) {
                return true;
            }
        } else {
            return false;
        }
    }
    OVS_NOT_REACHED();
}

static void
ipf_send_completed_frags(struct dp_packet_batch *pb, long long now, bool v6)
{
    if (ovs_list_is_empty(&frag_complete_list)) {
        return;
    }

    ipf_lock_lock(&ipf_lock);
    struct ipf_list *ipf_list, *next;

    LIST_FOR_EACH_SAFE (ipf_list, next, list_node, &frag_complete_list) {
        if (ipf_send_frags_in_list(ipf_list, pb, IPF_FRAG_COMPLETED_LIST,
                                   v6, now)) {
            ipf_completed_list_clean(ipf_list);
        } else {
            break;
        }
    }
    ipf_lock_unlock(&ipf_lock);
}

static void
ipf_send_expired_frags(struct dp_packet_batch *pb, long long now, bool v6)
{
    enum {
        /* Very conservative, due to DOS probability. */
        IPF_FRAG_LIST_MAX_EXPIRED = 1,
    };


    if (ovs_list_is_empty(&frag_exp_list)) {
        return;
    }

    ipf_lock_lock(&ipf_lock);
    struct ipf_list *ipf_list, *next;
    size_t lists_removed = 0;

    LIST_FOR_EACH_SAFE (ipf_list, next, list_node, &frag_exp_list) {
        if (!(now > ipf_list->expiration) ||
            lists_removed >= IPF_FRAG_LIST_MAX_EXPIRED) {
            break;
        }

        if (ipf_send_frags_in_list(ipf_list, pb, IPF_FRAG_EXPIRY_LIST, v6,
                                   now)) {
            ipf_expiry_list_clean(ipf_list);
            lists_removed++;
        } else {
            break;
        }
    }
    ipf_lock_unlock(&ipf_lock);
}

static void
ipf_execute_reass_pkts(struct dp_packet_batch *pb)
{
    if (ovs_list_is_empty(&reassembled_pkt_list)) {
        return;
    }

    ipf_lock_lock(&ipf_lock);
    struct reassembled_pkt *rp, *next;

    LIST_FOR_EACH_SAFE (rp, next, rp_list_node, &reassembled_pkt_list) {
        if (!rp->list->reass_execute_ctx &&
            ipf_dp_packet_batch_add(pb, rp->pkt, false)) {
            rp->list->reass_execute_ctx = rp->pkt;
        }
    }
    ipf_lock_unlock(&ipf_lock);
}

static void
ipf_post_execute_reass_pkts(struct dp_packet_batch *pb, bool v6)
{
    if (ovs_list_is_empty(&reassembled_pkt_list)) {
        return;
    }

    ipf_lock_lock(&ipf_lock);
    struct reassembled_pkt *rp, *next;

    LIST_FOR_EACH_SAFE (rp, next, rp_list_node, &reassembled_pkt_list) {
        const size_t pb_cnt = dp_packet_batch_size(pb);
        int pb_idx;
        struct dp_packet *pkt;
        /* Inner batch loop is constant time since batch size is <=
         * NETDEV_MAX_BURST. */
        DP_PACKET_BATCH_REFILL_FOR_EACH (pb_idx, pb_cnt, pkt, pb) {
            if (pkt == rp->list->reass_execute_ctx) {
                for (int i = 0; i <= rp->list->last_inuse_idx; i++) {
                    rp->list->frag_list[i].pkt->md.ct_label = pkt->md.ct_label;
                    rp->list->frag_list[i].pkt->md.ct_mark = pkt->md.ct_mark;
                    rp->list->frag_list[i].pkt->md.ct_state = pkt->md.ct_state;
                    rp->list->frag_list[i].pkt->md.ct_zone = pkt->md.ct_zone;
                    rp->list->frag_list[i].pkt->md.ct_orig_tuple_ipv6 =
                        pkt->md.ct_orig_tuple_ipv6;
                    if (pkt->md.ct_orig_tuple_ipv6) {
                        rp->list->frag_list[i].pkt->md.ct_orig_tuple.ipv6 =
                            pkt->md.ct_orig_tuple.ipv6;
                    } else {
                        rp->list->frag_list[i].pkt->md.ct_orig_tuple.ipv4  =
                            pkt->md.ct_orig_tuple.ipv4;
                    }
                }

                const char *tail_frag =
                    dp_packet_tail(rp->list->frag_list[0].pkt);
                uint8_t pad_frag =
                    dp_packet_l2_pad_size(rp->list->frag_list[0].pkt);

                void *l4_frag = dp_packet_l4(rp->list->frag_list[0].pkt);
                void *l4_reass = dp_packet_l4(pkt);
                memcpy(l4_frag, l4_reass,
                       tail_frag - (char *) l4_frag - pad_frag);

                if (v6) {
                    struct  ovs_16aligned_ip6_hdr *l3_frag =
                        dp_packet_l3(rp->list->frag_list[0].pkt);
                    struct  ovs_16aligned_ip6_hdr *l3_reass =
                        dp_packet_l3(pkt);
                    l3_frag->ip6_src = l3_reass->ip6_src;
                    l3_frag->ip6_dst = l3_reass->ip6_dst;
                } else {
                    struct ip_header *l3_frag =
                        dp_packet_l3(rp->list->frag_list[0].pkt);
                    struct ip_header *l3_reass = dp_packet_l3(pkt);
                    ovs_be32 reass_ip = get_16aligned_be32(&l3_reass->ip_src);
                    ovs_be32 frag_ip = get_16aligned_be32(&l3_frag->ip_src);
                    l3_frag->ip_csum = recalc_csum32(l3_frag->ip_csum,
                                                     frag_ip, reass_ip);
                    l3_frag->ip_src = l3_reass->ip_src;

                    reass_ip = get_16aligned_be32(&l3_reass->ip_dst);
                    frag_ip = get_16aligned_be32(&l3_frag->ip_dst);
                    l3_frag->ip_csum = recalc_csum32(l3_frag->ip_csum,
                                                     frag_ip, reass_ip);
                    l3_frag->ip_dst = l3_reass->ip_dst;
                }

                ipf_completed_list_add(rp->list);
                ipf_reassembled_list_remove(rp);
                dp_packet_delete(rp->pkt);
                free(rp);
            } else {
                dp_packet_batch_refill(pb, pkt, pb_idx);
            }
        }
    }
    ipf_lock_unlock(&ipf_lock);
}

/* Extracts any fragments from the batch and reassembles them when a
 * complete packet is received.  Completed packets are attempted to
 * be added to the batch to be sent through conntrack. */
void
ipf_preprocess_conntrack(struct dp_packet_batch *pb, long long now,
                         ovs_be16 dl_type, uint16_t zone, uint32_t hash_basis)
{
    if (ipf_get_enabled()) {
        ipf_extract_frags_from_batch(pb, dl_type, zone, now, hash_basis);
    }

    if (ipf_get_enabled() || atomic_count_get(&nfrag)) {
        ipf_execute_reass_pkts(pb);
    }
}

/* Updates fragments based on the processing of the reassembled packet sent
 * through conntrack and adds these fragments to any batches seen.  Expired
 * fragments are marked as invalid and also added to the batches seen
 * with low priority.  Reassembled packets are freed. */
void
ipf_postprocess_conntrack(struct dp_packet_batch *pb, long long now,
                          ovs_be16 dl_type)
{
    if (ipf_get_enabled() || atomic_count_get(&nfrag)) {
        bool v6 = dl_type == htons(ETH_TYPE_IPV6);
        ipf_post_execute_reass_pkts(pb, v6);
        ipf_send_completed_frags(pb, now, v6);
        ipf_send_expired_frags(pb, now, v6);
    }
}

static void *
ipf_clean_thread_main(void *f OVS_UNUSED)
{
    enum {
        IPF_FRAG_LIST_CLEAN_TIMEOUT = 60000,
    };

    while (!latch_is_set(&ipf_clean_thread_exit)) {

        long long now = time_msec();

        if (!ovs_list_is_empty(&frag_exp_list) ||
            !ovs_list_is_empty(&frag_complete_list)) {

            ipf_lock_lock(&ipf_lock);

            struct ipf_list *ipf_list, *next;
            LIST_FOR_EACH_SAFE (ipf_list, next, list_node, &frag_exp_list) {
                if (ipf_purge_list_check(ipf_list, now)) {
                    ipf_expiry_list_clean(ipf_list);
                }
            }

            LIST_FOR_EACH_SAFE (ipf_list, next, list_node,
                                &frag_complete_list) {
                if (ipf_purge_list_check(ipf_list, now)) {
                    ipf_completed_list_clean(ipf_list);
                }
            }

            ipf_lock_unlock(&ipf_lock);
        }

        poll_timer_wait_until(now + IPF_FRAG_LIST_CLEAN_TIMEOUT);
        latch_wait(&ipf_clean_thread_exit);
        poll_block();
    }

    return NULL;
}

void
ipf_init(void)
{
    ipf_lock_init(&ipf_lock);
    ipf_lock_lock(&ipf_lock);
    hmap_init(&frag_lists);
    ovs_list_init(&frag_exp_list);
    ovs_list_init(&frag_complete_list);
    ovs_list_init(&reassembled_pkt_list);
    atomic_init(&min_v4_frag_size, IPF_V4_FRAG_SIZE_MIN_DEF);
    atomic_init(&min_v6_frag_size, IPF_V6_FRAG_SIZE_MIN_DEF);
    max_v4_frag_list_size = DIV_ROUND_UP(
        IPV4_PACKET_MAX_SIZE - IPV4_PACKET_MAX_HDR_SIZE,
        min_v4_frag_size - IPV4_PACKET_MAX_HDR_SIZE);
    ipf_lock_unlock(&ipf_lock);
    atomic_count_init(&nfrag, 0);
    atomic_init(&n4frag_accepted, 0);
    atomic_init(&n4frag_completed_sent, 0);
    atomic_init(&n4frag_expired_sent, 0);
    atomic_init(&n4frag_too_small, 0);
    atomic_init(&n4frag_overlap, 0);
    atomic_init(&n4frag_purged, 0);
    atomic_init(&n6frag_accepted, 0);
    atomic_init(&n6frag_completed_sent, 0);
    atomic_init(&n6frag_expired_sent, 0);
    atomic_init(&n6frag_too_small, 0);
    atomic_init(&n6frag_overlap, 0);
    atomic_init(&n6frag_purged, 0);
    atomic_init(&nfrag_max, IPF_MAX_FRAGS_DEFAULT);
    atomic_init(&ifp_v4_enabled, true);
    atomic_init(&ifp_v6_enabled, true);
    latch_init(&ipf_clean_thread_exit);
    ipf_clean_thread = ovs_thread_create("ipf_clean",
                                         ipf_clean_thread_main, NULL);
}

void
ipf_destroy(void)
{
    ipf_lock_lock(&ipf_lock);

    latch_set(&ipf_clean_thread_exit);
    pthread_join(ipf_clean_thread, NULL);
    latch_destroy(&ipf_clean_thread_exit);

    struct ipf_list *ipf_list;
    HMAP_FOR_EACH_POP (ipf_list, node, &frag_lists) {
        struct dp_packet *pkt;
        while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
            pkt = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
            dp_packet_delete(pkt);
            atomic_count_dec(&nfrag);
            ipf_list->last_sent_idx++;
        }
        free(ipf_list->frag_list);
        free(ipf_list);
    }

    if (atomic_count_get(&nfrag)) {
        VLOG_WARN("ipf destroy with non-zero fragment count. ");
    }

    struct reassembled_pkt * rp;
    LIST_FOR_EACH_POP (rp, rp_list_node, &reassembled_pkt_list) {
        dp_packet_delete(rp->pkt);
        free(rp);
    }

    hmap_destroy(&frag_lists);
    ovs_list_poison(&frag_exp_list);
    ovs_list_poison(&frag_complete_list);
    ovs_list_poison(&reassembled_pkt_list);
    ipf_lock_unlock(&ipf_lock);
    ipf_lock_destroy(&ipf_lock);
}

int
ipf_set_enabled(bool v6, bool enable)
{
    atomic_store_relaxed(v6 ? &ifp_v6_enabled : &ifp_v4_enabled, enable);
    return 0;
}

int
ipf_set_min_frag(bool v6, uint32_t value)
{
    /* If the user specifies an unreasonably large number, fragmentation
     * will not work well but it will not blow up. */
    if ((!v6 && value < IPF_V4_FRAG_SIZE_LBOUND) ||
        (v6 && value < IPF_V6_FRAG_SIZE_LBOUND)) {
        return 1;
    }

    ipf_lock_lock(&ipf_lock);
    if (v6) {
        atomic_store_relaxed(&min_v6_frag_size, value);
    } else {
        atomic_store_relaxed(&min_v4_frag_size, value);
        max_v4_frag_list_size = DIV_ROUND_UP(
            IPV4_PACKET_MAX_SIZE - IPV4_PACKET_MAX_HDR_SIZE,
            min_v4_frag_size - IPV4_PACKET_MAX_HDR_SIZE);
    }
    ipf_lock_unlock(&ipf_lock);
    return 0;
}
