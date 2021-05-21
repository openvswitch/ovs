/*
 * Copyright (c) 2019 Nicira, Inc.
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

static char *ipf_state_name[IPF_LIST_STATE_NUM] =
    {"unused", "reassemble fail", "other frag", "first frag", "last frag",
     "first/last frag", "complete"};

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
    IPF_NFRAGS_ACCEPTED,
    IPF_NFRAGS_COMPL_SENT,
    IPF_NFRAGS_EXPD_SENT,
    IPF_NFRAGS_TOO_SMALL,
    IPF_NFRAGS_OVERLAP,
    IPF_NFRAGS_PURGED,
    IPF_NFRAGS_NUM_CNTS,
};

union ipf_addr {
    ovs_be32 ipv4;
    struct in6_addr ipv6;
};

/* Represents a single fragment; part of a list of fragments. */
struct ipf_frag {
    struct dp_packet *pkt;
    uint16_t start_data_byte;
    uint16_t end_data_byte;
};

/* The key for a collection of fragments potentially making up an unfragmented
 * packet. */
struct ipf_list_key {
    /* ipf_list_key_hash() requires 'src_addr' and 'dst_addr' to be the first
     * two members. */
    union ipf_addr src_addr;
    union ipf_addr dst_addr;
    uint32_t recirc_id;
    ovs_be32 ip_id;   /* V6 is 32 bits. */
    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

/* A collection of fragments potentially making up an unfragmented packet. */
struct ipf_list {
    struct hmap_node node;         /* In struct ipf's 'frag_lists'. */
    struct ovs_list list_node;     /* In struct ipf's 'frag_exp_list' or
                                    * 'frag_complete_list'. */
    struct ipf_frag *frag_list;    /* List of fragments for this list. */
    struct ipf_list_key key;       /* The key for the fragemnt list. */
    struct dp_packet *reass_execute_ctx; /* Reassembled packet. */
    long long expiration;          /* In milliseconds. */
    int last_sent_idx;             /* Last sent fragment idx. */
    int last_inuse_idx;            /* Last inuse fragment idx. */
    int size;                      /* Fragment list size. */
    uint8_t state;                 /* Frag list state; see ipf_list_state. */
};

/* Represents a reassambled packet which typically is passed through
 * conntrack. */
struct reassembled_pkt {
    struct ovs_list rp_list_node;  /* In struct ipf's
                                    * 'reassembled_pkt_list'. */
    struct dp_packet *pkt;
    struct ipf_list *list;
};

struct ipf {
    /* The clean thread is used to clean up fragments in the 'ipf'
     * module if packet batches are not longer be sent through its user. */
    pthread_t ipf_clean_thread;
    struct latch ipf_clean_thread_exit;

    int max_v4_frag_list_size;

    struct ovs_mutex ipf_lock; /* Protects all of the following. */
    /* These contain 'struct ipf_list's. */
    struct hmap frag_lists OVS_GUARDED;
    struct ovs_list frag_exp_list OVS_GUARDED;
    struct ovs_list frag_complete_list OVS_GUARDED;
    /* Contains 'struct reassembled_pkt's. */
    struct ovs_list reassembled_pkt_list OVS_GUARDED;

    /* Used to allow disabling fragmentation reassembly. */
    atomic_bool ifp_v4_enabled;
    atomic_bool ifp_v6_enabled;

    /* Will be clamped above 400 bytes; the value chosen should handle
     * alg control packets of interest that use string encoding of mutable
     * IP fields; meaning, the control packets should not be fragmented. */
    atomic_uint min_v4_frag_size;
    atomic_uint min_v6_frag_size;

    /* Configurable maximum allowable fragments in process. */
    atomic_uint nfrag_max;

    /* Number of fragments in process. */
    atomic_count nfrag;

    atomic_uint64_t n4frag_cnt[IPF_NFRAGS_NUM_CNTS];
    atomic_uint64_t n6frag_cnt[IPF_NFRAGS_NUM_CNTS];
};

static void
ipf_print_reass_packet(const char *es, const void *pkt)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    if (!VLOG_DROP_WARN(&rl)) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ds_put_hex_dump(&ds, pkt, 128, 0, false);
        VLOG_WARN("%s\n%s", es, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

static void
ipf_count(struct ipf *ipf, bool v6, enum ipf_counter_type cntr)
{
    atomic_count_inc64(v6 ? &ipf->n6frag_cnt[cntr] : &ipf->n4frag_cnt[cntr]);
}

static bool
ipf_get_v4_enabled(struct ipf *ipf)
{
    bool ifp_v4_enabled_;
    atomic_read_relaxed(&ipf->ifp_v4_enabled, &ifp_v4_enabled_);
    return ifp_v4_enabled_;
}

static bool
ipf_get_v6_enabled(struct ipf *ipf)
{
    bool ifp_v6_enabled_;
    atomic_read_relaxed(&ipf->ifp_v6_enabled, &ifp_v6_enabled_);
    return ifp_v6_enabled_;
}

static bool
ipf_get_enabled(struct ipf *ipf)
{
    return ipf_get_v4_enabled(ipf) || ipf_get_v6_enabled(ipf);
}

static uint32_t
ipf_addr_hash_add(uint32_t hash, const union ipf_addr *addr)
{
    BUILD_ASSERT_DECL(sizeof *addr % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) addr, sizeof *addr);
}

/* Adds a list of fragments to the list tracking expiry of yet to be
 * completed reassembled packets, hence subject to expirty. */
static void
ipf_expiry_list_add(struct ovs_list *frag_exp_list, struct ipf_list *ipf_list,
                    long long now)
   /* OVS_REQUIRES(ipf->ipf_lock) */
{
    enum {
        IPF_FRAG_LIST_TIMEOUT = 15000,
    };

    ipf_list->expiration = now + IPF_FRAG_LIST_TIMEOUT;
    ovs_list_push_back(frag_exp_list, &ipf_list->list_node);
}

/* Adds a list of fragments to the list of completed packets, which will be
 * subsequently transmitted. */
static void
ipf_completed_list_add(struct ovs_list *frag_complete_list,
                       struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    ovs_list_push_back(frag_complete_list, &ipf_list->list_node);
}

/* Adds a reassmebled packet to the list of reassembled packets, awaiting some
 * processing, such as being sent through conntrack. */
static void
ipf_reassembled_list_add(struct ovs_list *reassembled_pkt_list,
                         struct reassembled_pkt *rp)
    /* OVS_REQUIRES(ipf_lock) */
{
    ovs_list_push_back(reassembled_pkt_list, &rp->rp_list_node);
}

/* Removed a frag list from tracking datastructures and frees list heap
 * memory. */
static void
ipf_list_clean(struct hmap *frag_lists,
               struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    ovs_list_remove(&ipf_list->list_node);
    hmap_remove(frag_lists, &ipf_list->node);
    free(ipf_list->frag_list);
    free(ipf_list);
}

/* Removed a frag list sitting on the expiry list from tracking
 * datastructures and frees list heap memory. */
static void
ipf_expiry_list_clean(struct hmap *frag_lists,
                      struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    ipf_list_clean(frag_lists, ipf_list);
}

/* Removed a frag list sitting on the completed list from tracking
 * datastructures and frees list heap memory. */
static void
ipf_completed_list_clean(struct hmap *frag_lists,
                         struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    ipf_list_clean(frag_lists, ipf_list);
}

static void
ipf_expiry_list_remove(struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    ovs_list_remove(&ipf_list->list_node);
}

static void
ipf_reassembled_list_remove(struct reassembled_pkt *rp)
    /* OVS_REQUIRES(ipf_lock) */
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
    return hash_words((uint32_t *) (&key->dst_addr + 1),
                      (uint32_t *) (key + 1) -
                      (uint32_t *) (&key->dst_addr + 1),
                      hash);
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

/* Checks for a completed packet collection of fragments. */
static bool
ipf_list_complete(const struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    for (int i = 1; i <= ipf_list->last_inuse_idx; i++) {
        if (ipf_list->frag_list[i - 1].end_data_byte + 1
            != ipf_list->frag_list[i].start_data_byte) {
            return false;
        }
    }
    return true;
}

/* Runs O(n) for a sorted or almost sorted list. */
static void
ipf_sort(struct ipf_frag *frag_list, size_t last_idx)
    /* OVS_REQUIRES(ipf_lock) */
{
    for (int li = 1; li <= last_idx; li++) {
        struct ipf_frag ipf_frag = frag_list[li];
        int ci = li - 1;
        while (ci >= 0 &&
               frag_list[ci].start_data_byte > ipf_frag.start_data_byte) {
            frag_list[ci + 1] = frag_list[ci];
            ci--;
        }
        frag_list[ci + 1] = ipf_frag;
    }
}

/* Called on a sorted complete list of v4 fragments to reassemble them into
 * a single packet that can be processed, such as passing through conntrack.
 */
static struct dp_packet *
ipf_reassemble_v4_frags(struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    struct ipf_frag *frag_list = ipf_list->frag_list;
    struct dp_packet *pkt = dp_packet_clone(frag_list[0].pkt);
    dp_packet_set_size(pkt, dp_packet_size(pkt) - dp_packet_l2_pad_size(pkt));
    struct ip_header *l3 = dp_packet_l3(pkt);
    int len = ntohs(l3->ip_tot_len);

    int rest_len = frag_list[ipf_list->last_inuse_idx].end_data_byte -
                   frag_list[1].start_data_byte + 1;

    if (len + rest_len > IPV4_PACKET_MAX_SIZE) {
        ipf_print_reass_packet(
            "Unsupported big reassembled v4 packet; v4 hdr:", l3);
        dp_packet_delete(pkt);
        return NULL;
    }

    dp_packet_prealloc_tailroom(pkt, rest_len);

    for (int i = 1; i <= ipf_list->last_inuse_idx; i++) {
        size_t add_len = frag_list[i].end_data_byte -
                         frag_list[i].start_data_byte + 1;
        const char *l4 = dp_packet_l4(frag_list[i].pkt);
        dp_packet_put(pkt, l4, add_len);
    }

    len += rest_len;
    l3 = dp_packet_l3(pkt);
    ovs_be16 new_ip_frag_off = l3->ip_frag_off & ~htons(IP_MORE_FRAGMENTS);
    if (!dp_packet_hwol_is_ipv4(pkt)) {
        l3->ip_csum = recalc_csum16(l3->ip_csum, l3->ip_frag_off,
                                    new_ip_frag_off);
        l3->ip_csum = recalc_csum16(l3->ip_csum, l3->ip_tot_len, htons(len));
    }
    l3->ip_tot_len = htons(len);
    l3->ip_frag_off = new_ip_frag_off;
    dp_packet_set_l2_pad_size(pkt, 0);

    return pkt;
}

/* Called on a sorted complete list of v6 fragments to reassemble them into
 * a single packet that can be processed, such as passing through conntrack.
 */
static struct dp_packet *
ipf_reassemble_v6_frags(struct ipf_list *ipf_list)
    /* OVS_REQUIRES(ipf_lock) */
{
    struct ipf_frag *frag_list = ipf_list->frag_list;
    struct dp_packet *pkt = dp_packet_clone(frag_list[0].pkt);
    dp_packet_set_size(pkt, dp_packet_size(pkt) - dp_packet_l2_pad_size(pkt));
    struct  ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    int pl = ntohs(l3->ip6_plen) - sizeof(struct ovs_16aligned_ip6_frag);

    int rest_len = frag_list[ipf_list->last_inuse_idx].end_data_byte -
                   frag_list[1].start_data_byte + 1;

    if (pl + rest_len > IPV6_PACKET_MAX_DATA) {
        ipf_print_reass_packet(
             "Unsupported big reassembled v6 packet; v6 hdr:", l3);
        dp_packet_delete(pkt);
        return NULL;
    }

    dp_packet_prealloc_tailroom(pkt, rest_len);

    for (int i = 1; i <= ipf_list->last_inuse_idx; i++) {
        size_t add_len = frag_list[i].end_data_byte -
                          frag_list[i].start_data_byte + 1;
        const char *l4 = dp_packet_l4(frag_list[i].pkt);
        dp_packet_put(pkt, l4, add_len);
    }

    pl += rest_len;
    l3 = dp_packet_l3(pkt);

    uint8_t nw_proto = l3->ip6_nxt;
    uint8_t nw_frag = 0;
    const void *data = l3 + 1;
    size_t datasize = pl;

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
    dp_packet_set_l2_pad_size(pkt, 0);
    return pkt;
}

/* Called when a frag list state transitions to another state. This is
 * triggered by new fragment for the list being received.*/
static void
ipf_list_state_transition(struct ipf *ipf, struct ipf_list *ipf_list,
                          bool ff, bool lf, bool v6)
    OVS_REQUIRES(ipf->ipf_lock)
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
        if (lf) {
            next_state = IPF_LIST_STATE_FIRST_LAST_SEEN;
        } else {
            next_state = IPF_LIST_STATE_FIRST_SEEN;
        }
        break;
    case IPF_LIST_STATE_LAST_SEEN:
        if (ff) {
            next_state = IPF_LIST_STATE_FIRST_LAST_SEEN;
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
                ipf_reassembled_list_add(&ipf->reassembled_pkt_list, rp);
                ipf_expiry_list_remove(ipf_list);
                next_state = IPF_LIST_STATE_COMPLETED;
            } else {
                next_state = IPF_LIST_STATE_REASS_FAIL;
            }
        }
    }
    ipf_list->state = next_state;
}

/* Some sanity checks are redundant, but prudent, in case code paths for
 * fragments change in future. The processing cost for fragments is not
 * important. */
static bool
ipf_is_valid_v4_frag(struct ipf *ipf, struct dp_packet *pkt)
{
    if (OVS_UNLIKELY(dp_packet_ip_checksum_bad(pkt))) {
        goto invalid_pkt;
    }

    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);

    if (OVS_UNLIKELY(!l2 || !l3)) {
        goto invalid_pkt;
    }

    size_t l3_size = dp_packet_l3_size(pkt);
    if (OVS_UNLIKELY(l3_size < IP_HEADER_LEN)) {
        goto invalid_pkt;
    }

    if (!IP_IS_FRAGMENT(l3->ip_frag_off)) {
        return false;
    }

    uint16_t ip_tot_len = ntohs(l3->ip_tot_len);
    if (OVS_UNLIKELY(ip_tot_len != l3_size)) {
        goto invalid_pkt;
    }

    size_t ip_hdr_len = IP_IHL(l3->ip_ihl_ver) * 4;
    if (OVS_UNLIKELY(ip_hdr_len < IP_HEADER_LEN)) {
        goto invalid_pkt;
    }
    if (OVS_UNLIKELY(l3_size < ip_hdr_len)) {
        goto invalid_pkt;
    }

    if (OVS_UNLIKELY(!dp_packet_ip_checksum_valid(pkt)
                     && !dp_packet_hwol_is_ipv4(pkt)
                     && csum(l3, ip_hdr_len) != 0)) {
        goto invalid_pkt;
    }

    uint32_t min_v4_frag_size_;
    atomic_read_relaxed(&ipf->min_v4_frag_size, &min_v4_frag_size_);
    bool lf = ipf_is_last_v4_frag(pkt);
    if (OVS_UNLIKELY(!lf && dp_packet_l3_size(pkt) < min_v4_frag_size_)) {
        ipf_count(ipf, false, IPF_NFRAGS_TOO_SMALL);
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
    key->src_addr.ipv4 = get_16aligned_be32(&l3->ip_src);
    key->dst_addr.ipv4 = get_16aligned_be32(&l3->ip_dst);
    key->nw_proto = l3->ip_proto;
    key->zone = zone;
    key->recirc_id = pkt->md.recirc_id;
    return true;
}

/* Some sanity checks are redundant, but prudent, in case code paths for
 * fragments change in future. The processing cost for fragments is not
 * important. */
static bool
ipf_is_valid_v6_frag(struct ipf *ipf, struct dp_packet *pkt)
{
    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct  ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);

    if (OVS_UNLIKELY(!l2 || !l3 || !l4)) {
        goto invalid_pkt;
    }

    size_t l3_size = dp_packet_l3_size(pkt);
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
    atomic_read_relaxed(&ipf->min_v6_frag_size, &min_v6_frag_size_);
    bool lf = ipf_is_last_v6_frag(ip6f_offlg);

    if (OVS_UNLIKELY(!lf && dp_packet_l3_size(pkt) < min_v6_frag_size_)) {
        ipf_count(ipf, true, IPF_NFRAGS_TOO_SMALL);
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
    const struct ovs_16aligned_ip6_hdr *l3 = dp_packet_l3(pkt);
    uint8_t nw_frag = 0;
    uint8_t nw_proto = l3->ip6_nxt;
    const void *data = l3 + 1;
    size_t datasize = dp_packet_l3_size(pkt) - sizeof *l3;
    const struct ovs_16aligned_ip6_frag *frag_hdr = NULL;

    parse_ipv6_ext_hdrs(&data, &datasize, &nw_proto, &nw_frag, &frag_hdr);
    ovs_assert(nw_frag && frag_hdr);
    ovs_be16 ip6f_offlg = frag_hdr->ip6f_offlg;
    *start_data_byte = ntohs(ip6f_offlg & IP6F_OFF_MASK) +
        sizeof (struct ovs_16aligned_ip6_frag);
    *end_data_byte = *start_data_byte + dp_packet_l4_size(pkt) - 1;
    *ff = ipf_is_first_v6_frag(ip6f_offlg);
    *lf = ipf_is_last_v6_frag(ip6f_offlg);
    memset(key, 0, sizeof *key);
    key->ip_id = get_16aligned_be32(&frag_hdr->ip6f_ident);
    key->dl_type = dl_type;
    memcpy(&key->src_addr.ipv6, &l3->ip6_src, sizeof key->src_addr.ipv6);
    /* We are not supporting parsing of the routing header to use as the
     * dst address part of the key. */
    memcpy(&key->dst_addr.ipv6, &l3->ip6_dst, sizeof key->dst_addr.ipv6);
    key->nw_proto = 0;   /* Not used for key for V6. */
    key->zone = zone;
    key->recirc_id = pkt->md.recirc_id;
}

static bool
ipf_list_key_eq(const struct ipf_list_key *key1,
                const struct ipf_list_key *key2)
    /* OVS_REQUIRES(ipf_lock) */
{
    if (!memcmp(&key1->src_addr, &key2->src_addr, sizeof key1->src_addr) &&
        !memcmp(&key1->dst_addr, &key2->dst_addr, sizeof key1->dst_addr) &&
        key1->dl_type == key2->dl_type &&
        key1->ip_id == key2->ip_id &&
        key1->zone == key2->zone &&
        key1->nw_proto == key2->nw_proto &&
        key1->recirc_id == key2->recirc_id) {
        return true;
    }
    return false;
}

static struct ipf_list *
ipf_list_key_lookup(struct ipf *ipf, const struct ipf_list_key *key,
                    uint32_t hash)
    OVS_REQUIRES(ipf->ipf_lock)
{
    struct ipf_list *ipf_list;
    HMAP_FOR_EACH_WITH_HASH (ipf_list, node, hash, &ipf->frag_lists) {
        if (ipf_list_key_eq(&ipf_list->key, key)) {
            return ipf_list;
        }
    }
    return NULL;
}

static bool
ipf_is_frag_duped(const struct ipf_frag *frag_list, int last_inuse_idx,
                  size_t start_data_byte, size_t end_data_byte)
    /* OVS_REQUIRES(ipf_lock) */
{
    for (int i = 0; i <= last_inuse_idx; i++) {
        if ((start_data_byte >= frag_list[i].start_data_byte &&
            start_data_byte <= frag_list[i].end_data_byte) ||
            (end_data_byte >= frag_list[i].start_data_byte &&
             end_data_byte <= frag_list[i].end_data_byte)) {
            return true;
        }
    }
    return false;
}

/* Adds a fragment to a list of fragments, if the fragment is not a
 * duplicate. If the fragment is a duplicate, that fragment is marked
 * invalid to avoid the work that conntrack would do to mark the fragment
 * as invalid, which it will in all cases. */
static bool
ipf_process_frag(struct ipf *ipf, struct ipf_list *ipf_list,
                 struct dp_packet *pkt, uint16_t start_data_byte,
                 uint16_t end_data_byte, bool ff, bool lf, bool v6)
    OVS_REQUIRES(ipf->ipf_lock)
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
            struct ipf_frag *frag = &ipf_list->frag_list[last_inuse_idx + 1];
            frag->pkt = dp_packet_clone(pkt);
            frag->start_data_byte = start_data_byte;
            frag->end_data_byte = end_data_byte;
            ipf_list->last_inuse_idx++;
            atomic_count_inc(&ipf->nfrag);
            ipf_count(ipf, v6, IPF_NFRAGS_ACCEPTED);
            ipf_list_state_transition(ipf, ipf_list, ff, lf, v6);
        } else {
            OVS_NOT_REACHED();
        }
    } else {
        ipf_count(ipf, v6, IPF_NFRAGS_OVERLAP);
        pkt->md.ct_state = CS_INVALID;
        return false;
    }
    return true;
}

static void
ipf_list_init(struct ipf_list *ipf_list, struct ipf_list_key *key,
              int max_frag_list_size)
{
    ipf_list->key = *key;
    ipf_list->last_inuse_idx = IPF_INVALID_IDX;
    ipf_list->last_sent_idx = IPF_INVALID_IDX;
    ipf_list->reass_execute_ctx = NULL;
    ipf_list->state = IPF_LIST_STATE_UNUSED;
    ipf_list->size = max_frag_list_size;
    ipf_list->frag_list
        = xzalloc(ipf_list->size * sizeof *ipf_list->frag_list);
}

/* Generates a fragment list key from a well formed fragment and either starts
 * a new fragment list or increases the size of the existing fragment list,
 * while checking if the maximum supported fragements are supported or the
 * list size is impossibly big. Calls 'ipf_process_frag()' to add a fragment
 * to a list of fragemnts. */
static bool
ipf_handle_frag(struct ipf *ipf, struct dp_packet *pkt, ovs_be16 dl_type,
                uint16_t zone, long long now, uint32_t hash_basis)
    OVS_REQUIRES(ipf->ipf_lock)
{
    struct ipf_list_key key;
    /* Initialize 4 variables for some versions of GCC. */
    uint16_t start_data_byte = 0;
    uint16_t end_data_byte = 0;
    bool ff = false;
    bool lf = false;
    bool v6 = dl_type == htons(ETH_TYPE_IPV6);

    if (v6 && ipf_get_v6_enabled(ipf)) {
        ipf_v6_key_extract(pkt, dl_type, zone, &key, &start_data_byte,
                           &end_data_byte, &ff, &lf);
    } else if (!v6 && ipf_get_v4_enabled(ipf)) {
        ipf_v4_key_extract(pkt, dl_type, zone, &key, &start_data_byte,
                           &end_data_byte, &ff, &lf);
    } else {
        return false;
    }

    unsigned int nfrag_max;
    atomic_read_relaxed(&ipf->nfrag_max, &nfrag_max);
    if (atomic_count_get(&ipf->nfrag) >= nfrag_max) {
        return false;
    }

    uint32_t hash = ipf_list_key_hash(&key, hash_basis);
    struct ipf_list *ipf_list = ipf_list_key_lookup(ipf, &key, hash);
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
        max_frag_list_size = ipf->max_v4_frag_list_size;
    }

    if (!ipf_list) {
        ipf_list = xmalloc(sizeof *ipf_list);
        ipf_list_init(ipf_list, &key,
                      MIN(max_frag_list_size, IPF_FRAG_LIST_MIN_INCREMENT));
        hmap_insert(&ipf->frag_lists, &ipf_list->node, hash);
        ipf_expiry_list_add(&ipf->frag_exp_list, ipf_list, now);
    } else if (ipf_list->state == IPF_LIST_STATE_REASS_FAIL ||
               ipf_list->state == IPF_LIST_STATE_COMPLETED) {
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

    return ipf_process_frag(ipf, ipf_list, pkt, start_data_byte,
                            end_data_byte, ff, lf, v6);
}

/* Filters out fragments from a batch of fragments and adjust the batch. */
static void
ipf_extract_frags_from_batch(struct ipf *ipf, struct dp_packet_batch *pb,
                             ovs_be16 dl_type, uint16_t zone, long long now,
                             uint32_t hash_basis)
{
    const size_t pb_cnt = dp_packet_batch_size(pb);
    int pb_idx; /* Index in a packet batch. */
    struct dp_packet *pkt;

    DP_PACKET_BATCH_REFILL_FOR_EACH (pb_idx, pb_cnt, pkt, pb) {
        if (OVS_UNLIKELY((dl_type == htons(ETH_TYPE_IP) &&
                          ipf_is_valid_v4_frag(ipf, pkt))
                          ||
                          (dl_type == htons(ETH_TYPE_IPV6) &&
                          ipf_is_valid_v6_frag(ipf, pkt)))) {

            ovs_mutex_lock(&ipf->ipf_lock);
            if (!ipf_handle_frag(ipf, pkt, dl_type, zone, now, hash_basis)) {
                dp_packet_batch_refill(pb, pkt, pb_idx);
            }
            ovs_mutex_unlock(&ipf->ipf_lock);
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
{
#ifdef DPDK_NETDEV
    if ((dp_packet_batch_is_full(pb)) ||
        /* DPDK cannot handle multiple sources in a batch. */
        (check_source && !dp_packet_batch_is_empty(pb)
         && pb->packets[0]->source != pkt->source)) {
#else
    if (dp_packet_batch_is_full(pb)) {
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
ipf_purge_list_check(struct ipf *ipf, struct ipf_list *ipf_list,
                     long long now)
    OVS_REQUIRES(ipf->ipf_lock)
{
    enum {
        IPF_FRAG_LIST_PURGE_TIME_ADJ = 10000
    };

    if (now < ipf_list->expiration + IPF_FRAG_LIST_PURGE_TIME_ADJ) {
        return false;
    }

    while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
        struct dp_packet * pkt
            = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
        dp_packet_delete(pkt);
        atomic_count_dec(&ipf->nfrag);
        COVERAGE_INC(ipf_stuck_frag_list_purged);
        ipf_count(ipf, ipf_list->key.dl_type == htons(ETH_TYPE_IPV6),
                  IPF_NFRAGS_PURGED);
        ipf_list->last_sent_idx++;
    }

    return true;
}

/* Does the packet batch management and common accounting work associated
 * with 'ipf_send_completed_frags()' and 'ipf_send_expired_frags()'. */
static bool
ipf_send_frags_in_list(struct ipf *ipf, struct ipf_list *ipf_list,
                       struct dp_packet_batch *pb,
                       enum ipf_list_type list_type, bool v6, long long now)
    OVS_REQUIRES(ipf->ipf_lock)
{
    if (ipf_purge_list_check(ipf, ipf_list, now)) {
        return true;
    }

    while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
        struct dp_packet *pkt
            = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
        if (ipf_dp_packet_batch_add(pb, pkt, true)) {
            ipf_list->last_sent_idx++;
            atomic_count_dec(&ipf->nfrag);

            if (list_type == IPF_FRAG_COMPLETED_LIST) {
                ipf_count(ipf, v6, IPF_NFRAGS_COMPL_SENT);
            } else {
                ipf_count(ipf, v6, IPF_NFRAGS_EXPD_SENT);
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

/* Adds fragments associated with a completed fragment list to a packet batch
 * to be processed by the calling application, typically conntrack. Also
 * cleans up the list context when it is empty.*/
static void
ipf_send_completed_frags(struct ipf *ipf, struct dp_packet_batch *pb,
                         long long now, bool v6)
{
    if (ovs_list_is_empty(&ipf->frag_complete_list)) {
        return;
    }

    ovs_mutex_lock(&ipf->ipf_lock);
    struct ipf_list *ipf_list, *next;

    LIST_FOR_EACH_SAFE (ipf_list, next, list_node, &ipf->frag_complete_list) {
        if (ipf_send_frags_in_list(ipf, ipf_list, pb, IPF_FRAG_COMPLETED_LIST,
                                   v6, now)) {
            ipf_completed_list_clean(&ipf->frag_lists, ipf_list);
        } else {
            break;
        }
    }

    ovs_mutex_unlock(&ipf->ipf_lock);
}

/* Conservatively adds fragments associated with a expired fragment list to
 * a packet batch to be processed by the calling application, typically
 * conntrack. Also cleans up the list context when it is empty.*/
static void
ipf_send_expired_frags(struct ipf *ipf, struct dp_packet_batch *pb,
                       long long now, bool v6)
{
    enum {
        /* Very conservative, due to DOS probability. */
        IPF_FRAG_LIST_MAX_EXPIRED = 1,
    };


    if (ovs_list_is_empty(&ipf->frag_exp_list)) {
        return;
    }

    ovs_mutex_lock(&ipf->ipf_lock);
    struct ipf_list *ipf_list, *next;
    size_t lists_removed = 0;

    LIST_FOR_EACH_SAFE (ipf_list, next, list_node, &ipf->frag_exp_list) {
        if (now <= ipf_list->expiration ||
            lists_removed >= IPF_FRAG_LIST_MAX_EXPIRED) {
            break;
        }

        if (ipf_send_frags_in_list(ipf, ipf_list, pb, IPF_FRAG_EXPIRY_LIST,
                                   v6, now)) {
            ipf_expiry_list_clean(&ipf->frag_lists, ipf_list);
            lists_removed++;
        } else {
            break;
        }
    }

    ovs_mutex_unlock(&ipf->ipf_lock);
}

/* Adds a reassmebled packet to a packet batch to be processed by the caller.
 */
static void
ipf_execute_reass_pkts(struct ipf *ipf, struct dp_packet_batch *pb)
{
    if (ovs_list_is_empty(&ipf->reassembled_pkt_list)) {
        return;
    }

    ovs_mutex_lock(&ipf->ipf_lock);
    struct reassembled_pkt *rp, *next;

    LIST_FOR_EACH_SAFE (rp, next, rp_list_node, &ipf->reassembled_pkt_list) {
        if (!rp->list->reass_execute_ctx &&
            ipf_dp_packet_batch_add(pb, rp->pkt, false)) {
            rp->list->reass_execute_ctx = rp->pkt;
        }
    }

    ovs_mutex_unlock(&ipf->ipf_lock);
}

/* Checks for reassembled packets post processing by conntrack and edits the
 * fragments if needed based on what conntrack decided. */
static void
ipf_post_execute_reass_pkts(struct ipf *ipf,
                            struct dp_packet_batch *pb, bool v6)
{
    if (ovs_list_is_empty(&ipf->reassembled_pkt_list)) {
        return;
    }

    ovs_mutex_lock(&ipf->ipf_lock);
    struct reassembled_pkt *rp, *next;

    LIST_FOR_EACH_SAFE (rp, next, rp_list_node, &ipf->reassembled_pkt_list) {
        const size_t pb_cnt = dp_packet_batch_size(pb);
        int pb_idx;
        struct dp_packet *pkt;
        /* Inner batch loop is constant time since batch size is <=
         * NETDEV_MAX_BURST. */
        DP_PACKET_BATCH_REFILL_FOR_EACH (pb_idx, pb_cnt, pkt, pb) {
            if (rp && pkt == rp->list->reass_execute_ctx) {
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

                const struct ipf_frag *frag_0 = &rp->list->frag_list[0];
                void *l4_frag = dp_packet_l4(frag_0->pkt);
                void *l4_reass = dp_packet_l4(pkt);
                memcpy(l4_frag, l4_reass, dp_packet_l4_size(frag_0->pkt));

                if (v6) {
                    struct ovs_16aligned_ip6_hdr *l3_frag
                        = dp_packet_l3(frag_0->pkt);
                    struct ovs_16aligned_ip6_hdr *l3_reass = dp_packet_l3(pkt);
                    l3_frag->ip6_src = l3_reass->ip6_src;
                    l3_frag->ip6_dst = l3_reass->ip6_dst;
                } else {
                    struct ip_header *l3_frag = dp_packet_l3(frag_0->pkt);
                    struct ip_header *l3_reass = dp_packet_l3(pkt);
                    if (!dp_packet_hwol_is_ipv4(frag_0->pkt)) {
                        ovs_be32 reass_ip =
                            get_16aligned_be32(&l3_reass->ip_src);
                        ovs_be32 frag_ip =
                            get_16aligned_be32(&l3_frag->ip_src);

                        l3_frag->ip_csum = recalc_csum32(l3_frag->ip_csum,
                                                         frag_ip, reass_ip);
                        reass_ip = get_16aligned_be32(&l3_reass->ip_dst);
                        frag_ip = get_16aligned_be32(&l3_frag->ip_dst);
                        l3_frag->ip_csum = recalc_csum32(l3_frag->ip_csum,
                                                         frag_ip, reass_ip);
                    }

                    l3_frag->ip_src = l3_reass->ip_src;
                    l3_frag->ip_dst = l3_reass->ip_dst;
                }

                ipf_completed_list_add(&ipf->frag_complete_list, rp->list);
                ipf_reassembled_list_remove(rp);
                dp_packet_delete(rp->pkt);
                free(rp);
                rp = NULL;
            } else {
                dp_packet_batch_refill(pb, pkt, pb_idx);
            }
        }
    }

    ovs_mutex_unlock(&ipf->ipf_lock);
}

/* Extracts any fragments from the batch and reassembles them when a
 * complete packet is received.  Completed packets are attempted to
 * be added to the batch to be sent through conntrack. */
void
ipf_preprocess_conntrack(struct ipf *ipf, struct dp_packet_batch *pb,
                         long long now, ovs_be16 dl_type, uint16_t zone,
                         uint32_t hash_basis)
{
    if (ipf_get_enabled(ipf)) {
        ipf_extract_frags_from_batch(ipf, pb, dl_type, zone, now, hash_basis);
    }

    if (ipf_get_enabled(ipf) || atomic_count_get(&ipf->nfrag)) {
        ipf_execute_reass_pkts(ipf, pb);
    }
}

/* Updates fragments based on the processing of the reassembled packet sent
 * through conntrack and adds these fragments to any batches seen.  Expired
 * fragments are marked as invalid and also added to the batches seen
 * with low priority.  Reassembled packets are freed. */
void
ipf_postprocess_conntrack(struct ipf *ipf, struct dp_packet_batch *pb,
                          long long now, ovs_be16 dl_type)
{
    if (ipf_get_enabled(ipf) || atomic_count_get(&ipf->nfrag)) {
        bool v6 = dl_type == htons(ETH_TYPE_IPV6);
        ipf_post_execute_reass_pkts(ipf, pb, v6);
        ipf_send_completed_frags(ipf, pb, now, v6);
        ipf_send_expired_frags(ipf, pb, now, v6);
    }
}

static void *
ipf_clean_thread_main(void *f)
{
    struct ipf *ipf = f;

    enum {
        IPF_FRAG_LIST_CLEAN_TIMEOUT = 60000,
    };

    while (!latch_is_set(&ipf->ipf_clean_thread_exit)) {

        long long now = time_msec();

        if (!ovs_list_is_empty(&ipf->frag_exp_list) ||
            !ovs_list_is_empty(&ipf->frag_complete_list)) {

            ovs_mutex_lock(&ipf->ipf_lock);

            struct ipf_list *ipf_list, *next;
            LIST_FOR_EACH_SAFE (ipf_list, next, list_node,
                                &ipf->frag_exp_list) {
                if (ipf_purge_list_check(ipf, ipf_list, now)) {
                    ipf_expiry_list_clean(&ipf->frag_lists, ipf_list);
                }
            }

            LIST_FOR_EACH_SAFE (ipf_list, next, list_node,
                                &ipf->frag_complete_list) {
                if (ipf_purge_list_check(ipf, ipf_list, now)) {
                    ipf_completed_list_clean(&ipf->frag_lists, ipf_list);
                }
            }

            ovs_mutex_unlock(&ipf->ipf_lock);
        }

        poll_timer_wait_until(now + IPF_FRAG_LIST_CLEAN_TIMEOUT);
        latch_wait(&ipf->ipf_clean_thread_exit);
        poll_block();
    }

    return NULL;
}

struct ipf *
ipf_init(void)
{
    struct ipf *ipf = xzalloc(sizeof *ipf);

    ovs_mutex_init_adaptive(&ipf->ipf_lock);
    ovs_mutex_lock(&ipf->ipf_lock);
    hmap_init(&ipf->frag_lists);
    ovs_list_init(&ipf->frag_exp_list);
    ovs_list_init(&ipf->frag_complete_list);
    ovs_list_init(&ipf->reassembled_pkt_list);
    atomic_init(&ipf->min_v4_frag_size, IPF_V4_FRAG_SIZE_MIN_DEF);
    atomic_init(&ipf->min_v6_frag_size, IPF_V6_FRAG_SIZE_MIN_DEF);
    ipf->max_v4_frag_list_size = DIV_ROUND_UP(
        IPV4_PACKET_MAX_SIZE - IPV4_PACKET_MAX_HDR_SIZE,
        ipf->min_v4_frag_size - IPV4_PACKET_MAX_HDR_SIZE);
    ovs_mutex_unlock(&ipf->ipf_lock);
    atomic_count_init(&ipf->nfrag, 0);
    for (size_t i = 0; i < IPF_NFRAGS_NUM_CNTS; i++) {
        atomic_init(&ipf->n4frag_cnt[i], 0);
        atomic_init(&ipf->n6frag_cnt[i], 0);
    }
    atomic_init(&ipf->nfrag_max, IPF_MAX_FRAGS_DEFAULT);
    atomic_init(&ipf->ifp_v4_enabled, true);
    atomic_init(&ipf->ifp_v6_enabled, true);
    latch_init(&ipf->ipf_clean_thread_exit);
    ipf->ipf_clean_thread = ovs_thread_create("ipf_clean",
                                         ipf_clean_thread_main, ipf);

    return ipf;
}

void
ipf_destroy(struct ipf *ipf)
{
    ovs_mutex_lock(&ipf->ipf_lock);
    latch_set(&ipf->ipf_clean_thread_exit);
    pthread_join(ipf->ipf_clean_thread, NULL);
    latch_destroy(&ipf->ipf_clean_thread_exit);

    struct ipf_list *ipf_list;
    HMAP_FOR_EACH_POP (ipf_list, node, &ipf->frag_lists) {
        while (ipf_list->last_sent_idx < ipf_list->last_inuse_idx) {
            struct dp_packet *pkt
                = ipf_list->frag_list[ipf_list->last_sent_idx + 1].pkt;
            dp_packet_delete(pkt);
            atomic_count_dec(&ipf->nfrag);
            ipf_list->last_sent_idx++;
        }
        free(ipf_list->frag_list);
        free(ipf_list);
    }

    if (atomic_count_get(&ipf->nfrag)) {
        VLOG_WARN("ipf destroy with non-zero fragment count. ");
    }

    struct reassembled_pkt *rp;
    LIST_FOR_EACH_POP (rp, rp_list_node, &ipf->reassembled_pkt_list) {
        dp_packet_delete(rp->pkt);
        free(rp);
    }

    hmap_destroy(&ipf->frag_lists);
    ovs_list_poison(&ipf->frag_exp_list);
    ovs_list_poison(&ipf->frag_complete_list);
    ovs_list_poison(&ipf->reassembled_pkt_list);
    ovs_mutex_unlock(&ipf->ipf_lock);
    ovs_mutex_destroy(&ipf->ipf_lock);
    free(ipf);
}

int
ipf_set_enabled(struct ipf *ipf, bool v6, bool enable)
{
    atomic_store_relaxed(v6 ? &ipf->ifp_v6_enabled : &ipf->ifp_v4_enabled,
                         enable);
    return 0;
}

int
ipf_set_min_frag(struct ipf *ipf, bool v6, uint32_t value)
{
    /* If the user specifies an unreasonably large number, fragmentation
     * will not work well but it will not blow up. */
    if (value < (v6 ? IPF_V6_FRAG_SIZE_LBOUND :  IPF_V4_FRAG_SIZE_LBOUND)) {
        return 1;
    }

    ovs_mutex_lock(&ipf->ipf_lock);
    if (v6) {
        atomic_store_relaxed(&ipf->min_v6_frag_size, value);
    } else {
        atomic_store_relaxed(&ipf->min_v4_frag_size, value);
        ipf->max_v4_frag_list_size = DIV_ROUND_UP(
            IPV4_PACKET_MAX_SIZE - IPV4_PACKET_MAX_HDR_SIZE,
            ipf->min_v4_frag_size - IPV4_PACKET_MAX_HDR_SIZE);
    }
    ovs_mutex_unlock(&ipf->ipf_lock);
    return 0;
}

int
ipf_set_max_nfrags(struct ipf *ipf, uint32_t value)
{
    if (value > IPF_NFRAG_UBOUND) {
        return 1;
    }
    atomic_store_relaxed(&ipf->nfrag_max, value);
    return 0;
}

int
ipf_get_status(struct ipf *ipf, struct ipf_status *ipf_status)
{
    ipf_status->nfrag = atomic_count_get(&ipf->nfrag);
    atomic_read_relaxed(&ipf->nfrag_max, &ipf_status->nfrag_max);

    atomic_read_relaxed(&ipf->ifp_v4_enabled, &ipf_status->v4.enabled);
    atomic_read_relaxed(&ipf->min_v4_frag_size,
                        &ipf_status->v4.min_frag_size);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_ACCEPTED],
                        &ipf_status->v4.nfrag_accepted);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_COMPL_SENT],
                        &ipf_status->v4.nfrag_completed_sent);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_EXPD_SENT],
                        &ipf_status->v4.nfrag_expired_sent);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_TOO_SMALL],
                        &ipf_status->v4.nfrag_too_small);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_OVERLAP],
                        &ipf_status->v4.nfrag_overlap);
    atomic_read_relaxed(&ipf->n4frag_cnt[IPF_NFRAGS_PURGED],
                        &ipf_status->v4.nfrag_purged);

    atomic_read_relaxed(&ipf->ifp_v6_enabled, &ipf_status->v6.enabled);
    atomic_read_relaxed(&ipf->min_v6_frag_size,
                        &ipf_status->v6.min_frag_size);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_ACCEPTED],
                        &ipf_status->v6.nfrag_accepted);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_COMPL_SENT],
                        &ipf_status->v6.nfrag_completed_sent);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_EXPD_SENT],
                        &ipf_status->v6.nfrag_expired_sent);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_TOO_SMALL],
                        &ipf_status->v6.nfrag_too_small);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_OVERLAP],
                        &ipf_status->v6.nfrag_overlap);
    atomic_read_relaxed(&ipf->n6frag_cnt[IPF_NFRAGS_PURGED],
                        &ipf_status->v6.nfrag_purged);
    return 0;
}

struct ipf_dump_ctx {
    struct hmap_position bucket_pos;
};

/* Allocates an 'ipf_dump_ctx' to keep track of an hmap position. The
 * caller must call ipf_dump_done() when dumping is finished. */
int
ipf_dump_start(struct ipf_dump_ctx **ipf_dump_ctx)
{
    *ipf_dump_ctx = xzalloc(sizeof **ipf_dump_ctx);
    return 0;
}

/* Creates a string representation of the state of an 'ipf_list' and puts
 * it in 'ds'. */
static void
ipf_dump_create(const struct ipf_list *ipf_list, struct ds *ds)
{
    ds_put_cstr(ds, "(");
    if (ipf_list->key.dl_type == htons(ETH_TYPE_IP)) {
        ds_put_format(ds, "src="IP_FMT",dst="IP_FMT",",
                      IP_ARGS(ipf_list->key.src_addr.ipv4),
                      IP_ARGS(ipf_list->key.dst_addr.ipv4));
    } else {
        ds_put_cstr(ds, "src=");
        ipv6_format_addr(&ipf_list->key.src_addr.ipv6, ds);
        ds_put_cstr(ds, ",dst=");
        ipv6_format_addr(&ipf_list->key.dst_addr.ipv6, ds);
        ds_put_cstr(ds, ",");
    }

    ds_put_format(ds, "recirc_id=%u,ip_id=%u,dl_type=0x%x,zone=%u,nw_proto=%u",
                  ipf_list->key.recirc_id, ntohl(ipf_list->key.ip_id),
                  ntohs(ipf_list->key.dl_type), ipf_list->key.zone,
                  ipf_list->key.nw_proto);

    ds_put_format(ds, ",num_fragments=%u,state=%s",
                  ipf_list->last_inuse_idx + 1,
                  ipf_state_name[ipf_list->state]);

    ds_put_cstr(ds, ")");
}

/* Finds the next ipf list starting from 'ipf_dump_ctx->bucket_pos' and uses
 * ipf_dump_create() to create a string representation of the state of an
 * ipf list, to which 'dump' is pointed to.  Returns EOF when there are no
 * more ipf lists. */
int
ipf_dump_next(struct ipf *ipf, struct ipf_dump_ctx *ipf_dump_ctx, char **dump)
{
    ovs_mutex_lock(&ipf->ipf_lock);

    struct hmap_node *node = hmap_at_position(&ipf->frag_lists,
                                              &ipf_dump_ctx->bucket_pos);
    if (!node) {
        ovs_mutex_unlock(&ipf->ipf_lock);
        return EOF;
    } else {
        struct ipf_list *ipf_list_;
        INIT_CONTAINER(ipf_list_, node, node);
        struct ipf_list ipf_list = *ipf_list_;
        ovs_mutex_unlock(&ipf->ipf_lock);
        struct ds ds = DS_EMPTY_INITIALIZER;
        ipf_dump_create(&ipf_list, &ds);
        *dump = ds_steal_cstr(&ds);
        return 0;
    }
}

/* Frees 'ipf_dump_ctx' allocated by ipf_dump_start(). */
int
ipf_dump_done(struct ipf_dump_ctx *ipf_dump_ctx)
{
    free(ipf_dump_ctx);
    return 0;
}
