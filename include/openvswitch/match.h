/*
 * Copyright (c) 2009-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_MATCH_H
#define OPENVSWITCH_MATCH_H 1

#include "openvswitch/flow.h"
#include "openvswitch/packets.h"
#include "openvswitch/tun-metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ds;
struct ofputil_port_map;
struct mf_field;

/* A flow classification match.
 *
 * Use one of the match_*() functions to initialize a "struct match".
 *
 * The match_*() functions below maintain the following important invariant.
 * If a bit or a field is wildcarded in 'wc', then the corresponding bit or
 * field in 'flow' is set to all-0-bits.  (The match_zero_wildcarded_fields()
 * function can be used to restore this invariant after adding wildcards.) */
struct match {
    struct flow flow;
    struct flow_wildcards wc;
    struct tun_metadata_allocation tun_md;
};

/* Initializer for a "struct match" that matches every packet. */
#define MATCH_CATCHALL_INITIALIZER { .flow = { .dl_type = 0 } }

#define MATCH_SET_FIELD_MASKED(match, field, value, msk)      \
    do {                                                      \
        (match)->wc.masks.field = (msk);                      \
        (match)->flow.field = (value) & (msk);                \
    } while (0)

#define MATCH_SET_FIELD_UINT8(match, field, value)            \
    MATCH_SET_FIELD_MASKED(match, field, value, UINT8_MAX)

#define MATCH_SET_FIELD_BE32(match, field, value)             \
    MATCH_SET_FIELD_MASKED(match, field, value, OVS_BE32_MAX)

void match_init(struct match *,
                const struct flow *, const struct flow_wildcards *);
void match_wc_init(struct match *match, const struct flow *flow);
void match_init_catchall(struct match *);

void match_zero_wildcarded_fields(struct match *);

void match_set_dp_hash(struct match *, uint32_t value);
void match_set_dp_hash_masked(struct match *, uint32_t value, uint32_t mask);

void match_set_recirc_id(struct match *, uint32_t value);

void match_set_conj_id(struct match *, uint32_t value);

void match_set_reg(struct match *, unsigned int reg_idx, uint32_t value);
void match_set_reg_masked(struct match *, unsigned int reg_idx,
                          uint32_t value, uint32_t mask);
void match_set_xreg(struct match *, unsigned int xreg_idx, uint64_t value);
void match_set_xreg_masked(struct match *, unsigned int xreg_idx,
                           uint64_t value, uint64_t mask);
void match_set_xxreg(struct match *, unsigned int xxreg_idx, ovs_u128 value);
void match_set_xxreg_masked(struct match *, unsigned int xxreg_idx,
                           ovs_u128 value, ovs_u128 mask);
void match_set_actset_output(struct match *, ofp_port_t actset_output);
void match_set_metadata(struct match *, ovs_be64 metadata);
void match_set_metadata_masked(struct match *,
                               ovs_be64 metadata, ovs_be64 mask);
void match_set_tun_id(struct match *, ovs_be64 tun_id);
void match_set_tun_id_masked(struct match *, ovs_be64 tun_id, ovs_be64 mask);
void match_set_tun_src(struct match *match, ovs_be32 src);
void match_set_tun_src_masked(struct match *match, ovs_be32 src, ovs_be32 mask);
void match_set_tun_dst(struct match *match, ovs_be32 dst);
void match_set_tun_dst_masked(struct match *match, ovs_be32 dst, ovs_be32 mask);
void match_set_tun_ipv6_src(struct match *, const struct in6_addr *);
void match_set_tun_ipv6_src_masked(struct match *, const struct in6_addr *,
                                   const struct in6_addr *);
void match_set_tun_ipv6_dst(struct match *, const struct in6_addr *);
void match_set_tun_ipv6_dst_masked(struct match *, const struct in6_addr *,
                                   const struct in6_addr *);
void match_set_tun_ttl(struct match *match, uint8_t ttl);
void match_set_tun_ttl_masked(struct match *match, uint8_t ttl, uint8_t mask);
void match_set_tun_tos(struct match *match, uint8_t tos);
void match_set_tun_tos_masked(struct match *match, uint8_t tos, uint8_t mask);
void match_set_tun_flags(struct match *match, uint16_t flags);
void match_set_tun_flags_masked(struct match *match, uint16_t flags, uint16_t mask);
void match_set_tun_tp_dst(struct match *match, ovs_be16 tp_dst);
void match_set_tun_tp_dst_masked(struct match *match, ovs_be16 port, ovs_be16 mask);
void match_set_tun_gbp_id_masked(struct match *match, ovs_be16 gbp_id, ovs_be16 mask);
void match_set_tun_gbp_id(struct match *match, ovs_be16 gbp_id);
void match_set_tun_gbp_flags_masked(struct match *match, uint8_t flags, uint8_t mask);
void match_set_tun_gbp_flags(struct match *match, uint8_t flags);
void match_set_tun_erspan_ver(struct match *match, uint8_t ver);
void match_set_tun_erspan_ver_masked(struct match *match, uint8_t ver,
                                     uint8_t mask);
void match_set_tun_erspan_idx(struct match *match, uint32_t idx);
void match_set_tun_erspan_idx_masked(struct match *match, uint32_t idx,
                                     uint32_t mask);
void match_set_tun_erspan_dir(struct match *match, uint8_t dir);
void match_set_tun_erspan_dir_masked(struct match *match, uint8_t dir,
                                     uint8_t mask);
void match_set_tun_erspan_hwid(struct match *match, uint8_t hwid);
void match_set_tun_erspan_hwid_masked(struct match *match, uint8_t hwid,
                                      uint8_t mask);
void match_set_in_port(struct match *, ofp_port_t ofp_port);
void match_set_pkt_mark(struct match *, uint32_t pkt_mark);
void match_set_pkt_mark_masked(struct match *, uint32_t pkt_mark, uint32_t mask);
void match_set_ct_state(struct match *, uint32_t ct_state);
void match_set_ct_state_masked(struct match *, uint32_t ct_state, uint32_t mask);
void match_set_ct_zone(struct match *, uint16_t ct_zone);
void match_set_ct_mark(struct match *, uint32_t ct_mark);
void match_set_ct_mark_masked(struct match *, uint32_t ct_mark, uint32_t mask);
void match_set_ct_label(struct match *, ovs_u128 ct_label);
void match_set_ct_label_masked(struct match *, ovs_u128 ct_label, ovs_u128 mask);
void match_set_ct_nw_src(struct match *, ovs_be32);
void match_set_ct_nw_src_masked(struct match *, ovs_be32, ovs_be32 mask);
void match_set_ct_nw_dst(struct match *, ovs_be32);
void match_set_ct_nw_dst_masked(struct match *, ovs_be32, ovs_be32 mask);
void match_set_ct_nw_proto(struct match *, uint8_t);
void match_set_ct_tp_src(struct match *, ovs_be16);
void match_set_ct_tp_src_masked(struct match *, ovs_be16, ovs_be16 mask);
void match_set_ct_tp_dst(struct match *, ovs_be16);
void match_set_ct_tp_dst_masked(struct match *, ovs_be16, ovs_be16 mask);
void match_set_ct_ipv6_src(struct match *, const struct in6_addr *);
void match_set_ct_ipv6_src_masked(struct match *, const struct in6_addr *,
                                  const struct in6_addr *);
void match_set_ct_ipv6_dst(struct match *, const struct in6_addr *);
void match_set_ct_ipv6_dst_masked(struct match *, const struct in6_addr *,
                                  const struct in6_addr *);

void match_set_packet_type(struct match *, ovs_be32 packet_type);
void match_set_default_packet_type(struct match *);
bool match_has_default_packet_type(const struct match *);
void match_add_ethernet_prereq(struct match *, const struct mf_field *);

void match_set_skb_priority(struct match *, uint32_t skb_priority);
void match_set_dl_type(struct match *, ovs_be16);
void match_set_dl_src(struct match *, const struct eth_addr );
void match_set_dl_src_masked(struct match *, const struct eth_addr dl_src,
                             const struct eth_addr mask);
void match_set_dl_dst(struct match *, const struct eth_addr);
void match_set_dl_dst_masked(struct match *, const struct eth_addr dl_dst,
                             const struct eth_addr mask);
void match_set_dl_tci(struct match *, ovs_be16 tci);
void match_set_dl_tci_masked(struct match *, ovs_be16 tci, ovs_be16 mask);
void match_set_any_vid(struct match *);
void match_set_dl_vlan(struct match *, ovs_be16);
void match_set_vlan_vid(struct match *, ovs_be16);
void match_set_vlan_vid_masked(struct match *, ovs_be16 vid, ovs_be16 mask);
void match_set_any_pcp(struct match *);
void match_set_dl_vlan_pcp(struct match *, uint8_t);
void match_set_any_mpls_lse(struct match *, int idx);
void match_set_mpls_lse(struct match *, int idx, ovs_be32);
void match_set_any_mpls_label(struct match *, int idx);
void match_set_mpls_label(struct match *, int idx, ovs_be32);
void match_set_any_mpls_tc(struct match *, int idx);
void match_set_mpls_tc(struct match *, int idx, uint8_t);
void match_set_any_mpls_bos(struct match *, int idx);
void match_set_mpls_bos(struct match *, int idx, uint8_t);
void match_set_any_mpls_ttl(struct match *, int idx);
void match_set_mpls_ttl(struct match *, int idx, uint8_t);
void match_set_tp_src(struct match *, ovs_be16);
void match_set_mpls_lse(struct match *, int idx, ovs_be32 lse);
void match_set_tp_src_masked(struct match *, ovs_be16 port, ovs_be16 mask);
void match_set_tp_dst(struct match *, ovs_be16);
void match_set_tp_dst_masked(struct match *, ovs_be16 port, ovs_be16 mask);
void match_set_tcp_flags(struct match *, ovs_be16);
void match_set_tcp_flags_masked(struct match *, ovs_be16 flags, ovs_be16 mask);
void match_set_nw_proto(struct match *, uint8_t);
void match_set_nw_src(struct match *, ovs_be32);
void match_set_nw_src_masked(struct match *, ovs_be32 ip, ovs_be32 mask);
void match_set_nw_dst(struct match *, ovs_be32);
void match_set_nw_dst_masked(struct match *, ovs_be32 ip, ovs_be32 mask);
void match_set_nw_dscp(struct match *, uint8_t);
void match_set_nw_ecn(struct match *, uint8_t);
void match_set_nw_ttl(struct match *, uint8_t nw_ttl);
void match_set_nw_ttl_masked(struct match *, uint8_t nw_ttl, uint8_t mask);
void match_set_nw_frag(struct match *, uint8_t nw_frag);
void match_set_nw_frag_masked(struct match *, uint8_t nw_frag, uint8_t mask);
void match_set_icmp_type(struct match *, uint8_t);
void match_set_icmp_code(struct match *, uint8_t);
void match_set_arp_sha(struct match *, const struct eth_addr);
void match_set_arp_sha_masked(struct match *,
                              const struct eth_addr arp_sha,
                              const struct eth_addr mask);
void match_set_arp_tha(struct match *, const struct eth_addr);
void match_set_arp_tha_masked(struct match *,
                              const struct eth_addr arp_tha,
                              const struct eth_addr mask);
void match_set_ipv6_src(struct match *, const struct in6_addr *);
void match_set_ipv6_src_masked(struct match *, const struct in6_addr *,
                               const struct in6_addr *);
void match_set_ipv6_dst(struct match *, const struct in6_addr *);
void match_set_ipv6_dst_masked(struct match *, const struct in6_addr *,
                               const struct in6_addr *);
void match_set_ipv6_label(struct match *, ovs_be32);
void match_set_ipv6_label_masked(struct match *, ovs_be32, ovs_be32);
void match_set_nd_target(struct match *, const struct in6_addr *);
void match_set_nd_target_masked(struct match *, const struct in6_addr *,
                                const struct in6_addr *);

bool match_equal(const struct match *, const struct match *);
uint32_t match_hash(const struct match *, uint32_t basis);

void match_init_hidden_fields(struct match *);
bool match_has_default_hidden_fields(const struct match *);

void match_format(const struct match *, const struct ofputil_port_map *,
                  struct ds *, int priority);
char *match_to_string(const struct match *, const struct ofputil_port_map *,
                      int priority);
void match_print(const struct match *, const struct ofputil_port_map *);

/* Compressed match. */

/* A sparse representation of a "struct match".
 *
 * 'flows' is used for allocating both 'flow' and 'mask' with one
 * miniflow_alloc() call.
 *
 * There are two invariants:
 *
 *   - The same invariant as "struct match", that is, a 1-bit in the 'flow'
 *     must correspond to a 1-bit in 'mask'.
 *
 *   - 'flow' and 'mask' have the same 'map'.  This implies that 'flow' and
 *     'mask' have the same part of "struct flow" at the same offset into
 *     'values', which makes minimatch_matches_flow() faster.
 */
struct minimatch {
    union {
        struct {
            struct miniflow *flow;
            struct minimask *mask;
        };
        struct miniflow *flows[2];
    };
    struct tun_metadata_allocation *tun_md;
};

void minimatch_init(struct minimatch *, const struct match *);
void minimatch_init_catchall(struct minimatch *);
void minimatch_clone(struct minimatch *, const struct minimatch *);
void minimatch_move(struct minimatch *dst, struct minimatch *src);
void minimatch_destroy(struct minimatch *);

void minimatch_expand(const struct minimatch *, struct match *);

bool minimatch_equal(const struct minimatch *a, const struct minimatch *b);
uint32_t minimatch_hash(const struct minimatch *, uint32_t basis);

bool minimatch_matches_flow(const struct minimatch *, const struct flow *);

void minimatch_format(const struct minimatch *, const struct tun_table *,
                      const struct ofputil_port_map *,
                      struct ds *, int priority);
char *minimatch_to_string(const struct minimatch *,
                          const struct ofputil_port_map *, int priority);

bool minimatch_has_default_hidden_fields(const struct minimatch *);

#ifdef __cplusplus
}
#endif

#endif /* match.h */
