/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#ifndef MATCH_H
#define MATCH_H 1

#include "flow.h"

struct ds;

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
};

void match_init(struct match *,
                const struct flow *, const struct flow_wildcards *);
void match_wc_init(struct match *match, const struct flow *flow);
void match_init_catchall(struct match *);
void match_init_exact(struct match *, const struct flow *);

void match_zero_wildcarded_fields(struct match *);

void match_set_reg(struct match *, unsigned int reg_idx, uint32_t value);
void match_set_reg_masked(struct match *, unsigned int reg_idx,
                          uint32_t value, uint32_t mask);
void match_set_metadata(struct match *, ovs_be64 metadata);
void match_set_metadata_masked(struct match *,
                               ovs_be64 metadata, ovs_be64 mask);
void match_set_tun_id(struct match *, ovs_be64 tun_id);
void match_set_tun_id_masked(struct match *, ovs_be64 tun_id, ovs_be64 mask);
void match_set_tun_src(struct match *match, ovs_be32 src);
void match_set_tun_src_masked(struct match *match, ovs_be32 src, ovs_be32 mask);
void match_set_tun_dst(struct match *match, ovs_be32 dst);
void match_set_tun_dst_masked(struct match *match, ovs_be32 dst, ovs_be32 mask);
void match_set_tun_ttl(struct match *match, uint8_t ttl);
void match_set_tun_ttl_masked(struct match *match, uint8_t ttl, uint8_t mask);
void match_set_tun_tos(struct match *match, uint8_t tos);
void match_set_tun_tos_masked(struct match *match, uint8_t tos, uint8_t mask);
void match_set_tun_flags(struct match *match, uint16_t flags);
void match_set_tun_flags_masked(struct match *match, uint16_t flags, uint16_t mask);
void match_set_in_port(struct match *, uint16_t ofp_port);
void match_set_skb_mark(struct match *, uint32_t skb_mark);
void match_set_skb_priority(struct match *, uint32_t skb_priority);
void match_set_dl_type(struct match *, ovs_be16);
void match_set_dl_src(struct match *, const uint8_t[6]);
void match_set_dl_src_masked(struct match *, const uint8_t dl_src[6],
                             const uint8_t mask[6]);
void match_set_dl_dst(struct match *, const uint8_t[6]);
void match_set_dl_dst_masked(struct match *, const uint8_t dl_dst[6],
                             const uint8_t mask[6]);
void match_set_dl_tci(struct match *, ovs_be16 tci);
void match_set_dl_tci_masked(struct match *, ovs_be16 tci, ovs_be16 mask);
void match_set_any_vid(struct match *);
void match_set_dl_vlan(struct match *, ovs_be16);
void match_set_vlan_vid(struct match *, ovs_be16);
void match_set_vlan_vid_masked(struct match *, ovs_be16 vid, ovs_be16 mask);
void match_set_any_pcp(struct match *);
void match_set_dl_vlan_pcp(struct match *, uint8_t);
void match_set_tp_src(struct match *, ovs_be16);
void match_set_tp_src_masked(struct match *, ovs_be16 port, ovs_be16 mask);
void match_set_tp_dst(struct match *, ovs_be16);
void match_set_tp_dst_masked(struct match *, ovs_be16 port, ovs_be16 mask);
void match_set_nw_proto(struct match *, uint8_t);
void match_set_nw_src(struct match *, ovs_be32);
void match_set_nw_src_masked(struct match *, ovs_be32 ip, ovs_be32 mask);
void match_set_nw_dst(struct match *, ovs_be32);
void match_set_nw_dst_masked(struct match *, ovs_be32 ip, ovs_be32 mask);
void match_set_nw_dscp(struct match *, uint8_t);
void match_set_nw_ecn(struct match *, uint8_t);
void match_set_nw_ttl(struct match *, uint8_t);
void match_set_nw_frag(struct match *, uint8_t nw_frag);
void match_set_nw_frag_masked(struct match *, uint8_t nw_frag, uint8_t mask);
void match_set_icmp_type(struct match *, uint8_t);
void match_set_icmp_code(struct match *, uint8_t);
void match_set_arp_sha(struct match *, const uint8_t[6]);
void match_set_arp_sha_masked(struct match *,
                              const uint8_t arp_sha[6],
                              const uint8_t mask[6]);
void match_set_arp_tha(struct match *, const uint8_t[6]);
void match_set_arp_tha_masked(struct match *,
                              const uint8_t arp_tha[6],
                              const uint8_t mask[6]);
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

void match_format(const struct match *, struct ds *, unsigned int priority);
char *match_to_string(const struct match *, unsigned int priority);
void match_print(const struct match *);

/* Compressed match. */

/* A sparse representation of a "struct match".
 *
 * This has the same invariant as "struct match", that is, a 1-bit in the
 * 'flow' must correspond to a 1-bit in 'mask'.
 *
 * The invariants for the underlying miniflow and minimask are also maintained,
 * which means that 'flow' and 'mask' can have different 'map's.  In
 * particular, if the match checks that a given 32-bit field has value 0, then
 * 'map' will have a 1-bit in 'mask' but a 0-bit in 'flow' for that field. */
struct minimatch {
    struct miniflow flow;
    struct minimask mask;
};

void minimatch_init(struct minimatch *, const struct match *);
void minimatch_clone(struct minimatch *, const struct minimatch *);
void minimatch_destroy(struct minimatch *);

void minimatch_expand(const struct minimatch *, struct match *);

bool minimatch_equal(const struct minimatch *a, const struct minimatch *b);
uint32_t minimatch_hash(const struct minimatch *, uint32_t basis);

void minimatch_format(const struct minimatch *, struct ds *,
                      unsigned int priority);
char *minimatch_to_string(const struct minimatch *, unsigned int priority);

#endif /* match.h */
