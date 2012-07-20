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

#include <config.h>
#include "classifier.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "packets.h"

static struct cls_table *find_table(const struct classifier *,
                                    const struct flow_wildcards *);
static struct cls_table *insert_table(struct classifier *,
                                      const struct flow_wildcards *);

static void destroy_table(struct classifier *, struct cls_table *);

static struct cls_rule *find_match(const struct cls_table *,
                                   const struct flow *);
static struct cls_rule *find_equal(struct cls_table *, const struct flow *,
                                   uint32_t hash);
static struct cls_rule *insert_rule(struct cls_table *, struct cls_rule *);

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)                               \
    for ((RULE) = (HEAD); (RULE) != NULL; (RULE) = next_rule_in_list(RULE))
#define FOR_EACH_RULE_IN_LIST_SAFE(RULE, NEXT, HEAD)                    \
    for ((RULE) = (HEAD);                                               \
         (RULE) != NULL && ((NEXT) = next_rule_in_list(RULE), true);    \
         (RULE) = (NEXT))

static struct cls_rule *next_rule_in_list__(struct cls_rule *);
static struct cls_rule *next_rule_in_list(struct cls_rule *);

/* Converts the flow in 'flow' into a cls_rule in 'rule', with the given
 * 'wildcards' and 'priority'. */
void
cls_rule_init(const struct flow *flow, const struct flow_wildcards *wildcards,
              unsigned int priority, struct cls_rule *rule)
{
    rule->flow = *flow;
    rule->wc = *wildcards;
    rule->priority = priority;
    cls_rule_zero_wildcarded_fields(rule);
}

/* Converts the flow in 'flow' into an exact-match cls_rule in 'rule', with the
 * given 'priority'.  (For OpenFlow 1.0, exact-match rule are always highest
 * priority, so 'priority' should be at least 65535.) */
void
cls_rule_init_exact(const struct flow *flow,
                    unsigned int priority, struct cls_rule *rule)
{
    rule->flow = *flow;
    rule->flow.skb_priority = 0;
    flow_wildcards_init_exact(&rule->wc);
    rule->priority = priority;
}

/* Initializes 'rule' as a "catch-all" rule that matches every packet, with
 * priority 'priority'. */
void
cls_rule_init_catchall(struct cls_rule *rule, unsigned int priority)
{
    memset(&rule->flow, 0, sizeof rule->flow);
    flow_wildcards_init_catchall(&rule->wc);
    rule->priority = priority;
}

/* For each bit or field wildcarded in 'rule', sets the corresponding bit or
 * field in 'flow' to all-0-bits.  It is important to maintain this invariant
 * in a clr_rule that might be inserted into a classifier.
 *
 * It is never necessary to call this function directly for a cls_rule that is
 * initialized or modified only by cls_rule_*() functions.  It is useful to
 * restore the invariant in a cls_rule whose 'wc' member is modified by hand.
 */
void
cls_rule_zero_wildcarded_fields(struct cls_rule *rule)
{
    flow_zero_wildcards(&rule->flow, &rule->wc);
}

void
cls_rule_set_reg(struct cls_rule *rule, unsigned int reg_idx, uint32_t value)
{
    cls_rule_set_reg_masked(rule, reg_idx, value, UINT32_MAX);
}

void
cls_rule_set_reg_masked(struct cls_rule *rule, unsigned int reg_idx,
                        uint32_t value, uint32_t mask)
{
    assert(reg_idx < FLOW_N_REGS);
    flow_wildcards_set_reg_mask(&rule->wc, reg_idx, mask);
    rule->flow.regs[reg_idx] = value & mask;
}

void
cls_rule_set_metadata(struct cls_rule *rule, ovs_be64 metadata)
{
    cls_rule_set_metadata_masked(rule, metadata, htonll(UINT64_MAX));
}

void
cls_rule_set_metadata_masked(struct cls_rule *rule, ovs_be64 metadata,
                             ovs_be64 mask)
{
    rule->wc.masks.metadata = mask;
    rule->flow.metadata = metadata & mask;
}

void
cls_rule_set_tun_id(struct cls_rule *rule, ovs_be64 tun_id)
{
    cls_rule_set_tun_id_masked(rule, tun_id, htonll(UINT64_MAX));
}

void
cls_rule_set_tun_id_masked(struct cls_rule *rule,
                           ovs_be64 tun_id, ovs_be64 mask)
{
    rule->wc.masks.tun_id = mask;
    rule->flow.tun_id = tun_id & mask;
}

void
cls_rule_set_in_port(struct cls_rule *rule, uint16_t ofp_port)
{
    rule->wc.masks.in_port = UINT16_MAX;
    rule->flow.in_port = ofp_port;
}

void
cls_rule_set_dl_type(struct cls_rule *rule, ovs_be16 dl_type)
{
    rule->wc.masks.dl_type = htons(UINT16_MAX);
    rule->flow.dl_type = dl_type;
}

/* Modifies 'value_src' so that the Ethernet address must match
 * 'value_dst' exactly. 'mask_dst' is set to all 1s */
static void
cls_rule_set_eth(const uint8_t value_src[ETH_ADDR_LEN],
                 uint8_t value_dst[ETH_ADDR_LEN],
                 uint8_t mask_dst[ETH_ADDR_LEN])
{
    memcpy(value_dst, value_src, ETH_ADDR_LEN);
    memset(mask_dst, 0xff, ETH_ADDR_LEN);
}

/* Modifies 'value_src' so that the Ethernet address must match
 * 'value_src' after each byte is ANDed with the appropriate byte in
 * 'mask_src'. 'mask_dst' is set to 'mask_src' */
static void
cls_rule_set_eth_masked(const uint8_t value_src[ETH_ADDR_LEN],
                        const uint8_t mask_src[ETH_ADDR_LEN],
                        uint8_t value_dst[ETH_ADDR_LEN],
                        uint8_t mask_dst[ETH_ADDR_LEN])
{
    size_t i;

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        value_dst[i] = value_src[i] & mask_src[i];
        mask_dst[i] = mask_src[i];
    }
}

/* Modifies 'rule' so that the source Ethernet address
 * must match 'dl_src' exactly. */
void
cls_rule_set_dl_src(struct cls_rule *rule, const uint8_t dl_src[ETH_ADDR_LEN])
{
    cls_rule_set_eth(dl_src, rule->flow.dl_src, rule->wc.masks.dl_src);
}

/* Modifies 'rule' so that the source Ethernet address
 * must match 'dl_src' after each byte is ANDed with
 * the appropriate byte in 'mask'. */
void
cls_rule_set_dl_src_masked(struct cls_rule *rule,
                           const uint8_t dl_src[ETH_ADDR_LEN],
                           const uint8_t mask[ETH_ADDR_LEN])
{
    cls_rule_set_eth_masked(dl_src, mask,
                            rule->flow.dl_src, rule->wc.masks.dl_src);
}

/* Modifies 'rule' so that the destination Ethernet address
 * must match 'dl_dst' exactly. */
void
cls_rule_set_dl_dst(struct cls_rule *rule, const uint8_t dl_dst[ETH_ADDR_LEN])
{
    cls_rule_set_eth(dl_dst, rule->flow.dl_dst, rule->wc.masks.dl_dst);
}

/* Modifies 'rule' so that the destination Ethernet address
 * must match 'dl_src' after each byte is ANDed with
 * the appropriate byte in 'mask'. */
void
cls_rule_set_dl_dst_masked(struct cls_rule *rule,
                           const uint8_t dl_dst[ETH_ADDR_LEN],
                           const uint8_t mask[ETH_ADDR_LEN])
{
    cls_rule_set_eth_masked(dl_dst, mask,
                            rule->flow.dl_dst, rule->wc.masks.dl_dst);
}

void
cls_rule_set_dl_tci(struct cls_rule *rule, ovs_be16 tci)
{
    cls_rule_set_dl_tci_masked(rule, tci, htons(0xffff));
}

void
cls_rule_set_dl_tci_masked(struct cls_rule *rule, ovs_be16 tci, ovs_be16 mask)
{
    rule->flow.vlan_tci = tci & mask;
    rule->wc.masks.vlan_tci = mask;
}

/* Modifies 'rule' so that the VLAN VID is wildcarded.  If the PCP is already
 * wildcarded, then 'rule' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
cls_rule_set_any_vid(struct cls_rule *rule)
{
    if (rule->wc.masks.vlan_tci & htons(VLAN_PCP_MASK)) {
        rule->wc.masks.vlan_tci &= ~htons(VLAN_VID_MASK);
        rule->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
    } else {
        cls_rule_set_dl_tci_masked(rule, htons(0), htons(0));
    }
}

/* Modifies 'rule' depending on 'dl_vlan':
 *
 *   - If 'dl_vlan' is htons(OFP_VLAN_NONE), makes 'rule' match only packets
 *     without an 802.1Q header.
 *
 *   - Otherwise, makes 'rule' match only packets with an 802.1Q header whose
 *     VID equals the low 12 bits of 'dl_vlan'.
 */
void
cls_rule_set_dl_vlan(struct cls_rule *rule, ovs_be16 dl_vlan)
{
    flow_set_dl_vlan(&rule->flow, dl_vlan);
    if (dl_vlan == htons(OFP10_VLAN_NONE)) {
        rule->wc.masks.vlan_tci = htons(UINT16_MAX);
    } else {
        rule->wc.masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
    }
}

/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI). */
void
cls_rule_set_vlan_vid(struct cls_rule *rule, ovs_be16 vid)
{
    cls_rule_set_vlan_vid_masked(rule, vid, htons(VLAN_VID_MASK | VLAN_CFI));
}


/* Sets the VLAN VID that 'flow' matches to 'vid', which is interpreted as an
 * OpenFlow 1.2 "vlan_vid" value, that is, the low 13 bits of 'vlan_tci' (VID
 * plus CFI), with the corresponding 'mask'. */
void
cls_rule_set_vlan_vid_masked(struct cls_rule *rule,
                             ovs_be16 vid, ovs_be16 mask)
{
    ovs_be16 pcp_mask = htons(VLAN_PCP_MASK);
    ovs_be16 vid_mask = htons(VLAN_VID_MASK | VLAN_CFI);

    mask &= vid_mask;
    flow_set_vlan_vid(&rule->flow, vid & mask);
    rule->wc.masks.vlan_tci = mask | (rule->wc.masks.vlan_tci & pcp_mask);
}

/* Modifies 'rule' so that the VLAN PCP is wildcarded.  If the VID is already
 * wildcarded, then 'rule' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
cls_rule_set_any_pcp(struct cls_rule *rule)
{
    if (rule->wc.masks.vlan_tci & htons(VLAN_VID_MASK)) {
        rule->wc.masks.vlan_tci &= ~htons(VLAN_PCP_MASK);
        rule->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
    } else {
        cls_rule_set_dl_tci_masked(rule, htons(0), htons(0));
    }
}

/* Modifies 'rule' so that it matches only packets with an 802.1Q header whose
 * PCP equals the low 3 bits of 'dl_vlan_pcp'. */
void
cls_rule_set_dl_vlan_pcp(struct cls_rule *rule, uint8_t dl_vlan_pcp)
{
    flow_set_vlan_pcp(&rule->flow, dl_vlan_pcp);
    rule->wc.masks.vlan_tci |= htons(VLAN_CFI | VLAN_PCP_MASK);
}

void
cls_rule_set_tp_src(struct cls_rule *rule, ovs_be16 tp_src)
{
    cls_rule_set_tp_src_masked(rule, tp_src, htons(UINT16_MAX));
}

void
cls_rule_set_tp_src_masked(struct cls_rule *rule, ovs_be16 port, ovs_be16 mask)
{
    rule->flow.tp_src = port & mask;
    rule->wc.masks.tp_src = mask;
}

void
cls_rule_set_tp_dst(struct cls_rule *rule, ovs_be16 tp_dst)
{
    cls_rule_set_tp_dst_masked(rule, tp_dst, htons(UINT16_MAX));
}

void
cls_rule_set_tp_dst_masked(struct cls_rule *rule, ovs_be16 port, ovs_be16 mask)
{
    rule->flow.tp_dst = port & mask;
    rule->wc.masks.tp_dst = mask;
}

void
cls_rule_set_nw_proto(struct cls_rule *rule, uint8_t nw_proto)
{
    rule->flow.nw_proto = nw_proto;
    rule->wc.masks.nw_proto = UINT8_MAX;
}

void
cls_rule_set_nw_src(struct cls_rule *rule, ovs_be32 nw_src)
{
    rule->flow.nw_src = nw_src;
    rule->wc.masks.nw_src = htonl(UINT32_MAX);
}

void
cls_rule_set_nw_src_masked(struct cls_rule *rule,
                           ovs_be32 nw_src, ovs_be32 mask)
{
    rule->flow.nw_src = nw_src & mask;
    rule->wc.masks.nw_src = mask;
}

void
cls_rule_set_nw_dst(struct cls_rule *rule, ovs_be32 nw_dst)
{
    rule->flow.nw_dst = nw_dst;
    rule->wc.masks.nw_dst = htonl(UINT32_MAX);
}

void
cls_rule_set_nw_dst_masked(struct cls_rule *rule, ovs_be32 ip, ovs_be32 mask)
{
    rule->flow.nw_dst = ip & mask;
    rule->wc.masks.nw_dst = mask;
}

void
cls_rule_set_nw_dscp(struct cls_rule *rule, uint8_t nw_dscp)
{
    rule->wc.masks.nw_tos |= IP_DSCP_MASK;
    rule->flow.nw_tos &= ~IP_DSCP_MASK;
    rule->flow.nw_tos |= nw_dscp & IP_DSCP_MASK;
}

void
cls_rule_set_nw_ecn(struct cls_rule *rule, uint8_t nw_ecn)
{
    rule->wc.masks.nw_tos |= IP_ECN_MASK;
    rule->flow.nw_tos &= ~IP_ECN_MASK;
    rule->flow.nw_tos |= nw_ecn & IP_ECN_MASK;
}

void
cls_rule_set_nw_ttl(struct cls_rule *rule, uint8_t nw_ttl)
{
    rule->wc.masks.nw_ttl = UINT8_MAX;
    rule->flow.nw_ttl = nw_ttl;
}

void
cls_rule_set_nw_frag(struct cls_rule *rule, uint8_t nw_frag)
{
    rule->wc.masks.nw_frag |= FLOW_NW_FRAG_MASK;
    rule->flow.nw_frag = nw_frag;
}

void
cls_rule_set_nw_frag_masked(struct cls_rule *rule,
                            uint8_t nw_frag, uint8_t mask)
{
    rule->flow.nw_frag = nw_frag & mask;
    rule->wc.masks.nw_frag = mask;
}

void
cls_rule_set_icmp_type(struct cls_rule *rule, uint8_t icmp_type)
{
    cls_rule_set_tp_src(rule, htons(icmp_type));
}

void
cls_rule_set_icmp_code(struct cls_rule *rule, uint8_t icmp_code)
{
    cls_rule_set_tp_dst(rule, htons(icmp_code));
}

void
cls_rule_set_arp_sha(struct cls_rule *rule, const uint8_t sha[ETH_ADDR_LEN])
{
    cls_rule_set_eth(sha, rule->flow.arp_sha, rule->wc.masks.arp_sha);
}

void
cls_rule_set_arp_sha_masked(struct cls_rule *rule,
                           const uint8_t arp_sha[ETH_ADDR_LEN],
                           const uint8_t mask[ETH_ADDR_LEN])
{
    cls_rule_set_eth_masked(arp_sha, mask,
                            rule->flow.arp_sha, rule->wc.masks.arp_sha);
}

void
cls_rule_set_arp_tha(struct cls_rule *rule, const uint8_t tha[ETH_ADDR_LEN])
{
    cls_rule_set_eth(tha, rule->flow.arp_tha, rule->wc.masks.arp_tha);
}

void
cls_rule_set_arp_tha_masked(struct cls_rule *rule,
                           const uint8_t arp_tha[ETH_ADDR_LEN],
                           const uint8_t mask[ETH_ADDR_LEN])
{
    cls_rule_set_eth_masked(arp_tha, mask,
                            rule->flow.arp_tha, rule->wc.masks.arp_tha);
}

void
cls_rule_set_ipv6_src(struct cls_rule *rule, const struct in6_addr *src)
{
    rule->flow.ipv6_src = *src;
    rule->wc.masks.ipv6_src = in6addr_exact;
}

void
cls_rule_set_ipv6_src_masked(struct cls_rule *rule, const struct in6_addr *src,
                             const struct in6_addr *mask)
{
    rule->flow.ipv6_src = ipv6_addr_bitand(src, mask);
    rule->wc.masks.ipv6_src = *mask;
}

void
cls_rule_set_ipv6_dst(struct cls_rule *rule, const struct in6_addr *dst)
{
    rule->flow.ipv6_dst = *dst;
    rule->wc.masks.ipv6_dst = in6addr_exact;
}

void
cls_rule_set_ipv6_dst_masked(struct cls_rule *rule, const struct in6_addr *dst,
                             const struct in6_addr *mask)
{
    rule->flow.ipv6_dst = ipv6_addr_bitand(dst, mask);
    rule->wc.masks.ipv6_dst = *mask;
}

void
cls_rule_set_ipv6_label(struct cls_rule *rule, ovs_be32 ipv6_label)
{
    cls_rule_set_ipv6_label_masked(rule, ipv6_label, htonl(UINT32_MAX));
}

void
cls_rule_set_ipv6_label_masked(struct cls_rule *rule, ovs_be32 ipv6_label,
                               ovs_be32 mask)
{
    rule->flow.ipv6_label = ipv6_label & mask;
    rule->wc.masks.ipv6_label = mask;
}

void
cls_rule_set_nd_target(struct cls_rule *rule, const struct in6_addr *target)
{
    rule->flow.nd_target = *target;
    rule->wc.masks.nd_target = in6addr_exact;
}

void
cls_rule_set_nd_target_masked(struct cls_rule *rule,
                              const struct in6_addr *target,
                              const struct in6_addr *mask)
{
    rule->flow.nd_target = ipv6_addr_bitand(target, mask);
    rule->wc.masks.nd_target = *mask;
}

/* Returns true if 'a' and 'b' have the same priority, wildcard the same
 * fields, and have the same values for fixed fields, otherwise false. */
bool
cls_rule_equal(const struct cls_rule *a, const struct cls_rule *b)
{
    return (a->priority == b->priority
            && flow_wildcards_equal(&a->wc, &b->wc)
            && flow_equal(&a->flow, &b->flow));
}

/* Returns a hash value for the flow, wildcards, and priority in 'rule',
 * starting from 'basis'. */
uint32_t
cls_rule_hash(const struct cls_rule *rule, uint32_t basis)
{
    uint32_t h0 = flow_hash(&rule->flow, basis);
    uint32_t h1 = flow_wildcards_hash(&rule->wc, h0);
    return hash_int(rule->priority, h1);
}

static void
format_eth_masked(struct ds *s, const char *name, const uint8_t eth[6],
                  const uint8_t mask[6])
{
    if (!eth_addr_is_zero(mask)) {
        ds_put_format(s, "%s=", name);
        eth_format_masked(eth, mask, s);
        ds_put_char(s, ',');
    }
}

static void
format_ip_netmask(struct ds *s, const char *name, ovs_be32 ip,
                  ovs_be32 netmask)
{
    if (netmask) {
        ds_put_format(s, "%s=", name);
        ip_format_masked(ip, netmask, s);
        ds_put_char(s, ',');
    }
}

static void
format_ipv6_netmask(struct ds *s, const char *name,
                    const struct in6_addr *addr,
                    const struct in6_addr *netmask)
{
    if (!ipv6_mask_is_any(netmask)) {
        ds_put_format(s, "%s=", name);
        print_ipv6_masked(s, addr, netmask);
        ds_put_char(s, ',');
    }
}


static void
format_be16_masked(struct ds *s, const char *name,
                   ovs_be16 value, ovs_be16 mask)
{
    if (mask != htons(0)) {
        ds_put_format(s, "%s=", name);
        if (mask == htons(UINT16_MAX)) {
            ds_put_format(s, "%"PRIu16, ntohs(value));
        } else {
            ds_put_format(s, "0x%"PRIx16"/0x%"PRIx16,
                          ntohs(value), ntohs(mask));
        }
        ds_put_char(s, ',');
    }
}

void
cls_rule_format(const struct cls_rule *rule, struct ds *s)
{
    const struct flow_wildcards *wc = &rule->wc;
    size_t start_len = s->length;
    const struct flow *f = &rule->flow;
    bool skip_type = false;
    bool skip_proto = false;

    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 17);

    if (rule->priority != OFP_DEFAULT_PRIORITY) {
        ds_put_format(s, "priority=%d,", rule->priority);
    }

    if (wc->masks.dl_type) {
        skip_type = true;
        if (f->dl_type == htons(ETH_TYPE_IP)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMP) {
                    ds_put_cstr(s, "icmp,");
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(s, "tcp,");
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(s, "udp,");
                } else {
                    ds_put_cstr(s, "ip,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(s, "ip,");
            }
        } else if (f->dl_type == htons(ETH_TYPE_IPV6)) {
            if (wc->masks.nw_proto) {
                skip_proto = true;
                if (f->nw_proto == IPPROTO_ICMPV6) {
                    ds_put_cstr(s, "icmp6,");
                } else if (f->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(s, "tcp6,");
                } else if (f->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(s, "udp6,");
                } else {
                    ds_put_cstr(s, "ipv6,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(s, "ipv6,");
            }
        } else if (f->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_cstr(s, "arp,");
        } else {
            skip_type = false;
        }
    }
    for (i = 0; i < FLOW_N_REGS; i++) {
        switch (wc->masks.regs[i]) {
        case 0:
            break;
        case UINT32_MAX:
            ds_put_format(s, "reg%d=0x%"PRIx32",", i, f->regs[i]);
            break;
        default:
            ds_put_format(s, "reg%d=0x%"PRIx32"/0x%"PRIx32",",
                          i, f->regs[i], wc->masks.regs[i]);
            break;
        }
    }
    switch (wc->masks.tun_id) {
    case 0:
        break;
    case CONSTANT_HTONLL(UINT64_MAX):
        ds_put_format(s, "tun_id=%#"PRIx64",", ntohll(f->tun_id));
        break;
    default:
        ds_put_format(s, "tun_id=%#"PRIx64"/%#"PRIx64",",
                      ntohll(f->tun_id), ntohll(wc->masks.tun_id));
        break;
    }
    switch (wc->masks.metadata) {
    case 0:
        break;
    case CONSTANT_HTONLL(UINT64_MAX):
        ds_put_format(s, "metadata=%#"PRIx64",", ntohll(f->metadata));
        break;
    default:
        ds_put_format(s, "metadata=%#"PRIx64"/%#"PRIx64",",
                      ntohll(f->metadata), ntohll(wc->masks.metadata));
        break;
    }
    if (wc->masks.in_port) {
        ds_put_format(s, "in_port=%"PRIu16",", f->in_port);
    }
    if (wc->masks.vlan_tci) {
        ovs_be16 vid_mask = wc->masks.vlan_tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = wc->masks.vlan_tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = wc->masks.vlan_tci & htons(VLAN_CFI);

        if (cfi && f->vlan_tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                ds_put_format(s, "dl_vlan=%"PRIu16",",
                              vlan_tci_to_vid(f->vlan_tci));
            }
            if (pcp_mask) {
                ds_put_format(s, "dl_vlan_pcp=%d,",
                              vlan_tci_to_pcp(f->vlan_tci));
            }
        } else if (wc->masks.vlan_tci == htons(0xffff)) {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16",", ntohs(f->vlan_tci));
        } else {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16"/0x%04"PRIx16",",
                          ntohs(f->vlan_tci), ntohs(wc->masks.vlan_tci));
        }
    }
    format_eth_masked(s, "dl_src", f->dl_src, wc->masks.dl_src);
    format_eth_masked(s, "dl_dst", f->dl_dst, wc->masks.dl_dst);
    if (!skip_type && wc->masks.dl_type) {
        ds_put_format(s, "dl_type=0x%04"PRIx16",", ntohs(f->dl_type));
    }
    if (f->dl_type == htons(ETH_TYPE_IPV6)) {
        format_ipv6_netmask(s, "ipv6_src", &f->ipv6_src, &wc->masks.ipv6_src);
        format_ipv6_netmask(s, "ipv6_dst", &f->ipv6_dst, &wc->masks.ipv6_dst);
        if (wc->masks.ipv6_label) {
            if (wc->masks.ipv6_label == htonl(UINT32_MAX)) {
                ds_put_format(s, "ipv6_label=0x%05"PRIx32",",
                              ntohl(f->ipv6_label));
            } else {
                ds_put_format(s, "ipv6_label=0x%05"PRIx32"/0x%05"PRIx32",",
                              ntohl(f->ipv6_label),
                              ntohl(wc->masks.ipv6_label));
            }
        }
    } else {
        format_ip_netmask(s, "nw_src", f->nw_src, wc->masks.nw_src);
        format_ip_netmask(s, "nw_dst", f->nw_dst, wc->masks.nw_dst);
    }
    if (!skip_proto && wc->masks.nw_proto) {
        if (f->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_format(s, "arp_op=%"PRIu8",", f->nw_proto);
        } else {
            ds_put_format(s, "nw_proto=%"PRIu8",", f->nw_proto);
        }
    }
    if (f->dl_type == htons(ETH_TYPE_ARP)) {
        format_eth_masked(s, "arp_sha", f->arp_sha, wc->masks.arp_sha);
        format_eth_masked(s, "arp_tha", f->arp_tha, wc->masks.arp_tha);
    }
    if (wc->masks.nw_tos & IP_DSCP_MASK) {
        ds_put_format(s, "nw_tos=%"PRIu8",", f->nw_tos & IP_DSCP_MASK);
    }
    if (wc->masks.nw_tos & IP_ECN_MASK) {
        ds_put_format(s, "nw_ecn=%"PRIu8",", f->nw_tos & IP_ECN_MASK);
    }
    if (wc->masks.nw_ttl) {
        ds_put_format(s, "nw_ttl=%"PRIu8",", f->nw_ttl);
    }
    switch (wc->masks.nw_frag) {
    case FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_ANY
                      ? (f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "first")
                      : (f->nw_frag & FLOW_NW_FRAG_LATER ? "<error>" : "no"));
        break;

    case FLOW_NW_FRAG_ANY:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_ANY ? "yes" : "no");
        break;

    case FLOW_NW_FRAG_LATER:
        ds_put_format(s, "nw_frag=%s,",
                      f->nw_frag & FLOW_NW_FRAG_LATER ? "later" : "not_later");
        break;
    }
    if (f->nw_proto == IPPROTO_ICMP) {
        format_be16_masked(s, "icmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "icmp_code", f->tp_dst, wc->masks.tp_dst);
    } else if (f->nw_proto == IPPROTO_ICMPV6) {
        format_be16_masked(s, "icmp_type", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "icmp_code", f->tp_dst, wc->masks.tp_dst);
        format_ipv6_netmask(s, "nd_target", &f->nd_target,
                            &wc->masks.nd_target);
        format_eth_masked(s, "nd_sll", f->arp_sha, wc->masks.arp_sha);
        format_eth_masked(s, "nd_tll", f->arp_tha, wc->masks.arp_tha);
   } else {
        format_be16_masked(s, "tp_src", f->tp_src, wc->masks.tp_src);
        format_be16_masked(s, "tp_dst", f->tp_dst, wc->masks.tp_dst);
    }

    if (s->length > start_len && ds_last(s) == ',') {
        s->length--;
    }
}

/* Converts 'rule' to a string and returns the string.  The caller must free
 * the string (with free()). */
char *
cls_rule_to_string(const struct cls_rule *rule)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    cls_rule_format(rule, &s);
    return ds_steal_cstr(&s);
}

void
cls_rule_print(const struct cls_rule *rule)
{
    char *s = cls_rule_to_string(rule);
    puts(s);
    free(s);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
void
classifier_init(struct classifier *cls)
{
    cls->n_rules = 0;
    hmap_init(&cls->tables);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility. */
void
classifier_destroy(struct classifier *cls)
{
    if (cls) {
        struct cls_table *table, *next_table;

        HMAP_FOR_EACH_SAFE (table, next_table, hmap_node, &cls->tables) {
            hmap_destroy(&table->rules);
            hmap_remove(&cls->tables, &table->hmap_node);
            free(table);
        }
        hmap_destroy(&cls->tables);
    }
}

/* Returns true if 'cls' contains no classification rules, false otherwise. */
bool
classifier_is_empty(const struct classifier *cls)
{
    return cls->n_rules == 0;
}

/* Returns the number of rules in 'cls'. */
int
classifier_count(const struct classifier *cls)
{
    return cls->n_rules;
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority), replaces the old rule by 'rule' and returns the
 * rule that was replaced.  The caller takes ownership of the returned rule and
 * is thus responsible for freeing it, etc., as necessary.
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority. */
struct cls_rule *
classifier_replace(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *old_rule;
    struct cls_table *table;

    table = find_table(cls, &rule->wc);
    if (!table) {
        table = insert_table(cls, &rule->wc);
    }

    old_rule = insert_rule(table, rule);
    if (!old_rule) {
        table->n_table_rules++;
        cls->n_rules++;
    }
    return old_rule;
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * 'cls' must not contain an identical rule (including wildcards, values of
 * fixed fields, and priority).  Use classifier_find_rule_exactly() to find
 * such a rule. */
void
classifier_insert(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *displaced_rule = classifier_replace(cls, rule);
    assert(!displaced_rule);
}

/* Removes 'rule' from 'cls'.  It is the caller's responsibility to free
 * 'rule', if this is desirable. */
void
classifier_remove(struct classifier *cls, struct cls_rule *rule)
{
    struct cls_rule *head;
    struct cls_table *table;

    table = find_table(cls, &rule->wc);
    head = find_equal(table, &rule->flow, rule->hmap_node.hash);
    if (head != rule) {
        list_remove(&rule->list);
    } else if (list_is_empty(&rule->list)) {
        hmap_remove(&table->rules, &rule->hmap_node);
    } else {
        struct cls_rule *next = CONTAINER_OF(rule->list.next,
                                             struct cls_rule, list);

        list_remove(&rule->list);
        hmap_replace(&table->rules, &rule->hmap_node, &next->hmap_node);
    }

    if (--table->n_table_rules == 0) {
        destroy_table(cls, table);
    }

    cls->n_rules--;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow'.
 * Returns a null pointer if no rules in 'cls' match 'flow'.  If multiple rules
 * of equal priority match 'flow', returns one arbitrarily. */
struct cls_rule *
classifier_lookup(const struct classifier *cls, const struct flow *flow)
{
    struct cls_table *table;
    struct cls_rule *best;

    best = NULL;
    HMAP_FOR_EACH (table, hmap_node, &cls->tables) {
        struct cls_rule *rule = find_match(table, flow);
        if (rule && (!best || rule->priority > best->priority)) {
            best = rule;
        }
    }
    return best;
}

/* Finds and returns a rule in 'cls' with exactly the same priority and
 * matching criteria as 'target'.  Returns a null pointer if 'cls' doesn't
 * contain an exact match. */
struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target)
{
    struct cls_rule *head, *rule;
    struct cls_table *table;

    table = find_table(cls, &target->wc);
    if (!table) {
        return NULL;
    }

    head = find_equal(table, &target->flow, flow_hash(&target->flow, 0));
    FOR_EACH_RULE_IN_LIST (rule, head) {
        if (target->priority >= rule->priority) {
            return target->priority == rule->priority ? rule : NULL;
        }
    }
    return NULL;
}

/* Checks if 'target' would overlap any other rule in 'cls'.  Two rules are
 * considered to overlap if both rules have the same priority and a packet
 * could match both. */
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target)
{
    struct cls_table *table;

    HMAP_FOR_EACH (table, hmap_node, &cls->tables) {
        struct flow_wildcards wc;
        struct cls_rule *head;

        flow_wildcards_combine(&wc, &target->wc, &table->wc);
        HMAP_FOR_EACH (head, hmap_node, &table->rules) {
            struct cls_rule *rule;

            FOR_EACH_RULE_IN_LIST (rule, head) {
                if (rule->priority == target->priority
                    && flow_equal_except(&target->flow, &rule->flow, &wc)) {
                    return true;
                }
            }
        }
    }

    return false;
}

/* Returns true if 'rule' exactly matches 'criteria' or if 'rule' is more
 * specific than 'criteria'.  That is, 'rule' matches 'criteria' and this
 * function returns true if, for every field:
 *
 *   - 'criteria' and 'rule' specify the same (non-wildcarded) value for the
 *     field, or
 *
 *   - 'criteria' wildcards the field,
 *
 * Conversely, 'rule' does not match 'criteria' and this function returns false
 * if, for at least one field:
 *
 *   - 'criteria' and 'rule' specify different values for the field, or
 *
 *   - 'criteria' specifies a value for the field but 'rule' wildcards it.
 *
 * Equivalently, the truth table for whether a field matches is:
 *
 *                                     rule
 *
 *                   c         wildcard    exact
 *                   r        +---------+---------+
 *                   i   wild |   yes   |   yes   |
 *                   t   card |         |         |
 *                   e        +---------+---------+
 *                   r  exact |    no   |if values|
 *                   i        |         |are equal|
 *                   a        +---------+---------+
 *
 * This is the matching rule used by OpenFlow 1.0 non-strict OFPT_FLOW_MOD
 * commands and by OpenFlow 1.0 aggregate and flow stats.
 *
 * Ignores rule->priority and criteria->priority. */
bool
cls_rule_is_loose_match(const struct cls_rule *rule,
                        const struct cls_rule *criteria)
{
    return (!flow_wildcards_has_extra(&rule->wc, &criteria->wc)
            && flow_equal_except(&rule->flow, &criteria->flow, &criteria->wc));
}

/* Iteration. */

static bool
rule_matches(const struct cls_rule *rule, const struct cls_rule *target)
{
    return (!target
            || flow_equal_except(&rule->flow, &target->flow, &target->wc));
}

static struct cls_rule *
search_table(const struct cls_table *table, const struct cls_rule *target)
{
    if (!target || !flow_wildcards_has_extra(&table->wc, &target->wc)) {
        struct cls_rule *rule;

        HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
            if (rule_matches(rule, target)) {
                return rule;
            }
        }
    }
    return NULL;
}

/* Initializes 'cursor' for iterating through rules in 'cls':
 *
 *     - If 'target' is null, the cursor will visit every rule in 'cls'.
 *
 *     - If 'target' is nonnull, the cursor will visit each 'rule' in 'cls'
 *       such that cls_rule_is_loose_match(rule, target) returns true.
 *
 * Ignores target->priority. */
void
cls_cursor_init(struct cls_cursor *cursor, const struct classifier *cls,
                const struct cls_rule *target)
{
    cursor->cls = cls;
    cursor->target = target;
}

/* Returns the first matching cls_rule in 'cursor''s iteration, or a null
 * pointer if there are no matches. */
struct cls_rule *
cls_cursor_first(struct cls_cursor *cursor)
{
    struct cls_table *table;

    HMAP_FOR_EACH (table, hmap_node, &cursor->cls->tables) {
        struct cls_rule *rule = search_table(table, cursor->target);
        if (rule) {
            cursor->table = table;
            return rule;
        }
    }

    return NULL;
}

/* Returns the next matching cls_rule in 'cursor''s iteration, or a null
 * pointer if there are no more matches. */
struct cls_rule *
cls_cursor_next(struct cls_cursor *cursor, struct cls_rule *rule)
{
    const struct cls_table *table;
    struct cls_rule *next;

    next = next_rule_in_list__(rule);
    if (next->priority < rule->priority) {
        return next;
    }

    /* 'next' is the head of the list, that is, the rule that is included in
     * the table's hmap.  (This is important when the classifier contains rules
     * that differ only in priority.) */
    rule = next;
    HMAP_FOR_EACH_CONTINUE (rule, hmap_node, &cursor->table->rules) {
        if (rule_matches(rule, cursor->target)) {
            return rule;
        }
    }

    table = cursor->table;
    HMAP_FOR_EACH_CONTINUE (table, hmap_node, &cursor->cls->tables) {
        rule = search_table(table, cursor->target);
        if (rule) {
            cursor->table = table;
            return rule;
        }
    }

    return NULL;
}

static struct cls_table *
find_table(const struct classifier *cls, const struct flow_wildcards *wc)
{
    struct cls_table *table;

    HMAP_FOR_EACH_IN_BUCKET (table, hmap_node, flow_wildcards_hash(wc, 0),
                             &cls->tables) {
        if (flow_wildcards_equal(wc, &table->wc)) {
            return table;
        }
    }
    return NULL;
}

static struct cls_table *
insert_table(struct classifier *cls, const struct flow_wildcards *wc)
{
    struct cls_table *table;

    table = xzalloc(sizeof *table);
    hmap_init(&table->rules);
    table->wc = *wc;
    table->is_catchall = flow_wildcards_is_catchall(&table->wc);
    hmap_insert(&cls->tables, &table->hmap_node, flow_wildcards_hash(wc, 0));

    return table;
}

static void
destroy_table(struct classifier *cls, struct cls_table *table)
{
    hmap_remove(&cls->tables, &table->hmap_node);
    hmap_destroy(&table->rules);
    free(table);
}

static struct cls_rule *
find_match(const struct cls_table *table, const struct flow *flow)
{
    struct cls_rule *rule;

    if (table->is_catchall) {
        HMAP_FOR_EACH (rule, hmap_node, &table->rules) {
            return rule;
        }
    } else {
        struct flow f;

        f = *flow;
        flow_zero_wildcards(&f, &table->wc);
        HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, flow_hash(&f, 0),
                                 &table->rules) {
            if (flow_equal(&f, &rule->flow)) {
                return rule;
            }
        }
    }

    return NULL;
}

static struct cls_rule *
find_equal(struct cls_table *table, const struct flow *flow, uint32_t hash)
{
    struct cls_rule *head;

    HMAP_FOR_EACH_WITH_HASH (head, hmap_node, hash, &table->rules) {
        if (flow_equal(&head->flow, flow)) {
            return head;
        }
    }
    return NULL;
}

static struct cls_rule *
insert_rule(struct cls_table *table, struct cls_rule *new)
{
    struct cls_rule *head;

    new->hmap_node.hash = flow_hash(&new->flow, 0);

    head = find_equal(table, &new->flow, new->hmap_node.hash);
    if (!head) {
        hmap_insert(&table->rules, &new->hmap_node, new->hmap_node.hash);
        list_init(&new->list);
        return NULL;
    } else {
        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority. */
        struct cls_rule *rule;
        FOR_EACH_RULE_IN_LIST (rule, head) {
            if (new->priority >= rule->priority) {
                if (rule == head) {
                    /* 'new' is the new highest-priority flow in the list. */
                    hmap_replace(&table->rules,
                                 &rule->hmap_node, &new->hmap_node);
                }

                if (new->priority == rule->priority) {
                    list_replace(&new->list, &rule->list);
                    return rule;
                } else {
                    list_insert(&rule->list, &new->list);
                    return NULL;
                }
            }
        }

        /* Insert 'new' at the end of the list. */
        list_push_back(&head->list, &new->list);
        return NULL;
    }
}

static struct cls_rule *
next_rule_in_list__(struct cls_rule *rule)
{
    struct cls_rule *next = OBJECT_CONTAINING(rule->list.next, next, list);
    return next;
}

static struct cls_rule *
next_rule_in_list(struct cls_rule *rule)
{
    struct cls_rule *next = next_rule_in_list__(rule);
    return next->priority < rule->priority ? next : NULL;
}
