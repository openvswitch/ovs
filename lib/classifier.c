/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

static struct cls_table *classifier_first_table(const struct classifier *);
static struct cls_table *classifier_next_table(const struct classifier *,
                                               const struct cls_table *);
static void destroy_table(struct classifier *, struct cls_table *);

static struct cls_rule *find_match(const struct cls_table *,
                                   const struct flow *);
static struct cls_rule *find_equal(struct cls_table *, const struct flow *,
                                   uint32_t hash);
static struct cls_rule *insert_rule(struct cls_table *, struct cls_rule *);

static bool flow_equal_except(const struct flow *, const struct flow *,
                                const struct flow_wildcards *);
static void zero_wildcards(struct flow *, const struct flow_wildcards *);

/* Iterates RULE over HEAD and all of the cls_rules on HEAD->list. */
#define FOR_EACH_RULE_IN_LIST(RULE, HEAD)                               \
    for ((RULE) = (HEAD); (RULE) != NULL; (RULE) = next_rule_in_list(RULE))
#define FOR_EACH_RULE_IN_LIST_SAFE(RULE, NEXT, HEAD)                    \
    for ((RULE) = (HEAD);                                               \
         (RULE) != NULL && ((NEXT) = next_rule_in_list(RULE), true);    \
         (RULE) = (NEXT))

static struct cls_rule *next_rule_in_list__(struct cls_rule *);
static struct cls_rule *next_rule_in_list(struct cls_rule *);

static struct cls_table *
cls_table_from_hmap_node(const struct hmap_node *node)
{
    return node ? CONTAINER_OF(node, struct cls_table, hmap_node) : NULL;
}

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
    zero_wildcards(&rule->flow, &rule->wc);
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
cls_rule_set_tun_id(struct cls_rule *rule, ovs_be64 tun_id)
{
    cls_rule_set_tun_id_masked(rule, tun_id, htonll(UINT64_MAX));
}

void
cls_rule_set_tun_id_masked(struct cls_rule *rule,
                           ovs_be64 tun_id, ovs_be64 mask)
{
    rule->wc.tun_id_mask = mask;
    rule->flow.tun_id = tun_id & mask;
}

void
cls_rule_set_in_port(struct cls_rule *rule, uint16_t ofp_port)
{
    rule->wc.wildcards &= ~FWW_IN_PORT;
    rule->flow.in_port = ofp_port;
}

void
cls_rule_set_dl_type(struct cls_rule *rule, ovs_be16 dl_type)
{
    rule->wc.wildcards &= ~FWW_DL_TYPE;
    rule->flow.dl_type = dl_type;
}

void
cls_rule_set_dl_src(struct cls_rule *rule, const uint8_t dl_src[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~FWW_DL_SRC;
    memcpy(rule->flow.dl_src, dl_src, ETH_ADDR_LEN);
}

/* Modifies 'rule' so that the Ethernet address must match 'dl_dst' exactly. */
void
cls_rule_set_dl_dst(struct cls_rule *rule, const uint8_t dl_dst[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~(FWW_DL_DST | FWW_ETH_MCAST);
    memcpy(rule->flow.dl_dst, dl_dst, ETH_ADDR_LEN);
}

/* Modifies 'rule' so that the Ethernet address must match 'dl_dst' after each
 * byte is ANDed with the appropriate byte in 'mask'.
 *
 * This function will assert-fail if 'mask' is invalid.  Only 'mask' values
 * accepted by flow_wildcards_is_dl_dst_mask_valid() are allowed. */
void
cls_rule_set_dl_dst_masked(struct cls_rule *rule,
                           const uint8_t dl_dst[ETH_ADDR_LEN],
                           const uint8_t mask[ETH_ADDR_LEN])
{
    flow_wildcards_t *wc = &rule->wc.wildcards;
    size_t i;

    *wc = flow_wildcards_set_dl_dst_mask(*wc, mask);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        rule->flow.dl_dst[i] = dl_dst[i] & mask[i];
    }
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
    rule->wc.vlan_tci_mask = mask;
}

/* Modifies 'rule' so that the VLAN VID is wildcarded.  If the PCP is already
 * wildcarded, then 'rule' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
cls_rule_set_any_vid(struct cls_rule *rule)
{
    if (rule->wc.vlan_tci_mask & htons(VLAN_PCP_MASK)) {
        rule->wc.vlan_tci_mask &= ~htons(VLAN_VID_MASK);
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
    if (dl_vlan == htons(OFP_VLAN_NONE)) {
        cls_rule_set_dl_tci(rule, htons(0));
    } else {
        dl_vlan &= htons(VLAN_VID_MASK);
        rule->flow.vlan_tci &= ~htons(VLAN_VID_MASK);
        rule->flow.vlan_tci |= htons(VLAN_CFI) | dl_vlan;
        rule->wc.vlan_tci_mask |= htons(VLAN_VID_MASK | VLAN_CFI);
    }
}

/* Modifies 'rule' so that the VLAN PCP is wildcarded.  If the VID is already
 * wildcarded, then 'rule' will match a packet regardless of whether it has an
 * 802.1Q header or not. */
void
cls_rule_set_any_pcp(struct cls_rule *rule)
{
    if (rule->wc.vlan_tci_mask & htons(VLAN_VID_MASK)) {
        rule->wc.vlan_tci_mask &= ~htons(VLAN_PCP_MASK);
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
    dl_vlan_pcp &= 0x07;
    rule->flow.vlan_tci &= ~htons(VLAN_PCP_MASK);
    rule->flow.vlan_tci |= htons((dl_vlan_pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
    rule->wc.vlan_tci_mask |= htons(VLAN_CFI | VLAN_PCP_MASK);
}

void
cls_rule_set_tp_src(struct cls_rule *rule, ovs_be16 tp_src)
{
    rule->wc.wildcards &= ~FWW_TP_SRC;
    rule->flow.tp_src = tp_src;
}

void
cls_rule_set_tp_dst(struct cls_rule *rule, ovs_be16 tp_dst)
{
    rule->wc.wildcards &= ~FWW_TP_DST;
    rule->flow.tp_dst = tp_dst;
}

void
cls_rule_set_nw_proto(struct cls_rule *rule, uint8_t nw_proto)
{
    rule->wc.wildcards &= ~FWW_NW_PROTO;
    rule->flow.nw_proto = nw_proto;
}

void
cls_rule_set_nw_src(struct cls_rule *rule, ovs_be32 nw_src)
{
    cls_rule_set_nw_src_masked(rule, nw_src, htonl(UINT32_MAX));
}

bool
cls_rule_set_nw_src_masked(struct cls_rule *rule, ovs_be32 ip, ovs_be32 mask)
{
    if (flow_wildcards_set_nw_src_mask(&rule->wc, mask)) {
        rule->flow.nw_src = ip & mask;
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_nw_dst(struct cls_rule *rule, ovs_be32 nw_dst)
{
    cls_rule_set_nw_dst_masked(rule, nw_dst, htonl(UINT32_MAX));
}

bool
cls_rule_set_nw_dst_masked(struct cls_rule *rule, ovs_be32 ip, ovs_be32 mask)
{
    if (flow_wildcards_set_nw_dst_mask(&rule->wc, mask)) {
        rule->flow.nw_dst = ip & mask;
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_nw_tos(struct cls_rule *rule, uint8_t nw_tos)
{
    rule->wc.wildcards &= ~FWW_NW_TOS;
    rule->flow.nw_tos = nw_tos & IP_DSCP_MASK;
}

void
cls_rule_set_icmp_type(struct cls_rule *rule, uint8_t icmp_type)
{
    rule->wc.wildcards &= ~FWW_TP_SRC;
    rule->flow.icmp_type = htons(icmp_type);

}

void
cls_rule_set_icmp_code(struct cls_rule *rule, uint8_t icmp_code)
{
    rule->wc.wildcards &= ~FWW_TP_DST;
    rule->flow.icmp_code = htons(icmp_code);
}

void
cls_rule_set_arp_sha(struct cls_rule *rule, const uint8_t sha[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~FWW_ARP_SHA;
    memcpy(rule->flow.arp_sha, sha, ETH_ADDR_LEN);
}

void
cls_rule_set_arp_tha(struct cls_rule *rule, const uint8_t tha[ETH_ADDR_LEN])
{
    rule->wc.wildcards &= ~FWW_ARP_THA;
    memcpy(rule->flow.arp_tha, tha, ETH_ADDR_LEN);
}

void
cls_rule_set_ipv6_src(struct cls_rule *rule, const struct in6_addr *src)
{
    cls_rule_set_ipv6_src_masked(rule, src, &in6addr_exact);
}

bool
cls_rule_set_ipv6_src_masked(struct cls_rule *rule, const struct in6_addr *src,
                             const struct in6_addr *mask)
{
    if (flow_wildcards_set_ipv6_src_mask(&rule->wc, mask)) {
        rule->flow.ipv6_src = ipv6_addr_bitand(src, mask);
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_ipv6_dst(struct cls_rule *rule, const struct in6_addr *dst)
{
    cls_rule_set_ipv6_dst_masked(rule, dst, &in6addr_exact);
}

bool
cls_rule_set_ipv6_dst_masked(struct cls_rule *rule, const struct in6_addr *dst,
                             const struct in6_addr *mask)
{
    if (flow_wildcards_set_ipv6_dst_mask(&rule->wc, mask)) {
        rule->flow.ipv6_dst = ipv6_addr_bitand(dst, mask);
        return true;
    } else {
        return false;
    }
}

void
cls_rule_set_nd_target(struct cls_rule *rule, const struct in6_addr target)
{
    rule->wc.wildcards &= ~FWW_ND_TARGET;
    rule->flow.nd_target = target;
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
format_ip_netmask(struct ds *s, const char *name, ovs_be32 ip,
                  ovs_be32 netmask)
{
    if (netmask) {
        ds_put_format(s, "%s="IP_FMT, name, IP_ARGS(&ip));
        if (netmask != htonl(UINT32_MAX)) {
            if (ip_is_cidr(netmask)) {
                int wcbits = ofputil_netmask_to_wcbits(netmask);
                ds_put_format(s, "/%d", 32 - wcbits);
            } else {
                ds_put_format(s, "/"IP_FMT, IP_ARGS(&netmask));
            }
        }
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
        print_ipv6_addr(s, addr);
        if (!ipv6_mask_is_exact(netmask)) {
            if (ipv6_is_cidr(netmask)) {
                int cidr_bits = ipv6_count_cidr_bits(netmask);
                ds_put_format(s, "/%d", cidr_bits);
            } else {
                ds_put_char(s, '/');
                print_ipv6_addr(s, netmask);
            }
        }
        ds_put_char(s, ',');
    }
}

void
cls_rule_format(const struct cls_rule *rule, struct ds *s)
{
    const struct flow_wildcards *wc = &rule->wc;
    size_t start_len = s->length;
    flow_wildcards_t w = wc->wildcards;
    const struct flow *f = &rule->flow;
    bool skip_type = false;
    bool skip_proto = false;

    int i;

    if (rule->priority != OFP_DEFAULT_PRIORITY) {
        ds_put_format(s, "priority=%d,", rule->priority);
    }

    if (!(w & FWW_DL_TYPE)) {
        skip_type = true;
        if (f->dl_type == htons(ETH_TYPE_IP)) {
            if (!(w & FWW_NW_PROTO)) {
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
            if (!(w & FWW_NW_PROTO)) {
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
        switch (wc->reg_masks[i]) {
        case 0:
            break;
        case UINT32_MAX:
            ds_put_format(s, "reg%d=0x%"PRIx32",", i, f->regs[i]);
            break;
        default:
            ds_put_format(s, "reg%d=0x%"PRIx32"/0x%"PRIx32",",
                          i, f->regs[i], wc->reg_masks[i]);
            break;
        }
    }
    switch (wc->tun_id_mask) {
    case 0:
        break;
    case CONSTANT_HTONLL(UINT64_MAX):
        ds_put_format(s, "tun_id=%#"PRIx64",", ntohll(f->tun_id));
        break;
    default:
        ds_put_format(s, "tun_id=%#"PRIx64"/%#"PRIx64",",
                      ntohll(f->tun_id), ntohll(wc->tun_id_mask));
        break;
    }
    if (!(w & FWW_IN_PORT)) {
        ds_put_format(s, "in_port=%"PRIu16",", f->in_port);
    }
    if (wc->vlan_tci_mask) {
        ovs_be16 vid_mask = wc->vlan_tci_mask & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = wc->vlan_tci_mask & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = wc->vlan_tci_mask & htons(VLAN_CFI);

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
        } else if (wc->vlan_tci_mask == htons(0xffff)) {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16",", ntohs(f->vlan_tci));
        } else {
            ds_put_format(s, "vlan_tci=0x%04"PRIx16"/0x%04"PRIx16",",
                          ntohs(f->vlan_tci), ntohs(wc->vlan_tci_mask));
        }
    }
    if (!(w & FWW_DL_SRC)) {
        ds_put_format(s, "dl_src="ETH_ADDR_FMT",", ETH_ADDR_ARGS(f->dl_src));
    }
    switch (w & (FWW_DL_DST | FWW_ETH_MCAST)) {
    case 0:
        ds_put_format(s, "dl_dst="ETH_ADDR_FMT",", ETH_ADDR_ARGS(f->dl_dst));
        break;
    case FWW_DL_DST:
        ds_put_format(s, "dl_dst="ETH_ADDR_FMT"/01:00:00:00:00:00,",
                      ETH_ADDR_ARGS(f->dl_dst));
        break;
    case FWW_ETH_MCAST:
        ds_put_format(s, "dl_dst="ETH_ADDR_FMT"/fe:ff:ff:ff:ff:ff,",
                      ETH_ADDR_ARGS(f->dl_dst));
        break;
    case FWW_DL_DST | FWW_ETH_MCAST:
        break;
    }
    if (!skip_type && !(w & FWW_DL_TYPE)) {
        ds_put_format(s, "dl_type=0x%04"PRIx16",", ntohs(f->dl_type));
    }
    if (f->dl_type == htons(ETH_TYPE_IPV6)) {
        format_ipv6_netmask(s, "ipv6_src", &f->ipv6_src, &wc->ipv6_src_mask);
        format_ipv6_netmask(s, "ipv6_dst", &f->ipv6_dst, &wc->ipv6_dst_mask);
    } else {
        format_ip_netmask(s, "nw_src", f->nw_src, wc->nw_src_mask);
        format_ip_netmask(s, "nw_dst", f->nw_dst, wc->nw_dst_mask);
    }
    if (!skip_proto && !(w & FWW_NW_PROTO)) {
        if (f->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_format(s, "arp_op=%"PRIu8",", f->nw_proto);
        } else {
            ds_put_format(s, "nw_proto=%"PRIu8",", f->nw_proto);
        }
    }
    if (f->dl_type == htons(ETH_TYPE_ARP)) {
        if (!(w & FWW_ARP_SHA)) {
            ds_put_format(s, "arp_sha="ETH_ADDR_FMT",",
                    ETH_ADDR_ARGS(f->arp_sha));
        }
        if (!(w & FWW_ARP_THA)) {
            ds_put_format(s, "arp_tha="ETH_ADDR_FMT",",
                    ETH_ADDR_ARGS(f->arp_tha));
        }
    }
    if (!(w & FWW_NW_TOS)) {
        ds_put_format(s, "nw_tos=%"PRIu8",", f->nw_tos);
    }
    if (f->nw_proto == IPPROTO_ICMP) {
        if (!(w & FWW_TP_SRC)) {
            ds_put_format(s, "icmp_type=%"PRIu16",", ntohs(f->tp_src));
        }
        if (!(w & FWW_TP_DST)) {
            ds_put_format(s, "icmp_code=%"PRIu16",", ntohs(f->tp_dst));
        }
    } else if (f->nw_proto == IPPROTO_ICMPV6) {
        if (!(w & FWW_TP_SRC)) {
            ds_put_format(s, "icmp_type=%"PRIu16",", ntohs(f->tp_src));
        }
        if (!(w & FWW_TP_DST)) {
            ds_put_format(s, "icmp_code=%"PRIu16",", ntohs(f->tp_dst));
        }
        if (!(w & FWW_ND_TARGET)) {
            ds_put_cstr(s, "nd_target=");
            print_ipv6_addr(s, &f->nd_target);
            ds_put_char(s, ',');
        }
        if (!(w & FWW_ARP_SHA)) {
            ds_put_format(s, "nd_sll="ETH_ADDR_FMT",", 
                    ETH_ADDR_ARGS(f->arp_sha));
        }
        if (!(w & FWW_ARP_THA)) {
            ds_put_format(s, "nd_tll="ETH_ADDR_FMT",", 
                    ETH_ADDR_ARGS(f->arp_tha));
        }
   } else {
        if (!(w & FWW_TP_SRC)) {
            ds_put_format(s, "tp_src=%"PRIu16",", ntohs(f->tp_src));
        }
        if (!(w & FWW_TP_DST)) {
            ds_put_format(s, "tp_dst=%"PRIu16",", ntohs(f->tp_dst));
        }
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

/* Returns the number of rules in 'classifier'. */
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

/* Initializes 'cursor' for iterating through 'cls' rules that exactly match
 * 'target' or are more specific than 'target'.  That is, a given 'rule'
 * matches 'target' if, for every field:
 *
 *   - 'target' and 'rule' specify the same (non-wildcarded) value for the
 *     field, or
 *
 *   - 'target' wildcards the field,
 *
 * but not if:
 *
 *   - 'target' and 'rule' specify different values for the field, or
 *
 *   - 'target' specifies a value for the field but 'rule' wildcards it.
 *
 * Equivalently, the truth table for whether a field matches is:
 *
 *                                     rule
 *
 *                             wildcard    exact
 *                            +---------+---------+
 *                   t   wild |   yes   |   yes   |
 *                   a   card |         |         |
 *                   r        +---------+---------+
 *                   g  exact |    no   |if values|
 *                   e        |         |are equal|
 *                   t        +---------+---------+
 *
 * This is the matching rule used by OpenFlow 1.0 non-strict OFPT_FLOW_MOD
 * commands and by OpenFlow 1.0 aggregate and flow stats.
 *
 * Ignores target->priority.
 *
 * 'target' may be NULL to iterate over every rule in 'cls'. */
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

    for (table = classifier_first_table(cursor->cls); table;
         table = classifier_next_table(cursor->cls, table)) {
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

    for (table = classifier_next_table(cursor->cls, cursor->table); table;
         table = classifier_next_table(cursor->cls, table)) {
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
    hmap_insert(&cls->tables, &table->hmap_node, flow_wildcards_hash(wc, 0));

    return table;
}

static struct cls_table *
classifier_first_table(const struct classifier *cls)
{
    return cls_table_from_hmap_node(hmap_first(&cls->tables));
}

static struct cls_table *
classifier_next_table(const struct classifier *cls,
                      const struct cls_table *table)
{
    return cls_table_from_hmap_node(hmap_next(&cls->tables,
                                              &table->hmap_node));
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
    struct flow f;

    f = *flow;
    zero_wildcards(&f, &table->wc);
    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, flow_hash(&f, 0),
                             &table->rules) {
        if (flow_equal(&f, &rule->flow)) {
            return rule;
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

static bool
ipv6_equal_except(const struct in6_addr *a, const struct in6_addr *b,
                  const struct in6_addr *mask)
{
    int i;

#ifdef s6_addr32
    for (i=0; i<4; i++) {
        if ((a->s6_addr32[i] ^ b->s6_addr32[i]) & mask->s6_addr32[i]) {
            return false;
        }
    }
#else
    for (i=0; i<16; i++) {
        if ((a->s6_addr[i] ^ b->s6_addr[i]) & mask->s6_addr[i]) {
            return false;
        }
    }
#endif

    return true;
}


static bool
flow_equal_except(const struct flow *a, const struct flow *b,
                  const struct flow_wildcards *wildcards)
{
    const flow_wildcards_t wc = wildcards->wildcards;
    int i;

    BUILD_ASSERT_DECL(FLOW_SIG_SIZE == 100 + FLOW_N_REGS * 4);

    for (i = 0; i < FLOW_N_REGS; i++) {
        if ((a->regs[i] ^ b->regs[i]) & wildcards->reg_masks[i]) {
            return false;
        }
    }

    return (!((a->tun_id ^ b->tun_id) & wildcards->tun_id_mask)
            && !((a->nw_src ^ b->nw_src) & wildcards->nw_src_mask)
            && !((a->nw_dst ^ b->nw_dst) & wildcards->nw_dst_mask)
            && (wc & FWW_IN_PORT || a->in_port == b->in_port)
            && !((a->vlan_tci ^ b->vlan_tci) & wildcards->vlan_tci_mask)
            && (wc & FWW_DL_TYPE || a->dl_type == b->dl_type)
            && (wc & FWW_TP_SRC || a->tp_src == b->tp_src)
            && (wc & FWW_TP_DST || a->tp_dst == b->tp_dst)
            && (wc & FWW_DL_SRC || eth_addr_equals(a->dl_src, b->dl_src))
            && (wc & FWW_DL_DST
                || (!((a->dl_dst[0] ^ b->dl_dst[0]) & 0xfe)
                    && a->dl_dst[1] == b->dl_dst[1]
                    && a->dl_dst[2] == b->dl_dst[2]
                    && a->dl_dst[3] == b->dl_dst[3]
                    && a->dl_dst[4] == b->dl_dst[4]
                    && a->dl_dst[5] == b->dl_dst[5]))
            && (wc & FWW_ETH_MCAST
                || !((a->dl_dst[0] ^ b->dl_dst[0]) & 0x01))
            && (wc & FWW_NW_PROTO || a->nw_proto == b->nw_proto)
            && (wc & FWW_NW_TOS || a->nw_tos == b->nw_tos)
            && (wc & FWW_ARP_SHA || eth_addr_equals(a->arp_sha, b->arp_sha))
            && (wc & FWW_ARP_THA || eth_addr_equals(a->arp_tha, b->arp_tha))
            && ipv6_equal_except(&a->ipv6_src, &b->ipv6_src,
                    &wildcards->ipv6_src_mask)
            && ipv6_equal_except(&a->ipv6_dst, &b->ipv6_dst,
                    &wildcards->ipv6_dst_mask)
            && (wc & FWW_ND_TARGET 
                || ipv6_addr_equals(&a->nd_target, &b->nd_target)));
}

static void
zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    const flow_wildcards_t wc = wildcards->wildcards;
    int i;

    BUILD_ASSERT_DECL(FLOW_SIG_SIZE == 100 + 4 * FLOW_N_REGS);

    for (i = 0; i < FLOW_N_REGS; i++) {
        flow->regs[i] &= wildcards->reg_masks[i];
    }
    flow->tun_id &= wildcards->tun_id_mask;
    flow->nw_src &= wildcards->nw_src_mask;
    flow->nw_dst &= wildcards->nw_dst_mask;
    if (wc & FWW_IN_PORT) {
        flow->in_port = 0;
    }
    flow->vlan_tci &= wildcards->vlan_tci_mask;
    if (wc & FWW_DL_TYPE) {
        flow->dl_type = 0;
    }
    if (wc & FWW_TP_SRC) {
        flow->tp_src = 0;
    }
    if (wc & FWW_TP_DST) {
        flow->tp_dst = 0;
    }
    if (wc & FWW_DL_SRC) {
        memset(flow->dl_src, 0, sizeof flow->dl_src);
    }
    if (wc & FWW_DL_DST) {
        flow->dl_dst[0] &= 0x01;
        memset(&flow->dl_dst[1], 0, 5);
    }
    if (wc & FWW_ETH_MCAST) {
        flow->dl_dst[0] &= 0xfe;
    }
    if (wc & FWW_NW_PROTO) {
        flow->nw_proto = 0;
    }
    if (wc & FWW_NW_TOS) {
        flow->nw_tos = 0;
    }
    if (wc & FWW_ARP_SHA) {
        memset(flow->arp_sha, 0, sizeof flow->arp_sha);
    }
    if (wc & FWW_ARP_THA) {
        memset(flow->arp_tha, 0, sizeof flow->arp_tha);
    }
    flow->ipv6_src = ipv6_addr_bitand(&flow->ipv6_src,
            &wildcards->ipv6_src_mask);
    flow->ipv6_dst = ipv6_addr_bitand(&flow->ipv6_dst,
            &wildcards->ipv6_dst_mask);
    if (wc & FWW_ND_TARGET) {
        memset(&flow->nd_target, 0, sizeof flow->nd_target);
    }
}
