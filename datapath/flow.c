/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include "flow.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/rcupdate.h>

#include "openflow.h"
#include "compat.h"
#include "snap.h"

struct kmem_cache *flow_cache;

/* Internal function used to compare fields in flow. */
static inline
int flow_fields_match(const struct sw_flow_key *a, const struct sw_flow_key *b,
		uint16_t w)
{
	return ((w & OFPFW_IN_PORT || a->in_port == b->in_port)
		&& (w & OFPFW_DL_VLAN || a->dl_vlan == b->dl_vlan)
		&& (w & OFPFW_DL_SRC || !memcmp(a->dl_src, b->dl_src, ETH_ALEN))
		&& (w & OFPFW_DL_DST || !memcmp(a->dl_dst, b->dl_dst, ETH_ALEN))
		&& (w & OFPFW_DL_TYPE || a->dl_type == b->dl_type)
		&& (w & OFPFW_NW_SRC || a->nw_src == b->nw_src)
		&& (w & OFPFW_NW_DST || a->nw_dst == b->nw_dst)
		&& (w & OFPFW_NW_PROTO || a->nw_proto == b->nw_proto)
		&& (w & OFPFW_TP_SRC || a->tp_src == b->tp_src)
		&& (w & OFPFW_TP_DST || a->tp_dst == b->tp_dst));
}

/* Returns nonzero if 'a' and 'b' match, that is, if their fields are equal
 * modulo wildcards, zero otherwise. */
int flow_matches(const struct sw_flow_key *a, const struct sw_flow_key *b)
{
	return flow_fields_match(a, b, (a->wildcards | b->wildcards));
}
EXPORT_SYMBOL(flow_matches);

/* Returns nonzero if 't' (the table entry's key) and 'd' (the key 
 * describing the deletion) match, that is, if their fields are 
 * equal modulo wildcards, zero otherwise.  If 'strict' is nonzero, the
 * wildcards must match in both 't_key' and 'd_key'.  Note that the
 * table's wildcards are ignored unless 'strict' is set. */
int flow_del_matches(const struct sw_flow_key *t, const struct sw_flow_key *d, int strict)
{
	if (strict && (t->wildcards != d->wildcards))
		return 0;

	return flow_fields_match(t, d, d->wildcards);
}
EXPORT_SYMBOL(flow_del_matches);

void flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from)
{
	to->wildcards = ntohs(from->wildcards) & OFPFW_ALL;
	memset(to->pad, '\0', sizeof(to->pad));
	to->in_port = from->in_port;
	to->dl_vlan = from->dl_vlan;
	memcpy(to->dl_src, from->dl_src, ETH_ALEN);
	memcpy(to->dl_dst, from->dl_dst, ETH_ALEN);
	to->dl_type = from->dl_type;

	to->nw_src = to->nw_dst = to->nw_proto = 0;
	to->tp_src = to->tp_dst = 0;

#define OFPFW_TP (OFPFW_TP_SRC | OFPFW_TP_DST)
#define OFPFW_NW (OFPFW_NW_SRC | OFPFW_NW_DST | OFPFW_NW_PROTO)
	if (to->wildcards & OFPFW_DL_TYPE) {
		/* Can't sensibly match on network or transport headers if the
		 * data link type is unknown. */
		to->wildcards |= OFPFW_NW | OFPFW_TP;
	} else if (from->dl_type == htons(ETH_P_IP)) {
		to->nw_src   = from->nw_src;
		to->nw_dst   = from->nw_dst;
		to->nw_proto = from->nw_proto;

		if (to->wildcards & OFPFW_NW_PROTO) {
			/* Can't sensibly match on transport headers if the
			 * network protocol is unknown. */
			to->wildcards |= OFPFW_TP;
		} else if (from->nw_proto == IPPROTO_TCP
			   || from->nw_proto == IPPROTO_UDP) {
			to->tp_src = from->tp_src;
			to->tp_dst = from->tp_dst;
		} else {
			/* Transport layer fields are undefined.  Mark them as
			 * exact-match to allow such flows to reside in
			 * table-hash, instead of falling into table-linear. */
			to->wildcards &= ~OFPFW_TP;
		}
	} else {
		/* Network and transport layer fields are undefined.  Mark them
		 * as exact-match to allow such flows to reside in table-hash,
		 * instead of falling into table-linear. */
		to->wildcards &= ~(OFPFW_NW | OFPFW_TP);
	}
}

void flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from)
{
	to->wildcards = htons(from->wildcards);
	to->in_port   = from->in_port;
	to->dl_vlan   = from->dl_vlan;
	memcpy(to->dl_src, from->dl_src, ETH_ALEN);
	memcpy(to->dl_dst, from->dl_dst, ETH_ALEN);
	to->dl_type   = from->dl_type;
	to->nw_src	  = from->nw_src;
	to->nw_dst	  = from->nw_dst;
	to->nw_proto  = from->nw_proto;
	to->tp_src	  = from->tp_src;
	to->tp_dst	  = from->tp_dst;
	memset(to->pad, '\0', sizeof(to->pad));
}

/* Allocates and returns a new flow with 'n_actions' action, using allocation
 * flags 'flags'.  Returns the new flow or a null pointer on failure. */
struct sw_flow *flow_alloc(int n_actions, gfp_t flags)
{
	struct sw_flow *flow = kmem_cache_alloc(flow_cache, flags);
	if (unlikely(!flow))
		return NULL;

	flow->n_actions = n_actions;
	flow->actions = kmalloc(n_actions * sizeof *flow->actions,
				flags);
	if (unlikely(!flow->actions) && n_actions > 0) {
		kmem_cache_free(flow_cache, flow);
		return NULL;
	}
	return flow;
}

/* Frees 'flow' immediately. */
void flow_free(struct sw_flow *flow)
{
	if (unlikely(!flow))
		return;
	kfree(flow->actions);
	kmem_cache_free(flow_cache, flow);
}
EXPORT_SYMBOL(flow_free);

/* RCU callback used by flow_deferred_free. */
static void rcu_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);
	flow_free(flow);
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, rcu_callback);
}
EXPORT_SYMBOL(flow_deferred_free);

/* Prints a representation of 'key' to the kernel log. */
void print_flow(const struct sw_flow_key *key)
{
	printk("wild%04x port%04x:vlan%04x mac%02x:%02x:%02x:%02x:%02x:%02x"
			"->%02x:%02x:%02x:%02x:%02x:%02x "
			"proto%04x ip%u.%u.%u.%u->%u.%u.%u.%u port%d->%d\n",
			key->wildcards, ntohs(key->in_port), ntohs(key->dl_vlan),
			key->dl_src[0], key->dl_src[1], key->dl_src[2],
			key->dl_src[3], key->dl_src[4], key->dl_src[5],
			key->dl_dst[0], key->dl_dst[1], key->dl_dst[2],
			key->dl_dst[3], key->dl_dst[4], key->dl_dst[5],
			ntohs(key->dl_type),
			((unsigned char *)&key->nw_src)[0],
			((unsigned char *)&key->nw_src)[1],
			((unsigned char *)&key->nw_src)[2],
			((unsigned char *)&key->nw_src)[3],
			((unsigned char *)&key->nw_dst)[0],
			((unsigned char *)&key->nw_dst)[1],
			((unsigned char *)&key->nw_dst)[2],
			((unsigned char *)&key->nw_dst)[3],
			ntohs(key->tp_src), ntohs(key->tp_dst));
}
EXPORT_SYMBOL(print_flow);

/* Parses the Ethernet frame in 'skb', which was received on 'in_port',
 * and initializes 'key' to match. */
void flow_extract(struct sk_buff *skb, uint16_t in_port,
		  struct sw_flow_key *key)
{
	struct ethhdr *mac;
	struct udphdr *th;
	int nh_ofs, th_ofs;

	key->in_port = htons(in_port);
	key->wildcards = 0;
	memset(key->pad, '\0', sizeof(key->pad));

	/* This code doesn't check that skb->len is long enough to contain the
	 * MAC or network header.  With a 46-byte minimum length frame this
	 * assumption is always correct. */

	/* Doesn't verify checksums.  Should it? */

	/* Data link layer.  We only support Ethernet. */
	mac = eth_hdr(skb);
	nh_ofs = sizeof(struct ethhdr);
	if (likely(ntohs(mac->h_proto) >= OFP_DL_TYPE_ETH2_CUTOFF)) {
		/* This is an Ethernet II frame */
		key->dl_type = mac->h_proto;
	} else {
		/* This is an 802.2 frame */
		if (snap_get_ethertype(skb, &key->dl_type) != -EINVAL) {
			nh_ofs += sizeof(struct snap_hdr);
		} else {
			key->dl_type = OFP_DL_TYPE_NOT_ETH_TYPE;
			nh_ofs += sizeof(struct llc_pdu_un);
		}
	}

	/* Check for a VLAN tag */
	if (likely(key->dl_type != htons(ETH_P_8021Q))) {
		key->dl_vlan = htons(OFP_VLAN_NONE);
	} else {
		struct vlan_hdr *vh = (struct vlan_hdr *)(skb_mac_header(skb) + nh_ofs);
		key->dl_type = vh->h_vlan_encapsulated_proto;
		key->dl_vlan = vh->h_vlan_TCI & htons(VLAN_VID_MASK);
		nh_ofs += sizeof(*vh);
	}
	memcpy(key->dl_src, mac->h_source, ETH_ALEN);
	memcpy(key->dl_dst, mac->h_dest, ETH_ALEN);
	skb_set_network_header(skb, nh_ofs);

	/* Network layer. */
	if (likely(key->dl_type == htons(ETH_P_IP))) {
		struct iphdr *nh = ip_hdr(skb);
		key->nw_src = nh->saddr;
		key->nw_dst = nh->daddr;
		key->nw_proto = nh->protocol;
		th_ofs = nh_ofs + nh->ihl * 4;
		skb_set_transport_header(skb, th_ofs);

		/* Transport layer. */
		if ((key->nw_proto != IPPROTO_TCP && key->nw_proto != IPPROTO_UDP)
				|| skb->len < th_ofs + sizeof(struct udphdr)) {
			goto no_th;
		}
		th = udp_hdr(skb);
		key->tp_src = th->source;
		key->tp_dst = th->dest;

		return;
	}

	key->nw_src = 0;
	key->nw_dst = 0;
	key->nw_proto = 0;

no_th:
	key->tp_src = 0;
	key->tp_dst = 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int flow_init(void)
{
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow), 0,
					0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	return 0;
}

/* Uninitializes the flow module. */
void flow_exit(void)
{
	kmem_cache_destroy(flow_cache);
}

