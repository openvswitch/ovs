/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010, 2011 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Functions for executing flow actions. */

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/checksum.h>

#include "actions.h"
#include "checksum.h"
#include "datapath.h"
#include "loop_counter.h"
#include "openvswitch/datapath-protocol.h"
#include "vlan.h"
#include "vport.h"

static int do_execute_actions(struct datapath *, struct sk_buff *,
			      struct sw_flow_actions *acts);

static int make_writable(struct sk_buff *skb, int write_len)
{
	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

static int strip_vlan(struct sk_buff *skb)
{
	struct ethhdr *eh;
	int err;

	if (vlan_tx_tag_present(skb)) {
		vlan_set_tci(skb, 0);
		return 0;
	}

	if (unlikely(skb->protocol != htons(ETH_P_8021Q) ||
	    skb->len < VLAN_ETH_HLEN))
		return 0;

	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ ETH_HLEN, VLAN_HLEN, 0));

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);

	eh = (struct ethhdr *)skb_pull(skb, VLAN_HLEN);

	skb->protocol = eh->h_proto;
	skb->mac_header += VLAN_HLEN;

	return 0;
}

static int modify_vlan_tci(struct sk_buff *skb, __be16 tci)
{
	if (!vlan_tx_tag_present(skb) && skb->protocol == htons(ETH_P_8021Q)) {
		int err;

		if (unlikely(skb->len < VLAN_ETH_HLEN))
			return 0;

		err = strip_vlan(skb);
		if (unlikely(err))
			return err;
	}

	__vlan_hwaccel_put_tag(skb, ntohs(tci));

	return 0;
}

static bool is_ip(struct sk_buff *skb)
{
	return (OVS_CB(skb)->flow->key.eth.type == htons(ETH_P_IP) &&
		skb->transport_header > skb->network_header);
}

static __sum16 *get_l4_checksum(struct sk_buff *skb)
{
	u8 nw_proto = OVS_CB(skb)->flow->key.ip.proto;
	int transport_len = skb->len - skb_transport_offset(skb);
	if (nw_proto == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			return &tcp_hdr(skb)->check;
	} else if (nw_proto == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr)))
			return &udp_hdr(skb)->check;
	}
	return NULL;
}

static int set_nw_addr(struct sk_buff *skb, const struct nlattr *a)
{
	__be32 new_nwaddr = nla_get_be32(a);
	struct iphdr *nh;
	__sum16 *check;
	__be32 *nwaddr;
	int err;

	if (unlikely(!is_ip(skb)))
		return 0;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);
	nwaddr = nla_type(a) == ODP_ACTION_ATTR_SET_NW_SRC ? &nh->saddr : &nh->daddr;

	check = get_l4_checksum(skb);
	if (likely(check))
		inet_proto_csum_replace4(check, skb, *nwaddr, new_nwaddr, 1);
	csum_replace4(&nh->check, *nwaddr, new_nwaddr);

	skb_clear_rxhash(skb);

	*nwaddr = new_nwaddr;

	return 0;
}

static int set_nw_tos(struct sk_buff *skb, u8 nw_tos)
{
	struct iphdr *nh = ip_hdr(skb);
	u8 old, new;
	int err;

	if (unlikely(!is_ip(skb)))
		return 0;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	/* Set the DSCP bits and preserve the ECN bits. */
	old = nh->tos;
	new = nw_tos | (nh->tos & INET_ECN_MASK);
	csum_replace4(&nh->check, (__force __be32)old,
				  (__force __be32)new);
	nh->tos = new;

	return 0;
}

static int set_tp_port(struct sk_buff *skb, const struct nlattr *a)
{
	struct udphdr *th;
	__sum16 *check;
	__be16 *port;
	int err;

	if (unlikely(!is_ip(skb)))
		return 0;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	/* Must follow make_writable() since that can move the skb data. */
	check = get_l4_checksum(skb);
	if (unlikely(!check))
		return 0;

	/*
	 * Update port and checksum.
	 *
	 * This is OK because source and destination port numbers are at the
	 * same offsets in both UDP and TCP headers, and get_l4_checksum() only
	 * supports those protocols.
	 */
	th = udp_hdr(skb);
	port = nla_type(a) == ODP_ACTION_ATTR_SET_TP_SRC ? &th->source : &th->dest;
	inet_proto_csum_replace2(check, skb, *port, nla_get_be16(a), 0);
	*port = nla_get_be16(a);
	skb_clear_rxhash(skb);

	return 0;
}

static void do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *p;

	if (!skb)
		goto error;

	p = rcu_dereference(dp->ports[out_port]);
	if (!p)
		goto error;

	vport_send(p, skb);
	return;

error:
	kfree_skb(skb);
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb, u64 arg)
{
	struct dp_upcall_info upcall;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	upcall.cmd = ODP_PACKET_CMD_ACTION;
	upcall.key = &OVS_CB(skb)->flow->key;
	upcall.userdata = arg;
	upcall.sample_pool = 0;
	upcall.actions = NULL;
	upcall.actions_len = 0;
	return dp_upcall(dp, skb, &upcall);
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_actions *acts)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	u32 priority = skb->priority;
	const struct nlattr *a;
	int rem;

	for (a = acts->actions, rem = acts->actions_len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
			prev_port = -1;
		}

		switch (nla_type(a)) {
		case ODP_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case ODP_ACTION_ATTR_USERSPACE:
			err = output_userspace(dp, skb, nla_get_u64(a));
			break;

		case ODP_ACTION_ATTR_SET_TUNNEL:
			OVS_CB(skb)->tun_id = nla_get_be64(a);
			break;

		case ODP_ACTION_ATTR_SET_DL_TCI:
			err = modify_vlan_tci(skb, nla_get_be16(a));
			break;

		case ODP_ACTION_ATTR_STRIP_VLAN:
			err = strip_vlan(skb);
			break;

		case ODP_ACTION_ATTR_SET_DL_SRC:
			err = make_writable(skb, ETH_HLEN);
			if (likely(!err))
				memcpy(eth_hdr(skb)->h_source, nla_data(a), ETH_ALEN);
			break;

		case ODP_ACTION_ATTR_SET_DL_DST:
			err = make_writable(skb, ETH_HLEN);
			if (likely(!err))
				memcpy(eth_hdr(skb)->h_dest, nla_data(a), ETH_ALEN);
			break;

		case ODP_ACTION_ATTR_SET_NW_SRC:
		case ODP_ACTION_ATTR_SET_NW_DST:
			err = set_nw_addr(skb, a);
			break;

		case ODP_ACTION_ATTR_SET_NW_TOS:
			err = set_nw_tos(skb, nla_get_u8(a));
			break;

		case ODP_ACTION_ATTR_SET_TP_SRC:
		case ODP_ACTION_ATTR_SET_TP_DST:
			err = set_tp_port(skb, a);
			break;

		case ODP_ACTION_ATTR_SET_PRIORITY:
			skb->priority = nla_get_u32(a);
			break;

		case ODP_ACTION_ATTR_POP_PRIORITY:
			skb->priority = priority;
			break;
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1)
		do_output(dp, skb, prev_port);
	else
		consume_skb(skb);

	return 0;
}

static void sflow_sample(struct datapath *dp, struct sk_buff *skb,
			 struct sw_flow_actions *acts)
{
	struct sk_buff *nskb;
	struct vport *p = OVS_CB(skb)->vport;
	struct dp_upcall_info upcall;

	if (unlikely(!p))
		return;

	atomic_inc(&p->sflow_pool);
	if (net_random() >= dp->sflow_probability)
		return;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(!nskb))
		return;

	upcall.cmd = ODP_PACKET_CMD_SAMPLE;
	upcall.key = &OVS_CB(skb)->flow->key;
	upcall.userdata = 0;
	upcall.sample_pool = atomic_read(&p->sflow_pool);
	upcall.actions = acts->actions;
	upcall.actions_len = acts->actions_len;
	dp_upcall(dp, nskb, &upcall);
}

/* Execute a list of actions against 'skb'. */
int execute_actions(struct datapath *dp, struct sk_buff *skb)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
	struct loop_counter *loop;
	int error;

	/* Check whether we've looped too much. */
	loop = loop_get_counter();
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	/* Really execute actions. */
	if (dp->sflow_probability)
		sflow_sample(dp, skb, acts);
	OVS_CB(skb)->tun_id = 0;
	error = do_execute_actions(dp, skb, acts);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;
	loop_put_counter();

	return error;
}
