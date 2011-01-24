/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010 Nicira Networks.
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
#include "openvswitch/datapath-protocol.h"
#include "vport.h"

static int do_execute_actions(struct datapath *, struct sk_buff *,
			      const struct sw_flow_key *,
			      const struct nlattr *actions, u32 actions_len);

static struct sk_buff *make_writable(struct sk_buff *skb, unsigned min_headroom)
{
	if (skb_cloned(skb)) {
		struct sk_buff *nskb;
		unsigned headroom = max(min_headroom, skb_headroom(skb));

		nskb = skb_copy_expand(skb, headroom, skb_tailroom(skb), GFP_ATOMIC);
		if (nskb) {
			set_skb_csum_bits(skb, nskb);
			kfree_skb(skb);
			return nskb;
		}
	} else {
		unsigned int hdr_len = (skb_transport_offset(skb)
					+ sizeof(struct tcphdr));
		if (pskb_may_pull(skb, min(hdr_len, skb->len)))
			return skb;
	}
	kfree_skb(skb);
	return NULL;
}

static struct sk_buff *vlan_pull_tag(struct sk_buff *skb)
{
	struct vlan_ethhdr *vh = vlan_eth_hdr(skb);
	struct ethhdr *eh;

	/* Verify we were given a vlan packet */
	if (vh->h_vlan_proto != htons(ETH_P_8021Q) || skb->len < VLAN_ETH_HLEN)
		return skb;

	if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ ETH_HLEN, VLAN_HLEN, 0));

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * VLAN_ETH_ALEN);

	eh = (struct ethhdr *)skb_pull(skb, VLAN_HLEN);

	skb->protocol = eh->h_proto;
	skb->mac_header += VLAN_HLEN;

	return skb;
}

static struct sk_buff *modify_vlan_tci(struct datapath *dp, struct sk_buff *skb,
				       const struct sw_flow_key *key,
				       const struct nlattr *a, u32 actions_len)
{
	__be16 tci = nla_get_be16(a);

	skb = make_writable(skb, VLAN_HLEN);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	if (skb->protocol == htons(ETH_P_8021Q)) {
		/* Modify vlan id, but maintain other TCI values */
		struct vlan_ethhdr *vh;
		__be16 old_tci;

		if (skb->len < VLAN_ETH_HLEN)
			return skb;

		vh = vlan_eth_hdr(skb);
		old_tci = vh->h_vlan_TCI;

		vh->h_vlan_TCI = tci;

		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			__be16 diff[] = { ~old_tci, vh->h_vlan_TCI };

			skb->csum = ~csum_partial((char *)diff, sizeof(diff),
						~skb->csum);
		}
	} else {
		int err;

		/* Add vlan header */

		/* Set up checksumming pointers for checksum-deferred packets
		 * on Xen.  Otherwise, dev_queue_xmit() will try to do this
		 * when we send the packet out on the wire, and it will fail at
		 * that point because skb_checksum_setup() will not look inside
		 * an 802.1Q header. */
		err = vswitch_skb_checksum_setup(skb);
		if (unlikely(err)) {
			kfree_skb(skb);
			return ERR_PTR(err);
		}

		/* GSO is not implemented for packets with an 802.1Q header, so
		 * we have to do segmentation before we add that header.
		 *
		 * GSO does work with hardware-accelerated VLAN tagging, but we
		 * can't use hardware-accelerated VLAN tagging since it
		 * requires the device to have a VLAN group configured (with
		 * e.g. vconfig(8)) and we don't do that.
		 *
		 * Having to do this here may be a performance loss, since we
		 * can't take advantage of TSO hardware support, although it
		 * does not make a measurable network performance difference
		 * for 1G Ethernet.  Fixing that would require patching the
		 * kernel (either to add GSO support to the VLAN protocol or to
		 * support hardware-accelerated VLAN tagging without VLAN
		 * groups configured). */
		if (skb_is_gso(skb)) {
			const struct nlattr *actions_left;
			int actions_len_left;
			struct sk_buff *segs;

			segs = skb_gso_segment(skb, 0);
			kfree_skb(skb);
			if (IS_ERR(segs))
				return ERR_CAST(segs);

			actions_len_left = actions_len;
			actions_left = nla_next(a, &actions_len_left);

			do {
				struct sk_buff *nskb = segs->next;

				segs->next = NULL;

				/* GSO can change the checksum type so update.*/
				compute_ip_summed(segs, true);

				segs = __vlan_put_tag(segs, ntohs(tci));
				err = -ENOMEM;
				if (segs) {
					err = do_execute_actions(
						dp, segs, key, actions_left,
						actions_len_left);
				}

				if (unlikely(err)) {
					while ((segs = nskb)) {
						nskb = segs->next;
						segs->next = NULL;
						kfree_skb(segs);
					}
					return ERR_PTR(err);
				}

				segs = nskb;
			} while (segs->next);

			skb = segs;
			compute_ip_summed(skb, true);
		}

		/* The hardware-accelerated version of vlan_put_tag() works
		 * only for a device that has a VLAN group configured (with
		 * e.g. vconfig(8)), so call the software-only version
		 * __vlan_put_tag() directly instead.
		 */
		skb = __vlan_put_tag(skb, ntohs(tci));
		if (!skb)
			return ERR_PTR(-ENOMEM);

		/* GSO doesn't fix up the hardware computed checksum so this
		 * will only be hit in the non-GSO case. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
						+ ETH_HLEN, VLAN_HLEN, 0));
	}

	return skb;
}

static struct sk_buff *strip_vlan(struct sk_buff *skb)
{
	skb = make_writable(skb, 0);
	if (skb)
		vlan_pull_tag(skb);
	return skb;
}

static bool is_ip(struct sk_buff *skb, const struct sw_flow_key *key)
{
	return (key->dl_type == htons(ETH_P_IP) &&
		skb->transport_header > skb->network_header);
}

static __sum16 *get_l4_checksum(struct sk_buff *skb, const struct sw_flow_key *key)
{
	int transport_len = skb->len - skb_transport_offset(skb);
	if (key->nw_proto == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			return &tcp_hdr(skb)->check;
	} else if (key->nw_proto == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr)))
			return &udp_hdr(skb)->check;
	}
	return NULL;
}

static struct sk_buff *set_nw_addr(struct sk_buff *skb,
				   const struct sw_flow_key *key,
				   const struct nlattr *a)
{
	__be32 new_nwaddr = nla_get_be32(a);
	struct iphdr *nh;
	__sum16 *check;
	__be32 *nwaddr;

	if (unlikely(!is_ip(skb, key)))
		return skb;

	skb = make_writable(skb, 0);
	if (unlikely(!skb))
		return NULL;

	nh = ip_hdr(skb);
	nwaddr = nla_type(a) == ODPAT_SET_NW_SRC ? &nh->saddr : &nh->daddr;

	check = get_l4_checksum(skb, key);
	if (likely(check))
		inet_proto_csum_replace4(check, skb, *nwaddr, new_nwaddr, 1);
	csum_replace4(&nh->check, *nwaddr, new_nwaddr);

	*nwaddr = new_nwaddr;

	return skb;
}

static struct sk_buff *set_nw_tos(struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  u8 nw_tos)
{
	if (unlikely(!is_ip(skb, key)))
		return skb;

	skb = make_writable(skb, 0);
	if (skb) {
		struct iphdr *nh = ip_hdr(skb);
		u8 *f = &nh->tos;
		u8 old = *f;
		u8 new;

		/* Set the DSCP bits and preserve the ECN bits. */
		new = nw_tos | (nh->tos & INET_ECN_MASK);
		csum_replace4(&nh->check, (__force __be32)old,
					  (__force __be32)new);
		*f = new;
	}
	return skb;
}

static struct sk_buff *set_tp_port(struct sk_buff *skb,
				   const struct sw_flow_key *key,
				   const struct nlattr *a)
{
	struct udphdr *th;
	__sum16 *check;
	__be16 *port;

	if (unlikely(!is_ip(skb, key)))
		return skb;

	skb = make_writable(skb, 0);
	if (unlikely(!skb))
		return NULL;

	/* Must follow make_writable() since that can move the skb data. */
	check = get_l4_checksum(skb, key);
	if (unlikely(!check))
		return skb;

	/*
	 * Update port and checksum.
	 *
	 * This is OK because source and destination port numbers are at the
	 * same offsets in both UDP and TCP headers, and get_l4_checksum() only
	 * supports those protocols.
	 */
	th = udp_hdr(skb);
	port = nla_type(a) == ODPAT_SET_TP_SRC ? &th->source : &th->dest;
	inet_proto_csum_replace2(check, skb, *port, nla_get_be16(a), 0);
	*port = nla_get_be16(a);

	return skb;
}

/**
 * is_spoofed_arp - check for invalid ARP packet
 *
 * @skb: skbuff containing an Ethernet packet, with network header pointing
 * just past the Ethernet and optional 802.1Q header.
 * @key: flow key extracted from @skb by flow_extract()
 *
 * Returns true if @skb is an invalid Ethernet+IPv4 ARP packet: one with screwy
 * or truncated header fields or one whose inner and outer Ethernet address
 * differ.
 */
static bool is_spoofed_arp(struct sk_buff *skb, const struct sw_flow_key *key)
{
	struct arp_eth_header *arp;

	if (key->dl_type != htons(ETH_P_ARP))
		return false;

	if (skb_network_offset(skb) + sizeof(struct arp_eth_header) > skb->len)
		return true;

	arp = (struct arp_eth_header *)skb_network_header(skb);
	return (arp->ar_hrd != htons(ARPHRD_ETHER) ||
		arp->ar_pro != htons(ETH_P_IP) ||
		arp->ar_hln != ETH_ALEN ||
		arp->ar_pln != 4 ||
		compare_ether_addr(arp->ar_sha, eth_hdr(skb)->h_source));
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

static int output_control(struct datapath *dp, struct sk_buff *skb, u64 arg)
{
	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	return dp_output_control(dp, skb, _ODPL_ACTION_NR, arg);
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      const struct sw_flow_key *key,
			      const struct nlattr *actions, u32 actions_len)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	u32 priority = skb->priority;
	const struct nlattr *a;
	int rem, err;

	for (a = actions, rem = actions_len; rem > 0; a = nla_next(a, &rem)) {
		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
			prev_port = -1;
		}

		switch (nla_type(a)) {
		case ODPAT_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case ODPAT_CONTROLLER:
			err = output_control(dp, skb, nla_get_u64(a));
			if (err) {
				kfree_skb(skb);
				return err;
			}
			break;

		case ODPAT_SET_TUNNEL:
			OVS_CB(skb)->tun_id = nla_get_be64(a);
			break;

		case ODPAT_SET_DL_TCI:
			skb = modify_vlan_tci(dp, skb, key, a, rem);
			if (IS_ERR(skb))
				return PTR_ERR(skb);
			break;

		case ODPAT_STRIP_VLAN:
			skb = strip_vlan(skb);
			break;

		case ODPAT_SET_DL_SRC:
			skb = make_writable(skb, 0);
			if (!skb)
				return -ENOMEM;
			memcpy(eth_hdr(skb)->h_source, nla_data(a), ETH_ALEN);
			break;

		case ODPAT_SET_DL_DST:
			skb = make_writable(skb, 0);
			if (!skb)
				return -ENOMEM;
			memcpy(eth_hdr(skb)->h_dest, nla_data(a), ETH_ALEN);
			break;

		case ODPAT_SET_NW_SRC:
		case ODPAT_SET_NW_DST:
			skb = set_nw_addr(skb, key, a);
			break;

		case ODPAT_SET_NW_TOS:
			skb = set_nw_tos(skb, key, nla_get_u8(a));
			break;

		case ODPAT_SET_TP_SRC:
		case ODPAT_SET_TP_DST:
			skb = set_tp_port(skb, key, a);
			break;

		case ODPAT_SET_PRIORITY:
			skb->priority = nla_get_u32(a);
			break;

		case ODPAT_POP_PRIORITY:
			skb->priority = priority;
			break;

		case ODPAT_DROP_SPOOFED_ARP:
			if (unlikely(is_spoofed_arp(skb, key)))
				goto exit;
			break;
		}
		if (!skb)
			return -ENOMEM;
	}
exit:
	if (prev_port != -1)
		do_output(dp, skb, prev_port);
	else
		kfree_skb(skb);
	return 0;
}

/* Send a copy of this packet up to the sFlow agent, along with extra
 * information about what happened to it. */
static void sflow_sample(struct datapath *dp, struct sk_buff *skb,
			 const struct nlattr *a, u32 actions_len,
			 struct vport *vport)
{
	struct odp_sflow_sample_header *hdr;
	unsigned int hdrlen = sizeof(struct odp_sflow_sample_header);
	struct sk_buff *nskb;

	nskb = skb_copy_expand(skb, actions_len + hdrlen, 0, GFP_ATOMIC);
	if (!nskb)
		return;

	memcpy(__skb_push(nskb, actions_len), a, actions_len);
	hdr = (struct odp_sflow_sample_header*)__skb_push(nskb, hdrlen);
	hdr->actions_len = actions_len;
	hdr->sample_pool = atomic_read(&vport->sflow_pool);
	dp_output_control(dp, nskb, _ODPL_SFLOW_NR, 0);
}

/* Execute a list of actions against 'skb'. */
int execute_actions(struct datapath *dp, struct sk_buff *skb,
		    const struct sw_flow_key *key,
		    const struct nlattr *actions, u32 actions_len)
{
	if (dp->sflow_probability) {
		struct vport *p = OVS_CB(skb)->vport;
		if (p) {
			atomic_inc(&p->sflow_pool);
			if (dp->sflow_probability == UINT_MAX ||
			    net_random() < dp->sflow_probability)
				sflow_sample(dp, skb, actions, actions_len, p);
		}
	}

	OVS_CB(skb)->tun_id = 0;

	return do_execute_actions(dp, skb, key, actions, actions_len);
}
