/*
 * Copyright (c) 2007-2013 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */


#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/rculist.h>
#include <net/ip_tunnels.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "compat.h"
#include "gso.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
int rpl_iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
                      __be32 src, __be32 dst, __u8 proto, __u8 tos, __u8 ttl,
                      __be16 df, bool xnet)
{
	int pkt_len = skb->len;
	struct iphdr *iph;
	int err;

	nf_reset(skb);
	secpath_reset(skb);
	skb_clear_hash(skb);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt_dst(rt));
#if 0
	/* Do not clear ovs_skb_cb.  It will be done in gso code. */
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
#endif

	/* Push down and install the IP header. */
	__skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	df;
	iph->protocol	=	proto;
	iph->tos	=	tos;
	iph->daddr	=	dst;
	iph->saddr	=	src;
	iph->ttl	=	ttl;

#ifdef HAVE_IP_SELECT_IDENT_USING_DST_ENTRY
	__ip_select_ident(iph, &rt_dst(rt), (skb_shinfo(skb)->gso_segs ?: 1) - 1);
#else
	__ip_select_ident(iph, skb_shinfo(skb)->gso_segs ?: 1);
#endif

	err = ip_local_out(skb);
	if (unlikely(net_xmit_eval(err)))
		pkt_len = 0;
	return pkt_len;
}
EXPORT_SYMBOL_GPL(rpl_iptunnel_xmit);

struct sk_buff *ovs_iptunnel_handle_offloads(struct sk_buff *skb,
					     bool csum_help, int gso_type_mask,
				             void (*fix_segment)(struct sk_buff *))
{
	int err;

	if (likely(!skb_is_encapsulated(skb))) {
		skb_reset_inner_headers(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
		skb->encapsulation = 1;
#endif
	} else if (skb_is_gso(skb)) {
		err = -ENOSYS;
		goto error;
	}

	if (gso_type_mask)
		fix_segment = NULL;

	OVS_GSO_CB(skb)->fix_segment = fix_segment;

	if (skb_is_gso(skb)) {
		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			goto error;
		skb_shinfo(skb)->gso_type |= gso_type_mask;
		return skb;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	/* If packet is not gso and we are resolving any partial checksum,
	 * clear encapsulation flag. This allows setting CHECKSUM_PARTIAL
	 * on the outer header without confusing devices that implement
	 * NETIF_F_IP_CSUM with encapsulation.
	 */
	if (csum_help)
		skb->encapsulation = 0;
#endif

	if (skb->ip_summed == CHECKSUM_PARTIAL && csum_help) {
		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error;
	} else if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_NONE;

	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(ovs_iptunnel_handle_offloads);

int rpl_iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto)
{
	if (unlikely(!pskb_may_pull(skb, hdr_len)))
		return -ENOMEM;

	skb_pull_rcsum(skb, hdr_len);

	if (inner_proto == htons(ETH_P_TEB)) {
		struct ethhdr *eh;

		if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
			return -ENOMEM;

		eh = (struct ethhdr *)skb->data;

		if (likely(ntohs(eh->h_proto) >= ETH_P_802_3_MIN))
			skb->protocol = eh->h_proto;
		else
			skb->protocol = htons(ETH_P_802_2);

	} else {
		skb->protocol = inner_proto;
	}

	nf_reset(skb);
	secpath_reset(skb);
	skb_clear_hash(skb);
	skb_dst_drop(skb);
	vlan_set_tci(skb, 0);
	skb_set_queue_mapping(skb, 0);
	skb->pkt_type = PACKET_HOST;
	return 0;
}
EXPORT_SYMBOL_GPL(rpl_iptunnel_pull_header);

#endif

bool ovs_skb_is_encapsulated(struct sk_buff *skb)
{
	/* checking for inner protocol should be sufficient on newer kernel, but
	 * old kernel just set encapsulation bit.
	 */
	return ovs_skb_get_inner_protocol(skb) || skb_encapsulation(skb);
}
EXPORT_SYMBOL_GPL(ovs_skb_is_encapsulated);
