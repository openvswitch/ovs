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

#include <linux/version.h>

#include <linux/module.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/if_vlan.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <net/gre.h>
#include <net/icmp.h>
#include <net/mpls.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "gso.h"

#ifdef OVS_USE_COMPAT_GSO_SEGMENTATION
/* Strictly this is not needed and will be optimised out
 * as this code is guarded by if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0).
 * It is here to make things explicit should the compatibility
 * code be extended in some way prior extending its life-span
 * beyond v3.19.
 */
static bool supports_mpls_gso(void)
{
/* MPLS GSO was introduced in v3.11, however it was not correctly
 * activated using mpls_features until v3.19. */
#ifdef OVS_USE_COMPAT_GSO_SEGMENTATION
	return true;
#else
	return false;
#endif
}

int rpl_dev_queue_xmit(struct sk_buff *skb)
{
#undef dev_queue_xmit
	int err = -ENOMEM;
	bool mpls;

	mpls = false;

	/* Avoid traversing any VLAN tags that are present to determine if
	 * the ethtype is MPLS. Instead compare the mac_len (end of L2) and
	 * skb_network_offset() (beginning of L3) whose inequality will
	 * indicate the presence of an MPLS label stack. */
	if (skb->mac_len != skb_network_offset(skb) && !supports_mpls_gso())
		mpls = true;

	if (mpls) {
		int features;

		features = netif_skb_features(skb);

		/* As of v3.11 the kernel provides an mpls_features field in
		 * struct net_device which allows devices to advertise which
		 * features its supports for MPLS. This value defaults to
		 * NETIF_F_SG and as of v3.19.
		 *
		 * This compatibility code is intended for kernels older
		 * than v3.19 that do not support MPLS GSO and do not
		 * use mpls_features. Thus this code uses NETIF_F_SG
		 * directly in place of mpls_features.
		 */
		if (mpls)
			features &= NETIF_F_SG;

		if (netif_needs_gso(skb, features)) {
			struct sk_buff *nskb;

			nskb = skb_gso_segment(skb, features);
			if (!nskb) {
				if (unlikely(skb_cloned(skb) &&
				    pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
					goto drop;

				skb_shinfo(skb)->gso_type &= ~SKB_GSO_DODGY;
				goto xmit;
			}

			if (IS_ERR(nskb)) {
				err = PTR_ERR(nskb);
				goto drop;
			}
			consume_skb(skb);
			skb = nskb;

			do {
				nskb = skb->next;
				skb->next = NULL;
				err = dev_queue_xmit(skb);
				skb = nskb;
			} while (skb);

			return err;
		}
	}
xmit:
	return dev_queue_xmit(skb);

drop:
	kfree_skb(skb);
	return err;
}
EXPORT_SYMBOL_GPL(rpl_dev_queue_xmit);
#endif /* OVS_USE_COMPAT_GSO_SEGMENTATION */

#ifndef USE_UPSTREAM_TUNNEL_GSO
static __be16 __skb_network_protocol(struct sk_buff *skb)
{
	__be16 type = skb->protocol;
	int vlan_depth = ETH_HLEN;

	while (type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh;

		if (unlikely(!pskb_may_pull(skb, vlan_depth + VLAN_HLEN)))
			return 0;

		vh = (struct vlan_hdr *)(skb->data + vlan_depth);
		type = vh->h_vlan_encapsulated_proto;
		vlan_depth += VLAN_HLEN;
	}

	if (eth_p_mpls(type))
		type = ovs_skb_get_inner_protocol(skb);

	return type;
}

static struct sk_buff *tnl_skb_gso_segment(struct sk_buff *skb,
					   netdev_features_t features,
					   bool tx_path,
					   sa_family_t sa_family)
{
	void *iph = skb_network_header(skb);
	int pkt_hlen = skb_inner_network_offset(skb); /* inner l2 + tunnel hdr. */
	int mac_offset = skb_inner_mac_offset(skb);
	int outer_l3_offset = skb_network_offset(skb);
	int outer_l4_offset = skb_transport_offset(skb);
	struct sk_buff *skb1 = skb;
	struct dst_entry *dst = skb_dst(skb);
	struct sk_buff *segs;
	__be16 proto = skb->protocol;
	char cb[sizeof(skb->cb)];

	BUILD_BUG_ON(sizeof(struct ovs_gso_cb) > FIELD_SIZEOF(struct sk_buff, cb));
	OVS_GSO_CB(skb)->ipv6 = (sa_family == AF_INET6);
	/* setup whole inner packet to get protocol. */
	__skb_pull(skb, mac_offset);
	skb->protocol = __skb_network_protocol(skb);

	/* setup l3 packet to gso, to get around segmentation bug on older kernel.*/
	__skb_pull(skb, (pkt_hlen - mac_offset));
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	/* From 3.9 kernel skb->cb is used by skb gso. Therefore
	 * make copy of it to restore it back. */
	memcpy(cb, skb->cb, sizeof(cb));

	/* We are handling offloads by segmenting l3 packet, so
	 * no need to call OVS compat segmentation function. */

#ifdef HAVE___SKB_GSO_SEGMENT
#undef __skb_gso_segment
	segs = __skb_gso_segment(skb, 0, tx_path);
#else
#undef skb_gso_segment
	segs = skb_gso_segment(skb, 0);
#endif

	if (!segs || IS_ERR(segs))
		goto free;

	skb = segs;
	while (skb) {
		__skb_push(skb, pkt_hlen);
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, outer_l3_offset);
		skb_set_transport_header(skb, outer_l4_offset);
		skb->mac_len = 0;

		memcpy(skb_network_header(skb), iph, pkt_hlen);
		memcpy(skb->cb, cb, sizeof(cb));

		skb->protocol = proto;
		if (skb->next)
			dst = dst_clone(dst);

		skb_dst_set(skb, dst);
		OVS_GSO_CB(skb)->fix_segment(skb);

		skb = skb->next;
	}
free:
	consume_skb(skb1);
	return segs;
}

static int output_ip(struct sk_buff *skb)
{
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

#undef ip_local_out
	return ip_local_out(skb);
}

int rpl_ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	if (!OVS_GSO_CB(skb)->fix_segment)
		return output_ip(skb);

	/* This bit set can confuse some drivers on old kernel. */
	skb->encapsulation = 0;

	if (skb_is_gso(skb)) {
		int ret;
		int id;

		skb = tnl_skb_gso_segment(skb, 0, false, AF_INET);
		if (!skb || IS_ERR(skb))
			return NET_XMIT_DROP;

		id = ntohs(ip_hdr(skb)->id);
		do {
			struct sk_buff *next_skb = skb->next;

			skb->next = NULL;
			ip_hdr(skb)->id = htons(id++);

			ret = output_ip(skb);
			skb = next_skb;
		} while (skb);
		return ret;
	}  else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		int err;

		err = skb_checksum_help(skb);
		if (unlikely(err))
			return NET_XMIT_DROP;
	}

	return output_ip(skb);
}
EXPORT_SYMBOL_GPL(rpl_ip_local_out);

static int output_ipv6(struct sk_buff *skb)
{
	memset(IP6CB(skb), 0, sizeof (*IP6CB(skb)));
#undef ip6_local_out
	return ip6_local_out(skb);
}

int rpl_ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	if (!OVS_GSO_CB(skb)->fix_segment)
		return output_ipv6(skb);

	/* This bit set can confuse some drivers on old kernel. */
	skb->encapsulation = 0;

	if (skb_is_gso(skb)) {
		int ret;

		skb = tnl_skb_gso_segment(skb, 0, false, AF_INET6);
		if (!skb || IS_ERR(skb))
			return NET_XMIT_DROP;

		do {
			struct sk_buff *next_skb = skb->next;

			skb->next = NULL;
			ret = output_ipv6(skb);
			skb = next_skb;
		} while (skb);
		return ret;
	}  else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		int err;

		err = skb_checksum_help(skb);
		if (unlikely(err))
			return NET_XMIT_DROP;
	}

	return output_ipv6(skb);
}
EXPORT_SYMBOL_GPL(rpl_ip6_local_out);
#endif /* USE_UPSTREAM_TUNNEL_GSO */
