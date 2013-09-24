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

#include <linux/module.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <net/gre.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "gso.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && \
	!defined(HAVE_VLAN_BUG_WORKAROUND)
#include <linux/module.h>

static int vlan_tso __read_mostly;
module_param(vlan_tso, int, 0644);
MODULE_PARM_DESC(vlan_tso, "Enable TSO for VLAN packets");
#else
#define vlan_tso true
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
static bool dev_supports_vlan_tx(struct net_device *dev)
{
#if defined(HAVE_VLAN_BUG_WORKAROUND)
	return dev->features & NETIF_F_HW_VLAN_TX;
#else
	/* Assume that the driver is buggy. */
	return false;
#endif
}

int rpl_dev_queue_xmit(struct sk_buff *skb)
{
#undef dev_queue_xmit
	int err = -ENOMEM;

	if (vlan_tx_tag_present(skb) && !dev_supports_vlan_tx(skb->dev)) {
		int features;

		features = netif_skb_features(skb);

		if (!vlan_tso)
			features &= ~(NETIF_F_TSO | NETIF_F_TSO6 |
				      NETIF_F_UFO | NETIF_F_FSO);

		skb = __vlan_put_tag(skb, skb->vlan_proto, vlan_tx_tag_get(skb));
		if (unlikely(!skb))
			return err;
		vlan_set_tci(skb, 0);

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
#endif /* kernel version < 2.6.37 */

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

	return type;
}

static struct sk_buff *tnl_skb_gso_segment(struct sk_buff *skb,
					   netdev_features_t features,
					   bool tx_path)
{
	struct iphdr *iph = ip_hdr(skb);
	int pkt_hlen = skb_inner_network_offset(skb); /* inner l2 + tunnel hdr. */
	int mac_offset = skb_inner_mac_offset(skb);
	struct sk_buff *skb1 = skb;
	struct sk_buff *segs;
	__be16 proto = skb->protocol;
	char cb[sizeof(skb->cb)];

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

	segs = __skb_gso_segment(skb, 0, tx_path);
	if (!segs || IS_ERR(segs))
		goto free;

	skb = segs;
	while (skb) {
		__skb_push(skb, pkt_hlen);
		skb_reset_mac_header(skb);
		skb_reset_network_header(skb);
		skb_set_transport_header(skb, sizeof(struct iphdr));
		skb->mac_len = 0;

		memcpy(ip_hdr(skb), iph, pkt_hlen);
		memcpy(skb->cb, cb, sizeof(cb));
		if (OVS_GSO_CB(skb)->fix_segment)
			OVS_GSO_CB(skb)->fix_segment(skb);

		skb->protocol = proto;
		skb = skb->next;
	}
free:
	consume_skb(skb1);
	return segs;
}

int rpl_ip_local_out(struct sk_buff *skb)
{
	int ret = NETDEV_TX_OK;
	int id = -1;

	if (skb_is_gso(skb)) {
		struct iphdr *iph;

		iph = ip_hdr(skb);
		id = ntohs(iph->id);
		skb = tnl_skb_gso_segment(skb, 0, false);
		if (!skb || IS_ERR(skb))
			return 0;
	}  else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		int err;

		err = skb_checksum_help(skb);
		if (unlikely(err))
			return 0;
	}

	while (skb) {
		struct sk_buff *next_skb = skb->next;
		struct iphdr *iph;
		int err;

		skb->next = NULL;

		iph = ip_hdr(skb);
		if (id >= 0)
			iph->id = htons(id++);

		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

#undef ip_local_out
		err = ip_local_out(skb);
		if (unlikely(net_xmit_eval(err)))
			ret = err;

		skb = next_skb;
	}
	return ret;
}
