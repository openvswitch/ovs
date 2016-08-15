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

#include <linux/if_vlan.h>
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
#include <net/ip6_tunnel.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "compat.h"
#include "gso.h"
#include "vport-netdev.h"

#ifndef USE_UPSTREAM_TUNNEL
void rpl_iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
                      __be32 src, __be32 dst, __u8 proto, __u8 tos, __u8 ttl,
                      __be16 df, bool xnet)
{
	struct net_device *dev = skb->dev;
	int pkt_len = skb->len - skb_inner_network_offset(skb);
	struct iphdr *iph;
	int err;

	skb_scrub_packet(skb, xnet);

	skb_clear_hash(skb);
	skb_dst_set(skb, &rt->dst);

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
	__ip_select_ident(iph, &rt->dst, (skb_shinfo(skb)->gso_segs ?: 1) - 1);
#elif defined(HAVE_IP_SELECT_IDENT_USING_NET)
	__ip_select_ident(dev_net(rt->dst.dev), iph,
			  skb_shinfo(skb)->gso_segs ?: 1);
#else
	__ip_select_ident(iph, skb_shinfo(skb)->gso_segs ?: 1);
#endif

	err = ip_local_out(dev_net(rt->dst.dev), sk, skb);
	if (unlikely(net_xmit_eval(err)))
		pkt_len = 0;
	iptunnel_xmit_stats(dev, pkt_len);
}
EXPORT_SYMBOL_GPL(rpl_iptunnel_xmit);

int ovs_iptunnel_handle_offloads(struct sk_buff *skb,
				 int gso_type_mask,
				 void (*fix_segment)(struct sk_buff *))
{
	int err;

	if (likely(!skb_is_encapsulated(skb))) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	} else if (skb_is_gso(skb)) {
		err = -ENOSYS;
		goto error;
	}

	if (skb_is_gso(skb)) {
		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			goto error;
		skb_shinfo(skb)->gso_type |= gso_type_mask;

#ifndef USE_UPSTREAM_TUNNEL_GSO
		if (gso_type_mask)
			fix_segment = NULL;

		OVS_GSO_CB(skb)->fix_segment = fix_segment;
#endif
		return 0;
	}

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		skb->ip_summed = CHECKSUM_NONE;
		skb->encapsulation = 0;
	}

	return 0;
error:
	return err;
}
EXPORT_SYMBOL_GPL(ovs_iptunnel_handle_offloads);

int rpl___iptunnel_pull_header(struct sk_buff *skb, int hdr_len,
			       __be16 inner_proto, bool raw_proto, bool xnet)
{
	if (unlikely(!pskb_may_pull(skb, hdr_len)))
		return -ENOMEM;

	skb_pull_rcsum(skb, hdr_len);

	if (!raw_proto && inner_proto == htons(ETH_P_TEB)) {
		struct ethhdr *eh;

		if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
			return -ENOMEM;

		eh = (struct ethhdr *)skb->data;
		if (likely(eth_proto_is_802_3(eh->h_proto)))
			skb->protocol = eh->h_proto;
		else
			skb->protocol = htons(ETH_P_802_2);

	} else {
		skb->protocol = inner_proto;
	}

	skb_clear_hash_if_not_l4(skb);
	skb->vlan_tci = 0;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, xnet);

	return iptunnel_pull_offloads(skb);
}
EXPORT_SYMBOL_GPL(rpl___iptunnel_pull_header);
#endif /* USE_UPSTREAM_TUNNEL */

bool ovs_skb_is_encapsulated(struct sk_buff *skb)
{
	/* checking for inner protocol should be sufficient on newer kernel, but
	 * old kernel just set encapsulation bit.
	 */
	return ovs_skb_get_inner_protocol(skb) || skb->encapsulation;
}
EXPORT_SYMBOL_GPL(ovs_skb_is_encapsulated);

/* derived from ip_tunnel_rcv(). */
void ovs_ip_tunnel_rcv(struct net_device *dev, struct sk_buff *skb,
		       struct metadata_dst *tun_dst)
{
	struct pcpu_sw_netstats *tstats;

	tstats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)dev->tstats);
	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += skb->len;
	u64_stats_update_end(&tstats->syncp);

	skb_reset_mac_header(skb);
	skb_scrub_packet(skb, false);
	skb->protocol = eth_type_trans(skb, dev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

	ovs_skb_dst_set(skb, (struct dst_entry *)tun_dst);

#ifndef USE_UPSTREAM_TUNNEL
	netdev_port_receive(skb, &tun_dst->u.tun_info);
#else
	netif_rx(skb);
#endif
}

#ifndef HAVE_PCPU_SW_NETSTATS
#define netdev_stats_to_stats64 rpl_netdev_stats_to_stats64
static void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
				    const struct net_device_stats *netdev_stats)
{
#if BITS_PER_LONG == 64
	BUILD_BUG_ON(sizeof(*stats64) != sizeof(*netdev_stats));
	memcpy(stats64, netdev_stats, sizeof(*stats64));
#else
	size_t i, n = sizeof(*stats64) / sizeof(u64);
	const unsigned long *src = (const unsigned long *)netdev_stats;
	u64 *dst = (u64 *)stats64;

	BUILD_BUG_ON(sizeof(*netdev_stats) / sizeof(unsigned long) !=
		     sizeof(*stats64) / sizeof(u64));
	for (i = 0; i < n; i++)
		dst[i] = src[i];
#endif
}

struct rtnl_link_stats64 *rpl_ip_tunnel_get_stats64(struct net_device *dev,
						struct rtnl_link_stats64 *tot)
{
	int i;

	netdev_stats_to_stats64(tot, &dev->stats);

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *tstats =
						   per_cpu_ptr((struct pcpu_sw_netstats __percpu *)dev->tstats, i);
		u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&tstats->syncp);
			rx_packets = tstats->rx_packets;
			tx_packets = tstats->tx_packets;
			rx_bytes = tstats->rx_bytes;
			tx_bytes = tstats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&tstats->syncp, start));

		tot->rx_packets += rx_packets;
		tot->tx_packets += tx_packets;
		tot->rx_bytes   += rx_bytes;
		tot->tx_bytes   += tx_bytes;
	}

	return tot;
}
#endif

void rpl_ip6tunnel_xmit(struct sock *sk, struct sk_buff *skb,
		    struct net_device *dev)
{
	int pkt_len, err;

	pkt_len = skb->len - skb_inner_network_offset(skb);
#ifdef HAVE_IP6_LOCAL_OUT_SK
	err = ip6_local_out_sk(sk, skb);
#else
	err = ip6_local_out(dev_net(skb_dst(skb)->dev), sk, skb);
#endif
	if (net_xmit_eval(err))
		pkt_len = -1;

	iptunnel_xmit_stats(dev, pkt_len);
}
EXPORT_SYMBOL_GPL(rpl_ip6tunnel_xmit);
