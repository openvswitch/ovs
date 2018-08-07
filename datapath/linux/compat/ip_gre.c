/*
 *	Linux NET3:	GRE over IP protocol decoder.
 *
 *	Authors: Alexey Kuznetsov (kuznet@ms2.inr.ac.ru)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#ifndef USE_UPSTREAM_TUNNEL
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netdev_features.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/gre.h>
#include <net/dst_metadata.h>
#include <net/erspan.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#endif

#include "gso.h"
#include "vport-netdev.h"

static int gre_tap_net_id __read_mostly;
static int ipgre_net_id __read_mostly;
static unsigned int erspan_net_id __read_mostly;
static void erspan_build_header(struct sk_buff *skb,
				__be32 id, u32 index,
				bool truncate, bool is_ipv4);

static struct rtnl_link_ops ipgre_link_ops __read_mostly;
static bool ip_gre_loaded = false;

#define ip_gre_calc_hlen rpl_ip_gre_calc_hlen
static int ip_gre_calc_hlen(__be16 o_flags)
{
	int addend = 4;

	if (o_flags & TUNNEL_CSUM)
		addend += 4;
	if (o_flags & TUNNEL_KEY)
		addend += 4;
	if (o_flags & TUNNEL_SEQ)
		addend += 4;
	return addend;
}

/* Returns the least-significant 32 bits of a __be64. */
static __be32 tunnel_id_to_key(__be64 x)
{
#ifdef __BIG_ENDIAN
	return (__force __be32)x;
#else
	return (__force __be32)((__force u64)x >> 32);
#endif
}

static struct dst_ops md_dst_ops = {
	.family =		AF_UNSPEC,
};

#ifndef DST_METADATA
#define DST_METADATA 0x0080
#endif

static void rpl__metadata_dst_init(struct metadata_dst *md_dst,
				enum metadata_type type, u8 optslen)

{
	struct dst_entry *dst;

	dst = &md_dst->dst;
	dst_init(dst, &md_dst_ops, NULL, 1, DST_OBSOLETE_NONE,
		 DST_METADATA | DST_NOCOUNT);

#if 0
	/* unused in OVS */
	dst->input = dst_md_discard;
	dst->output = dst_md_discard_out;
#endif
	memset(dst + 1, 0, sizeof(*md_dst) + optslen - sizeof(*dst));
	md_dst->type = type;
}

static struct metadata_dst *erspan_rpl_metadata_dst_alloc(u8 optslen, enum metadata_type type,
					gfp_t flags)
{
	struct metadata_dst *md_dst;

	md_dst = kmalloc(sizeof(*md_dst) + optslen, flags);
	if (!md_dst)
		return NULL;

	rpl__metadata_dst_init(md_dst, type, optslen);

	return md_dst;
}
static inline struct metadata_dst *rpl_tun_rx_dst(int md_size)
{
	struct metadata_dst *tun_dst;

	tun_dst = erspan_rpl_metadata_dst_alloc(md_size, METADATA_IP_TUNNEL, GFP_ATOMIC);
	if (!tun_dst)
		return NULL;

	tun_dst->u.tun_info.options_len = 0;
	tun_dst->u.tun_info.mode = 0;
	return tun_dst;
}
static inline struct metadata_dst *rpl__ip_tun_set_dst(__be32 saddr,
						    __be32 daddr,
						    __u8 tos, __u8 ttl,
						    __be16 tp_dst,
						    __be16 flags,
						    __be64 tunnel_id,
						    int md_size)
{
	struct metadata_dst *tun_dst;

	tun_dst = rpl_tun_rx_dst(md_size);
	if (!tun_dst)
		return NULL;

	ip_tunnel_key_init(&tun_dst->u.tun_info.key,
			   saddr, daddr, tos, ttl,
			   0, 0, tp_dst, tunnel_id, flags);
	return tun_dst;
}

static inline struct metadata_dst *rpl_ip_tun_rx_dst(struct sk_buff *skb,
						 __be16 flags,
						 __be64 tunnel_id,
						 int md_size)
{
	const struct iphdr *iph = ip_hdr(skb);

	return rpl__ip_tun_set_dst(iph->saddr, iph->daddr, iph->tos, iph->ttl,
				0, flags, tunnel_id, md_size);
}

static int erspan_rcv(struct sk_buff *skb, struct tnl_ptk_info *tpi,
		      int gre_hdr_len)
{
	struct net *net = dev_net(skb->dev);
	struct metadata_dst *tun_dst = NULL;
	struct erspan_base_hdr *ershdr;
	struct erspan_metadata *pkt_md;
	struct ip_tunnel_net *itn;
	struct ip_tunnel *tunnel;
	const struct iphdr *iph;
	struct erspan_md2 *md2;
	int ver;
	int len;

	itn = net_generic(net, erspan_net_id);
	len = gre_hdr_len + sizeof(*ershdr);

	/* Check based hdr len */
	if (unlikely(!pskb_may_pull(skb, len)))
		return PACKET_REJECT;

	iph = ip_hdr(skb);
	ershdr = (struct erspan_base_hdr *)(skb->data + gre_hdr_len);
	ver = ershdr->ver;

	/* The original GRE header does not have key field,
	 * Use ERSPAN 10-bit session ID as key.
	 */
	tpi->key = cpu_to_be32(get_session_id(ershdr));
	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex,
				  tpi->flags,
				  iph->saddr, iph->daddr, tpi->key);

	if (tunnel) {
		len = gre_hdr_len + erspan_hdr_len(ver);
		if (unlikely(!pskb_may_pull(skb, len)))
			return PACKET_REJECT;

		ershdr = (struct erspan_base_hdr *)skb->data;
		pkt_md = (struct erspan_metadata *)(ershdr + 1);

		if (__iptunnel_pull_header(skb,
					   len,
					   htons(ETH_P_TEB),
					   false, false) < 0)
			goto drop;

		if (tunnel->collect_md) {
			struct ip_tunnel_info *info;
			struct erspan_metadata *md;
			__be64 tun_id;
			__be16 flags;

			tpi->flags |= TUNNEL_KEY;
			flags = tpi->flags;
			tun_id = key32_to_tunnel_id(tpi->key);

			tun_dst = rpl_ip_tun_rx_dst(skb, flags, tun_id, sizeof(*md));
			if (!tun_dst)
				return PACKET_REJECT;

			md = ip_tunnel_info_opts(&tun_dst->u.tun_info);
			md->version = ver;
			md2 = &md->u.md2;
			memcpy(md2, pkt_md, ver == 1 ? ERSPAN_V1_MDSIZE :
						       ERSPAN_V2_MDSIZE);

			info = &tun_dst->u.tun_info;
			info->key.tun_flags |= TUNNEL_ERSPAN_OPT;
			info->options_len = sizeof(*md);
		}

		skb_reset_mac_header(skb);
		ovs_ip_tunnel_rcv(tunnel->dev, skb, tun_dst);
		kfree(tun_dst);
		return PACKET_RCVD;
	}
drop:
	kfree_skb(skb);
	return PACKET_RCVD;
}


static int __ipgre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		       struct ip_tunnel_net *itn, int hdr_len, bool raw_proto)
{
	struct metadata_dst tun_dst;
	const struct iphdr *iph;
	struct ip_tunnel *tunnel;

	iph = ip_hdr(skb);
	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, tpi->flags,
				  iph->saddr, iph->daddr, tpi->key);

	if (tunnel) {
		if (__iptunnel_pull_header(skb, hdr_len, tpi->proto,
					   raw_proto, false) < 0)
			goto drop;

		if (tunnel->dev->type != ARPHRD_NONE)
			skb_pop_mac_header(skb);
		else
			skb_reset_mac_header(skb);
		if (tunnel->collect_md) {
			__be16 flags;
			__be64 tun_id;

			flags = tpi->flags & (TUNNEL_CSUM | TUNNEL_KEY);
			tun_id = key32_to_tunnel_id(tpi->key);
			ovs_ip_tun_rx_dst(&tun_dst, skb, flags, tun_id, 0);
		}

		ovs_ip_tunnel_rcv(tunnel->dev, skb, &tun_dst);
		return PACKET_RCVD;
	}
	return PACKET_NEXT;

drop:
	kfree_skb(skb);
	return PACKET_RCVD;
}


static int ipgre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		     int hdr_len)
{
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn;
	int res;

	if (tpi->proto == htons(ETH_P_TEB))
		itn = net_generic(net, gre_tap_net_id);
	else
		itn = net_generic(net, ipgre_net_id);

	res = __ipgre_rcv(skb, tpi, itn, hdr_len, false);
	if (res == PACKET_NEXT && tpi->proto == htons(ETH_P_TEB)) {
		/* ipgre tunnels in collect metadata mode should receive
		 * also ETH_P_TEB traffic.
		 */
		itn = net_generic(net, ipgre_net_id);
		res = __ipgre_rcv(skb, tpi, itn, hdr_len, true);
	}
	return res;
}

static void __gre_xmit(struct sk_buff *skb, struct net_device *dev,
		       const struct iphdr *tnl_params,
		       __be16 proto)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct tnl_ptk_info tpi;

	tpi.flags = tunnel->parms.o_flags;
	tpi.proto = proto;
	tpi.key = tunnel->parms.o_key;
	if (tunnel->parms.o_flags & TUNNEL_SEQ)
		tunnel->o_seqno++;
	tpi.seq = htonl(tunnel->o_seqno);

	/* Push GRE header. */
	gre_build_header(skb, &tpi, tunnel->hlen);

	ip_tunnel_xmit(skb, dev, tnl_params, tnl_params->protocol);
}

static int gre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *unused_tpi)
{
	struct tnl_ptk_info tpi;
	bool csum_err = false;
	int hdr_len;

	hdr_len = gre_parse_header(skb, &tpi, &csum_err, htons(ETH_P_IP), 0);
	if (hdr_len < 0)
		goto drop;

	if (unlikely(tpi.proto == htons(ETH_P_ERSPAN) ||
		     tpi.proto == htons(ETH_P_ERSPAN2))) {
		if (erspan_rcv(skb, &tpi, hdr_len) == PACKET_RCVD)
			return 0;
		goto drop;
	}

	if (ipgre_rcv(skb, &tpi, hdr_len) == PACKET_RCVD)
		return 0;
drop:

	kfree_skb(skb);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#include "gso.h"
/* gre_handle_offloads() has different return type on older kernsl. */
static void gre_nop_fix(struct sk_buff *skb) { }

static void gre_csum_fix(struct sk_buff *skb)
{
	struct gre_base_hdr *greh;
	__be32 *options;
	int gre_offset = skb_transport_offset(skb);

	greh = (struct gre_base_hdr *)skb_transport_header(skb);
	options = ((__be32 *)greh + 1);

	*options = 0;
	*(__sum16 *)options = csum_fold(skb_checksum(skb, gre_offset,
						     skb->len - gre_offset, 0));
}

#define gre_handle_offloads rpl_gre_handle_offloads
static int rpl_gre_handle_offloads(struct sk_buff *skb, bool gre_csum)
{
	int type = gre_csum ? SKB_GSO_GRE_CSUM : SKB_GSO_GRE;
	gso_fix_segment_t fix_segment;

	if (gre_csum)
		fix_segment = gre_csum_fix;
	else
		fix_segment = gre_nop_fix;

	return ovs_iptunnel_handle_offloads(skb, type, fix_segment);
}
#else
static int gre_handle_offloads(struct sk_buff *skb, bool csum)
{
	return iptunnel_handle_offloads(skb, csum,
					csum ? SKB_GSO_GRE_CSUM : SKB_GSO_GRE);
}
#endif

static bool is_gre_gso(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type &
		(SKB_GSO_GRE | SKB_GSO_GRE_CSUM);
}

static void build_header(struct sk_buff *skb, int hdr_len, __be16 flags,
			 __be16 proto, __be32 key, __be32 seq)
{
	struct gre_base_hdr *greh;

	skb_push(skb, hdr_len);

	skb_reset_transport_header(skb);
	greh = (struct gre_base_hdr *)skb->data;
	greh->flags = tnl_flags_to_gre_flags(flags);
	greh->protocol = proto;

	if (flags & (TUNNEL_KEY | TUNNEL_CSUM | TUNNEL_SEQ)) {
		__be32 *ptr = (__be32 *)(((u8 *)greh) + hdr_len - 4);

		if (flags & TUNNEL_SEQ) {
			*ptr = seq;
			ptr--;
		}
		if (flags & TUNNEL_KEY) {
			*ptr = key;
			ptr--;
		}
		if (flags & TUNNEL_CSUM && !is_gre_gso(skb)) {
			*ptr = 0;
			*(__sum16 *)ptr = csum_fold(skb_checksum(skb, 0,
								 skb->len, 0));
		}
	}
	ovs_skb_set_inner_protocol(skb, proto);
}

static struct rtable *gre_get_rt(struct sk_buff *skb,
				 struct net_device *dev,
				 struct flowi4 *fl,
				 const struct ip_tunnel_key *key)
{
	struct net *net = dev_net(dev);

	memset(fl, 0, sizeof(*fl));
	fl->daddr = key->u.ipv4.dst;
	fl->saddr = key->u.ipv4.src;
	fl->flowi4_tos = RT_TOS(key->tos);
	fl->flowi4_mark = skb->mark;
	fl->flowi4_proto = IPPROTO_GRE;

	return ip_route_output_key(net, fl);
}

static struct rtable *prepare_fb_xmit(struct sk_buff *skb,
				      struct net_device *dev,
				      struct flowi4 *fl,
				      int tunnel_hlen)
{
	struct ip_tunnel_info *tun_info;
	const struct ip_tunnel_key *key;
	struct rtable *rt = NULL;
	int min_headroom;
	bool use_cache;
	int err;

	tun_info = skb_tunnel_info(skb);
	key = &tun_info->key;
	use_cache = ip_tunnel_dst_cache_usable(skb, tun_info);

	if (use_cache)
		rt = dst_cache_get_ip4(&tun_info->dst_cache, &fl->saddr);
	if (!rt) {
		rt = gre_get_rt(skb, dev, fl, key);
		if (IS_ERR(rt))
			goto err_free_skb;
		if (use_cache)
			dst_cache_set_ip4(&tun_info->dst_cache, &rt->dst,
					  fl->saddr);
	}

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ tunnel_hlen + sizeof(struct iphdr);
	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);
		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
				       0, GFP_ATOMIC);
		if (unlikely(err))
			goto err_free_rt;
	}
	return rt;

err_free_rt:
	ip_rt_put(rt);
err_free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NULL;
}

netdev_tx_t rpl_gre_fb_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct ip_tunnel_info *tun_info;
	const struct ip_tunnel_key *key;
	struct flowi4 fl;
	struct rtable *rt;
	int min_headroom;
	int tunnel_hlen;
	__be16 df, flags;
	int err;

	tun_info = skb_tunnel_info(skb);
	if (unlikely(!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX) ||
		     ip_tunnel_info_af(tun_info) != AF_INET))
		goto err_free_skb;

	key = &tun_info->key;

	rt = gre_get_rt(skb, dev, &fl, key);
	if (IS_ERR(rt))
		goto err_free_skb;

	tunnel_hlen = ip_gre_calc_hlen(key->tun_flags);

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ tunnel_hlen + sizeof(struct iphdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);
	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);
		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
				       0, GFP_ATOMIC);
		if (unlikely(err))
			goto err_free_rt;
	}

	if (skb_vlan_tag_present(skb)) {
		skb = __vlan_hwaccel_push_inside(skb);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto err_free_rt;
		}
	}

	/* Push Tunnel header. */
	err = gre_handle_offloads(skb, !!(tun_info->key.tun_flags & TUNNEL_CSUM));
	if (err)
		goto err_free_rt;

	flags = tun_info->key.tun_flags & (TUNNEL_CSUM | TUNNEL_KEY);
	build_header(skb, tunnel_hlen, flags, htons(ETH_P_TEB),
		     tunnel_id_to_key(tun_info->key.tun_id), 0);

	df = key->tun_flags & TUNNEL_DONT_FRAGMENT ?  htons(IP_DF) : 0;
	iptunnel_xmit(skb->sk, rt, skb, fl.saddr, key->u.ipv4.dst, IPPROTO_GRE,
		      key->tos, key->ttl, df, false);
	return NETDEV_TX_OK;

err_free_rt:
	ip_rt_put(rt);
err_free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(rpl_gre_fb_xmit);

static void erspan_fb_xmit(struct sk_buff *skb, struct net_device *dev,
			   __be16 proto)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct ip_tunnel_info *tun_info;
	const struct ip_tunnel_key *key;
	struct erspan_metadata *md;
	struct rtable *rt = NULL;
	struct tnl_ptk_info tpi;
	bool truncate = false;
	struct flowi4 fl;
	int tunnel_hlen;
	int version;
	__be16 df;
	int nhoff;
	int thoff;

	tun_info = skb_tunnel_info(skb);
	if (unlikely(!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX) ||
		     ip_tunnel_info_af(tun_info) != AF_INET))
		goto err_free_skb;

	key = &tun_info->key;
	md = ip_tunnel_info_opts(tun_info);
	if (!md)
		goto err_free_rt;

	/* ERSPAN has fixed 8 byte GRE header */
	version = md->version;
	tunnel_hlen = 8 + erspan_hdr_len(version);

	rt = prepare_fb_xmit(skb, dev, &fl, tunnel_hlen);
	if (!rt)
		return;

	if (gre_handle_offloads(skb, false))
		goto err_free_rt;

	if (skb->len > dev->mtu + dev->hard_header_len) {
		pskb_trim(skb, dev->mtu + dev->hard_header_len);
		truncate = true;
	}

	nhoff = skb_network_header(skb) - skb_mac_header(skb);
	if (skb->protocol == htons(ETH_P_IP) &&
	    (ntohs(ip_hdr(skb)->tot_len) > skb->len - nhoff))
		truncate = true;

	thoff = skb_transport_header(skb) - skb_mac_header(skb);
	if (skb->protocol == htons(ETH_P_IPV6) &&
	    (ntohs(ipv6_hdr(skb)->payload_len) > skb->len - thoff))
		truncate = true;

	if (version == 1) {
		erspan_build_header(skb, ntohl(tunnel_id_to_key32(key->tun_id)),
				    ntohl(md->u.index), truncate, true);
		tpi.hdr_len = ERSPAN_V1_MDSIZE;
		tpi.proto = htons(ETH_P_ERSPAN);
	} else if (version == 2) {
		erspan_build_header_v2(skb,
				       ntohl(tunnel_id_to_key32(key->tun_id)),
				       md->u.md2.dir,
				       get_hwid(&md->u.md2),
				       truncate, true);
		tpi.hdr_len = ERSPAN_V2_MDSIZE;
		tpi.proto = htons(ETH_P_ERSPAN2);
	} else {
		goto err_free_rt;
	}

	tpi.flags = TUNNEL_SEQ;
	tpi.key = tunnel_id_to_key32(key->tun_id);
	tpi.seq = htonl(tunnel->o_seqno++);

	gre_build_header(skb, &tpi, 8);

	df = key->tun_flags & TUNNEL_DONT_FRAGMENT ?  htons(IP_DF) : 0;

	iptunnel_xmit(skb->sk, rt, skb, fl.saddr, key->u.ipv4.dst, IPPROTO_GRE,
		      key->tos, key->ttl, df, false);
	return;

err_free_rt:
	ip_rt_put(rt);
err_free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
}

#define GRE_FEATURES	(NETIF_F_SG |		\
			 NETIF_F_FRAGLIST |	\
			 NETIF_F_HIGHDMA |	\
			 NETIF_F_HW_CSUM |	\
			 NETIF_F_NETNS_LOCAL)

static void __gre_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel;
	int t_hlen;

	tunnel = netdev_priv(dev);
	tunnel->tun_hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);
	tunnel->parms.iph.protocol = IPPROTO_GRE;

	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;

	t_hlen = tunnel->hlen + sizeof(struct iphdr);

	dev->features		|= GRE_FEATURES;
	dev->hw_features	|= GRE_FEATURES;

	if (!(tunnel->parms.o_flags & TUNNEL_SEQ)) {
		/* TCP offload with GRE SEQ is not supported, nor
		 * can we support 2 levels of outer headers requiring
		 * an update.
		 */
		if (!(tunnel->parms.o_flags & TUNNEL_CSUM) ||
		    (tunnel->encap.type == TUNNEL_ENCAP_NONE)) {
			dev->features    |= NETIF_F_GSO_SOFTWARE;
			dev->hw_features |= NETIF_F_GSO_SOFTWARE;
		}

		/* Can use a lockless transmit, unless we generate
		 * output sequences
		 */
		dev->features |= NETIF_F_LLTX;
	}
}

static int __gre_rcv(struct sk_buff *skb)
{
	return gre_rcv(skb, NULL);
}

void __gre_err(struct sk_buff *skb, u32 info)
{
	pr_warn("%s: GRE receive error\n", __func__);
}

static const struct gre_protocol ipgre_protocol = {
	.handler     = __gre_rcv,
	.err_handler = __gre_err,
};

static int __net_init ipgre_init_net(struct net *net)
{
	return ip_tunnel_init_net(net, ipgre_net_id, &ipgre_link_ops, NULL);
}

static void __net_exit ipgre_exit_net(struct net *net)
{
	struct ip_tunnel_net *itn = net_generic(net, ipgre_net_id);

	ip_tunnel_delete_net(itn, &ipgre_link_ops);
}

static struct pernet_operations ipgre_net_ops = {
	.init = ipgre_init_net,
	.exit = ipgre_exit_net,
	.id   = &ipgre_net_id,
	.size = sizeof(struct ip_tunnel_net),
};

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int ipgre_tunnel_validate(struct nlattr *tb[], struct nlattr *data[],
				 struct netlink_ext_ack *extack)
#else
static int ipgre_tunnel_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	__be16 flags;

	if (!data)
		return 0;

	flags = 0;
	if (data[IFLA_GRE_IFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_IFLAGS]);
	if (data[IFLA_GRE_OFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_OFLAGS]);
	if (flags & (GRE_VERSION|GRE_ROUTING))
		return -EINVAL;

	return 0;
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int ipgre_tap_validate(struct nlattr *tb[], struct nlattr *data[],
			      struct netlink_ext_ack *extack)
#else
static int ipgre_tap_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	__be32 daddr;

	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	if (!data)
		goto out;

	if (data[IFLA_GRE_REMOTE]) {
		memcpy(&daddr, nla_data(data[IFLA_GRE_REMOTE]), 4);
		if (!daddr)
			return -EINVAL;
	}

out:
#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
	return ipgre_tunnel_validate(tb, data, NULL);
#else
	return ipgre_tunnel_validate(tb, data);
#endif
}

enum {
#ifndef HAVE_IFLA_GRE_ENCAP_DPORT
	IFLA_GRE_ENCAP_TYPE = IFLA_GRE_FLAGS + 1,
	IFLA_GRE_ENCAP_FLAGS,
	IFLA_GRE_ENCAP_SPORT,
	IFLA_GRE_ENCAP_DPORT,
#endif
#ifndef HAVE_IFLA_GRE_COLLECT_METADATA
	IFLA_GRE_COLLECT_METADATA = IFLA_GRE_ENCAP_DPORT + 1,
#endif
#ifndef HAVE_IFLA_GRE_IGNORE_DF
	IFLA_GRE_IGNORE_DF = IFLA_GRE_COLLECT_METADATA + 1,
#endif
#ifndef HAVE_IFLA_GRE_FWMARK
	IFLA_GRE_FWMARK = IFLA_GRE_IGNORE_DF + 1,
#endif
#ifndef HAVE_IFLA_GRE_ERSPAN_INDEX
	IFLA_GRE_ERSPAN_INDEX = IFLA_GRE_FWMARK + 1,
#endif
#ifndef HAVE_IFLA_GRE_ERSPAN_HWID
	IFLA_GRE_ERSPAN_VER = IFLA_GRE_ERSPAN_INDEX + 1,
	IFLA_GRE_ERSPAN_DIR,
	IFLA_GRE_ERSPAN_HWID,
#endif
};

#define RPL_IFLA_GRE_MAX (IFLA_GRE_ERSPAN_HWID + 1)

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int erspan_validate(struct nlattr *tb[], struct nlattr *data[],
			   struct netlink_ext_ack *extack)
#else
static int erspan_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	__be16 flags = 0;
	int ret;

	if (!data)
		return 0;

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
	ret = ipgre_tap_validate(tb, data, NULL);
#else
	ret = ipgre_tap_validate(tb, data);
#endif
	if (ret)
		return ret;

	/* ERSPAN should only have GRE sequence and key flag */
	if (data[IFLA_GRE_OFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_OFLAGS]);
	if (data[IFLA_GRE_IFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_IFLAGS]);
	if (!data[IFLA_GRE_COLLECT_METADATA] &&
	    flags != (GRE_SEQ | GRE_KEY))
		return -EINVAL;

	/* ERSPAN Session ID only has 10-bit. Since we reuse
	 * 32-bit key field as ID, check it's range.
	 */
	if (data[IFLA_GRE_OKEY] &&
	    (ntohl(nla_get_be32(data[IFLA_GRE_OKEY])) & ~ID_MASK))
		return -EINVAL;

	return 0;
}

static int ipgre_netlink_parms(struct net_device *dev,
			       struct nlattr *data[],
			       struct nlattr *tb[],
			       struct ip_tunnel_parm *parms)
{
	struct ip_tunnel *t = netdev_priv(dev);

	memset(parms, 0, sizeof(*parms));

	parms->iph.protocol = IPPROTO_GRE;

	if (!data)
		return 0;

	if (data[IFLA_GRE_LINK])
		parms->link = nla_get_u32(data[IFLA_GRE_LINK]);

	if (data[IFLA_GRE_IFLAGS])
		parms->i_flags = gre_flags_to_tnl_flags(nla_get_be16(data[IFLA_GRE_IFLAGS]));

	if (data[IFLA_GRE_OFLAGS])
		parms->o_flags = gre_flags_to_tnl_flags(nla_get_be16(data[IFLA_GRE_OFLAGS]));

	if (data[IFLA_GRE_IKEY])
		parms->i_key = nla_get_be32(data[IFLA_GRE_IKEY]);

	if (data[IFLA_GRE_OKEY])
		parms->o_key = nla_get_be32(data[IFLA_GRE_OKEY]);

	if (data[IFLA_GRE_LOCAL])
		parms->iph.saddr = nla_get_in_addr(data[IFLA_GRE_LOCAL]);

	if (data[IFLA_GRE_REMOTE])
		parms->iph.daddr = nla_get_in_addr(data[IFLA_GRE_REMOTE]);

	if (data[IFLA_GRE_TTL])
		parms->iph.ttl = nla_get_u8(data[IFLA_GRE_TTL]);

	if (data[IFLA_GRE_TOS])
		parms->iph.tos = nla_get_u8(data[IFLA_GRE_TOS]);

	if (!data[IFLA_GRE_PMTUDISC] || nla_get_u8(data[IFLA_GRE_PMTUDISC])) {
		if (t->ignore_df)
			return -EINVAL;
		parms->iph.frag_off = htons(IP_DF);
	}

	if (data[IFLA_GRE_COLLECT_METADATA]) {
		t->collect_md = true;
		if (dev->type == ARPHRD_IPGRE)
			dev->type = ARPHRD_NONE;
	}

	if (data[IFLA_GRE_IGNORE_DF]) {
		if (nla_get_u8(data[IFLA_GRE_IGNORE_DF])
		  && (parms->iph.frag_off & htons(IP_DF)))
			return -EINVAL;
		t->ignore_df = !!nla_get_u8(data[IFLA_GRE_IGNORE_DF]);
	}

	if (data[IFLA_GRE_ERSPAN_INDEX]) {
		t->index = nla_get_u32(data[IFLA_GRE_ERSPAN_INDEX]);

		if (t->index & ~INDEX_MASK)
			return -EINVAL;
	}

	return 0;
}

static int gre_tap_init(struct net_device *dev)
{
	__gre_tunnel_init(dev);
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	return ip_tunnel_init(dev);
}

static netdev_tx_t gre_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */

	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static netdev_tx_t erspan_xmit(struct sk_buff *skb,
			       struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	bool truncate = false;

	if (tunnel->collect_md) {
		erspan_fb_xmit(skb, dev, skb->protocol);
		return NETDEV_TX_OK;
	}

	if (gre_handle_offloads(skb, false))
		goto free_skb;

	if (skb_cow_head(skb, dev->needed_headroom))
		goto free_skb;

	if (skb->len > dev->mtu + dev->hard_header_len) {
		pskb_trim(skb, dev->mtu + dev->hard_header_len);
		truncate = true;
	}

	/* Push ERSPAN header */
	if (tunnel->erspan_ver == 1)
		erspan_build_header(skb, ntohl(tunnel->parms.o_key),
				    tunnel->index,
				    truncate, true);
	else if (tunnel->erspan_ver == 2)
		erspan_build_header_v2(skb, ntohl(tunnel->parms.o_key),
				       tunnel->dir, tunnel->hwid,
				       truncate, true);
	else
		goto free_skb;

	tunnel->parms.o_flags &= ~TUNNEL_KEY;
	__gre_xmit(skb, dev, &tunnel->parms.iph, htons(ETH_P_ERSPAN));
	return NETDEV_TX_OK;

free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static netdev_tx_t __erspan_fb_xmit(struct sk_buff *skb)
{
	erspan_fb_xmit(skb, skb->dev, skb->protocol);
	return NETDEV_TX_OK;
}

int ovs_gre_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	struct rtable *rt;
	struct flowi4 fl4;

	if (ip_tunnel_info_af(info) != AF_INET)
		return -EINVAL;

	rt = gre_get_rt(skb, dev, &fl4, &info->key);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	ip_rt_put(rt);
	info->key.u.ipv4.src = fl4.saddr;
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_gre_fill_metadata_dst);

static int erspan_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	int t_hlen;

	tunnel->tun_hlen = 8;
	tunnel->parms.iph.protocol = IPPROTO_GRE;
	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen +
		       erspan_hdr_len(tunnel->erspan_ver);
	t_hlen = tunnel->hlen + sizeof(struct iphdr);

	dev->features		|= GRE_FEATURES;
	dev->hw_features	|= GRE_FEATURES;
	dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE;
	netif_keep_dst(dev);

	return ip_tunnel_init(dev);
}

static int ipgre_header(struct sk_buff *skb, struct net_device *dev,
			unsigned short type,
			const void *daddr, const void *saddr, unsigned int len)
{
	struct ip_tunnel *t = netdev_priv(dev);
	struct iphdr *iph;
	struct gre_base_hdr *greh;

	iph = (struct iphdr *)__skb_push(skb, t->hlen + sizeof(*iph));
	greh = (struct gre_base_hdr *)(iph+1);
	greh->flags = gre_tnl_flags_to_gre_flags(t->parms.o_flags);
	greh->protocol = htons(type);

	memcpy(iph, &t->parms.iph, sizeof(struct iphdr));

	/* Set the source hardware address. */
	if (saddr)
		memcpy(&iph->saddr, saddr, 4);
	if (daddr)
		memcpy(&iph->daddr, daddr, 4);
	if (iph->daddr)
		return t->hlen + sizeof(*iph);

	return -(t->hlen + sizeof(*iph));
}

static int ipgre_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const struct iphdr *iph = (const struct iphdr *) skb_mac_header(skb);
	memcpy(haddr, &iph->saddr, 4);
	return 4;
}

static const struct header_ops ipgre_header_ops = {
	.create	= ipgre_header,
	.parse	= ipgre_header_parse,
};

static int ipgre_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;

	__gre_tunnel_init(dev);

	memcpy(dev->dev_addr, &iph->saddr, 4);
	memcpy(dev->broadcast, &iph->daddr, 4);

	dev->flags		= IFF_NOARP;
	netif_keep_dst(dev);
	dev->addr_len		= 4;

	if (!tunnel->collect_md) {
		dev->header_ops = &ipgre_header_ops;
	}

	return ip_tunnel_init(dev);
}

static netdev_tx_t ipgre_xmit(struct sk_buff *skb,
			      struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *tnl_params;

	if (tunnel->collect_md) {
		gre_fb_xmit(skb);
		return NETDEV_TX_OK;
	}

	if (dev->header_ops) {
		/* Need space for new headers */
		if (skb_cow_head(skb, dev->needed_headroom -
				      (tunnel->hlen + sizeof(struct iphdr))))
			goto free_skb;

		tnl_params = (const struct iphdr *)skb->data;

		/* Pull skb since ip_tunnel_xmit() needs skb->data pointing
		 * to gre header.
		 */
		skb_pull(skb, tunnel->hlen + sizeof(struct iphdr));
		skb_reset_mac_header(skb);
	} else {
		if (skb_cow_head(skb, dev->needed_headroom))
			goto free_skb;

		tnl_params = &tunnel->parms.iph;
	}

	if (gre_handle_offloads(skb, !!(tunnel->parms.o_flags & TUNNEL_CSUM)))
		goto free_skb;

	__gre_xmit(skb, dev, tnl_params, skb->protocol);
	return NETDEV_TX_OK;

free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static const struct net_device_ops ipgre_netdev_ops = {
	.ndo_init		= ipgre_tunnel_init,
	.ndo_uninit		= rpl_ip_tunnel_uninit,
	.ndo_start_xmit		= ipgre_xmit,
#ifdef	HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = ip_tunnel_change_mtu,
#else
	.ndo_change_mtu		= ip_tunnel_change_mtu,
#endif
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#ifdef HAVE_GET_LINK_NET
	.ndo_get_iflink		= ip_tunnel_get_iflink,
#endif
};

static const struct net_device_ops gre_tap_netdev_ops = {
	.ndo_init		= gre_tap_init,
	.ndo_uninit		= rpl_ip_tunnel_uninit,
	.ndo_start_xmit		= gre_dev_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef	HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = ip_tunnel_change_mtu,
#else
	.ndo_change_mtu		= ip_tunnel_change_mtu,
#endif
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#ifdef HAVE_NDO_GET_IFLINK
	.ndo_get_iflink		= rpl_ip_tunnel_get_iflink,
#endif
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst  = gre_fill_metadata_dst,
#endif
};

static const struct net_device_ops erspan_netdev_ops = {
	.ndo_init		= erspan_tunnel_init,
	.ndo_uninit		= rpl_ip_tunnel_uninit,
	.ndo_start_xmit		= erspan_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef	HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = ip_tunnel_change_mtu,
#else
	.ndo_change_mtu		= ip_tunnel_change_mtu,
#endif
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#ifdef HAVE_NDO_GET_IFLINK
	.ndo_get_iflink		= rpl_ip_tunnel_get_iflink,
#endif
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst	= gre_fill_metadata_dst,
#endif
};

static void ipgre_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops		= &ipgre_netdev_ops;
	dev->type		= ARPHRD_IPGRE;
	ip_tunnel_setup(dev, ipgre_net_id);
}

static void ipgre_tap_setup(struct net_device *dev)
{
	ether_setup(dev);
#ifdef HAVE_NET_DEVICE_MAX_MTU
	dev->max_mtu = 0;
#endif
	dev->netdev_ops		= &gre_tap_netdev_ops;
	dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE;
	ip_tunnel_setup(dev, gre_tap_net_id);
}

static void erspan_setup(struct net_device *dev)
{
	eth_hw_addr_random(dev);
	ether_setup(dev);
	dev->netdev_ops = &erspan_netdev_ops;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	ip_tunnel_setup(dev, erspan_net_id);
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int ipgre_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
#else
static int ipgre_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
#endif
{
	struct ip_tunnel_parm p;
	int err;

	ipgre_netlink_parms(dev, data, tb, &p);
	err = ip_tunnel_newlink(dev, tb, &p);
	return err;

}

static size_t ipgre_get_size(const struct net_device *dev)
{
	return
		/* IFLA_GRE_LINK */
		nla_total_size(4) +
		/* IFLA_GRE_IFLAGS */
		nla_total_size(2) +
		/* IFLA_GRE_OFLAGS */
		nla_total_size(2) +
		/* IFLA_GRE_IKEY */
		nla_total_size(4) +
		/* IFLA_GRE_OKEY */
		nla_total_size(4) +
		/* IFLA_GRE_LOCAL */
		nla_total_size(4) +
		/* IFLA_GRE_REMOTE */
		nla_total_size(4) +
		/* IFLA_GRE_TTL */
		nla_total_size(1) +
		/* IFLA_GRE_TOS */
		nla_total_size(1) +
		/* IFLA_GRE_PMTUDISC */
		nla_total_size(1) +
		/* IFLA_GRE_ENCAP_TYPE */
		nla_total_size(2) +
		/* IFLA_GRE_ENCAP_FLAGS */
		nla_total_size(2) +
		/* IFLA_GRE_ENCAP_SPORT */
		nla_total_size(2) +
		/* IFLA_GRE_ENCAP_DPORT */
		nla_total_size(2) +
		/* IFLA_GRE_COLLECT_METADATA */
		nla_total_size(0) +
		/* IFLA_GRE_ERSPAN_INDEX */
		nla_total_size(4) +
		/* IFLA_GRE_ERSPAN_VER */
		nla_total_size(1) +
		/* IFLA_GRE_ERSPAN_DIR */
		nla_total_size(1) +
		/* IFLA_GRE_ERSPAN_HWID */
		nla_total_size(2) +
		0;
}

static int ipgre_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ip_tunnel *t = netdev_priv(dev);
	struct ip_tunnel_parm *p = &t->parms;

	if (nla_put_u32(skb, IFLA_GRE_LINK, p->link) ||
	    nla_put_be16(skb, IFLA_GRE_IFLAGS, tnl_flags_to_gre_flags(p->i_flags)) ||
	    nla_put_be16(skb, IFLA_GRE_OFLAGS, tnl_flags_to_gre_flags(p->o_flags)) ||
	    nla_put_be32(skb, IFLA_GRE_IKEY, p->i_key) ||
	    nla_put_be32(skb, IFLA_GRE_OKEY, p->o_key) ||
	    nla_put_in_addr(skb, IFLA_GRE_LOCAL, p->iph.saddr) ||
	    nla_put_in_addr(skb, IFLA_GRE_REMOTE, p->iph.daddr) ||
	    nla_put_u8(skb, IFLA_GRE_TTL, p->iph.ttl) ||
	    nla_put_u8(skb, IFLA_GRE_TOS, p->iph.tos) ||
	    nla_put_u8(skb, IFLA_GRE_PMTUDISC,
		       !!(p->iph.frag_off & htons(IP_DF))))
		goto nla_put_failure;

	if (nla_put_u8(skb, IFLA_GRE_ERSPAN_VER, t->erspan_ver))
		goto nla_put_failure;

	if (t->erspan_ver == 1) {
 		if (nla_put_u32(skb, IFLA_GRE_ERSPAN_INDEX, t->index))
 			goto nla_put_failure;
	} else if (t->erspan_ver == 2) {
		if (nla_put_u8(skb, IFLA_GRE_ERSPAN_DIR, t->dir))
			goto nla_put_failure;
		if (nla_put_u16(skb, IFLA_GRE_ERSPAN_HWID, t->hwid))
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static const struct nla_policy ipgre_policy[RPL_IFLA_GRE_MAX + 1] = {
	[IFLA_GRE_LINK]		= { .type = NLA_U32 },
	[IFLA_GRE_IFLAGS]	= { .type = NLA_U16 },
	[IFLA_GRE_OFLAGS]	= { .type = NLA_U16 },
	[IFLA_GRE_IKEY]		= { .type = NLA_U32 },
	[IFLA_GRE_OKEY]		= { .type = NLA_U32 },
	[IFLA_GRE_LOCAL]	= { .len = FIELD_SIZEOF(struct iphdr, saddr) },
	[IFLA_GRE_REMOTE]	= { .len = FIELD_SIZEOF(struct iphdr, daddr) },
	[IFLA_GRE_TTL]		= { .type = NLA_U8 },
	[IFLA_GRE_TOS]		= { .type = NLA_U8 },
	[IFLA_GRE_PMTUDISC]	= { .type = NLA_U8 },
	[IFLA_GRE_ERSPAN_INDEX]	= { .type = NLA_U32 },
	[IFLA_GRE_ERSPAN_VER]	= { .type = NLA_U8 },
	[IFLA_GRE_ERSPAN_DIR]	= { .type = NLA_U8 },
	[IFLA_GRE_ERSPAN_HWID]	= { .type = NLA_U16 },
};

static struct rtnl_link_ops ipgre_link_ops __read_mostly = {
	.kind		= "gre",
	.maxtype	= RPL_IFLA_GRE_MAX,
	.policy		= ipgre_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipgre_tunnel_setup,
	.validate	= ipgre_tunnel_validate,
	.newlink	= ipgre_newlink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipgre_get_size,
	.fill_info	= ipgre_fill_info,
#ifdef HAVE_GET_LINK_NET
	.get_link_net	= ip_tunnel_get_link_net,
#endif
};

static struct rtnl_link_ops ipgre_tap_ops __read_mostly = {
	.kind		= "ovs_gretap",
	.maxtype	= RPL_IFLA_GRE_MAX,
	.policy		= ipgre_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipgre_tap_setup,
	.validate	= ipgre_tap_validate,
	.newlink	= ipgre_newlink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipgre_get_size,
	.fill_info	= ipgre_fill_info,
#ifdef HAVE_GET_LINK_NET
	.get_link_net	= ip_tunnel_get_link_net,
#endif
};

static struct rtnl_link_ops erspan_link_ops __read_mostly = {
	.kind		= "erspan",
	.maxtype	= RPL_IFLA_GRE_MAX,
	.policy		= ipgre_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= erspan_setup,
	.validate	= erspan_validate,
	.newlink	= ipgre_newlink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipgre_get_size,
	.fill_info	= ipgre_fill_info,
#ifdef HAVE_GET_LINK_NET
	.get_link_net	= ip_tunnel_get_link_net,
#endif
};

struct net_device *rpl_gretap_fb_dev_create(struct net *net, const char *name,
					u8 name_assign_type)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	LIST_HEAD(list_kill);
	struct ip_tunnel *t;
	int err;

	memset(&tb, 0, sizeof(tb));

	dev = rtnl_create_link(net, (char *)name, name_assign_type,
			       &ipgre_tap_ops, tb);
	if (IS_ERR(dev))
		return dev;

	t = netdev_priv(dev);
	t->collect_md = true;
	/* Configure flow based GRE device. */
#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
	err = ipgre_newlink(net, dev, tb, NULL, NULL);
#else
	err = ipgre_newlink(net, dev, tb, NULL);
#endif
	if (err < 0) {
		free_netdev(dev);
		return ERR_PTR(err);
	}

	/* openvswitch users expect packet sizes to be unrestricted,
	 * so set the largest MTU we can.
	 */
	err = __ip_tunnel_change_mtu(dev, IP_MAX_MTU, false);
	if (err)
		goto out;

	return dev;
out:
	ip_tunnel_dellink(dev, &list_kill);
	unregister_netdevice_many(&list_kill);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rpl_gretap_fb_dev_create);

static int __net_init erspan_init_net(struct net *net)
{
	return ip_tunnel_init_net(net, erspan_net_id,
				  &erspan_link_ops, NULL);
}

static void __net_exit erspan_exit_net(struct net *net)
{
	struct ip_tunnel_net *itn = net_generic(net, erspan_net_id);

	ip_tunnel_delete_net(itn, &erspan_link_ops);
}

static struct pernet_operations erspan_net_ops = {
	.init = erspan_init_net,
	.exit = erspan_exit_net,
	.id   = &erspan_net_id,
	.size = sizeof(struct ip_tunnel_net),
};

static int __net_init ipgre_tap_init_net(struct net *net)
{
	return ip_tunnel_init_net(net, gre_tap_net_id, &ipgre_tap_ops, "gretap0");
}

static void __net_exit ipgre_tap_exit_net(struct net *net)
{
	struct ip_tunnel_net *itn = net_generic(net, gre_tap_net_id);

	ip_tunnel_delete_net(itn, &ipgre_tap_ops);
}

static struct pernet_operations ipgre_tap_net_ops = {
	.init = ipgre_tap_init_net,
	.exit = ipgre_tap_exit_net,
	.id   = &gre_tap_net_id,
	.size = sizeof(struct ip_tunnel_net),
};

static struct net_device *erspan_fb_dev_create(struct net *net,
					       const char *name,
					       u8 name_assign_type)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	LIST_HEAD(list_kill);
	struct ip_tunnel *t;
	int err;

	memset(&tb, 0, sizeof(tb));

	dev = rtnl_create_link(net, (char *)name, name_assign_type,
			       &erspan_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	t = netdev_priv(dev);
	t->collect_md = true;
	/* Configure flow based GRE device. */
#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
	err = ipgre_newlink(net, dev, tb, NULL, NULL);
#else
	err = ipgre_newlink(net, dev, tb, NULL);
#endif
	if (err < 0) {
		free_netdev(dev);
		return ERR_PTR(err);
	}

	/* openvswitch users expect packet sizes to be unrestricted,
	 * so set the largest MTU we can.
	 */
	err = __ip_tunnel_change_mtu(dev, IP_MAX_MTU, false);
	if (err)
		goto out;

	return dev;
out:
	ip_tunnel_dellink(dev, &list_kill);
	unregister_netdevice_many(&list_kill);
	return ERR_PTR(err);
}

static struct vport_ops ovs_erspan_vport_ops;

static struct vport *erspan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct net_device *dev;
	struct vport *vport;
	int err;

	vport = ovs_vport_alloc(0, &ovs_erspan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	rtnl_lock();
	dev = erspan_fb_dev_create(net, parms->name, NET_NAME_USER);
	if (IS_ERR(dev)) {
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_CAST(dev);
	}

	err = dev_change_flags(dev, dev->flags | IFF_UP);
	if (err < 0) {
		rtnl_delete_link(dev);
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_PTR(err);
	}

	rtnl_unlock();
	return vport;
}

static struct vport *erspan_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = erspan_tnl_create(parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static struct vport_ops ovs_erspan_vport_ops = {
	.type		= OVS_VPORT_TYPE_ERSPAN,
	.create		= erspan_create,
	.send		= __erspan_fb_xmit,
#ifndef USE_UPSTREAM_TUNNEL
	.fill_metadata_dst = gre_fill_metadata_dst,
#endif
	.destroy	= ovs_netdev_tunnel_destroy,
};

static struct vport_ops ovs_ipgre_vport_ops;

static struct vport *ipgre_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct net_device *dev;
	struct vport *vport;
	int err;

	vport = ovs_vport_alloc(0, &ovs_ipgre_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	rtnl_lock();
	dev = gretap_fb_dev_create(net, parms->name, NET_NAME_USER);
	if (IS_ERR(dev)) {
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_CAST(dev);
	}

	err = dev_change_flags(dev, dev->flags | IFF_UP);
	if (err < 0) {
		rtnl_delete_link(dev);
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_PTR(err);
	}

	rtnl_unlock();
	return vport;
}

static struct vport *ipgre_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ipgre_tnl_create(parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static struct vport_ops ovs_ipgre_vport_ops = {
	.type		= OVS_VPORT_TYPE_GRE,
	.create		= ipgre_create,
	.send		= gre_fb_xmit,
#ifndef USE_UPSTREAM_TUNNEL
	.fill_metadata_dst = gre_fill_metadata_dst,
#endif
	.destroy	= ovs_netdev_tunnel_destroy,
};

int rpl_ipgre_init(void)
{
	int err;

	err = register_pernet_device(&ipgre_tap_net_ops);
	if (err < 0) {
		if (err == -EEXIST)
			goto ip_gre_loaded;
		else
			goto pnet_tap_failed;
	}

	err = register_pernet_device(&erspan_net_ops);
	if (err < 0) {
		if (err == -EEXIST)
			goto ip_gre_loaded;
		else
			goto pnet_erspan_failed;
	}

	err = register_pernet_device(&ipgre_net_ops);
	if (err < 0) {
		if (err == -EEXIST)
			goto ip_gre_loaded;
		else
			goto pnet_ipgre_failed;
	}

	err = gre_add_protocol(&ipgre_protocol, GREPROTO_CISCO);
	if (err < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		if (err == -EBUSY) {
			goto ip_gre_loaded;
		} else {
			goto add_proto_failed;
		}
	}

	pr_info("GRE over IPv4 tunneling driver\n");
	ovs_vport_ops_register(&ovs_ipgre_vport_ops);
	ovs_vport_ops_register(&ovs_erspan_vport_ops);
	return 0;

ip_gre_loaded:
	/* Since GRE only allows single receiver to be registerd,
	 * we skip here so only gre transmit works, see:
	 *
	 * commit 9f57c67c379d88a10e8ad676426fee5ae7341b14
	 * Author: Pravin B Shelar <pshelar@nicira.com>
	 * Date:   Fri Aug 7 23:51:52 2015 -0700
	 *     gre: Remove support for sharing GRE protocol hook
	 *
	 * OVS GRE receive part is disabled.
	 */
	pr_info("GRE TX only over IPv4 tunneling driver\n");
	ip_gre_loaded = true;
	ovs_vport_ops_register(&ovs_ipgre_vport_ops);
	ovs_vport_ops_register(&ovs_erspan_vport_ops);
	return 0;

add_proto_failed:
	unregister_pernet_device(&ipgre_net_ops);
pnet_ipgre_failed:
	unregister_pernet_device(&erspan_net_ops);
pnet_erspan_failed:
	unregister_pernet_device(&ipgre_tap_net_ops);
pnet_tap_failed:
	pr_err("Error while initializing GRE %d\n", err);
	return err;
}

void rpl_ipgre_fini(void)
{
	ovs_vport_ops_unregister(&ovs_erspan_vport_ops);
	ovs_vport_ops_unregister(&ovs_ipgre_vport_ops);

	if (!ip_gre_loaded) {
		gre_del_protocol(&ipgre_protocol, GREPROTO_CISCO);
		unregister_pernet_device(&ipgre_net_ops);
		unregister_pernet_device(&erspan_net_ops);
		unregister_pernet_device(&ipgre_tap_net_ops);
	}
}

#endif
