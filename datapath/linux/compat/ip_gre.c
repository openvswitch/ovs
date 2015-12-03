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

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
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

#ifndef HAVE_METADATA_DST
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#endif

#include "gso.h"
#include "vport-netdev.h"

static int gre_tap_net_id __read_mostly;

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

#define tnl_flags_to_gre_flags rpl_tnl_flags_to_gre_flags
static __be16 tnl_flags_to_gre_flags(__be16 tflags)
{
	__be16 flags = 0;

	if (tflags & TUNNEL_CSUM)
		flags |= GRE_CSUM;
	if (tflags & TUNNEL_ROUTING)
		flags |= GRE_ROUTING;
	if (tflags & TUNNEL_KEY)
		flags |= GRE_KEY;
	if (tflags & TUNNEL_SEQ)
		flags |= GRE_SEQ;
	if (tflags & TUNNEL_STRICT)
		flags |= GRE_STRICT;
	if (tflags & TUNNEL_REC)
		flags |= GRE_REC;
	if (tflags & TUNNEL_VERSION)
		flags |= GRE_VERSION;

	return flags;
}

static __be64 key_to_tunnel_id(__be32 key)
{
#ifdef __BIG_ENDIAN
	return (__force __be64)((__force u32)key);
#else
	return (__force __be64)((__force u64)key << 32);
#endif
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

static int ipgre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *tpi)
{
	struct net *net = dev_net(skb->dev);
	struct metadata_dst tun_dst;
	struct ip_tunnel_net *itn;
	const struct iphdr *iph;
	struct ip_tunnel *tunnel;

	if (tpi->proto != htons(ETH_P_TEB))
		return PACKET_REJECT;

	itn = net_generic(net, gre_tap_net_id);

	iph = ip_hdr(skb);
	tunnel = rcu_dereference(itn->collect_md_tun);
	if (tunnel) {
		__be16 flags;
		__be64 tun_id;
		int err;


		skb_pop_mac_header(skb);
		flags = tpi->flags & (TUNNEL_CSUM | TUNNEL_KEY);
		tun_id = key_to_tunnel_id(tpi->key);
		ovs_ip_tun_rx_dst(&tun_dst.u.tun_info, skb, flags, tun_id, 0);

		skb_reset_network_header(skb);
		err = IP_ECN_decapsulate(iph, skb);
		if (unlikely(err)) {
			if (err > 1) {
				++tunnel->dev->stats.rx_frame_errors;
				++tunnel->dev->stats.rx_errors;
				return PACKET_REJECT;
			}
		}

		ovs_ip_tunnel_rcv(tunnel->dev, skb, &tun_dst);
		return PACKET_RCVD;
	}
	return PACKET_REJECT;
}

static int gre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *tpi)
{
	if (ipgre_rcv(skb, tpi) == PACKET_RCVD)
		return 0;

	kfree_skb(skb);
	return 0;
}

#ifndef HAVE_GRE_HANDLE_OFFLOADS
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

static bool is_gre_gso(struct sk_buff *skb)
{
	return skb_is_gso(skb);
}

static struct sk_buff *rpl_gre_handle_offloads(struct sk_buff *skb, bool gre_csum)
{
	int type = gre_csum ? SKB_GSO_GRE_CSUM : SKB_GSO_GRE;
	gso_fix_segment_t fix_segment;

	if (gre_csum)
		fix_segment = gre_csum_fix;
	else
		fix_segment = gre_nop_fix;

	return ovs_iptunnel_handle_offloads(skb, gre_csum, type, fix_segment);
}
#else

static bool is_gre_gso(struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type &
		(SKB_GSO_GRE | SKB_GSO_GRE_CSUM);
}

static struct sk_buff *rpl_gre_handle_offloads(struct sk_buff *skb, bool gre_csum)
{
	if (skb_is_gso(skb) && skb_is_encapsulated(skb)) {
		kfree_skb(skb);
		return ERR_PTR(-ENOSYS);
	}
#undef gre_handle_offloads
	return gre_handle_offloads(skb, gre_csum);
}
#endif

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


netdev_tx_t rpl_gre_fb_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
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
	memset(&fl, 0, sizeof(fl));
	fl.daddr = key->u.ipv4.dst;
	fl.saddr = key->u.ipv4.src;
	fl.flowi4_tos = RT_TOS(key->tos);
	fl.flowi4_mark = skb->mark;
	fl.flowi4_proto = IPPROTO_GRE;

	rt = ip_route_output_key(net, &fl);
	if (IS_ERR(rt))
		goto err_free_skb;

	tunnel_hlen = ip_gre_calc_hlen(key->tun_flags);

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
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

	skb = vlan_hwaccel_push_inside(skb);
	if (unlikely(!skb)) {
		err = -ENOMEM;
		goto err_free_rt;
	}

	/* Push Tunnel header. */
	skb = rpl_gre_handle_offloads(skb, !!(tun_info->key.tun_flags & TUNNEL_CSUM));
	if (IS_ERR(skb)) {
		skb = NULL;
		goto err_free_rt;
	}

	flags = tun_info->key.tun_flags & (TUNNEL_CSUM | TUNNEL_KEY);
	build_header(skb, tunnel_hlen, flags, htons(ETH_P_TEB),
		     tunnel_id_to_key(tun_info->key.tun_id), 0);

	df = key->tun_flags & TUNNEL_DONT_FRAGMENT ?  htons(IP_DF) : 0;
	err = iptunnel_xmit(skb->sk, rt, skb, fl.saddr,
			    key->u.ipv4.dst, IPPROTO_GRE,
			    key->tos, key->ttl, df, false);
	iptunnel_xmit_stats(err, &dev->stats, (struct pcpu_sw_netstats __percpu *)dev->tstats);
	return NETDEV_TX_OK;

err_free_rt:
	ip_rt_put(rt);
err_free_skb:
	kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(rpl_gre_fb_xmit);

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
	tunnel->parms.iph.protocol = IPPROTO_GRE;
	tunnel->tun_hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);

	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;

	t_hlen = tunnel->hlen + sizeof(struct iphdr);

	dev->needed_headroom	= LL_MAX_HEADER + t_hlen + 4;
	dev->mtu		= ETH_DATA_LEN - t_hlen - 4;

	dev->features		|= GRE_FEATURES;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	dev->hw_features	|= GRE_FEATURES;
#endif

	if (!(tunnel->parms.o_flags & TUNNEL_SEQ)) {
		/* TCP offload with GRE SEQ is not supported. */
		dev->features    |= NETIF_F_GSO_SOFTWARE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
		dev->hw_features |= NETIF_F_GSO_SOFTWARE;
#endif
		/* Can use a lockless transmit, unless we generate
		 * output sequences
		 */
		dev->features |= NETIF_F_LLTX;
	}
}

/* Called with rcu_read_lock and BH disabled. */
static int gre_err(struct sk_buff *skb, u32 info,
		   const struct tnl_ptk_info *tpi)
{
	return PACKET_REJECT;
}

static struct gre_cisco_protocol ipgre_protocol = {
	.handler        = gre_rcv,
	.err_handler    = gre_err,
	.priority       = 1,
};

static int ipgre_tunnel_validate(struct nlattr *tb[], struct nlattr *data[])
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

static int ipgre_tap_validate(struct nlattr *tb[], struct nlattr *data[])
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
	return ipgre_tunnel_validate(tb, data);
}

static void ipgre_netlink_parms(struct net_device *dev,
				struct nlattr *data[],
				struct nlattr *tb[],
				struct ip_tunnel_parm *parms)
{
	memset(parms, 0, sizeof(*parms));

	parms->iph.protocol = IPPROTO_GRE;
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

static const struct net_device_ops gre_tap_netdev_ops = {
	.ndo_init		= gre_tap_init,
	.ndo_uninit		= ip_tunnel_uninit,
	.ndo_start_xmit		= gre_dev_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= ip_tunnel_change_mtu,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#endif
#ifdef HAVE_NDO_GET_IFLINK
	.ndo_get_iflink		= ip_tunnel_get_iflink,
#endif
};

static void ipgre_tap_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops		= &gre_tap_netdev_ops;
	dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE;
	ip_tunnel_setup(dev, gre_tap_net_id);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
static int ipgre_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
#else
static int ipgre_newlink(struct net_device *dev,
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

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static const struct nla_policy ipgre_policy[IFLA_GRE_MAX + 1] = {
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
};

static struct rtnl_link_ops ipgre_tap_ops __read_mostly = {
	.kind		= "ovs_gretap",
	.maxtype	= IFLA_GRE_MAX,
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

struct net_device *rpl_gretap_fb_dev_create(struct net *net, const char *name,
					u8 name_assign_type)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	err = ipgre_newlink(net, dev, tb, NULL);
#else
	err = ipgre_newlink(dev, tb, NULL);
#endif
	if (err < 0)
		goto out;
	return dev;
out:
	free_netdev(dev);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rpl_gretap_fb_dev_create);

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

DEFINE_COMPAT_PNET_REG_FUNC(device);

int rpl_ipgre_init(void)
{
	int err;

	err = register_pernet_device(&ipgre_tap_net_ops);
	if (err < 0)
		goto pnet_tap_faied;

	err = gre_cisco_register(&ipgre_protocol);
	if (err < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		goto add_proto_failed;
	}

	err = rtnl_link_register(&ipgre_tap_ops);
	if (err < 0)
		goto tap_ops_failed;

	pr_info("GRE over IPv4 tunneling driver\n");
	return 0;

tap_ops_failed:
	gre_cisco_unregister(&ipgre_protocol);
add_proto_failed:
	unregister_pernet_device(&ipgre_tap_net_ops);
pnet_tap_faied:
	return err;
}

void rpl_ipgre_fini(void)
{
	rtnl_link_unregister(&ipgre_tap_ops);
	gre_cisco_unregister(&ipgre_protocol);
	unregister_pernet_device(&ipgre_tap_net_ops);
}

#endif
