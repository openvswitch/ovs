/*
 * Geneve: Generic Network Virtualization Encapsulation
 *
 * Copyright (c) 2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>
#include <linux/mutex.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/geneve.h>
#include <net/protocol.h>
#include <net/udp_tunnel.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/ip6_checksum.h>
#endif

#include "compat.h"
#include "gso.h"

static inline struct genevehdr *geneve_hdr(const struct sk_buff *skb)
{
	return (struct genevehdr *)(udp_hdr(skb) + 1);
}

static void geneve_build_header(struct genevehdr *geneveh,
				__be16 tun_flags, u8 vni[3],
				u8 options_len, u8 *options)
{
	geneveh->ver = GENEVE_VER;
	geneveh->opt_len = options_len / 4;
	geneveh->oam = !!(tun_flags & TUNNEL_OAM);
	geneveh->critical = !!(tun_flags & TUNNEL_CRIT_OPT);
	geneveh->rsvd1 = 0;
	memcpy(geneveh->vni, vni, 3);
	geneveh->proto_type = htons(ETH_P_TEB);
	geneveh->rsvd2 = 0;

	memcpy(geneveh->options, options, options_len);
}

/* Transmit a fully formatted Geneve frame.
 *
 * When calling this function. The skb->data should point
 * to the geneve header which is fully formed.
 *
 * This function will add other UDP tunnel headers.
 */
int rpl_geneve_xmit_skb(struct geneve_sock *gs, struct rtable *rt,
		        struct sk_buff *skb, __be32 src, __be32 dst, __u8 tos,
		        __u8 ttl, __be16 df, __be16 src_port, __be16 dst_port,
		        __be16 tun_flags, u8 vni[3], u8 opt_len, u8 *opt,
		        bool csum, bool xnet)
{
	struct genevehdr *gnvh;
	int min_headroom;
	int err;

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ GENEVE_BASE_HLEN + opt_len + sizeof(struct iphdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}

	skb = vlan_hwaccel_push_inside(skb);
	if (unlikely(!skb))
		return -ENOMEM;

	skb = udp_tunnel_handle_offloads(skb, csum, (opt_len == 0));
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	gnvh = (struct genevehdr *)__skb_push(skb, sizeof(*gnvh) + opt_len);
	geneve_build_header(gnvh, tun_flags, vni, opt_len, opt);

	ovs_skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	return udp_tunnel_xmit_skb(rt, skb, src, dst,
				   tos, ttl, df, src_port, dst_port, xnet,
				   !csum);
}
EXPORT_SYMBOL_GPL(rpl_geneve_xmit_skb);

/* Callback from net/ipv4/udp.c to receive packets */
static int geneve_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct genevehdr *geneveh;
	struct geneve_sock *gs;
	int opts_len;

	/* Need Geneve and inner Ethernet header to be present */
	if (unlikely(!pskb_may_pull(skb, GENEVE_BASE_HLEN)))
		goto error;

	/* Return packets with reserved bits set */
	geneveh = geneve_hdr(skb);

	if (unlikely(geneveh->ver != GENEVE_VER))
		goto error;

	if (unlikely(geneveh->proto_type != htons(ETH_P_TEB)))
		goto error;

	opts_len = geneveh->opt_len * 4;
	if (iptunnel_pull_header(skb, GENEVE_BASE_HLEN + opts_len,
				 htons(ETH_P_TEB)))
		goto drop;

	gs = rcu_dereference_sk_user_data(sk);
	if (!gs)
		goto drop;

	gs->rcv(gs, skb);
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;

error:
	/* Let the UDP layer deal with the skb */
	return 1;
}

static struct socket *geneve_create_sock(struct net *net, bool ipv6,
					 __be16 port)
{
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	if (ipv6) {
		udp_conf.family = AF_INET6;
	} else {
		udp_conf.family = AF_INET;
		udp_conf.local_ip.s_addr = htonl(INADDR_ANY);
	}

	udp_conf.local_udp_port = port;

	/* Open UDP socket */
	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	return sock;
}

/* Create new listen socket if needed */
static struct geneve_sock *geneve_socket_create(struct net *net, __be16 port,
						geneve_rcv_t *rcv, void *data,
						bool ipv6)
{
	struct geneve_sock *gs;
	struct socket *sock;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	gs = kzalloc(sizeof(*gs), GFP_KERNEL);
	if (!gs)
		return ERR_PTR(-ENOMEM);

	sock = geneve_create_sock(net, ipv6, port);
	if (IS_ERR(sock)) {
		kfree(gs);
		return ERR_CAST(sock);
	}

	gs->sock = sock;
	gs->rcv = rcv;
	gs->rcv_data = data;

	/* Mark socket as an encapsulation socket */
	tunnel_cfg.sk_user_data = gs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = geneve_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return gs;
}

struct geneve_sock *rpl_geneve_sock_add(struct net *net, __be16 port,
				        geneve_rcv_t *rcv, void *data,
				        bool no_share, bool ipv6)
{
	return geneve_socket_create(net, port, rcv, data, ipv6);
}
EXPORT_SYMBOL_GPL(rpl_geneve_sock_add);

static void rcu_free_gs(struct rcu_head *rcu)
{
	struct geneve_sock *gs = container_of(rcu, struct geneve_sock, rcu);

	kfree(gs);
}

void rpl_geneve_sock_release(struct geneve_sock *gs)
{
	udp_tunnel_sock_release(gs->sock);
	call_rcu(&gs->rcu, rcu_free_gs);
}
EXPORT_SYMBOL_GPL(rpl_geneve_sock_release);

#endif /* kernel < 4.0 */
