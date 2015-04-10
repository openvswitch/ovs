/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/stt.h>
#include <net/udp.h>

#include "datapath.h"
#include "vport.h"

#ifdef OVS_STT
static struct vport_ops ovs_stt_vport_ops;

/**
 * struct stt_port
 * @stt_sock: The socket created for this port number.
 * @name: vport name.
 */
struct stt_port {
	struct stt_sock *stt_sock;
	char name[IFNAMSIZ];
};

static inline struct stt_port *stt_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static void stt_rcv(struct stt_sock *stt_sock, struct sk_buff *skb)
{
	struct vport *vport = stt_sock->rcv_data;
	struct stthdr *stth = stt_hdr(skb);
	struct ovs_tunnel_info tun_info;
	struct sk_buff *next;

	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb),
			       tcp_hdr(skb)->source, tcp_hdr(skb)->dest,
			       get_unaligned(&stth->key),
			       TUNNEL_KEY | TUNNEL_CSUM,
			       NULL, 0);
	do {
		next = skb->next;
		skb->next = NULL;
		ovs_vport_receive(vport, skb, &tun_info);
	} while ((skb = next));
}

static int stt_tnl_get_options(const struct vport *vport,
			       struct sk_buff *skb)
{
	struct stt_port *stt_port = stt_vport(vport);
	struct inet_sock *sk = inet_sk(stt_port->stt_sock->sock->sk);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(sk->inet_sport)))
		return -EMSGSIZE;
	return 0;
}

static void stt_tnl_destroy(struct vport *vport)
{
	struct stt_port *stt_port = stt_vport(vport);

	stt_sock_release(stt_port->stt_sock);
	ovs_vport_deferred_free(vport);
}

static struct vport *stt_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct stt_port *stt_port;
	struct stt_sock *stt_sock;
	struct vport *vport;
	struct nlattr *a;
	int err;
	u16 dst_port;

	if (!options) {
		err = -EINVAL;
		goto error;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct stt_port),
				&ovs_stt_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	stt_port = stt_vport(vport);
	strncpy(stt_port->name, parms->name, IFNAMSIZ);

	stt_sock = stt_sock_add(net, htons(dst_port), stt_rcv, vport);
	if (IS_ERR(stt_sock)) {
		ovs_vport_free(vport);
		return ERR_CAST(stt_sock);
	}
	stt_port->stt_sock = stt_sock;

	return vport;
error:
	return ERR_PTR(err);
}

static int stt_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct stt_port *stt_port = stt_vport(vport);
	__be16 dport = inet_sk(stt_port->stt_sock->sock->sk)->inet_sport;
	const struct ovs_key_ipv4_tunnel *tun_key;
	const struct ovs_tunnel_info *tun_info;
	struct rtable *rt;
	__be16 sport;
	__be32 saddr;
	__be16 df;
	int err;

	tun_info = OVS_CB(skb)->egress_tun_info;
	if (unlikely(!tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &tun_info->tunnel;
	/* Route lookup */
	saddr = tun_key->ipv4_src;
	rt = find_route(ovs_dp_get_net(vport->dp),
			&saddr, tun_key->ipv4_dst,
			IPPROTO_TCP, tun_key->ipv4_tos,
			skb->mark);

	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);
	skb->ignore_df = 1;

	return stt_xmit_skb(skb, rt, saddr, tun_key->ipv4_dst,
			    tun_key->ipv4_tos, tun_key->ipv4_ttl,
			    df, sport, dport, tun_key->tun_id);
error:
	kfree_skb(skb);
	return err;
}

static const char *stt_tnl_get_name(const struct vport *vport)
{
	return stt_vport(vport)->name;
}

static int stt_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				   struct ovs_tunnel_info *egress_tun_info)
{
	struct stt_port *stt_port = stt_vport(vport);
	struct net *net = ovs_dp_get_net(vport->dp);
	__be16 dport = inet_sk(stt_port->stt_sock->sock->sk)->inet_sport;
	__be16 sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);

	/* Get tp_src and tp_dst, refert to stt_build_header().
	 */
	return ovs_tunnel_get_egress_info(egress_tun_info,
					  ovs_dp_get_net(vport->dp),
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark, sport, dport);
}

static struct vport_ops ovs_stt_vport_ops = {
	.type			= OVS_VPORT_TYPE_STT,
	.create			= stt_tnl_create,
	.destroy		= stt_tnl_destroy,
	.get_name		= stt_tnl_get_name,
	.get_options		= stt_tnl_get_options,
	.send			= stt_tnl_send,
	.get_egress_tun_info	= stt_get_egress_tun_info,
	.owner			= THIS_MODULE,
};

static int __init ovs_stt_tnl_init(void)
{
	int err;

	err = stt_init_module();
	if (err)
		return err;
	err = ovs_vport_ops_register(&ovs_stt_vport_ops);
	if (err)
		stt_cleanup_module();
	return err;
}

static void __exit ovs_stt_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_stt_vport_ops);
	stt_cleanup_module();
}

module_init(ovs_stt_tnl_init);
module_exit(ovs_stt_tnl_exit);

MODULE_DESCRIPTION("OVS: STT switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-106");
#endif
