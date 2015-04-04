/*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
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

#include <linux/version.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"

/*
 *  LISP encapsulation header:
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |N|L|E|V|I|flags|            Nonce/Map-Version                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Instance ID/Locator Status Bits               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * struct lisphdr - LISP header
 * @nonce_present: Flag indicating the presence of a 24 bit nonce value.
 * @locator_status_bits_present: Flag indicating the presence of Locator Status
 *                               Bits (LSB).
 * @solicit_echo_nonce: Flag indicating the use of the echo noncing mechanism.
 * @map_version_present: Flag indicating the use of mapping versioning.
 * @instance_id_present: Flag indicating the presence of a 24 bit Instance ID.
 * @reserved_flags: 3 bits reserved for future flags.
 * @nonce: 24 bit nonce value.
 * @map_version: 24 bit mapping version.
 * @locator_status_bits: Locator Status Bits: 32 bits when instance_id_present
 *                       is not set, 8 bits when it is.
 * @instance_id: 24 bit Instance ID
 */
struct lisphdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 reserved_flags:3;
	__u8 instance_id_present:1;
	__u8 map_version_present:1;
	__u8 solicit_echo_nonce:1;
	__u8 locator_status_bits_present:1;
	__u8 nonce_present:1;
#else
	__u8 nonce_present:1;
	__u8 locator_status_bits_present:1;
	__u8 solicit_echo_nonce:1;
	__u8 map_version_present:1;
	__u8 instance_id_present:1;
	__u8 reserved_flags:3;
#endif
	union {
		__u8 nonce[3];
		__u8 map_version[3];
	} u1;
	union {
		__be32 locator_status_bits;
		struct {
			__u8 instance_id[3];
			__u8 locator_status_bits;
		} word2;
	} u2;
};

#define LISP_HLEN (sizeof(struct udphdr) + sizeof(struct lisphdr))

/**
 * struct lisp_port - Keeps track of open UDP ports
 * @dst_port: lisp UDP port no.
 * @list: list element in @lisp_ports.
 * @lisp_rcv_socket: The socket created for this port number.
 * @name: vport name.
 */
struct lisp_port {
	__be16 dst_port;
	struct list_head list;
	struct socket *lisp_rcv_socket;
	char name[IFNAMSIZ];
};

static LIST_HEAD(lisp_ports);
static struct vport_ops ovs_lisp_vport_ops;

static inline struct lisp_port *lisp_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static struct lisp_port *lisp_find_port(struct net *net, __be16 port)
{
	struct lisp_port *lisp_port;

	list_for_each_entry_rcu(lisp_port, &lisp_ports, list) {
		if (lisp_port->dst_port == port &&
			net_eq(sock_net(lisp_port->lisp_rcv_socket->sk), net))
			return lisp_port;
	}

	return NULL;
}

static inline struct lisphdr *lisp_hdr(const struct sk_buff *skb)
{
	return (struct lisphdr *)(udp_hdr(skb) + 1);
}

/* Convert 64 bit tunnel ID to 24 bit Instance ID. */
static void tunnel_id_to_instance_id(__be64 tun_id, __u8 *iid)
{

#ifdef __BIG_ENDIAN
	iid[0] = (__force __u8)(tun_id >> 16);
	iid[1] = (__force __u8)(tun_id >> 8);
	iid[2] = (__force __u8)tun_id;
#else
	iid[0] = (__force __u8)((__force u64)tun_id >> 40);
	iid[1] = (__force __u8)((__force u64)tun_id >> 48);
	iid[2] = (__force __u8)((__force u64)tun_id >> 56);
#endif
}

/* Convert 24 bit Instance ID to 64 bit tunnel ID. */
static __be64 instance_id_to_tunnel_id(__u8 *iid)
{
#ifdef __BIG_ENDIAN
	return (iid[0] << 16) | (iid[1] << 8) | iid[2];
#else
	return (__force __be64)(((__force u64)iid[0] << 40) |
				((__force u64)iid[1] << 48) |
				((__force u64)iid[2] << 56));
#endif
}

/* Compute source UDP port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct net *net, struct sk_buff *skb)
{
	u32 hash = skb_get_hash(skb);
	unsigned int range;
	int high;
	int low;

	if (!hash) {
		if (skb->protocol == htons(ETH_P_IP)) {
			struct iphdr *iph;
			int size = (sizeof(iph->saddr) * 2) / sizeof(u32);

			iph = (struct iphdr *) skb_network_header(skb);
			hash = jhash2((const u32 *)&iph->saddr, size, 0);
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *ipv6hdr;

			ipv6hdr = (struct ipv6hdr *) skb_network_header(skb);
			hash = jhash2((const u32 *)&ipv6hdr->saddr,
				      (sizeof(struct in6_addr) * 2) / sizeof(u32), 0);
		} else {
			pr_warn_once("LISP inner protocol is not IP when "
				     "calculating hash.\n");
		}
	}

	inet_get_local_port_range(net, &low, &high);
	range = (high - low) + 1;
	return (((u64) hash * range) >> 32) + low;
}

static void lisp_build_header(struct sk_buff *skb)
{
	struct lisphdr *lisph;
	const struct ovs_key_ipv4_tunnel *tun_key;

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	lisph = (struct lisphdr *)__skb_push(skb, sizeof(struct lisphdr));
	lisph->nonce_present = 0;	/* We don't support echo nonce algorithm */
	lisph->locator_status_bits_present = 1;	/* Set LSB */
	lisph->solicit_echo_nonce = 0;	/* No echo noncing */
	lisph->map_version_present = 0;	/* No mapping versioning, nonce instead */
	lisph->instance_id_present = 1;	/* Store the tun_id as Instance ID  */
	lisph->reserved_flags = 0;	/* Reserved flags, set to 0  */

	lisph->u1.nonce[0] = 0;
	lisph->u1.nonce[1] = 0;
	lisph->u1.nonce[2] = 0;

	tunnel_id_to_instance_id(tun_key->tun_id, &lisph->u2.word2.instance_id[0]);
	lisph->u2.word2.locator_status_bits = 1;
}

/* Called with rcu_read_lock and BH disabled. */
static int lisp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct lisp_port *lisp_port;
	struct lisphdr *lisph;
	struct iphdr *iph, *inner_iph;
	struct ovs_tunnel_info tun_info;
	__be64 key;
	struct ethhdr *ethh;
	__be16 protocol;

	lisp_port = rcu_dereference_sk_user_data(sk);
	if (unlikely(!lisp_port))
		goto error;

	if (iptunnel_pull_header(skb, LISP_HLEN, 0))
		goto error;

	lisph = lisp_hdr(skb);

	if (lisph->instance_id_present != 1)
		key = 0;
	else
		key = instance_id_to_tunnel_id(&lisph->u2.word2.instance_id[0]);

	/* Save outer tunnel values */
	iph = ip_hdr(skb);
	ovs_flow_tun_info_init(&tun_info, iph,
			       udp_hdr(skb)->source, udp_hdr(skb)->dest,
			       key, TUNNEL_KEY, NULL, 0);

	/* Drop non-IP inner packets */
	inner_iph = (struct iphdr *)(lisph + 1);
	switch (inner_iph->version) {
	case 4:
		protocol = htons(ETH_P_IP);
		break;
	case 6:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		goto error;
	}
	skb->protocol = protocol;

	/* Add Ethernet header */
	ethh = (struct ethhdr *)skb_push(skb, ETH_HLEN);
	memset(ethh, 0, ETH_HLEN);
	ethh->h_dest[0] = 0x02;
	ethh->h_source[0] = 0x02;
	ethh->h_proto = protocol;

	ovs_skb_postpush_rcsum(skb, skb->data, ETH_HLEN);

	ovs_vport_receive(vport_from_priv(lisp_port), skb, &tun_info);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

static int lisp_socket_init(struct lisp_port *lisp_port, struct net *net)
{
	struct udp_port_cfg udp_conf;
	struct udp_tunnel_sock_cfg tunnel_cfg;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	udp_conf.family = AF_INET;
	udp_conf.local_ip.s_addr = htonl(INADDR_ANY);
	udp_conf.local_udp_port = lisp_port->dst_port;

        err = udp_sock_create(net, &udp_conf, &lisp_port->lisp_rcv_socket);
        if (err < 0) {
		pr_warn("cannot register lisp protocol handler: %d\n", err);
                return err;
	}

	tunnel_cfg.sk_user_data = lisp_port;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = lisp_rcv;
	tunnel_cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(net, lisp_port->lisp_rcv_socket, &tunnel_cfg);

	return 0;
}

static int lisp_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct lisp_port *lisp_port = lisp_vport(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(lisp_port->dst_port)))
		return -EMSGSIZE;
	return 0;
}

static void lisp_tnl_destroy(struct vport *vport)
{
	struct lisp_port *lisp_port = lisp_vport(vport);

	list_del_rcu(&lisp_port->list);
	udp_tunnel_sock_release(lisp_port->lisp_rcv_socket);
	ovs_vport_deferred_free(vport);
}

static struct vport *lisp_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct lisp_port *lisp_port;
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

	/* Verify if we already have a socket created for this port */
	if (lisp_find_port(net, htons(dst_port))) {
		err = -EEXIST;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct lisp_port),
				&ovs_lisp_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	lisp_port = lisp_vport(vport);
	lisp_port->dst_port = htons(dst_port);
	strncpy(lisp_port->name, parms->name, IFNAMSIZ);

	err = lisp_socket_init(lisp_port, net);
	if (err)
		goto error_free;

	list_add_tail_rcu(&lisp_port->list, &lisp_ports);
	return vport;

error_free:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static int lisp_send(struct vport *vport, struct sk_buff *skb)
{
	struct ovs_key_ipv4_tunnel *tun_key;
	struct lisp_port *lisp_port = lisp_vport(vport);
	struct net *net = ovs_dp_get_net(vport->dp);
	int network_offset = skb_network_offset(skb);
	struct rtable *rt;
	int min_headroom;
	__be32 saddr;
	__be16 src_port, dst_port;
	__be16 df;
	int sent_len;
	int err;

	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	if (skb->protocol != htons(ETH_P_IP) &&
	    skb->protocol != htons(ETH_P_IPV6)) {
		err = 0;
		goto error;
	}

	/* Route lookup */
	saddr = tun_key->ipv4_src;
	rt = find_route(ovs_dp_get_net(vport->dp),
			&saddr, tun_key->ipv4_dst,
			IPPROTO_UDP, tun_key->ipv4_tos,
			skb->mark);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ sizeof(struct iphdr) + LISP_HLEN;

	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);

		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
					0, GFP_ATOMIC);
		if (unlikely(err))
			goto err_free_rt;
	}

	/* Reset l2 headers. */
	skb_pull(skb, network_offset);
	skb_reset_mac_header(skb);
	vlan_set_tci(skb, 0);

	skb = udp_tunnel_handle_offloads(skb, false, false);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		skb = NULL;
		goto err_free_rt;
	}

	src_port = htons(get_src_port(net, skb));
	dst_port = lisp_port->dst_port;

	lisp_build_header(skb);

	skb->ignore_df = 1;

	ovs_skb_set_inner_protocol(skb, skb->protocol);

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	sent_len = udp_tunnel_xmit_skb(rt, skb, saddr, tun_key->ipv4_dst,
				       tun_key->ipv4_tos, tun_key->ipv4_ttl,
				       df, src_port, dst_port, false, true);

	return sent_len > 0 ? sent_len + network_offset : sent_len;

err_free_rt:
	ip_rt_put(rt);
error:
	kfree_skb(skb);
	return err;
}

static const char *lisp_get_name(const struct vport *vport)
{
	struct lisp_port *lisp_port = lisp_vport(vport);
	return lisp_port->name;
}

static int lisp_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				    struct ovs_tunnel_info *egress_tun_info)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct lisp_port *lisp_port = lisp_vport(vport);

	if (skb->protocol != htons(ETH_P_IP) &&
	    skb->protocol != htons(ETH_P_IPV6)) {
		return -EINVAL;
	}

	/*
	 * Get tp_src and tp_dst, refert to lisp_build_header().
	 */
	return ovs_tunnel_get_egress_info(egress_tun_info, net,
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark,
					  htons(get_src_port(net, skb)),
					  lisp_port->dst_port);
}

static struct vport_ops ovs_lisp_vport_ops = {
	.type			= OVS_VPORT_TYPE_LISP,
	.create			= lisp_tnl_create,
	.destroy		= lisp_tnl_destroy,
	.get_name		= lisp_get_name,
	.get_options		= lisp_get_options,
	.send			= lisp_send,
	.get_egress_tun_info	= lisp_get_egress_tun_info,
	.owner			= THIS_MODULE,
};

static int __init ovs_lisp_tnl_init(void)
{
	return ovs_vport_ops_register(&ovs_lisp_vport_ops);
}

static void __exit ovs_lisp_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_lisp_vport_ops);
}

module_init(ovs_lisp_tnl_init);
module_exit(ovs_lisp_tnl_exit);

MODULE_DESCRIPTION("OVS: LISP switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-105");
