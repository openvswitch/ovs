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
 *
 * This code is derived from kernel vxlan module.
 */

#include <linux/version.h>

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/rculist.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/hash.h>
#include <linux/ethtool.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <net/ip.h>
#include <net/gre.h>
#include <net/ip_tunnels.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>

#include "compat.h"
#include "datapath.h"
#include "gso.h"
#include "vlan.h"

#ifndef USE_UPSTREAM_VXLAN

/* VXLAN protocol header */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

/* Callback from net/ipv4/udp.c to receive packets */
static int vxlan_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct vxlan_sock *vs;
	struct vxlanhdr *vxh;
	u32 flags, vni;
	struct vxlan_metadata md = {0};

	/* Need Vxlan and inner Ethernet header to be present */
	if (!pskb_may_pull(skb, VXLAN_HLEN))
		goto error;

	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);
	flags = ntohl(vxh->vx_flags);
	vni = ntohl(vxh->vx_vni);

	if (flags & VXLAN_HF_VNI) {
		flags &= ~VXLAN_HF_VNI;
	} else {
		/* VNI flag always required to be set */
		goto bad_flags;
	}

	if (iptunnel_pull_header(skb, VXLAN_HLEN, htons(ETH_P_TEB)))
		goto drop;

	vs = rcu_dereference_sk_user_data(sk);
	if (!vs)
		goto drop;

	/* For backwards compatibility, only allow reserved fields to be
	* used by VXLAN extensions if explicitly requested.
	*/
	if ((flags & VXLAN_HF_GBP) && (vs->flags & VXLAN_F_GBP)) {
		struct vxlanhdr_gbp *gbp;

		gbp = (struct vxlanhdr_gbp *)vxh;
		md.gbp = ntohs(gbp->policy_id);

		if (gbp->dont_learn)
			md.gbp |= VXLAN_GBP_DONT_LEARN;

		if (gbp->policy_applied)
			md.gbp |= VXLAN_GBP_POLICY_APPLIED;

		flags &= ~VXLAN_GBP_USED_BITS;
	}

	if (flags || (vni & 0xff)) {
		/* If there are any unprocessed flags remaining treat
		* this as a malformed packet. This behavior diverges from
		* VXLAN RFC (RFC7348) which stipulates that bits in reserved
		* in reserved fields are to be ignored. The approach here
		* maintains compatbility with previous stack code, and also
		* is more robust and provides a little more security in
		* adding extensions to VXLAN.
		*/

		goto bad_flags;
	}

	md.vni = vxh->vx_vni;
	vs->rcv(vs, skb, &md);
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;
bad_flags:
	pr_debug("invalid vxlan flags=%#x vni=%#x\n",
		 ntohl(vxh->vx_flags), ntohl(vxh->vx_vni));

error:
	/* Return non vxlan pkt */
	return 1;
}

static void vxlan_sock_put(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

/* On transmit, associate with the tunnel socket */
static void vxlan_set_owner(struct sock *sk, struct sk_buff *skb)
{
	skb_orphan(skb);
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = vxlan_sock_put;
}

static void vxlan_build_gbp_hdr(struct vxlanhdr *vxh, u32 vxflags,
				struct vxlan_metadata *md)
{
	struct vxlanhdr_gbp *gbp;

	if (!md->gbp)
		return;

	gbp = (struct vxlanhdr_gbp *)vxh;
	vxh->vx_flags |= htonl(VXLAN_HF_GBP);

	if (md->gbp & VXLAN_GBP_DONT_LEARN)
		gbp->dont_learn = 1;

	if (md->gbp & VXLAN_GBP_POLICY_APPLIED)
		gbp->policy_applied = 1;

	gbp->policy_id = htons(md->gbp & VXLAN_GBP_ID_MASK);
}

int rpl_vxlan_xmit_skb(struct vxlan_sock *vs,
		       struct rtable *rt, struct sk_buff *skb,
		       __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		       __be16 src_port, __be16 dst_port,
		       struct vxlan_metadata *md, bool xnet, u32 vxflags)
{
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	bool udp_sum = !!(vxflags & VXLAN_F_UDP_CSUM);

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ VXLAN_HLEN + sizeof(struct iphdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}

	skb = vlan_hwaccel_push_inside(skb);
	if (WARN_ON(!skb))
		return -ENOMEM;

	skb = udp_tunnel_handle_offloads(skb, udp_sum, true);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = md->vni;

	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);

	vxlan_set_owner(vs->sock->sk, skb);

	ovs_skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	return udp_tunnel_xmit_skb(rt, skb, src, dst, tos,
				   ttl, df, src_port, dst_port, xnet,
				   !udp_sum);
}
EXPORT_SYMBOL_GPL(rpl_vxlan_xmit_skb);

static void rcu_free_vs(struct rcu_head *rcu)
{
	struct vxlan_sock *vs = container_of(rcu, struct vxlan_sock, rcu);

	kfree(vs);
}

static void vxlan_del_work(struct work_struct *work)
{
	struct vxlan_sock *vs = container_of(work, struct vxlan_sock, del_work);

	udp_tunnel_sock_release(vs->sock);
	call_rcu(&vs->rcu, rcu_free_vs);
}

static struct socket *vxlan_create_sock(struct net *net, bool ipv6,
					__be16 port, u32 flags)
{
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	if (ipv6) {
		udp_conf.family = AF_INET6;
		/* The checksum flag is silently ignored but it
		 * doesn't make sense here anyways because OVS enables
		 * checksums on a finer granularity than per-socket.
		 */
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

static struct vxlan_sock *vxlan_socket_create(struct net *net, __be16 port,
					      vxlan_rcv_t *rcv, void *data, u32 flags)
{
	struct vxlan_sock *vs;
	struct socket *sock;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kmalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs) {
		pr_debug("memory alocation failure\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_WORK(&vs->del_work, vxlan_del_work);

	sock = vxlan_create_sock(net, false, port, flags);
	if (IS_ERR(sock)) {
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	vs->rcv = rcv;
	vs->data = data;
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return vs;
}

struct vxlan_sock *rpl_vxlan_sock_add(struct net *net, __be16 port,
				      vxlan_rcv_t *rcv, void *data,
				      bool no_share, u32 flags)
{
	return vxlan_socket_create(net, port, rcv, data, flags);
}
EXPORT_SYMBOL_GPL(rpl_vxlan_sock_add);

void rpl_vxlan_sock_release(struct vxlan_sock *vs)
{
	ASSERT_OVSL();

	queue_work(system_wq, &vs->del_work);
}
EXPORT_SYMBOL_GPL(rpl_vxlan_sock_release);

#endif /* !USE_UPSTREAM_VXLAN */
