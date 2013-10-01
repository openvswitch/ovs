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
#include <net/ip_tunnels.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>

#include "compat.h"
#include "gso.h"
#include "vlan.h"

#define PORT_HASH_BITS	8
#define PORT_HASH_SIZE  (1<<PORT_HASH_BITS)

/* IP header + UDP + VXLAN + Ethernet header */
#define VXLAN_HEADROOM (20 + 8 + 8 + 14)
#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

#define VXLAN_FLAGS 0x08000000	/* struct vxlanhdr.vx_flags required value. */

/* VXLAN protocol header */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

static int vxlan_net_id;

static int vxlan_init_module(void);
static void vxlan_cleanup_module(void);

/* per-network namespace private data for this module */
struct vxlan_net {
	struct hlist_head sock_list[PORT_HASH_SIZE];
	spinlock_t  sock_lock;
};

/* Socket hash table head */
static inline struct hlist_head *vs_head(struct net *net, __be16 port)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);

	return &vn->sock_list[hash_32(ntohs(port), PORT_HASH_BITS)];
}

/* Find VXLAN socket based on network namespace and UDP port */

static struct vxlan_sock *vxlan_find_sock(struct net *net, __be16 port)
{
	struct vxlan_sock *vs;

	hlist_for_each_entry_rcu(vs, vs_head(net, port), hlist) {
		if (inet_sport(vs->sock->sk) == port)
			return vs;
	}
	return NULL;
}

/* Callback from net/ipv4/udp.c to receive packets */
static int vxlan_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct vxlan_sock *vs;
	struct vxlanhdr *vxh;

	/* Need Vxlan and inner Ethernet header to be present */
	if (!pskb_may_pull(skb, VXLAN_HLEN))
		goto error;

	/* Return packets with reserved bits set */
	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);
	if (vxh->vx_flags != htonl(VXLAN_FLAGS) ||
	    (vxh->vx_vni & htonl(0xff))) {
		pr_warn("invalid vxlan flags=%#x vni=%#x\n",
			ntohl(vxh->vx_flags), ntohl(vxh->vx_vni));
		goto error;
	}

	if (iptunnel_pull_header(skb, VXLAN_HLEN, htons(ETH_P_TEB)))
		goto drop;

	vs = vxlan_find_sock(sock_net(sk), inet_sport(sk));
	if (!vs)
		goto drop;

	vs->rcv(vs, skb, vxh->vx_vni);
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;

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

/* Compute source port for outgoing packet
 *   first choice to use L4 flow hash since it will spread
 *     better and maybe available from hardware
 *   secondary choice is to use jhash on the Ethernet header
 */
__be16 vxlan_src_port(__u16 port_min, __u16 port_max, struct sk_buff *skb)
{
	unsigned int range = (port_max - port_min) + 1;
	u32 hash;

	hash = skb_get_rxhash(skb);
	if (!hash)
		hash = jhash(skb->data, 2 * ETH_ALEN,
			     (__force u32) skb->protocol);

	return htons((((u64) hash * range) >> 32) + port_min);
}

static void vxlan_gso(struct sk_buff *skb)
{
	int udp_offset = skb_transport_offset(skb);
	struct udphdr *uh;

	uh = udp_hdr(skb);
	uh->len = htons(skb->len - udp_offset);

	/* csum segment if tunnel sets skb with csum. */
	if (unlikely(uh->check)) {
		struct iphdr *iph = ip_hdr(skb);

		uh->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
					       skb->len - udp_offset,
					       IPPROTO_UDP, 0);
		uh->check = csum_fold(skb_checksum(skb, udp_offset,
				      skb->len - udp_offset, 0));

		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;

	}
	skb->ip_summed = CHECKSUM_NONE;
}

static int handle_offloads(struct sk_buff *skb)
{
	if (skb_is_gso(skb)) {
		OVS_GSO_CB(skb)->fix_segment = vxlan_gso;
	} else {
		if (skb->ip_summed != CHECKSUM_PARTIAL)
			skb->ip_summed = CHECKSUM_NONE;
	}
	return 0;
}

int vxlan_xmit_skb(struct net *net, struct vxlan_sock *vs,
		   struct rtable *rt, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port, __be32 vni)
{
	struct vxlanhdr *vxh;
	struct udphdr *uh;
	int min_headroom;
	int err;

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ VXLAN_HLEN + sizeof(struct iphdr)
			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		return err;

	if (vlan_tx_tag_present(skb)) {
		if (unlikely(!__vlan_put_tag(skb,
						skb->vlan_proto,
						vlan_tx_tag_get(skb))))
			return -ENOMEM;

		vlan_set_tci(skb, 0);
	}

	skb_reset_inner_headers(skb);

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = vni;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;

	uh->len = htons(skb->len);
	uh->check = 0;

	vxlan_set_owner(vs->sock->sk, skb);

	err = handle_offloads(skb);
	if (err)
		return err;

	return iptunnel_xmit(net, rt, skb, src, dst,
			IPPROTO_UDP, tos, ttl, df);
}

static void rcu_free_vs(struct rcu_head *rcu)
{
	struct vxlan_sock *vs = container_of(rcu, struct vxlan_sock, rcu);

	kfree(vs);
}

static void vxlan_del_work(struct work_struct *work)
{
	struct vxlan_sock *vs = container_of(work, struct vxlan_sock, del_work);

	sk_release_kernel(vs->sock->sk);
	call_rcu(&vs->rcu, rcu_free_vs);
	vxlan_cleanup_module();
}

static struct vxlan_sock *vxlan_socket_create(struct net *net, __be16 port,
					      vxlan_rcv_t *rcv, void *data)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct sock *sk;
	struct sockaddr_in vxlan_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = port,
	};
	int rc;

	vs = kmalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs) {
		pr_debug("memory alocation failure\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_WORK(&vs->del_work, vxlan_del_work);

	/* Create UDP socket for encapsulation receive. */
	rc = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &vs->sock);
	if (rc < 0) {
		pr_debug("UDP socket create failed\n");
		kfree(vs);
		return ERR_PTR(rc);
	}

	/* Put in proper namespace */
	sk = vs->sock->sk;
	sk_change_net(sk, net);

	rc = kernel_bind(vs->sock, (struct sockaddr *) &vxlan_addr,
			sizeof(vxlan_addr));
	if (rc < 0) {
		pr_debug("bind for UDP socket %pI4:%u (%d)\n",
				&vxlan_addr.sin_addr, ntohs(vxlan_addr.sin_port), rc);
		sk_release_kernel(sk);
		kfree(vs);
		return ERR_PTR(rc);
	}
	vs->rcv = rcv;
	vs->data = data;

	/* Disable multicast loopback */
	inet_sk(sk)->mc_loop = 0;
	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));
	spin_unlock(&vn->sock_lock);

	/* Mark socket as an encapsulation socket. */
	udp_sk(sk)->encap_type = 1;
	udp_sk(sk)->encap_rcv = vxlan_udp_encap_recv;
	udp_encap_enable();
	return vs;
}

struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
				  vxlan_rcv_t *rcv, void *data,
				  bool no_share)
{
	struct vxlan_net *vn;
	struct vxlan_sock *vs;
	int err;

	err = vxlan_init_module();
	if (err)
		return ERR_PTR(err);

	vn = net_generic(net, vxlan_net_id);
	vs = vxlan_socket_create(net, port, rcv, data);
	return vs;
}

void vxlan_sock_release(struct vxlan_sock *vs)
{
	struct vxlan_net *vn = net_generic(sock_net(vs->sock->sk), vxlan_net_id);

	spin_lock(&vn->sock_lock);
	hlist_del_rcu(&vs->hlist);
	spin_unlock(&vn->sock_lock);

	queue_work(&vs->del_work);
}

static int vxlan_init_net(struct net *net)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	unsigned int h;

	spin_lock_init(&vn->sock_lock);

	for (h = 0; h < PORT_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vn->sock_list[h]);

	return 0;
}

static struct pernet_operations vxlan_net_ops = {
	.init = vxlan_init_net,
	.id   = &vxlan_net_id,
	.size = sizeof(struct vxlan_net),
};

static int refcnt;
static DEFINE_MUTEX(init_lock);
DEFINE_COMPAT_PNET_REG_FUNC(device);

static int vxlan_init_module(void)
{
	int err = 0;

	mutex_lock(&init_lock);
	if (refcnt)
		goto out;
	err = register_pernet_device(&vxlan_net_ops);
out:
	if (!err)
		refcnt++;
	mutex_unlock(&init_lock);
	return err;
}

static void vxlan_cleanup_module(void)
{
	mutex_lock(&init_lock);
	refcnt--;
	if (refcnt)
		goto out;
	unregister_pernet_device(&vxlan_net_ops);
out:
	mutex_unlock(&init_lock);
}
