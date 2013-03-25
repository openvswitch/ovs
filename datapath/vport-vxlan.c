/*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2012 Cisco Systems, Inc.
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"

#define VXLAN_FLAGS 0x08000000  /* struct vxlanhdr.vx_flags required value. */

/**
 * struct vxlanhdr - VXLAN header
 * @vx_flags: Must have the exact value %VXLAN_FLAGS.
 * @vx_vni: VXLAN Network Identifier (VNI) in top 24 bits, low 8 bits zeroed.
 */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

static inline int vxlan_hdr_len(const struct ovs_key_ipv4_tunnel *tun_key)
{
	return VXLAN_HLEN;
}

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @list: list element.
 * @vport: vport for the tunnel.
 * @socket: The socket created for this port number.
 */
struct vxlan_port {
	struct list_head list;
	struct vport *vport;
	struct socket *vxlan_rcv_socket;
	struct rcu_head rcu;
};

static LIST_HEAD(vxlan_ports);

static struct vxlan_port *vxlan_find_port(struct net *net, __be16 port)
{
	struct vxlan_port *vxlan_port;

	list_for_each_entry_rcu(vxlan_port, &vxlan_ports, list) {
		struct tnl_vport *tnl_vport = tnl_vport_priv(vxlan_port->vport);

		if (tnl_vport->dst_port == port &&
			net_eq(sock_net(vxlan_port->vxlan_rcv_socket->sk), net))
			return vxlan_port;
	}

	return NULL;
}

static inline struct vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

static void vxlan_build_header(const struct vport *vport,
			       struct sk_buff *skb,
			       int tunnel_hlen)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;

	udph->dest = tnl_vport->dst_port;
	udph->source = htons(ovs_tnl_get_src_port(skb));
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(be64_to_cpu(tun_key->tun_id) << 8);
}

/* Called with rcu_read_lock and BH disabled. */
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vxlan_port *vxlan_vport;
	struct vxlanhdr *vxh;
	struct iphdr *iph;
	struct ovs_key_ipv4_tunnel tun_key;
	__be64 key;

	vxlan_vport = vxlan_find_port(dev_net(skb->dev), udp_hdr(skb)->dest);
	if (unlikely(!vxlan_vport))
		goto error;

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	vxh = vxlan_hdr(skb);
	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff)))
		goto error;

	__skb_pull(skb, VXLAN_HLEN);
	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);

	key = cpu_to_be64(ntohl(vxh->vx_vni) >> 8);

	/* Save outer tunnel values */
	iph = ip_hdr(skb);
	tnl_tun_key_init(&tun_key, iph, key, OVS_TNL_F_KEY);
	OVS_CB(skb)->tun_key = &tun_key;

	ovs_tnl_rcv(vxlan_vport->vport, skb);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

/* Random value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_VXLAN 1
static int vxlan_socket_init(struct vxlan_port *vxlan_port, struct net *net)
{
	int err;
	struct sockaddr_in sin;
	struct tnl_vport *tnl_vport = tnl_vport_priv(vxlan_port->vport);

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &vxlan_port->vxlan_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(vxlan_port->vxlan_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = tnl_vport->dst_port;

	err = kernel_bind(vxlan_port->vxlan_rcv_socket, (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(vxlan_port->vxlan_rcv_socket->sk)->encap_type = UDP_ENCAP_VXLAN;
	udp_sk(vxlan_port->vxlan_rcv_socket->sk)->encap_rcv = vxlan_rcv;

	udp_encap_enable();

	return 0;

error_sock:
	sk_release_kernel(vxlan_port->vxlan_rcv_socket->sk);
error:
	pr_warn("cannot register vxlan protocol handler\n");
	return err;
}

static void free_port_rcu(struct rcu_head *rcu)
{
	struct vxlan_port *vxlan_port = container_of(rcu,
			struct vxlan_port, rcu);

	kfree(vxlan_port);
}

static void vxlan_tunnel_release(struct vxlan_port *vxlan_port)
{
	if (!vxlan_port)
		return;

	list_del_rcu(&vxlan_port->list);
	/* Release socket */
	sk_release_kernel(vxlan_port->vxlan_rcv_socket->sk);
	call_rcu(&vxlan_port->rcu, free_port_rcu);
}

static int vxlan_tunnel_setup(struct net *net, struct vport *vport,
			      struct nlattr *options)
{
	struct vxlan_port *vxlan_port;
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct nlattr *a;
	int err;
	u16 dst_port;

	if (!options) {
		err = -EINVAL;
		goto out;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto out;
	}

	/* Verify if we already have a socket created for this port */
	vxlan_port = vxlan_find_port(net, htons(dst_port));
	if (vxlan_port) {
		err = -EEXIST;
		goto out;
	}

	/* Add a new socket for this port */
	vxlan_port = kzalloc(sizeof(struct vxlan_port), GFP_KERNEL);
	if (!vxlan_port) {
		err = -ENOMEM;
		goto out;
	}

	tnl_vport->dst_port = htons(dst_port);
	vxlan_port->vport = vport;
	list_add_tail_rcu(&vxlan_port->list, &vxlan_ports);

	err = vxlan_socket_init(vxlan_port, net);
	if (err)
		goto error;

	return 0;

error:
	list_del_rcu(&vxlan_port->list);
	kfree(vxlan_port);
out:
	return err;
}

static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	const struct tnl_vport *tnl_vport = tnl_vport_priv(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(tnl_vport->dst_port)))
		return -EMSGSIZE;
	return 0;
}

static const struct tnl_ops ovs_vxlan_tnl_ops = {
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
};

static void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_port *vxlan_port;
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);

	vxlan_port = vxlan_find_port(ovs_dp_get_net(vport->dp),
					 tnl_vport->dst_port);

	vxlan_tunnel_release(vxlan_port);
	ovs_tnl_destroy(vport);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	int err;
	struct vport *vport;

	vport = ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_vxlan_tnl_ops);
	if (IS_ERR(vport))
		return vport;

	err = vxlan_tunnel_setup(ovs_dp_get_net(parms->dp), vport,
				 parms->options);
	if (err) {
		ovs_tnl_destroy(vport);
		return ERR_PTR(err);
	}

	return vport;
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.flags		= VPORT_F_TUN_ID,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.get_name	= ovs_tnl_get_name,
	.get_options	= vxlan_get_options,
	.send		= ovs_tnl_send,
};
#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
