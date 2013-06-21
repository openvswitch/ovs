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

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @dst_port: vxlan UDP port no.
 * @list: list element in @vxlan_ports.
 * @vxlan_rcv_socket: The socket created for this port number.
 * @name: vport name.
 */
struct vxlan_port {
	__be16 dst_port;
	struct list_head list;
	struct socket *vxlan_rcv_socket;
	char name[IFNAMSIZ];
};

static LIST_HEAD(vxlan_ports);

static inline struct vxlan_port *vxlan_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static struct vxlan_port *vxlan_find_port(struct net *net, __be16 port)
{
	struct vxlan_port *vxlan_port;

	list_for_each_entry_rcu(vxlan_port, &vxlan_ports, list) {

		if (vxlan_port->dst_port == port &&
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
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;

	udph->dest = vxlan_port->dst_port;
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

	skb_pull_rcsum(skb, VXLAN_HLEN);

	key = cpu_to_be64(ntohl(vxh->vx_vni) >> 8);

	/* Save outer tunnel values */
	iph = ip_hdr(skb);
	tnl_tun_key_init(&tun_key, iph, key, TUNNEL_KEY);

	ovs_tnl_rcv(vport_from_priv(vxlan_vport), skb, &tun_key);
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
	struct sockaddr_in sin;
	int err;

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &vxlan_port->vxlan_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(vxlan_port->vxlan_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = vxlan_port->dst_port;

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

static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(vxlan_port->dst_port)))
		return -EMSGSIZE;
	return 0;
}

static void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);

	list_del_rcu(&vxlan_port->list);
	/* Release socket */
	sk_release_kernel(vxlan_port->vxlan_rcv_socket->sk);

	ovs_vport_deferred_free(vport);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct vxlan_port *vxlan_port;
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
	if (vxlan_find_port(net, htons(dst_port))) {
		err = -EEXIST;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct vxlan_port),
				&ovs_vxlan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	vxlan_port = vxlan_vport(vport);
	vxlan_port->dst_port = htons(dst_port);
	strncpy(vxlan_port->name, parms->name, IFNAMSIZ);

	err = vxlan_socket_init(vxlan_port, net);
	if (err)
		goto error_free;

	list_add_tail_rcu(&vxlan_port->list, &vxlan_ports);
	return vport;

error_free:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static int vxlan_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	if (unlikely(!OVS_CB(skb)->tun_key))
		return -EINVAL;

	return ovs_tnl_send(vport, skb, IPPROTO_UDP,
			VXLAN_HLEN, vxlan_build_header);
}

static const char *vxlan_get_name(const struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	return vxlan_port->name;
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.get_name	= vxlan_get_name,
	.get_options	= vxlan_get_options,
	.send		= vxlan_tnl_send,
};
#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
