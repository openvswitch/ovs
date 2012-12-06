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
#include <linux/list.h>
#include <linux/net.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

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

static inline int vxlan_hdr_len(const struct tnl_mutable_config *mutable,
				const struct ovs_key_ipv4_tunnel *tun_key)
{
	return VXLAN_HLEN;
}

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @list: list element.
 * @port: The UDP port number in network byte order.
 * @socket: The socket created for this port number.
 * @count: How many ports are using this socket/port.
 */
struct vxlan_port {
	struct list_head list;
	__be16 port;
	struct socket *vxlan_rcv_socket;
	int count;
};

static LIST_HEAD(vxlan_ports);

static struct vxlan_port *vxlan_port_exists(struct net *net, __be16 port)
{
	struct vxlan_port *vxlan_port;

	list_for_each_entry(vxlan_port, &vxlan_ports, list) {
		if (vxlan_port->port == port &&
			net_eq(sock_net(vxlan_port->vxlan_rcv_socket->sk), net))
			return vxlan_port;
	}

	return NULL;
}

static inline struct vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

/* Compute source port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct sk_buff *skb)
{
	int low;
	int high;
	unsigned int range;
	u32 hash = OVS_CB(skb)->flow->hash;

        inet_get_local_port_range(&low, &high);
        range = (high - low) + 1;
	return (((u64) hash * range) >> 32) + low;
}

static struct sk_buff *vxlan_build_header(const struct vport *vport,
					  const struct tnl_mutable_config *mutable,
					  struct dst_entry *dst,
					  struct sk_buff *skb,
					  int tunnel_hlen)
{
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
	__be64 out_key;
	u32 flags;

	tnl_get_param(mutable, tun_key, &flags, &out_key);

	udph->dest = mutable->dst_port;
	udph->source = htons(get_src_port(skb));
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(be64_to_cpu(out_key) << 8);

	/*
	 * Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort.  We also need to force selection of
	 * an IP ID here because Linux will otherwise leave it at 0 if the
	 * packet originally had DF set.
	 */
	skb->local_df = 1;
	__ip_select_ident(ip_hdr(skb), dst, 0);

	return skb;
}

/* Called with rcu_read_lock and BH disabled. */
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct vxlanhdr *vxh;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;
	struct ovs_key_ipv4_tunnel tun_key;
	__be64 key;
	u32 tunnel_flags = 0;

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	vxh = vxlan_hdr(skb);
	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff)))
		goto error;

	__skb_pull(skb, VXLAN_HLEN);
	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);

	key = cpu_to_be64(ntohl(vxh->vx_vni) >> 8);

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(dev_net(skb->dev), iph->daddr, iph->saddr,
		key, TNL_T_PROTO_VXLAN, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	if (mutable->flags & TNL_F_IN_KEY_MATCH || !mutable->key.daddr)
		tunnel_flags = OVS_TNL_F_KEY;
	else
		key = 0;

	/* Save outer tunnel values */
	tnl_tun_key_init(&tun_key, iph, key, tunnel_flags);
	OVS_CB(skb)->tun_key = &tun_key;

	ovs_tnl_rcv(vport, skb);
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

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &vxlan_port->vxlan_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(vxlan_port->vxlan_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = vxlan_port->port;

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

static void vxlan_tunnel_release(struct vxlan_port *vxlan_port)
{
	vxlan_port->count--;

	if (vxlan_port->count == 0) {
		/* Release old socket */
		sk_release_kernel(vxlan_port->vxlan_rcv_socket->sk);
		list_del(&vxlan_port->list);
		kfree(vxlan_port);
	}
}
static int vxlan_tunnel_setup(struct net *net, struct nlattr *options,
			      struct vxlan_port **vxport)
{
	struct nlattr *a;
	int err;
	u16 dst_port;
	struct vxlan_port *vxlan_port = NULL;

	*vxport = NULL;

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
	vxlan_port = vxlan_port_exists(net, htons(dst_port));
	if (vxlan_port) {
		vxlan_port->count++;
		err = 0;
		goto out;
	}

	/* Add a new socket for this port */
	vxlan_port = kzalloc(sizeof(struct vxlan_port), GFP_KERNEL);
	if (!vxlan_port) {
		err = -ENOMEM;
		goto out;
	}

	vxlan_port->port = htons(dst_port);
	vxlan_port->count = 1;
	list_add_tail(&vxlan_port->list, &vxlan_ports);

	err = vxlan_socket_init(vxlan_port, net);
	if (err)
		goto error;

	*vxport = vxlan_port;
	goto out;

error:
	list_del(&vxlan_port->list);
	kfree(vxlan_port);
out:
	return err;
}

static int vxlan_set_options(struct vport *vport, struct nlattr *options)
{
	int err;
	struct net *net = ovs_dp_get_net(vport->dp);
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *config;
	struct vxlan_port *old_port = NULL;
	struct vxlan_port *vxlan_port = NULL;

	config = rtnl_dereference(tnl_vport->mutable);

	old_port = vxlan_port_exists(net, config->dst_port);

	err = vxlan_tunnel_setup(net, options, &vxlan_port);
	if (err)
		goto out;

	err = ovs_tnl_set_options(vport, options);

	if (err)
		vxlan_tunnel_release(vxlan_port);
	else {
		/* Release old socket */
		vxlan_tunnel_release(old_port);
	}
out:
	return err;
}

static const struct tnl_ops ovs_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
};

static void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_port *vxlan_port;
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *config;

	config = rtnl_dereference(tnl_vport->mutable);

	vxlan_port = vxlan_port_exists(ovs_dp_get_net(vport->dp),
					 config->dst_port);

	vxlan_tunnel_release(vxlan_port);

	ovs_tnl_destroy(vport);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	int err;
	struct vport *vport;
	struct vxlan_port *vxlan_port = NULL;

	err = vxlan_tunnel_setup(ovs_dp_get_net(parms->dp), parms->options,
				 &vxlan_port);
	if (err)
		return ERR_PTR(err);

	vport = ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_vxlan_tnl_ops);

	if (IS_ERR(vport))
		vxlan_tunnel_release(vxlan_port);

	return vport;
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.flags		= VPORT_F_TUN_ID,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.set_addr	= ovs_tnl_set_addr,
	.get_name	= ovs_tnl_get_name,
	.get_addr	= ovs_tnl_get_addr,
	.get_options	= ovs_tnl_get_options,
	.set_options	= vxlan_set_options,
	.get_dev_flags	= ovs_vport_gen_get_dev_flags,
	.is_running	= ovs_vport_gen_is_running,
	.get_operstate	= ovs_vport_gen_get_operstate,
	.send		= ovs_tnl_send,
};
#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
