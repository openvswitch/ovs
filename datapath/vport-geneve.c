/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/geneve.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"

/*
 * Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	u8 opt_len:6;
	u8 ver:2;
	u8 rsvd1:6;
	u8 critical:1;
	u8 oam:1;
#else
	u8 ver:2;
	u8 opt_len:6;
	u8 oam:1;
	u8 critical:1;
	u8 rsvd1:6;
#endif
	__be16 proto_type;
	u8 vni[3];
	u8 rsvd2;
	struct geneve_opt options[];
};

#define GENEVE_VER 0

#define GENEVE_BASE_HLEN (sizeof(struct udphdr) + sizeof(struct genevehdr))

/**
 * struct geneve_port - Keeps track of open UDP ports
 * @sock: The socket created for this port number.
 * @name: vport name.
 */
struct geneve_port {
	struct socket *sock;
	char name[IFNAMSIZ];
};

static LIST_HEAD(geneve_ports);

static inline struct geneve_port *geneve_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline struct genevehdr *geneve_hdr(const struct sk_buff *skb)
{
	return (struct genevehdr *)(udp_hdr(skb) + 1);
}

/* Convert 64 bit tunnel ID to 24 bit VNI. */
static void tunnel_id_to_vni(__be64 tun_id, __u8 *vni)
{
#ifdef __BIG_ENDIAN
	vni[0] = (__force __u8)(tun_id >> 16);
	vni[1] = (__force __u8)(tun_id >> 8);
	vni[2] = (__force __u8)tun_id;
#else
	vni[0] = (__force __u8)((__force u64)tun_id >> 40);
	vni[1] = (__force __u8)((__force u64)tun_id >> 48);
	vni[2] = (__force __u8)((__force u64)tun_id >> 56);
#endif
}

/* Convert 24 bit VNI to 64 bit tunnel ID. */
static __be64 vni_to_tunnel_id(const __u8 *vni)
{
#ifdef __BIG_ENDIAN
	return (vni[0] << 16) | (vni[1] << 8) | vni[2];
#else
	return (__force __be64)(((__force u64)vni[0] << 40) |
				((__force u64)vni[1] << 48) |
				((__force u64)vni[2] << 56));
#endif
}

static void geneve_build_header(const struct vport *vport,
			      struct sk_buff *skb)
{
	struct geneve_port *geneve_port = geneve_vport(vport);
	struct net *net = ovs_dp_get_net(vport->dp);
	struct udphdr *udph = udp_hdr(skb);
	struct genevehdr *geneveh = (struct genevehdr *)(udph + 1);
	const struct ovs_tunnel_info *tun_info = OVS_CB(skb)->egress_tun_info;

	udph->dest = inet_sport(geneve_port->sock->sk);
	udph->source = udp_flow_src_port(net, skb, 0, 0, true);
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	geneveh->ver = GENEVE_VER;
	geneveh->opt_len = tun_info->options_len / 4;
	geneveh->oam = !!(tun_info->tunnel.tun_flags & TUNNEL_OAM);
	geneveh->critical = !!(tun_info->tunnel.tun_flags & TUNNEL_CRIT_OPT);
	geneveh->rsvd1 = 0;
	geneveh->proto_type = htons(ETH_P_TEB);
	tunnel_id_to_vni(tun_info->tunnel.tun_id, geneveh->vni);
	geneveh->rsvd2 = 0;

	memcpy(geneveh->options, tun_info->options, tun_info->options_len);
}

static int geneve_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct geneve_port *geneve_port;
	struct genevehdr *geneveh;
	int opts_len;
	struct ovs_tunnel_info tun_info;
	__be64 key;
	__be16 flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	if (unlikely(udp_lib_checksum_complete(skb)))
		goto error;
#endif

	if (unlikely(!pskb_may_pull(skb, GENEVE_BASE_HLEN)))
		goto error;

	geneveh = geneve_hdr(skb);

	if (unlikely(geneveh->ver != GENEVE_VER))
		goto error;

	if (unlikely(geneveh->proto_type != htons(ETH_P_TEB)))
		goto error;

	geneve_port = rcu_dereference_sk_user_data(sk);
	if (unlikely(!geneve_port))
		goto error;

	opts_len = geneveh->opt_len * 4;
	if (iptunnel_pull_header(skb, GENEVE_BASE_HLEN + opts_len,
				 htons(ETH_P_TEB)))
		goto error;

	geneveh = geneve_hdr(skb);

	flags = TUNNEL_KEY | TUNNEL_OPTIONS_PRESENT |
		(udp_hdr(skb)->check != 0 ? TUNNEL_CSUM : 0) |
		(geneveh->oam ? TUNNEL_OAM : 0) |
		(geneveh->critical ? TUNNEL_CRIT_OPT : 0);

	key = vni_to_tunnel_id(geneveh->vni);
	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb),
				udp_hdr(skb)->source, udp_hdr(skb)->dest,
				key, flags,
				geneveh->options, opts_len);

	ovs_vport_receive(vport_from_priv(geneve_port), skb, &tun_info);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

/* Arbitrary value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_GENEVE 1
static int geneve_socket_init(struct geneve_port *geneve_port, struct net *net,
			      __be16 dst_port)
{
	struct sockaddr_in sin;
	int err;

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &geneve_port->sock);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(geneve_port->sock->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = dst_port;

	err = kernel_bind(geneve_port->sock,
			  (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	rcu_assign_sk_user_data(geneve_port->sock->sk, geneve_port);
	udp_sk(geneve_port->sock->sk)->encap_type = UDP_ENCAP_GENEVE;
	udp_sk(geneve_port->sock->sk)->encap_rcv = geneve_rcv;

	udp_encap_enable();

	return 0;

error_sock:
	sk_release_kernel(geneve_port->sock->sk);
error:
	pr_warn("cannot register geneve protocol handler: %d\n", err);
	return err;
}

static int geneve_get_options(const struct vport *vport,
			      struct sk_buff *skb)
{
	struct geneve_port *geneve_port = geneve_vport(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT,
			ntohs(inet_sport(geneve_port->sock->sk))))
		return -EMSGSIZE;
	return 0;
}

static void geneve_tnl_destroy(struct vport *vport)
{
	struct geneve_port *geneve_port = geneve_vport(vport);

	/* Release socket */
	rcu_assign_sk_user_data(geneve_port->sock->sk, NULL);
	sk_release_kernel(geneve_port->sock->sk);

	ovs_vport_deferred_free(vport);
}

static struct vport *geneve_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct geneve_port *geneve_port;
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

	vport = ovs_vport_alloc(sizeof(struct geneve_port),
				&ovs_geneve_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	geneve_port = geneve_vport(vport);
	strncpy(geneve_port->name, parms->name, IFNAMSIZ);

	err = geneve_socket_init(geneve_port, net, htons(dst_port));
	if (err)
		goto error_free;

	return vport;

error_free:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

static void geneve_fix_segment(struct sk_buff *skb)
{
	struct udphdr *udph = udp_hdr(skb);

	udph->len = htons(skb->len - skb_transport_offset(skb));
}

static struct sk_buff *handle_offloads(struct sk_buff *skb)
{
	return ovs_iptunnel_handle_offloads(skb, false, geneve_fix_segment);
}
#else

static struct sk_buff *handle_offloads(struct sk_buff *skb)
{
	int err = 0;

	if (skb_is_gso(skb)) {

		if (skb_is_encapsulated(skb)) {
			err = -ENOSYS;
			goto error;
		}

		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			goto error;

		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;
	} else if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_NONE;

	skb->encapsulation = 1;
	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}
#endif

static int geneve_send(struct vport *vport, struct sk_buff *skb)
{
	struct ovs_key_ipv4_tunnel *tun_key;
	int network_offset = skb_network_offset(skb);
	struct rtable *rt;
	int min_headroom;
	__be32 saddr;
	__be16 df;
	int sent_len;
	int err;

	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

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
			+ GENEVE_BASE_HLEN
			+ OVS_CB(skb)->egress_tun_info->options_len
			+ sizeof(struct iphdr)
			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);

		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
					0, GFP_ATOMIC);
		if (unlikely(err))
			goto err_free_rt;
	}

	if (vlan_tx_tag_present(skb)) {
		if (unlikely(!vlan_insert_tag_set_proto(skb,
							skb->vlan_proto,
							vlan_tx_tag_get(skb)))) {
			err = -ENOMEM;
			skb = NULL;
			goto err_free_rt;
		}
		vlan_set_tci(skb, 0);
	}

	skb_reset_inner_headers(skb);

	__skb_push(skb, GENEVE_BASE_HLEN +
			OVS_CB(skb)->egress_tun_info->options_len);
	skb_reset_transport_header(skb);

	geneve_build_header(vport, skb);

	/* Offloading */
	skb = handle_offloads(skb);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		skb = NULL;
		goto err_free_rt;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;

	sent_len = iptunnel_xmit(skb->sk, rt, skb,
			     saddr, tun_key->ipv4_dst,
			     IPPROTO_UDP, tun_key->ipv4_tos,
			     tun_key->ipv4_ttl,
			     df, false);

	return sent_len > 0 ? sent_len + network_offset : sent_len;

err_free_rt:
	ip_rt_put(rt);
error:
	kfree_skb(skb);
	return err;
}

static const char *geneve_get_name(const struct vport *vport)
{
	struct geneve_port *geneve_port = geneve_vport(vport);
	return geneve_port->name;
}

static int geneve_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				      struct ovs_tunnel_info *egress_tun_info)
{
	struct geneve_port *geneve_port = geneve_vport(vport);
	struct net *net = ovs_dp_get_net(vport->dp);

	/*
	 * Get tp_src and tp_dst, refert to geneve_build_header().
	 */
	return ovs_tunnel_get_egress_info(egress_tun_info,
					  ovs_dp_get_net(vport->dp),
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark,
					  udp_flow_src_port(net, skb, 0, 0, true),
					  inet_sport(geneve_port->sock->sk));

}

const struct vport_ops ovs_geneve_vport_ops = {
	.type			= OVS_VPORT_TYPE_GENEVE,
	.create			= geneve_tnl_create,
	.destroy		= geneve_tnl_destroy,
	.get_name		= geneve_get_name,
	.get_options		= geneve_get_options,
	.send			= geneve_send,
	.get_egress_tun_info	= geneve_get_egress_tun_info,
};
