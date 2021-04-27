/*
 * VXLAN: Virtual eXtensible Local Area Network
 *
 * Copyright (c) 2012-2013 Vyatta Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
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
#include <linux/netdev_features.h>
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
#include <net/dst_metadata.h>
#include <net/ndisc.h>
#include <net/ip.h>
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
#include <net/protocol.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#endif

#include <net/tun_proto.h>
#include <net/vxlan.h>
#include "gso.h"
#include "vport-netdev.h"
#include "compat.h"

#ifndef USE_UPSTREAM_TUNNEL
#define VXLAN_VERSION	"0.1"

#define PORT_HASH_BITS	8
#define PORT_HASH_SIZE  (1<<PORT_HASH_BITS)
#define FDB_AGE_DEFAULT 300 /* 5 min */
#define FDB_AGE_INTERVAL (10 * HZ)	/* rescan interval */

/* UDP port for VXLAN traffic.
 * The IANA assigned port is 4789, but the Linux default is 8472
 * for compatibility with early adopters.
 */
static unsigned short vxlan_port __read_mostly = 8472;
module_param_named(udp_port, vxlan_port, ushort, 0444);
MODULE_PARM_DESC(udp_port, "Destination UDP port");

static int vxlan_net_id;
static struct rtnl_link_ops vxlan_link_ops;

static const u8 all_zeros_mac[ETH_ALEN + 2];

static int vxlan_sock_add(struct vxlan_dev *vxlan);

/* per-network namespace private data for this module */
struct vxlan_net {
	struct list_head  vxlan_list;
	struct hlist_head sock_list[PORT_HASH_SIZE];
	spinlock_t	  sock_lock;
};

/* Forwarding table entry */
struct vxlan_fdb {
	struct hlist_node hlist;	/* linked list of entries */
	struct rcu_head	  rcu;
	unsigned long	  updated;	/* jiffies */
	unsigned long	  used;
	struct list_head  remotes;
	u8		  eth_addr[ETH_ALEN];
	u16		  state;	/* see ndm_state */
	u8		  flags;	/* see ndm_flags */
};

/* salt for hash table */
static u32 vxlan_salt __read_mostly;

static inline bool vxlan_collect_metadata(struct vxlan_sock *vs)
{
	return vs->flags & VXLAN_F_COLLECT_METADATA ||
	       ip_tunnel_collect_metadata();
}

#if IS_ENABLED(CONFIG_IPV6)
static inline
bool vxlan_addr_equal(const union vxlan_addr *a, const union vxlan_addr *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;
	if (a->sa.sa_family == AF_INET6)
		return ipv6_addr_equal(&a->sin6.sin6_addr, &b->sin6.sin6_addr);
	else
		return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
}

static inline bool vxlan_addr_any(const union vxlan_addr *ipa)
{
	if (ipa->sa.sa_family == AF_INET6)
		return ipv6_addr_any(&ipa->sin6.sin6_addr);
	else
		return ipa->sin.sin_addr.s_addr == htonl(INADDR_ANY);
}

static inline bool vxlan_addr_multicast(const union vxlan_addr *ipa)
{
	if (ipa->sa.sa_family == AF_INET6)
		return ipv6_addr_is_multicast(&ipa->sin6.sin6_addr);
	else
		return IN_MULTICAST(ntohl(ipa->sin.sin_addr.s_addr));
}

#else /* !CONFIG_IPV6 */

static inline
bool vxlan_addr_equal(const union vxlan_addr *a, const union vxlan_addr *b)
{
	return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
}

static inline bool vxlan_addr_any(const union vxlan_addr *ipa)
{
	return ipa->sin.sin_addr.s_addr == htonl(INADDR_ANY);
}

static inline bool vxlan_addr_multicast(const union vxlan_addr *ipa)
{
	return IN_MULTICAST(ntohl(ipa->sin.sin_addr.s_addr));
}
#endif

/* Virtual Network hash table head */
static inline struct hlist_head *vni_head(struct vxlan_sock *vs, __be32 vni)
{
	return &vs->vni_list[hash_32((__force u32)vni, VNI_HASH_BITS)];
}

/* Socket hash table head */
static inline struct hlist_head *vs_head(struct net *net, __be16 port)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);

	return &vn->sock_list[hash_32(ntohs(port), PORT_HASH_BITS)];
}

/* Find VXLAN socket based on network namespace, address family and UDP port
 * and enabled unshareable flags.
 */
static struct vxlan_sock *vxlan_find_sock(struct net *net, sa_family_t family,
					  __be16 port, u32 flags)
{
	struct vxlan_sock *vs;

	flags &= VXLAN_F_RCV_FLAGS;

	hlist_for_each_entry_rcu(vs, vs_head(net, port), hlist) {
		if (inet_sk(vs->sock->sk)->inet_sport == port &&
		    vxlan_get_sk_family(vs) == family &&
		    vs->flags == flags)
			return vs;
	}
	return NULL;
}

static struct vxlan_dev *vxlan_vs_find_vni(struct vxlan_sock *vs, __be32 vni)
{
	struct vxlan_dev *vxlan;

	/* For flow based devices, map all packets to VNI 0 */
	if (vs->flags & VXLAN_F_COLLECT_METADATA)
		vni = 0;

	hlist_for_each_entry_rcu(vxlan, vni_head(vs, vni), hlist) {
		if (vxlan->default_dst.remote_vni == vni)
			return vxlan;
	}

	return NULL;
}

/* Look up VNI in a per net namespace table */
static struct vxlan_dev *vxlan_find_vni(struct net *net, __be32 vni,
					sa_family_t family, __be16 port,
					u32 flags)
{
	struct vxlan_sock *vs;

	vs = vxlan_find_sock(net, family, port, flags);
	if (!vs)
		return NULL;

	return vxlan_vs_find_vni(vs, vni);
}

static int vxlan_fdb_create(struct vxlan_dev *vxlan,
			    const u8 *mac, union vxlan_addr *ip,
			    __u16 state, __u16 flags,
			    __be16 port, __be32 vni, __u32 ifindex,
			    __u8 ndm_flags)
{
	return -EINVAL;
}

static void vxlan_fdb_destroy(struct vxlan_dev *vxlan, struct vxlan_fdb *f)
{

}

static inline size_t vxlan_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
		+ nla_total_size(ETH_ALEN) /* NDA_LLADDR */
		+ nla_total_size(sizeof(struct in6_addr)) /* NDA_DST */
		+ nla_total_size(sizeof(__be16)) /* NDA_PORT */
		+ nla_total_size(sizeof(__be32)) /* NDA_VNI */
		+ nla_total_size(sizeof(__u32)) /* NDA_IFINDEX */
		+ nla_total_size(sizeof(__s32)) /* NDA_LINK_NETNSID */
		+ nla_total_size(sizeof(struct nda_cacheinfo));
}

#ifdef HAVE_UDP_OFFLOAD
#ifdef HAVE_NETIF_F_GSO_TUNNEL_REMCSUM

static struct vxlanhdr *vxlan_gro_remcsum(struct sk_buff *skb,
					  unsigned int off,
					  struct vxlanhdr *vh, size_t hdrlen,
					  __be32 vni_field,
					  struct gro_remcsum *grc,
					  bool nopartial)
{
	size_t start, offset;

	if (skb->remcsum_offload)
		return vh;

	if (!NAPI_GRO_CB(skb)->csum_valid)
		return NULL;

	start = vxlan_rco_start(vni_field);
	offset = start + vxlan_rco_offset(vni_field);

	vh = skb_gro_remcsum_process(skb, (void *)vh, off, hdrlen,
				     start, offset, grc, nopartial);

	skb->remcsum_offload = 1;

	return vh;
}
#else
static struct vxlanhdr *vxlan_gro_remcsum(struct sk_buff *skb,
		unsigned int off,
		struct vxlanhdr *vh, size_t hdrlen,
		u32 data, struct gro_remcsum *grc,
		bool nopartial)
{
	return NULL;
}
#endif

#ifndef HAVE_UDP_OFFLOAD_ARG_UOFF
static struct sk_buff **vxlan_gro_receive(struct sk_buff **head,
                                          struct sk_buff *skb)
#else
static struct sk_buff **vxlan_gro_receive(struct sk_buff **head,
                                          struct sk_buff *skb,
                                          struct udp_offload *uoff)
#endif
{
#ifdef HAVE_UDP_OFFLOAD_ARG_UOFF
	struct vxlan_sock *vs = container_of(uoff, struct vxlan_sock,
			udp_offloads);
#else
	struct vxlan_sock *vs = NULL;
#endif
	struct sk_buff *p, **pp = NULL;
	struct vxlanhdr *vh, *vh2;
	unsigned int hlen, off_vx;
	int flush = 1;
	__be32 flags;
	struct gro_remcsum grc;

	skb_gro_remcsum_init(&grc);

	off_vx = skb_gro_offset(skb);
	hlen = off_vx + sizeof(*vh);
	vh   = skb_gro_header_fast(skb, off_vx);
	if (skb_gro_header_hard(skb, hlen)) {
		vh = skb_gro_header_slow(skb, hlen, off_vx);
		if (unlikely(!vh))
			goto out;
	}

	skb_gro_postpull_rcsum(skb, vh, sizeof(struct vxlanhdr));

	flags = vh->vx_flags;

	if ((flags & VXLAN_HF_RCO) && vs && (vs->flags & VXLAN_F_REMCSUM_RX)) {
		vh = vxlan_gro_remcsum(skb, off_vx, vh, sizeof(struct vxlanhdr),
				       vh->vx_vni, &grc,
				       !!(vs->flags &
					  VXLAN_F_REMCSUM_NOPARTIAL));

		if (!vh)
			goto out;
	}

	skb_gro_pull(skb, sizeof(struct vxlanhdr)); /* pull vxlan header */

	for (p = *head; p; p = p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		vh2 = (struct vxlanhdr *)(p->data + off_vx);
		if (vh->vx_flags != vh2->vx_flags ||
		    vh->vx_vni != vh2->vx_vni) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	pp = eth_gro_receive(head, skb);
	flush = 0;

out:
	skb_gro_remcsum_cleanup(skb, &grc);
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

#ifndef HAVE_UDP_OFFLOAD_ARG_UOFF
static int vxlan_gro_complete(struct sk_buff *skb, int nhoff)
#else
static int vxlan_gro_complete(struct sk_buff *skb, int nhoff,
                              struct udp_offload *uoff)
#endif
{
	/* Sets 'skb->inner_mac_header' since we are always called with
	 * 'skb->encapsulation' set.
	 */
	udp_tunnel_gro_complete(skb, nhoff);

	return eth_gro_complete(skb, nhoff + sizeof(struct vxlanhdr));
}
#endif

/* Notify netdevs that UDP port started listening */
static void vxlan_notify_add_rx_port(struct vxlan_sock *vs)
{
	struct net_device *dev;
	struct sock *sk = vs->sock->sk;
	struct net *net = sock_net(sk);
	sa_family_t sa_family = vxlan_get_sk_family(vs);


	if (sa_family == AF_INET) {
		int err;

		err = udp_add_offload(net, &vs->udp_offloads);
		if (err)
			pr_warn("vxlan: udp_add_offload failed with status %d\n", err);
	}

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
#ifdef HAVE_NDO_ADD_VXLAN_PORT
		__be16 port = inet_sk(sk)->inet_sport;

		if (dev->netdev_ops->ndo_add_vxlan_port)
			dev->netdev_ops->ndo_add_vxlan_port(dev, sa_family,
					port);
#elif defined(HAVE_NDO_UDP_TUNNEL_ADD)
		struct udp_tunnel_info ti;
		if (vs->flags & VXLAN_F_GPE)
			ti.type = UDP_TUNNEL_TYPE_VXLAN_GPE;
		else
			ti.type = UDP_TUNNEL_TYPE_VXLAN;
		ti.sa_family = sa_family;
		ti.port = inet_sk(sk)->inet_sport;

		if (dev->netdev_ops->ndo_udp_tunnel_add)
			dev->netdev_ops->ndo_udp_tunnel_add(dev, &ti);
#endif
	}
	rcu_read_unlock();
}

/* Notify netdevs that UDP port is no more listening */
static void vxlan_notify_del_rx_port(struct vxlan_sock *vs)
{
	struct net_device *dev;
	struct sock *sk = vs->sock->sk;
	struct net *net = sock_net(sk);
	sa_family_t sa_family = vxlan_get_sk_family(vs);

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
#ifdef HAVE_NDO_ADD_VXLAN_PORT
		__be16 port = inet_sk(sk)->inet_sport;

		if (dev->netdev_ops->ndo_del_vxlan_port)
			dev->netdev_ops->ndo_del_vxlan_port(dev, sa_family,
					port);
#elif defined(HAVE_NDO_UDP_TUNNEL_ADD)
		struct udp_tunnel_info ti;
		if (vs->flags & VXLAN_F_GPE)
			ti.type = UDP_TUNNEL_TYPE_VXLAN_GPE;
		else
			ti.type = UDP_TUNNEL_TYPE_VXLAN;
		ti.port = inet_sk(sk)->inet_sport;
		ti.sa_family = sa_family;

		if (dev->netdev_ops->ndo_udp_tunnel_del)
			dev->netdev_ops->ndo_udp_tunnel_del(dev, &ti);
#endif
	}
	rcu_read_unlock();

	if (sa_family == AF_INET) {
		udp_del_offload(&vs->udp_offloads);
	}
}

/* See if multicast group is already in use by other ID */
static bool vxlan_group_used(struct vxlan_net *vn, struct vxlan_dev *dev)
{
	struct vxlan_dev *vxlan;
	struct vxlan_sock *sock4;
	struct vxlan_sock *sock6 = NULL;
	unsigned short family = dev->default_dst.remote_ip.sa.sa_family;

	sock4 = rtnl_dereference(dev->vn4_sock);

	/* The vxlan_sock is only used by dev, leaving group has
	 * no effect on other vxlan devices.
	 */
	if (family == AF_INET && sock4 && atomic_read(&sock4->refcnt) == 1)
		return false;
#if IS_ENABLED(CONFIG_IPV6)
	sock6 = rtnl_dereference(dev->vn6_sock);
	if (family == AF_INET6 && sock6 && atomic_read(&sock6->refcnt) == 1)
		return false;
#endif

	list_for_each_entry(vxlan, &vn->vxlan_list, next) {
		if (!netif_running(vxlan->dev) || vxlan == dev)
			continue;

		if (family == AF_INET &&
		    rtnl_dereference(vxlan->vn4_sock) != sock4)
			continue;
#if IS_ENABLED(CONFIG_IPV6)
		if (family == AF_INET6 &&
		    rtnl_dereference(vxlan->vn6_sock) != sock6)
			continue;
#endif

		if (!vxlan_addr_equal(&vxlan->default_dst.remote_ip,
				      &dev->default_dst.remote_ip))
			continue;

		if (vxlan->default_dst.remote_ifindex !=
		    dev->default_dst.remote_ifindex)
			continue;

		return true;
	}

	return false;
}

static bool __vxlan_sock_release_prep(struct vxlan_sock *vs)
{
	struct vxlan_net *vn;

	if (!vs)
		return false;
	if (!atomic_dec_and_test(&vs->refcnt))
		return false;

	vn = net_generic(sock_net(vs->sock->sk), vxlan_net_id);
	spin_lock(&vn->sock_lock);
	hlist_del_rcu(&vs->hlist);
	vxlan_notify_del_rx_port(vs);
	spin_unlock(&vn->sock_lock);

	return true;
}

static void vxlan_sock_release(struct vxlan_dev *vxlan)
{
	struct vxlan_sock *sock4 = rtnl_dereference(vxlan->vn4_sock);
#if IS_ENABLED(CONFIG_IPV6)
	struct vxlan_sock *sock6 = rtnl_dereference(vxlan->vn6_sock);

	rcu_assign_pointer(vxlan->vn6_sock, NULL);
#endif

	rcu_assign_pointer(vxlan->vn4_sock, NULL);
	synchronize_net();

	if (__vxlan_sock_release_prep(sock4)) {
		udp_tunnel_sock_release(sock4->sock);
		kfree(sock4);
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (__vxlan_sock_release_prep(sock6)) {
		udp_tunnel_sock_release(sock6->sock);
		kfree(sock6);
	}
#endif
}

/* Update multicast group membership when first VNI on
 * multicast address is brought up
 */
static int vxlan_igmp_join(struct vxlan_dev *vxlan)
{
	return -EINVAL;
}

/* Inverse of vxlan_igmp_join when last VNI is brought down */
static int vxlan_igmp_leave(struct vxlan_dev *vxlan)
{
	return -EINVAL;
}

static bool vxlan_remcsum(struct vxlanhdr *unparsed,
			  struct sk_buff *skb, u32 vxflags)
{
#ifndef USE_UPSTREAM_TUNNEL
	return false;
#else
	size_t start, offset;

	if (!(unparsed->vx_flags & VXLAN_HF_RCO) || skb->remcsum_offload)
		goto out;

	start = vxlan_rco_start(unparsed->vx_vni);
	offset = start + vxlan_rco_offset(unparsed->vx_vni);

	if (!pskb_may_pull(skb, offset + sizeof(u16)))
		return false;

	skb_remcsum_process(skb, (void *)(vxlan_hdr(skb) + 1), start, offset,
			    !!(vxflags & VXLAN_F_REMCSUM_NOPARTIAL));
out:
	unparsed->vx_flags &= ~VXLAN_HF_RCO;
	unparsed->vx_vni &= VXLAN_VNI_MASK;
	return true;
#endif
}

static void vxlan_parse_gbp_hdr(struct vxlanhdr *unparsed,
				struct sk_buff *skb, u32 vxflags,
				struct vxlan_metadata *md)
{
	struct vxlanhdr_gbp *gbp = (struct vxlanhdr_gbp *)unparsed;
	struct metadata_dst *tun_dst;

	if (!(unparsed->vx_flags & VXLAN_HF_GBP))
		goto out;

	md->gbp = ntohs(gbp->policy_id);

	tun_dst = (struct metadata_dst *)skb_dst(skb);
	if (tun_dst) {
		tun_dst->u.tun_info.key.tun_flags |= TUNNEL_VXLAN_OPT;
		tun_dst->u.tun_info.options_len = sizeof(*md);
	}
	if (gbp->dont_learn)
		md->gbp |= VXLAN_GBP_DONT_LEARN;

	if (gbp->policy_applied)
		md->gbp |= VXLAN_GBP_POLICY_APPLIED;

	/* In flow-based mode, GBP is carried in dst_metadata */
	if (!(vxflags & VXLAN_F_COLLECT_METADATA))
		skb->mark = md->gbp;
out:
	unparsed->vx_flags &= ~VXLAN_GBP_USED_BITS;
}

static bool vxlan_parse_gpe_hdr(struct vxlanhdr *unparsed,
				__be16 *protocol,
				struct sk_buff *skb, u32 vxflags)
{
	struct vxlanhdr_gpe *gpe = (struct vxlanhdr_gpe *)unparsed;

	/* Need to have Next Protocol set for interfaces in GPE mode. */
	if (!gpe->np_applied)
		return false;
	/* "The initial version is 0. If a receiver does not support the
	 * version indicated it MUST drop the packet.
	 */
	if (gpe->version != 0)
		return false;
	/* "When the O bit is set to 1, the packet is an OAM packet and OAM
	 * processing MUST occur." However, we don't implement OAM
	 * processing, thus drop the packet.
	 */
	if (gpe->oam_flag)
		return false;

	*protocol = tun_p_to_eth_p(gpe->next_protocol);
	if (!*protocol)
		return false;

	unparsed->vx_flags &= ~VXLAN_GPE_USED_BITS;
	return true;
}

static bool vxlan_set_mac(struct vxlan_dev *vxlan,
			  struct vxlan_sock *vs,
			  struct sk_buff *skb)
{
	return true;
}

static bool vxlan_ecn_decapsulate(struct vxlan_sock *vs, void *oiph,
				  struct sk_buff *skb)
{
	int err = 0;

	if (vxlan_get_sk_family(vs) == AF_INET)
		err = IP_ECN_decapsulate(oiph, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else
		err = IP6_ECN_decapsulate(oiph, skb);
#endif
	return err <= 1;
}

/* Callback from net/ipv4/udp.c to receive packets */
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	union {
		struct metadata_dst dst;
		char buf[sizeof(struct metadata_dst) + sizeof(struct vxlan_metadata)];
	} buf;

	struct pcpu_sw_netstats *stats;
	struct vxlan_dev *vxlan;
	struct vxlan_sock *vs;
	struct vxlanhdr unparsed;
	struct vxlan_metadata _md;
	struct vxlan_metadata *md = &_md;
	__be16 protocol = htons(ETH_P_TEB);
	bool raw_proto = false;
	void *oiph;

	/* Need UDP and VXLAN header to be present */
	if (!pskb_may_pull(skb, VXLAN_HLEN))
		goto drop;

	unparsed = *vxlan_hdr(skb);
	/* VNI flag always required to be set */
	if (!(unparsed.vx_flags & VXLAN_HF_VNI)) {
		netdev_dbg(skb->dev, "invalid vxlan flags=%#x vni=%#x\n",
			   ntohl(vxlan_hdr(skb)->vx_flags),
			   ntohl(vxlan_hdr(skb)->vx_vni));
		/* Return non vxlan pkt */
		goto drop;
	}

	unparsed.vx_flags &= ~VXLAN_HF_VNI;
	unparsed.vx_vni &= ~VXLAN_VNI_MASK;

	vs = rcu_dereference_sk_user_data(sk);
	if (!vs)
		goto drop;

#if IS_ENABLED(CONFIG_IPV6)
#ifdef OVS_CHECK_UDP_TUNNEL_ZERO_CSUM
	if (vxlan_get_sk_family(vs) == AF_INET6 &&
	    !udp_hdr(skb)->check &&
	    !(vs->flags & VXLAN_F_UDP_ZERO_CSUM6_RX)) {
		udp6_csum_zero_error(skb);
		goto drop;
	}
#endif
#endif
	vxlan = vxlan_vs_find_vni(vs, vxlan_vni(vxlan_hdr(skb)->vx_vni));
	if (!vxlan)
		goto drop;

	/* For backwards compatibility, only allow reserved fields to be
	 * used by VXLAN extensions if explicitly requested.
	 */
	if (vs->flags & VXLAN_F_GPE) {
		if (!vxlan_parse_gpe_hdr(&unparsed, &protocol, skb, vs->flags))
			goto drop;
		raw_proto = true;
	}

	if (__iptunnel_pull_header(skb, VXLAN_HLEN, protocol, raw_proto,
				   !net_eq(vxlan->net, dev_net(vxlan->dev))))
			goto drop;

	if (vxlan_collect_metadata(vs)) {
		__be32 vni = vxlan_vni(vxlan_hdr(skb)->vx_vni);
		struct metadata_dst *tun_dst;

		tun_dst = &buf.dst;
		ovs_udp_tun_rx_dst(tun_dst, skb,
				   vxlan_get_sk_family(vs), TUNNEL_KEY,
				   vxlan_vni_to_tun_id(vni), sizeof(*md));

		if (!tun_dst)
			goto drop;

		md = ip_tunnel_info_opts(&tun_dst->u.tun_info);

		ovs_skb_dst_set(skb, (struct dst_entry *)tun_dst);
	} else {
		memset(md, 0, sizeof(*md));
	}

	if (vs->flags & VXLAN_F_REMCSUM_RX)
		if (!vxlan_remcsum(&unparsed, skb, vs->flags))
			goto drop;

	if (vs->flags & VXLAN_F_GBP)
		vxlan_parse_gbp_hdr(&unparsed, skb, vs->flags, md);
	/* Note that GBP and GPE can never be active together. This is
	 * ensured in vxlan_dev_configure.
	 */

	if (unparsed.vx_flags || unparsed.vx_vni) {
		/* If there are any unprocessed flags remaining treat
		 * this as a malformed packet. This behavior diverges from
		 * VXLAN RFC (RFC7348) which stipulates that bits in reserved
		 * in reserved fields are to be ignored. The approach here
		 * maintains compatibility with previous stack code, and also
		 * is more robust and provides a little more security in
		 * adding extensions to VXLAN.
		 */
		goto drop;
	}

	if (!raw_proto) {
		if (!vxlan_set_mac(vxlan, vs, skb))
			goto drop;
		skb_reset_mac_header(skb);
		skb->protocol = eth_type_trans(skb, vxlan->dev);
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
	} else {
		skb_reset_mac_header(skb);
		skb->dev = vxlan->dev;
		skb->pkt_type = PACKET_HOST;
	}

	oiph = skb_network_header(skb);
	skb_reset_network_header(skb);

	if (!vxlan_ecn_decapsulate(vs, oiph, skb)) {
		++vxlan->dev->stats.rx_frame_errors;
		++vxlan->dev->stats.rx_errors;
		goto drop;
	}

	stats = this_cpu_ptr(vxlan->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netdev_port_receive(skb, skb_tunnel_info(skb));
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;
}

static void vxlan_build_gbp_hdr(struct vxlanhdr *vxh, u32 vxflags,
				struct vxlan_metadata *md)
{
	struct vxlanhdr_gbp *gbp;

	if (!md->gbp)
		return;

	gbp = (struct vxlanhdr_gbp *)vxh;
	vxh->vx_flags |= VXLAN_HF_GBP;

	if (md->gbp & VXLAN_GBP_DONT_LEARN)
		gbp->dont_learn = 1;

	if (md->gbp & VXLAN_GBP_POLICY_APPLIED)
		gbp->policy_applied = 1;

	gbp->policy_id = htons(md->gbp & VXLAN_GBP_ID_MASK);
}

static int vxlan_build_gpe_hdr(struct vxlanhdr *vxh, u32 vxflags,
			       __be16 protocol)
{
	struct vxlanhdr_gpe *gpe = (struct vxlanhdr_gpe *)vxh;

	gpe->np_applied = 1;
	gpe->next_protocol = tun_p_from_eth_p(protocol);
	if (!gpe->next_protocol)
		return -EPFNOSUPPORT;
	return 0;
}

static int vxlan_build_skb(struct sk_buff *skb, struct dst_entry *dst,
			   int iphdr_len, __be32 vni,
			   struct vxlan_metadata *md, u32 vxflags,
			   bool udp_sum)
{
	void (*fix_segment)(struct sk_buff *);
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	int type = udp_sum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
	__be16 inner_protocol = htons(ETH_P_TEB);

	if ((vxflags & VXLAN_F_REMCSUM_TX) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		int csum_start = skb_checksum_start_offset(skb);

		if (csum_start <= VXLAN_MAX_REMCSUM_START &&
		    !(csum_start & VXLAN_RCO_SHIFT_MASK) &&
		    (skb->csum_offset == offsetof(struct udphdr, check) ||
		     skb->csum_offset == offsetof(struct tcphdr, check)))
			type |= SKB_GSO_TUNNEL_REMCSUM;
	}

	min_headroom = LL_RESERVED_SPACE(dst->dev) + dst->header_len
			+ VXLAN_HLEN + iphdr_len
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		goto out_free;

	if (skb_vlan_tag_present(skb))
		skb = __vlan_hwaccel_push_inside(skb);
	if (WARN_ON(!skb))
		return -ENOMEM;

	type |= udp_sum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
#ifndef USE_UPSTREAM_TUNNEL_GSO
	fix_segment = !udp_sum ? ovs_udp_gso : ovs_udp_csum_gso;
#else
	fix_segment = NULL;
#endif
	err = ovs_iptunnel_handle_offloads(skb, type, fix_segment);
	if (err)
		goto out_free;

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vni);

	if (type & SKB_GSO_TUNNEL_REMCSUM) {
		unsigned int start;

		start = skb_checksum_start_offset(skb) - sizeof(struct vxlanhdr);
		vxh->vx_vni |= vxlan_compute_rco(start, skb->csum_offset);
		vxh->vx_flags |= VXLAN_HF_RCO;

		if (!skb_is_gso(skb)) {
			skb->ip_summed = CHECKSUM_NONE;
			skb->encapsulation = 0;
		}
	}

	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);
	if (vxflags & VXLAN_F_GPE) {
		err = vxlan_build_gpe_hdr(vxh, vxflags, skb->protocol);
		if (err < 0)
			goto out_free;
		inner_protocol = skb->protocol;
	}

	ovs_skb_set_inner_protocol(skb, inner_protocol);
	return 0;

out_free:
	kfree_skb(skb);
	return err;
}

static struct rtable *vxlan_get_route(struct vxlan_dev *vxlan,
				      struct sk_buff *skb, int oif, u8 tos,
				      __be32 daddr, __be32 *saddr,
				      __be16 dport, __be16 sport,
				      struct dst_cache *dst_cache,
				      const struct ip_tunnel_info *info)
{
	bool use_cache = (dst_cache && ip_tunnel_dst_cache_usable(skb, info));
	struct rtable *rt = NULL;
	struct flowi4 fl4;

	if (tos && !info)
		use_cache = false;
	if (use_cache) {
		rt = dst_cache_get_ip4(dst_cache, saddr);
		if (rt)
			return rt;
	}

	memset(&fl4, 0, sizeof(fl4));
	fl4.flowi4_oif = oif;
	fl4.flowi4_tos = RT_TOS(tos);
	fl4.flowi4_mark = skb->mark;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.daddr = daddr;
	fl4.saddr = *saddr;
	fl4.fl4_dport = dport;
	fl4.fl4_sport = sport;

	rt = ip_route_output_key(vxlan->net, &fl4);
	if (!IS_ERR(rt)) {
		*saddr = fl4.saddr;
		if (use_cache)
			dst_cache_set_ip4(dst_cache, &rt->dst, fl4.saddr);
	}
	return rt;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct dst_entry *vxlan6_get_route(struct vxlan_dev *vxlan,
					  struct sk_buff *skb, int oif, u8 tos,
					  __be32 label,
					  const struct in6_addr *daddr,
					  struct in6_addr *saddr,
					  __be16 dport, __be16 sport,
					  struct dst_cache *dst_cache,
					  const struct ip_tunnel_info *info)
{
	struct vxlan_sock *sock6 = rcu_dereference(vxlan->vn6_sock);
	bool use_cache = (dst_cache && ip_tunnel_dst_cache_usable(skb, info));
	struct dst_entry *ndst;
	struct flowi6 fl6;
#if !defined(HAVE_IPV6_STUB_WITH_DST_ENTRY) || \
    !defined(HAVE_IPV6_DST_LOOKUP_FLOW)
	int err;
#endif

	if (!sock6)
		return ERR_PTR(-EIO);

	if (tos && !info)
		use_cache = false;
	if (use_cache) {
		ndst = dst_cache_get_ip6(dst_cache, saddr);
		if (ndst)
			return ndst;
	}

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = oif;
	fl6.daddr = *daddr;
	fl6.saddr = *saddr;
	fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tos), label);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.fl6_dport = dport;
	fl6.fl6_sport = sport;

#if defined(HAVE_IPV6_STUB_WITH_DST_ENTRY) && defined(HAVE_IPV6_DST_LOOKUP_FLOW)
#ifdef HAVE_IPV6_DST_LOOKUP_FLOW_NET
	ndst = ipv6_stub->ipv6_dst_lookup_flow(vxlan->net, sock6->sock->sk,
					       &fl6, NULL);
#else
	ndst = ipv6_stub->ipv6_dst_lookup_flow(sock6->sock->sk, &fl6, NULL);
#endif
	if (unlikely(IS_ERR(ndst))) {
#elif defined(HAVE_IPV6_DST_LOOKUP_FLOW_NET)
	err = ipv6_stub->ipv6_dst_lookup_flow(vxlan->net, sock6->sock->sk,
					      &ndst, &fl6);
#elif defined(HAVE_IPV6_DST_LOOKUP_FLOW)
	err = ipv6_stub->ipv6_dst_lookup_flow(sock6->sock->sk, &ndst, &fl6);
#elif defined(HAVE_IPV6_DST_LOOKUP_NET)
	err = ipv6_stub->ipv6_dst_lookup(vxlan->net, sock6->sock->sk,
					 &ndst, &fl6);
#elif defined(HAVE_IPV6_STUB)
	err = ipv6_stub->ipv6_dst_lookup(vxlan->vn6_sock->sock->sk,
					 &ndst, &fl6);
#else
	err = ip6_dst_lookup(vxlan->vn6_sock->sock->sk, &ndst, &fl6);
#endif
#if defined(HAVE_IPV6_STUB_WITH_DST_ENTRY) && defined(HAVE_IPV6_DST_LOOKUP_FLOW)
		return ERR_PTR(-ENETUNREACH);
	}
#else
	if (err < 0)
		return ERR_PTR(err);
#endif

	*saddr = fl6.saddr;
	if (use_cache)
		dst_cache_set_ip6(dst_cache, ndst, saddr);
	return ndst;
}
#endif

/* Bypass encapsulation if the destination is local */
static void vxlan_encap_bypass(struct sk_buff *skb, struct vxlan_dev *src_vxlan,
			       struct vxlan_dev *dst_vxlan)
{
	skb->dev->stats.rx_dropped++;
	kfree_skb(skb);
}

static void vxlan_xmit_one(struct sk_buff *skb, struct net_device *dev,
			   struct vxlan_rdst *rdst, bool did_rsc)
{
	struct dst_cache *dst_cache;
	struct ip_tunnel_info *info;
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct sock *sk;
	struct rtable *rt = NULL;
	const struct iphdr *old_iph;
	union vxlan_addr *dst;
	union vxlan_addr remote_ip, local_ip;
	union vxlan_addr *src;
	struct vxlan_metadata _md;
	struct vxlan_metadata *md = &_md;
	__be16 src_port = 0, dst_port;
	__be32 vni, label;
	__be16 df = 0;
	__u8 tos, ttl;
	int err;
	u32 flags = vxlan->flags;
	bool udp_sum = false;
	bool xnet = !net_eq(vxlan->net, dev_net(vxlan->dev));

	info = skb_tunnel_info(skb);

	if (rdst) {
		dst_port = rdst->remote_port ? rdst->remote_port : vxlan->cfg.dst_port;
		vni = rdst->remote_vni;
		dst = &rdst->remote_ip;
		src = &vxlan->cfg.saddr;
		dst_cache = &rdst->dst_cache;
	} else {
		if (!info) {
			WARN_ONCE(1, "%s: Missing encapsulation instructions\n",
				  dev->name);
			goto drop;
		}
		dst_port = info->key.tp_dst ? : vxlan->cfg.dst_port;
		vni = vxlan_tun_id_to_vni(info->key.tun_id);
		remote_ip.sa.sa_family = ip_tunnel_info_af(info);
		if (remote_ip.sa.sa_family == AF_INET) {
			remote_ip.sin.sin_addr.s_addr = info->key.u.ipv4.dst;
			local_ip.sin.sin_addr.s_addr = info->key.u.ipv4.src;
		} else {
			remote_ip.sin6.sin6_addr = info->key.u.ipv6.dst;
			local_ip.sin6.sin6_addr = info->key.u.ipv6.src;
		}
		dst = &remote_ip;
		src = &local_ip;
		dst_cache = &info->dst_cache;
	}

	if (vxlan_addr_any(dst)) {
		if (did_rsc) {
			/* short-circuited back to local bridge */
			vxlan_encap_bypass(skb, vxlan, vxlan);
			return;
		}
		goto drop;
	}

	old_iph = ip_hdr(skb);

	ttl = vxlan->cfg.ttl;
	if (!ttl && vxlan_addr_multicast(dst))
		ttl = 1;

	tos = vxlan->cfg.tos;
	if (tos == 1)
		tos = ip_tunnel_get_dsfield(old_iph, skb);

	label = vxlan->cfg.label;
	src_port = udp_flow_src_port(dev_net(dev), skb, vxlan->cfg.port_min,
				     vxlan->cfg.port_max, true);

	if (info) {
		ttl = info->key.ttl;
		tos = info->key.tos;
		label = info->key.label;
		udp_sum = !!(info->key.tun_flags & TUNNEL_CSUM);

		if (info->options_len &&
		    info->key.tun_flags & TUNNEL_VXLAN_OPT)
			md = ip_tunnel_info_opts(info);
	} else {
		md->gbp = skb->mark;
	}

	if (dst->sa.sa_family == AF_INET) {
		struct vxlan_sock *sock4 = rcu_dereference(vxlan->vn4_sock);

		if (!sock4)
			goto drop;
		sk = sock4->sock->sk;

		rt = vxlan_get_route(vxlan, skb,
				     rdst ? rdst->remote_ifindex : 0, tos,
				     dst->sin.sin_addr.s_addr,
				     &src->sin.sin_addr.s_addr,
				     dst_port, src_port,
				     dst_cache, info);
		if (IS_ERR(rt)) {
			netdev_dbg(dev, "no route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}

		if (rt->dst.dev == dev) {
			netdev_dbg(dev, "circular route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.collisions++;
			goto rt_tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		if (!info && rt->rt_flags & RTCF_LOCAL &&
		    !(rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			ip_rt_put(rt);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			vxlan_encap_bypass(skb, vxlan, dst_vxlan);
			return;
		}

		if (!info)
			udp_sum = !(flags & VXLAN_F_UDP_ZERO_CSUM_TX);
		else if (info->key.tun_flags & TUNNEL_DONT_FRAGMENT)
			df = htons(IP_DF);

		tos = ip_tunnel_ecn_encap(tos, old_iph, skb);
		ttl = ttl ? : ip4_dst_hoplimit(&rt->dst);
		err = vxlan_build_skb(skb, &rt->dst, sizeof(struct iphdr),
				      vni, md, flags, udp_sum);
		if (err < 0)
			goto xmit_tx_error;

		udp_tunnel_xmit_skb(rt, sk, skb, src->sin.sin_addr.s_addr,
				    dst->sin.sin_addr.s_addr, tos, ttl, df,
				    src_port, dst_port, xnet, !udp_sum);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct vxlan_sock *sock6 = rcu_dereference(vxlan->vn6_sock);
		struct dst_entry *ndst;
		u32 rt6i_flags;

		if (!sock6)
			goto drop;
		sk = sock6->sock->sk;

		ndst = vxlan6_get_route(vxlan, skb,
					rdst ? rdst->remote_ifindex : 0, tos,
					label, &dst->sin6.sin6_addr,
					&src->sin6.sin6_addr,
					dst_port, src_port,
					dst_cache, info);
		if (IS_ERR(ndst)) {
			netdev_dbg(dev, "no route to %pI6\n",
				   &dst->sin6.sin6_addr);
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}

		if (ndst->dev == dev) {
			netdev_dbg(dev, "circular route to %pI6\n",
				   &dst->sin6.sin6_addr);
			dst_release(ndst);
			dev->stats.collisions++;
			goto tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		rt6i_flags = ((struct rt6_info *)ndst)->rt6i_flags;
		if (!info && rt6i_flags & RTF_LOCAL &&
		    !(rt6i_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			dst_release(ndst);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			vxlan_encap_bypass(skb, vxlan, dst_vxlan);
			return;
		}

		if (!info)
			udp_sum = !(flags & VXLAN_F_UDP_ZERO_CSUM6_TX);

		tos = ip_tunnel_ecn_encap(tos, old_iph, skb);
		ttl = ttl ? : ip6_dst_hoplimit(ndst);
		skb_scrub_packet(skb, xnet);
		err = vxlan_build_skb(skb, ndst, sizeof(struct ipv6hdr),
				      vni, md, flags, udp_sum);
		if (err < 0) {
			dst_release(ndst);
			return;
		}
		udp_tunnel6_xmit_skb(ndst, sk, skb, dev,
				     &src->sin6.sin6_addr,
				     &dst->sin6.sin6_addr, tos, ttl,
				     label, src_port, dst_port, !udp_sum);
#endif
	}

	return;

drop:
	dev->stats.tx_dropped++;
	goto tx_free;

xmit_tx_error:
	/* skb is already freed. */
	skb = NULL;
rt_tx_error:
	ip_rt_put(rt);
tx_error:
	dev->stats.tx_errors++;
tx_free:
	dev_kfree_skb(skb);
}

/* Transmit local packets over Vxlan
 *
 * Outer IP header inherits ECN and DF from inner header.
 * Outer UDP destination is the VXLAN assigned port.
 *           source port is based on hash of flow
 */
netdev_tx_t rpl_vxlan_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct vxlan_dev *vxlan = netdev_priv(dev);
	const struct ip_tunnel_info *info;

	info = skb_tunnel_info(skb);
	skb_reset_mac_header(skb);
	if (vxlan->flags & VXLAN_F_COLLECT_METADATA) {
		if (info && info->mode & IP_TUNNEL_INFO_TX) {
			vxlan_xmit_one(skb, dev, NULL, false);
			return NETDEV_TX_OK;
		}
	}

	dev->stats.tx_dropped++;
	kfree_skb(skb);
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL_GPL(rpl_vxlan_xmit);

/* Walk the forwarding table and purge stale entries */
#ifdef HAVE_INIT_TIMER_DEFERRABLE
static void vxlan_cleanup(unsigned long arg)
{
	struct vxlan_dev *vxlan = (struct vxlan_dev *) arg;
#else
static void vxlan_cleanup(struct timer_list *t)
{
       struct vxlan_dev *vxlan = from_timer(vxlan, t, age_timer);
#endif
	unsigned long next_timer = jiffies + FDB_AGE_INTERVAL;
	unsigned int h;

	if (!netif_running(vxlan->dev))
		return;

	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct hlist_node *p, *n;

		spin_lock_bh(&vxlan->hash_lock);
		hlist_for_each_safe(p, n, &vxlan->fdb_head[h]) {
			struct vxlan_fdb *f
				= container_of(p, struct vxlan_fdb, hlist);
			unsigned long timeout;

			if (f->state & NUD_PERMANENT)
				continue;

			timeout = f->used + vxlan->cfg.age_interval * HZ;
			if (time_before_eq(timeout, jiffies)) {
				netdev_dbg(vxlan->dev,
					   "garbage collect %pM\n",
					   f->eth_addr);
				f->state = NUD_STALE;
				vxlan_fdb_destroy(vxlan, f);
			} else if (time_before(timeout, next_timer))
				next_timer = timeout;
		}
		spin_unlock_bh(&vxlan->hash_lock);
	}

	mod_timer(&vxlan->age_timer, next_timer);
}

static void vxlan_vs_add_dev(struct vxlan_sock *vs, struct vxlan_dev *vxlan)
{
	struct vxlan_net *vn = net_generic(vxlan->net, vxlan_net_id);
	__be32 vni = vxlan->default_dst.remote_vni;

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vxlan->hlist, vni_head(vs, vni));
	spin_unlock(&vn->sock_lock);
}

/* Setup stats when device is created */
static int vxlan_init(struct net_device *dev)
{
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void vxlan_fdb_delete_default(struct vxlan_dev *vxlan)
{
}

static void vxlan_uninit(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);

	vxlan_fdb_delete_default(vxlan);

	free_percpu(dev->tstats);
}

/* Start ageing timer and join group when device is brought up */
static int vxlan_open(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	int ret;

	ret = vxlan_sock_add(vxlan);
	if (ret < 0)
		return ret;

	if (vxlan_addr_multicast(&vxlan->default_dst.remote_ip)) {
		ret = vxlan_igmp_join(vxlan);
		if (ret == -EADDRINUSE)
			ret = 0;
		if (ret) {
			vxlan_sock_release(vxlan);
			return ret;
		}
	}

	if (vxlan->cfg.age_interval)
		mod_timer(&vxlan->age_timer, jiffies + FDB_AGE_INTERVAL);

	return ret;
}

/* Purge the forwarding table */
static void vxlan_flush(struct vxlan_dev *vxlan)
{
	unsigned int h;

	spin_lock_bh(&vxlan->hash_lock);
	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct hlist_node *p, *n;
		hlist_for_each_safe(p, n, &vxlan->fdb_head[h]) {
			struct vxlan_fdb *f
				= container_of(p, struct vxlan_fdb, hlist);
			/* the all_zeros_mac entry is deleted at vxlan_uninit */
			if (!is_zero_ether_addr(f->eth_addr))
				vxlan_fdb_destroy(vxlan, f);
		}
	}
	spin_unlock_bh(&vxlan->hash_lock);
}

/* Cleanup timer and forwarding table on shutdown */
static int vxlan_stop(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_net *vn = net_generic(vxlan->net, vxlan_net_id);
	int ret = 0;

	if (vxlan_addr_multicast(&vxlan->default_dst.remote_ip) &&
	    !vxlan_group_used(vn, vxlan))
		ret = vxlan_igmp_leave(vxlan);

	del_timer_sync(&vxlan->age_timer);

	vxlan_flush(vxlan);
	vxlan_sock_release(vxlan);

	return ret;
}

/* Stub, nothing needs to be done. */
static void vxlan_set_multicast_list(struct net_device *dev)
{
}

static int __vxlan_change_mtu(struct net_device *dev,
			      struct net_device *lowerdev,
			      struct vxlan_rdst *dst, int new_mtu, bool strict)
{
	int max_mtu = IP_MAX_MTU;

	if (lowerdev)
		max_mtu = lowerdev->mtu;

	if (dst->remote_ip.sa.sa_family == AF_INET6)
		max_mtu -= VXLAN6_HEADROOM;
	else
		max_mtu -= VXLAN_HEADROOM;

	if (new_mtu < 68)
		return -EINVAL;

	if (new_mtu > max_mtu) {
		if (strict)
			return -EINVAL;

		new_mtu = max_mtu;
	}

	dev->mtu = new_mtu;
	return 0;
}

static int vxlan_change_mtu(struct net_device *dev, int new_mtu)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_rdst *dst = &vxlan->default_dst;
	struct net_device *lowerdev = __dev_get_by_index(vxlan->net,
							 dst->remote_ifindex);
	return __vxlan_change_mtu(dev, lowerdev, dst, new_mtu, true);
}

int ovs_vxlan_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	__be16 sport, dport;

	sport = udp_flow_src_port(dev_net(dev), skb, vxlan->cfg.port_min,
				  vxlan->cfg.port_max, true);
	dport = info->key.tp_dst ? : vxlan->cfg.dst_port;

	if (ip_tunnel_info_af(info) == AF_INET) {
		struct vxlan_sock *sock4 = rcu_dereference(vxlan->vn4_sock);
		struct rtable *rt;

		if (!sock4)
			return -EINVAL;
		rt = vxlan_get_route(vxlan, skb, 0, info->key.tos,
				     info->key.u.ipv4.dst,
				     &info->key.u.ipv4.src,
				     dport, sport, NULL, info);
		if (IS_ERR(rt))
			return PTR_ERR(rt);
		ip_rt_put(rt);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		struct dst_entry *ndst;

		ndst = vxlan6_get_route(vxlan, skb, 0, info->key.tos,
					info->key.label, &info->key.u.ipv6.dst,
					&info->key.u.ipv6.src,
					dport, sport, NULL, info);
		if (IS_ERR(ndst))
			return PTR_ERR(ndst);
		dst_release(ndst);
#else /* !CONFIG_IPV6 */
		return -EPFNOSUPPORT;
#endif
	}
	info->key.tp_src = sport;
	info->key.tp_dst = dport;
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_vxlan_fill_metadata_dst);

static netdev_tx_t vxlan_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */

	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static const struct net_device_ops vxlan_netdev_ether_ops = {
	.ndo_init		= vxlan_init,
	.ndo_uninit		= vxlan_uninit,
	.ndo_open		= vxlan_open,
	.ndo_stop		= vxlan_stop,
	.ndo_start_xmit		= vxlan_dev_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_set_rx_mode	= vxlan_set_multicast_list,
#ifdef	HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = vxlan_change_mtu,
#else
	.ndo_change_mtu		= vxlan_change_mtu,
#endif
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst	= ovs_vxlan_fill_metadata_dst,
#endif
};

static const struct net_device_ops vxlan_netdev_raw_ops = {
	.ndo_init		= vxlan_init,
	.ndo_uninit		= vxlan_uninit,
	.ndo_open		= vxlan_open,
	.ndo_stop		= vxlan_stop,
	.ndo_start_xmit		= vxlan_dev_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#ifdef	HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = vxlan_change_mtu,
#else
	.ndo_change_mtu		= vxlan_change_mtu,
#endif
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst	= ovs_vxlan_fill_metadata_dst,
#endif
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type vxlan_type = {
	.name = "vxlan",
};

/* Calls the ndo_add_vxlan_port or ndo_udp_tunnel_add of the caller
 * in order to supply the listening VXLAN udp ports. Callers are
 * expected to implement the ndo_add_vxlan_port.
 */
static void vxlan_push_rx_ports(struct net_device *dev)
{
#ifdef HAVE_NDO_ADD_VXLAN_PORT
	struct vxlan_sock *vs;
	struct net *net = dev_net(dev);
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	sa_family_t sa_family;
	__be16 port;
	unsigned int i;

	if (!dev->netdev_ops->ndo_add_vxlan_port)
		return;

	spin_lock(&vn->sock_lock);
	for (i = 0; i < PORT_HASH_SIZE; ++i) {
		hlist_for_each_entry_rcu(vs, &vn->sock_list[i], hlist) {
			port = inet_sk(vs->sock->sk)->inet_sport;
			sa_family = vxlan_get_sk_family(vs);
			dev->netdev_ops->ndo_add_vxlan_port(dev, sa_family,
							    port);
		}
	}
	spin_unlock(&vn->sock_lock);
#elif defined(HAVE_NDO_UDP_TUNNEL_ADD)
	struct vxlan_sock *vs;
	struct net *net = dev_net(dev);
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	unsigned int i;

	if (!dev->netdev_ops->ndo_udp_tunnel_add)
		return;

	spin_lock(&vn->sock_lock);
	for (i = 0; i < PORT_HASH_SIZE; ++i) {
		hlist_for_each_entry_rcu(vs, &vn->sock_list[i], hlist) {
			struct udp_tunnel_info ti;
			if (vs->flags & VXLAN_F_GPE)
				ti.type = UDP_TUNNEL_TYPE_VXLAN_GPE;
			else
				ti.type = UDP_TUNNEL_TYPE_VXLAN;
			ti.port = inet_sk(vs->sock->sk)->inet_sport;
			ti.sa_family = vxlan_get_sk_family(vs);

			dev->netdev_ops->ndo_udp_tunnel_add(dev, &ti);
		}
	}
	spin_unlock(&vn->sock_lock);
#endif
}

/* Initialize the device structure. */
static void vxlan_setup(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	unsigned int h;

	eth_hw_addr_random(dev);
	ether_setup(dev);

#ifndef HAVE_NEEDS_FREE_NETDEV
	dev->destructor = free_netdev;
#else
	dev->needs_free_netdev = true;
#endif
	SET_NETDEV_DEVTYPE(dev, &vxlan_type);

	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features   |= NETIF_F_RXCSUM;
	dev->features   |= NETIF_F_GSO_SOFTWARE;

	dev->vlan_features = dev->features;
	dev->features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
#if 0
	netif_keep_dst(dev);
#endif
	dev->priv_flags |= IFF_NO_QUEUE;

	INIT_LIST_HEAD(&vxlan->next);
	spin_lock_init(&vxlan->hash_lock);

#ifdef HAVE_INIT_TIMER_DEFERRABLE
	init_timer_deferrable(&vxlan->age_timer);
	vxlan->age_timer.function = vxlan_cleanup;
	vxlan->age_timer.data = (unsigned long) vxlan;
#else
	timer_setup(&vxlan->age_timer, vxlan_cleanup, TIMER_DEFERRABLE);
#endif

	vxlan->cfg.dst_port = htons(vxlan_port);

	vxlan->dev = dev;

	for (h = 0; h < FDB_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vxlan->fdb_head[h]);
}

static void vxlan_ether_setup(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->netdev_ops = &vxlan_netdev_ether_ops;
}

static void vxlan_raw_setup(struct net_device *dev)
{
	dev->header_ops = NULL;
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->netdev_ops = &vxlan_netdev_raw_ops;
}

static const struct nla_policy vxlan_policy[IFLA_VXLAN_MAX + 1] = {
	[IFLA_VXLAN_ID]		= { .type = NLA_U32 },
	[IFLA_VXLAN_GROUP]	= { .len = sizeof_field(struct iphdr, daddr) },
	[IFLA_VXLAN_GROUP6]	= { .len = sizeof(struct in6_addr) },
	[IFLA_VXLAN_LINK]	= { .type = NLA_U32 },
	[IFLA_VXLAN_LOCAL]	= { .len = sizeof_field(struct iphdr, saddr) },
	[IFLA_VXLAN_LOCAL6]	= { .len = sizeof(struct in6_addr) },
	[IFLA_VXLAN_TOS]	= { .type = NLA_U8 },
	[IFLA_VXLAN_TTL]	= { .type = NLA_U8 },
	[IFLA_VXLAN_LABEL]	= { .type = NLA_U32 },
	[IFLA_VXLAN_LEARNING]	= { .type = NLA_U8 },
	[IFLA_VXLAN_AGEING]	= { .type = NLA_U32 },
	[IFLA_VXLAN_LIMIT]	= { .type = NLA_U32 },
	[IFLA_VXLAN_PORT_RANGE] = { .len  = sizeof(struct ifla_vxlan_port_range) },
	[IFLA_VXLAN_PROXY]	= { .type = NLA_U8 },
	[IFLA_VXLAN_RSC]	= { .type = NLA_U8 },
	[IFLA_VXLAN_L2MISS]	= { .type = NLA_U8 },
	[IFLA_VXLAN_L3MISS]	= { .type = NLA_U8 },
	[IFLA_VXLAN_COLLECT_METADATA]	= { .type = NLA_U8 },
	[IFLA_VXLAN_PORT]	= { .type = NLA_U16 },
	[IFLA_VXLAN_UDP_CSUM]	= { .type = NLA_U8 },
	[IFLA_VXLAN_UDP_ZERO_CSUM6_TX]	= { .type = NLA_U8 },
	[IFLA_VXLAN_UDP_ZERO_CSUM6_RX]	= { .type = NLA_U8 },
	[IFLA_VXLAN_REMCSUM_TX]	= { .type = NLA_U8 },
	[IFLA_VXLAN_REMCSUM_RX]	= { .type = NLA_U8 },
	[IFLA_VXLAN_GBP]	= { .type = NLA_FLAG, },
	[IFLA_VXLAN_GPE]	= { .type = NLA_FLAG, },
	[IFLA_VXLAN_REMCSUM_NOPARTIAL]	= { .type = NLA_FLAG },
};

#ifdef HAVE_RTNLOP_VALIDATE_WITH_EXTACK
static int vxlan_validate(struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
#else
static int vxlan_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			pr_debug("invalid link address (not ethernet)\n");
			return -EINVAL;
		}

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			pr_debug("invalid all zero ethernet address\n");
			return -EADDRNOTAVAIL;
		}
	}

	if (!data)
		return -EINVAL;

	if (data[IFLA_VXLAN_ID]) {
		__u32 id = nla_get_u32(data[IFLA_VXLAN_ID]);
		if (id >= VXLAN_VID_MASK)
			return -ERANGE;
	}

	if (data[IFLA_VXLAN_PORT_RANGE]) {
		const struct ifla_vxlan_port_range *p
			= nla_data(data[IFLA_VXLAN_PORT_RANGE]);

		if (ntohs(p->high) < ntohs(p->low)) {
			pr_debug("port range %u .. %u not valid\n",
				 ntohs(p->low), ntohs(p->high));
			return -EINVAL;
		}
	}

	return 0;
}

static void vxlan_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->version, VXLAN_VERSION, sizeof(drvinfo->version));
	strlcpy(drvinfo->driver, "vxlan", sizeof(drvinfo->driver));
}

static const struct ethtool_ops vxlan_ethtool_ops = {
	.get_drvinfo	= vxlan_get_drvinfo,
	.get_link	= ethtool_op_get_link,
};

static struct socket *vxlan_create_sock(struct net *net, bool ipv6,
					__be16 port, u32 flags)
{
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	if (ipv6) {
		udp_conf.family = AF_INET6;
		udp_conf.use_udp6_rx_checksums =
		    !(flags & VXLAN_F_UDP_ZERO_CSUM6_RX);
		udp_conf.ipv6_v6only = 1;
	} else {
		udp_conf.family = AF_INET;
	}

	udp_conf.local_udp_port = port;

	/* Open UDP socket */
	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	return sock;
}

/* Create new listen socket if needed */
static struct vxlan_sock *vxlan_socket_create(struct net *net, bool ipv6,
					      __be16 port, u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct socket *sock;
	unsigned int h;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs)
		return ERR_PTR(-ENOMEM);

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vs->vni_list[h]);

	sock = vxlan_create_sock(net, ipv6, port, flags);
	if (IS_ERR(sock)) {
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	atomic_set(&vs->refcnt, 1);
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

#ifdef HAVE_UDP_OFFLOAD
	vs->udp_offloads.port = port;
	vs->udp_offloads.callbacks.gro_receive  = vxlan_gro_receive;
	vs->udp_offloads.callbacks.gro_complete = vxlan_gro_complete;
#endif

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));
	vxlan_notify_add_rx_port(vs);
	spin_unlock(&vn->sock_lock);

	/* Mark socket as an encapsulation socket. */
	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_rcv;
	tunnel_cfg.encap_destroy = NULL;
#ifdef HAVE_UDP_TUNNEL_SOCK_CFG_GRO_RECEIVE
	tunnel_cfg.gro_receive = vxlan_gro_receive;
	tunnel_cfg.gro_complete = vxlan_gro_complete;
#endif
	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return vs;
}

static int __vxlan_sock_add(struct vxlan_dev *vxlan, bool ipv6)
{
	struct vxlan_net *vn = net_generic(vxlan->net, vxlan_net_id);
	struct vxlan_sock *vs = NULL;

	if (!vxlan->cfg.no_share) {
		spin_lock(&vn->sock_lock);
		vs = vxlan_find_sock(vxlan->net, ipv6 ? AF_INET6 : AF_INET,
				     vxlan->cfg.dst_port, vxlan->flags);
		if (vs && !atomic_add_unless(&vs->refcnt, 1, 0)) {
			spin_unlock(&vn->sock_lock);
			return -EBUSY;
		}
		spin_unlock(&vn->sock_lock);
	}
	if (!vs)
		vs = vxlan_socket_create(vxlan->net, ipv6,
					 vxlan->cfg.dst_port, vxlan->flags);
	if (IS_ERR(vs))
		return PTR_ERR(vs);
#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6)
		rcu_assign_pointer(vxlan->vn6_sock, vs);
	else
#endif
		rcu_assign_pointer(vxlan->vn4_sock, vs);
	vxlan_vs_add_dev(vs, vxlan);
	return 0;
}

static int vxlan_sock_add(struct vxlan_dev *vxlan)
{
	bool metadata = vxlan->flags & VXLAN_F_COLLECT_METADATA;
	bool ipv6 = vxlan->flags & VXLAN_F_IPV6 || metadata;
	bool ipv4 = !ipv6 || metadata;
	int ret = 0;

	RCU_INIT_POINTER(vxlan->vn4_sock, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	RCU_INIT_POINTER(vxlan->vn6_sock, NULL);
	if (ipv6) {
		ret = __vxlan_sock_add(vxlan, true);
		if (ret < 0 && ret != -EAFNOSUPPORT)
			ipv4 = false;
	}
#endif
	if (ipv4)
		ret = __vxlan_sock_add(vxlan, false);
	if (ret < 0)
		vxlan_sock_release(vxlan);
	return ret;
}

static int vxlan_dev_configure(struct net *src_net, struct net_device *dev,
			       struct vxlan_config *conf)
{
	struct vxlan_net *vn = net_generic(src_net, vxlan_net_id);
	struct vxlan_dev *vxlan = netdev_priv(dev), *tmp;
	struct vxlan_rdst *dst = &vxlan->default_dst;
	unsigned short needed_headroom = ETH_HLEN;
	int err;
	bool use_ipv6 = false;
	__be16 default_port = vxlan->cfg.dst_port;
	struct net_device *lowerdev = NULL;

	if (conf->flags & VXLAN_F_GPE) {
		if (conf->flags & ~VXLAN_F_ALLOWED_GPE)
			return -EINVAL;
		/* For now, allow GPE only together with COLLECT_METADATA.
		 * This can be relaxed later; in such case, the other side
		 * of the PtP link will have to be provided.
		 */
		if (!(conf->flags & VXLAN_F_COLLECT_METADATA))
			return -EINVAL;

		vxlan_raw_setup(dev);
	} else {
		vxlan_ether_setup(dev);
	}

	vxlan->net = src_net;

	dst->remote_vni = conf->vni;

	memcpy(&dst->remote_ip, &conf->remote_ip, sizeof(conf->remote_ip));

	/* Unless IPv6 is explicitly requested, assume IPv4 */
	if (!dst->remote_ip.sa.sa_family)
		dst->remote_ip.sa.sa_family = AF_INET;

	if (dst->remote_ip.sa.sa_family == AF_INET6 ||
	    vxlan->cfg.saddr.sa.sa_family == AF_INET6) {
		if (!IS_ENABLED(CONFIG_IPV6))
			return -EPFNOSUPPORT;
		use_ipv6 = true;
		vxlan->flags |= VXLAN_F_IPV6;
	}

	if (conf->label && !use_ipv6) {
		pr_info("label only supported in use with IPv6\n");
		return -EINVAL;
	}

	if (conf->remote_ifindex) {
		lowerdev = __dev_get_by_index(src_net, conf->remote_ifindex);
		dst->remote_ifindex = conf->remote_ifindex;

		if (!lowerdev) {
			pr_info("ifindex %d does not exist\n", dst->remote_ifindex);
			return -ENODEV;
		}

#if IS_ENABLED(CONFIG_IPV6)
		if (use_ipv6) {
			struct inet6_dev *idev = __in6_dev_get(lowerdev);
			if (idev && idev->cnf.disable_ipv6) {
				pr_info("IPv6 is disabled via sysctl\n");
				return -EPERM;
			}
		}
#endif

		if (!conf->mtu)
			dev->mtu = lowerdev->mtu - (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);

		needed_headroom = lowerdev->hard_header_len;
	}

	if (conf->mtu) {
		err = __vxlan_change_mtu(dev, lowerdev, dst, conf->mtu, false);
		if (err)
			return err;
	}

	if (use_ipv6 || conf->flags & VXLAN_F_COLLECT_METADATA)
		needed_headroom += VXLAN6_HEADROOM;
	else
		needed_headroom += VXLAN_HEADROOM;
	dev->needed_headroom = needed_headroom;

	memcpy(&vxlan->cfg, conf, sizeof(*conf));
	if (!vxlan->cfg.dst_port) {
		if (conf->flags & VXLAN_F_GPE)
			vxlan->cfg.dst_port = 4790; /* IANA assigned VXLAN-GPE port */
		else
			vxlan->cfg.dst_port = default_port;
	}
	vxlan->flags |= conf->flags;

	if (!vxlan->cfg.age_interval)
		vxlan->cfg.age_interval = FDB_AGE_DEFAULT;

	list_for_each_entry(tmp, &vn->vxlan_list, next) {
		if (tmp->cfg.vni == conf->vni &&
		    (tmp->default_dst.remote_ip.sa.sa_family == AF_INET6 ||
		     tmp->cfg.saddr.sa.sa_family == AF_INET6) == use_ipv6 &&
		    tmp->cfg.dst_port == vxlan->cfg.dst_port &&
		    (tmp->flags & VXLAN_F_RCV_FLAGS) ==
		    (vxlan->flags & VXLAN_F_RCV_FLAGS))
		return -EEXIST;
	}

	dev->ethtool_ops = &vxlan_ethtool_ops;

	/* create an fdb entry for a valid default destination */
	if (!vxlan_addr_any(&vxlan->default_dst.remote_ip)) {
		err = vxlan_fdb_create(vxlan, all_zeros_mac,
				       &vxlan->default_dst.remote_ip,
				       NUD_REACHABLE|NUD_PERMANENT,
				       NLM_F_EXCL|NLM_F_CREATE,
				       vxlan->cfg.dst_port,
				       vxlan->default_dst.remote_vni,
				       vxlan->default_dst.remote_ifindex,
				       NTF_SELF);
		if (err)
			return err;
	}

	err = register_netdevice(dev);
	if (err) {
		vxlan_fdb_delete_default(vxlan);
		return err;
	}

	list_add(&vxlan->next, &vn->vxlan_list);

	return 0;
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int vxlan_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
#else
static int vxlan_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
#endif
{
	pr_info("unsupported operation\n");
	return -EINVAL;
}

static void vxlan_dellink(struct net_device *dev, struct list_head *head)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_net *vn = net_generic(vxlan->net, vxlan_net_id);

	spin_lock(&vn->sock_lock);
	if (!hlist_unhashed(&vxlan->hlist))
		hlist_del_rcu(&vxlan->hlist);
	spin_unlock(&vn->sock_lock);

	list_del(&vxlan->next);
	unregister_netdevice_queue(dev, head);
}

static size_t vxlan_get_size(const struct net_device *dev)
{

	return nla_total_size(sizeof(__u32)) +	/* IFLA_VXLAN_ID */
		nla_total_size(sizeof(struct in6_addr)) + /* IFLA_VXLAN_GROUP{6} */
		nla_total_size(sizeof(__u32)) +	/* IFLA_VXLAN_LINK */
		nla_total_size(sizeof(struct in6_addr)) + /* IFLA_VXLAN_LOCAL{6} */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_TTL */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_TOS */
		nla_total_size(sizeof(__be32)) + /* IFLA_VXLAN_LABEL */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_LEARNING */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_PROXY */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_RSC */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_L2MISS */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_L3MISS */
		nla_total_size(sizeof(__u8)) +	/* IFLA_VXLAN_COLLECT_METADATA */
		nla_total_size(sizeof(__u32)) +	/* IFLA_VXLAN_AGEING */
		nla_total_size(sizeof(__u32)) +	/* IFLA_VXLAN_LIMIT */
		nla_total_size(sizeof(struct ifla_vxlan_port_range)) +
		nla_total_size(sizeof(__be16)) + /* IFLA_VXLAN_PORT */
		nla_total_size(sizeof(__u8)) + /* IFLA_VXLAN_UDP_CSUM */
		nla_total_size(sizeof(__u8)) + /* IFLA_VXLAN_UDP_ZERO_CSUM6_TX */
		nla_total_size(sizeof(__u8)) + /* IFLA_VXLAN_UDP_ZERO_CSUM6_RX */
		nla_total_size(sizeof(__u8)) + /* IFLA_VXLAN_REMCSUM_TX */
		nla_total_size(sizeof(__u8)) + /* IFLA_VXLAN_REMCSUM_RX */
		0;
}

static int vxlan_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct vxlan_dev *vxlan = netdev_priv(dev);
	const struct vxlan_rdst *dst = &vxlan->default_dst;
	struct ifla_vxlan_port_range ports = {
		.low =  htons(vxlan->cfg.port_min),
		.high = htons(vxlan->cfg.port_max),
	};

	if (nla_put_u32(skb, IFLA_VXLAN_ID, be32_to_cpu(dst->remote_vni)))
		goto nla_put_failure;

	if (!vxlan_addr_any(&dst->remote_ip)) {
		if (dst->remote_ip.sa.sa_family == AF_INET) {
			if (nla_put_in_addr(skb, IFLA_VXLAN_GROUP,
					    dst->remote_ip.sin.sin_addr.s_addr))
				goto nla_put_failure;
#if IS_ENABLED(CONFIG_IPV6)
		} else {
			if (nla_put_in6_addr(skb, IFLA_VXLAN_GROUP6,
					     &dst->remote_ip.sin6.sin6_addr))
				goto nla_put_failure;
#endif
		}
	}

	if (dst->remote_ifindex && nla_put_u32(skb, IFLA_VXLAN_LINK, dst->remote_ifindex))
		goto nla_put_failure;

	if (!vxlan_addr_any(&vxlan->cfg.saddr)) {
		if (vxlan->cfg.saddr.sa.sa_family == AF_INET) {
			if (nla_put_in_addr(skb, IFLA_VXLAN_LOCAL,
					    vxlan->cfg.saddr.sin.sin_addr.s_addr))
				goto nla_put_failure;
#if IS_ENABLED(CONFIG_IPV6)
		} else {
			if (nla_put_in6_addr(skb, IFLA_VXLAN_LOCAL6,
					     &vxlan->cfg.saddr.sin6.sin6_addr))
				goto nla_put_failure;
#endif
		}
	}

	if (nla_put_u8(skb, IFLA_VXLAN_TTL, vxlan->cfg.ttl) ||
	    nla_put_u8(skb, IFLA_VXLAN_TOS, vxlan->cfg.tos) ||
	    nla_put_be32(skb, IFLA_VXLAN_LABEL, vxlan->cfg.label) ||
	    nla_put_u8(skb, IFLA_VXLAN_LEARNING,
			!!(vxlan->flags & VXLAN_F_LEARN)) ||
	    nla_put_u8(skb, IFLA_VXLAN_PROXY,
			!!(vxlan->flags & VXLAN_F_PROXY)) ||
	    nla_put_u8(skb, IFLA_VXLAN_RSC, !!(vxlan->flags & VXLAN_F_RSC)) ||
	    nla_put_u8(skb, IFLA_VXLAN_L2MISS,
			!!(vxlan->flags & VXLAN_F_L2MISS)) ||
	    nla_put_u8(skb, IFLA_VXLAN_L3MISS,
			!!(vxlan->flags & VXLAN_F_L3MISS)) ||
	    nla_put_u8(skb, IFLA_VXLAN_COLLECT_METADATA,
		       !!(vxlan->flags & VXLAN_F_COLLECT_METADATA)) ||
	    nla_put_u32(skb, IFLA_VXLAN_AGEING, vxlan->cfg.age_interval) ||
	    nla_put_u32(skb, IFLA_VXLAN_LIMIT, vxlan->cfg.addrmax) ||
	    nla_put_be16(skb, IFLA_VXLAN_PORT, vxlan->cfg.dst_port) ||
	    nla_put_u8(skb, IFLA_VXLAN_UDP_CSUM,
			!(vxlan->flags & VXLAN_F_UDP_ZERO_CSUM_TX)) ||
	    nla_put_u8(skb, IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
			!!(vxlan->flags & VXLAN_F_UDP_ZERO_CSUM6_TX)) ||
	    nla_put_u8(skb, IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
			!!(vxlan->flags & VXLAN_F_UDP_ZERO_CSUM6_RX)) ||
	    nla_put_u8(skb, IFLA_VXLAN_REMCSUM_TX,
			!!(vxlan->flags & VXLAN_F_REMCSUM_TX)) ||
	    nla_put_u8(skb, IFLA_VXLAN_REMCSUM_RX,
			!!(vxlan->flags & VXLAN_F_REMCSUM_RX)))
		goto nla_put_failure;

	if (nla_put(skb, IFLA_VXLAN_PORT_RANGE, sizeof(ports), &ports))
		goto nla_put_failure;

	if (vxlan->flags & VXLAN_F_GBP &&
	    nla_put_flag(skb, IFLA_VXLAN_GBP))
		goto nla_put_failure;

	if (vxlan->flags & VXLAN_F_GPE &&
	    nla_put_flag(skb, IFLA_VXLAN_GPE))
		goto nla_put_failure;

	if (vxlan->flags & VXLAN_F_REMCSUM_NOPARTIAL &&
	    nla_put_flag(skb, IFLA_VXLAN_REMCSUM_NOPARTIAL))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

#ifdef HAVE_GET_LINK_NET
static struct net *vxlan_get_link_net(const struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);

	return vxlan->net;
}
#endif

static struct rtnl_link_ops vxlan_link_ops __read_mostly = {
	.kind		= "ovs_vxlan",
	.maxtype	= IFLA_VXLAN_MAX,
	.policy		= vxlan_policy,
	.priv_size	= sizeof(struct vxlan_dev),
	.setup		= vxlan_setup,
	.validate	= vxlan_validate,
	.newlink	= vxlan_newlink,
	.dellink	= vxlan_dellink,
	.get_size	= vxlan_get_size,
	.fill_info	= vxlan_fill_info,
#ifdef HAVE_GET_LINK_NET
	.get_link_net	= vxlan_get_link_net,
#endif
};

struct net_device *rpl_vxlan_dev_create(struct net *net, const char *name,
				    u8 name_assign_type,
				    struct vxlan_config *conf)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	int err;

	memset(&tb, 0, sizeof(tb));

	dev = rtnl_create_link(net, name, name_assign_type,
			       &vxlan_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = vxlan_dev_configure(net, dev, conf);
	if (err < 0) {
		free_netdev(dev);
		return ERR_PTR(err);
	}

	err = rtnl_configure_link(dev, NULL);
	if (err < 0) {
		LIST_HEAD(list_kill);

		vxlan_dellink(dev, &list_kill);
		unregister_netdevice_many(&list_kill);
		return ERR_PTR(err);
	}

	return dev;
}
EXPORT_SYMBOL_GPL(rpl_vxlan_dev_create);

static void vxlan_handle_lowerdev_unregister(struct vxlan_net *vn,
					     struct net_device *dev)
{
	struct vxlan_dev *vxlan, *next;
	LIST_HEAD(list_kill);

	list_for_each_entry_safe(vxlan, next, &vn->vxlan_list, next) {
		struct vxlan_rdst *dst = &vxlan->default_dst;

		/* In case we created vxlan device with carrier
		 * and we loose the carrier due to module unload
		 * we also need to remove vxlan device. In other
		 * cases, it's not necessary and remote_ifindex
		 * is 0 here, so no matches.
		 */
		if (dst->remote_ifindex == dev->ifindex)
			vxlan_dellink(vxlan->dev, &list_kill);
	}

	unregister_netdevice_many(&list_kill);
}

static int vxlan_netdevice_event(struct notifier_block *unused,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct vxlan_net *vn = net_generic(dev_net(dev), vxlan_net_id);

	if (event == NETDEV_UNREGISTER)
		vxlan_handle_lowerdev_unregister(vn, dev);
	else if (event == NETDEV_OFFLOAD_PUSH_VXLAN)
		vxlan_push_rx_ports(dev);

	return NOTIFY_DONE;
}

static struct notifier_block vxlan_notifier_block __read_mostly = {
	.notifier_call = vxlan_netdevice_event,
};

static __net_init int vxlan_init_net(struct net *net)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	unsigned int h;

	INIT_LIST_HEAD(&vn->vxlan_list);
	spin_lock_init(&vn->sock_lock);

	for (h = 0; h < PORT_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vn->sock_list[h]);

	return 0;
}

static void __net_exit vxlan_exit_net(struct net *net)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_dev *vxlan, *next;
	struct net_device *dev, *aux;
	LIST_HEAD(list);

	rtnl_lock();
	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == &vxlan_link_ops)
			unregister_netdevice_queue(dev, &list);

	list_for_each_entry_safe(vxlan, next, &vn->vxlan_list, next) {
		/* If vxlan->dev is in the same netns, it has already been added
		 * to the list by the previous loop.
		 */
		if (!net_eq(dev_net(vxlan->dev), net)) {
			unregister_netdevice_queue(vxlan->dev, &list);
		}
	}

	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations vxlan_net_ops = {
	.init = vxlan_init_net,
	.exit = vxlan_exit_net,
	.id   = &vxlan_net_id,
	.size = sizeof(struct vxlan_net),
};

int rpl_vxlan_init_module(void)
{
	int rc;

	get_random_bytes(&vxlan_salt, sizeof(vxlan_salt));

	rc = register_pernet_subsys(&vxlan_net_ops);
	if (rc)
		goto out1;

	rc = register_netdevice_notifier(&vxlan_notifier_block);
	if (rc)
		goto out2;

	rc = rtnl_link_register(&vxlan_link_ops);
	if (rc)
		goto out3;

	pr_info("VxLAN tunneling driver\n");
	return 0;
out3:
	unregister_netdevice_notifier(&vxlan_notifier_block);
out2:
	unregister_pernet_subsys(&vxlan_net_ops);
out1:
	pr_err("Error while initializing VxLAN %d\n", rc);
	return rc;
}

void rpl_vxlan_cleanup_module(void)
{
	rtnl_link_unregister(&vxlan_link_ops);
	unregister_netdevice_notifier(&vxlan_notifier_block);
	unregister_pernet_subsys(&vxlan_net_ops);
	/* rcu_barrier() is called by netns */
}
#endif
