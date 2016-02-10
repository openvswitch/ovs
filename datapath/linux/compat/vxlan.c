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
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/hash.h>
#include <linux/ethtool.h>
#include <linux/netdev_features.h>
#include <net/arp.h>
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
#include <net/vxlan.h>
#include <net/protocol.h>
#include <net/udp_tunnel.h>
#include <net/ip6_route.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/ip6_checksum.h>
#endif
#include <net/dst_metadata.h>

#ifndef HAVE_METADATA_DST
#include "gso.h"
#include "vport-netdev.h"

#define VXLAN_VERSION	"0.1"

#define PORT_HASH_BITS	8
#define PORT_HASH_SIZE  (1<<PORT_HASH_BITS)
#define FDB_AGE_DEFAULT 300 /* 5 min */
#define FDB_AGE_INTERVAL (10 * HZ)	/* rescan interval */

#ifndef NTF_SELF
#define NTF_SELF        0x02
#endif

/* UDP port for VXLAN traffic.
 * The IANA assigned port is 4789, but the Linux default is 8472
 * for compatibility with early adopters.
 */
static unsigned short vxlan_port __read_mostly = 8472;
module_param_named(udp_port, vxlan_port, ushort, 0444);
MODULE_PARM_DESC(udp_port, "Destination UDP port");

static int vxlan_net_id;
static struct rtnl_link_ops vxlan_link_ops;

static const u8 all_zeros_mac[ETH_ALEN];

static struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
					 bool no_share, u32 flags);

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
static struct workqueue_struct *vxlan_wq;

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
static inline struct hlist_head *vni_head(struct vxlan_sock *vs, u32 id)
{
	return &vs->vni_list[hash_32(id, VNI_HASH_BITS)];
}

/* Socket hash table head */
static inline struct hlist_head *vs_head(struct net *net, __be16 port)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);

	return &vn->sock_list[hash_32(ntohs(port), PORT_HASH_BITS)];
}

/* First remote destination for a forwarding entry.
 * Guaranteed to be non-NULL because remotes are never deleted.
 */
static inline struct vxlan_rdst *first_remote_rcu(struct vxlan_fdb *fdb)
{
	return list_entry_rcu(fdb->remotes.next, struct vxlan_rdst, list);
}

static inline struct vxlan_rdst *first_remote_rtnl(struct vxlan_fdb *fdb)
{
	return list_first_entry(&fdb->remotes, struct vxlan_rdst, list);
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
		if (inet_sport(vs->sock->sk) == port &&
		    vxlan_get_sk_family(vs) == family &&
		    vs->flags == flags)
			return vs;
	}
	return NULL;
}

static struct vxlan_dev *vxlan_vs_find_vni(struct vxlan_sock *vs, u32 id)
{
	struct vxlan_dev *vxlan;

	hlist_for_each_entry_rcu(vxlan, vni_head(vs, id), hlist) {
		if (vxlan->default_dst.remote_vni == id)
			return vxlan;
	}

	return NULL;
}

/* Look up VNI in a per net namespace table */
static struct vxlan_dev *vxlan_find_vni(struct net *net, u32 id,
					sa_family_t family, __be16 port,
					u32 flags)
{
	struct vxlan_sock *vs;

	vs = vxlan_find_sock(net, family, port, flags);
	if (!vs)
		return NULL;

	return vxlan_vs_find_vni(vs, id);
}

/* Fill in neighbour message in skbuff. */
static int vxlan_fdb_info(struct sk_buff *skb, struct vxlan_dev *vxlan,
			  const struct vxlan_fdb *fdb,
			  u32 portid, u32 seq, int type, unsigned int flags,
			  const struct vxlan_rdst *rdst)
{
	return -EINVAL;
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

static void vxlan_fdb_notify(struct vxlan_dev *vxlan, struct vxlan_fdb *fdb,
			     struct vxlan_rdst *rd, int type)
{
	struct net *net = dev_net(vxlan->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(vxlan_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = vxlan_fdb_info(skb, vxlan, fdb, 0, 0, type, 0, rd);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in vxlan_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}

	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

/* Hash Ethernet address */
static u32 eth_hash(const unsigned char *addr)
{
	u64 value = get_unaligned((u64 *)addr);

	/* only want 6 bytes */
#ifdef __BIG_ENDIAN
	value >>= 16;
#else
	value <<= 16;
#endif
	return hash_64(value, FDB_HASH_BITS);
}

/* Hash chain to use given mac address */
static inline struct hlist_head *vxlan_fdb_head(struct vxlan_dev *vxlan,
						const u8 *mac)
{
	return &vxlan->fdb_head[eth_hash(mac)];
}

/* Look up Ethernet address in forwarding table */
static struct vxlan_fdb *__vxlan_find_mac(struct vxlan_dev *vxlan,
					const u8 *mac)
{
	struct hlist_head *head = vxlan_fdb_head(vxlan, mac);
	struct vxlan_fdb *f;

	hlist_for_each_entry_rcu(f, head, hlist) {
		if (ether_addr_equal(mac, f->eth_addr))
			return f;
	}

	return NULL;
}

static struct vxlan_fdb *vxlan_find_mac(struct vxlan_dev *vxlan,
					const u8 *mac)
{
	struct vxlan_fdb *f;

	f = __vxlan_find_mac(vxlan, mac);
	if (f)
		f->used = jiffies;

	return f;
}

/* caller should hold vxlan->hash_lock */
static struct vxlan_rdst *vxlan_fdb_find_rdst(struct vxlan_fdb *f,
					      union vxlan_addr *ip, __be16 port,
					      __u32 vni, __u32 ifindex)
{
	struct vxlan_rdst *rd;

	list_for_each_entry(rd, &f->remotes, list) {
		if (vxlan_addr_equal(&rd->remote_ip, ip) &&
		    rd->remote_port == port &&
		    rd->remote_vni == vni &&
		    rd->remote_ifindex == ifindex)
			return rd;
	}

	return NULL;
}

/* Replace destination of unicast mac */
static int vxlan_fdb_replace(struct vxlan_fdb *f,
			     union vxlan_addr *ip, __be16 port, __u32 vni, __u32 ifindex)
{
	struct vxlan_rdst *rd;

	rd = vxlan_fdb_find_rdst(f, ip, port, vni, ifindex);
	if (rd)
		return 0;

	rd = list_first_entry_or_null(&f->remotes, struct vxlan_rdst, list);
	if (!rd)
		return 0;
	rd->remote_ip = *ip;
	rd->remote_port = port;
	rd->remote_vni = vni;
	rd->remote_ifindex = ifindex;
	return 1;
}

/* Add/update destinations for multicast */
static int vxlan_fdb_append(struct vxlan_fdb *f,
			    union vxlan_addr *ip, __be16 port, __u32 vni,
			    __u32 ifindex, struct vxlan_rdst **rdp)
{
	struct vxlan_rdst *rd;

	rd = vxlan_fdb_find_rdst(f, ip, port, vni, ifindex);
	if (rd)
		return 0;

	rd = kmalloc(sizeof(*rd), GFP_ATOMIC);
	if (rd == NULL)
		return -ENOBUFS;
	rd->remote_ip = *ip;
	rd->remote_port = port;
	rd->remote_vni = vni;
	rd->remote_ifindex = ifindex;

	list_add_tail_rcu(&rd->list, &f->remotes);

	*rdp = rd;
	return 1;
}

#ifdef HAVE_UDP_OFFLOAD
#ifdef HAVE_NETIF_F_GSO_TUNNEL_REMCSUM
static struct vxlanhdr *vxlan_gro_remcsum(struct sk_buff *skb,
					  unsigned int off,
					  struct vxlanhdr *vh, size_t hdrlen,
					  u32 data, struct gro_remcsum *grc,
					  bool nopartial)
{
	size_t start, offset;

	if (skb->remcsum_offload)
		return vh;

	if (!NAPI_GRO_CB(skb)->csum_valid)
		return NULL;

	start = (data & VXLAN_RCO_MASK) << VXLAN_RCO_SHIFT;
	offset = start + ((data & VXLAN_RCO_UDP) ?
			  offsetof(struct udphdr, check) :
			  offsetof(struct tcphdr, check));

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
	u32 flags;
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

	flags = ntohl(vh->vx_flags);

	if ((flags & VXLAN_HF_RCO) && vs && (vs->flags & VXLAN_F_REMCSUM_RX)) {

		vh = vxlan_gro_remcsum(skb, off_vx, vh, sizeof(struct vxlanhdr),
				       ntohl(vh->vx_vni), &grc,
				       !!(vs->flags &
					  VXLAN_F_REMCSUM_NOPARTIAL));

		if (!vh)
			goto out;
	}

	skb_gro_pull(skb, sizeof(struct vxlanhdr)); /* pull vxlan header */

	flush = 0;

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
	udp_tunnel_gro_complete(skb, nhoff);

	return eth_gro_complete(skb, nhoff + sizeof(struct vxlanhdr));
}

/* Notify netdevs that UDP port started listening */
static void vxlan_notify_add_rx_port(struct vxlan_sock *vs)
{
	struct net_device *dev;
	struct sock *sk = vs->sock->sk;
	struct net *net = sock_net(sk);
	sa_family_t sa_family = vxlan_get_sk_family(vs);
	__be16 port = inet_sk(sk)->inet_sport;
	int err;

	if (sa_family == AF_INET) {
		err = udp_add_offload(&vs->udp_offloads);
		if (err)
			pr_warn("vxlan: udp_add_offload failed with status %d\n", err);
	}

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (dev->netdev_ops->ndo_add_vxlan_port)
			dev->netdev_ops->ndo_add_vxlan_port(dev, sa_family,
							    port);
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
	__be16 port = inet_sk(sk)->inet_sport;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (dev->netdev_ops->ndo_del_vxlan_port)
			dev->netdev_ops->ndo_del_vxlan_port(dev, sa_family,
							    port);
	}
	rcu_read_unlock();

	if (sa_family == AF_INET)
		udp_del_offload(&vs->udp_offloads);
}
#endif

/* Add new entry to forwarding table -- assumes lock held */
static int vxlan_fdb_create(struct vxlan_dev *vxlan,
			    const u8 *mac, union vxlan_addr *ip,
			    __u16 state, __u16 flags,
			    __be16 port, __u32 vni, __u32 ifindex,
			    __u8 ndm_flags)
{
	struct vxlan_rdst *rd = NULL;
	struct vxlan_fdb *f;
	int notify = 0;

	f = __vxlan_find_mac(vxlan, mac);
	if (f) {
		if (flags & NLM_F_EXCL) {
			netdev_dbg(vxlan->dev,
				   "lost race to create %pM\n", mac);
			return -EEXIST;
		}
		if (f->state != state) {
			f->state = state;
			f->updated = jiffies;
			notify = 1;
		}
		if (f->flags != ndm_flags) {
			f->flags = ndm_flags;
			f->updated = jiffies;
			notify = 1;
		}
		if ((flags & NLM_F_REPLACE)) {
			/* Only change unicasts */
			if (!(is_multicast_ether_addr(f->eth_addr) ||
			     is_zero_ether_addr(f->eth_addr))) {
				notify |= vxlan_fdb_replace(f, ip, port, vni,
							   ifindex);
			} else
				return -EOPNOTSUPP;
		}
		if ((flags & NLM_F_APPEND) &&
		    (is_multicast_ether_addr(f->eth_addr) ||
		     is_zero_ether_addr(f->eth_addr))) {
			int rc = vxlan_fdb_append(f, ip, port, vni, ifindex,
						  &rd);

			if (rc < 0)
				return rc;
			notify |= rc;
		}
	} else {
		if (!(flags & NLM_F_CREATE))
			return -ENOENT;

		if (vxlan->cfg.addrmax &&
		    vxlan->addrcnt >= vxlan->cfg.addrmax)
			return -ENOSPC;

		/* Disallow replace to add a multicast entry */
		if ((flags & NLM_F_REPLACE) &&
		    (is_multicast_ether_addr(mac) || is_zero_ether_addr(mac)))
			return -EOPNOTSUPP;

		netdev_dbg(vxlan->dev, "add %pM -> %pIS\n", mac, ip);
		f = kmalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			return -ENOMEM;

		notify = 1;
		f->state = state;
		f->flags = ndm_flags;
		f->updated = f->used = jiffies;
		INIT_LIST_HEAD(&f->remotes);
		memcpy(f->eth_addr, mac, ETH_ALEN);

		vxlan_fdb_append(f, ip, port, vni, ifindex, &rd);

		++vxlan->addrcnt;
		hlist_add_head_rcu(&f->hlist,
				   vxlan_fdb_head(vxlan, mac));
	}

	if (notify) {
		if (rd == NULL)
			rd = first_remote_rtnl(f);
		vxlan_fdb_notify(vxlan, f, rd, RTM_NEWNEIGH);
	}

	return 0;
}

static void vxlan_fdb_free(struct rcu_head *head)
{
	struct vxlan_fdb *f = container_of(head, struct vxlan_fdb, rcu);
	struct vxlan_rdst *rd, *nd;

	list_for_each_entry_safe(rd, nd, &f->remotes, list)
		kfree(rd);
	kfree(f);
}

static void vxlan_fdb_destroy(struct vxlan_dev *vxlan, struct vxlan_fdb *f)
{
	netdev_dbg(vxlan->dev,
		    "delete %pM\n", f->eth_addr);

	--vxlan->addrcnt;
	vxlan_fdb_notify(vxlan, f, first_remote_rtnl(f), RTM_DELNEIGH);

	hlist_del_rcu(&f->hlist);
	call_rcu(&f->rcu, vxlan_fdb_free);
}

/* Watch incoming packets to learn mapping between Ethernet address
 * and Tunnel endpoint.
 * Return true if packet is bogus and should be dropped.
 */
static bool vxlan_snoop(struct net_device *dev,
			union vxlan_addr *src_ip, const u8 *src_mac)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_fdb *f;

	f = vxlan_find_mac(vxlan, src_mac);
	if (likely(f)) {
		struct vxlan_rdst *rdst = first_remote_rcu(f);

		if (likely(vxlan_addr_equal(&rdst->remote_ip, src_ip)))
			return false;

		/* Don't migrate static entries, drop packets */
		if (f->state & NUD_NOARP)
			return true;

		if (net_ratelimit())
			netdev_info(dev,
				    "%pM migrated from %pIS to %pIS\n",
				    src_mac, &rdst->remote_ip.sa, &src_ip->sa);

		rdst->remote_ip = *src_ip;
		f->updated = jiffies;
		vxlan_fdb_notify(vxlan, f, rdst, RTM_NEWNEIGH);
	} else {
		/* learned new entry */
		spin_lock(&vxlan->hash_lock);

		/* close off race between vxlan_flush and incoming packets */
		if (netif_running(dev))
			vxlan_fdb_create(vxlan, src_mac, src_ip,
					 NUD_REACHABLE,
					 NLM_F_EXCL|NLM_F_CREATE,
					 vxlan->cfg.dst_port,
					 vxlan->default_dst.remote_vni,
					 0, NTF_SELF);
		spin_unlock(&vxlan->hash_lock);
	}

	return false;
}

/* See if multicast group is already in use by other ID */
static bool vxlan_group_used(struct vxlan_net *vn, struct vxlan_dev *dev)
{
	struct vxlan_dev *vxlan;

	/* The vxlan_sock is only used by dev, leaving group has
	 * no effect on other vxlan devices.
	 */
	if (atomic_read(&dev->vn_sock->refcnt) == 1)
		return false;

	list_for_each_entry(vxlan, &vn->vxlan_list, next) {
		if (!netif_running(vxlan->dev) || vxlan == dev)
			continue;

		if (vxlan->vn_sock != dev->vn_sock)
			continue;

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

static void vxlan_sock_release(struct vxlan_sock *vs)
{
	struct sock *sk = vs->sock->sk;
	struct net *net = sock_net(sk);
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);

	if (!atomic_dec_and_test(&vs->refcnt))
		return;

	spin_lock(&vn->sock_lock);
	hlist_del_rcu(&vs->hlist);
#ifdef HAVE_UDP_OFFLOAD
	vxlan_notify_del_rx_port(vs);
#endif
	spin_unlock(&vn->sock_lock);

	queue_work(vxlan_wq, &vs->del_work);
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

#ifdef HAVE_VXLAN_HF_RCO
static struct vxlanhdr *vxlan_remcsum(struct sk_buff *skb, struct vxlanhdr *vh,
				      size_t hdrlen, u32 data, bool nopartial)
{
	size_t start, offset, plen;

	if (skb->remcsum_offload)
		return vh;

	start = (data & VXLAN_RCO_MASK) << VXLAN_RCO_SHIFT;
	offset = start + ((data & VXLAN_RCO_UDP) ?
			  offsetof(struct udphdr, check) :
			  offsetof(struct tcphdr, check));

	plen = hdrlen + offset + sizeof(u16);

	if (!pskb_may_pull(skb, plen))
		return NULL;

	vh = (struct vxlanhdr *)(udp_hdr(skb) + 1);

	skb_remcsum_process(skb, (void *)vh + hdrlen, start, offset,
			    nopartial);

	return vh;
}
#endif

static void vxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb,
		      struct vxlan_metadata *md, u32 vni,
		      struct metadata_dst *tun_dst)
{
	struct iphdr *oip = NULL;
	struct ipv6hdr *oip6 = NULL;
	struct vxlan_dev *vxlan;
#ifdef HAVE_DEV_TSTATS
	struct pcpu_sw_netstats *stats;
#endif
	union vxlan_addr saddr;
	int err = 0;

	/* For flow based devices, map all packets to VNI 0 */
	if (vs->flags & VXLAN_F_COLLECT_METADATA)
		vni = 0;

	/* Is this VNI defined? */
	vxlan = vxlan_vs_find_vni(vs, vni);
	if (!vxlan)
		goto drop;

	skb_reset_mac_header(skb);
	skb_scrub_packet(skb, !net_eq(vxlan->net, dev_net(vxlan->dev)));
	skb->protocol = eth_type_trans(skb, vxlan->dev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

	/* Ignore packet loops (and multicast echo) */
	if (ether_addr_equal(eth_hdr(skb)->h_source, vxlan->dev->dev_addr))
		goto drop;

	/* Get data from the outer IP header */
	if (vxlan_get_sk_family(vs) == AF_INET) {
		oip = ip_hdr(skb);
		saddr.sin.sin_addr.s_addr = oip->saddr;
		saddr.sa.sa_family = AF_INET;
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		oip6 = ipv6_hdr(skb);
		saddr.sin6.sin6_addr = oip6->saddr;
		saddr.sa.sa_family = AF_INET6;
#endif
	}

	if (tun_dst) {
		ovs_skb_dst_set(skb, (struct dst_entry *)tun_dst);
		tun_dst = NULL;
	} else {
		goto drop;
	}

	if ((vxlan->flags & VXLAN_F_LEARN) &&
	    vxlan_snoop(skb->dev, &saddr, eth_hdr(skb)->h_source))
		goto drop;

	skb_reset_network_header(skb);
	/* In flow-based mode, GBP is carried in dst_metadata */
	if (!(vs->flags & VXLAN_F_COLLECT_METADATA))
		skb->mark = md->gbp;

	if (oip6)
		err = IP6_ECN_decapsulate(oip6, skb);
	if (oip)
		err = IP_ECN_decapsulate(oip, skb);

	if (unlikely(err)) {
		if (err > 1) {
			++vxlan->dev->stats.rx_frame_errors;
			++vxlan->dev->stats.rx_errors;
			goto drop;
		}
	}

#ifdef HAVE_DEV_TSTATS
	stats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)vxlan->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);
#endif
	netdev_port_receive(skb, skb_tunnel_info(skb));
	return;
drop:

	/* Consume bad packet */
	kfree_skb(skb);
}

/* Callback from net/ipv4/udp.c to receive packets */
static int vxlan_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct vxlan_sock *vs;
	struct vxlanhdr *vxh;
	u32 flags, vni;
	struct vxlan_metadata _md;
	struct vxlan_metadata *md = &_md;
	union {
		struct metadata_dst dst;
		char buf[sizeof(struct metadata_dst) + sizeof(*md)];
	} buf;

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
	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);

	vs = rcu_dereference_sk_user_data(sk);
	if (!vs)
		goto drop;

#ifdef HAVE_VXLAN_HF_RCO
	if ((flags & VXLAN_HF_RCO) && (vs->flags & VXLAN_F_REMCSUM_RX)) {
		vxh = vxlan_remcsum(skb, vxh, sizeof(struct vxlanhdr), vni,
				    !!(vs->flags & VXLAN_F_REMCSUM_NOPARTIAL));
		if (!vxh)
			goto drop;

		flags &= ~VXLAN_HF_RCO;
		vni &= VXLAN_VNI_MASK;
	}
#endif

	if (vxlan_collect_metadata(vs)) {
		ovs_udp_tun_rx_dst(&buf.dst.u.tun_info, skb, AF_INET, TUNNEL_KEY,
				   cpu_to_be64(vni >> 8), sizeof(*md));

		md = ip_tunnel_info_opts(&buf.dst.u.tun_info);
	} else {
		memset(md, 0, sizeof(*md));
	}

	/* For backwards compatibility, only allow reserved fields to be
	 * used by VXLAN extensions if explicitly requested.
	 */
	if ((flags & VXLAN_HF_GBP) && (vs->flags & VXLAN_F_GBP)) {
		struct vxlanhdr_gbp *gbp;

		gbp = (struct vxlanhdr_gbp *)vxh;
		md->gbp = ntohs(gbp->policy_id);

		buf.dst.u.tun_info.key.tun_flags |= TUNNEL_VXLAN_OPT;

		if (gbp->dont_learn)
			md->gbp |= VXLAN_GBP_DONT_LEARN;

		if (gbp->policy_applied)
			md->gbp |= VXLAN_GBP_POLICY_APPLIED;

		flags &= ~VXLAN_GBP_USED_BITS;
	}

	if (flags || vni & ~VXLAN_VNI_MASK) {
		/* If there are any unprocessed flags remaining treat
		 * this as a malformed packet. This behavior diverges from
		 * VXLAN RFC (RFC7348) which stipulates that bits in reserved
		 * in reserved fields are to be ignored. The approach here
		 * maintains compatibility with previous stack code, and also
		 * is more robust and provides a little more security in
		 * adding extensions to VXLAN.
		 */

		goto bad_flags;
	}

	vxlan_rcv(vs, skb, md, vni >> 8, &buf.dst);
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;

bad_flags:
	netdev_dbg(skb->dev, "invalid vxlan flags=%#x vni=%#x\n",
		   ntohl(vxh->vx_flags), ntohl(vxh->vx_vni));

error:
	/* Return non vxlan pkt */
	return 1;
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

#if IS_ENABLED(CONFIG_IPV6)
static int vxlan6_xmit_skb(struct dst_entry *dst, struct sock *sk,
			   struct sk_buff *skb,
			   struct net_device *dev, struct in6_addr *saddr,
			   struct in6_addr *daddr, __u8 prio, __u8 ttl,
			   __be16 src_port, __be16 dst_port, __be32 vni,
			   struct vxlan_metadata *md, bool xnet, u32 vxflags)
{
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	bool udp_sum = !(vxflags & VXLAN_F_UDP_ZERO_CSUM6_TX);
	int type = 0;

	if ((vxflags & VXLAN_F_REMCSUM_TX) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		int csum_start = skb_checksum_start_offset(skb);

		if (csum_start <= VXLAN_MAX_REMCSUM_START &&
		    !(csum_start & VXLAN_RCO_SHIFT_MASK) &&
		    (skb->csum_offset == offsetof(struct udphdr, check) ||
		     skb->csum_offset == offsetof(struct tcphdr, check))) {
			udp_sum = false;
			type |= SKB_GSO_TUNNEL_REMCSUM;
			/* Add support for remote csum. */
			if (!SKB_GSO_TUNNEL_REMCSUM) {
				kfree_skb(skb);
				err = -EOPNOTSUPP;
				goto err;
			}
		}
	}

	skb_scrub_packet(skb, xnet);

	min_headroom = LL_RESERVED_SPACE(dst->dev) + dst->header_len
			+ VXLAN_HLEN + sizeof(struct ipv6hdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err)) {
		kfree_skb(skb);
		goto err;
	}

	skb = vlan_hwaccel_push_inside(skb);
	if (WARN_ON(!skb)) {
		err = -ENOMEM;
		goto err;
	}

	skb = udp_tunnel_handle_offloads(skb, udp_sum, type, true);
	if (IS_ERR(skb)) {
		err = -EINVAL;
		goto err;
	}

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = vni;

	if (type & SKB_GSO_TUNNEL_REMCSUM) {
		u16 hdrlen = sizeof(struct vxlanhdr);
		u32 data = (skb_checksum_start_offset(skb) - hdrlen) >>
			   VXLAN_RCO_SHIFT;

		if (skb->csum_offset == offsetof(struct udphdr, check))
			data |= VXLAN_RCO_UDP;

		vxh->vx_vni |= htonl(data);
		vxh->vx_flags |= htonl(VXLAN_HF_RCO);

		if (!skb_is_gso(skb)) {
			skb->ip_summed = CHECKSUM_NONE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
			skb->encapsulation = 0;
#endif
		}
	}

	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);

	ovs_skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio,
			     ttl, src_port, dst_port,
			     !!(vxflags & VXLAN_F_UDP_ZERO_CSUM6_TX));
	return 0;
err:
	dst_release(dst);
	return err;
}
#endif

static int vxlan_xmit_skb(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
			  __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
			  __be16 src_port, __be16 dst_port, __be32 vni,
			  struct vxlan_metadata *md, bool xnet, u32 vxflags)
{
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	bool udp_sum = !!(vxflags & VXLAN_F_UDP_CSUM);
	int type = 0;

	if ((vxflags & VXLAN_F_REMCSUM_TX) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		int csum_start = skb_checksum_start_offset(skb);

		if (csum_start <= VXLAN_MAX_REMCSUM_START &&
		    !(csum_start & VXLAN_RCO_SHIFT_MASK) &&
		    (skb->csum_offset == offsetof(struct udphdr, check) ||
		     skb->csum_offset == offsetof(struct tcphdr, check))) {
			udp_sum = false;
			type |= SKB_GSO_TUNNEL_REMCSUM;

			if (!SKB_GSO_TUNNEL_REMCSUM) {
				kfree_skb(skb);
				return -EOPNOTSUPP;
			}
		}
	}

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

	skb = udp_tunnel_handle_offloads(skb, udp_sum, type, true);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = vni;

	if (type & SKB_GSO_TUNNEL_REMCSUM) {
		u16 hdrlen = sizeof(struct vxlanhdr);
		u32 data = (skb_checksum_start_offset(skb) - hdrlen) >>
			   VXLAN_RCO_SHIFT;

		if (skb->csum_offset == offsetof(struct udphdr, check))
			data |= VXLAN_RCO_UDP;

		vxh->vx_vni |= htonl(data);
		vxh->vx_flags |= htonl(VXLAN_HF_RCO);

		if (!skb_is_gso(skb)) {
			skb->ip_summed = CHECKSUM_NONE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
			skb->encapsulation = 0;
#endif
		}
	}
	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);

	ovs_skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	return udp_tunnel_xmit_skb(rt, sk, skb, src, dst, tos,
				   ttl, df, src_port, dst_port, xnet,
				   !(vxflags & VXLAN_F_UDP_CSUM));
}

static void vxlan_xmit_one(struct sk_buff *skb, struct net_device *dev,
			   struct vxlan_rdst *rdst, bool did_rsc)
{
	struct ip_tunnel_info *info;
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct sock *sk = vxlan->vn_sock->sock->sk;
	unsigned short family = vxlan_get_sk_family(vxlan->vn_sock);
	struct rtable *rt = NULL;
	const struct iphdr *old_iph;
	struct flowi4 fl4;
	union vxlan_addr *dst;
	union vxlan_addr remote_ip;
	struct vxlan_metadata _md;
	struct vxlan_metadata *md = &_md;
	__be16 src_port = 0, dst_port;
	u32 vni;
	__be16 df = 0;
	__u8 tos, ttl;
	int err;
	u32 flags = vxlan->flags;

	info = skb_tunnel_info(skb);

	if (rdst) {
		dst_port = rdst->remote_port ? rdst->remote_port : vxlan->cfg.dst_port;
		vni = rdst->remote_vni;
		dst = &rdst->remote_ip;
	} else {
		if (!info) {
			WARN_ONCE(1, "%s: Missing encapsulation instructions\n",
				  dev->name);
			goto drop;
		}
		if (family != ip_tunnel_info_af(info))
			goto drop;

		dst_port = info->key.tp_dst ? : vxlan->cfg.dst_port;
		vni = be64_to_cpu(info->key.tun_id);
		remote_ip.sa.sa_family = family;
		if (family == AF_INET)
			remote_ip.sin.sin_addr.s_addr = info->key.u.ipv4.dst;
		else
			remote_ip.sin6.sin6_addr = info->key.u.ipv6.dst;
		dst = &remote_ip;
	}

	if (vxlan_addr_any(dst)) {
		if (did_rsc) {
			/* short-circuited back to local bridge */
			WARN_ONCE(1, "%s: vxlan_encap_bypass not supported\n",
				  dev->name);
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

	src_port = udp_flow_src_port(dev_net(dev), skb, vxlan->cfg.port_min,
				     vxlan->cfg.port_max, true);

	if (info) {
		if (info->key.tun_flags & TUNNEL_CSUM)
			flags |= VXLAN_F_UDP_CSUM;
		else
			flags &= ~VXLAN_F_UDP_CSUM;

		ttl = info->key.ttl;
		tos = info->key.tos;

		if (info->options_len)
			md = ip_tunnel_info_opts(info);
	} else {
		md->gbp = skb->mark;
	}

	if (dst->sa.sa_family == AF_INET) {
		if (info && (info->key.tun_flags & TUNNEL_DONT_FRAGMENT))
			df = htons(IP_DF);

		memset(&fl4, 0, sizeof(fl4));
		fl4.flowi4_oif = rdst ? rdst->remote_ifindex : 0;
		fl4.flowi4_tos = RT_TOS(tos);
		fl4.flowi4_mark = skb->mark;
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.daddr = dst->sin.sin_addr.s_addr;
		fl4.saddr = vxlan->cfg.saddr.sin.sin_addr.s_addr;

		rt = ip_route_output_key(vxlan->net, &fl4);
		if (IS_ERR(rt)) {
			netdev_dbg(dev, "no route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}

		if (rt_dst(rt).dev == dev) {
			netdev_dbg(dev, "circular route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.collisions++;
			goto rt_tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		if (rt->rt_flags & RTCF_LOCAL &&
		    !(rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			ip_rt_put(rt);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			WARN_ONCE(1, "%s: vxlan_encap_bypass not supported\n",
				  dev->name);
			goto tx_error;
		}

		tos = ip_tunnel_ecn_encap(tos, old_iph, skb);
		ttl = ttl ? : ip4_dst_hoplimit(&rt_dst(rt));
		err = vxlan_xmit_skb(rt, sk, skb, fl4.saddr,
				     dst->sin.sin_addr.s_addr, tos, ttl, df,
				     src_port, dst_port, htonl(vni << 8), md,
				     !net_eq(vxlan->net, dev_net(vxlan->dev)),
				     flags);
		if (err < 0) {
			/* skb is already freed. */
			skb = NULL;
			goto rt_tx_error;
		}

		iptunnel_xmit_stats(err, &dev->stats, (struct pcpu_sw_netstats __percpu *)dev->tstats);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct dst_entry *ndst;
		struct flowi6 fl6;
		u32 rt6i_flags;

		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_oif = rdst ? rdst->remote_ifindex : 0;
		fl6.daddr = dst->sin6.sin6_addr;
		fl6.saddr = vxlan->cfg.saddr.sin6.sin6_addr;
		fl6.flowi6_mark = skb->mark;
		fl6.flowi6_proto = IPPROTO_UDP;

#ifdef HAVE_IPV6_DST_LOOKUP_NET
		if (ipv6_stub->ipv6_dst_lookup(vxlan->net, sk, &ndst, &fl6)) {
#else
#ifdef HAVE_IPV6_STUB
		if (ipv6_stub->ipv6_dst_lookup(sk, &ndst, &fl6)) {
#else
		ndst = ip6_route_output(vxlan->net, sk, &fl6);
		if (ndst->error) {
#endif
#endif
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
		if (rt6i_flags & RTF_LOCAL &&
		    !(rt6i_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			dst_release(ndst);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			WARN_ONCE(1, "%s: vxlan_encap_bypass not supported\n",
				  dev->name);
			goto tx_error;
		}

		ttl = ttl ? : ip6_dst_hoplimit(ndst);
		err = vxlan6_xmit_skb(ndst, sk, skb, dev, &fl6.saddr, &fl6.daddr,
				      0, ttl, src_port, dst_port, htonl(vni << 8), md,
				      !net_eq(vxlan->net, dev_net(vxlan->dev)),
				      flags);
#endif
	}

	return;

drop:
	dev->stats.tx_dropped++;
	goto tx_free;

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

	if ((vxlan->flags & VXLAN_F_PROXY))
		goto out;

	if (vxlan->flags & VXLAN_F_COLLECT_METADATA &&
	    info && info->mode & IP_TUNNEL_INFO_TX) {
		vxlan_xmit_one(skb, dev, NULL, false);
		return NETDEV_TX_OK;
	}
out:
	pr_warn("vxlan: unsupported flag set %x", vxlan->flags);
	kfree_skb(skb);
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(rpl_vxlan_xmit);

/* Walk the forwarding table and purge stale entries */
static void vxlan_cleanup(unsigned long arg)
{
	struct vxlan_dev *vxlan = (struct vxlan_dev *) arg;
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
	__u32 vni = vxlan->default_dst.remote_vni;

	vxlan->vn_sock = vs;
	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vxlan->hlist, vni_head(vs, vni));
	spin_unlock(&vn->sock_lock);
}

/* Setup stats when device is created */
#ifdef HAVE_DEV_TSTATS
static int vxlan_init(struct net_device *dev)
{
	dev->tstats = (typeof(dev->tstats)) netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}
#endif

static void vxlan_fdb_delete_default(struct vxlan_dev *vxlan)
{
	struct vxlan_fdb *f;

	spin_lock_bh(&vxlan->hash_lock);
	f = __vxlan_find_mac(vxlan, all_zeros_mac);
	if (f)
		vxlan_fdb_destroy(vxlan, f);
	spin_unlock_bh(&vxlan->hash_lock);
}

#ifdef HAVE_DEV_TSTATS
static void vxlan_uninit(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);

	vxlan_fdb_delete_default(vxlan);

	free_percpu(dev->tstats);
}
#endif

/* Start ageing timer and join group when device is brought up */
static int vxlan_open(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_sock *vs;
	int ret = 0;

	vs = vxlan_sock_add(vxlan->net, vxlan->cfg.dst_port,
			    vxlan->cfg.no_share, vxlan->flags);
	if (IS_ERR(vs))
		return PTR_ERR(vs);

	vxlan_vs_add_dev(vs, vxlan);

	if (vxlan_addr_multicast(&vxlan->default_dst.remote_ip)) {
		ret = vxlan_igmp_join(vxlan);
		if (ret == -EADDRINUSE)
			ret = 0;
		if (ret) {
			vxlan_sock_release(vs);
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
	struct vxlan_sock *vs = vxlan->vn_sock;
	int ret = 0;

	if (vxlan_addr_multicast(&vxlan->default_dst.remote_ip) &&
	    !vxlan_group_used(vn, vxlan))
		ret = vxlan_igmp_leave(vxlan);

	del_timer_sync(&vxlan->age_timer);

	vxlan_flush(vxlan);
	vxlan_sock_release(vs);

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

static netdev_tx_t vxlan_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */

	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static const struct net_device_ops vxlan_netdev_ops = {
#ifdef HAVE_DEV_TSTATS
	.ndo_init		= vxlan_init,
	.ndo_uninit		= vxlan_uninit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
#endif
	.ndo_open		= vxlan_open,
	.ndo_stop		= vxlan_stop,
	.ndo_start_xmit		= vxlan_dev_xmit,
	.ndo_set_rx_mode	= vxlan_set_multicast_list,
	.ndo_change_mtu		= vxlan_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type vxlan_type = {
	.name = "vxlan",
};

/* Initialize the device structure. */
static void vxlan_setup(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	unsigned int h;

	eth_hw_addr_random(dev);
	ether_setup(dev);

	dev->netdev_ops = &vxlan_netdev_ops;
	dev->destructor = free_netdev;
	SET_NETDEV_DEVTYPE(dev, &vxlan_type);

	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features   |= NETIF_F_RXCSUM;
	dev->features   |= NETIF_F_GSO_SOFTWARE;

	dev->vlan_features = dev->features;
	dev->features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
#endif

#if 0
	netif_keep_dst(dev);
#endif
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;

	INIT_LIST_HEAD(&vxlan->next);
	spin_lock_init(&vxlan->hash_lock);

	init_timer_deferrable(&vxlan->age_timer);
	vxlan->age_timer.function = vxlan_cleanup;
	vxlan->age_timer.data = (unsigned long) vxlan;

	vxlan->cfg.dst_port = htons(vxlan_port);

	vxlan->dev = dev;

	for (h = 0; h < FDB_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vxlan->fdb_head[h]);
}

static const struct nla_policy vxlan_policy[IFLA_VXLAN_MAX + 1] = {
	[IFLA_VXLAN_PORT]	= { .type = NLA_U16 },
};

static int vxlan_validate(struct nlattr *tb[], struct nlattr *data[])
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

static void free_vs_rcu(struct rcu_head *rcu)
{
	struct vxlan_sock *vs = container_of(rcu, struct vxlan_sock, rcu);

	kfree(vs);
}

static void vxlan_del_work(struct work_struct *work)
{
	struct vxlan_sock *vs = container_of(work, struct vxlan_sock, del_work);
	udp_tunnel_sock_release(vs->sock);

	call_rcu(&vs->rcu, free_vs_rcu);
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
static struct vxlan_sock *vxlan_socket_create(struct net *net, __be16 port,
					      u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct socket *sock;
	unsigned int h;
	bool ipv6 = !!(flags & VXLAN_F_IPV6);
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs)
		return ERR_PTR(-ENOMEM);

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vs->vni_list[h]);

	INIT_WORK(&vs->del_work, vxlan_del_work);

	sock = vxlan_create_sock(net, ipv6, port, flags);
	if (IS_ERR(sock)) {
		pr_info("Cannot bind port %d, err=%ld\n", ntohs(port),
			PTR_ERR(sock));
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	atomic_set(&vs->refcnt, 1);
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

	/* Initialize the vxlan udp offloads structure */
#ifdef HAVE_UDP_OFFLOAD
	vs->udp_offloads.port = port;
	vs->udp_offloads.callbacks.gro_receive  = vxlan_gro_receive;
	vs->udp_offloads.callbacks.gro_complete = vxlan_gro_complete;
	vxlan_notify_add_rx_port(vs);
#endif

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));
	spin_unlock(&vn->sock_lock);

	/* Mark socket as an encapsulation socket. */
	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return vs;
}

static struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
					 bool no_share, u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	bool ipv6 = flags & VXLAN_F_IPV6;

	if (!no_share) {
		spin_lock(&vn->sock_lock);
		vs = vxlan_find_sock(net, ipv6 ? AF_INET6 : AF_INET, port,
				     flags);
		if (vs) {
			if (!atomic_add_unless(&vs->refcnt, 1, 0))
				vs = ERR_PTR(-EBUSY);
			spin_unlock(&vn->sock_lock);
			return vs;
		}
		spin_unlock(&vn->sock_lock);
	}

	return vxlan_socket_create(net, port, flags);
}

static int vxlan_dev_configure(struct net *src_net, struct net_device *dev,
			       struct vxlan_config *conf)
{
	struct vxlan_net *vn = net_generic(src_net, vxlan_net_id);
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_rdst *dst = &vxlan->default_dst;
	int err;
	bool use_ipv6 = false;
	__be16 default_port = vxlan->cfg.dst_port;
	struct net_device *lowerdev = NULL;

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
			vxlan->flags |= VXLAN_F_IPV6;
		}
#endif

		if (!conf->mtu)
			dev->mtu = lowerdev->mtu - (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);

		dev->needed_headroom = lowerdev->hard_header_len +
				       (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);
	} else if (use_ipv6) {
		vxlan->flags |= VXLAN_F_IPV6;
		dev->needed_headroom = ETH_HLEN + VXLAN6_HEADROOM;
	} else {
		dev->needed_headroom = ETH_HLEN + VXLAN_HEADROOM;
	}

	if (conf->mtu) {
		err = __vxlan_change_mtu(dev, lowerdev, dst, conf->mtu, false);
		if (err)
			return err;
	}

	memcpy(&vxlan->cfg, conf, sizeof(*conf));
	if (!vxlan->cfg.dst_port)
		vxlan->cfg.dst_port = default_port;
	vxlan->flags |= conf->flags;

	if (!vxlan->cfg.age_interval)
		vxlan->cfg.age_interval = FDB_AGE_DEFAULT;

	if (vxlan_find_vni(src_net, conf->vni, use_ipv6 ? AF_INET6 : AF_INET,
			   vxlan->cfg.dst_port, vxlan->flags))
		return -EEXIST;

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

struct net_device *rpl_vxlan_dev_create(struct net *net, const char *name,
				    u8 name_assign_type, struct vxlan_config *conf)
{
	struct nlattr *tb[IFLA_MAX+1];
	struct net_device *dev;
	int err;

	memset(&tb, 0, sizeof(tb));

	dev = rtnl_create_link(net, (char *)name, name_assign_type,
			       &vxlan_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = vxlan_dev_configure(net, dev, conf);
	if (err < 0) {
		free_netdev(dev);
		return ERR_PTR(err);
	}

	return dev;
}
EXPORT_SYMBOL_GPL(rpl_vxlan_dev_create);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
static int vxlan_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
#else
static int vxlan_newlink(struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
#endif
{
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
static void vxlan_dellink(struct net_device *dev, struct list_head *head)
#else
static void vxlan_dellink(struct net_device *dev)
#endif
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

	if (nla_put_be16(skb, IFLA_VXLAN_PORT, vxlan->cfg.dst_port))
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
			vxlan_dellink(vxlan->dev, &list_kill);
#else
			vxlan_dellink(vxlan->dev);
#endif
	}

	unregister_netdevice_many(&list_kill);
}

static int vxlan_lowerdev_event(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct vxlan_net *vn = net_generic(dev_net(dev), vxlan_net_id);

	if (event == NETDEV_UNREGISTER)
		vxlan_handle_lowerdev_unregister(vn, dev);

	return NOTIFY_DONE;
}

static struct notifier_block vxlan_notifier_block __read_mostly = {
	.notifier_call = vxlan_lowerdev_event,
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
		if (!net_eq(dev_net(vxlan->dev), net))
			unregister_netdevice_queue(vxlan->dev, &list);
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

DEFINE_COMPAT_PNET_REG_FUNC(device)
int rpl_vxlan_init_module(void)
{
	int rc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	vxlan_wq = create_workqueue("vxlan");
#else
	vxlan_wq = alloc_workqueue("vxlan", 0, 0);
#endif
	if (!vxlan_wq)
		return -ENOMEM;

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
	destroy_workqueue(vxlan_wq);
	return rc;
}

void rpl_vxlan_cleanup_module(void)
{
	rtnl_link_unregister(&vxlan_link_ops);
	unregister_netdevice_notifier(&vxlan_notifier_block);
	destroy_workqueue(vxlan_wq);
	unregister_pernet_subsys(&vxlan_net_ops);
	/* rcu_barrier() is called by netns */
}
#endif
