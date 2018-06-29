/*
 * Copyright (c) 2013,2018 Nicira, Inc.
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
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/rculist.h>
#include <linux/err.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#endif

#include "compat.h"

#ifndef USE_UPSTREAM_TUNNEL
const struct ip_tunnel_encap_ops __rcu *
		rpl_iptun_encaps[MAX_IPTUN_ENCAP_OPS] __read_mostly;

static unsigned int rpl_ip_tunnel_hash(__be32 key, __be32 remote)
{
	return hash_32((__force u32)key ^ (__force u32)remote,
			 IP_TNL_HASH_BITS);
}

static bool rpl_ip_tunnel_key_match(const struct ip_tunnel_parm *p,
				    __be16 flags, __be32 key)
{
	if (p->i_flags & TUNNEL_KEY) {
		if (flags & TUNNEL_KEY)
			return key == p->i_key;
		else
			/* key expected, none present */
			return false;
	} else
		return !(flags & TUNNEL_KEY);
}

static struct hlist_head *ip_bucket(struct ip_tunnel_net *itn,
				    struct ip_tunnel_parm *parms)
{
	unsigned int h;
	__be32 remote;
	__be32 i_key = parms->i_key;

	if (parms->iph.daddr && !ipv4_is_multicast(parms->iph.daddr))
		remote = parms->iph.daddr;
	else
		remote = 0;

	if (!(parms->i_flags & TUNNEL_KEY) && (parms->i_flags & VTI_ISVTI))
		i_key = 0;

	h = rpl_ip_tunnel_hash(i_key, remote);
	return &itn->tunnels[h];
}

static void ip_tunnel_add(struct ip_tunnel_net *itn, struct ip_tunnel *t)
{
	struct hlist_head *head = ip_bucket(itn, &t->parms);

	if (t->collect_md)
		rcu_assign_pointer(itn->collect_md_tun, t);
	hlist_add_head_rcu(&t->hash_node, head);
}

static void ip_tunnel_del(struct ip_tunnel_net *itn, struct ip_tunnel *t)
{
	if (t->collect_md)
		rcu_assign_pointer(itn->collect_md_tun, NULL);
	hlist_del_init_rcu(&t->hash_node);
}

static struct net_device *__ip_tunnel_create(struct net *net,
					     const struct rtnl_link_ops *ops,
					     struct ip_tunnel_parm *parms)
{
	int err;
	struct ip_tunnel *tunnel;
	struct net_device *dev;
	char name[IFNAMSIZ];

	if (parms->name[0])
		strlcpy(name, parms->name, IFNAMSIZ);
	else {
		if (strlen(ops->kind) > (IFNAMSIZ - 3)) {
			err = -E2BIG;
			goto failed;
		}
		strlcpy(name, ops->kind, IFNAMSIZ);
		strncat(name, "%d", 2);
	}

	ASSERT_RTNL();
	dev = alloc_netdev(ops->priv_size, name, NET_NAME_UNKNOWN, ops->setup);
	if (!dev) {
		err = -ENOMEM;
		goto failed;
	}
	dev_net_set(dev, net);

	dev->rtnl_link_ops = ops;

	tunnel = netdev_priv(dev);
	tunnel->parms = *parms;
	tunnel->net = net;

	err = register_netdevice(dev);
	if (err)
		goto failed_free;

	return dev;

failed_free:
	free_netdev(dev);
failed:
	return ERR_PTR(err);
}

static inline void init_tunnel_flow(struct flowi4 *fl4,
				    int proto,
				    __be32 daddr, __be32 saddr,
				    __be32 key, __u8 tos, int oif)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = oif;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = proto;
	fl4->fl4_gre_key = key;
}

static int ip_tunnel_bind_dev(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *iph;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int t_hlen = tunnel->hlen + sizeof(struct iphdr);

	iph = &tunnel->parms.iph;

	/* Guess output device to choose reasonable mtu and needed_headroom */
	if (iph->daddr) {
		struct flowi4 fl4;
		struct rtable *rt;

		init_tunnel_flow(&fl4, iph->protocol, iph->daddr,
				 iph->saddr, tunnel->parms.o_key,
				 RT_TOS(iph->tos), tunnel->parms.link);
		rt = ip_route_output_key(tunnel->net, &fl4);

		if (!IS_ERR(rt)) {
			tdev = rt->dst.dev;
			ip_rt_put(rt);
		}
		if (dev->type != ARPHRD_ETHER)
			dev->flags |= IFF_POINTOPOINT;

		dst_cache_reset(&tunnel->dst_cache);
	}

	if (!tdev && tunnel->parms.link)
		tdev = __dev_get_by_index(tunnel->net, tunnel->parms.link);

	if (tdev) {
		hlen = tdev->hard_header_len + tdev->needed_headroom;
		mtu = tdev->mtu;
	}

	dev->needed_headroom = t_hlen + hlen;
	mtu -= (dev->hard_header_len + t_hlen);

	if (mtu < 68)
		mtu = 68;

	return mtu;
}

int rpl___ip_tunnel_change_mtu(struct net_device *dev, int new_mtu, bool strict)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	int t_hlen = tunnel->hlen + sizeof(struct iphdr);
	int max_mtu = 0xFFF8 - dev->hard_header_len - t_hlen;

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

int rpl_ip_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	return rpl___ip_tunnel_change_mtu(dev, new_mtu, true);
}

static int rpl_tnl_update_pmtu(struct net_device *dev, struct sk_buff *skb,
			       struct rtable *rt, __be16 df,
			       const struct iphdr *inner_iph)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	int pkt_size = skb->len - tunnel->hlen - dev->hard_header_len;
	int mtu;

	if (df)
		mtu = dst_mtu(&rt->dst) - dev->hard_header_len
					- sizeof(struct iphdr) - tunnel->hlen;
	else
		mtu = skb_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!skb_is_gso(skb) &&
		    (inner_iph->frag_off & htons(IP_DF)) &&
		    mtu < pkt_size) {
			memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
			return -E2BIG;
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct rt6_info *rt6 = (struct rt6_info *)skb_dst(skb);

		if (rt6 && mtu < dst_mtu(skb_dst(skb)) &&
			   mtu >= IPV6_MIN_MTU) {
			if ((tunnel->parms.iph.daddr &&
			    !ipv4_is_multicast(tunnel->parms.iph.daddr)) ||
			    rt6->rt6i_dst.plen == 128) {
				rt6->rt6i_flags |= RTF_MODIFIED;
				dst_metric_set(skb_dst(skb), RTAX_MTU, mtu);
			}
		}

		if (!skb_is_gso(skb) && mtu >= IPV6_MIN_MTU &&
					mtu < pkt_size) {
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
			return -E2BIG;
		}
	}
#endif
	return 0;
}

void rpl_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
		        const struct iphdr *tnl_params, const u8 protocol)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *inner_iph;
	struct flowi4 fl4;
	u8     tos, ttl;
	__be16 df;
	struct rtable *rt;		/* Route to the other host */
	unsigned int max_headroom;	/* The extra header space needed */
	__be32 dst;
	bool connected;

	inner_iph = (const struct iphdr *)skb_inner_network_header(skb);
	connected = (tunnel->parms.iph.daddr != 0);

	dst = tnl_params->daddr;
	if (dst == 0) {
		/* NBMA tunnel */

		if (skb_dst(skb) == NULL) {
			dev->stats.tx_fifo_errors++;
			goto tx_error;
		}

		if (skb->protocol == htons(ETH_P_IP)) {
			rt = skb_rtable(skb);
			dst = rt_nexthop(rt, inner_iph->daddr);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (skb->protocol == htons(ETH_P_IPV6)) {
			const struct in6_addr *addr6;
			struct neighbour *neigh;
			bool do_tx_error_icmp;
			int addr_type;

			neigh = dst_neigh_lookup(skb_dst(skb),
						 &ipv6_hdr(skb)->daddr);
			if (neigh == NULL)
				goto tx_error;

			addr6 = (const struct in6_addr *)&neigh->primary_key;
			addr_type = ipv6_addr_type(addr6);

			if (addr_type == IPV6_ADDR_ANY) {
				addr6 = &ipv6_hdr(skb)->daddr;
				addr_type = ipv6_addr_type(addr6);
			}

			if ((addr_type & IPV6_ADDR_COMPATv4) == 0)
				do_tx_error_icmp = true;
			else {
				do_tx_error_icmp = false;
				dst = addr6->s6_addr32[3];
			}
			neigh_release(neigh);
			if (do_tx_error_icmp)
				goto tx_error_icmp;
		}
#endif
		else
			goto tx_error;

		connected = false;
	}

	tos = tnl_params->tos;
	if (tos & 0x1) {
		tos &= ~0x1;
		if (skb->protocol == htons(ETH_P_IP)) {
			tos = inner_iph->tos;
			connected = false;
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			tos = ipv6_get_dsfield((const struct ipv6hdr *)inner_iph);
			connected = false;
		}
	}

	init_tunnel_flow(&fl4, protocol, dst, tnl_params->saddr,
			 tunnel->parms.o_key, RT_TOS(tos), tunnel->parms.link);

	if (ovs_ip_tunnel_encap(skb, tunnel, &protocol, &fl4) < 0)
		goto tx_error;

	rt = connected ? dst_cache_get_ip4(&tunnel->dst_cache, &fl4.saddr) :
			 NULL;

	if (!rt) {
		rt = ip_route_output_key(tunnel->net, &fl4);

		if (IS_ERR(rt)) {
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}
		if (connected)
			dst_cache_set_ip4(&tunnel->dst_cache, &rt->dst,
					  fl4.saddr);
	}

	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		dev->stats.collisions++;
		goto tx_error;
	}

	if (rpl_tnl_update_pmtu(dev, skb, rt,
				tnl_params->frag_off, inner_iph)) {
		ip_rt_put(rt);
		goto tx_error;
	}

	if (tunnel->err_count > 0) {
		if (time_before(jiffies,
				tunnel->err_time + IPTUNNEL_ERR_TIMEO)) {
			tunnel->err_count--;

			memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	tos = ip_tunnel_ecn_encap(tos, inner_iph, skb);
	ttl = tnl_params->ttl;
	if (ttl == 0) {
		if (skb->protocol == htons(ETH_P_IP))
			ttl = inner_iph->ttl;
#if IS_ENABLED(CONFIG_IPV6)
		else if (skb->protocol == htons(ETH_P_IPV6))
			ttl = ((const struct ipv6hdr *)inner_iph)->hop_limit;
#endif
		else
			ttl = ip4_dst_hoplimit(&rt->dst);
	}

	df = tnl_params->frag_off;
	if (skb->protocol == htons(ETH_P_IP))
		df |= (inner_iph->frag_off&htons(IP_DF));

	max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr)
			+ rt->dst.header_len;
	if (max_headroom > dev->needed_headroom)
		dev->needed_headroom = max_headroom;

	if (skb_cow_head(skb, dev->needed_headroom)) {
		ip_rt_put(rt);
		dev->stats.tx_dropped++;
		kfree_skb(skb);
		return;
	}

	iptunnel_xmit(skb->sk, rt, skb, fl4.saddr, fl4.daddr, protocol,
		      tos, ttl, df, !net_eq(tunnel->net, dev_net(dev)));

	return;

#if IS_ENABLED(CONFIG_IPV6)
tx_error_icmp:
	dst_link_failure(skb);
#endif
tx_error:
	dev->stats.tx_errors++;
	kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(rpl_ip_tunnel_xmit);

static void ip_tunnel_dev_free(struct net_device *dev)
{
	free_percpu(dev->tstats);
#ifndef HAVE_NEEDS_FREE_NETDEV
	free_netdev(dev);
#endif
}

void rpl_ip_tunnel_dellink(struct net_device *dev, struct list_head *head)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct ip_tunnel_net *itn;

	itn = net_generic(tunnel->net, tunnel->ip_tnl_net_id);

	ip_tunnel_del(itn, netdev_priv(dev));
        unregister_netdevice_queue(dev, head);
}

int rpl_ip_tunnel_init_net(struct net *net, int ip_tnl_net_id,
				  struct rtnl_link_ops *ops, char *devname)
{
	struct ip_tunnel_net *itn = net_generic(net, ip_tnl_net_id);
	struct ip_tunnel_parm parms;
	unsigned int i;

	for (i = 0; i < IP_TNL_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&itn->tunnels[i]);

	if (!ops) {
		itn->fb_tunnel_dev = NULL;
		return 0;
	}

	memset(&parms, 0, sizeof(parms));
	if (devname)
		strlcpy(parms.name, devname, IFNAMSIZ);

	rtnl_lock();
	itn->fb_tunnel_dev = __ip_tunnel_create(net, ops, &parms);
	/* FB netdevice is special: we have one, and only one per netns.
 * 	 * Allowing to move it to another netns is clearly unsafe.
 * 	 	 */
	if (!IS_ERR(itn->fb_tunnel_dev)) {
		itn->fb_tunnel_dev->features |= NETIF_F_NETNS_LOCAL;
		itn->fb_tunnel_dev->mtu = ip_tunnel_bind_dev(itn->fb_tunnel_dev);
		ip_tunnel_add(itn, netdev_priv(itn->fb_tunnel_dev));
	}
	rtnl_unlock();

	return PTR_ERR_OR_ZERO(itn->fb_tunnel_dev);
}

static void ip_tunnel_destroy(struct ip_tunnel_net *itn, struct list_head *head,
			      struct rtnl_link_ops *ops)
{
	struct net *net = dev_net(itn->fb_tunnel_dev);
	struct net_device *dev, *aux;
	int h;

	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == ops)
			unregister_netdevice_queue(dev, head);

	for (h = 0; h < IP_TNL_HASH_SIZE; h++) {
		struct ip_tunnel *t;
		struct hlist_node *n;
		struct hlist_head *thead = &itn->tunnels[h];

		hlist_for_each_entry_safe(t, n, thead, hash_node)
			/* If dev is in the same netns, it has already
			 * been added to the list by the previous loop.
 			 */
			if (!net_eq(dev_net(t->dev), net))
				unregister_netdevice_queue(t->dev, head);
	}
}

void rpl_ip_tunnel_delete_net(struct ip_tunnel_net *itn,
			      struct rtnl_link_ops *ops)
{
	LIST_HEAD(list);

	rtnl_lock();
	ip_tunnel_destroy(itn, &list, ops);
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

int rpl_ip_tunnel_newlink(struct net_device *dev, struct nlattr *tb[],
		      struct ip_tunnel_parm *p)
{
	struct ip_tunnel *nt;
	struct net *net = dev_net(dev);
	struct ip_tunnel_net *itn;
	int mtu;
	int err;

	nt = netdev_priv(dev);
	itn = net_generic(net, nt->ip_tnl_net_id);

	if (nt->collect_md) {
		if (rtnl_dereference(itn->collect_md_tun))
			return -EEXIST;
	} else {
		return -EOPNOTSUPP;
	}

	nt->net = net;
	nt->parms = *p;
	err = register_netdevice(dev);
	if (err)
		goto out;

	if (dev->type == ARPHRD_ETHER && !tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	mtu = ip_tunnel_bind_dev(dev);
	if (!tb[IFLA_MTU])
		dev->mtu = mtu;

	ip_tunnel_add(itn, nt);
out:
	return err;
}

int rpl_ip_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;
	int err;

#ifndef HAVE_NEEDS_FREE_NETDEV
	dev->destructor = ip_tunnel_dev_free;
#else
	dev->needs_free_netdev = true;
	dev->priv_destructor = ip_tunnel_dev_free;
#endif
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	err = dst_cache_init(&tunnel->dst_cache, GFP_KERNEL);
	if (err) {
		free_percpu(dev->tstats);
		return err;
	}

	err = gro_cells_init(&tunnel->gro_cells, dev);
	if (err) {
		dst_cache_destroy(&tunnel->dst_cache);
		free_percpu(dev->tstats);
		return err;
	}

	tunnel->dev = dev;
	tunnel->net = dev_net(dev);
	strcpy(tunnel->parms.name, dev->name);
	iph->version		= 4;
	iph->ihl		= 5;

	if (tunnel->collect_md) {
		dev->features |= NETIF_F_NETNS_LOCAL;
		netif_keep_dst(dev);
	}
	return 0;
}

void rpl_ip_tunnel_uninit(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct net *net = tunnel->net;
	struct ip_tunnel_net *itn;

	itn = net_generic(net, tunnel->ip_tnl_net_id);
	ip_tunnel_del(itn, netdev_priv(dev));
}

/* Do least required initialization, rest of init is done in tunnel_init call */
void rpl_ip_tunnel_setup(struct net_device *dev, int net_id)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);

	tunnel->ip_tnl_net_id = net_id;
}

int rpl_ip_tunnel_get_iflink(const struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);

	return tunnel->parms.link;
}

struct net *rpl_ip_tunnel_get_link_net(const struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);

	return tunnel->net;
}

struct ip_tunnel *rpl_ip_tunnel_lookup(struct ip_tunnel_net *itn,
				       int link, __be16 flags,
				       __be32 remote, __be32 local,
				       __be32 key)
{
	unsigned int hash;
	struct ip_tunnel *t, *cand = NULL;
	struct hlist_head *head;

	hash = rpl_ip_tunnel_hash(key, remote);
	head = &itn->tunnels[hash];

	hlist_for_each_entry_rcu(t, head, hash_node) {
		if (local != t->parms.iph.saddr ||
		    remote != t->parms.iph.daddr ||
		    !(t->dev->flags & IFF_UP))
			continue;

		if (!rpl_ip_tunnel_key_match(&t->parms, flags, key))
			continue;

		if (t->parms.link == link)
			return t;
		else
			cand = t;
	}

	hlist_for_each_entry_rcu(t, head, hash_node) {
		if (remote != t->parms.iph.daddr ||
		    t->parms.iph.saddr != 0 ||
		    !(t->dev->flags & IFF_UP))
			continue;

		if (!rpl_ip_tunnel_key_match(&t->parms, flags, key))
			continue;

		if (t->parms.link == link)
			return t;
		else if (!cand)
			cand = t;
	}

	hash = rpl_ip_tunnel_hash(key, 0);
	head = &itn->tunnels[hash];

	hlist_for_each_entry_rcu(t, head, hash_node) {
		if ((local != t->parms.iph.saddr || t->parms.iph.daddr != 0) &&
		    (local != t->parms.iph.daddr || !ipv4_is_multicast(local)))
			continue;

		if (!(t->dev->flags & IFF_UP))
			continue;

		if (!rpl_ip_tunnel_key_match(&t->parms, flags, key))
			continue;

		if (t->parms.link == link)
			return t;
		else if (!cand)
			cand = t;
	}

	if (flags & TUNNEL_NO_KEY)
		goto skip_key_lookup;

	hlist_for_each_entry_rcu(t, head, hash_node) {
		if (t->parms.i_key != key ||
		    t->parms.iph.saddr != 0 ||
		    t->parms.iph.daddr != 0 ||
		    !(t->dev->flags & IFF_UP))
			continue;

		if (t->parms.link == link)
			return t;
		else if (!cand)
			cand = t;
	}

skip_key_lookup:
	if (cand)
		return cand;

	t = rcu_dereference(itn->collect_md_tun);
	if (t)
		return t;

	if (itn->fb_tunnel_dev && itn->fb_tunnel_dev->flags & IFF_UP)
		return netdev_priv(itn->fb_tunnel_dev);


	return NULL;
}
EXPORT_SYMBOL_GPL(rpl_ip_tunnel_lookup);

#endif
