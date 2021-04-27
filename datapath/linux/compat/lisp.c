/*
 * Copyright (c) 2015 Nicira, Inc.
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
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>

#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/lisp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-netdev.h"

#define LISP_UDP_PORT		4341
#define LISP_NETDEV_VER		"0.1"
static int lisp_net_id;

/* Pseudo network device */
struct lisp_dev {
	struct net         *net;        /* netns for packet i/o */
	struct net_device  *dev;        /* netdev for lisp tunnel */
	struct socket __rcu  *sock;
	__be16             dst_port;
	struct list_head   next;
};

/* per-network namespace private data for this module */
struct lisp_net {
	struct list_head lisp_list;
};

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
#define LISP_MAX_MTU (IP_MAX_MTU - LISP_HLEN - sizeof(struct iphdr))

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

static void lisp_build_header(struct sk_buff *skb,
			      const struct ip_tunnel_key *tun_key)
{
	struct lisphdr *lisph;

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
	struct lisp_dev *lisp_dev;
	struct net_device *dev;
	struct lisphdr *lisph;
	struct iphdr *inner_iph;
	struct metadata_dst *tun_dst;
#ifndef USE_UPSTREAM_TUNNEL
	struct metadata_dst temp;
#endif
	__be64 key;
	struct ethhdr *ethh;
	__be16 protocol;

	dev = rcu_dereference_sk_user_data(sk);
	if (unlikely(!dev))
		goto error;

	lisp_dev = netdev_priv(dev);
	if (iptunnel_pull_header(skb, LISP_HLEN, 0,
				 !net_eq(lisp_dev->net, dev_net(lisp_dev->dev))))
		goto error;

	lisph = lisp_hdr(skb);

	if (lisph->instance_id_present != 1)
		key = 0;
	else
		key = instance_id_to_tunnel_id(&lisph->u2.word2.instance_id[0]);

	/* Save outer tunnel values */
#ifndef USE_UPSTREAM_TUNNEL
	tun_dst = &temp;
	ovs_udp_tun_rx_dst(tun_dst, skb, AF_INET, TUNNEL_KEY, key, 0);
#else
	tun_dst = udp_tun_rx_dst(skb, AF_INET, TUNNEL_KEY, key, 0);
#endif
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

	ovs_ip_tunnel_rcv(dev, skb, tun_dst);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

static struct rtable *lisp_get_rt(struct sk_buff *skb,
				 struct net_device *dev,
				 struct flowi4 *fl,
				 const struct ip_tunnel_key *key)
{
	struct net *net = dev_net(dev);

	/* Route lookup */
	memset(fl, 0, sizeof(*fl));
	fl->daddr = key->u.ipv4.dst;
	fl->saddr = key->u.ipv4.src;
	fl->flowi4_tos = RT_TOS(key->tos);
	fl->flowi4_mark = skb->mark;
	fl->flowi4_proto = IPPROTO_UDP;

	return ip_route_output_key(net, fl);
}

/* this is to handle the return type change in handle-offload
 * functions.
 */
#if !defined(HAVE_UDP_TUNNEL_HANDLE_OFFLOAD_RET_SKB) || !defined(USE_UPSTREAM_TUNNEL)
static struct sk_buff *
__udp_tunnel_handle_offloads(struct sk_buff *skb, bool udp_csum)
{
	int err;

	err = udp_tunnel_handle_offloads(skb, udp_csum);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}
	return skb;
}
#else
#define __udp_tunnel_handle_offloads udp_tunnel_handle_offloads
#endif

netdev_tx_t rpl_lisp_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct lisp_dev *lisp_dev = netdev_priv(dev);
	struct net *net = lisp_dev->net;
	int network_offset = skb_network_offset(skb);
	struct ip_tunnel_info *info;
	struct ip_tunnel_key *tun_key;
	__be16 src_port, dst_port;
	struct rtable *rt;
	int min_headroom;
	struct socket *sock;
	struct flowi4 fl;
	__be16 df;
	int err;

	info = skb_tunnel_info(skb);
	if (unlikely(!info)) {
		err = -EINVAL;
		goto error;
	}

	sock = rcu_dereference(lisp_dev->sock);
	if (!sock) {
		err = -EIO;
		goto error;
	}

	if (skb->protocol != htons(ETH_P_IP) &&
			skb->protocol != htons(ETH_P_IPV6)) {
		err = 0;
		goto error;
	}

	tun_key = &info->key;

	rt = lisp_get_rt(skb, dev, &fl, tun_key);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
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
	skb->vlan_tci = 0;

	if (skb_is_gso(skb) && skb_is_encapsulated(skb))
		goto err_free_rt;

	skb = __udp_tunnel_handle_offloads(skb, false);
	if (!skb)
		return NETDEV_TX_OK;

	src_port = htons(get_src_port(net, skb));
	dst_port = lisp_dev->dst_port;

	lisp_build_header(skb, tun_key);

	skb->ignore_df = 1;

	ovs_skb_set_inner_protocol(skb, skb->protocol);

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	udp_tunnel_xmit_skb(rt, sock->sk, skb,
			    fl.saddr, tun_key->u.ipv4.dst,
			    tun_key->tos, tun_key->ttl,
			    df, src_port, dst_port, false, true);

	return NETDEV_TX_OK;

err_free_rt:
	ip_rt_put(rt);
error:
	kfree_skb(skb);
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(rpl_lisp_xmit);

/* Setup stats when device is created */
static int lisp_init(struct net_device *dev)
{
	dev->tstats = (typeof(dev->tstats)) netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void lisp_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}

static struct socket *create_sock(struct net *net, bool ipv6,
				       __be16 port)
{
	struct socket *sock;
	struct udp_port_cfg udp_conf;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));

	if (ipv6) {
		udp_conf.family = AF_INET6;
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

static int lisp_open(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct udp_tunnel_sock_cfg tunnel_cfg;
	struct net *net = lisp->net;
	struct socket *sock;

	sock = create_sock(net, false, lisp->dst_port);
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	rcu_assign_pointer(lisp->sock, sock);
	/* Mark socket as an encapsulation socket */
	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = dev;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = lisp_rcv;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);
	return 0;
}

static int lisp_stop(struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct socket *socket;

	socket = rtnl_dereference(lisp->sock);
	if (!socket)
		return 0;

	rcu_assign_pointer(lisp->sock, NULL);

	synchronize_net();
	udp_tunnel_sock_release(socket);
	return 0;
}

static netdev_tx_t lisp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
#ifdef USE_UPSTREAM_TUNNEL
	return rpl_lisp_xmit(skb);
#else
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */

	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
#endif
}

static int lisp_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > LISP_MAX_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int egress_ipv4_tun_info(struct net_device *dev, struct sk_buff *skb,
				struct ip_tunnel_info *info,
				__be16 sport, __be16 dport)
{
	struct rtable *rt;
	struct flowi4 fl4;

	rt = lisp_get_rt(skb, dev, &fl4, &info->key);
	if (IS_ERR(rt))
		return PTR_ERR(rt);
	ip_rt_put(rt);

	info->key.u.ipv4.src = fl4.saddr;
	info->key.tp_src = sport;
	info->key.tp_dst = dport;
	return 0;
}

int ovs_lisp_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct lisp_dev *lisp = netdev_priv(dev);
	struct net *net = lisp->net;
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	__be16 sport, dport;

	sport = htons(get_src_port(net, skb));
	dport = lisp->dst_port;

	if (ip_tunnel_info_af(info) == AF_INET)
		return egress_ipv4_tun_info(dev, skb, info, sport, dport);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(ovs_lisp_fill_metadata_dst);

static const struct net_device_ops lisp_netdev_ops = {
	.ndo_init               = lisp_init,
	.ndo_uninit             = lisp_uninit,
	.ndo_get_stats64        = ip_tunnel_get_stats64,
	.ndo_open               = lisp_open,
	.ndo_stop               = lisp_stop,
	.ndo_start_xmit         = lisp_dev_xmit,
#ifdef  HAVE_RHEL7_MAX_MTU
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_change_mtu = lisp_change_mtu,
#else
	.ndo_change_mtu         = lisp_change_mtu,
#endif
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_set_mac_address    = eth_mac_addr,
#ifdef USE_UPSTREAM_TUNNEL
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst  = lisp_fill_metadata_dst,
#endif
#endif
};

static void lisp_get_drvinfo(struct net_device *dev,
		struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->version, LISP_NETDEV_VER, sizeof(drvinfo->version));
	strlcpy(drvinfo->driver, "lisp", sizeof(drvinfo->driver));
}

static const struct ethtool_ops lisp_ethtool_ops = {
	.get_drvinfo    = lisp_get_drvinfo,
	.get_link       = ethtool_op_get_link,
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type lisp_type = {
	.name = "lisp",
};

/* Initialize the device structure. */
static void lisp_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &lisp_netdev_ops;
	dev->ethtool_ops = &lisp_ethtool_ops;
#ifndef HAVE_NEEDS_FREE_NETDEV
	dev->destructor = free_netdev;
#else
	dev->needs_free_netdev = true;
#endif

	SET_NETDEV_DEVTYPE(dev, &lisp_type);

	dev->features    |= NETIF_F_LLTX | NETIF_F_NETNS_LOCAL;
	dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features    |= NETIF_F_RXCSUM;
	dev->features    |= NETIF_F_GSO_SOFTWARE;

	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
#ifdef USE_UPSTREAM_TUNNEL
	netif_keep_dst(dev);
#endif
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	eth_hw_addr_random(dev);
}

static const struct nla_policy lisp_policy[IFLA_LISP_MAX + 1] = {
	[IFLA_LISP_PORT]              = { .type = NLA_U16 },
};

#ifdef HAVE_RTNLOP_VALIDATE_WITH_EXTACK
static int lisp_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack __always_unused *extack)
#else
static int lisp_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	return 0;
}

static struct lisp_dev *find_dev(struct net *net, __be16 dst_port)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);
	struct lisp_dev *dev;

	list_for_each_entry(dev, &ln->lisp_list, next) {
		if (dev->dst_port == dst_port)
			return dev;
	}
	return NULL;
}

static int lisp_configure(struct net *net, struct net_device *dev,
			  __be16 dst_port)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);
	struct lisp_dev *lisp = netdev_priv(dev);
	int err;

	lisp->net = net;
	lisp->dev = dev;

	lisp->dst_port = dst_port;

	if (find_dev(net, dst_port))
		return -EBUSY;

	err = lisp_change_mtu(dev, LISP_MAX_MTU);
	if (err)
		return err;

	err = register_netdevice(dev);
	if (err)
		return err;

	list_add(&lisp->next, &ln->lisp_list);
	return 0;
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int lisp_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack __always_unused *extack)
#else
static int lisp_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[])
#endif
{
	__be16 dst_port = htons(LISP_UDP_PORT);

	if (data[IFLA_LISP_PORT])
		dst_port = nla_get_be16(data[IFLA_LISP_PORT]);

	return lisp_configure(net, dev, dst_port);
}

static void lisp_dellink(struct net_device *dev, struct list_head *head)
{
	struct lisp_dev *lisp = netdev_priv(dev);

	list_del(&lisp->next);
	unregister_netdevice_queue(dev, head);
}

static size_t lisp_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__be32));  /* IFLA_LISP_PORT */
}

static int lisp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct lisp_dev *lisp = netdev_priv(dev);

	if (nla_put_be16(skb, IFLA_LISP_PORT, lisp->dst_port))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops lisp_link_ops __read_mostly = {
	.kind           = "lisp",
	.maxtype        = IFLA_LISP_MAX,
	.policy         = lisp_policy,
	.priv_size      = sizeof(struct lisp_dev),
	.setup          = lisp_setup,
	.validate       = lisp_validate,
	.newlink        = lisp_newlink,
	.dellink        = lisp_dellink,
	.get_size       = lisp_get_size,
	.fill_info      = lisp_fill_info,
};

struct net_device *rpl_lisp_dev_create_fb(struct net *net, const char *name,
				      u8 name_assign_type, u16 dst_port)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	int err;

	memset(tb, 0, sizeof(tb));
	dev = rtnl_create_link(net, (char *) name, name_assign_type,
			&lisp_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = lisp_configure(net, dev, htons(dst_port));
	if (err) {
		free_netdev(dev);
		return ERR_PTR(err);
	}
	return dev;
}
EXPORT_SYMBOL_GPL(rpl_lisp_dev_create_fb);

static int lisp_init_net(struct net *net)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);

	INIT_LIST_HEAD(&ln->lisp_list);
	return 0;
}

static void lisp_exit_net(struct net *net)
{
	struct lisp_net *ln = net_generic(net, lisp_net_id);
	struct lisp_dev *lisp, *next;
	struct net_device *dev, *aux;
	LIST_HEAD(list);

	rtnl_lock();

	/* gather any lisp devices that were moved into this ns */
	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == &lisp_link_ops)
			unregister_netdevice_queue(dev, &list);

	list_for_each_entry_safe(lisp, next, &ln->lisp_list, next) {
		/* If lisp->dev is in the same netns, it was already added
		 * to the lisp by the previous loop.
		 */
		if (!net_eq(dev_net(lisp->dev), net))
			unregister_netdevice_queue(lisp->dev, &list);
	}

	/* unregister the devices gathered above */
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations lisp_net_ops = {
	.init = lisp_init_net,
	.exit = lisp_exit_net,
	.id   = &lisp_net_id,
	.size = sizeof(struct lisp_net),
};

int rpl_lisp_init_module(void)
{
	int rc;

	rc = register_pernet_subsys(&lisp_net_ops);
	if (rc)
		goto out1;

	rc = rtnl_link_register(&lisp_link_ops);
	if (rc)
		goto out2;

	pr_info("LISP tunneling driver\n");
	return 0;
out2:
	unregister_pernet_subsys(&lisp_net_ops);
out1:
	pr_err("Error while initializing LISP %d\n", rc);
	return rc;
}

void rpl_lisp_cleanup_module(void)
{
	rtnl_link_unregister(&lisp_link_ops);
	unregister_pernet_subsys(&lisp_net_ops);
}
