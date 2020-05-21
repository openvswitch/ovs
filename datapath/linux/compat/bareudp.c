// SPDX-License-Identifier: GPL-2.0
/* Bareudp: UDP  tunnel encasulation for different Payload types like
 * MPLS, NSH, IP, etc.
 * Copyright (c) 2019 Nokia, Inc.
 * Authors:  Martin Varghese, <martin.varghese@nokia.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/hash.h>
#include <net/netns/generic.h>
#include <net/dst_metadata.h>
#include <net/rtnetlink.h>
#include <net/protocol.h>
#include <net/ip6_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/udp_tunnel.h>
#include <net/bareudp.h>

#include "compat.h"
#include "vport-netdev.h"

#ifndef USE_UPSTREAM_TUNNEL

#define BAREUDP_BASE_HLEN sizeof(struct udphdr)
#define BAREUDP_IPV4_HLEN (sizeof(struct iphdr) + \
		sizeof(struct udphdr))
#define BAREUDP_IPV6_HLEN (sizeof(struct ipv6hdr) + \
		sizeof(struct udphdr))

static bool log_ecn_error = true;
module_param(log_ecn_error, bool, 0644);
MODULE_PARM_DESC(log_ecn_error, "Log packets received with corrupted ECN");

/* per-network namespace private data for this module */

static unsigned int bareudp_net_id;

struct bareudp_net {
	struct list_head        bareudp_list;
};

/* Pseudo network device */
struct bareudp_dev {
	struct net         *net;        /* netns for packet i/o */
	struct net_device  *dev;        /* netdev for bareudp tunnel */
	__be16		   ethertype;
	__be16             port;
	u16	           sport_min;
	bool               multi_proto_mode;
	struct socket      __rcu *sock;
	struct list_head   next;        /* bareudp node  on namespace list */
};

static int bareudp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct metadata_dst *tun_dst = NULL;
	struct pcpu_sw_netstats *stats;
	struct bareudp_dev *bareudp;
	unsigned short family;
	unsigned int len;
	__be16 proto;
	void *oiph;
	int err;
	union {
		struct metadata_dst dst;
		char buf[sizeof(struct metadata_dst) + 256];
	} buf;

	bareudp = rcu_dereference_sk_user_data(sk);
	if (!bareudp)
		goto drop;

	if (skb->protocol ==  htons(ETH_P_IP))
		family = AF_INET;
	else
		family = AF_INET6;

	if (bareudp->ethertype == htons(ETH_P_IP)) {
		struct iphdr *iphdr;

		iphdr = (struct iphdr *)(skb->data + BAREUDP_BASE_HLEN);
		if (iphdr->version == 4) {
			proto = bareudp->ethertype;
		} else if (bareudp->multi_proto_mode && (iphdr->version == 6)) {
			proto = htons(ETH_P_IPV6);
		} else {
			bareudp->dev->stats.rx_dropped++;
			goto drop;
		}
	} else if (bareudp->ethertype == htons(ETH_P_MPLS_UC)) {
		struct iphdr *tunnel_hdr;

		tunnel_hdr = (struct iphdr *)skb_network_header(skb);
		if (tunnel_hdr->version == 4) {
			if (!ipv4_is_multicast(tunnel_hdr->daddr)) {
				proto = bareudp->ethertype;
			} else if (bareudp->multi_proto_mode &&
					ipv4_is_multicast(tunnel_hdr->daddr)) {
				proto = htons(ETH_P_MPLS_MC);
			} else {
				bareudp->dev->stats.rx_dropped++;
				goto drop;
			}
		} else {
			int addr_type;
			struct ipv6hdr *tunnel_hdr_v6;

			tunnel_hdr_v6 = (struct ipv6hdr *)skb_network_header(skb);
			addr_type =
				ipv6_addr_type((struct in6_addr *)&tunnel_hdr_v6->daddr);
			if (!(addr_type & IPV6_ADDR_MULTICAST)) {
				proto = bareudp->ethertype;
			} else if (bareudp->multi_proto_mode &&
					(addr_type & IPV6_ADDR_MULTICAST)) {
				proto = htons(ETH_P_MPLS_MC);
			} else {
				bareudp->dev->stats.rx_dropped++;
				goto drop;
			}
		}
	} else {
		proto = bareudp->ethertype;
	}

	if (iptunnel_pull_header(skb, BAREUDP_BASE_HLEN,
				proto,
				!net_eq(bareudp->net,
					dev_net(bareudp->dev)))) {
		bareudp->dev->stats.rx_dropped++;
		goto drop;
	}
	tun_dst = &buf.dst;
	ovs_udp_tun_rx_dst(tun_dst, skb, family, TUNNEL_KEY, 0, 0);
	if (!tun_dst) {
		bareudp->dev->stats.rx_dropped++;
		goto drop;
	}
	ovs_skb_dst_set(skb, &tun_dst->dst);

	skb->dev = bareudp->dev;
	oiph = skb_network_header(skb);
	skb_reset_network_header(skb);

	if (family == AF_INET)
		err = IP_ECN_decapsulate(oiph, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else
		err = IP6_ECN_decapsulate(oiph, skb);
#endif

	if (unlikely(err)) {
		if (log_ecn_error) {
			if  (family == AF_INET)
				net_info_ratelimited("non-ECT from %pI4 "
						"with TOS=%#x\n",
						&((struct iphdr *)oiph)->saddr,
						((struct iphdr *)oiph)->tos);
#if IS_ENABLED(CONFIG_IPV6)
			else
				net_info_ratelimited("non-ECT from %pI6\n",
						&((struct ipv6hdr *)oiph)->saddr);
#endif
		}
		if (err > 1) {
			++bareudp->dev->stats.rx_frame_errors;
			++bareudp->dev->stats.rx_errors;
			goto drop;
		}
	}

	len = skb->len;
	netdev_port_receive(skb, skb_tunnel_info(skb));
	if (likely(err == NET_RX_SUCCESS)) {
		stats = this_cpu_ptr(bareudp->dev->tstats);
		u64_stats_update_begin(&stats->syncp);
		stats->rx_packets++;
		stats->rx_bytes += len;
		u64_stats_update_end(&stats->syncp);
	}
	return 0;
drop:
	/* Consume bad packet */
	kfree_skb(skb);

	return 0;
}

static int bareudp_init(struct net_device *dev)
{
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void bareudp_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}

static struct socket *bareudp_create_sock(struct net *net, __be16 port)
{
	struct udp_port_cfg udp_conf;
	struct socket *sock;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));
#if IS_ENABLED(CONFIG_IPV6)
	udp_conf.family = AF_INET6;
#else
	udp_conf.family = AF_INET;
#endif
	udp_conf.local_udp_port = port;
	/* Open UDP socket */
	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	return sock;
}

/* Create new listen socket if needed */
static int bareudp_socket_create(struct bareudp_dev *bareudp, __be16 port)
{
	struct udp_tunnel_sock_cfg tunnel_cfg;
	struct socket *sock;

	sock = bareudp_create_sock(bareudp->net, port);
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	/* Mark socket as an encapsulation socket */
	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = bareudp;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = bareudp_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock(bareudp->net, sock, &tunnel_cfg);

	/* As the setup_udp_tunnel_sock does not call udp_encap_enable if the
	 * socket type is v6 an explicit call to udp_encap_enable is needed.
	 */
	if (sock->sk->sk_family == AF_INET6)
		udp_encap_enable();

	rcu_assign_pointer(bareudp->sock, sock);
	return 0;
}

static int bareudp_open(struct net_device *dev)
{
	struct bareudp_dev *bareudp = netdev_priv(dev);
	int ret = 0;

	ret =  bareudp_socket_create(bareudp, bareudp->port);
	return ret;
}

static void bareudp_sock_release(struct bareudp_dev *bareudp)
{
	struct socket *sock;

	sock = bareudp->sock;
	rcu_assign_pointer(bareudp->sock, NULL);
	synchronize_net();
	udp_tunnel_sock_release(sock);
}

static int bareudp_stop(struct net_device *dev)
{
	struct bareudp_dev *bareudp = netdev_priv(dev);

	bareudp_sock_release(bareudp);
	return 0;
}

static int bareudp_xmit_skb(struct sk_buff *skb, struct net_device *dev,
		struct bareudp_dev *bareudp,
		const struct ip_tunnel_info *info)
{
	bool xnet = !net_eq(bareudp->net, dev_net(bareudp->dev));
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct socket *sock = rcu_dereference(bareudp->sock);
	bool udp_sum = !!(info->key.tun_flags & TUNNEL_CSUM);
	const struct ip_tunnel_key *key = &info->key;
	struct rtable *rt;
	__be16 sport, df;
	int min_headroom;
	__u8 tos, ttl;
	__be32 saddr;
	int err;

	if (!sock)
		return -ESHUTDOWN;

	rt = ip_route_output_tunnel(skb, dev, bareudp->net, &saddr, info,
			IPPROTO_UDP, use_cache);

	if (IS_ERR(rt))
		return PTR_ERR(rt);

	sport = udp_flow_src_port(bareudp->net, skb,
			bareudp->sport_min, USHRT_MAX,
			true);
	tos = ip_tunnel_ecn_encap(key->tos, ip_hdr(skb), skb);
	ttl = key->ttl;
	df = key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	skb_scrub_packet(skb, xnet);

	err = -ENOSPC;
	if (!skb_pull(skb, skb_network_offset(skb)))
		goto free_dst;

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len +
		BAREUDP_BASE_HLEN + info->options_len + sizeof(struct iphdr);

	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		goto free_dst;

	err = udp_tunnel_handle_offloads(skb, udp_sum);
	if (err)
		goto free_dst;

	skb_set_inner_protocol(skb, bareudp->ethertype);
	udp_tunnel_xmit_skb(rt, sock->sk, skb, saddr, info->key.u.ipv4.dst,
			tos, ttl, df, sport, bareudp->port,
			!net_eq(bareudp->net, dev_net(bareudp->dev)),
			!(info->key.tun_flags & TUNNEL_CSUM));
	return 0;

free_dst:
	dst_release(&rt->dst);
	return err;
}

#if IS_ENABLED(CONFIG_IPV6)
static int bareudp6_xmit_skb(struct sk_buff *skb, struct net_device *dev,
		struct bareudp_dev *bareudp,
		const struct ip_tunnel_info *info)
{
	bool xnet = !net_eq(bareudp->net, dev_net(bareudp->dev));
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct socket *sock  = rcu_dereference(bareudp->sock);
	bool udp_sum = !!(info->key.tun_flags & TUNNEL_CSUM);
	const struct ip_tunnel_key *key = &info->key;
	struct dst_entry *dst = NULL;
	struct in6_addr saddr, daddr;
	int min_headroom;
	__u8 prio, ttl;
	__be16 sport;
	int err;

	if (!sock)
		return -ESHUTDOWN;

	dst = ip6_dst_lookup_tunnel(skb, dev, bareudp->net, sock, &saddr, info,
			IPPROTO_UDP, use_cache);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	sport = udp_flow_src_port(bareudp->net, skb,
			bareudp->sport_min, USHRT_MAX,
			true);
	prio = ip_tunnel_ecn_encap(key->tos, ip_hdr(skb), skb);
	ttl = key->ttl;

	skb_scrub_packet(skb, xnet);

	err = -ENOSPC;
	if (!skb_pull(skb, skb_network_offset(skb)))
		goto free_dst;

	min_headroom = LL_RESERVED_SPACE(dst->dev) + dst->header_len +
		BAREUDP_BASE_HLEN + info->options_len + sizeof(struct iphdr);

	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		goto free_dst;

	err = udp_tunnel_handle_offloads(skb, udp_sum);
	if (err)
		goto free_dst;

	daddr = info->key.u.ipv6.dst;
	udp_tunnel6_xmit_skb(dst, sock->sk, skb, dev,
			&saddr, &daddr, prio, ttl,
			info->key.label, sport, bareudp->port,
			!(info->key.tun_flags & TUNNEL_CSUM));
	return 0;

free_dst:
	dst_release(dst);
	return err;
}
#endif

netdev_tx_t rpl_bareudp_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct bareudp_dev *bareudp = netdev_priv(dev);
	struct ip_tunnel_info *info = NULL;
	int err;

	if (skb->protocol != bareudp->ethertype) {
		if (!bareudp->multi_proto_mode ||
				(skb->protocol !=  htons(ETH_P_MPLS_MC) &&
				 skb->protocol !=  htons(ETH_P_IPV6))) {
			err = -EINVAL;
			goto tx_error;
		}
	}

	info = skb_tunnel_info(skb);
	if (unlikely(!info || !(info->mode & IP_TUNNEL_INFO_TX))) {
		err = -EINVAL;
		goto tx_error;
	}

	rcu_read_lock();
#if IS_ENABLED(CONFIG_IPV6)
	if (info->mode & IP_TUNNEL_INFO_IPV6)
		err = bareudp6_xmit_skb(skb, dev, bareudp, info);
	else
#endif
		err = bareudp_xmit_skb(skb, dev, bareudp, info);

	rcu_read_unlock();

	if (likely(!err))
		return NETDEV_TX_OK;
tx_error:
	dev_kfree_skb(skb);

	if (err == -ELOOP)
		dev->stats.collisions++;
	else if (err == -ENETUNREACH)
		dev->stats.tx_carrier_errors++;

	dev->stats.tx_errors++;
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL_GPL(rpl_bareudp_xmit);

static netdev_tx_t bareudp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */
	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}


int ovs_bareudp_fill_metadata_dst(struct net_device *dev,
		struct sk_buff *skb)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	struct bareudp_dev *bareudp = netdev_priv(dev);
	bool use_cache;

	use_cache = ip_tunnel_dst_cache_usable(skb, info);

	if (ip_tunnel_info_af(info) == AF_INET) {
		struct rtable *rt;
		__be32 saddr;

		rt = ip_route_output_tunnel(skb, dev, bareudp->net, &saddr,
				info, IPPROTO_UDP, use_cache);
		if (IS_ERR(rt))
			return PTR_ERR(rt);

		ip_rt_put(rt);
		info->key.u.ipv4.src = saddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_tunnel_info_af(info) == AF_INET6) {
		struct dst_entry *dst;
		struct in6_addr saddr;
		struct socket *sock = rcu_dereference(bareudp->sock);

		dst = ip6_dst_lookup_tunnel(skb, dev, bareudp->net, sock,
				&saddr, info, IPPROTO_UDP,
				use_cache);
		if (IS_ERR(dst))
			return PTR_ERR(dst);

		dst_release(dst);
		info->key.u.ipv6.src = saddr;
#endif
	} else {
		return -EINVAL;
	}

	info->key.tp_src = udp_flow_src_port(bareudp->net, skb,
			bareudp->sport_min,
			USHRT_MAX, true);
	info->key.tp_dst = bareudp->port;
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_bareudp_fill_metadata_dst);

static const struct net_device_ops bareudp_netdev_ops = {
	.ndo_init               = bareudp_init,
	.ndo_uninit             = bareudp_uninit,
	.ndo_open               = bareudp_open,
	.ndo_stop               = bareudp_stop,
	.ndo_start_xmit         = bareudp_dev_xmit,
	.ndo_get_stats64        = ip_tunnel_get_stats64,
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst  = bareudp_fill_metadata_dst,
#endif
};

static const struct nla_policy bareudp_policy[IFLA_BAREUDP_MAX + 1] = {
	[IFLA_BAREUDP_PORT]                = { .type = NLA_U16 },
	[IFLA_BAREUDP_ETHERTYPE]	   = { .type = NLA_U16 },
	[IFLA_BAREUDP_SRCPORT_MIN]         = { .type = NLA_U16 },
	[IFLA_BAREUDP_MULTIPROTO_MODE]     = { .type = NLA_FLAG },
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type bareudp_type = {
	.name = "bareudp",
};

/* Initialize the device structure. */
static void bareudp_setup(struct net_device *dev)
{
	dev->netdev_ops = &bareudp_netdev_ops;
	SET_NETDEV_DEVTYPE(dev, &bareudp_type);
	dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features    |= NETIF_F_RXCSUM;
	dev->features    |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = IP_MAX_MTU - BAREUDP_BASE_HLEN;
	dev->type = ARPHRD_NONE;
	netif_keep_dst(dev);
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
}
#ifdef  HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int bareudp_validate(struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack *extack)
#else
static int bareudp_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	if (!data) {
		return -EINVAL;
	}
	return 0;
}
#ifdef  HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int bareudp2info(struct nlattr *data[], struct bareudp_conf *conf,
		struct netlink_ext_ack *extack)
#else
static int bareudp2info(struct nlattr *data[], struct bareudp_conf *conf)
#endif
{
	if (!data[IFLA_BAREUDP_PORT]) {
		return -EINVAL;
	}
	if (!data[IFLA_BAREUDP_ETHERTYPE]) {
		return -EINVAL;
	}

	if (data[IFLA_BAREUDP_PORT])
		conf->port =  nla_get_u16(data[IFLA_BAREUDP_PORT]);

	if (data[IFLA_BAREUDP_ETHERTYPE])
		conf->ethertype =  nla_get_u16(data[IFLA_BAREUDP_ETHERTYPE]);

	if (data[IFLA_BAREUDP_SRCPORT_MIN])
		conf->sport_min =  nla_get_u16(data[IFLA_BAREUDP_SRCPORT_MIN]);

	return 0;
}

static struct bareudp_dev *bareudp_find_dev(struct bareudp_net *bn,
		const struct bareudp_conf *conf)
{
	struct bareudp_dev *bareudp, *t = NULL;

	list_for_each_entry(bareudp, &bn->bareudp_list, next) {
		if (conf->port == bareudp->port)
			t = bareudp;
	}
	return t;
}

static int bareudp_configure(struct net *net, struct net_device *dev,
		struct bareudp_conf *conf)
{
	struct bareudp_net *bn = net_generic(net, bareudp_net_id);
	struct bareudp_dev *t, *bareudp = netdev_priv(dev);
	int err;

	bareudp->net = net;
	bareudp->dev = dev;
	t = bareudp_find_dev(bn, conf);
	if (t)
		return -EBUSY;

	if (conf->multi_proto_mode &&
			(conf->ethertype != htons(ETH_P_MPLS_UC) &&
			 conf->ethertype != htons(ETH_P_IP)))
		return -EINVAL;

	bareudp->port = conf->port;
	bareudp->ethertype = conf->ethertype;
	bareudp->sport_min = conf->sport_min;
	bareudp->multi_proto_mode = conf->multi_proto_mode;
	err = register_netdevice(dev);
	if (err)
		return err;

	list_add(&bareudp->next, &bn->bareudp_list);
	return 0;
}

static int bareudp_link_config(struct net_device *dev,
		struct nlattr *tb[])
{
	int err;

	if (tb[IFLA_MTU]) {
		err = dev_set_mtu(dev, nla_get_u32(tb[IFLA_MTU]));
		if (err)
			return err;
	}
	return 0;
}
#ifdef  HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int bareudp_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack *extack)
#else
static int bareudp_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[])
#endif

{
	struct bareudp_conf conf;
	int err;
#ifdef  HAVE_EXT_ACK_IN_RTNL_LINKOPS
	err = bareudp2info(data, &conf, extack);
#else
	err = bareudp2info(data, &conf);
#endif
	if (err)
		return err;

	err = bareudp_configure(net, dev, &conf);
	if (err)
		return err;

	err = bareudp_link_config(dev, tb);
	if (err)
		return err;

	return 0;
}

static void bareudp_dellink(struct net_device *dev, struct list_head *head)
{
	struct bareudp_dev *bareudp = netdev_priv(dev);

	list_del(&bareudp->next);
	unregister_netdevice_queue(dev, head);
}

static size_t bareudp_get_size(const struct net_device *dev)
{
	return  nla_total_size(sizeof(__be16)) +  /* IFLA_BAREUDP_PORT */
		nla_total_size(sizeof(__be16)) +  /* IFLA_BAREUDP_ETHERTYPE */
		nla_total_size(sizeof(__u16))  +  /* IFLA_BAREUDP_SRCPORT_MIN */
		nla_total_size(0)              +  /* IFLA_BAREUDP_MULTIPROTO_MODE */
		0;
}

static int bareudp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct bareudp_dev *bareudp = netdev_priv(dev);

	if (nla_put_be16(skb, IFLA_BAREUDP_PORT, bareudp->port))
		goto nla_put_failure;
	if (nla_put_be16(skb, IFLA_BAREUDP_ETHERTYPE, bareudp->ethertype))
		goto nla_put_failure;
	if (nla_put_u16(skb, IFLA_BAREUDP_SRCPORT_MIN, bareudp->sport_min))
		goto nla_put_failure;
	if (bareudp->multi_proto_mode &&
			nla_put_flag(skb, IFLA_BAREUDP_MULTIPROTO_MODE))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops bareudp_link_ops __read_mostly = {
	.kind           = "ovs_bareudp",
	.maxtype        = IFLA_BAREUDP_MAX,
	.policy         = bareudp_policy,
	.priv_size      = sizeof(struct bareudp_dev),
	.setup          = bareudp_setup,
	.validate       = bareudp_validate,
	.newlink        = bareudp_newlink,
	.dellink        = bareudp_dellink,
	.get_size       = bareudp_get_size,
	.fill_info      = bareudp_fill_info,
};

struct net_device *rpl_bareudp_dev_create(struct net *net, const char *name,
		u8 name_assign_type,
		struct bareudp_conf *conf)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	LIST_HEAD(list_kill);
	int err;

	memset(tb, 0, sizeof(tb));
	dev = rtnl_create_link(net, name, name_assign_type,
			&bareudp_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = bareudp_configure(net, dev, conf);
	if (err) {
		free_netdev(dev);
		return ERR_PTR(err);
	}
	err = dev_set_mtu(dev, IP_MAX_MTU - BAREUDP_BASE_HLEN);
	if (err)
		goto err;

	err = rtnl_configure_link(dev, NULL);
	if (err < 0)
		goto err;

	return dev;
err:
	bareudp_dellink(dev, &list_kill);
	unregister_netdevice_many(&list_kill);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rpl_bareudp_dev_create);

static __net_init int bareudp_init_net(struct net *net)
{
	struct bareudp_net *bn = net_generic(net, bareudp_net_id);

	INIT_LIST_HEAD(&bn->bareudp_list);
	return 0;
}

static void bareudp_destroy_tunnels(struct net *net, struct list_head *head)
{
	struct bareudp_net *bn = net_generic(net, bareudp_net_id);
	struct bareudp_dev *bareudp, *next;

	list_for_each_entry_safe(bareudp, next, &bn->bareudp_list, next)
		unregister_netdevice_queue(bareudp->dev, head);
}

static void __net_exit bareudp_exit_batch_net(struct list_head *net_list)
{
	struct net *net;
	LIST_HEAD(list);

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list)
		bareudp_destroy_tunnels(net, &list);

	/* unregister the devices gathered above */
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations bareudp_net_ops = {
	.init = bareudp_init_net,
	.exit_batch = bareudp_exit_batch_net,
	.id   = &bareudp_net_id,
	.size = sizeof(struct bareudp_net),
};

static struct vport_ops ovs_bareudp_vport_ops;

/**
 * struct bareudp_port - Keeps track of open UDP ports
 * @dst_port: destination port.
 * @payload_ethertype: ethertype of the l3 traffic tunnelled
 */
struct bareudp_port {
	u16 dst_port;
	u16 payload_ethertype;
};

static inline struct bareudp_port *bareudp_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static int bareudp_get_options(const struct vport *vport,
		struct sk_buff *skb)
{
	struct bareudp_port *bareudp_port = bareudp_vport(vport);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, bareudp_port->dst_port))
		return -EMSGSIZE;

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_PAYLOAD_ETHERTYPE, bareudp_port->dst_port))
		return -EMSGSIZE;

	return 0;
}

static const struct nla_policy exts_policy[OVS_BAREUDP_EXT_MAX + 1] = {
        [OVS_BAREUDP_EXT_MULTIPROTO_MODE]     = { .type = NLA_FLAG, },
};

static int bareudp_configure_exts(struct vport *vport, struct nlattr *attr,
		struct bareudp_conf *conf)
{
	struct nlattr *exts[OVS_BAREUDP_EXT_MAX + 1];
	int err;

	if (nla_len(attr) < sizeof(struct nlattr))
		return -EINVAL;

	err = nla_parse_nested_deprecated(exts, OVS_BAREUDP_EXT_MAX, attr,
			exts_policy, NULL);
	if (err < 0)
		return err;

	if (exts[OVS_BAREUDP_EXT_MULTIPROTO_MODE])
		conf->multi_proto_mode = true;

	return 0;
}

static struct vport *bareudp_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct bareudp_port *bareudp_port;
	struct net_device *dev;
	struct vport *vport;
	struct bareudp_conf conf;
	struct nlattr *a;
	u16 ethertype;
	u16 dst_port;
	int err;

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

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_PAYLOAD_ETHERTYPE);
	if (a && nla_len(a) == sizeof(u16)) {
		ethertype = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	vport = ovs_vport_alloc(sizeof(struct bareudp_port),
				&ovs_bareudp_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_EXTENSION);
	if (a) {
		err = bareudp_configure_exts(vport, a, &conf);
		if (err) {
			ovs_vport_free(vport);
			goto error;
		}
	}

	bareudp_port = bareudp_vport(vport);
	bareudp_port->dst_port = dst_port;
	bareudp_port->payload_ethertype = ethertype;

	conf.ethertype = htons(ethertype);
	conf.port = htons(dst_port);

	rtnl_lock();
	dev = bareudp_dev_create(net, parms->name, NET_NAME_USER, &conf);
	if (IS_ERR(dev)) {
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_CAST(dev);
	}

	err = dev_change_flags(dev, dev->flags | IFF_UP, NULL);
	if (err < 0) {
		rtnl_delete_link(dev);
		rtnl_unlock();
		ovs_vport_free(vport);
		goto error;
	}

	rtnl_unlock();
	return vport;
error:
	return ERR_PTR(err);
}

static struct vport *bareudp_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = bareudp_tnl_create(parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static struct vport_ops ovs_bareudp_vport_ops = {
        .type           = OVS_VPORT_TYPE_BAREUDP,
        .create         = bareudp_create,
        .destroy        = ovs_netdev_tunnel_destroy,
        .get_options    = bareudp_get_options,
#ifndef USE_UPSTREAM_TUNNEL
        .fill_metadata_dst = bareudp_fill_metadata_dst,
#endif
        .send           = bareudp_xmit,
};

int rpl_bareudp_init_module(void)
{
	int rc;

	rc = register_pernet_subsys(&bareudp_net_ops);
	if (rc)
		goto out1;

	rc = rtnl_link_register(&bareudp_link_ops);
	if (rc)
		goto out2;

	pr_info("Bareudp tunneling driver\n");
        ovs_vport_ops_register(&ovs_bareudp_vport_ops);
	return 0;
out2:
	unregister_pernet_subsys(&bareudp_net_ops);
out1:
	return rc;
}

void rpl_bareudp_cleanup_module(void)
{
        ovs_vport_ops_unregister(&ovs_bareudp_vport_ops);
	rtnl_link_unregister(&bareudp_link_ops);
	unregister_pernet_subsys(&bareudp_net_ops);
}
#endif
