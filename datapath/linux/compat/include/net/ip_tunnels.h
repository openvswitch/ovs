#ifndef __NET_IP_TUNNELS_WRAPPER_H
#define __NET_IP_TUNNELS_WRAPPER_H 1

#include <linux/version.h>

#ifdef USE_UPSTREAM_TUNNEL
/* Block all ip_tunnel functions.
 * Only function that do not depend on ip_tunnel structure can
 * be used. Those needs to be explicitly defined in this header file. */
#include_next <net/ip_tunnels.h>

#ifndef TUNNEL_ERSPAN_OPT
#define TUNNEL_ERSPAN_OPT	__cpu_to_be16(0x4000)
#endif
#define ovs_ip_tunnel_encap ip_tunnel_encap
#else

#include <linux/if_tunnel.h>
#include <linux/types.h>
#include <net/dsfield.h>
#include <net/dst_cache.h>
#include <net/flow.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/rtnetlink.h>
#include <net/gro_cells.h>

#ifndef MAX_IPTUN_ENCAP_OPS
#define MAX_IPTUN_ENCAP_OPS 8
#endif

#ifndef HAVE_TUNNEL_ENCAP_TYPES
enum tunnel_encap_types {
	TUNNEL_ENCAP_NONE,
	TUNNEL_ENCAP_FOU,
	TUNNEL_ENCAP_GUE,
};

#define HAVE_TUNNEL_ENCAP_TYPES 1
#endif

#define __iptunnel_pull_header rpl___iptunnel_pull_header
int rpl___iptunnel_pull_header(struct sk_buff *skb, int hdr_len,
			   __be16 inner_proto, bool raw_proto, bool xnet);

#define iptunnel_pull_header rpl_iptunnel_pull_header
static inline int rpl_iptunnel_pull_header(struct sk_buff *skb, int hdr_len,
				       __be16 inner_proto, bool xnet)
{
	return rpl___iptunnel_pull_header(skb, hdr_len, inner_proto, false, xnet);
}

int ovs_iptunnel_handle_offloads(struct sk_buff *skb,
				 int gso_type_mask,
				 void (*fix_segment)(struct sk_buff *));

/* This is required to compile upstream gre.h. gre_handle_offloads()
 * is defined in gre.h and needs iptunnel_handle_offloads(). This provides
 * default signature for this function.
 * rpl prefix is to make OVS build happy.
 */
#define iptunnel_handle_offloads rpl_iptunnel_handle_offloads
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
struct sk_buff *rpl_iptunnel_handle_offloads(struct sk_buff *skb,
					     bool csum_help,
					     int gso_type_mask);
#else
int rpl_iptunnel_handle_offloads(struct sk_buff *skb,
				 bool csum_help,
				 int gso_type_mask);
#endif

#define iptunnel_xmit rpl_iptunnel_xmit
void rpl_iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
		       __be32 src, __be32 dst, __u8 proto, __u8 tos, __u8 ttl,
		       __be16 df, bool xnet);
#define ip_tunnel_xmit rpl_ip_tunnel_xmit
void rpl_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
			const struct iphdr *tnl_params, const u8 protocol);


#ifndef TUNNEL_CSUM
#define TUNNEL_CSUM		__cpu_to_be16(0x01)
#define TUNNEL_ROUTING		__cpu_to_be16(0x02)
#define TUNNEL_KEY		__cpu_to_be16(0x04)
#define TUNNEL_SEQ		__cpu_to_be16(0x08)
#define TUNNEL_STRICT		__cpu_to_be16(0x10)
#define TUNNEL_REC		__cpu_to_be16(0x20)
#define TUNNEL_VERSION		__cpu_to_be16(0x40)
#define TUNNEL_NO_KEY		__cpu_to_be16(0x80)
#define TUNNEL_DONT_FRAGMENT    __cpu_to_be16(0x0100)
#define TUNNEL_OAM		__cpu_to_be16(0x0200)
#define TUNNEL_CRIT_OPT		__cpu_to_be16(0x0400)
#define TUNNEL_GENEVE_OPT	__cpu_to_be16(0x0800)
#define TUNNEL_VXLAN_OPT	__cpu_to_be16(0x1000)
#define TUNNEL_NOCACHE		__cpu_to_be16(0x2000)
#define TUNNEL_ERSPAN_OPT	__cpu_to_be16(0x4000)

#undef TUNNEL_OPTIONS_PRESENT
#define TUNNEL_OPTIONS_PRESENT \
		(TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT | TUNNEL_ERSPAN_OPT)

struct tnl_ptk_info {
	__be16 flags;
	__be16 proto;
	__be32 key;
	__be32 seq;
	int hdr_len;
};

#define PACKET_RCVD	0
#define PACKET_REJECT	1
#define PACKET_NEXT	2
#endif

#define IP_TNL_HASH_BITS   7
#define IP_TNL_HASH_SIZE   (1 << IP_TNL_HASH_BITS)

/* Keep error state on tunnel for 30 sec */
#define IPTUNNEL_ERR_TIMEO	(30*HZ)

/* Used to memset ip_tunnel padding. */
#define IP_TUNNEL_KEY_SIZE	offsetofend(struct ip_tunnel_key, tp_dst)

/* Used to memset ipv4 address padding. */
#define IP_TUNNEL_KEY_IPV4_PAD	offsetofend(struct ip_tunnel_key, u.ipv4.dst)
#define IP_TUNNEL_KEY_IPV4_PAD_LEN				\
	(FIELD_SIZEOF(struct ip_tunnel_key, u) -		\
	 FIELD_SIZEOF(struct ip_tunnel_key, u.ipv4))

struct ip_tunnel_key {
	__be64			tun_id;
	union {
		struct {
			__be32	src;
			__be32	dst;
		} ipv4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
	} u;
	__be16			tun_flags;
	u8			tos;		/* TOS for IPv4, TC for IPv6 */
	u8			ttl;		/* TTL for IPv4, HL for IPv6 */
	__be32                  label;          /* Flow Label for IPv6 */
	__be16			tp_src;
	__be16			tp_dst;
};

/* Flags for ip_tunnel_info mode. */
#define IP_TUNNEL_INFO_TX	0x01	/* represents tx tunnel parameters */
#define IP_TUNNEL_INFO_IPV6	0x02	/* key contains IPv6 addresses */

struct ip_tunnel_info {
	struct ip_tunnel_key	key;
	struct dst_cache        dst_cache;
	u8			options_len;
	u8			mode;
};

/* 6rd prefix/relay information */
#ifdef CONFIG_IPV6_SIT_6RD
struct ip_tunnel_6rd_parm {
	struct in6_addr		prefix;
	__be32			relay_prefix;
	u16			prefixlen;
	u16			relay_prefixlen;
};
#endif

struct ip_tunnel_encap {
	u16			type;
	u16			flags;
	__be16			sport;
	__be16			dport;
};

struct ip_tunnel_prl_entry {
	struct ip_tunnel_prl_entry __rcu *next;
	__be32				addr;
	u16				flags;
	struct rcu_head			rcu_head;
};

static inline unsigned short ip_tunnel_info_af(const struct ip_tunnel_info *tun_info)
{
	return tun_info->mode & IP_TUNNEL_INFO_IPV6 ? AF_INET6 : AF_INET;
}

static inline void *ip_tunnel_info_opts(struct ip_tunnel_info *info)
{
	return info + 1;
}

static inline void ip_tunnel_info_opts_get(void *to,
					   const struct ip_tunnel_info *info)
{
	memcpy(to, info + 1, info->options_len);
}

static inline void ip_tunnel_info_opts_set(struct ip_tunnel_info *info,
					   const void *from, int len)
{
	memcpy(ip_tunnel_info_opts(info), from, len);
	info->options_len = len;
}

static inline void ip_tunnel_key_init(struct ip_tunnel_key *key,
				      __be32 saddr, __be32 daddr,
				      u8 tos, u8 ttl, __be32 label,
				      __be16 tp_src, __be16 tp_dst,
				      __be64 tun_id, __be16 tun_flags)
{
	key->tun_id = tun_id;
	key->u.ipv4.src = saddr;
	key->u.ipv4.dst = daddr;
	memset((unsigned char *)key + IP_TUNNEL_KEY_IPV4_PAD,
	       0, IP_TUNNEL_KEY_IPV4_PAD_LEN);
	key->tos = tos;
	key->ttl = ttl;
	key->label = label;
	key->tun_flags = tun_flags;

	/* For the tunnel types on the top of IPsec, the tp_src and tp_dst of
	 * the upper tunnel are used.
	 * E.g: GRE over IPSEC, the tp_src and tp_port are zero.
	 */
	key->tp_src = tp_src;
	key->tp_dst = tp_dst;

	/* Clear struct padding. */
	if (sizeof(*key) != IP_TUNNEL_KEY_SIZE)
		memset((unsigned char *)key + IP_TUNNEL_KEY_SIZE,
		       0, sizeof(*key) - IP_TUNNEL_KEY_SIZE);
}

#define ip_tunnel_collect_metadata() true

#undef TUNNEL_NOCACHE
#define TUNNEL_NOCACHE 0

static inline bool
ip_tunnel_dst_cache_usable(const struct sk_buff *skb,
			   const struct ip_tunnel_info *info)
{
	if (skb->mark)
		return false;
	if (!info)
		return true;
	if (info->key.tun_flags & TUNNEL_NOCACHE)
		return false;

	return true;
}

#define ip_tunnel_dst rpl_ip_tunnel_dst
struct rpl_ip_tunnel_dst {
	struct dst_entry __rcu		*dst;
	__be32				saddr;
};

#define ip_tunnel rpl_ip_tunnel
struct rpl_ip_tunnel {
	struct ip_tunnel __rcu	*next;
	struct hlist_node hash_node;
	struct net_device	*dev;
	struct net		*net;	/* netns for packet i/o */

	unsigned long	err_time;	/* Time when the last ICMP error
					 * arrived */
	int		err_count;	/* Number of arrived ICMP errors */

	/* These four fields used only by GRE */
	u32		i_seqno;	/* The last seen seqno	*/
	u32		o_seqno;	/* The last output seqno */
	int		tun_hlen;	/* Precalculated header length */

	/* These four fields used only by ERSPAN */
	u32		index;		/* ERSPAN type II index */
	u8		erspan_ver;	/* ERSPAN version */
	u8		dir;		/* ERSPAN direction */
	u16		hwid;		/* ERSPAN hardware ID */

	struct dst_cache dst_cache;

	struct ip_tunnel_parm parms;

	int		mlink;
	int		encap_hlen;	/* Encap header length (FOU,GUE) */
	int		hlen;		/* tun_hlen + encap_hlen */
	struct ip_tunnel_encap encap;

	/* for SIT */
#ifdef CONFIG_IPV6_SIT_6RD
	struct ip_tunnel_6rd_parm ip6rd;
#endif
	struct ip_tunnel_prl_entry __rcu *prl;	/* potential router list */
	unsigned int		prl_count;	/* # of entries in PRL */
	unsigned int		ip_tnl_net_id;
	struct gro_cells	gro_cells;
	__u32			fwmark;
	bool			collect_md;
	bool			ignore_df;
};

#define ip_tunnel_net rpl_ip_tunnel_net
struct rpl_ip_tunnel_net {
	struct net_device *fb_tunnel_dev;
	struct hlist_head tunnels[IP_TNL_HASH_SIZE];
	struct ip_tunnel __rcu *collect_md_tun;
};


struct ip_tunnel_encap_ops {
	size_t (*encap_hlen)(struct ip_tunnel_encap *e);
	int (*build_header)(struct sk_buff *skb, struct ip_tunnel_encap *e,
			    const u8 *protocol, struct flowi4 *fl4);
};

extern const struct ip_tunnel_encap_ops __rcu *
		rpl_iptun_encaps[MAX_IPTUN_ENCAP_OPS];

#define ip_encap_hlen rpl_ip_encap_hlen
static inline int rpl_ip_encap_hlen(struct ip_tunnel_encap *e)
{
	const struct ip_tunnel_encap_ops *ops;
	int hlen = -EINVAL;

	if (e->type == TUNNEL_ENCAP_NONE)
		return 0;

	if (e->type >= MAX_IPTUN_ENCAP_OPS)
		return -EINVAL;

	rcu_read_lock();
	ops = rcu_dereference(rpl_iptun_encaps[e->type]);
	if (likely(ops && ops->encap_hlen))
		hlen = ops->encap_hlen(e);
	rcu_read_unlock();

	return hlen;
}

static inline int ovs_ip_tunnel_encap(struct sk_buff *skb, struct ip_tunnel *t,
				      const u8 *protocol, struct flowi4 *fl4)
{
	const struct ip_tunnel_encap_ops *ops;
	int ret = -EINVAL;

	if (t->encap.type == TUNNEL_ENCAP_NONE)
		return 0;

	if (t->encap.type >= MAX_IPTUN_ENCAP_OPS)
		return -EINVAL;

	rcu_read_lock();
	ops = rcu_dereference(rpl_iptun_encaps[t->encap.type]);
	if (likely(ops && ops->build_header))
		ret = ops->build_header(skb, &t->encap, protocol, fl4);
	rcu_read_unlock();

	return ret;
}

#define ip_tunnel_get_stats64 rpl_ip_tunnel_get_stats64
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0) && !defined(HAVE_RHEL7_MAX_MTU)
struct rtnl_link_stats64 *rpl_ip_tunnel_get_stats64(struct net_device *dev,
						    struct rtnl_link_stats64 *tot);
#else
void rpl_ip_tunnel_get_stats64(struct net_device *dev,
						    struct rtnl_link_stats64 *tot);
#endif
#define ip_tunnel_get_dsfield rpl_ip_tunnel_get_dsfield
static inline u8 rpl_ip_tunnel_get_dsfield(const struct iphdr *iph,
					   const struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return iph->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		return ipv6_get_dsfield((const struct ipv6hdr *)iph);
	else
		return 0;
}

#define ip_tunnel_ecn_encap rpl_ip_tunnel_ecn_encap
static inline u8 rpl_ip_tunnel_ecn_encap(u8 tos, const struct iphdr *iph,
		const struct sk_buff *skb)
{
	u8 inner = ip_tunnel_get_dsfield(iph, skb);

	return INET_ECN_encapsulate(tos, inner);
}

static inline void iptunnel_xmit_stats(struct net_device *dev, int pkt_len)
{
	if (pkt_len > 0) {
		struct pcpu_sw_netstats *tstats = get_cpu_ptr(dev->tstats);

		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += pkt_len;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
		put_cpu_ptr(tstats);
	} else {
		struct net_device_stats *err_stats = &dev->stats;

		if (pkt_len < 0) {
			err_stats->tx_errors++;
			err_stats->tx_aborted_errors++;
		} else {
			err_stats->tx_dropped++;
		}
	}
}

static inline __be64 key32_to_tunnel_id(__be32 key)
{
#ifdef __BIG_ENDIAN
	return (__force __be64)key;
#else
	return (__force __be64)((__force u64)key << 32);
#endif
}

/* Returns the least-significant 32 bits of a __be64. */
static inline __be32 tunnel_id_to_key32(__be64 tun_id)
{
#ifdef __BIG_ENDIAN
	return (__force __be32)tun_id;
#else
	return (__force __be32)((__force u64)tun_id >> 32);
#endif
}

#define ip_tunnel_init rpl_ip_tunnel_init
int rpl_ip_tunnel_init(struct net_device *dev);

#define ip_tunnel_uninit rpl_ip_tunnel_uninit
void rpl_ip_tunnel_uninit(struct net_device *dev);

#define ip_tunnel_change_mtu rpl_ip_tunnel_change_mtu
int rpl_ip_tunnel_change_mtu(struct net_device *dev, int new_mtu);

#define ip_tunnel_newlink rpl_ip_tunnel_newlink
int rpl_ip_tunnel_newlink(struct net_device *dev, struct nlattr *tb[],
			  struct ip_tunnel_parm *p);

#define ip_tunnel_dellink rpl_ip_tunnel_dellink
void rpl_ip_tunnel_dellink(struct net_device *dev, struct list_head *head);

#define ip_tunnel_init_net rpl_ip_tunnel_init_net
int rpl_ip_tunnel_init_net(struct net *net, int ip_tnl_net_id,
			   struct rtnl_link_ops *ops, char *devname);

#define ip_tunnel_delete_net rpl_ip_tunnel_delete_net
void rpl_ip_tunnel_delete_net(struct ip_tunnel_net *itn, struct rtnl_link_ops *ops);

#define ip_tunnel_setup rpl_ip_tunnel_setup
void rpl_ip_tunnel_setup(struct net_device *dev, int net_id);

#define ip_tunnel_get_iflink rpl_ip_tunnel_get_iflink
int rpl_ip_tunnel_get_iflink(const struct net_device *dev);

#define ip_tunnel_get_link_net rpl_ip_tunnel_get_link_net
struct net *rpl_ip_tunnel_get_link_net(const struct net_device *dev);

#define __ip_tunnel_change_mtu rpl___ip_tunnel_change_mtu
int rpl___ip_tunnel_change_mtu(struct net_device *dev, int new_mtu, bool strict);

#define ip_tunnel_lookup rpl_ip_tunnel_lookup
struct ip_tunnel *rpl_ip_tunnel_lookup(struct ip_tunnel_net *itn,
				       int link, __be16 flags,
				       __be32 remote, __be32 local,
				       __be32 key);

static inline int iptunnel_pull_offloads(struct sk_buff *skb)
{
	if (skb_is_gso(skb)) {
		int err;

		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			return err;
		skb_shinfo(skb)->gso_type &= ~(NETIF_F_GSO_ENCAP_ALL >>
					       NETIF_F_GSO_SHIFT);
	}

	skb->encapsulation = 0;
	return 0;
}
#endif /* USE_UPSTREAM_TUNNEL */

#define skb_is_encapsulated ovs_skb_is_encapsulated
bool ovs_skb_is_encapsulated(struct sk_buff *skb);

#endif /* __NET_IP_TUNNELS_H */
