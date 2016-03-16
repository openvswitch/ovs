#ifndef __NET_IP_TUNNELS_WRAPPER_H
#define __NET_IP_TUNNELS_WRAPPER_H 1

#include <linux/version.h>

#ifdef HAVE_METADATA_DST
/* Block all ip_tunnel functions.
 * Only function that do not depend on ip_tunnel structure can
 * be used. Those needs to be explicitly defined in this header file. */
#include_next <net/ip_tunnels.h>
#endif

#include <linux/if_tunnel.h>
#include <linux/types.h>
#include <net/dsfield.h>
#include <net/flow.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/rtnetlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
struct sk_buff *ovs_iptunnel_handle_offloads(struct sk_buff *skb,
					     bool csum_help, int gso_type_mask,
					     void (*fix_segment)(struct sk_buff *));

#define iptunnel_xmit rpl_iptunnel_xmit
int rpl_iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
		      __be32 src, __be32 dst, __u8 proto, __u8 tos, __u8 ttl,
		      __be16 df, bool xnet);

#define iptunnel_pull_header rpl_iptunnel_pull_header
int rpl_iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto);

#else

#define ovs_iptunnel_handle_offloads(skb, csum_help, gso_type_mask, fix_segment) \
	iptunnel_handle_offloads(skb, csum_help, gso_type_mask)

/* This macro is to make OVS build happy about declared functions name. */
#define rpl_iptunnel_pull_header iptunnel_pull_header
int rpl_iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto);

#define rpl_iptunnel_xmit iptunnel_xmit
int rpl_iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
		      __be32 src, __be32 dst, __u8 proto, __u8 tos, __u8 ttl,
		      __be16 df, bool xnet);

#endif /* 3.18 */

/* This is not required for OVS on kernel older than 3.18, but gre.h
 * header file needs this declaration for function gre_handle_offloads().
 * So it is defined for all kernel version.
 */
#define rpl_iptunnel_handle_offloads iptunnel_handle_offloads
struct sk_buff *rpl_iptunnel_handle_offloads(struct sk_buff *skb, bool gre_csum,
					 int gso_type_mask);

#ifndef TUNNEL_CSUM
#define TUNNEL_CSUM	__cpu_to_be16(0x01)
#define TUNNEL_ROUTING	__cpu_to_be16(0x02)
#define TUNNEL_KEY	__cpu_to_be16(0x04)
#define TUNNEL_SEQ	__cpu_to_be16(0x08)
#define TUNNEL_STRICT	__cpu_to_be16(0x10)
#define TUNNEL_REC	__cpu_to_be16(0x20)
#define TUNNEL_VERSION	__cpu_to_be16(0x40)
#define TUNNEL_NO_KEY	__cpu_to_be16(0x80)

struct tnl_ptk_info {
	__be16 flags;
	__be16 proto;
	__be32 key;
	__be32 seq;
};

#define PACKET_RCVD	0
#define PACKET_REJECT	1
#endif

#ifndef TUNNEL_DONT_FRAGMENT
#define TUNNEL_DONT_FRAGMENT	__cpu_to_be16(0x0100)
#endif

#ifndef TUNNEL_OAM
#define TUNNEL_OAM	__cpu_to_be16(0x0200)
#define TUNNEL_CRIT_OPT	__cpu_to_be16(0x0400)
#endif

#ifndef TUNNEL_GENEVE_OPT
#define TUNNEL_GENEVE_OPT	__cpu_to_be16(0x0800)
#endif

#ifndef TUNNEL_VXLAN_OPT
#define TUNNEL_VXLAN_OPT	__cpu_to_be16(0x1000)
#endif

/* Older kernels defined TUNNEL_OPTIONS_PRESENT to GENEVE only */
#undef TUNNEL_OPTIONS_PRESENT
#define TUNNEL_OPTIONS_PRESENT (TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT)

#define skb_is_encapsulated ovs_skb_is_encapsulated
bool ovs_skb_is_encapsulated(struct sk_buff *skb);

#ifndef HAVE_METADATA_DST
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
	__be16			tp_src;
	__be16			tp_dst;
};

/* Flags for ip_tunnel_info mode. */
#define IP_TUNNEL_INFO_TX	0x01	/* represents tx tunnel parameters */
#define IP_TUNNEL_INFO_IPV6	0x02	/* key contains IPv6 addresses */

struct ip_tunnel_info {
	struct ip_tunnel_key	key;
	u8			options_len;
	u8			mode;
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
				      u8 tos, u8 ttl,
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


#define ip_tunnel rpl_ip_tunnel

struct ip_tunnel {
	struct net_device	*dev;
	struct net		*net;	/* netns for packet i/o */

	int		err_count;	/* Number of arrived ICMP errors */
	unsigned long	err_time;	/* Time when the last ICMP error
					 * arrived
					 */

	/* These four fields used only by GRE */
	u32		i_seqno;	/* The last seen seqno	*/
	u32		o_seqno;	/* The last output seqno */
	int		tun_hlen;	/* Precalculated header length */
	int		mlink;

	struct ip_tunnel_parm parms;

	int		encap_hlen;	/* Encap header length (FOU,GUE) */
	int		hlen;		/* tun_hlen + encap_hlen */

	int		ip_tnl_net_id;
	bool		collect_md;
};

#define ip_tunnel_net rpl_ip_tunnel_net
struct ip_tunnel_net {
	struct ip_tunnel __rcu *collect_md_tun;
	struct rtnl_link_ops *rtnl_ops;
};


#ifndef HAVE_PCPU_SW_NETSTATS
#define ip_tunnel_get_stats64 rpl_ip_tunnel_get_stats64
#else
#define rpl_ip_tunnel_get_stats64 ip_tunnel_get_stats64
#endif
struct rtnl_link_stats64 *rpl_ip_tunnel_get_stats64(struct net_device *dev,
						    struct rtnl_link_stats64 *tot);

#define ip_tunnel_get_dsfield rpl_ip_tunnel_get_dsfield
static inline u8 ip_tunnel_get_dsfield(const struct iphdr *iph,
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
static inline u8 ip_tunnel_ecn_encap(u8 tos, const struct iphdr *iph,
		const struct sk_buff *skb)
{
	u8 inner = ip_tunnel_get_dsfield(iph, skb);

	return INET_ECN_encapsulate(tos, inner);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define iptunnel_xmit_stats(err, stats, dummy)		\
do {							\
	if (err > 0) {					\
		(stats)->tx_bytes += err;		\
		(stats)->tx_packets++;			\
	} else if (err < 0) {				\
		(stats)->tx_errors++;			\
		(stats)->tx_aborted_errors++;		\
	} else {					\
		(stats)->tx_dropped++;			\
	}						\
} while (0)

#else
#define iptunnel_xmit_stats rpl_iptunnel_xmit_stats
static inline void iptunnel_xmit_stats(int err,
		struct net_device_stats *err_stats,
		struct pcpu_sw_netstats __percpu *stats)
{
	if (err > 0) {
		struct pcpu_sw_netstats *tstats = this_cpu_ptr(stats);

		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += err;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
	} else if (err < 0) {
		err_stats->tx_errors++;
		err_stats->tx_aborted_errors++;
	} else {
		err_stats->tx_dropped++;
	}
}
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
void rpl_ip_tunnel_dellink(struct net_device *dev, struct list_head *head);
#else
void rpl_ip_tunnel_dellink(struct net_device *dev);
#endif

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
#endif /* HAVE_METADATA_DST */

#ifndef HAVE___IP_TUNNEL_CHANGE_MTU
#define __ip_tunnel_change_mtu rpl___ip_tunnel_change_mtu
int rpl___ip_tunnel_change_mtu(struct net_device *dev, int new_mtu, bool strict);
#endif

#endif /* __NET_IP_TUNNELS_H */
