#ifndef NET_IP6_TUNNEL_WRAPPER_H
#define NET_IP6_TUNNEL_WRAPPER_H 1

#ifdef HAVE_IP6_TNL_PARM_ERSPAN_VER
#include_next <net/ip6_tunnel.h>
#else

#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/dst_cache.h>
#include <net/dst_metadata.h>
#include "gso.h"

#define IP6TUNNEL_ERR_TIMEO (30*HZ)

/* capable of sending packets */
#define IP6_TNL_F_CAP_XMIT 0x10000
/* capable of receiving packets */
#define IP6_TNL_F_CAP_RCV 0x20000
/* determine capability on a per-packet basis */
#define IP6_TNL_F_CAP_PER_PACKET 0x40000

#ifndef IP6_TNL_F_ALLOW_LOCAL_REMOTE
#define IP6_TNL_F_ALLOW_LOCAL_REMOTE 0
#endif

struct rpl__ip6_tnl_parm {
	char name[IFNAMSIZ];	/* name of tunnel device */
	int link;		/* ifindex of underlying L2 interface */
	__u8 proto;		/* tunnel protocol */
	__u8 encap_limit;	/* encapsulation limit for tunnel */
	__u8 hop_limit;		/* hop limit for tunnel */
	bool collect_md;
	__be32 flowinfo;	/* traffic class and flowlabel for tunnel */
	__u32 flags;		/* tunnel flags */
	struct in6_addr laddr;	/* local tunnel end-point address */
	struct in6_addr raddr;	/* remote tunnel end-point address */

	__be16			i_flags;
	__be16			o_flags;
	__be32			i_key;
	__be32			o_key;

	__u32			fwmark;
	__u32			index;	/* ERSPAN type II index */
	__u8			erspan_ver;	/* ERSPAN version */
	__u8			dir;	/* direction */
	__u16			hwid;	/* hwid */
};

#define __ip6_tnl_parm rpl__ip6_tnl_parm

/* IPv6 tunnel */
struct rpl_ip6_tnl {
	struct rpl_ip6_tnl __rcu *next;	/* next tunnel in list */
	struct net_device *dev;	/* virtual device associated with tunnel */
	struct net *net;	/* netns for packet i/o */
	struct __ip6_tnl_parm parms;	/* tunnel configuration parameters */
	struct flowi fl;	/* flowi template for xmit */
	struct dst_cache dst_cache;	/* cached dst */
	struct gro_cells gro_cells;

	int err_count;
	unsigned long err_time;

	/* These fields used only by GRE */
	__u32 i_seqno;	/* The last seen seqno	*/
	__u32 o_seqno;	/* The last output seqno */
	int hlen;       /* tun_hlen + encap_hlen */
	int tun_hlen;	/* Precalculated header length */
	int encap_hlen; /* Encap header length (FOU,GUE) */
	struct ip_tunnel_encap encap;
	int mlink;
};

#define ip6_tnl rpl_ip6_tnl

struct rpl_ip6_tnl_encap_ops {
	size_t (*encap_hlen)(struct ip_tunnel_encap *e);
	int (*build_header)(struct sk_buff *skb, struct ip_tunnel_encap *e,
			    u8 *protocol, struct flowi6 *fl6);
};

#define ip6_tnl_encap_ops rpl_ip6_tnl_encap_ops

#ifdef CONFIG_INET

#ifndef MAX_IPTUN_ENCAP_OPS
#define MAX_IPTUN_ENCAP_OPS 8
#endif

extern const struct ip6_tnl_encap_ops __rcu *
		rpl_ip6tun_encaps[MAX_IPTUN_ENCAP_OPS];

int rpl_ip6_tnl_encap_add_ops(const struct ip6_tnl_encap_ops *ops,
			      unsigned int num);
#define ip6_tnl_encap_add_ops rpl_ip6_tnl_encap_add_ops
int rpl_ip6_tnl_encap_del_ops(const struct ip6_tnl_encap_ops *ops,
			      unsigned int num);
#define ip6_tnl_encap_del_ops rpl_ip6_tnl_encap_del_ops 
int rpl_ip6_tnl_encap_setup(struct ip6_tnl *t,
			    struct ip_tunnel_encap *ipencap);
#define ip6_tnl_encap_setup rpl_ip6_tnl_encap_setup

#ifndef HAVE_TUNNEL_ENCAP_TYPES
enum tunnel_encap_types {
	TUNNEL_ENCAP_NONE,
	TUNNEL_ENCAP_FOU,
	TUNNEL_ENCAP_GUE,
};

#endif
static inline int ip6_encap_hlen(struct ip_tunnel_encap *e)
{
	const struct ip6_tnl_encap_ops *ops;
	int hlen = -EINVAL;

	if (e->type == TUNNEL_ENCAP_NONE)
		return 0;

	if (e->type >= MAX_IPTUN_ENCAP_OPS)
		return -EINVAL;

	rcu_read_lock();
	ops = rcu_dereference(rpl_ip6tun_encaps[e->type]);
	if (likely(ops && ops->encap_hlen))
		hlen = ops->encap_hlen(e);
	rcu_read_unlock();

	return hlen;
}

static inline int ip6_tnl_encap(struct sk_buff *skb, struct ip6_tnl *t,
				u8 *protocol, struct flowi6 *fl6)
{
	const struct ip6_tnl_encap_ops *ops;
	int ret = -EINVAL;

	if (t->encap.type == TUNNEL_ENCAP_NONE)
		return 0;

	if (t->encap.type >= MAX_IPTUN_ENCAP_OPS)
		return -EINVAL;

	rcu_read_lock();
	ops = rcu_dereference(rpl_ip6tun_encaps[t->encap.type]);
	if (likely(ops && ops->build_header))
		ret = ops->build_header(skb, &t->encap, protocol, fl6);
	rcu_read_unlock();

	return ret;
}

/* Tunnel encapsulation limit destination sub-option */

struct ipv6_tlv_tnl_enc_lim {
	__u8 type;		/* type-code for option         */
	__u8 length;		/* option length                */
	__u8 encap_limit;	/* tunnel encapsulation limit   */
} __packed;

int rpl_ip6_tnl_rcv_ctl(struct ip6_tnl *t, const struct in6_addr *laddr,
			const struct in6_addr *raddr);
#define ip6_tnl_rcv_ctl rpl_ip6_tnl_rcv_ctl
int rpl_ip6_tnl_rcv(struct ip6_tnl *tunnel, struct sk_buff *skb,
		    const struct tnl_ptk_info *tpi,
		    struct metadata_dst *tun_dst,
		    bool log_ecn_error);
#define ip6_tnl_rcv rpl_ip6_tnl_rcv
int rpl_ip6_tnl_xmit_ctl(struct ip6_tnl *t, const struct in6_addr *laddr,
			 const struct in6_addr *raddr);
#define ip6_tnl_xmit_ctl rpl_ip6_tnl_xmit_ctl
int rpl_ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev, __u8 dsfield,
		     struct flowi6 *fl6, int encap_limit, __u32 *pmtu,
		     __u8 proto);
#define ip6_tnl_xmit rpl_ip6_tnl_xmit
__u16 rpl_ip6_tnl_parse_tlv_enc_lim(struct sk_buff *skb, __u8 *raw);
#define ip6_tnl_parse_tlv_enc_lim rpl_ip6_tnl_parse_tlv_enc_lim
__u32 rpl_ip6_tnl_get_cap(struct ip6_tnl *t, const struct in6_addr *laddr,
			  const struct in6_addr *raddr);
#define ip6_tnl_get_cap rpl_ip6_tnl_get_cap
struct net *rpl_ip6_tnl_get_link_net(const struct net_device *dev);
#define ip6_tnl_get_link_net rpl_ip6_tnl_get_link_net
int rpl_ip6_tnl_get_iflink(const struct net_device *dev);
#define ip6_tnl_get_iflink rpl_ip6_tnl_get_iflink
int rpl_ip6_tnl_change_mtu(struct net_device *dev, int new_mtu);
#define ip6_tnl_change_mtu rpl_ip6_tnl_change_mtu

static inline void ip6tunnel_xmit(struct sock *sk, struct sk_buff *skb,
				  struct net_device *dev)
{
	int pkt_len, err;

	memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
	pkt_len = skb->len - skb_inner_network_offset(skb);
	err = ip6_local_out(dev_net(skb_dst(skb)->dev), sk, skb);
	if (unlikely(net_xmit_eval(err)))
		pkt_len = -1;
	iptunnel_xmit_stats(dev, pkt_len);
}
#endif

#endif /* HAVE_IP6_TNL_PARM_ERSPAN_VER */

#endif
