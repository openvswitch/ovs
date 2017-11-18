#ifndef __LINUX_GSO_WRAPPER_H
#define __LINUX_GSO_WRAPPER_H

#include <linux/version.h>
#include "datapath.h"

typedef void (*gso_fix_segment_t)(struct sk_buff *);

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
#ifndef USE_UPSTREAM_TUNNEL
	struct metadata_dst	*tun_dst;
#endif
#ifndef USE_UPSTREAM_TUNNEL_GSO
	gso_fix_segment_t fix_segment;
	bool ipv6;
#endif
#ifndef HAVE_INNER_PROTOCOL
	__be16		inner_protocol;
#endif
#ifndef USE_UPSTREAM_TUNNEL
	/* Keep original tunnel info during userspace action execution. */
	struct metadata_dst *fill_md_dst;
#endif
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)


#ifndef USE_UPSTREAM_TUNNEL_GSO
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/protocol.h>

static inline void skb_clear_ovs_gso_cb(struct sk_buff *skb)
{
	OVS_GSO_CB(skb)->fix_segment = NULL;
#ifndef USE_UPSTREAM_TUNNEL
	OVS_GSO_CB(skb)->tun_dst = NULL;
#endif
}
#else
static inline void skb_clear_ovs_gso_cb(struct sk_buff *skb)
{
#ifndef USE_UPSTREAM_TUNNEL
	OVS_GSO_CB(skb)->tun_dst = NULL;
#endif
}
#endif

#ifndef HAVE_INNER_PROTOCOL
static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb)
{
	OVS_GSO_CB(skb)->inner_protocol = htons(0);
}

static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype)
{
	OVS_GSO_CB(skb)->inner_protocol = ethertype;
}

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_protocol;
}

#else

static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb)
{
	/* Nothing to do. The inner_protocol is either zero or
	 * has been set to a value by another user.
	 * Either way it may be considered initialised.
	 */
}

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return skb->inner_protocol;
}

#ifdef ENCAP_TYPE_ETHER
#define ovs_skb_set_inner_protocol skb_set_inner_protocol
#else
static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype)
{
	skb->inner_protocol = ethertype;
}
#endif /* ENCAP_TYPE_ETHER */
#endif /* HAVE_INNER_PROTOCOL */

#define skb_inner_mac_offset rpl_skb_inner_mac_offset
static inline int skb_inner_mac_offset(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) - skb->data;
}

#ifndef USE_UPSTREAM_TUNNEL_GSO
#define ip_local_out rpl_ip_local_out
int rpl_ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);

#define ip6_local_out rpl_ip6_local_out
int rpl_ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
#else

static inline int rpl_ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
#ifdef HAVE_IP_LOCAL_OUT_TAKES_NET
	/* net and sk parameters are added at same time. */
	return ip_local_out(net, sk, skb);
#else
	return ip_local_out(skb);
#endif
}
#define ip_local_out rpl_ip_local_out

static inline int rpl_ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	memset(IP6CB(skb), 0, sizeof (*IP6CB(skb)));
#ifdef HAVE_IP_LOCAL_OUT_TAKES_NET
	return ip6_local_out(net, sk, skb);
#else
	return ip6_local_out(skb);
#endif
}
#define ip6_local_out rpl_ip6_local_out

#endif /* USE_UPSTREAM_TUNNEL_GSO */

#ifndef USE_UPSTREAM_TUNNEL
/* We need two separate functions to manage different dst in this case.
 * First is dst_entry and second is tunnel-dst.
 * So define ovs_* separate functions for tun_dst.
 */
static inline void ovs_skb_dst_set(struct sk_buff *skb, void *dst)
{
	OVS_GSO_CB(skb)->tun_dst = (void *)dst;
}

static inline struct ip_tunnel_info *ovs_skb_tunnel_info(struct sk_buff *skb)
{
	if (likely(OVS_GSO_CB(skb)->tun_dst))
		return &OVS_GSO_CB(skb)->tun_dst->u.tun_info;
	else
		return NULL;
}

static inline void ovs_skb_dst_drop(struct sk_buff *skb)
{
	OVS_GSO_CB(skb)->tun_dst = NULL;
}

static inline void ovs_dst_hold(void *dst)
{
}

static inline void ovs_dst_release(struct dst_entry *dst)
{
	struct metadata_dst *tun_dst = (struct metadata_dst *) dst;

	dst_cache_destroy(&tun_dst->u.tun_info.dst_cache);
	kfree(dst);
}

#else
#define ovs_skb_dst_set skb_dst_set
#define ovs_skb_dst_drop skb_dst_drop
#define ovs_dst_hold dst_hold
#define ovs_dst_release dst_release
#endif

#ifndef USE_UPSTREAM_TUNNEL
#define SKB_INIT_FILL_METADATA_DST(skb)	OVS_GSO_CB(skb)->fill_md_dst = NULL;

#define SKB_RESTORE_FILL_METADATA_DST(skb)	do {			\
	if (OVS_GSO_CB(skb)->fill_md_dst) {					\
		kfree(OVS_GSO_CB(skb)->tun_dst);			\
		OVS_GSO_CB(skb)->tun_dst = OVS_GSO_CB(skb)->fill_md_dst;	\
	}								\
} while (0)


#define SKB_SETUP_FILL_METADATA_DST(skb) ({			\
	struct metadata_dst *new_md_dst;			\
	struct metadata_dst *md_dst;				\
	int md_size;						\
	int ret = 1;						\
								\
	SKB_RESTORE_FILL_METADATA_DST(skb); 			\
	new_md_dst = kmalloc(sizeof(struct metadata_dst) + 256, GFP_ATOMIC); \
	if (new_md_dst) {						\
		md_dst = OVS_GSO_CB(skb)->tun_dst;			\
		md_size = new_md_dst->u.tun_info.options_len;		\
		memcpy(&new_md_dst->u.tun_info, &md_dst->u.tun_info,	\
			sizeof(struct ip_tunnel_info) + md_size);	\
									\
		OVS_GSO_CB(skb)->fill_md_dst = md_dst;				\
		OVS_GSO_CB(skb)->tun_dst = new_md_dst;			\
		ret = 1;						\
	} else {							\
		ret = 0;						\
	}								\
	ret;								\
})

#else
#define SKB_INIT_FILL_METADATA_DST(skb)		do {} while(0)
#define SKB_SETUP_FILL_METADATA_DST(skb)	(true)
#define SKB_RESTORE_FILL_METADATA_DST(skb)	do {} while(0)
#endif

#endif
