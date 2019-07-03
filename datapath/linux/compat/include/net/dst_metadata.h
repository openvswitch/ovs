#ifndef __NET_DST_METADATA_WRAPPER_H
#define __NET_DST_METADATA_WRAPPER_H 1

#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/dst_metadata.h>
#else
#include <linux/skbuff.h>

#include <net/dsfield.h>
#include <net/dst.h>
#include <net/ipv6.h>
#include <net/ip_tunnels.h>

enum metadata_type {
	METADATA_IP_TUNNEL,
	METADATA_HW_PORT_MUX,
};

struct hw_port_info {
	struct net_device *lower_dev;
	u32 port_id;
};

struct metadata_dst {
	struct dst_entry 	dst;
	enum metadata_type	type;
	union {
		struct ip_tunnel_info	tun_info;
		struct hw_port_info	port_info;
	} u;
};

#ifndef DST_METADATA
#define DST_METADATA 0x0080
#endif

extern struct dst_ops md_dst_ops;

static void rpl__metadata_dst_init(struct metadata_dst *md_dst,
				enum metadata_type type, u8 optslen)

{
	struct dst_entry *dst;

	dst = &md_dst->dst;
	dst_init(dst, &md_dst_ops, NULL, 1, DST_OBSOLETE_NONE,
		 DST_METADATA | DST_NOCOUNT);

#if 0
	/* unused in OVS */
	dst->input = dst_md_discard;
	dst->output = dst_md_discard_out;
#endif
	memset(dst + 1, 0, sizeof(*md_dst) + optslen - sizeof(*dst));
	md_dst->type = type;
}

static struct
metadata_dst *__rpl_metadata_dst_alloc(u8 optslen,
				       enum metadata_type type,
				       gfp_t flags)
{
	struct metadata_dst *md_dst;

	md_dst = kmalloc(sizeof(*md_dst) + optslen, flags);
	if (!md_dst)
		return NULL;

	rpl__metadata_dst_init(md_dst, type, optslen);

	return md_dst;
}
static inline struct metadata_dst *rpl_tun_rx_dst(int md_size)
{
	struct metadata_dst *tun_dst;

	tun_dst = __rpl_metadata_dst_alloc(md_size, METADATA_IP_TUNNEL,
					 GFP_ATOMIC);
	if (!tun_dst)
		return NULL;

	tun_dst->u.tun_info.options_len = 0;
	tun_dst->u.tun_info.mode = 0;
	return tun_dst;
}
static inline struct metadata_dst *rpl__ip_tun_set_dst(__be32 saddr,
						    __be32 daddr,
						    __u8 tos, __u8 ttl,
						    __be16 tp_dst,
						    __be16 flags,
						    __be64 tunnel_id,
						    int md_size)
{
	struct metadata_dst *tun_dst;

	tun_dst = rpl_tun_rx_dst(md_size);
	if (!tun_dst)
		return NULL;

	ip_tunnel_key_init(&tun_dst->u.tun_info.key,
			   saddr, daddr, tos, ttl,
			   0, 0, tp_dst, tunnel_id, flags);
	return tun_dst;
}

static inline struct metadata_dst *rpl_ip_tun_rx_dst(struct sk_buff *skb,
						 __be16 flags,
						 __be64 tunnel_id,
						 int md_size)
{
	const struct iphdr *iph = ip_hdr(skb);

	return rpl__ip_tun_set_dst(iph->saddr, iph->daddr, iph->tos, iph->ttl,
				0, flags, tunnel_id, md_size);
}

static inline
struct metadata_dst *rpl__ipv6_tun_set_dst(const struct in6_addr *saddr,
					   const struct in6_addr *daddr,
					    __u8 tos, __u8 ttl,
					    __be16 tp_dst,
					    __be32 label,
					    __be16 flags,
					    __be64 tunnel_id,
					    int md_size)
{
	struct metadata_dst *tun_dst;
	struct ip_tunnel_info *info;

	tun_dst = rpl_tun_rx_dst(md_size);
	if (!tun_dst)
		return NULL;

	info = &tun_dst->u.tun_info;
	info->mode = IP_TUNNEL_INFO_IPV6;
	info->key.tun_flags = flags;
	info->key.tun_id = tunnel_id;
	info->key.tp_src = 0;
	info->key.tp_dst = tp_dst;

	info->key.u.ipv6.src = *saddr;
	info->key.u.ipv6.dst = *daddr;

	info->key.tos = tos;
	info->key.ttl = ttl;
	info->key.label = label;

	return tun_dst;
}

static inline struct metadata_dst *rpl_ipv6_tun_rx_dst(struct sk_buff *skb,
						 __be16 flags,
						 __be64 tunnel_id,
						 int md_size)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	return rpl__ipv6_tun_set_dst(&ip6h->saddr, &ip6h->daddr,
				     ipv6_get_dsfield(ip6h), ip6h->hop_limit,
				     0, ip6_flowlabel(ip6h), flags, tunnel_id,
				     md_size);
}

static void __metadata_dst_init(struct metadata_dst *md_dst, u8 optslen)
{
	struct dst_entry *dst;

	dst = &md_dst->dst;

#if 0
	dst_init(dst, &md_dst_ops, NULL, 1, DST_OBSOLETE_NONE,
			DST_METADATA | DST_NOCACHE | DST_NOCOUNT);

	dst->input = dst_md_discard;
	dst->output = dst_md_discard_out;
#endif

	memset(dst + 1, 0, sizeof(*md_dst) + optslen - sizeof(*dst));
}

static inline struct metadata_dst *metadata_dst_alloc(u8 optslen, gfp_t flags)
{
	struct metadata_dst *md_dst;

	md_dst = kmalloc(sizeof(*md_dst) + optslen, flags);
	if (!md_dst)
		return NULL;

	__metadata_dst_init(md_dst, optslen);
	return md_dst;
}

#define skb_tunnel_info ovs_skb_tunnel_info

static inline void ovs_tun_rx_dst(struct metadata_dst *md_dst, int optslen)
{
	/* No need to allocate for OVS backport case. */
#if 0
	struct metadata_dst *tun_dst;
	struct ip_tunnel_info *info;

	tun_dst = metadata_dst_alloc(md_size, GFP_ATOMIC);
	if (!tun_dst)
		return NULL;
#endif
	__metadata_dst_init(md_dst, optslen);
}

static inline void ovs_ip_tun_rx_dst(struct metadata_dst *md_dst,
				     struct sk_buff *skb, __be16 flags,
				     __be64 tunnel_id, int md_size)
{
	const struct iphdr *iph = ip_hdr(skb);

	ovs_tun_rx_dst(md_dst, md_size);
	ip_tunnel_key_init(&md_dst->u.tun_info.key,
			   iph->saddr, iph->daddr, iph->tos, iph->ttl, 0,
			   0, 0, tunnel_id, flags);
}

static inline void ovs_ipv6_tun_rx_dst(struct metadata_dst *md_dst,
				       struct sk_buff *skb,
				       __be16 flags,
				       __be64 tunnel_id,
				       int md_size)
{
	struct ip_tunnel_info *info = &md_dst->u.tun_info;
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	ovs_tun_rx_dst(md_dst, md_size);
	info->mode = IP_TUNNEL_INFO_IPV6;
	info->key.tun_flags = flags;
	info->key.tun_id = tunnel_id;
	info->key.tp_src = 0;
	info->key.tp_dst = 0;

	info->key.u.ipv6.src = ip6h->saddr;
	info->key.u.ipv6.dst = ip6h->daddr;

	info->key.tos = ipv6_get_dsfield(ip6h);
	info->key.ttl = ip6h->hop_limit;
	info->key.label = ip6_flowlabel(ip6h);
}

#endif /* USE_UPSTREAM_TUNNEL */

void ovs_ip_tunnel_rcv(struct net_device *dev, struct sk_buff *skb,
		      struct metadata_dst *tun_dst);

static inline struct metadata_dst *
rpl_metadata_dst_alloc(u8 optslen, enum metadata_type type, gfp_t flags)
{
#if defined(HAVE_METADATA_DST_ALLOC_WITH_METADATA_TYPE) && defined(USE_UPSTREAM_TUNNEL)
	return metadata_dst_alloc(optslen, type, flags);
#else
	return metadata_dst_alloc(optslen, flags);
#endif
}
#define metadata_dst_alloc rpl_metadata_dst_alloc

static inline bool rpl_skb_valid_dst(const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	return dst && !(dst->flags & DST_METADATA);
}
#define skb_valid_dst rpl_skb_valid_dst

#endif /* __NET_DST_METADATA_WRAPPER_H */
