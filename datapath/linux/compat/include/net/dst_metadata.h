#ifndef __NET_DST_METADATA_WRAPPER_H
#define __NET_DST_METADATA_WRAPPER_H 1

enum metadata_type {
	METADATA_IP_TUNNEL,
	METADATA_HW_PORT_MUX,
};

#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/dst_metadata.h>
#else
#include <linux/skbuff.h>

#include <net/dsfield.h>
#include <net/dst.h>
#include <net/ipv6.h>
#include <net/ip_tunnels.h>

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

#ifndef HAVE_METADATA_DST_ALLOC_WITH_METADATA_TYPE
static inline struct metadata_dst *
rpl_metadata_dst_alloc(u8 optslen, enum metadata_type type, gfp_t flags)
{
	return metadata_dst_alloc(optslen, flags);
}
#define metadata_dst_alloc rpl_metadata_dst_alloc
#endif

#endif /* __NET_DST_METADATA_WRAPPER_H */
