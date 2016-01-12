#ifndef __NET_DST_METADATA_WRAPPER_H
#define __NET_DST_METADATA_WRAPPER_H 1

#ifdef HAVE_METADATA_DST
#include_next <net/dst_metadata.h>
#else
#include <linux/skbuff.h>
#include <net/ip_tunnels.h>
#include <net/dst.h>

struct metadata_dst {
	unsigned long dst;
	union {
		struct ip_tunnel_info	tun_info;
	} u;
};

static inline struct metadata_dst *metadata_dst_alloc(u8 optslen, gfp_t flags)
{
	struct metadata_dst *md_dst;

	md_dst = kmalloc(sizeof(*md_dst) + optslen, flags);
	if (!md_dst)
		return NULL;

	return md_dst;
}
#define skb_tunnel_info ovs_skb_tunnel_info
#endif
static inline void ovs_ip_tun_rx_dst(struct ip_tunnel_info *tun_info,
				 struct sk_buff *skb, __be16 flags,
				 __be64 tunnel_id, int md_size)
{
	const struct iphdr *iph = ip_hdr(skb);

	ip_tunnel_key_init(&tun_info->key,
			   iph->saddr, iph->daddr, iph->tos, iph->ttl,
			   0, 0, tunnel_id, flags);
	tun_info->mode = 0;
}

void ovs_ip_tunnel_rcv(struct net_device *dev, struct sk_buff *skb,
		      struct metadata_dst *tun_dst);
#endif /* __NET_DST_METADATA_WRAPPER_H */
