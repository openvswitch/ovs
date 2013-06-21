#ifndef __NET_IP_TUNNELS_WRAPPER_H
#define __NET_IP_TUNNELS_WRAPPER_H 1

#include <linux/if_tunnel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/dsfield.h>
#include <net/flow.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/rtnetlink.h>

#define TUNNEL_CSUM	__cpu_to_be16(0x01)
#define TUNNEL_ROUTING	__cpu_to_be16(0x02)
#define TUNNEL_KEY	__cpu_to_be16(0x04)
#define TUNNEL_SEQ	__cpu_to_be16(0x08)
#define TUNNEL_STRICT	__cpu_to_be16(0x10)
#define TUNNEL_REC	__cpu_to_be16(0x20)
#define TUNNEL_VERSION	__cpu_to_be16(0x40)
#define TUNNEL_NO_KEY	__cpu_to_be16(0x80)
#define TUNNEL_DONT_FRAGMENT	__cpu_to_be16(0x0100)

struct tnl_ptk_info {
	__be16 flags;
	__be16 proto;
	__be32 key;
	__be32 seq;
};

#define PACKET_RCVD	0
#define PACKET_REJECT	1

static inline void tunnel_ip_select_ident(struct sk_buff *skb,
					  const struct iphdr  *old_iph,
					  struct dst_entry *dst)
{
	struct iphdr *iph = ip_hdr(skb);

	/* Use inner packet iph-id if possible. */
	if (skb->protocol == htons(ETH_P_IP) && old_iph->id)
		iph->id = old_iph->id;
	else
		__ip_select_ident(iph, dst,
				(skb_shinfo(skb)->gso_segs ?: 1) - 1);
}

int iptunnel_xmit(struct net *net, struct rtable *rt,
		  struct sk_buff *skb,
		  __be32 src, __be32 dst, __u8 proto,
		  __u8 tos, __u8 ttl, __be16 df);

int iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto);
#endif /* __NET_IP_TUNNELS_H */
