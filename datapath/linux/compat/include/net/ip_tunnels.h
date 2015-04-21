#ifndef __NET_IP_TUNNELS_WRAPPER_H
#define __NET_IP_TUNNELS_WRAPPER_H 1

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include_next <net/ip_tunnels.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)

#include <linux/if_tunnel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/dsfield.h>
#include <net/flow.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/rtnetlink.h>

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

#endif /* 3.18 */

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
#define TUNNEL_GENEVE_OPT      __cpu_to_be16(0x0800)
#endif

#ifndef TUNNEL_VXLAN_OPT
#define TUNNEL_VXLAN_OPT       __cpu_to_be16(0x1000)
#endif

/* Older kernels defined TUNNEL_OPTIONS_PRESENT to GENEVE only */
#undef TUNNEL_OPTIONS_PRESENT
#define TUNNEL_OPTIONS_PRESENT (TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT)

#define skb_is_encapsulated ovs_skb_is_encapsulated
bool ovs_skb_is_encapsulated(struct sk_buff *skb);

#endif /* __NET_IP_TUNNELS_H */
