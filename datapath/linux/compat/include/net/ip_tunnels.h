#ifndef __NET_IP_TUNNELS_WRAPPER_H
#define __NET_IP_TUNNELS_WRAPPER_H 1

#include <linux/version.h>
#if defined(HAVE_GRE_HANDLE_OFFLOADS) && \
     LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && \
     defined(HAVE_VXLAN_XMIT_SKB)
/* RHEL6 and RHEL7 both has backported tunnel API but RHEL6 has
 * older version, so avoid using RHEL6 backports.
 */
#define USE_KERNEL_TUNNEL_API
#endif

#ifdef USE_KERNEL_TUNNEL_API
#include_next <net/ip_tunnels.h>
static inline int rpl_iptunnel_xmit(struct rtable *rt,
                                    struct sk_buff *skb, __be32 src,
                                    __be32 dst, __u8 proto, __u8 tos,
                                    __u8 ttl, __be16 df, bool xnet)
{
#ifdef HAVE_IPTUNNEL_XMIT_NET
	return iptunnel_xmit(NULL, rt, skb, src, dst, proto, tos, ttl, df);
#else
	return iptunnel_xmit(rt, skb, src, dst, proto, tos, ttl, df, xnet);
#endif
}
#define iptunnel_xmit rpl_iptunnel_xmit

#else

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

int iptunnel_xmit(struct rtable *rt,
		  struct sk_buff *skb,
		  __be32 src, __be32 dst, __u8 proto,
		  __u8 tos, __u8 ttl, __be16 df, bool xnet);

int iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto);

#endif
#endif /* __NET_IP_TUNNELS_H */
