#ifndef __NET_VXLAN_WRAPPER_H
#define __NET_VXLAN_WRAPPER_H  1

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <net/gre.h>

#include <linux/version.h>
#ifdef USE_KERNEL_TUNNEL_API
#include_next <net/vxlan.h>

static inline int rpl_vxlan_xmit_skb(struct vxlan_sock *vs,
                   struct rtable *rt, struct sk_buff *skb,
                   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
                   __be16 src_port, __be16 dst_port, __be32 vni)
{
	if (skb->encapsulation && skb_is_gso(skb)) {
		kfree_skb(skb);
		return -ENOSYS;
	}
#ifndef HAVE_IPTUNNEL_XMIT_NET
	return vxlan_xmit_skb(vs, rt, skb, src, dst, tos, ttl, df,
			      src_port, dst_port, vni);
#else
	return vxlan_xmit_skb(NULL, vs, rt, skb, src, dst, tos, ttl, df,
			      src_port, dst_port, vni);
#endif
}
#define vxlan_xmit_skb rpl_vxlan_xmit_skb
#else

struct vxlan_sock;
typedef void (vxlan_rcv_t)(struct vxlan_sock *vs, struct sk_buff *skb, __be32 key);

/* per UDP socket information */
struct vxlan_sock {
	struct hlist_node hlist;
	vxlan_rcv_t	 *rcv;
	void		 *data;
	struct work_struct del_work;
	struct socket	 *sock;
	struct rcu_head	  rcu;
};

struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
				  vxlan_rcv_t *rcv, void *data,
				  bool no_share, bool ipv6);

void vxlan_sock_release(struct vxlan_sock *vs);

int vxlan_xmit_skb(struct vxlan_sock *vs,
		   struct rtable *rt, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port, __be32 vni);

__be16 vxlan_src_port(__u16 port_min, __u16 port_max, struct sk_buff *skb);

#endif /* 3.12 */
#endif
