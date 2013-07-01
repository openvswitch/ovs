#ifndef __NET_VXLAN_WRAPPER_H
#define __NET_VXLAN_WRAPPER_H  1

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/udp.h>

/* per UDP socket information */
struct vxlan_sock {
	struct hlist_node hlist;
	struct rcu_head	  rcu;
	struct socket	  *sock;
	struct list_head  handler_list;
};

struct vxlan_handler;
typedef int (vxlan_rcv_t)(struct vxlan_handler *vh, struct sk_buff *skb, __be32 key);

struct vxlan_handler {
	vxlan_rcv_t	  *rcv;
	struct list_head   node;
	void		  *data;
	struct vxlan_sock *vs;
	atomic_t	   refcnt;
	struct rcu_head    rcu;
	struct work_struct del_work;
	int		   priority;
};

void vxlan_handler_put(struct vxlan_handler *vh);

struct vxlan_handler *vxlan_handler_add(struct net *net,
					__be16 portno, vxlan_rcv_t *rcv,
					void *data, int priority, bool create);

int vxlan_xmit_skb(struct net *net, struct vxlan_handler *vh,
		   struct rtable *rt, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port, __be32 vni);

__be16 vxlan_src_port(__u16 port_min, __u16 port_max, struct sk_buff *skb);

#endif
