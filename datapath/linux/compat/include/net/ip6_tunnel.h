#ifndef _NET_IP6_TUNNEL_WRAPER_H
#define _NET_IP6_TUNNEL_WRAPER_H

#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include_next <net/ip6_tunnel.h>

#include "gso.h"

#define ip6tunnel_xmit rpl_ip6tunnel_xmit
static inline void ip6tunnel_xmit(struct sock *sk, struct sk_buff *skb,
				  struct net_device *dev)
{
	int pkt_len, err;

	pkt_len = skb->len - skb_inner_network_offset(skb);
#ifdef HAVE_IP6_LOCAL_OUT_SK
	err = ip6_local_out_sk(sk, skb);
#else
	err = ip6_local_out(skb);
#endif
	if (net_xmit_eval(err))
		pkt_len = -1;

	iptunnel_xmit_stats(dev, pkt_len);
}

#endif
