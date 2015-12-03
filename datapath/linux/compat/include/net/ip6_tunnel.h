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
	/* TODO: Fix GSO for ipv6 */
#ifdef HAVE_IP6_LOCAL_OUT_SK
	err = ip6_local_out_sk(sk, skb);
#else
	err = ip6_local_out(skb);
#endif
	if (net_xmit_eval(err) != 0)
		pkt_len = net_xmit_eval(err);
	else
		pkt_len = err;

	iptunnel_xmit_stats(pkt_len, &dev->stats, (struct pcpu_sw_netstats __percpu *)dev->tstats);
}

#endif
