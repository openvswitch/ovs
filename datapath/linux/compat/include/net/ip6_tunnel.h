#ifndef _NET_IP6_TUNNEL_WRAPER_H
#define _NET_IP6_TUNNEL_WRAPER_H

#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include_next <net/ip6_tunnel.h>

#define ip6tunnel_xmit rpl_ip6tunnel_xmit
void rpl_ip6tunnel_xmit(struct sock *sk, struct sk_buff *skb,
		    struct net_device *dev);

#endif
