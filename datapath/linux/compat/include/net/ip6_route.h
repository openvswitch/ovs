#ifndef __NET_IP6_ROUTE_WRAPPER
#define __NET_IP6_ROUTE_WRAPPER

#include <net/route.h>
#include <net/ip.h>                /* For OVS_VPORT_OUTPUT_PARAMS */
#include <net/ipv6.h>

#include_next<net/ip6_route.h>

#ifndef HAVE_NF_IPV6_OPS_FRAGMENT
int rpl_ip6_fragment(struct sock *sk, struct sk_buff *skb,
		     int (*output)(OVS_VPORT_OUTPUT_PARAMS));
#define ip6_fragment rpl_ip6_fragment
#endif /* HAVE_NF_IPV6_OPS_FRAGMENT */

#endif /* _NET_IP6_ROUTE_WRAPPER */
