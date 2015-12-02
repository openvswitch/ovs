#ifndef __NET_IP_WRAPPER_H
#define __NET_IP_WRAPPER_H 1

#include_next <net/ip.h>

#include <linux/version.h>

#ifndef HAVE_IP_IS_FRAGMENT
static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}
#endif

#ifndef HAVE_INET_GET_LOCAL_PORT_RANGE_USING_NET
static inline void rpl_inet_get_local_port_range(struct net *net, int *low,
					     int *high)
{
	inet_get_local_port_range(low, high);
}
#define inet_get_local_port_range rpl_inet_get_local_port_range

#endif

#endif
