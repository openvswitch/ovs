#ifndef __NET_NET_NETNS_GENERIC_WRAPPER_H
#define __NET_NET_NETNS_GENERIC_WRAPPER_H 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
/* <net/netns/generic.h> exists, go ahead and include it. */
#include_next <net/netns/generic.h>
#else
#define net_generic rpl_net_generic
void *net_generic(const struct net *net, int id);
#endif

#endif /* net/netns/generic.h wrapper */
