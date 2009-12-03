#ifndef __NET_NETNS_GENERIC_WRAPPER_H
#define __NET_NETNS_GENERIC_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

struct net;

extern void *net_generic(struct net *net, int id);
extern int net_assign_generic(struct net *net, int id, void *data);

#else
#include_next <net/netns/generic.h>
#endif /* linux kernel < 2.6.26 */

#endif
