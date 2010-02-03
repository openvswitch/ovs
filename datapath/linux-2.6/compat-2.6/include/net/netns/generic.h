#ifndef __NET_NETNS_GENERIC_WRAPPER_H
#define __NET_NETNS_GENERIC_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include_next <net/netns/generic.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#define net_assign_generic rpl_net_assign_generic
int rpl_net_assign_generic(struct net *net, int id, void *data);

#define net_generic rpl_net_generic
void *rpl_net_generic(struct net *net, int id);

#endif /* linux kernel < 2.6.33 */

#endif
