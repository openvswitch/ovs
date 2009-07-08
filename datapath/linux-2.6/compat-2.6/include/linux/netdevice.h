#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>

struct net;

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, class_dev)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline
struct net *dev_net(const struct net_device *dev)
{
	return NULL;
}
#endif /* linux kernel < 2.6.26 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define proc_net init_net.proc_net
#endif

#ifndef for_each_netdev
/* Linux before 2.6.22 didn't have for_each_netdev at all. */
#define for_each_netdev(net, d) for (d = dev_base; d; d = d->next)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* Linux 2.6.24 added a network namespace pointer to the macro. */
#undef for_each_netdev
#define for_each_netdev(net,d) list_for_each_entry(d, &dev_base_head, dev_list)
#endif



#endif
