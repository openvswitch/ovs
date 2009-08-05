#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>

struct net;

/* Before 2.6.21, struct net_device has a "struct class_device" member named
 * class_dev.  Beginning with 2.6.21, struct net_device instead has a "struct
 * device" member named dev.  Otherwise the usage of these members is pretty
 * much the same. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define NETDEV_DEV_MEMBER class_dev
#else
#define NETDEV_DEV_MEMBER dev
#endif

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, NETDEV_DEV_MEMBER)
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
