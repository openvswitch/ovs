#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>

/*----------------------------------------------------------------------------
 * In 2.6.24, a namespace argument became required for dev_get_by_name. 
 */ 
#define net_init NULL

#ifdef dev_get_by_name
#undef dev_get_by_name
#define dev_get_by_name(net, name) \
	compat_dev_get_by_name((name))
static inline struct net_device *compat_dev_get_by_name(const char *name)
{
	return (_set_ver(dev_get_by_name))(name);
}
#else
#define dev_get_by_name(net, name) \
	dev_get_by_name((name))
#endif /* dev_get_by_name */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,27)
static inline void *netdev_priv(struct net_device *dev)
{ 
	return dev->priv;
}
#endif

/* Synchronize with packet receive processing. */
static inline void synchronize_net(void) 
{
	synchronize_rcu();
}

#endif
