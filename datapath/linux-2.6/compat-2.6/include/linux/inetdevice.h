#ifndef __LINUX_INETDEVICE_WRAPPER_H
#define __LINUX_INETDEVICE_WRAPPER_H 1

#include_next <linux/inetdevice.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define inetdev_by_index(net, ifindex) \
		inetdev_by_index((ifindex))

#endif /* linux kernel < 2.6.25 */

#endif
