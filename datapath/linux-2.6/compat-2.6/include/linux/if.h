#ifndef __LINUX_IF_WRAPPER_H
#define __LINUX_IF_WRAPPER_H 1

#include_next <linux/if.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#define IFF_XMIT_DST_RELEASE 0

#endif /* linux kernel < 2.6.31 */

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,36)
#define IFF_OVS_DATAPATH IFF_BRIDGE_PORT
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define IFF_OVS_DATAPATH 0		/* no-op flag */
#endif

#endif
