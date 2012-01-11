#ifndef __LINUX_IF_WRAPPER_H
#define __LINUX_IF_WRAPPER_H 1

#include_next <linux/if.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#define IFF_XMIT_DST_RELEASE 0

#endif /* linux kernel < 2.6.31 */

#ifndef IFF_TX_SKB_SHARING
#define IFF_TX_SKB_SHARING 0
#endif

#ifndef IFF_OVS_DATAPATH
#define IFF_OVS_DATAPATH 0
#endif

#endif
