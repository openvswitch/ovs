#ifndef __LINUX_IF_ETHER_WRAPPER_H
#define __LINUX_IF_ETHER_WRAPPER_H 1

#include_next <linux/if_ether.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

#define ETH_P_TEB      0x6558          /* Trans Ether Bridging         */

#endif /* linux kernel < 2.6.28 */

#endif
