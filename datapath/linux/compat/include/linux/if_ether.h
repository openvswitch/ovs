#ifndef __LINUX_IF_ETHER_WRAPPER_H
#define __LINUX_IF_ETHER_WRAPPER_H 1

#include_next <linux/if_ether.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

#define ETH_P_TEB      0x6558          /* Trans Ether Bridging         */

#endif /* linux kernel < 2.6.28 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

#define ETH_P_FCOE	0x8906          /* Fibre Channel over Ethernet  */

#endif /* linux kernel < 2.6.30 */

#ifndef ETH_P_802_3_MIN
#define ETH_P_802_3_MIN        0x0600
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */
#endif

#endif
