#ifndef __LINUX_IF_WRAPPER_H
#define __LINUX_IF_WRAPPER_H 1

#include_next <linux/if.h>

#ifndef IFF_TX_SKB_SHARING
#define IFF_TX_SKB_SHARING 0
#endif

#ifndef IFF_OVS_DATAPATH
#define IFF_OVS_DATAPATH 0
#endif

#ifndef IFF_LIVE_ADDR_CHANGE
#define IFF_LIVE_ADDR_CHANGE 0
#endif

#endif
