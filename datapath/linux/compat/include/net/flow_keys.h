#ifndef _NET_FLOW_KEYS_WRAPPER_H
#define _NET_FLOW_KEYS_WRAPPER_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#include_next <net/flow_keys.h>
#else
struct flow_keys {
	/* (src,dst) must be grouped, in the same way than in IP header */
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	u16 thoff;
	u8 ip_proto;
};
#endif

#endif
