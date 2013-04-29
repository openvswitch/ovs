#ifndef _IF_TUNNEL_WRAPPER_H_
#define _IF_TUNNEL_WRAPPER_H_

#include <linux/version.h>
#include_next <linux/if_tunnel.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)

#include <linux/u64_stats_sync.h>

struct pcpu_tstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};
#endif

#endif /* _IF_TUNNEL_WRAPPER_H_ */
