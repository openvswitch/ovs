#ifndef __LINUX_IF_LINK_WRAPPER_H
#define __LINUX_IF_LINK_WRAPPER_H 1

#include <linux/version.h>

#ifdef HAVE_RTNL_LINK_STATS64
#include_next <linux/if_link.h>
#else  /* !HAVE_RTNL_LINK_STATS64 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#include_next <linux/if_link.h>
#else
/* Before 2.6.19 there was no <linux/if_link.h>.  Instead all of the types now
 * declared there were in <linux/if.h>.  Unfortunately <linux/if.h> from 2.6.18
 * conflicts badly enough with <net/if.h> to break the userspace build.  All
 * we really need from <linux/if_link.h> is struct rtnl_link_stats64, which in
 * turn only really needs __u64.  */
#include <linux/types.h>
#include <linux/netlink.h>
#endif	/* kernel < 2.6.19 */

/* The main device statistics structure */
struct rtnl_link_stats64 {
	__u64	rx_packets;		/* total packets received	*/
	__u64	tx_packets;		/* total packets transmitted	*/
	__u64	rx_bytes;		/* total bytes received 	*/
	__u64	tx_bytes;		/* total bytes transmitted	*/
	__u64	rx_errors;		/* bad packets received		*/
	__u64	tx_errors;		/* packet transmit problems	*/
	__u64	rx_dropped;		/* no space in linux buffers	*/
	__u64	tx_dropped;		/* no space available in linux	*/
	__u64	multicast;		/* multicast packets received	*/
	__u64	collisions;

	/* detailed rx_errors: */
	__u64	rx_length_errors;
	__u64	rx_over_errors;		/* receiver ring buff overflow	*/
	__u64	rx_crc_errors;		/* recved pkt with crc error	*/
	__u64	rx_frame_errors;	/* recv'd frame alignment error */
	__u64	rx_fifo_errors;		/* recv'r fifo overrun		*/
	__u64	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	__u64	tx_aborted_errors;
	__u64	tx_carrier_errors;
	__u64	tx_fifo_errors;
	__u64	tx_heartbeat_errors;
	__u64	tx_window_errors;

	/* for cslip etc */
	__u64	rx_compressed;
	__u64	tx_compressed;
};
#endif	/* !HAVE_RTNL_LINK_STATS64 */

#endif
