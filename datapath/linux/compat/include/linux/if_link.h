#ifndef _LINUX_IF_LINK_WRAPPER_H
#define _LINUX_IF_LINK_WRAPPER_H

#include_next<linux/if_link.h>

/* GENEVE section */
enum {
#define IFLA_GENEVE_UNSPEC rpl_IFLA_GENEVE_UNSPEC
	IFLA_GENEVE_UNSPEC,

#define IFLA_GENEVE_ID rpl_IFLA_GENEVE_ID
	IFLA_GENEVE_ID,

#define IFLA_GENEVE_REMOTE rpl_IFLA_GENEVE_REMOTE
	IFLA_GENEVE_REMOTE,

#define IFLA_GENEVE_TTL rpl_IFLA_GENEVE_TTL
	IFLA_GENEVE_TTL,

#define IFLA_GENEVE_TOS rpl_IFLA_GENEVE_TOS
	IFLA_GENEVE_TOS,

#define IFLA_GENEVE_PORT rpl_IFLA_GENEVE_PORT
	IFLA_GENEVE_PORT,	/* destination port */

#define IFLA_GENEVE_COLLECT_METADATA rpl_IFLA_GENEVE_COLLECT_METADATA
	IFLA_GENEVE_COLLECT_METADATA,

#define IFLA_GENEVE_REMOTE6 rpl_IFLA_GENEVE_REMOTE6
        IFLA_GENEVE_REMOTE6,

#define IFLA_GENEVE_UDP_CSUM rpl_IFLA_GENEVE_UDP_CSUM
        IFLA_GENEVE_UDP_CSUM,

#define IFLA_GENEVE_UDP_ZERO_CSUM6_TX rpl_IFLA_GENEVE_UDP_ZERO_CSUM6_TX
        IFLA_GENEVE_UDP_ZERO_CSUM6_TX,

#define IFLA_GENEVE_UDP_ZERO_CSUM6_RX rpl_IFLA_GENEVE_UDP_ZERO_CSUM6_RX
        IFLA_GENEVE_UDP_ZERO_CSUM6_RX,

#define IFLA_GENEVE_LABEL rpl_IFLA_GENEVE_LABEL
        IFLA_GENEVE_LABEL,

#define __IFLA_GENEVE_MAX rpl__IFLA_GENEVE_MAX
	__IFLA_GENEVE_MAX
};
#undef IFLA_GENEVE_MAX
#define IFLA_GENEVE_MAX	(__IFLA_GENEVE_MAX - 1)

/* STT section */
enum {
	IFLA_STT_PORT,	/* destination port */
	__IFLA_STT_MAX
};
#define IFLA_STT_MAX	(__IFLA_STT_MAX - 1)

/* LISP section */
enum {
	IFLA_LISP_PORT,	/* destination port */
	__IFLA_LISP_MAX
};
#define IFLA_LISP_MAX	(__IFLA_LISP_MAX - 1)

/* VXLAN section */
enum {
#define IFLA_VXLAN_UNSPEC rpl_IFLA_VXLAN_UNSPEC
	IFLA_VXLAN_UNSPEC,
#define IFLA_VXLAN_ID rpl_IFLA_VXLAN_ID
	IFLA_VXLAN_ID,
#define IFLA_VXLAN_GROUP rpl_IFLA_VXLAN_GROUP
	IFLA_VXLAN_GROUP,	/* group or remote address */
#define IFLA_VXLAN_LINK rpl_IFLA_VXLAN_LINK
	IFLA_VXLAN_LINK,
#define IFLA_VXLAN_LOCAL rpl_IFLA_VXLAN_LOCAL
	IFLA_VXLAN_LOCAL,
#define IFLA_VXLAN_TTL rpl_IFLA_VXLAN_TTL
	IFLA_VXLAN_TTL,
#define IFLA_VXLAN_TOS rpl_IFLA_VXLAN_TOS
	IFLA_VXLAN_TOS,
#define IFLA_VXLAN_LEARNING rpl_IFLA_VXLAN_LEARNING
	IFLA_VXLAN_LEARNING,
#define IFLA_VXLAN_AGEING rpl_IFLA_VXLAN_AGEING
	IFLA_VXLAN_AGEING,
#define IFLA_VXLAN_LIMIT rpl_IFLA_VXLAN_LIMIT
	IFLA_VXLAN_LIMIT,
#define IFLA_VXLAN_PORT_RANGE rpl_IFLA_VXLAN_PORT_RANGE
	IFLA_VXLAN_PORT_RANGE,	/* source port */
#define IFLA_VXLAN_PROXY rpl_IFLA_VXLAN_PROXY
	IFLA_VXLAN_PROXY,
#define IFLA_VXLAN_RSC rpl_IFLA_VXLAN_RSC
	IFLA_VXLAN_RSC,
#define IFLA_VXLAN_L2MISS rpl_IFLA_VXLAN_L2MISS
	IFLA_VXLAN_L2MISS,
#define IFLA_VXLAN_L3MISS rpl_IFLA_VXLAN_L3MISS
	IFLA_VXLAN_L3MISS,
#define IFLA_VXLAN_PORT rpl_IFLA_VXLAN_PORT
	IFLA_VXLAN_PORT,	/* destination port */
#define IFLA_VXLAN_GROUP6 rpl_IFLA_VXLAN_GROUP6
	IFLA_VXLAN_GROUP6,
#define IFLA_VXLAN_LOCAL6 rpl_IFLA_VXLAN_LOCAL6
	IFLA_VXLAN_LOCAL6,
#define IFLA_VXLAN_UDP_CSUM rpl_IFLA_VXLAN_UDP_CSUM
	IFLA_VXLAN_UDP_CSUM,
#define IFLA_VXLAN_UDP_ZERO_CSUM6_TX rpl_IFLA_VXLAN_UDP_ZERO_CSUM6_TX
	IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
#define IFLA_VXLAN_UDP_ZERO_CSUM6_RX rpl_IFLA_VXLAN_UDP_ZERO_CSUM6_RX
	IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
#define IFLA_VXLAN_REMCSUM_TX rpl_IFLA_VXLAN_REMCSUM_TX
	IFLA_VXLAN_REMCSUM_TX,
#define IFLA_VXLAN_REMCSUM_RX rpl_IFLA_VXLAN_REMCSUM_RX
	IFLA_VXLAN_REMCSUM_RX,
#define IFLA_VXLAN_GBP rpl_IFLA_VXLAN_GBP
	IFLA_VXLAN_GBP,
#define IFLA_VXLAN_REMCSUM_NOPARTIAL rpl_IFLA_VXLAN_REMCSUM_NOPARTIAL
	IFLA_VXLAN_REMCSUM_NOPARTIAL,
#define IFLA_VXLAN_COLLECT_METADATA rpl_IFLA_VXLAN_COLLECT_METADATA
	IFLA_VXLAN_COLLECT_METADATA,
#define IFLA_VXLAN_LABEL rpl_IFLA_VXLAN_LABEL
	IFLA_VXLAN_LABEL,
#define IFLA_VXLAN_GPE rpl_IFLA_VXLAN_GPE
	IFLA_VXLAN_GPE,

#define __IFLA_VXLAN_MAX rpl___IFLA_VXLAN_MAX
	__IFLA_VXLAN_MAX
};

#undef IFLA_VXLAN_MAX
#define IFLA_VXLAN_MAX	(rpl___IFLA_VXLAN_MAX - 1)

#define ifla_vxlan_port_range rpl_ifla_vxlan_port_range
struct ifla_vxlan_port_range {
	__be16	low;
	__be16	high;
};

#ifndef HAVE_RTNL_LINK_STATS64
/* The main device statistics structure */
struct rtnl_link_stats64 {
	__u64	rx_packets;		/* total packets received	*/
	__u64	tx_packets;		/* total packets transmitted	*/
	__u64	rx_bytes;		/* total bytes received		*/
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
	__u64	rx_frame_errors;	/* recv'd frame alignment error	*/
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
#endif

#endif
