/* Interface exported by OpenFlow module. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "openflow.h"
#include "flow.h"


#define NL_FLOWS_PER_MESSAGE 100

#ifdef NDEBUG
#define dprintk(x...)
#else
#define dprintk(x...) printk(x)
#endif

/* Capabilities supported by this implementation. */
#define OFP_SUPPORTED_CAPABILITIES (OFPC_MULTI_PHY_TX)

/* Actions supported by this implementation. */
#define OFP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT) \
		| (1 << OFPAT_SET_DL_VLAN) \
		| (1 << OFPAT_SET_DL_SRC) \
		| (1 << OFPAT_SET_DL_DST) \
		| (1 << OFPAT_SET_NW_SRC) \
		| (1 << OFPAT_SET_NW_DST) \
		| (1 << OFPAT_SET_TP_SRC) \
		| (1 << OFPAT_SET_TP_DST) )

struct sk_buff;

struct datapath {
	int dp_idx;

	/* Unique identifier for this datapath, incorporates the dp_idx and
	 * a hardware address */
	uint64_t  id;

	struct timer_list timer;	/* Expiration timer. */
	struct sw_chain *chain;	 /* Forwarding rules. */

	/* Data related to the "of" device of this datapath */
	struct net_device dev;
	struct net_device_stats stats;

	/* Flags from the control hello message */
	uint16_t hello_flags;

	/* Maximum number of bytes that should be sent for flow misses */
	uint16_t miss_send_len;

	/* Switch ports. */
	struct net_bridge_port *ports[OFPP_MAX];
	struct list_head port_list; /* List of ports, for flooding. */
};

int dp_output_port(struct datapath *, struct sk_buff *, int out_port);
int dp_output_control(struct datapath *, struct sk_buff *,
			   uint32_t buffer_id, size_t max_len, int reason);
int dp_set_origin(struct datapath *, uint16_t, struct sk_buff *);
int dp_send_hello(struct datapath *);
int dp_send_flow_expired(struct datapath *, struct sw_flow *);
int dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp);

/* Should hold at least RCU read lock when calling */
struct datapath *dp_get(int dp_idx);

#endif /* datapath.h */
