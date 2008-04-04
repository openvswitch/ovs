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
	struct task_struct *dp_task; /* Kernel thread for maintenance. */

	/* Data related to the "of" device of this datapath */
	struct net_device dev;
	struct net_device_stats stats;

	struct ofp_switch_config config;

	/* Switch ports. */
	struct net_bridge_port *ports[OFPP_MAX];
	struct list_head port_list; /* List of ports, for flooding. */
};

/* Information necessary to reply to the sender of an OpenFlow message. */
struct sender {
	uint32_t xid;		/* OpenFlow transaction ID of request. */
	uint32_t pid;		/* Netlink process ID of sending socket. */
	uint32_t seq;		/* Netlink sequence ID of request. */
};

int dp_output_port(struct datapath *, struct sk_buff *, int out_port);
int dp_output_control(struct datapath *, struct sk_buff *,
			   uint32_t buffer_id, size_t max_len, int reason);
int dp_set_origin(struct datapath *, uint16_t, struct sk_buff *);
int dp_send_features_reply(struct datapath *, const struct sender *);
int dp_send_config_reply(struct datapath *, const struct sender *);
int dp_send_flow_expired(struct datapath *, struct sw_flow *);
int dp_send_flow_stats(struct datapath *, const struct sender *,
		       const struct ofp_match *);
int dp_send_table_stats(struct datapath *, const struct sender *);
int dp_send_port_stats(struct datapath *, const struct sender *);
int dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp);

/* Should hold at least RCU read lock when calling */
struct datapath *dp_get(int dp_idx);

#endif /* datapath.h */
