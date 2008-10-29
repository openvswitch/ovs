/* Interface exported by OpenFlow module. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include "openflow/openflow.h"
#include "flow.h"


#define NL_FLOWS_PER_MESSAGE 100

#ifdef NDEBUG
#define dprintk(x...)
#else
#define dprintk(x...) printk(x)
#endif

/* Capabilities supported by this implementation. */
#define OFP_SUPPORTED_CAPABILITIES ( OFPC_FLOW_STATS \
		| OFPC_TABLE_STATS \
		| OFPC_PORT_STATS \
		| OFPC_MULTI_PHY_TX )

/* Actions supported by this implementation. */
#define OFP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT) \
		| (1 << OFPAT_SET_VLAN_VID) \
		| (1 << OFPAT_SET_VLAN_PCP) \
		| (1 << OFPAT_STRIP_VLAN) \
		| (1 << OFPAT_SET_DL_SRC) \
		| (1 << OFPAT_SET_DL_DST) \
		| (1 << OFPAT_SET_NW_SRC) \
		| (1 << OFPAT_SET_NW_DST) \
		| (1 << OFPAT_SET_TP_SRC) \
		| (1 << OFPAT_SET_TP_DST) )

struct sk_buff;

#define DP_MAX_PORTS 255

struct datapath {
	int dp_idx;

	/* Unique identifier for this datapath, incorporates the dp_idx and
	 * a hardware address */
	uint64_t  id;

	struct timer_list timer;	/* Expiration timer. */
	struct sw_chain *chain;	 /* Forwarding rules. */
	struct task_struct *dp_task; /* Kernel thread for maintenance. */

	/* Data related to the "of" device of this datapath */
	struct net_device *netdev;

	/* Configuration set from controller */
	uint16_t flags;
	uint16_t miss_send_len;

	/* Switch ports. */
	struct net_bridge_port *ports[DP_MAX_PORTS];
	struct net_bridge_port *local_port; /* OFPP_LOCAL port. */
	struct list_head port_list; /* All ports, including local_port. */
};

/* Information necessary to reply to the sender of an OpenFlow message. */
struct sender {
	uint32_t xid;		/* OpenFlow transaction ID of request. */
	uint32_t pid;		/* Netlink process ID of sending socket. */
	uint32_t seq;		/* Netlink sequence ID of request. */
};

struct net_bridge_port {
	u16	port_no;
	u32 config;		/* Some subset of OFPPC_* flags. */
	u32 state;		/* Some subset of OFPPS_* flags. */
	spinlock_t lock;
	struct work_struct port_task;
	struct datapath	*dp;
	struct net_device *dev;
	struct snat_conf *snat;  /* Only set if SNAT is configured for this port. */
	struct list_head node;   /* Element in datapath.ports. */
};

extern struct mutex dp_mutex;
extern struct notifier_block dp_device_notifier;

int dp_del_switch_port(struct net_bridge_port *);
int dp_xmit_skb(struct sk_buff *skb);
int dp_output_port(struct datapath *, struct sk_buff *, int out_port,
		   int ignore_no_fwd);
int dp_output_control(struct datapath *, struct sk_buff *, uint32_t, 
			size_t, int);
void dp_set_origin(struct datapath *, uint16_t, struct sk_buff *);
int dp_send_features_reply(struct datapath *, const struct sender *);
int dp_send_config_reply(struct datapath *, const struct sender *);
int dp_send_port_status(struct net_bridge_port *p, uint8_t status);
int dp_send_flow_expired(struct datapath *, struct sw_flow *,
			 enum ofp_flow_expired_reason);
int dp_send_error_msg(struct datapath *, const struct sender *, 
			uint16_t, uint16_t, const void *, size_t);
int dp_update_port_flags(struct datapath *dp, const struct ofp_port_mod *opm);
int dp_send_echo_reply(struct datapath *, const struct sender *,
		       const struct ofp_header *);
int dp_send_hello(struct datapath *, const struct sender *,
		  const struct ofp_header *);

/* Should hold at least RCU read lock when calling */
struct datapath *dp_get(int dp_idx);

#endif /* datapath.h */
