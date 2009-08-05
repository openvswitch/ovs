/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Interface exported by openvswitch_mod. */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include "flow.h"
#include "brc_sysfs.h"

/* Mask for the priority bits in a vlan header.  If we ever merge upstream
 * then this should go into include/linux/if_vlan.h. */
#define VLAN_PCP_MASK 0xe000

#define DP_MAX_PORTS 256
#define DP_MAX_GROUPS 16

#define DP_L2_BITS (PAGE_SHIFT - ilog2(sizeof(struct sw_flow*)))
#define DP_L2_SIZE (1 << DP_L2_BITS)
#define DP_L2_SHIFT 0

#define DP_L1_BITS (PAGE_SHIFT - ilog2(sizeof(struct sw_flow**)))
#define DP_L1_SIZE (1 << DP_L1_BITS)
#define DP_L1_SHIFT DP_L2_BITS

#define DP_MAX_BUCKETS (DP_L1_SIZE * DP_L2_SIZE)

struct dp_table {
	unsigned int n_buckets;
	struct sw_flow ***flows[2];
	struct rcu_head rcu;
};

#define DP_N_QUEUES 2
#define DP_MAX_QUEUE_LEN 100

struct dp_stats_percpu {
	u64 n_frags;
	u64 n_hit;
	u64 n_missed;
	u64 n_lost;
};

struct dp_port_group {
	struct rcu_head rcu;
	int n_ports;
	u16 ports[];
};

struct datapath {
	struct mutex mutex;
	int dp_idx;

#ifdef SUPPORT_SYSFS
	struct kobject ifobj;
#endif

	int drop_frags;

	/* Queued data. */
	struct sk_buff_head queues[DP_N_QUEUES];
	wait_queue_head_t waitqueue;

	/* Flow table. */
	unsigned int n_flows;
	struct dp_table *table;

	/* Port groups. */
	struct dp_port_group *groups[DP_MAX_GROUPS];

	/* Switch ports. */
	unsigned int n_ports;
	struct net_bridge_port *ports[DP_MAX_PORTS];
	struct list_head port_list; /* All ports, including local_port. */

	/* Stats. */
	struct dp_stats_percpu *stats_percpu;
};

struct net_bridge_port {
	u16 port_no;
	struct datapath	*dp;
	struct net_device *dev;
#ifdef SUPPORT_SYSFS
	struct kobject kobj;
#endif
	struct list_head node;   /* Element in datapath.ports. */
};

extern struct notifier_block dp_device_notifier;
extern int (*dp_ioctl_hook)(struct net_device *dev, struct ifreq *rq, int cmd);

/* Flow table. */
struct dp_table *dp_table_create(unsigned int n_buckets);
void dp_table_destroy(struct dp_table *, int free_flows);
struct sw_flow *dp_table_lookup(struct dp_table *, const struct odp_flow_key *);
struct sw_flow **dp_table_lookup_for_insert(struct dp_table *, const struct odp_flow_key *);
int dp_table_delete(struct dp_table *, struct sw_flow *);
int dp_table_expand(struct datapath *);
int dp_table_flush(struct datapath *);
int dp_table_foreach(struct dp_table *table,
		     int (*callback)(struct sw_flow *flow, void *aux),
		     void *aux);

void dp_process_received_packet(struct sk_buff *, struct net_bridge_port *);
int dp_del_port(struct net_bridge_port *);
int dp_output_control(struct datapath *, struct sk_buff *, int, u32 arg);
int dp_min_mtu(const struct datapath *dp);

struct datapath *get_dp(int dp_idx);

static inline const char *dp_name(const struct datapath *dp)
{
	return dp->ports[ODPP_LOCAL]->dev->name;
}

#ifdef CONFIG_XEN
int skb_checksum_setup(struct sk_buff *skb);
#else
static inline int skb_checksum_setup(struct sk_buff *skb)
{
	return 0;
}
#endif

#endif /* datapath.h */
