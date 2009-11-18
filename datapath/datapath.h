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
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include "flow.h"
#include "dp_sysfs.h"

/* Mask for the priority bits in a vlan header.  If we ever merge upstream
 * then this should go into include/linux/if_vlan.h. */
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13

#define DP_MAX_PORTS 1024
#define DP_MAX_GROUPS 16

#define DP_L2_BITS (PAGE_SHIFT - ilog2(sizeof(struct dp_bucket*)))
#define DP_L2_SIZE (1 << DP_L2_BITS)
#define DP_L2_SHIFT 0

#define DP_L1_BITS (PAGE_SHIFT - ilog2(sizeof(struct dp_bucket**)))
#define DP_L1_SIZE (1 << DP_L1_BITS)
#define DP_L1_SHIFT DP_L2_BITS

/* For 4 kB pages, this is 1,048,576 on 32-bit or 262,144 on 64-bit. */
#define DP_MAX_BUCKETS (DP_L1_SIZE * DP_L2_SIZE)

/**
 * struct dp_table - flow table
 * @n_buckets: number of buckets (a power of 2 between %DP_L1_SIZE and
 * %DP_MAX_BUCKETS)
 * @buckets: pointer to @n_buckets/%DP_L1_SIZE pointers to %DP_L1_SIZE pointers
 * to buckets
 * @hash_seed: random number used for flow hashing, to make the hash
 * distribution harder to predict
 * @rcu: RCU callback structure
 *
 * The @buckets array is logically an array of pointers to buckets.  It is
 * broken into two levels to avoid the need to kmalloc() any object larger than
 * a single page or to use vmalloc().  @buckets is always nonnull, as is each
 * @buckets[i], but each @buckets[i][j] is nonnull only if the specified hash
 * bucket is nonempty (for 0 <= i < @n_buckets/%DP_L1_SIZE, 0 <= j <
 * %DP_L1_SIZE).
 */
struct dp_table {
	unsigned int n_buckets;
	struct dp_bucket ***buckets;
	unsigned int hash_seed;
	struct rcu_head rcu;
};

/**
 * struct dp_bucket - single bucket within datapath flow table
 * @rcu: RCU callback structure
 * @n_flows: number of flows in @flows[] array
 * @flows: array of @n_flows pointers to flows
 *
 * The expected number of flows per bucket is 1, but this allows for an
 * arbitrary number of collisions.
 */
struct dp_bucket {
	struct rcu_head rcu;
	unsigned int n_flows;
	struct sw_flow *flows[];
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

	struct kobject ifobj;

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
	struct kobject kobj;
	char linkname[IFNAMSIZ];
	struct list_head node;   /* Element in datapath.ports. */
};

extern struct notifier_block dp_device_notifier;
extern int (*dp_ioctl_hook)(struct net_device *dev, struct ifreq *rq, int cmd);

/* Flow table. */
struct dp_table *dp_table_create(unsigned int n_buckets);
void dp_table_destroy(struct dp_table *, int free_flows);
struct sw_flow *dp_table_lookup(struct dp_table *, const struct odp_flow_key *);
int dp_table_insert(struct dp_table *, struct sw_flow *);
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

int vswitch_skb_checksum_setup(struct sk_buff *skb);

#endif /* datapath.h */
