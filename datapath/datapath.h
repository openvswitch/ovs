/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include <linux/seqlock.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include "checksum.h"
#include "flow.h"
#include "dp_sysfs.h"

struct vport;

/* Mask for the priority bits in a vlan header.  If we ever merge upstream
 * then this should go into include/linux/if_vlan.h. */
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13

#define DP_MAX_PORTS 1024

#define DP_N_QUEUES 3
#define DP_MAX_QUEUE_LEN 100

/**
 * struct dp_stats_percpu - per-cpu packet processing statistics for a given
 * datapath.
 * @n_frags: Number of IP fragments processed by datapath.
 * @n_hit: Number of received packets for which a matching flow was found in
 * the flow table.
 * @n_miss: Number of received packets that had no matching flow in the flow
 * table.  The sum of @n_hit and @n_miss is the number of packets that have
 * been received by the datapath.
 * @n_lost: Number of received packets that had no matching flow in the flow
 * table that could not be sent to userspace (normally due to an overflow in
 * one of the datapath's queues).
 */
struct dp_stats_percpu {
	u64 n_frags;
	u64 n_hit;
	u64 n_missed;
	u64 n_lost;
	seqcount_t seqlock;
};

/**
 * struct datapath - datapath for flow-based packet switching
 * @rcu: RCU callback head for deferred destruction.
 * @mutex: Mutual exclusion for ioctls.
 * @dp_idx: Datapath number (index into the dps[] array in datapath.c).
 * @ifobj: Represents /sys/class/net/<devname>/brif.
 * @drop_frags: Drop all IP fragments if nonzero.
 * @queues: %DP_N_QUEUES sets of queued packets for userspace to handle.
 * @waitqueue: Waitqueue, for waiting for new packets in @queues.
 * @n_flows: Number of flows currently in flow table.
 * @table: Current flow table.
 * @ports: Map from port number to &struct vport.  %ODPP_LOCAL port
 * always exists, other ports may be %NULL.
 * @port_list: List of all ports in @ports in arbitrary order.
 * @stats_percpu: Per-CPU datapath statistics.
 * @sflow_probability: Number of packets out of UINT_MAX to sample to the
 * %ODPL_SFLOW queue, e.g. (@sflow_probability/UINT_MAX) is the probability of
 * sampling a given packet.
 */
struct datapath {
	struct rcu_head rcu;
	struct mutex mutex;
	int dp_idx;
	struct kobject ifobj;

	int drop_frags;

	/* Queued data. */
	struct sk_buff_head queues[DP_N_QUEUES];
	wait_queue_head_t waitqueue;

	/* Flow table. */
	struct tbl __rcu *table;

	/* Switch ports. */
	struct vport __rcu *ports[DP_MAX_PORTS];
	struct list_head port_list;

	/* Stats. */
	struct dp_stats_percpu __percpu *stats_percpu;

	/* sFlow Sampling */
	unsigned int sflow_probability;
};

/**
 * struct ovs_skb_cb - OVS data in skb CB
 * @vport: The datapath port on which the skb entered the switch.
 * @flow: The flow associated with this packet.  May be %NULL if no flow.
 * @ip_summed: Consistently stores L4 checksumming status across different
 * kernel versions.
 * @tun_id: ID of the tunnel that encapsulated this packet.  It is 0 if the
 * packet was not received on a tunnel.
 */
struct ovs_skb_cb {
	struct vport		*vport;
	struct sw_flow		*flow;
#ifdef NEED_CSUM_NORMALIZE
	enum csum_type		ip_summed;
#endif
	__be64			tun_id;
};
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @type: One of %_ODPL_*_NR.
 * @key: Becomes %ODP_PACKET_ATTR_KEY.  Must be nonnull.
 * @userdata: Becomes %ODP_PACKET_ATTR_USERDATA if nonzero.
 * @sample_pool: Becomes %ODP_PACKET_ATTR_SAMPLE_POOL if nonzero.
 * @actions: Becomes %ODP_PACKET_ATTR_ACTIONS if nonnull.
 * @actions_len: Number of bytes in @actions.
*/
struct dp_upcall_info {
	u32 type;
	const struct sw_flow_key *key;
	u64 userdata;
	u32 sample_pool;
	const struct nlattr *actions;
	u32 actions_len;
};

extern struct notifier_block dp_device_notifier;
extern int (*dp_ioctl_hook)(struct net_device *dev, struct ifreq *rq, int cmd);

void dp_process_received_packet(struct vport *, struct sk_buff *);
int dp_detach_port(struct vport *);
int dp_upcall(struct datapath *, struct sk_buff *, const struct dp_upcall_info *);
int dp_min_mtu(const struct datapath *dp);
void set_internal_devs_mtu(const struct datapath *dp);

struct datapath *get_dp(int dp_idx);
const char *dp_name(const struct datapath *dp);

#endif /* datapath.h */
