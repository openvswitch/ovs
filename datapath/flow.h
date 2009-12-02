/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef FLOW_H
#define FLOW_H 1

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>

#include "openvswitch/datapath-protocol.h"

struct sk_buff;

struct sw_flow_actions {
	struct rcu_head rcu;
	unsigned int n_actions;
	union odp_action actions[];
};

struct sw_flow {
	struct rcu_head rcu;
	struct odp_flow_key key;
	struct sw_flow_actions *sf_acts;

	struct timespec used;	/* Last used time. */

	u8 ip_tos;		/* IP TOS value. */

	spinlock_t lock;	/* Lock for values below. */
	u64 packet_count;	/* Number of packets matched. */
	u64 byte_count;		/* Number of bytes matched. */
	u8 tcp_flags;		/* Union of seen TCP flags. */
};

extern struct kmem_cache *flow_cache;

struct sw_flow_actions *flow_actions_alloc(size_t n_actions);
void flow_free(struct sw_flow *);
void flow_deferred_free(struct sw_flow *);
void flow_deferred_free_acts(struct sw_flow_actions *);
int flow_extract(struct sk_buff *, u16 in_port, struct odp_flow_key *);
void flow_used(struct sw_flow *, struct sk_buff *);

int flow_init(void);
void flow_exit(void);

#endif /* flow.h */
