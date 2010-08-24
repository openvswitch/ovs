/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/time.h>

#include "openvswitch/datapath-protocol.h"
#include "table.h"

struct sk_buff;

struct sw_flow_actions {
	struct rcu_head rcu;
	unsigned int n_actions;
	union odp_action actions[];
};

struct sw_flow {
	struct rcu_head rcu;
	struct tbl_node tbl_node;

	struct odp_flow_key key;
	struct sw_flow_actions *sf_acts;

	spinlock_t lock;	/* Lock for values below. */
	unsigned long used;	/* Last used time (in jiffies). */
	u64 packet_count;	/* Number of packets matched. */
	u64 byte_count;		/* Number of bytes matched. */
	u8 tcp_flags;		/* Union of seen TCP flags. */
};

struct arp_eth_header
{
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	unsigned char   ar_hln;	/* length of hardware address   */
	unsigned char   ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __attribute__((packed));

extern struct kmem_cache *flow_cache;

struct sw_flow_actions *flow_actions_alloc(size_t n_actions);
void flow_deferred_free(struct sw_flow *);
void flow_deferred_free_acts(struct sw_flow_actions *);
int flow_extract(struct sk_buff *, u16 in_port, struct odp_flow_key *);
void flow_used(struct sw_flow *, struct sk_buff *);

u32 flow_hash(const struct odp_flow_key *key);
int flow_cmp(const struct tbl_node *, void *target);
void flow_free_tbl(struct tbl_node *);

int flow_init(void);
void flow_exit(void);

static inline struct sw_flow *flow_cast(const struct tbl_node *node)
{
	return container_of(node, struct sw_flow, tbl_node);
}

#endif /* flow.h */
