#ifndef FLOW_H
#define FLOW_H 1

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>

#include "openflow.h"

struct sk_buff;
struct ofp_flow_mod;

/* Identification data for a flow.
   Network byte order except for the "wildcards" field.
   In decreasing order by size, so that sw_flow_key structures can
   be hashed or compared bytewise.
   It might be useful to reorder members from (expected) greatest to least
   inter-flow variability, so that failing bytewise comparisons with memcmp
   terminate as quickly as possible on average. */
struct sw_flow_key {
	uint32_t nw_src;		/* IP source address. */
	uint32_t nw_dst;		/* IP destination address. */
	uint16_t in_port;	    /* Input switch port */
	uint16_t dl_vlan;	    /* Input VLAN. */
	uint16_t dl_type;	    /* Ethernet frame type. */
	uint16_t tp_src;        /* TCP/UDP source port. */
	uint16_t tp_dst;        /* TCP/UDP destination port. */
	uint16_t wildcards;	    /* Wildcard fields (host byte order). */
	uint8_t dl_src[6];	    /* Ethernet source address. */
	uint8_t dl_dst[6];	    /* Ethernet destination address. */
	uint8_t nw_proto;		/* IP protocol. */
	uint8_t pad[3];		    /* NB: Pad to make 32-bit aligned */
};

/* We need to manually make sure that the structure is 32-bit aligned,
 * since we don't want garbage values in compiler-generated pads from
 * messing up hash matches.
 */
static inline void check_key_align(void)
{
	BUILD_BUG_ON(sizeof(struct sw_flow_key) != 36); 
}

/* Locking:
 *
 * - Readers must take rcu_read_lock and hold it the entire time that the flow
 *   must continue to exist.
 *
 * - Writers must hold dp_mutex.
 */
struct sw_flow {
	struct sw_flow_key key;

	uint16_t max_idle;      /* Idle time before discarding (seconds). */
	uint16_t priority;      /* Only used on entries with wildcards. */
	unsigned long timeout;  /* Expiration time (in jiffies). */

	/* FIXME?  Probably most flows have only a single action. */
	unsigned int n_actions;
	struct ofp_action *actions;

	/* For use by table implementation. */
	struct list_head node;
	struct list_head iter_node;
	unsigned long serial;
	void *private;

	spinlock_t lock;         /* Lock this entry...mostly for stat updates */
	unsigned long init_time; /* When the flow was created (in jiffies). */
	uint64_t packet_count;   /* Number of packets associated with this entry */
	uint64_t byte_count;     /* Number of bytes associated with this entry */

	struct rcu_head rcu;
};

int flow_matches(const struct sw_flow_key *, const struct sw_flow_key *);
int flow_del_matches(const struct sw_flow_key *, const struct sw_flow_key *, 
		int);
struct sw_flow *flow_alloc(int n_actions, gfp_t flags);
void flow_free(struct sw_flow *);
void flow_deferred_free(struct sw_flow *);
void flow_extract(struct sk_buff *, uint16_t in_port, struct sw_flow_key *);
void flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from);
void flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from);

void print_flow(const struct sw_flow_key *);

#include <linux/jiffies.h>
static inline int flow_timeout(struct sw_flow *flow)
{
	if (flow->max_idle == OFP_FLOW_PERMANENT)
		return 0;

	return time_after(jiffies, flow->timeout);
}

static inline void flow_used(struct sw_flow *flow, struct sk_buff *skb) 
{
	unsigned long flags;

	if (flow->max_idle != OFP_FLOW_PERMANENT)
		flow->timeout = jiffies + HZ * flow->max_idle;

	spin_lock_irqsave(&flow->lock, flags);
	flow->packet_count++;
	flow->byte_count += skb->len;
	spin_unlock_irqrestore(&flow->lock, flags);
}

extern struct kmem_cache *flow_cache;

int flow_init(void);
void flow_exit(void);

#endif /* flow.h */
