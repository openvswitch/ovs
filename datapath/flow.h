#ifndef FLOW_H
#define FLOW_H 1

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>

#include "openflow.h"

struct sk_buff;
struct ofp_flow_mod;

/* Identification data for a flow.
 * Network byte order except for the "wildcards" field.
 * Ordered to make bytewise comparisons (e.g. with memcmp()) fail quickly and
 * to keep the amount of padding to a minimum.
 * If you change the ordering of fields here, change flow_keys_equal() to
 * compare the proper fields.
 */
struct sw_flow_key {
	uint32_t nw_src;	/* IP source address. */
	uint32_t nw_dst;	/* IP destination address. */
	uint16_t in_port;	/* Input switch port */
	uint16_t dl_vlan;	/* Input VLAN. */
	uint16_t dl_type;	/* Ethernet frame type. */
	uint16_t tp_src;	/* TCP/UDP source port. */
	uint16_t tp_dst;	/* TCP/UDP destination port. */
	uint8_t dl_src[ETH_ALEN]; /* Ethernet source address. */
	uint8_t dl_dst[ETH_ALEN]; /* Ethernet destination address. */
	uint8_t nw_proto;	/* IP protocol. */
	uint8_t pad;		/* Pad to 32-bit alignment. */
	uint32_t wildcards;	/* Wildcard fields (host byte order). */
	uint32_t nw_src_mask;	/* 1-bit in each significant nw_src bit. */
	uint32_t nw_dst_mask;	/* 1-bit in each significant nw_dst bit. */
};

/* Compare two sw_flow_keys and return true if they are the same flow, false
 * otherwise.  Wildcards and netmasks are not considered. */
static inline int flow_keys_equal(const struct sw_flow_key *a,
				   const struct sw_flow_key *b) 
{
	return !memcmp(a, b, offsetof(struct sw_flow_key, wildcards));
}

/* We need to manually make sure that the structure is 32-bit aligned,
 * since we don't want garbage values in compiler-generated pads from
 * messing up hash matches.
 */
static inline void check_key_align(void)
{
	BUILD_BUG_ON(sizeof(struct sw_flow_key) != 44); 
}

/* We keep actions as a separate structure because we need to be able to 
 * swap them out atomically when the modify command comes from a Flow
 * Modify message. */
struct sw_flow_actions {
	size_t actions_len;
	struct rcu_head rcu;

	struct ofp_action_header actions[0];
};

/* Locking:
 *
 * - Readers must take rcu_read_lock and hold it the entire time that the flow
 *   must continue to exist.
 *
 * - Writers must hold dp_mutex.
 */
struct sw_flow {
	struct sw_flow_key key;

	uint16_t priority;      /* Only used on entries with wildcards. */
	uint16_t idle_timeout;	/* Idle time before discarding (seconds). */
	uint16_t hard_timeout;  /* Hard expiration time (seconds) */
	unsigned long used;     /* Last used time (in jiffies). */

	struct sw_flow_actions *sf_acts;

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

int flow_matches_1wild(const struct sw_flow_key *, const struct sw_flow_key *);
int flow_matches_2wild(const struct sw_flow_key *, const struct sw_flow_key *);
int flow_matches_desc(const struct sw_flow_key *, const struct sw_flow_key *, 
		int);
struct sw_flow *flow_alloc(size_t actions_len, gfp_t flags);
void flow_free(struct sw_flow *);
void flow_deferred_free(struct sw_flow *);
void flow_deferred_free_acts(struct sw_flow_actions *);
void flow_replace_acts(struct sw_flow *, const struct ofp_action_header *, 
		size_t);
int flow_extract(struct sk_buff *, uint16_t in_port, struct sw_flow_key *);
void flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from);
void flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from);
int flow_timeout(struct sw_flow *);

void print_flow(const struct sw_flow_key *);

static inline void flow_used(struct sw_flow *flow, struct sk_buff *skb) 
{
	unsigned long flags;

	flow->used = jiffies;

	spin_lock_irqsave(&flow->lock, flags);
	flow->packet_count++;
	flow->byte_count += skb->len;
	spin_unlock_irqrestore(&flow->lock, flags);
}

extern struct kmem_cache *flow_cache;

int flow_init(void);
void flow_exit(void);

#endif /* flow.h */
