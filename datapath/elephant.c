/*
 * Copyright (c) 2007-2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "datapath.h"
#include "elephant.h"
#include "flow.h"
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/workqueue.h>

struct elephant_flow {
	struct rcu_head rcu;
	struct hlist_node hash_node[2];
	u32 hash;

	struct sw_flow_key key;

	spinlock_t lock;       /* Lock for values below. */
	unsigned long created; /* Time created (in jiffies). */
	unsigned long used;    /* Last used time (in jiffies). */
	u64 packet_count;      /* Number of packets matched. */
	u64 byte_count;        /* Number of bytes matched. */
	u64 tso_count;         /* Number of TSO-sized packets. */
};

#define ELEPHANT_CHECK_INTERVAL (1 * HZ)
#define ELEPHANT_FLOW_LIFE (5 * HZ)
static void elephant_check_table(struct work_struct *work);

static struct kmem_cache *elephant_table;

static void ovs_elephant_tbl_insert(struct elephant_table *table,
		struct elephant_flow *flow, struct sw_flow_key *key, int key_len);
static void ovs_elephant_tbl_remove(struct elephant_table *table,
		struct elephant_flow *flow);

static struct elephant_flow *ovs_elephant_tbl_lookup(struct elephant_table *table,
		struct sw_flow_key *key, int key_len);


void ovs_elephant_free(struct elephant_flow *flow);

static inline int ovs_elephant_tbl_need_to_expand(struct elephant_table *table)
{
	return (table->count > table->n_buckets);
}

static struct hlist_head *find_bucket(struct elephant_table *table, u32 hash)
{
	hash = jhash_1word(hash, table->hash_seed);
	return flex_array_get(table->buckets,
			(hash & (table->n_buckets - 1)));
}

static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head *),
			n_buckets, GFP_ATOMIC);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_ATOMIC);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
			flex_array_get(buckets, i));

	return buckets;
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}

struct elephant_table *ovs_elephant_tbl_alloc(int new_size)
{
	struct elephant_table *table = kmalloc(sizeof(*table), GFP_ATOMIC);

	if (!table)
		return NULL;

	table->buckets = alloc_buckets(new_size);

	if (!table->buckets) {
		kfree(table);
		return NULL;
	}
	table->n_buckets = new_size;
	table->count = 0;
	table->node_ver = 0;
	get_random_bytes(&table->hash_seed, sizeof(u32));

	return table;
}

void ovs_elephant_tbl_destroy(struct elephant_table *table)
{
	int i;

	if (!table)
		return;

	for (i = 0; i < table->n_buckets; i++) {
		struct elephant_flow *flow;
		struct hlist_head *head = flex_array_get(table->buckets, i);
		struct hlist_node *n;
		int ver = table->node_ver;

		hlist_for_each_entry_safe(flow, n, head, hash_node[ver]) {
			hlist_del_rcu(&flow->hash_node[ver]);
			ovs_elephant_free(flow);
		}
	}

	free_buckets(table->buckets);
	kfree(table);
}

static void elephant_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct elephant_table *table = container_of(rcu, struct elephant_table, rcu);

	ovs_elephant_tbl_destroy(table);
}

void ovs_elephant_tbl_deferred_destroy(struct elephant_table *table)
{
	if (!table)
		return;

	call_rcu(&table->rcu, elephant_tbl_destroy_rcu_cb);
}

struct elephant_flow *ovs_elephant_tbl_next(struct elephant_table *table, u32 *bucket, u32 *last)
{
	struct elephant_flow *flow;
	struct hlist_head *head;
	int ver;
	int i;

	ver = table->node_ver;
	while (*bucket < table->n_buckets) {
		i = 0;
		head = flex_array_get(table->buckets, *bucket);
		hlist_for_each_entry_rcu(flow, head, hash_node[ver]) {
			if (i < *last) {
				i++;
				continue;
			}
			*last = i + 1;
			return flow;
		}
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}

static void __elephant_tbl_insert(struct elephant_table *table, struct elephant_flow *flow)
{
	struct hlist_head *head;
	head = find_bucket(table, flow->hash);
	hlist_add_head_rcu(&flow->hash_node[table->node_ver], head);
	table->count++;
}

static void elephant_table_copy_flows(struct elephant_table *old, struct elephant_table *new)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct elephant_flow *flow;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);

		hlist_for_each_entry(flow, head, hash_node[old_ver])
			__elephant_tbl_insert(new, flow);
	}
}

static struct elephant_table *__elephant_tbl_rehash(struct elephant_table *table, int n_buckets)
{
	struct elephant_table *new_table;

	new_table = ovs_elephant_tbl_alloc(n_buckets);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	elephant_table_copy_flows(table, new_table);

	return new_table;
}

struct elephant_table *ovs_elephant_tbl_rehash(struct elephant_table *table)
{
	return __elephant_tbl_rehash(table, table->n_buckets);
}

struct elephant_table *ovs_elephant_tbl_expand(struct elephant_table *table)
{
	return __elephant_tbl_rehash(table, table->n_buckets * 2);
}

void ovs_elephant_free(struct elephant_flow *flow)
{
	if (unlikely(!flow))
		return;

	kmem_cache_free(elephant_table, flow);
}

/* RCU callback used by ovs_elephant_flow_deferred_free. */
static void rcu_free_elephant_flow_callback(struct rcu_head *rcu)
{
	struct elephant_flow *flow = container_of(rcu, struct elephant_flow, rcu);

	ovs_elephant_free(flow);
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void ovs_elephant_flow_deferred_free(struct elephant_flow *flow)
{
/* xxx Still need this? */
	call_rcu(&flow->rcu, rcu_free_elephant_flow_callback);
}

static u32 ovs_elephant_flow_hash(const struct sw_flow_key *key, int key_start, int key_len)
{
	return jhash2((u32 *)((u8 *)key + key_start),
			DIV_ROUND_UP(key_len - key_start, sizeof(u32)), 0);
}

static int flow_key_start(struct sw_flow_key *key)
{
	if (key->tun_key.ipv4_dst)
		return 0;
	else
		return offsetof(struct sw_flow_key, phy);
}

static struct elephant_flow *ovs_elephant_tbl_lookup(struct elephant_table *table,
				struct sw_flow_key *key, int key_len)
{
	struct elephant_flow *flow;
	struct hlist_head *head;
	u8 *_key;
	int key_start;
	u32 hash;

	key_start = flow_key_start(key);
	hash = ovs_elephant_flow_hash(key, key_start, key_len);

	_key = (u8 *) key + key_start;
	head = find_bucket(table, hash);
	hlist_for_each_entry_rcu(flow, head, hash_node[table->node_ver]) {
		if (flow->hash == hash &&
			!memcmp((u8 *)&flow->key + key_start, _key, key_len - key_start)) {
			return flow;
		}
	}
	return NULL;
}

static void ovs_elephant_tbl_insert(struct elephant_table *table,
		struct elephant_flow *flow, struct sw_flow_key *key, int key_len)
{
	flow->hash = ovs_elephant_flow_hash(key, flow_key_start(key), key_len);
	memcpy(&flow->key, key, sizeof(flow->key));
	__elephant_tbl_insert(table, flow);
}

static void ovs_elephant_tbl_remove(struct elephant_table *table,
		struct elephant_flow *flow)
{
	hlist_del_rcu(&flow->hash_node[table->node_ver]);
	table->count--;
	BUG_ON(table->count < 0);
}

static void elephant_check_table(struct work_struct *ws)
{
	struct elephant_table *table;
	int i;

	table = container_of(ws, struct elephant_table, work.work);

	for (i = 0; i < table->n_buckets; i++) {
		struct elephant_flow *flow;
		struct hlist_head *head = flex_array_get(table->buckets, i);
		struct hlist_node *n;
		int ver = table->node_ver;

		hlist_for_each_entry_safe(flow, n, head, hash_node[ver]) {
			if (time_after(jiffies, flow->used + ELEPHANT_FLOW_LIFE)) {
				ovs_elephant_tbl_remove(table, flow);
				ovs_elephant_flow_deferred_free(flow);
			}
		}
	}

	schedule_delayed_work(&table->work, ELEPHANT_CHECK_INTERVAL);
}

int ovs_elephant_dp_init(struct datapath *dp)
{
	INIT_DELAYED_WORK(&dp->elephant_table->work, elephant_check_table);
	schedule_delayed_work(&dp->elephant_table->work, ELEPHANT_CHECK_INTERVAL);

	return 0;
}

void ovs_elephant_dp_exit(struct datapath *dp)
{
	cancel_delayed_work_sync(&dp->elephant_table->work);
}

static struct elephant_flow *ovs_elephant_flow_alloc(void)
{
	struct elephant_flow *flow;

	flow = kmem_cache_alloc(elephant_table, GFP_ATOMIC);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&flow->lock);

	return flow;
}

static void clear_stats(struct elephant_flow *flow)
{
	flow->created = jiffies;
	flow->used = 0;
	flow->packet_count = 0;
	flow->byte_count = 0;
	flow->tso_count = 0;
}

static void print_flow(struct elephant_flow *flow)
{
	/* xxx Only supports non-tunneled IPv4! */
	printk("in_port(%d),ipv4(src=%#x,dst=%#x,proto=%d),tp(src=%d,dst=%d),"
		" packets:%lld, bytes:%lld, tso:%lld, created:%d, used:%d\n",
		flow->key.phy.in_port, ntohl(flow->key.ipv4.addr.src),
		ntohl(flow->key.ipv4.addr.dst),
		flow->key.ip.proto, ntohs(flow->key.tp.src),
		ntohs(flow->key.tp.dst),
		flow->packet_count, flow->byte_count, flow->tso_count,
		jiffies_to_msecs(jiffies - flow->created),
		jiffies_to_msecs(jiffies - flow->used));
}

void ovs_elephant_print_flows(struct datapath *dp)
{
	struct elephant_table *table = dp->elephant_table;
	int i;

	printk("--- Elephant Flows ---\n");
	for (i = 0; i < table->n_buckets; i++) {
		struct elephant_flow *flow;
		struct hlist_head *head = flex_array_get(table->buckets, i);
		int ver = table->node_ver;

		hlist_for_each_entry(flow, head, hash_node[ver]) {
			print_flow(flow);
		}
	}
}

void ovs_elephant_used(struct elephant_flow *flow, const struct sk_buff *skb,
		bool is_tso)
{
/* xxx Is the spin lock safe? */
	spin_lock(&flow->lock);
	flow->used = jiffies;
	flow->packet_count++;
	flow->byte_count += skb->len;
	if (is_tso)
		flow->tso_count++;
	spin_unlock(&flow->lock);
}

static bool byte_check(const struct elephant_flow *flow,
		uint32_t byte_count, uint32_t num_secs)

{
	if ((flow->byte_count >= byte_count) &&
			time_after(jiffies, flow->created + HZ * num_secs)) {
		return true;
	} else
		return false;
}

static bool tso_check(const struct elephant_flow *flow,
		uint32_t tso_size, uint32_t tso_count)

{
	if (flow->tso_count >= tso_count) {
		return true;
	} else
		return false;
}

bool is_elephant(const struct sk_buff *skb, uint32_t mech,
		uint32_t arg1, uint32_t arg2)
{
	struct elephant_table *table;
	struct sw_flow_key *key = OVS_CB(skb)->pkt_key;
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow_key elephant_key;
	struct elephant_flow *flow;

	if (mech == 0) {
		/* Detection disabled */
		return false;
	}

	/* Make a copy, since we need to zero-out the TCP flags */
	elephant_key = *key;
	elephant_key.tp.flags = 0;

/* xxx How should I do the locking here? */
	table = dp->elephant_table;
	flow = ovs_elephant_tbl_lookup(table, &elephant_key, sizeof(elephant_key));
	if (!flow) {
		/* Expand table, if necessary, to make room. */
		if (ovs_elephant_tbl_need_to_expand(table)) {
			struct elephant_table *new_table;

			new_table = ovs_elephant_tbl_expand(table);
			if (!IS_ERR(new_table)) {
				rcu_assign_pointer(dp->elephant_table, new_table);
				ovs_elephant_tbl_deferred_destroy(table);
				table = dp->elephant_table;
			}
		}

		/* Allocate flow. */
		flow = ovs_elephant_flow_alloc();
		if (IS_ERR(flow)) {
			/* xxx Not the greatest error handling. */
			return false;
		}
		clear_stats(flow);

		/* Put flow in bucket. */
		ovs_elephant_tbl_insert(table, flow, &elephant_key,
				sizeof(elephant_key));
	}

	if ((mech == 2) && (skb->len >= arg1))
		ovs_elephant_used(flow, skb, true);
	else
		ovs_elephant_used(flow, skb, false);

	if (mech == 1) {
		/* Byte counters */
		return byte_check(flow, arg1, arg2);
	} else if (mech == 2) {
		/* TSO buffers */
		return tso_check(flow, arg1, arg2);
	}

	return false;
}

/* Initializes the elephant module. */
int ovs_elephant_init(void)
{
	elephant_table = kmem_cache_create("sw_elephant", sizeof(struct sw_flow),
		0, 0, NULL);
	if (elephant_table == NULL)
		return -ENOMEM;

	return 0;
}

/* Uninitializes the elephant module. */
void ovs_elephant_exit(void)
{
	kmem_cache_destroy(elephant_table);
}
