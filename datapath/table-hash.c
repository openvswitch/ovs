/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include "table.h"
#include "crc32.h"
#include "flow.h"
#include "datapath.h"

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

static void *kmem_alloc(size_t);
static void *kmem_zalloc(size_t);
static void kmem_free(void *, size_t);

struct sw_table_hash {
	struct sw_table swt;
	struct crc32 crc32;
	unsigned int n_flows;
	unsigned int bucket_mask; /* Number of buckets minus 1. */
	struct sw_flow **buckets;
};

static struct sw_flow **find_bucket(struct sw_table *swt,
									const struct sw_flow_key *key)
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	unsigned int crc = crc32_calculate(&th->crc32, key, sizeof *key);
	return &th->buckets[crc & th->bucket_mask];
}

static struct sw_flow *table_hash_lookup(struct sw_table *swt,
										 const struct sw_flow_key *key)
{
	struct sw_flow *flow = *find_bucket(swt, key);
	return flow && !memcmp(&flow->key, key, sizeof *key) ? flow : NULL;
}

static int table_hash_insert(struct sw_table *swt, struct sw_flow *flow)
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	struct sw_flow **bucket;
	int retval;

	if (flow->key.wildcards != 0)
		return 0;

	bucket = find_bucket(swt, &flow->key);
	if (*bucket == NULL) {
		th->n_flows++;
		rcu_assign_pointer(*bucket, flow);
		retval = 1;
	} else {
		struct sw_flow *old_flow = *bucket;
		if (!memcmp(&old_flow->key, &flow->key, sizeof flow->key)) {
			rcu_assign_pointer(*bucket, flow);
			flow_deferred_free(old_flow);
			retval = 1;
		} else {
			retval = 0;
		}
	}
	return retval;
}

/* Caller must update n_flows. */
static int do_delete(struct sw_flow **bucket, struct sw_flow *flow)
{
	rcu_assign_pointer(*bucket, NULL);
	flow_deferred_free(flow);
	return 1;
}

/* Returns number of deleted flows.  We can ignore the priority
 * argument, since all exact-match entries are the same (highest)
 * priority. */
static int table_hash_delete(struct sw_table *swt,
							 const struct sw_flow_key *key, 
							 uint16_t priority, int strict)
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	unsigned int count = 0;

	if (key->wildcards == 0) {
		struct sw_flow **bucket = find_bucket(swt, key);
		struct sw_flow *flow = *bucket;
		if (flow && !memcmp(&flow->key, key, sizeof *key))
			count = do_delete(bucket, flow);
	} else {
		unsigned int i;

		for (i = 0; i <= th->bucket_mask; i++) {
			struct sw_flow **bucket = &th->buckets[i];
			struct sw_flow *flow = *bucket;
			if (flow && flow_del_matches(&flow->key, key, strict))
				count += do_delete(bucket, flow);
		}
	}
	th->n_flows -= count;
	return count;
}

static int table_hash_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	unsigned int i;
	int count = 0;

	mutex_lock(&dp_mutex);
	for (i = 0; i <= th->bucket_mask; i++) {
		struct sw_flow **bucket = &th->buckets[i];
		struct sw_flow *flow = *bucket;
		if (flow && flow_timeout(flow)) {
			count += do_delete(bucket, flow); 
			if (dp->flags & OFPC_SEND_FLOW_EXP)
				dp_send_flow_expired(dp, flow);
		}
	}
	th->n_flows -= count;
	mutex_unlock(&dp_mutex);

	return count;
}

static void table_hash_destroy(struct sw_table *swt)
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	unsigned int i;
	for (i = 0; i <= th->bucket_mask; i++)
	if (th->buckets[i])
		flow_free(th->buckets[i]);
	kmem_free(th->buckets, (th->bucket_mask + 1) * sizeof *th->buckets);
	kfree(th);
}

static int table_hash_iterate(struct sw_table *swt,
			      const struct sw_flow_key *key,
			      struct sw_table_position *position,
			      int (*callback)(struct sw_flow *, void *private),
			      void *private) 
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;

	if (position->private[0] > th->bucket_mask)
		return 0;

	if (key->wildcards == 0) {
		struct sw_flow *flow;
		int error;

		flow = table_hash_lookup(swt, key);
		if (!flow)
			return 0;

		error = callback(flow, private);
		if (!error)
			position->private[0] = -1;
		return error;
	} else {
		int i;

		for (i = position->private[0]; i <= th->bucket_mask; i++) {
			struct sw_flow *flow = th->buckets[i];
			if (flow && flow_matches(key, &flow->key)) {
				int error = callback(flow, private);
				if (error) {
					position->private[0] = i;
					return error;
				}
			}
		}
		return 0;
	}
}
static void table_hash_stats(struct sw_table *swt,
				 struct sw_table_stats *stats) 
{
	struct sw_table_hash *th = (struct sw_table_hash *) swt;
	stats->name = "hash";
	stats->n_flows = th->n_flows;
	stats->max_flows = th->bucket_mask + 1;
}

struct sw_table *table_hash_create(unsigned int polynomial,
			unsigned int n_buckets)
{
	struct sw_table_hash *th;
	struct sw_table *swt;

	th = kmalloc(sizeof *th, GFP_KERNEL);
	if (th == NULL)
		return NULL;

	BUG_ON(n_buckets & (n_buckets - 1));
	th->buckets = kmem_zalloc(n_buckets * sizeof *th->buckets);
	if (th->buckets == NULL) {
		printk("failed to allocate %u buckets\n", n_buckets);
		kfree(th);
		return NULL;
	}
	th->bucket_mask = n_buckets - 1;

	swt = &th->swt;
	swt->lookup = table_hash_lookup;
	swt->insert = table_hash_insert;
	swt->delete = table_hash_delete;
	swt->timeout = table_hash_timeout;
	swt->destroy = table_hash_destroy;
	swt->iterate = table_hash_iterate;
	swt->stats = table_hash_stats;

	crc32_init(&th->crc32, polynomial);
	th->n_flows = 0;

	return swt;
}

/* Double-hashing table. */

struct sw_table_hash2 {
	struct sw_table swt;
	struct sw_table *subtable[2];
};

static struct sw_flow *table_hash2_lookup(struct sw_table *swt,
										  const struct sw_flow_key *key)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	int i;
	
	for (i = 0; i < 2; i++) {
		struct sw_flow *flow = *find_bucket(t2->subtable[i], key);
		if (flow && !memcmp(&flow->key, key, sizeof *key))
			return flow;
	}
	return NULL;
}

static int table_hash2_insert(struct sw_table *swt, struct sw_flow *flow)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;

	if (table_hash_insert(t2->subtable[0], flow))
		return 1;
	return table_hash_insert(t2->subtable[1], flow);
}

static int table_hash2_delete(struct sw_table *swt,
							  const struct sw_flow_key *key, 
							  uint16_t priority, int strict)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	return (table_hash_delete(t2->subtable[0], key, priority, strict)
			+ table_hash_delete(t2->subtable[1], key, priority, strict));
}

static int table_hash2_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	return (table_hash_timeout(dp, t2->subtable[0])
			+ table_hash_timeout(dp, t2->subtable[1]));
}

static void table_hash2_destroy(struct sw_table *swt)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	table_hash_destroy(t2->subtable[0]);
	table_hash_destroy(t2->subtable[1]);
	kfree(t2);
}

static int table_hash2_iterate(struct sw_table *swt,
			       const struct sw_flow_key *key,
			       struct sw_table_position *position,
			       int (*callback)(struct sw_flow *, void *),
			       void *private)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	int i;

	for (i = position->private[1]; i < 2; i++) {
		int error = table_hash_iterate(t2->subtable[i], key, position,
					       callback, private);
		if (error) {
			return error;
		}
		position->private[0] = 0;
		position->private[1]++;
	}
	return 0;
}

static void table_hash2_stats(struct sw_table *swt,
				 struct sw_table_stats *stats)
{
	struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
	struct sw_table_stats substats[2];
	int i;

	for (i = 0; i < 2; i++)
		table_hash_stats(t2->subtable[i], &substats[i]);
	stats->name = "hash2";
	stats->n_flows = substats[0].n_flows + substats[1].n_flows;
	stats->max_flows = substats[0].max_flows + substats[1].max_flows;
}

struct sw_table *table_hash2_create(unsigned int poly0, unsigned int buckets0,
									unsigned int poly1, unsigned int buckets1)

{
	struct sw_table_hash2 *t2;
	struct sw_table *swt;

	t2 = kmalloc(sizeof *t2, GFP_KERNEL);
	if (t2 == NULL)
		return NULL;

	t2->subtable[0] = table_hash_create(poly0, buckets0);
	if (t2->subtable[0] == NULL)
		goto out_free_t2;

	t2->subtable[1] = table_hash_create(poly1, buckets1);
	if (t2->subtable[1] == NULL)
		goto out_free_subtable0;

	swt = &t2->swt;
	swt->lookup = table_hash2_lookup;
	swt->insert = table_hash2_insert;
	swt->delete = table_hash2_delete;
	swt->timeout = table_hash2_timeout;
	swt->destroy = table_hash2_destroy;
	swt->iterate = table_hash2_iterate;
	swt->stats = table_hash2_stats;

	return swt;

out_free_subtable0:
	table_hash_destroy(t2->subtable[0]);
out_free_t2:
	kfree(t2);
	return NULL;
}

/* From fs/xfs/linux-2.4/kmem.c. */

static void *
kmem_alloc(size_t size)
{
	void *ptr;

#ifdef KMALLOC_MAX_SIZE
	if (size > KMALLOC_MAX_SIZE)
		return NULL;
#endif
	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr) {
		ptr = vmalloc(size);
		if (ptr)
			printk("openflow: used vmalloc for %lu bytes\n", 
					(unsigned long)size);
	}
	return ptr;
}

static void *
kmem_zalloc(size_t size)
{
	void *ptr = kmem_alloc(size);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

static void
kmem_free(void *ptr, size_t size)
{
	if (((unsigned long)ptr < VMALLOC_START) ||
		((unsigned long)ptr >= VMALLOC_END)) {
		kfree(ptr);
	} else {
		vfree(ptr);
	}
}
