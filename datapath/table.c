/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include "flow.h"
#include "datapath.h"

#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

static inline int bucket_size(int n_flows)
{
	return sizeof(struct dp_bucket) + sizeof(struct sw_flow*) * n_flows;
}

static struct dp_bucket *dp_bucket_alloc(int n_flows)
{
	return kmalloc(bucket_size(n_flows), GFP_KERNEL);
}

static void free_buckets(struct dp_bucket ***l1, unsigned int n_buckets,
			 int free_flows)
{
	unsigned int i;

	for (i = 0; i < n_buckets >> DP_L1_BITS; i++) {
		struct dp_bucket **l2 = l1[i];
		unsigned int j;

		for (j = 0; j < DP_L1_SIZE; j++) {
			struct dp_bucket *bucket = l2[j];
			if (!bucket)
				continue;

			if (free_flows) {
				unsigned int k;
				for (k = 0; k < bucket->n_flows; k++)
					flow_free(bucket->flows[k]);
			}
			kfree(bucket);
		}
		free_page((unsigned long)l2);
	}
	kfree(l1);
}

static struct dp_bucket ***alloc_buckets(unsigned int n_buckets)
{
	struct dp_bucket ***l1;
	unsigned int i;

	l1 = kmalloc((n_buckets >> DP_L1_BITS) * sizeof(struct dp_bucket**),
		     GFP_KERNEL);
	if (!l1)
		return NULL;
	for (i = 0; i < n_buckets >> DP_L1_BITS; i++) {
		l1[i] = (struct dp_bucket **)get_zeroed_page(GFP_KERNEL);
		if (!l1[i]) {
			free_buckets(l1, i << DP_L1_BITS, 0);
			return NULL;
		}
	}
	return l1;
}

/**
 * dp_table_create - create and return a new flow table
 * @n_buckets: number of buckets in the new table
 *
 * Creates and returns a new flow table, or %NULL if memory cannot be
 * allocated.  @n_buckets must be a power of 2 in the range %DP_L1_SIZE to
 * %DP_MAX_BUCKETS.
 */
struct dp_table *dp_table_create(unsigned int n_buckets)
{
	struct dp_table *table;

	table = kzalloc(sizeof *table, GFP_KERNEL);
	if (!table)
		goto err;

	table->n_buckets = n_buckets;
	table->buckets = alloc_buckets(n_buckets);
	if (!table->buckets)
		goto err_free_table;
	get_random_bytes(&table->hash_seed, sizeof table->hash_seed);

	return table;

err_free_table:
	kfree(table);
err:
	return NULL;
}

/**
 * dp_table_destroy - destroy flow table and optionally the flows it contains
 * @table: table to destroy (must not be %NULL)
 * @free_flows: whether to destroy the flows
 *
 * If @free_flows is zero, then the buckets in @table are destroyed but not the
 * flows within those buckets.  This behavior is useful when a table is being
 * replaced by a larger or smaller one without destroying the flows.
 *
 * If @free_flows is nonzero, then the flows in @table are destroyed as well as
 * the buckets.
 */
void dp_table_destroy(struct dp_table *table, int free_flows)
{
	free_buckets(table->buckets, table->n_buckets, free_flows);
	kfree(table);
}

static struct dp_bucket **find_bucket(struct dp_table *table, u32 hash)
{
	unsigned int l1 = (hash & (table->n_buckets - 1)) >> DP_L1_SHIFT;
	unsigned int l2 = hash & ((1 << DP_L2_BITS) - 1);
	return &table->buckets[l1][l2];
}

static int search_bucket(const struct dp_bucket *bucket, const struct odp_flow_key *key)
{
	int i;

	for (i = 0; i < bucket->n_flows; i++) {
		struct sw_flow *flow = rcu_dereference(bucket->flows[i]);
		if (!memcmp(&flow->key, key, sizeof(struct odp_flow_key)))
			return i;
	}

	return -1;
}

static struct sw_flow *lookup_flow(struct dp_table *table, u32 hash,
				   const struct odp_flow_key *key)
{
	struct dp_bucket **bucketp = find_bucket(table, hash);
	struct dp_bucket *bucket = rcu_dereference(*bucketp);
	int index;

	if (!bucket)
		return NULL;

	index = search_bucket(bucket, key);
	if (index < 0)
		return NULL;

	return bucket->flows[index];
}

static u32 flow_hash(const struct dp_table *table,
		     const struct odp_flow_key *key)
{
	return jhash2((u32*)key, sizeof *key / sizeof(u32), table->hash_seed);
}

/**
 * dp_table_lookup - searches flow table for a matching flow
 * @table: flow table to search
 * @key: flow key for which to search
 *
 * Searches @table for a flow whose key is equal to @key.  Returns the flow if
 * successful, otherwise %NULL.
 */
struct sw_flow *dp_table_lookup(struct dp_table *table,
				const struct odp_flow_key *key)
{
	return lookup_flow(table, flow_hash(table, key), key);
}

/**
 * dp_table_foreach - iterate through flow table
 * @table: table to iterate
 * @callback: function to call for each flow entry
 * @aux: Extra data to pass to @callback
 *
 * Iterates through all of the flows in @table in hash order, passing each of
 * them in turn to @callback.  If @callback returns nonzero, this terminates
 * the iteration and dp_table_foreach() returns the same value.  Returns 0 if
 * @callback never returns nonzero.
 *
 * This function does not try to intelligently handle the case where @callback
 * adds or removes flows in @table.
 */
int dp_table_foreach(struct dp_table *table,
		     int (*callback)(struct sw_flow *flow, void *aux),
		     void *aux)
{
	unsigned int i, j, k;
	for (i = 0; i < table->n_buckets >> DP_L1_BITS; i++) {
		struct dp_bucket **l2 = table->buckets[i];
		for (j = 0; j < DP_L1_SIZE; j++) {
			struct dp_bucket *bucket = rcu_dereference(l2[j]);
			if (!bucket)
				continue;

			for (k = 0; k < bucket->n_flows; k++) {
				int error = (*callback)(bucket->flows[k], aux);
				if (error)
					return error;
			}
		}
	}
	return 0;
}

static int insert_flow(struct sw_flow *flow, void *new_table_)
{
	struct dp_table *new_table = new_table_;
	return dp_table_insert(new_table, flow);
}

static void dp_free_table_rcu(struct rcu_head *rcu)
{
	struct dp_table *table = container_of(rcu, struct dp_table, rcu);
	dp_table_destroy(table, 0);
}

/**
 * dp_table_expand - replace datapath's flow table by one with more buckets
 * @dp: datapath to expand
 *
 * Replaces @dp's flow table by one that has twice as many buckets.  All of the
 * flows in @dp's flow table are moved to the new flow table.  Returns 0 if
 * successful, otherwise a negative error.
 */
int dp_table_expand(struct datapath *dp)
{
	struct dp_table *old_table = rcu_dereference(dp->table);
	struct dp_table *new_table;

	new_table = dp_table_create(old_table->n_buckets * 2);
	if (!new_table)
		goto error;

	if (dp_table_foreach(old_table, insert_flow, new_table))
		goto error_free_new_table;

	rcu_assign_pointer(dp->table, new_table);
	call_rcu(&old_table->rcu, dp_free_table_rcu);
	return 0;

error_free_new_table:
	dp_table_destroy(new_table, 0);
error:
	return -ENOMEM;
}

static void dp_free_table_and_flows_rcu(struct rcu_head *rcu)
{
	struct dp_table *table = container_of(rcu, struct dp_table, rcu);
	dp_table_destroy(table, 1);
}

/**
 * dp_table_flush - clear datapath's flow table
 * @dp: datapath to clear
 *
 * Replaces @dp's flow table by an empty flow table, destroying all the flows
 * in the old table (after a suitable RCU grace period).
 */
int dp_table_flush(struct datapath *dp)
{
	struct dp_table *old_table = rcu_dereference(dp->table);
	struct dp_table *new_table = dp_table_create(DP_L1_SIZE);
	if (!new_table)
		return -ENOMEM;
	rcu_assign_pointer(dp->table, new_table);
	call_rcu(&old_table->rcu, dp_free_table_and_flows_rcu);
	return 0;
}

static void dp_free_bucket_rcu(struct rcu_head *rcu)
{
	struct dp_bucket *bucket = container_of(rcu, struct dp_bucket, rcu);
	kfree(bucket);
}

/**
 * dp_table_insert - insert flow into table
 * @table: table in which to insert flow
 * @target: flow to insert
 *
 * The caller must ensure that no flow with key identical to @target->key
 * already exists in @table.  Returns 0 or a negative error (currently just
 * -ENOMEM).
 *
 * The caller is responsible for updating &struct datapath's n_flows member.
 */
int dp_table_insert(struct dp_table *table, struct sw_flow *target)
{
	u32 hash = flow_hash(table, &target->key);
	struct dp_bucket **oldp = find_bucket(table, hash);
	struct dp_bucket *old = *rcu_dereference(oldp);
	unsigned int n = old ? old->n_flows : 0;
	struct dp_bucket *new = dp_bucket_alloc(n + 1);

	if (!new)
		return -ENOMEM;

	new->n_flows = n + 1;
	if (old)
		memcpy(new->flows, old->flows, n * sizeof(struct sw_flow*));
	new->flows[n] = target;

	rcu_assign_pointer(*oldp, new);
	if (old)
		call_rcu(&old->rcu, dp_free_bucket_rcu);

	return 0;
}

/**
 * dp_table_delete - remove flow from table
 * @table: table from which to remove flow
 * @target: flow to remove
 *
 * The caller must ensure that @target itself is in @table.  (It is not
 * good enough for @table to contain a different flow with a key equal to
 * @target's key.)
 *
 * Returns 0 or a negative error (currently just -ENOMEM).  Yes, it *is*
 * possible for a flow deletion to fail due to lack of memory.
 *
 * The caller is responsible for updating &struct datapath's n_flows member.
 */
int dp_table_delete(struct dp_table *table, struct sw_flow *target)
{
	u32 hash = flow_hash(table, &target->key);
	struct dp_bucket **oldp = find_bucket(table, hash);
	struct dp_bucket *old = *rcu_dereference(oldp);
	unsigned int n = old->n_flows;
	struct dp_bucket *new;

	if (n > 1) {
		unsigned int i;

		new = dp_bucket_alloc(n - 1);
		if (!new)
			return -ENOMEM;

		new->n_flows = 0;
		for (i = 0; i < n; i++) {
			struct sw_flow *flow = old->flows[i];
			if (flow != target)
				new->flows[new->n_flows++] = flow;
		}
		WARN_ON_ONCE(new->n_flows != n - 1);
	} else {
		new = NULL;
	}

	rcu_assign_pointer(*oldp, new);
	call_rcu(&old->rcu, dp_free_bucket_rcu);

	return 0;
}
