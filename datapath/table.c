/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include "flow.h"
#include "datapath.h"
#include "table.h"

#include <linux/genetlink.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

/**
 * struct tbl_bucket - single bucket within a hash table
 * @rcu: RCU callback structure
 * @n_objs: number of objects in @objs[] array
 * @objs: array of @n_objs pointers to table nodes contained inside objects
 *
 * The expected number of objects per bucket is 1, but this allows for an
 * arbitrary number of collisions.
 */
struct tbl_bucket {
	struct rcu_head rcu;
	unsigned int n_objs;
	struct tbl_node *objs[];
};

static struct tbl_bucket *get_bucket(struct tbl_bucket __rcu *bucket)
{
	return rcu_dereference_check(bucket, rcu_read_lock_held() ||
				     lockdep_genl_is_held());
}

static struct tbl_bucket *get_bucket_protected(struct tbl_bucket __rcu *bucket)
{
	return rcu_dereference_protected(bucket, lockdep_genl_is_held());
}

static inline int bucket_size(int n_objs)
{
	return sizeof(struct tbl_bucket) + sizeof(struct tbl_node *) * n_objs;
}

static struct tbl_bucket *bucket_alloc(int n_objs)
{
	return kmalloc(bucket_size(n_objs), GFP_KERNEL);
}

static void free_buckets(struct tbl_bucket __rcu ***l1,
			 unsigned int n_buckets,
			 void (*free_obj)(struct tbl_node *))
{
	unsigned int i;

	for (i = 0; i < n_buckets >> TBL_L1_SHIFT; i++) {
		struct tbl_bucket __rcu **l2 = l1[i];
		unsigned int j;

		for (j = 0; j < TBL_L2_SIZE; j++) {
			struct tbl_bucket *bucket = (struct tbl_bucket __force *)l2[j];
			if (!bucket)
				continue;

			if (free_obj) {
				unsigned int k;
				for (k = 0; k < bucket->n_objs; k++)
					free_obj(bucket->objs[k]);
			}
			kfree(bucket);
		}
		free_page((unsigned long)l2);
	}
	kfree(l1);
}

static struct tbl_bucket __rcu ***alloc_buckets(unsigned int n_buckets)
{
	struct tbl_bucket __rcu ***l1;
	unsigned int i;

	l1 = kmalloc((n_buckets >> TBL_L1_SHIFT) * sizeof(struct tbl_bucket **),
		     GFP_KERNEL);
	if (!l1)
		return NULL;
	for (i = 0; i < n_buckets >> TBL_L1_SHIFT; i++) {
		l1[i] = (struct tbl_bucket __rcu **)get_zeroed_page(GFP_KERNEL);
		if (!l1[i]) {
			free_buckets(l1, i << TBL_L1_SHIFT, NULL);
			return NULL;
		}
	}
	return l1;
}

/**
 * tbl_create - create and return a new hash table
 * @n_buckets: number of buckets in the new table
 *
 * Creates and returns a new hash table, or %NULL if memory cannot be
 * allocated.  @n_buckets must be a power of 2 in the range %TBL_MIN_BUCKETS to
 * %TBL_MAX_BUCKETS.
 */
struct tbl *tbl_create(unsigned int n_buckets)
{
	struct tbl *table;

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	table->n_buckets = n_buckets;
	table->buckets = alloc_buckets(n_buckets);
	if (!table->buckets)
		goto err_free_table;

	return table;

err_free_table:
	kfree(table);
err:
	return NULL;
}

/**
 * tbl_destroy - destroy hash table and optionally the objects it contains
 * @table: table to destroy
 * @destructor: function to be called on objects at destruction time
 *
 * If a destructor is null, then the buckets in @table are destroyed
 * but not the objects within those buckets.  This behavior is useful when a
 * table is being replaced by a larger or smaller one without destroying the
 * objects.
 *
 * If a destructor is not null, then it is called on the objects in @table
 * before destroying the buckets.
 */
void tbl_destroy(struct tbl *table, void (*destructor)(struct tbl_node *))
{
	if (!table)
		return;

	free_buckets(table->buckets, table->n_buckets, destructor);
	kfree(table);
}

static void destroy_table_rcu(struct rcu_head *rcu)
{
	struct tbl *table = container_of(rcu, struct tbl, rcu);
	tbl_destroy(table, table->obj_destructor);
}

/**
 * tbl_deferred_destroy - destroy table after a RCU grace period
 * @table: table to destroy
 * @destructor: function to be called on objects at destruction time
 *
 * Calls tbl_destroy() on @table after an RCU grace period. If @destructor is
 * not null it is called on every element before the table is destroyed. */
void tbl_deferred_destroy(struct tbl *table, void (*destructor)(struct tbl_node *))
{
	if (!table)
		return;

	table->obj_destructor = destructor;
	call_rcu(&table->rcu, destroy_table_rcu);
}

static struct tbl_bucket __rcu **find_bucket(struct tbl *table, u32 hash)
{
	unsigned int l1 = (hash & (table->n_buckets - 1)) >> TBL_L1_SHIFT;
	unsigned int l2 = hash & ((1 << TBL_L2_BITS) - 1);
	return &table->buckets[l1][l2];
}

static int search_bucket(const struct tbl_bucket *bucket, void *target, int len, u32 hash,
			 int (*cmp)(const struct tbl_node *, void *, int len))
{
	int i;

	for (i = 0; i < bucket->n_objs; i++) {
		struct tbl_node *obj = bucket->objs[i];
		if (obj->hash == hash && likely(cmp(obj, target, len)))
			return i;
	}

	return -1;
}

/**
 * tbl_lookup - searches hash table for a matching object
 * @table: hash table to search
 * @target: identifier for the object that is being searched for, will be
 * provided as an argument to @cmp when making comparisions
 * @len: length of @target in bytes, will be provided as an argument to @cmp
 * when making comparisons
 * @hash: hash of @target
 * @cmp: comparision function to match objects with the given hash, returns
 * nonzero if the objects match, zero otherwise
 *
 * Searches @table for an object identified by @target.  Returns the tbl_node
 * contained in the object if successful, otherwise %NULL.
 */
struct tbl_node *tbl_lookup(struct tbl *table, void *target, int len, u32 hash,
			    int (*cmp)(const struct tbl_node *, void *, int))
{
	struct tbl_bucket __rcu **bucketp = find_bucket(table, hash);
	struct tbl_bucket *bucket = get_bucket(*bucketp);
	int index;

	if (!bucket)
		return NULL;

	index = search_bucket(bucket, target, len, hash, cmp);
	if (index < 0)
		return NULL;

	return bucket->objs[index];
}

/**
 * tbl_foreach - iterate through hash table
 * @table: table to iterate
 * @callback: function to call for each entry
 * @aux: Extra data to pass to @callback
 *
 * Iterates through all of the objects in @table in hash order, passing each of
 * them in turn to @callback.  If @callback returns nonzero, this terminates
 * the iteration and tbl_foreach() returns the same value.  Returns 0 if
 * @callback never returns nonzero.
 *
 * This function does not try to intelligently handle the case where @callback
 * adds or removes flows in @table.
 */
int tbl_foreach(struct tbl *table,
		int (*callback)(struct tbl_node *, void *aux), void *aux)
{
	unsigned int n_l1 = table->n_buckets >> TBL_L1_SHIFT;
	unsigned int l1_idx;

	for (l1_idx = 0; l1_idx < n_l1; l1_idx++) {
		struct tbl_bucket __rcu **l2 = table->buckets[l1_idx];
		unsigned int l2_idx;

		for (l2_idx = 0; l2_idx < TBL_L2_SIZE; l2_idx++) {
			struct tbl_bucket *bucket;
			unsigned int i;

			bucket = get_bucket(l2[l2_idx]);
			if (!bucket)
				continue;

			for (i = 0; i < bucket->n_objs; i++) {
				int error = (*callback)(bucket->objs[i], aux);
				if (error)
					return error;
			}
		}
	}
	return 0;
}

/**
 * tbl_next - find next node in hash table
 * @table: table to iterate
 * @bucketp: On entry, hash value of bucket to start from.  On exit, updated
 * to bucket to start from on next call.
 * @objp: On entry, index to start from within first bucket.  On exit, updated
 * to index to start from on next call.
 *
 * Returns the next node in @table in hash order, or %NULL when no nodes remain
 * in the hash table.
 *
 * On entry, uses the values that @bucketp and @objp reference to determine
 * where to begin iteration.  Use 0 for both values to begin a new iteration.
 * On exit, stores the values to pass on the next iteration into @bucketp and
 * @objp's referents.
 */
struct tbl_node *tbl_next(struct tbl *table, u32 *bucketp, u32 *objp)
{
	unsigned int n_l1 = table->n_buckets >> TBL_L1_SHIFT;
	u32 s_l1_idx = *bucketp >> TBL_L1_SHIFT;
	u32 s_l2_idx = *bucketp & (TBL_L2_SIZE - 1);
	u32 s_obj = *objp;
	unsigned int l1_idx;

	for (l1_idx = s_l1_idx; l1_idx < n_l1; l1_idx++) {
		struct tbl_bucket __rcu **l2 = table->buckets[l1_idx];
		unsigned int l2_idx;

		for (l2_idx = s_l2_idx; l2_idx < TBL_L2_SIZE; l2_idx++) {
			struct tbl_bucket *bucket;

			bucket = get_bucket_protected(l2[l2_idx]);
			if (bucket && s_obj < bucket->n_objs) {
				*bucketp = (l1_idx << TBL_L1_SHIFT) + l2_idx;
				*objp = s_obj + 1;
				return bucket->objs[s_obj];
			}

			s_obj = 0;
		}
		s_l2_idx = 0;
	}
	*bucketp = 0;
	*objp = 0;
	return NULL;
}

static int insert_table_flow(struct tbl_node *node, void *new_table_)
{
	struct tbl *new_table = new_table_;
	return tbl_insert(new_table, node, node->hash);
}

/**
 * tbl_expand - create a hash table with more buckets
 * @table: table to expand
 *
 * Creates a new table containing the same objects as @table but with twice
 * as many buckets.  Returns 0 if successful, otherwise a negative error.  The
 * caller should free @table upon success (probably using
 * tbl_deferred_destroy()).
 */
struct tbl *tbl_expand(struct tbl *table)
{
	int err;
	int n_buckets = table->n_buckets * 2;
	struct tbl *new_table;

	if (n_buckets >= TBL_MAX_BUCKETS) {
		err = -ENOSPC;
		goto error;
	}

	err = -ENOMEM;
	new_table = tbl_create(n_buckets);
	if (!new_table)
		goto error;

	if (tbl_foreach(table, insert_table_flow, new_table))
		goto error_free_new_table;

	return new_table;

error_free_new_table:
	tbl_destroy(new_table, NULL);
error:
	return ERR_PTR(err);
}

/**
 * tbl_n_buckets - returns the number of buckets
 * @table: table to examine
 *
 * Returns the number of buckets currently allocated in @table, useful when
 * deciding whether to expand.
 */
int tbl_n_buckets(struct tbl *table)
{
	return table->n_buckets;
}

static void free_bucket_rcu(struct rcu_head *rcu)
{
	struct tbl_bucket *bucket = container_of(rcu, struct tbl_bucket, rcu);
	kfree(bucket);
}

/**
 * tbl_insert - insert object into table
 * @table: table in which to insert object
 * @target: tbl_node contained in object to insert
 * @hash: hash of object to insert
 *
 * The caller must ensure that no object considered to be identical to @target
 * already exists in @table.  Returns 0 or a negative error (currently just
 * -ENOMEM).
 */
int tbl_insert(struct tbl *table, struct tbl_node *target, u32 hash)
{
	struct tbl_bucket __rcu **oldp = find_bucket(table, hash);
	struct tbl_bucket *old = get_bucket_protected(*oldp);
	unsigned int n = old ? old->n_objs : 0;
	struct tbl_bucket *new = bucket_alloc(n + 1);

	if (!new)
		return -ENOMEM;

	target->hash = hash;

	new->n_objs = n + 1;
	if (old)
		memcpy(new->objs, old->objs, n * sizeof(struct tbl_node *));
	new->objs[n] = target;

	rcu_assign_pointer(*oldp, new);
	if (old)
		call_rcu(&old->rcu, free_bucket_rcu);

	table->count++;

	return 0;
}

/**
 * tbl_remove - remove object from table
 * @table: table from which to remove object
 * @target: tbl_node inside of object to remove
 *
 * The caller must ensure that @target itself is in @table.  (It is not
 * good enough for @table to contain a different object considered identical
 * @target.)
 *
 * Returns 0 or a negative error (currently just -ENOMEM).  Yes, it *is*
 * possible for object deletion to fail due to lack of memory.
 */
int tbl_remove(struct tbl *table, struct tbl_node *target)
{
	struct tbl_bucket __rcu **oldp = find_bucket(table, target->hash);
	struct tbl_bucket *old = get_bucket_protected(*oldp);
	unsigned int n = old->n_objs;
	struct tbl_bucket *new;

	if (n > 1) {
		unsigned int i;

		new = bucket_alloc(n - 1);
		if (!new)
			return -ENOMEM;

		new->n_objs = 0;
		for (i = 0; i < n; i++) {
			struct tbl_node *obj = old->objs[i];
			if (obj != target)
				new->objs[new->n_objs++] = obj;
		}
		WARN_ON_ONCE(new->n_objs != n - 1);
	} else {
		new = NULL;
	}

	rcu_assign_pointer(*oldp, new);
	call_rcu(&old->rcu, free_bucket_rcu);

	table->count--;

	return 0;
}

/**
 * tbl_count - retrieves the number of stored objects
 * @table: table to count
 *
 * Returns the number of objects that have been inserted into the hash table.
 */
unsigned int tbl_count(struct tbl *table)
{
	return table->count;
}
