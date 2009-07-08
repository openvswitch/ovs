#include "flow.h"
#include "datapath.h"

#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

static void free_table(struct sw_flow ***flows, unsigned int n_buckets,
		       int free_flows)
{
	unsigned int i;

	for (i = 0; i < n_buckets >> DP_L1_BITS; i++) {
		struct sw_flow **l2 = flows[i];
		if (free_flows) {
			unsigned int j;
			for (j = 0; j < DP_L1_SIZE; j++) {
				if (l2[j])
					flow_free(l2[j]);
			}
		}
		free_page((unsigned long)l2);
	}
	kfree(flows);
}

static struct sw_flow ***alloc_table(unsigned int n_buckets)
{
	struct sw_flow ***flows;
	unsigned int i;

	flows = kmalloc((n_buckets >> DP_L1_BITS) * sizeof(struct sw_flow**),
			GFP_KERNEL);
	if (!flows)
		return NULL;
	for (i = 0; i < n_buckets >> DP_L1_BITS; i++) {
		flows[i] = (struct sw_flow **)get_zeroed_page(GFP_KERNEL);
		if (!flows[i]) {
			free_table(flows, i << DP_L1_BITS, 0);
			return NULL;
		}
	}
	return flows;
}

struct dp_table *dp_table_create(unsigned int n_buckets)
{
	struct dp_table *table;

	table = kzalloc(sizeof *table, GFP_KERNEL);
	if (!table)
		goto err;

	table->n_buckets = n_buckets;
	table->flows[0] = alloc_table(n_buckets);
	if (!table[0].flows)
		goto err_free_tables;

	table->flows[1] = alloc_table(n_buckets);
	if (!table->flows[1])
		goto err_free_flows0;

	return table;

err_free_flows0:
	free_table(table->flows[0], table->n_buckets, 0);
err_free_tables:
	kfree(table);
err:
	return NULL;
}

void dp_table_destroy(struct dp_table *table, int free_flows)
{
	int i;
	for (i = 0; i < 2; i++)
		free_table(table->flows[i], table->n_buckets, free_flows);
	kfree(table);
}

static struct sw_flow **find_bucket(struct dp_table *table,
				    struct sw_flow ***flows, u32 hash)
{
	unsigned int l1 = (hash & (table->n_buckets - 1)) >> DP_L1_SHIFT;
	unsigned int l2 = hash & ((1 << DP_L2_BITS) - 1);
	return &flows[l1][l2];
}

static struct sw_flow *lookup_table(struct dp_table *table,
				    struct sw_flow ***flows, u32 hash,
				    const struct odp_flow_key *key)
{
	struct sw_flow **bucket = find_bucket(table, flows, hash);
	struct sw_flow *flow = rcu_dereference(*bucket);
	if (flow && !memcmp(&flow->key, key, sizeof(struct odp_flow_key)))
		return flow;
	return NULL;
}

static u32 flow_hash0(const struct odp_flow_key *key)
{
	return jhash2((u32*)key, sizeof *key / sizeof(u32), 0xaaaaaaaa);
}

static u32 flow_hash1(const struct odp_flow_key *key)
{
	return jhash2((u32*)key, sizeof *key / sizeof(u32), 0x55555555);
}

static void find_buckets(struct dp_table *table,
			 const struct odp_flow_key *key,
			 struct sw_flow **buckets[2])
{
	buckets[0] = find_bucket(table, table->flows[0], flow_hash0(key));
	buckets[1] = find_bucket(table, table->flows[1], flow_hash1(key));
}

struct sw_flow *dp_table_lookup(struct dp_table *table,
				const struct odp_flow_key *key)
{
	struct sw_flow *flow;
	flow = lookup_table(table, table->flows[0], flow_hash0(key), key);
	if (!flow)
		flow = lookup_table(table, table->flows[1],
				    flow_hash1(key), key);
	return flow;
}

int dp_table_foreach(struct dp_table *table,
		     int (*callback)(struct sw_flow *flow, void *aux),
		     void *aux)
{
	unsigned int i, j, k;
	for (i = 0; i < 2; i++) {
		for (j = 0; j < table->n_buckets >> DP_L1_BITS; j++) {
			struct sw_flow **l2 = table->flows[i][j];
			for (k = 0; k < DP_L1_SIZE; k++) {
				struct sw_flow *flow = rcu_dereference(l2[k]);
				if (flow) {
					int error = callback(flow, aux);
					if (error)
						return error;
				}
			}
		}
	}
	return 0;
}

static int insert_flow(struct sw_flow *flow, void *new_table_)
{
	struct dp_table *new_table = new_table_;
	struct sw_flow **buckets[2];
	int i;

	find_buckets(new_table, &flow->key, buckets);
	for (i = 0; i < 2; i++) {
		if (!*buckets[i]) {
			rcu_assign_pointer(*buckets[i], flow);
			return 0;
		}
	}
	WARN_ON_ONCE(1);
	return 0;
}

static void dp_free_table_rcu(struct rcu_head *rcu)
{
	struct dp_table *table = container_of(rcu, struct dp_table, rcu);
	dp_table_destroy(table, 0);
}

int dp_table_expand(struct datapath *dp)
{
	struct dp_table *old_table = rcu_dereference(dp->table);
	struct dp_table *new_table = dp_table_create(old_table->n_buckets * 2);
	if (!new_table)
		return -ENOMEM;
	dp_table_foreach(old_table, insert_flow, new_table);
	rcu_assign_pointer(dp->table, new_table);
	call_rcu(&old_table->rcu, dp_free_table_rcu);
	return 0;
}

static void dp_free_table_and_flows_rcu(struct rcu_head *rcu)
{
	struct dp_table *table = container_of(rcu, struct dp_table, rcu);
	dp_table_destroy(table, 1);
}

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

struct sw_flow **
dp_table_lookup_for_insert(struct dp_table *table,
			   const struct odp_flow_key *target)
{
	struct sw_flow **buckets[2];
	struct sw_flow **empty_bucket = NULL;
	int i;

	find_buckets(table, target, buckets);
	for (i = 0; i < 2; i++) {
		struct sw_flow *f = rcu_dereference(*buckets[i]);
		if (f) {
			if (!memcmp(&f->key, target, sizeof(struct odp_flow_key)))
				return buckets[i];
		} else if (!empty_bucket)
			empty_bucket = buckets[i];
	}
	return empty_bucket;
}

int dp_table_delete(struct dp_table *table, struct sw_flow *target)
{
	struct sw_flow **buckets[2];
	int i;

	find_buckets(table, &target->key, buckets);
	for (i = 0; i < 2; i++) {
		struct sw_flow *flow = rcu_dereference(*buckets[i]);
		if (flow == target) {
			rcu_assign_pointer(*buckets[i], NULL);
			return 0;
		}
	}
	return -ENOENT;
}
