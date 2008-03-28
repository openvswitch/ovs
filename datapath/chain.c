/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include "chain.h"
#include "flow.h"
#include "table.h"
#include <linux/rcupdate.h>
#include <linux/slab.h>

/* Attempts to append 'table' to the set of tables in 'chain'.  Returns 0 or
 * negative error.  If 'table' is null it is assumed that table creation failed
 * due to out-of-memory. */
static int add_table(struct sw_chain *chain, struct sw_table *table)
{
	if (table == NULL)
		return -ENOMEM;
	if (chain->n_tables >= CHAIN_MAX_TABLES) {
		printk("too many tables in chain\n");
		table->destroy(table);
		return -ENOBUFS;
	}
	chain->tables[chain->n_tables++] = table;
	return 0;
}

/* Creates and returns a new chain associated with 'dp'.  Returns NULL if the
 * chain cannot be created. */
struct sw_chain *chain_create(struct datapath *dp)
{
	struct sw_chain *chain = kzalloc(sizeof *chain, GFP_KERNEL);
	if (chain == NULL)
		return NULL;
	chain->dp = dp;

	if (add_table(chain, table_mac_create(TABLE_MAC_NUM_BUCKETS, 
						TABLE_MAC_MAX_FLOWS))
		|| add_table(chain, table_hash2_create(0x1EDC6F41, TABLE_HASH_MAX_FLOWS,
						0x741B8CD7, TABLE_HASH_MAX_FLOWS))
		|| add_table(chain, table_linear_create(TABLE_LINEAR_MAX_FLOWS))) {
		chain_destroy(chain);
		return NULL;
	}

	return chain;
}

/* Searches 'chain' for a flow matching 'key', which must not have any wildcard
 * fields.  Returns the flow if successful, otherwise a null pointer.
 *
 * Caller must hold rcu_read_lock, and not release it until it is done with the
 * returned flow. */
struct sw_flow *chain_lookup(struct sw_chain *chain,
			 const struct sw_flow_key *key)
{
	int i;

	BUG_ON(key->wildcards);
	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		struct sw_flow *flow = t->lookup(t, key);
		if (flow)
			return flow;
	}
	return NULL;
}

/* Inserts 'flow' into 'chain', replacing any duplicate flow.  Returns 0 if
 * successful or a negative error.
 *
 * If successful, 'flow' becomes owned by the chain, otherwise it is retained
 * by the caller.
 *
 * Caller must hold rcu_read_lock.  If insertion is successful, it must not
 * release rcu_read_lock until it is done with the inserted flow. */
int chain_insert(struct sw_chain *chain, struct sw_flow *flow)
{
	int i;

	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		if (t->insert(t, flow))
			return 0;
	}

	return -ENOBUFS;
}

/* Deletes from 'chain' any and all flows that match 'key'.  Returns the number
 * of flows that were deleted.
 *
 * Expensive in the general case as currently implemented, since it requires
 * iterating through the entire contents of each table for keys that contain
 * wildcards.  Relatively cheap for fully specified keys.
 *
 * The caller need not hold any locks. */
int chain_delete(struct sw_chain *chain, const struct sw_flow_key *key, int strict)
{
	int count = 0;
	int i;

	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		rcu_read_lock();
		count += t->delete(t, key, strict);
		rcu_read_unlock();
	}

	return count;

}

/* Performs timeout processing on all the tables in 'chain'.  Returns the
 * number of flow entries deleted through expiration.
 *
 * Expensive as currently implemented, since it iterates through the entire
 * contents of each table.
 *
 * The caller need not hold any locks. */
int chain_timeout(struct sw_chain *chain)
{
	int count = 0;
	int i;

	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		rcu_read_lock();
		count += t->timeout(chain->dp, t);
		rcu_read_unlock();
	}
	return count;
}

/* Destroys 'chain', which must not have any users. */
void chain_destroy(struct sw_chain *chain)
{
	int i;

	synchronize_rcu();
	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		t->destroy(t);
	}
	kfree(chain);
}

/* Prints statistics for each of the tables in 'chain'. */
void chain_print_stats(struct sw_chain *chain)
{
	int i;

	printk("\n");
	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		struct sw_table_stats stats;
		t->stats(t, &stats);
		printk("%s: %lu/%lu flows\n",
					stats.name, stats.n_flows, stats.max_flows);
	}
}
