/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include "chain.h"
#include "flow.h"
#include "table.h"
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

static struct sw_table *(*create_hw_table_hook)(void);
static struct module *hw_table_owner;
static DEFINE_SPINLOCK(hook_lock);

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
		goto error;
	chain->dp = dp;
	chain->owner = try_module_get(hw_table_owner) ? hw_table_owner : NULL;
	if (chain->owner && create_hw_table_hook) {
		struct sw_table *hwtable = create_hw_table_hook();
		if (!hwtable || add_table(chain, hwtable))
			goto error;
	}

	if (add_table(chain, table_hash2_create(0x1EDC6F41, TABLE_HASH_MAX_FLOWS,
						0x741B8CD7, TABLE_HASH_MAX_FLOWS))
	    || add_table(chain, table_linear_create(TABLE_LINEAR_MAX_FLOWS)))
		goto error;
	return chain;

error:
	if (chain)
		chain_destroy(chain);
	return NULL;
}

/* Searches 'chain' for a flow matching 'key', which must not have any wildcard
 * fields.  Returns the flow if successful, otherwise a null pointer.
 *
 * Caller must hold rcu_read_lock or dp_mutex. */
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
 * Caller must hold dp_mutex. */
int chain_insert(struct sw_chain *chain, struct sw_flow *flow)
{
	int i;

	might_sleep();
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
 * Caller must hold dp_mutex. */
int chain_delete(struct sw_chain *chain, const struct sw_flow_key *key, 
		uint16_t priority, int strict)
{
	int count = 0;
	int i;

	might_sleep();
	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		count += t->delete(t, key, priority, strict);
	}

	return count;
}

/* Performs timeout processing on all the tables in 'chain'.  Returns the
 * number of flow entries deleted through expiration.
 *
 * Expensive as currently implemented, since it iterates through the entire
 * contents of each table.
 *
 * Caller must not hold dp_mutex, because individual tables take and release it
 * as necessary. */
int chain_timeout(struct sw_chain *chain)
{
	int count = 0;
	int i;

	might_sleep();
	for (i = 0; i < chain->n_tables; i++) {
		struct sw_table *t = chain->tables[i];
		count += t->timeout(chain->dp, t);
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
		if (t->destroy)
			t->destroy(t);
	}
	module_put(chain->owner);
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


int chain_set_hw_hook(struct sw_table *(*create_hw_table)(void),
		      struct module *owner)
{
	int retval = -EBUSY;

	spin_lock(&hook_lock);
	if (!create_hw_table_hook) {
		create_hw_table_hook = create_hw_table;
		hw_table_owner = owner;
		retval = 0;
	}
	spin_unlock(&hook_lock);

	return retval;
}
EXPORT_SYMBOL(chain_set_hw_hook);

void chain_clear_hw_hook(void)
{
	create_hw_table_hook = NULL;
	hw_table_owner = NULL;
}
EXPORT_SYMBOL(chain_clear_hw_hook);
