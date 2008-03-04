/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007 The Board of Trustees of The Leland Stanford Junior Univer
sity
 */

#include "table.h"
#include "flow.h"
#include "datapath.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/list.h>

struct sw_table_linear {
	struct sw_table swt;

	spinlock_t lock;
	unsigned int max_flows;
	atomic_t n_flows;
	struct list_head flows;
};

static struct sw_flow *table_linear_lookup(struct sw_table *swt,
					 const struct sw_flow_key *key)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;
	struct sw_flow *flow;
	list_for_each_entry_rcu (flow, &tl->flows, u.node) {
		if (flow_matches(&flow->key, key))
			return flow;
	}
	return NULL;
}

static int table_linear_insert(struct sw_table *swt, struct sw_flow *flow)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;
	unsigned long int flags;
	struct sw_flow *f;

	/* Replace flows that match exactly. */
	spin_lock_irqsave(&tl->lock, flags);
	list_for_each_entry_rcu (f, &tl->flows, u.node) {
		if (f->key.wildcards == flow->key.wildcards
				&& flow_matches(&f->key, &flow->key)
				&& flow_del(f)) {
			list_replace_rcu(&f->u.node, &flow->u.node);
			spin_unlock_irqrestore(&tl->lock, flags);
			flow_deferred_free(f);
			return 1;
		}
	}

	/* Table overflow? */
	if (atomic_read(&tl->n_flows) >= tl->max_flows) {
		spin_unlock_irqrestore(&tl->lock, flags);
		return 0;
	}
	atomic_inc(&tl->n_flows);

	/* FIXME: need to order rules from most to least specific. */
	list_add_rcu(&flow->u.node, &tl->flows);
	spin_unlock_irqrestore(&tl->lock, flags);
	return 1;
}

static int do_delete(struct sw_table *swt, struct sw_flow *flow) 
{
	if (flow_del(flow)) {
		list_del_rcu(&flow->u.node);
		flow_deferred_free(flow);
		return 1;
	}
	return 0;
}

static int table_linear_delete(struct sw_table *swt,
				const struct sw_flow_key *key, int strict)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;
	struct list_head *pos, *n;
	unsigned int count = 0;

	list_for_each_safe_rcu (pos, n, &tl->flows) {
		struct sw_flow *flow = list_entry(pos, struct sw_flow, u.node);
		if (flow_del_matches(&flow->key, key, strict))
			count += do_delete(swt, flow);
	}
	if (count)
		atomic_sub(count, &tl->n_flows);
	return count;
}

static int table_linear_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;
	struct list_head *pos, *n;
	int count = 0;

	list_for_each_safe_rcu (pos, n, &tl->flows) {
		struct sw_flow *flow = list_entry(pos, struct sw_flow, u.node);
		if (flow_timeout(flow)) {
			count += do_delete(swt, flow);
			if (dp->hello_flags & OFP_CHELLO_SEND_FLOW_EXP)
				dp_send_flow_expired(dp, flow);
		}
	}
	if (count)
		atomic_sub(count, &tl->n_flows);
	return count;
}

static void table_linear_destroy(struct sw_table *swt)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;

	while (!list_empty(&tl->flows)) {
		struct sw_flow *flow = list_entry(tl->flows.next,
						  struct sw_flow, u.node);
		list_del(&flow->u.node);
		flow_free(flow);
	}
	kfree(tl);
}

/* Linear table's private data is just a pointer to the table */

static int table_linear_iterator(struct sw_table *swt,
				 struct swt_iterator *swt_iter) 
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;

	swt_iter->private = tl;

	if (atomic_read(&tl->n_flows) == 0)
		swt_iter->flow = NULL;
	else
		swt_iter->flow = list_entry(tl->flows.next,
				struct sw_flow, u.node);

	return 1;
}

static void table_linear_next(struct swt_iterator *swt_iter)
{
	struct sw_table_linear *tl;
	struct list_head *next;

	if (swt_iter->flow == NULL)
		return;

	tl = (struct sw_table_linear *) swt_iter->private;

	next = swt_iter->flow->u.node.next;
	if (next == &tl->flows)
		swt_iter->flow = NULL;
	else
		swt_iter->flow = list_entry(next, struct sw_flow, u.node);
}

static void table_linear_iterator_destroy(struct swt_iterator *swt_iter)
{}

static void table_linear_stats(struct sw_table *swt,
				struct sw_table_stats *stats)
{
	struct sw_table_linear *tl = (struct sw_table_linear *) swt;
	stats->name = "linear";
	stats->n_flows = atomic_read(&tl->n_flows);
	stats->max_flows = tl->max_flows;
}


struct sw_table *table_linear_create(unsigned int max_flows)
{
	struct sw_table_linear *tl;
	struct sw_table *swt;

	tl = kzalloc(sizeof *tl, GFP_KERNEL);
	if (tl == NULL)
		return NULL;

	swt = &tl->swt;
	swt->lookup = table_linear_lookup;
	swt->insert = table_linear_insert;
	swt->delete = table_linear_delete;
	swt->timeout = table_linear_timeout;
	swt->destroy = table_linear_destroy;
	swt->stats = table_linear_stats;

		swt->iterator = table_linear_iterator;
	swt->iterator_next = table_linear_next;
	swt->iterator_destroy = table_linear_iterator_destroy;

	tl->max_flows = max_flows;
	atomic_set(&tl->n_flows, 0);
	INIT_LIST_HEAD(&tl->flows);
	spin_lock_init(&tl->lock);

	return swt;
}
