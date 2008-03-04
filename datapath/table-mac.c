/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007 The Board of Trustees of The Leland Stanford Junior Univer
sity
 */

#include "table.h"
#include "crc32.h"
#include "flow.h"
#include "openflow.h"
#include "datapath.h"

#include <linux/slab.h>

struct sw_table_mac {
	struct sw_table swt;
	spinlock_t lock;
	struct crc32 crc32;
	atomic_t n_flows;
	unsigned int max_flows;
	unsigned int bucket_mask; /* Number of buckets minus 1. */
	struct hlist_head *buckets;
};

static struct hlist_head *find_bucket(struct sw_table *swt,
									 const struct sw_flow_key *key)
{
	struct sw_table_mac *tm = (struct sw_table_mac *) swt;
	unsigned int crc = crc32_calculate(&tm->crc32, key, sizeof *key);
	return &tm->buckets[crc & tm->bucket_mask];
}

static struct sw_flow *table_mac_lookup(struct sw_table *swt,
										const struct sw_flow_key *key)
{
	struct hlist_head *bucket = find_bucket(swt, key);
	struct hlist_node *pos;
	struct sw_flow *flow;
	hlist_for_each_entry_rcu (flow, pos, bucket, u.hnode)
		if (!memcmp(key->dl_src, flow->key.dl_src, 6))
			return flow;
	return NULL;
}

static int table_mac_insert(struct sw_table *swt, struct sw_flow *flow)
{
	struct sw_table_mac *tm = (struct sw_table_mac *) swt;
	struct hlist_head *bucket;
	struct hlist_node *pos;
	unsigned long int flags;
	struct sw_flow *f;

	/* MAC table only handles flows that match on Ethernet
	   source address and wildcard everything else. */
	if (likely(flow->key.wildcards != (OFPFW_ALL & ~OFPFW_DL_SRC)))
			return 0;
	bucket = find_bucket(swt, &flow->key);

	spin_lock_irqsave(&tm->lock, flags);
	hlist_for_each_entry_rcu (f, pos, bucket, u.hnode) {
		if (!memcmp(f->key.dl_src, flow->key.dl_src, 6)
					&& flow_del(f)) {
			hlist_replace_rcu(&f->u.hnode, &flow->u.hnode);
			spin_unlock_irqrestore(&tm->lock, flags);
			flow_deferred_free(f);
			return 1;
		}
	}

	/* Table overflow? */
	if (atomic_read(&tm->n_flows) >= tm->max_flows) {
		spin_unlock_irqrestore(&tm->lock, flags);
		return 0; 
	}
	atomic_inc(&tm->n_flows);

	hlist_add_head_rcu(&flow->u.hnode, bucket);
	spin_unlock_irqrestore(&tm->lock, flags);
	return 1;
}

static int do_delete(struct sw_table *swt, struct sw_flow *flow)
{
	if (flow_del(flow)) {
		hlist_del_rcu(&flow->u.hnode);
		flow_deferred_free(flow);
		return 1;
	}
	return 0;
}

/* Returns number of deleted flows. */
static int table_mac_delete(struct sw_table *swt,
			const struct sw_flow_key *key, int strict)
{
		struct sw_table_mac *tm = (struct sw_table_mac *) swt;

	if (key->wildcards == (OFPFW_ALL & ~OFPFW_DL_SRC)) {
		struct sw_flow *flow = table_mac_lookup(swt, key);
		if (flow && do_delete(swt, flow)) {
			atomic_dec(&tm->n_flows);
			return 1;
		}
		return 0;
	} else {
		unsigned int i;
		int count = 0;
		for (i = 0; i <= tm->bucket_mask; i++) {
			struct hlist_head *bucket = &tm->buckets[i];
			struct hlist_node *pos;
			struct sw_flow *flow;
			hlist_for_each_entry_rcu (flow, pos, bucket, u.hnode)
				if (flow_del_matches(&flow->key, key, strict))
					count += do_delete(swt, flow);
		}
		if (count)
			atomic_sub(count, &tm->n_flows);
		return count;
	}
}

static int table_mac_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_mac *tm = (struct sw_table_mac *) swt;
	unsigned int i;
	int count = 0;

	for (i = 0; i <= tm->bucket_mask; i++) {
		struct hlist_head *bucket = &tm->buckets[i];
		struct hlist_node *pos;
		struct sw_flow *flow;
		hlist_for_each_entry_rcu (flow, pos, bucket, u.hnode) {
			if (flow_timeout(flow)) {
				count += do_delete(swt, flow);
				if (dp->hello_flags & OFP_CHELLO_SEND_FLOW_EXP)
					dp_send_flow_expired(dp, flow);
			}
		}
	}
	if (count)
		atomic_sub(count, &tm->n_flows);
	return count;
}

static void table_mac_destroy(struct sw_table *swt)
{
	struct sw_table_mac *tm = (struct sw_table_mac *) swt;
	unsigned int i;
	for (i = 0; i <= tm->bucket_mask; i++) {
		struct hlist_head *hlist = &tm->buckets[i];
		while (!hlist_empty(hlist)) {
			struct sw_flow *flow = hlist_entry(hlist->first,
					   struct sw_flow, u.hnode);
			hlist_del(&flow->u.hnode);
			flow_free(flow);
			}
	}
	kfree(tm->buckets);
	kfree(tm);
}

struct swt_iterator_mac {
	struct sw_table_mac *tm;
	unsigned int bucket_i;
};

static struct sw_flow *next_head_flow(struct swt_iterator_mac *im)
{
	for (; im->bucket_i <= im->tm->bucket_mask; im->bucket_i++) {
		struct hlist_node *first = im->tm->buckets[im->bucket_i].first;
		if (first != NULL) {
			struct sw_flow *f = hlist_entry(first,
							struct sw_flow,
							u.hnode);
			return f;
		}
	}
	return NULL;
}

static int table_mac_iterator(struct sw_table *swt,
				  struct swt_iterator *swt_iter)
{
	struct swt_iterator_mac *im;

	swt_iter->private = im = kmalloc(sizeof *im, GFP_KERNEL);
	if (im == NULL)
		return 0;

	im->tm = (struct sw_table_mac *) swt;

	if (atomic_read(&im->tm->n_flows) == 0)
		swt_iter->flow = NULL;
	else {
		im->bucket_i = 0;
		swt_iter->flow = next_head_flow(im);
	}

	return 1;
}

static void table_mac_next(struct swt_iterator *swt_iter)
{
	struct swt_iterator_mac *im;
	struct hlist_node *next;

	if (swt_iter->flow == NULL)
		return;

	im = (struct swt_iterator_mac *) swt_iter->private;

	next = swt_iter->flow->u.hnode.next;
	if (next != NULL) {
		swt_iter->flow = hlist_entry(next, struct sw_flow, u.hnode);
	} else {
		im->bucket_i++;
		swt_iter->flow = next_head_flow(im);
	}
}

static void table_mac_iterator_destroy(struct swt_iterator *swt_iter)
{
	kfree(swt_iter->private);
}

static void table_mac_stats(struct sw_table *swt, struct sw_table_stats *stats)
{
	struct sw_table_mac *tm = (struct sw_table_mac *) swt;
	stats->name = "mac";
	stats->n_flows = atomic_read(&tm->n_flows);
	stats->max_flows = tm->max_flows;
}

struct sw_table *table_mac_create(unsigned int n_buckets,
								  unsigned int max_flows)
{
	struct sw_table_mac *tm;
	struct sw_table *swt;

	tm = kzalloc(sizeof *tm, GFP_KERNEL);
	if (tm == NULL)
		return NULL;

	BUG_ON(n_buckets & (n_buckets - 1));

	tm->buckets = kzalloc(n_buckets * sizeof *tm->buckets, GFP_KERNEL);
	if (tm->buckets == NULL) {
		printk("failed to allocate %u buckets\n", n_buckets);
		kfree(tm);
		return NULL;
	}
	tm->bucket_mask = n_buckets - 1;

	swt = &tm->swt;
	swt->lookup = table_mac_lookup;
	swt->insert = table_mac_insert;
	swt->delete = table_mac_delete;
	swt->timeout = table_mac_timeout;
	swt->destroy = table_mac_destroy;
	swt->stats = table_mac_stats;

	swt->iterator = table_mac_iterator;
	swt->iterator_next = table_mac_next;
	swt->iterator_destroy = table_mac_iterator_destroy;

	crc32_init(&tm->crc32, 0x04C11DB7); /* Ethernet CRC. */
	atomic_set(&tm->n_flows, 0);
	tm->max_flows = max_flows;
	spin_lock_init(&tm->lock);

	return swt;
}
