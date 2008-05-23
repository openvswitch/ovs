/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/if_arp.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"


/* Max number of flow entries supported by the hardware */
#define DUMMY_MAX_FLOW   8192


/* xxx Explain need for this separate list because of RCU */
static spinlock_t pending_free_lock;
static struct list_head pending_free_list;

/* sw_flow private data for dummy table entries.  */
struct sw_flow_dummy {
	struct list_head node;

	/* xxx If per-entry data is needed, define it here. */
};

struct sw_table_dummy {
	struct sw_table swt;

	spinlock_t lock;
	unsigned int max_flows;
	atomic_t n_flows;
	struct list_head flows;
	struct list_head iter_flows;
	unsigned long int next_serial;
};


static void table_dummy_sfw_destroy(struct sw_flow_dummy *sfw)
{
	/* xxx Remove the entry from hardware.  If you need to do any other
	 * xxx clean-up associated with the entry, do it here.
	 */

	kfree(sfw);
}

static void table_dummy_rcu_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	spin_lock(&pending_free_lock);
	if (flow->private) {
		struct sw_flow_dummy *sfw = flow->private;
		list_add(&sfw->node, &pending_free_list);
		flow->private = NULL;
	}
	spin_unlock(&pending_free_lock);
	flow_free(flow);
}

static void table_dummy_flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, table_dummy_rcu_callback);
}

static struct sw_flow *table_dummy_lookup(struct sw_table *swt,
					  const struct sw_flow_key *key)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	list_for_each_entry (flow, &td->flows, node) {
		if (flow_matches(&flow->key, key)) {
			return flow; 
		}
	}
	return NULL;
}

static int table_dummy_insert(struct sw_table *swt, struct sw_flow *flow)
{
	/* xxx Use a data cache? */
	flow->private = kzalloc(sizeof(struct sw_flow_dummy), GFP_ATOMIC);
	if (flow->private == NULL) 
		return 0;

	/* xxx Do whatever needs to be done to insert an entry in hardware. 
	 * xxx If the entry can't be inserted, return 0.  This stub code
	 * xxx doesn't do anything yet, so we're going to return 0...you
	 * xxx shouldn't.
	 */
	kfree(flow->private);
	return 0;
}


static int do_delete(struct sw_table *swt, struct sw_flow *flow)
{
	if (flow_del(flow)) {
		list_del_rcu(&flow->node);
		list_del_rcu(&flow->iter_node);
		table_dummy_flow_deferred_free(flow);
		return 1;
	}
	return 0;
}

static int table_dummy_delete(struct sw_table *swt,
			      const struct sw_flow_key *key, uint16_t priority, int strict)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry_rcu (flow, &td->flows, node) {
		if (flow_del_matches(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority)))
			count += do_delete(swt, flow);
	}
	if (count)
		atomic_sub(count, &td->n_flows);
	return count;
}


static int table_dummy_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	struct sw_flow_dummy *sfw, *n;
	int del_count = 0;
	uint64_t packet_count = 0;
	int i = 0;

	list_for_each_entry_rcu (flow, &td->flows, node) {
		/* xxx Retrieve the packet count associated with this entry
		 * xxx and store it in "packet_count".
		 */

		if ((packet_count > flow->packet_count)
                    && (flow->max_idle != OFP_FLOW_PERMANENT)) {
			flow->packet_count = packet_count;
			flow->timeout = jiffies + HZ * flow->max_idle;
		}

		if (flow_timeout(flow)) {
			if (dp->flags & OFPC_SEND_FLOW_EXP) {
				/* xxx Get byte count */
				flow->byte_count = 0;
				dp_send_flow_expired(dp, flow);
			}
			del_count += do_delete(swt, flow);
		}
		if ((i % 50) == 0) {
			msleep_interruptible(1);
		}
		i++;
	}

	/* Remove any entries queued for removal */
	spin_lock_bh(&pending_free_lock);
	list_for_each_entry_safe (sfw, n, &pending_free_list, node) {
		list_del(&sfw->node);
		table_dummy_sfw_destroy(sfw);
	}
	spin_unlock_bh(&pending_free_lock);

	if (del_count)
		atomic_sub(del_count, &td->n_flows);
	return del_count;
}


static void table_dummy_destroy(struct sw_table *swt)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *)swt;


	/* xxx This table is being destroyed, so free any data that you
	 * xxx don't want to leak.
	 */


	if (td) {
		while (!list_empty(&td->flows)) {
			struct sw_flow *flow = list_entry(td->flows.next,
							  struct sw_flow, node);
			list_del(&flow->node);
			flow_free(flow);
		}
		kfree(td);
	}
}

static int table_dummy_iterate(struct sw_table *swt,
			       const struct sw_flow_key *key,
			       struct sw_table_position *position,
			       int (*callback)(struct sw_flow *, void *),
			       void *private)
{
	struct sw_table_dummy *tl = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	unsigned long start;

	start = ~position->private[0];
	list_for_each_entry_rcu (flow, &tl->iter_flows, iter_node) {
		if (flow->serial <= start && flow_matches(key, &flow->key)) {
			int error = callback(flow, private);
			if (error) {
				position->private[0] = ~flow->serial;
				return error;
			}
		}
	}
	return 0;
}

static void table_dummy_stats(struct sw_table *swt,
			      struct sw_table_stats *stats)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	stats->name = "dummy";
	stats->n_flows = atomic_read(&td->n_flows);
	stats->max_flows = td->max_flows;
}


static struct sw_table *table_dummy_create(void)
{
	struct sw_table_dummy *td;
	struct sw_table *swt;

	td = kzalloc(sizeof *td, GFP_KERNEL);
	if (td == NULL)
		return NULL;

	swt = &td->swt;
	swt->lookup = table_dummy_lookup;
	swt->insert = table_dummy_insert;
	swt->delete = table_dummy_delete;
	swt->timeout = table_dummy_timeout;
	swt->destroy = table_dummy_destroy;
	swt->iterate = table_dummy_iterate;
	swt->stats = table_dummy_stats;

	td->max_flows = DUMMY_MAX_FLOW;
	atomic_set(&td->n_flows, 0);
	INIT_LIST_HEAD(&td->flows);
	INIT_LIST_HEAD(&td->iter_flows);
	spin_lock_init(&td->lock);
	tl->next_serial = 0

	INIT_LIST_HEAD(&pending_free_list);
	spin_lock_init(&pending_free_lock);

	return swt;
}

static int __init dummy_init(void)
{
	return chain_set_hw_hook(table_dummy_create, THIS_MODULE);
}
module_init(dummy_init);

static void dummy_cleanup(void) 
{
	chain_clear_hw_hook();
}
module_exit(dummy_cleanup);

MODULE_DESCRIPTION("Dummy hardware table driver");
MODULE_AUTHOR("Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("Stanford License");
