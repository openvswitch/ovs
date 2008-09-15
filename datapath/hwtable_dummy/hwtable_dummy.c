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
#include <linux/rculist.h>
#include <linux/delay.h>
#include <linux/if_arp.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"


/* Max number of flow entries supported by the hardware */
#define DUMMY_MAX_FLOW   8192


/* sw_flow private data for dummy table entries.  */
struct sw_flow_dummy {
	struct list_head node;

	/* xxx If per-entry data is needed, define it here. */
};

struct sw_table_dummy {
	struct sw_table swt;

	unsigned int max_flows;
	unsigned int n_flows;
	struct list_head flows;
	struct list_head iter_flows;
	unsigned long int next_serial;
};


static struct sw_flow *table_dummy_lookup(struct sw_table *swt,
					  const struct sw_flow_key *key)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	list_for_each_entry (flow, &td->flows, node) {
		if (flow_matches_1wild(key, &flow->key)) {
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
	 * xxx shouldn't (and you should update n_flows in struct
	 * xxx sw_table_dummy, too).
	 */
	kfree(flow->private);
	return 0;
}

static int table_dummy_modify(struct sw_table *swt, 
		const struct sw_flow_key *key,
		const struct ofp_action *actions, int n_actions)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry (flow, &td->flows, node) {
		if (flow_matches_1wild(&flow->key, key)) {
			flow_replace_acts(flow, actions, n_actions);
			/* xxx Do whatever is necessary to modify the entry in hardware */
			count++;
		}
	}
	return count;
}


static int do_delete(struct sw_table *swt, struct sw_flow *flow)
{
	/* xxx Remove the entry from hardware.  If you need to do any other
	 * xxx clean-up associated with the entry, do it here.
	 */
	list_del_rcu(&flow->node);
	list_del_rcu(&flow->iter_node);
	flow_deferred_free(flow);
	return 1;
}

static int table_dummy_delete(struct sw_table *swt,
			      const struct sw_flow_key *key, uint16_t priority, int strict)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	unsigned int count = 0;

	list_for_each_entry (flow, &td->flows, node) {
		if (flow_del_matches(&flow->key, key, strict)
		    && (!strict || (flow->priority == priority)))
			count += do_delete(swt, flow);
	}
	td->n_flows -= count;
	return count;
}


static int table_dummy_timeout(struct datapath *dp, struct sw_table *swt)
{
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	int del_count = 0;
	uint64_t packet_count = 0;
	uint64_t byte_count = 0;
	int reason;

	mutex_lock(&dp_mutex);
	list_for_each_entry (flow, &td->flows, node) {
		/* xxx Retrieve the packet and byte counts associated with this
		 * entry xxx and store them in "packet_count" and "byte_count".
		 */

		if (packet_count != flow->packet_count) {
			flow->packet_count = packet_count;
			flow->byte_count = byte_count;
			flow->used = jiffies;
		}

		reason = flow_timeout(flow);
		if (reason >= 0) {
			if (dp->flags & OFPC_SEND_FLOW_EXP) {
				/* xxx Get byte count */
				flow->byte_count = 0;
				dp_send_flow_expired(dp, flow, reason);
			}
			del_count += do_delete(swt, flow);
		}
	}
	mutex_unlock(&dp_mutex);

	td->n_flows -= del_count;
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
	struct sw_table_dummy *td = (struct sw_table_dummy *) swt;
	struct sw_flow *flow;
	unsigned long start;

	start = ~position->private[0];
	list_for_each_entry (flow, &td->iter_flows, iter_node) {
		if (flow->serial <= start && flow_matches_2wild(key,
								&flow->key)) {
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
	stats->wildcards = OFPFW_ALL;      /* xxx Set this appropriately */
	stats->n_flows   = td->n_flows;
	stats->max_flows = td->max_flows;
	stats->n_matched = swt->n_matched;
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
	swt->modify = table_dummy_modify;
	swt->delete = table_dummy_delete;
	swt->timeout = table_dummy_timeout;
	swt->destroy = table_dummy_destroy;
	swt->iterate = table_dummy_iterate;
	swt->stats = table_dummy_stats;

	td->max_flows = DUMMY_MAX_FLOW;
	td->n_flows = 0;
	INIT_LIST_HEAD(&td->flows);
	INIT_LIST_HEAD(&td->iter_flows);
	td->next_serial = 0;

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
