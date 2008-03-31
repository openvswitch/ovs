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

#include "table.h"
#include <stdlib.h>
#include "flow.h"
#include "list.h"
#include "switch-flow.h"
#include "datapath.h"

struct sw_table_linear {
    struct sw_table swt;

    unsigned int max_flows;
    unsigned int n_flows;
    struct list flows;
};

static struct sw_flow *table_linear_lookup(struct sw_table *swt,
                                           const struct sw_flow_key *key)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;
    struct sw_flow *flow;
    LIST_FOR_EACH (flow, struct sw_flow, node, &tl->flows) {
        if (flow_matches(&flow->key, key))
            return flow;
    }
    return NULL;
}

static int table_linear_insert(struct sw_table *swt, struct sw_flow *flow)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;
    struct sw_flow *f;

    /* Replace flows that match exactly. */
    LIST_FOR_EACH (f, struct sw_flow, node, &tl->flows) {
        if (f->key.wildcards == flow->key.wildcards
            && flow_matches(&f->key, &flow->key)) {
            list_replace(&flow->node, &f->node);
            flow_free(f);
            return 1;
        }
    }

    /* Table overflow? */
    if (tl->n_flows >= tl->max_flows) {
        return 0;
    }
    tl->n_flows++;

    /* FIXME: need to order rules from most to least specific. */
    list_push_back(&tl->flows, &flow->node);
    return 1;
}

static void
do_delete(struct sw_flow *flow) 
{
    list_remove(&flow->node);
    flow_free(flow);
}

static int table_linear_delete(struct sw_table *swt,
                               const struct sw_flow_key *key, int strict)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;
    struct sw_flow *flow, *n;
    unsigned int count = 0;

    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &tl->flows) {
        if (flow_del_matches(&flow->key, key, strict)) {
            do_delete(flow);
            count++;
        }
    }
    tl->n_flows -= count;
    return count;
}

static void table_linear_timeout(struct sw_table *swt, struct list *deleted)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;
    struct sw_flow *flow, *n;

    LIST_FOR_EACH_SAFE (flow, n, struct sw_flow, node, &tl->flows) {
        if (flow_timeout(flow)) {
            list_remove(&flow->node);
            list_push_back(deleted, &flow->node);
            tl->n_flows--;
        }
    }
}

static void table_linear_destroy(struct sw_table *swt)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;

    while (!list_is_empty(&tl->flows)) {
        struct sw_flow *flow = CONTAINER_OF(list_front(&tl->flows),
                                            struct sw_flow, node);
        list_remove(&flow->node);
        flow_free(flow);
    }
    free(tl);
}

/* Linear table's private data is just a pointer to the table */

static int table_linear_iterator(struct sw_table *swt,
                                 struct swt_iterator *swt_iter) 
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;

    swt_iter->private = tl;

    if (!tl->n_flows)
        swt_iter->flow = NULL;
    else
        swt_iter->flow = CONTAINER_OF(list_front(&tl->flows), struct sw_flow, node);

    return 1;
}

static void table_linear_next(struct swt_iterator *swt_iter)
{
    struct sw_table_linear *tl;
    struct list *next;

    if (swt_iter->flow == NULL)
        return;

    tl = (struct sw_table_linear *) swt_iter->private;

    next = swt_iter->flow->node.next;
    if (next == &tl->flows)
        swt_iter->flow = NULL;
    else
        swt_iter->flow = CONTAINER_OF(next, struct sw_flow, node);
}

static void table_linear_iterator_destroy(struct swt_iterator *swt_iter)
{}

static void table_linear_stats(struct sw_table *swt,
                               struct sw_table_stats *stats)
{
    struct sw_table_linear *tl = (struct sw_table_linear *) swt;
    stats->name = "linear";
    stats->n_flows = tl->n_flows;
    stats->max_flows = tl->max_flows;
}


struct sw_table *table_linear_create(unsigned int max_flows)
{
    struct sw_table_linear *tl;
    struct sw_table *swt;

    tl = calloc(1, sizeof *tl);
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
    tl->n_flows = 0;
    list_init(&tl->flows);

    return swt;
}
