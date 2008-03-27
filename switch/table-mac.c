/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "table.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "switch-flow.h"
#include "openflow.h"
#include "datapath.h"

struct sw_table_mac {
    struct sw_table swt;
    struct crc32 crc32;
    unsigned int n_flows;
    unsigned int max_flows;
    unsigned int bucket_mask; /* Number of buckets minus 1. */
    struct list *buckets;
};

static struct list *find_bucket(struct sw_table *swt,
                                const struct sw_flow_key *key)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;
    unsigned int crc = crc32_calculate(&tm->crc32, key, sizeof *key);
    return &tm->buckets[crc & tm->bucket_mask];
}

static struct sw_flow *table_mac_lookup(struct sw_table *swt,
                                        const struct sw_flow_key *key)
{
    struct list *bucket = find_bucket(swt, key);
    struct sw_flow *flow;
    LIST_FOR_EACH (flow, struct sw_flow, node, bucket) {
        if (!memcmp(key->flow.dl_src, flow->key.flow.dl_src, 6)) {
            return flow; 
        }
    }
    return NULL;
}

static int table_mac_insert(struct sw_table *swt, struct sw_flow *flow)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;
    struct list *bucket;
    struct sw_flow *f;

    /* MAC table only handles flows that match on Ethernet
       source address and wildcard everything else. */
    if (flow->key.wildcards != (OFPFW_ALL & ~OFPFW_DL_SRC))
        return 0;
    bucket = find_bucket(swt, &flow->key);

    LIST_FOR_EACH (f, struct sw_flow, node, bucket) {
        if (!memcmp(f->key.flow.dl_src, flow->key.flow.dl_src, 6)) {
            list_replace(&flow->node, &f->node);
            flow_free(f);
            return 1;
        }
    }

    /* Table overflow? */
    if (tm->n_flows >= tm->max_flows) {
        return 0; 
    }
    tm->n_flows++;

    list_push_front(bucket, &flow->node);
    return 1;
}

static void
do_delete(struct sw_flow *flow)
{
    list_remove(&flow->node);
    flow_free(flow);
}

/* Returns number of deleted flows. */
static int table_mac_delete(struct sw_table *swt,
                            const struct sw_flow_key *key, int strict)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;

    if (key->wildcards == (OFPFW_ALL & ~OFPFW_DL_SRC)) {
        struct sw_flow *flow = table_mac_lookup(swt, key);
        if (flow) {
            do_delete(flow);
            tm->n_flows--;
            return 1;
        }
        return 0;
    } else {
        unsigned int i;
        int count = 0;
        for (i = 0; i <= tm->bucket_mask; i++) {
            struct list *bucket = &tm->buckets[i];
            struct sw_flow *flow;
            LIST_FOR_EACH (flow, struct sw_flow, node, bucket) {
                if (flow_del_matches(&flow->key, key, strict)) {
                    do_delete(flow);
                    count++;
                }
            }
        }
        tm->n_flows -= count;
        return count;
    }
}

static int table_mac_timeout(struct datapath *dp, struct sw_table *swt)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;
    unsigned int i;
    int count = 0;

    for (i = 0; i <= tm->bucket_mask; i++) {
        struct list *bucket = &tm->buckets[i];
        struct sw_flow *flow;
        LIST_FOR_EACH (flow, struct sw_flow, node, bucket) {
            if (flow_timeout(flow)) {
                dp_send_flow_expired(dp, flow);
                do_delete(flow);
                count++;
            }
        }
    }
    tm->n_flows -= count;
    return count;
}

static void table_mac_destroy(struct sw_table *swt)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;
    unsigned int i;
    for (i = 0; i <= tm->bucket_mask; i++) {
        struct list *list = &tm->buckets[i];
        while (!list_is_empty(list)) {
            struct sw_flow *flow = CONTAINER_OF(list_front(list),
                                                struct sw_flow, node);
            list_remove(&flow->node);
            flow_free(flow);
        }
    }
    free(tm->buckets);
    free(tm);
}

struct swt_iterator_mac {
    struct sw_table_mac *tm;
    unsigned int bucket_i;
};

static struct sw_flow *next_head_flow(struct swt_iterator_mac *im)
{
    for (; im->bucket_i <= im->tm->bucket_mask; im->bucket_i++) {
        struct list *bucket = &im->tm->buckets[im->bucket_i];
        if (!list_is_empty(bucket)) {
            return CONTAINER_OF(bucket, struct sw_flow, node);
        }
    }
    return NULL;
}

static int table_mac_iterator(struct sw_table *swt,
                              struct swt_iterator *swt_iter)
{
    struct swt_iterator_mac *im;

    swt_iter->private = im = malloc(sizeof *im);
    if (im == NULL)
        return 0;

    im->tm = (struct sw_table_mac *) swt;

    if (!im->tm->n_flows)
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
    struct list *next;

    if (swt_iter->flow == NULL)
        return;

    im = (struct swt_iterator_mac *) swt_iter->private;

    next = swt_iter->flow->node.next;
    if (next != NULL) {
        swt_iter->flow = CONTAINER_OF(next, struct sw_flow, node);
    } else {
        im->bucket_i++;
        swt_iter->flow = next_head_flow(im);
    }
}

static void table_mac_iterator_destroy(struct swt_iterator *swt_iter)
{
    free(swt_iter->private);
}

static void table_mac_stats(struct sw_table *swt, struct sw_table_stats *stats)
{
    struct sw_table_mac *tm = (struct sw_table_mac *) swt;
    stats->name = "mac";
    stats->n_flows = tm->n_flows;
    stats->max_flows = tm->max_flows;
}

struct sw_table *table_mac_create(unsigned int n_buckets,
                                  unsigned int max_flows)
{
    struct sw_table_mac *tm;
    struct sw_table *swt;
    unsigned int i;

    tm = calloc(1, sizeof *tm);
    if (tm == NULL)
        return NULL;

    assert(!(n_buckets & (n_buckets - 1)));

    tm->buckets = malloc(n_buckets * sizeof *tm->buckets);
    if (tm->buckets == NULL) {
        printf("failed to allocate %u buckets\n", n_buckets);
        free(tm);
        return NULL;
    }
    for (i = 0; i < n_buckets; i++) {
        list_init(&tm->buckets[i]);
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
    tm->n_flows = 0;
    tm->max_flows = max_flows;

    return swt;
}
