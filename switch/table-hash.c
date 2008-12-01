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

#include <config.h>
#include "table.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "datapath.h"
#include "flow.h"
#include "switch-flow.h"

struct sw_table_hash {
    struct sw_table swt;
    struct crc32 crc32;
    unsigned int n_flows;
    unsigned int bucket_mask; /* Number of buckets minus 1. */
    struct sw_flow **buckets;
};

static struct sw_flow **find_bucket(struct sw_table *swt,
                                    const struct sw_flow_key *key)
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    unsigned int crc = crc32_calculate(&th->crc32, key, 
            offsetof(struct sw_flow_key, wildcards));
    return &th->buckets[crc & th->bucket_mask];
}

static struct sw_flow *table_hash_lookup(struct sw_table *swt,
                                         const struct sw_flow_key *key)
{
    struct sw_flow *flow = *find_bucket(swt, key);
    return flow && !flow_compare(&flow->key.flow, &key->flow) ? flow : NULL;
}

static int table_hash_insert(struct sw_table *swt, struct sw_flow *flow)
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    struct sw_flow **bucket;
    int retval;

    if (flow->key.wildcards != 0)
        return 0;

    bucket = find_bucket(swt, &flow->key);
    if (*bucket == NULL) {
        th->n_flows++;
        *bucket = flow;
        retval = 1;
    } else {
        struct sw_flow *old_flow = *bucket;
        if (!flow_compare(&old_flow->key.flow, &flow->key.flow)) {
            *bucket = flow;
            flow_free(old_flow);
            retval = 1;
        } else {
            retval = 0;
        }
    }
    return retval;
}

static int table_hash_modify(struct sw_table *swt, 
        const struct sw_flow_key *key, uint16_t priority, int strict,
        const struct ofp_action_header *actions, size_t actions_len) 
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    unsigned int count = 0;

    if (key->wildcards == 0) {
        struct sw_flow **bucket = find_bucket(swt, key);
        struct sw_flow *flow = *bucket;
        if (flow && flow_matches_desc(&flow->key, key, strict)
                && (!strict || (flow->priority == priority))) {
            flow_replace_acts(flow, actions, actions_len);
            count = 1;
        }
    } else {
        unsigned int i;

        for (i = 0; i <= th->bucket_mask; i++) {
            struct sw_flow **bucket = &th->buckets[i];
            struct sw_flow *flow = *bucket;
            if (flow && flow_matches_desc(&flow->key, key, strict)
                    && (!strict || (flow->priority == priority))) {
                flow_replace_acts(flow, actions, actions_len);
                count++;
            }
        }
    }
    return count;
}

/* Caller must update n_flows. */
static void
do_delete(struct sw_flow **bucket)
{
    flow_free(*bucket);
    *bucket = NULL;
}

/* Returns number of deleted flows.  We can igonre the priority
 * argument, since all exact-match entries are the same (highest)
 * priority. */
static int table_hash_delete(struct sw_table *swt,
                             const struct sw_flow_key *key, 
                             uint16_t out_port,
                             uint16_t priority, int strict)
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    unsigned int count = 0;

    if (key->wildcards == 0) {
        struct sw_flow **bucket = find_bucket(swt, key);
        struct sw_flow *flow = *bucket;
        if (flow && !flow_compare(&flow->key.flow, &key->flow)
                && flow_has_out_port(flow, out_port)) {
            do_delete(bucket);
            count = 1;
        }
    } else {
        unsigned int i;

        for (i = 0; i <= th->bucket_mask; i++) {
            struct sw_flow **bucket = &th->buckets[i];
            struct sw_flow *flow = *bucket;
            if (flow && flow_matches_desc(&flow->key, key, strict)
                    && flow_has_out_port(flow, out_port)) {
                do_delete(bucket);
                count++;
            }
        }
    }
    th->n_flows -= count;
    return count;
}

static void table_hash_timeout(struct sw_table *swt, struct list *deleted)
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    unsigned int i;

    for (i = 0; i <= th->bucket_mask; i++) {
        struct sw_flow **bucket = &th->buckets[i];
        struct sw_flow *flow = *bucket;
        if (flow && flow_timeout(flow)) {
            list_push_back(deleted, &flow->node);
            *bucket = NULL;
            th->n_flows--;
        }
    }
}

static void table_hash_destroy(struct sw_table *swt)
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    unsigned int i;
    for (i = 0; i <= th->bucket_mask; i++) {
        if (th->buckets[i]) {
            flow_free(th->buckets[i]); 
        }
    }
    free(th->buckets);
    free(th);
}

static int table_hash_iterate(struct sw_table *swt,
                              const struct sw_flow_key *key, uint16_t out_port,
                              struct sw_table_position *position,
                              int (*callback)(struct sw_flow *, void *private),
                              void *private) 
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;

    if (position->private[0] > th->bucket_mask)
        return 0;

    if (key->wildcards == 0) {
        struct sw_flow *flow = table_hash_lookup(swt, key);
        position->private[0] = -1;
        if (!flow || !flow_has_out_port(flow, out_port)) {
            return 0;
        }
        return callback(flow, private);
    } else {
        int i;

        for (i = position->private[0]; i <= th->bucket_mask; i++) {
            struct sw_flow *flow = th->buckets[i];
            if (flow && flow_matches_1wild(&flow->key, key)
                    && flow_has_out_port(flow, out_port)) {
                int error = callback(flow, private);
                if (error) {
                    position->private[0] = i + 1;
                    return error;
                }
            }
        }
        return 0;
    }
}

static void table_hash_stats(struct sw_table *swt,
                             struct sw_table_stats *stats) 
{
    struct sw_table_hash *th = (struct sw_table_hash *) swt;
    stats->name = "hash";
    stats->wildcards = 0;        /* No wildcards are supported. */
    stats->n_flows   = th->n_flows;
    stats->max_flows = th->bucket_mask + 1;
    stats->n_lookup  = swt->n_lookup;
    stats->n_matched = swt->n_matched;
}

struct sw_table *table_hash_create(unsigned int polynomial,
                                   unsigned int n_buckets)
{
    struct sw_table_hash *th;
    struct sw_table *swt;

    th = malloc(sizeof *th);
    if (th == NULL)
        return NULL;
    memset(th, '\0', sizeof *th);

    assert(!(n_buckets & (n_buckets - 1)));
    th->buckets = calloc(n_buckets, sizeof *th->buckets);
    if (th->buckets == NULL) {
        printf("failed to allocate %u buckets\n", n_buckets);
        free(th);
        return NULL;
    }
    th->n_flows = 0;
    th->bucket_mask = n_buckets - 1;

    swt = &th->swt;
    swt->lookup = table_hash_lookup;
    swt->insert = table_hash_insert;
    swt->modify = table_hash_modify;
    swt->delete = table_hash_delete;
    swt->timeout = table_hash_timeout;
    swt->destroy = table_hash_destroy;
    swt->iterate = table_hash_iterate;
    swt->stats = table_hash_stats;

    crc32_init(&th->crc32, polynomial);

    return swt;
}

/* Double-hashing table. */

struct sw_table_hash2 {
    struct sw_table swt;
    struct sw_table *subtable[2];
};

static struct sw_flow *table_hash2_lookup(struct sw_table *swt,
                                          const struct sw_flow_key *key)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    int i;
        
    for (i = 0; i < 2; i++) {
        struct sw_flow *flow = *find_bucket(t2->subtable[i], key);
        if (flow && !flow_compare(&flow->key.flow, &key->flow))
            return flow;
    }
    return NULL;
}

static int table_hash2_insert(struct sw_table *swt, struct sw_flow *flow)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;

    if (table_hash_insert(t2->subtable[0], flow))
        return 1;
    return table_hash_insert(t2->subtable[1], flow);
}

static int table_hash2_modify(struct sw_table *swt, 
        const struct sw_flow_key *key, uint16_t priority, int strict,
        const struct ofp_action_header *actions, size_t actions_len) 
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    return (table_hash_modify(t2->subtable[0], key, priority, strict,
                    actions, actions_len)
            + table_hash_modify(t2->subtable[1], key, priority, strict,
                    actions, actions_len));
}

static int table_hash2_delete(struct sw_table *swt,
                              const struct sw_flow_key *key, 
                              uint16_t out_port,
                              uint16_t priority, int strict)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    return (table_hash_delete(t2->subtable[0], key, out_port, priority, strict)
            + table_hash_delete(t2->subtable[1], key, out_port, priority, 
                strict));
}

static void table_hash2_timeout(struct sw_table *swt, struct list *deleted)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    table_hash_timeout(t2->subtable[0], deleted);
    table_hash_timeout(t2->subtable[1], deleted);
}

static void table_hash2_destroy(struct sw_table *swt)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    table_hash_destroy(t2->subtable[0]);
    table_hash_destroy(t2->subtable[1]);
    free(t2);
}

static int table_hash2_iterate(struct sw_table *swt,
                               const struct sw_flow_key *key, 
                               uint16_t out_port,
                               struct sw_table_position *position,
                               int (*callback)(struct sw_flow *, void *),
                               void *private)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    int i;

    for (i = position->private[1]; i < 2; i++) {
        int error = table_hash_iterate(t2->subtable[i], key, out_port, 
                                       position, callback, private);
        if (error) {
            return error;
        }
        position->private[0] = 0;
        position->private[1]++;
    }
    return 0;
}

static void table_hash2_stats(struct sw_table *swt,
                              struct sw_table_stats *stats)
{
    struct sw_table_hash2 *t2 = (struct sw_table_hash2 *) swt;
    struct sw_table_stats substats[2];
    int i;

    for (i = 0; i < 2; i++)
        table_hash_stats(t2->subtable[i], &substats[i]);
    stats->name = "hash2";
    stats->wildcards = 0;        /* No wildcards are supported. */
    stats->n_flows   = substats[0].n_flows + substats[1].n_flows;
    stats->max_flows = substats[0].max_flows + substats[1].max_flows;
    stats->n_lookup  = swt->n_lookup;
    stats->n_matched = swt->n_matched;
}

struct sw_table *table_hash2_create(unsigned int poly0, unsigned int buckets0,
                                    unsigned int poly1, unsigned int buckets1)

{
    struct sw_table_hash2 *t2;
    struct sw_table *swt;

    t2 = malloc(sizeof *t2);
    if (t2 == NULL)
        return NULL;
    memset(t2, '\0', sizeof *t2);

    t2->subtable[0] = table_hash_create(poly0, buckets0);
    if (t2->subtable[0] == NULL)
        goto out_free_t2;

    t2->subtable[1] = table_hash_create(poly1, buckets1);
    if (t2->subtable[1] == NULL)
        goto out_free_subtable0;

    swt = &t2->swt;
    swt->lookup = table_hash2_lookup;
    swt->insert = table_hash2_insert;
    swt->modify = table_hash2_modify;
    swt->delete = table_hash2_delete;
    swt->timeout = table_hash2_timeout;
    swt->destroy = table_hash2_destroy;
    swt->iterate = table_hash2_iterate;
    swt->stats = table_hash2_stats;

    return swt;

out_free_subtable0:
    table_hash_destroy(t2->subtable[0]);
out_free_t2:
    free(t2);
    return NULL;
}
