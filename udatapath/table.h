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

/* Individual switching tables.  Generally grouped together in a chain (see
 * chain.h). */

#ifndef TABLE_H
#define TABLE_H 1

#include <stddef.h>
#include <stdint.h>
#include "datapath.h"

struct sw_flow;
struct sw_flow_key;
struct ofp_action_header;
struct list;

/* Table statistics. */
struct sw_table_stats {
    const char *name;            /* Human-readable name. */
    uint32_t wildcards;          /* Bitmap of OFPFW_* wildcards that are
                                    supported by the table. */
    unsigned int n_flows;        /* Number of active flows. */
    unsigned int max_flows;      /* Flow capacity. */
    unsigned long int n_lookup;  /* Number of packets looked up. */
    unsigned long int n_matched; /* Number of packets that have hit. */
};

/* Position within an iteration of a sw_table.
 *
 * The contents are private to the table implementation, except that a position
 * initialized to all-zero-bits represents the start of a table. */
struct sw_table_position {
    unsigned long private[4];
};

/* A single table of flows.  */
struct sw_table {
    /* The number of packets that have been looked up and matched,
     * respecitvely.  To make these 100% accurate, they should be atomic.  
     * However, we're primarily concerned about speed. */
    unsigned long long n_lookup;
    unsigned long long n_matched;

    /* Searches 'table' for a flow matching 'key', which must not have any
     * wildcard fields.  Returns the flow if successful, a null pointer
     * otherwise. */
    struct sw_flow *(*lookup)(struct sw_table *table,
                              const struct sw_flow_key *key);

    /* Inserts 'flow' into 'table', replacing any duplicate flow.  Returns
     * 0 if successful or a negative error.  Error can be due to an
     * over-capacity table or because the flow is not one of the kind that
     * the table accepts.
     *
     * If successful, 'flow' becomes owned by 'table', otherwise it is
     * retained by the caller. */
    int (*insert)(struct sw_table *table, struct sw_flow *flow);

    /* Modifies the actions in 'table' that match 'key'.  If 'strict'
     * set, wildcards and priority must match.  Returns the number of flows 
     * that were modified. */
    int (*modify)(struct sw_table *table, const struct sw_flow_key *key,
            uint16_t priority, int strict,
            const struct ofp_action_header *actions, size_t actions_len);

    /* Deletes from 'table' any and all flows that match 'key' from
     * 'table'.  If 'out_port' is not OFPP_NONE, then matching entries
     * must have that port as an argument for an output action.  If 
     * 'strict' is set, wildcards and priority must match.  Returns the
     * number of flows that were deleted. */
    int (*delete)(struct datapath *dp, struct sw_table *table, 
                  const struct sw_flow_key *key, 
                  uint16_t out_port, uint16_t priority, int strict);

    /* Performs timeout processing on all the flow entries in 'table'.
     * Appends all the flow entries removed from 'table' to 'deleted' for the
     * caller to free. */
    void (*timeout)(struct sw_table *table, struct list *deleted);

    /* Destroys 'table', which must not have any users. */
    void (*destroy)(struct sw_table *table);

    /* Iterates through the flow entries in 'table', passing each one
     * matches 'key' and output port 'out_port' to 'callback'.  The 
     * callback function should return 0 to continue iteration or a 
     * nonzero error code to stop.  The iterator function returns either 
     * 0 if the table iteration completed or the value returned by the 
     * callback function otherwise.
     *
     * The iteration starts at 'position', which may be initialized to
     * all-zero-bits to iterate from the beginning of the table.  If the
     * iteration terminates due to an error from the callback function,
     * 'position' is updated to a value that can be passed back to the
     * iterator function to resume iteration later with the following
     * flow. */
    int (*iterate)(struct sw_table *table,
               const struct sw_flow_key *key, uint16_t out_port,
               struct sw_table_position *position,
               int (*callback)(struct sw_flow *flow, void *private),
               void *private);

    /* Dumps statistics for 'table' into 'stats'. */
    void (*stats)(struct sw_table *table, struct sw_table_stats *stats);
};

struct sw_table *table_hash_create(unsigned int polynomial,
                                   unsigned int n_buckets);
struct sw_table *table_hash2_create(unsigned int poly0, unsigned int buckets0,
                                    unsigned int poly1, unsigned int buckets1);
struct sw_table *table_linear_create(unsigned int max_flows);

#endif /* table.h */
