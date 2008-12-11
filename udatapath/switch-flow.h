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

#ifndef SWITCH_FLOW_H
#define SWITCH_FLOW_H 1

#include <time.h>
#include "openflow/openflow.h"
#include "flow.h"
#include "list.h"

struct ofp_match;

/* Identification data for a flow. */
struct sw_flow_key {
    struct flow flow;           /* Flow data (in network byte order). */
    uint32_t wildcards;         /* Wildcard fields (in host byte order). */
    uint32_t nw_src_mask;       /* 1-bit in each significant nw_src bit. */
    uint32_t nw_dst_mask;       /* 1-bit in each significant nw_dst bit. */
};

struct sw_flow_actions {
    size_t actions_len;
    struct ofp_action_header actions[0];
};

struct sw_flow {
    struct sw_flow_key key;

    uint16_t priority;          /* Only used on entries with wildcards. */
    uint16_t idle_timeout;      /* Idle time before discarding (seconds). */
    uint16_t hard_timeout;      /* Hard expiration time (seconds) */
    time_t used;                /* Last used time. */
    time_t created;             /* When the flow was created. */
    uint64_t packet_count;      /* Number of packets seen. */
    uint64_t byte_count;        /* Number of bytes seen. */
    uint8_t reason;             /* Reason flow expired (one of OFPER_*). */

    struct sw_flow_actions *sf_acts;

    /* Private to table implementations. */
    struct list node;
    struct list iter_node;
    unsigned long int serial;
};

int flow_matches_1wild(const struct sw_flow_key *, const struct sw_flow_key *);
int flow_matches_2wild(const struct sw_flow_key *, const struct sw_flow_key *);
int flow_matches_desc(const struct sw_flow_key *, const struct sw_flow_key *, 
                     int);
int flow_has_out_port(struct sw_flow *flow, uint16_t out_port);
struct sw_flow *flow_alloc(size_t);
void flow_free(struct sw_flow *);
void flow_deferred_free(struct sw_flow *);
void flow_deferred_free_acts(struct sw_flow_actions *);
void flow_replace_acts(struct sw_flow *, const struct ofp_action_header *, 
        size_t);
void flow_extract_match(struct sw_flow_key* to, const struct ofp_match* from);
void flow_fill_match(struct ofp_match* to, const struct sw_flow_key* from);

void print_flow(const struct sw_flow_key *);
bool flow_timeout(struct sw_flow *flow);
void flow_used(struct sw_flow *flow, struct ofpbuf *buffer);

#endif /* switch-flow.h */
