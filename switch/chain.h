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

#ifndef CHAIN_H
#define CHAIN_H 1

#include <stddef.h>
#include <stdint.h>

struct sw_flow;
struct sw_flow_key;
struct ofp_action_header;
struct list;

#define TABLE_LINEAR_MAX_FLOWS  100
#define TABLE_HASH_MAX_FLOWS    65536
#define TABLE_MAC_MAX_FLOWS      1024
#define TABLE_MAC_NUM_BUCKETS   1024

/* Set of tables chained together in sequence from cheap to expensive. */
#define CHAIN_MAX_TABLES 4
struct sw_chain {
    int n_tables;
    struct sw_table *tables[CHAIN_MAX_TABLES];
};

struct sw_chain *chain_create(void);
struct sw_flow *chain_lookup(struct sw_chain *, const struct sw_flow_key *);
int chain_insert(struct sw_chain *, struct sw_flow *);
int chain_modify(struct sw_chain *, const struct sw_flow_key *, 
        uint16_t, int, const struct ofp_action_header *, size_t);
int chain_delete(struct sw_chain *, const struct sw_flow_key *, uint16_t, 
        uint16_t, int);
void chain_timeout(struct sw_chain *, struct list *deleted);
void chain_destroy(struct sw_chain *);

#endif /* chain.h */
