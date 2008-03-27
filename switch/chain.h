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

#ifndef CHAIN_H
#define CHAIN_H 1

struct sw_flow;
struct sw_flow_key;
struct datapath;

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
int chain_delete(struct sw_chain *, const struct sw_flow_key *, int);
int chain_timeout(struct sw_chain *, struct datapath *);
void chain_destroy(struct sw_chain *);
void chain_print_stats(struct sw_chain *);

#endif /* chain.h */
