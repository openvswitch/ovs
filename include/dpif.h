/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
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

#ifndef DPIF_H
#define DPIF_H 1

/* Operations for the datapath running in the local kernel.  The interface can
 * generalize to multiple types of local datapaths, but the implementation only
 * supports the openflow kernel module via netlink. */

#include <stdbool.h>
#include <stdint.h>

struct buffer;
struct ofp_match;

/* A datapath interface.  Opaque. */
struct dpif
{
    int dp_idx;
    struct nl_sock *sock;
};

int dpif_open(int dp_idx, bool subscribe, struct dpif *);
void dpif_close(struct dpif *);
int dpif_recv_openflow(struct dpif *, struct buffer **, bool wait);
int dpif_send_openflow(struct dpif *, struct buffer *, bool wait);
int dpif_add_dp(struct dpif *);
int dpif_del_dp(struct dpif *);
int dpif_add_port(struct dpif *, const char *netdev);
int dpif_del_port(struct dpif *, const char *netdev);
int dpif_show(struct dpif *);
int dpif_dump_tables(struct dpif *);
int dpif_dump_flows(struct dpif *, int table, struct ofp_match *);
int dpif_benchmark_nl(struct dpif *, uint32_t, uint32_t);

#endif /* dpif.h */
