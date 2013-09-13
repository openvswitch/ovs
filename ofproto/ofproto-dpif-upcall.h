/* Copyright (c) 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#ifndef OFPROTO_DPIF_UPCALL_H
#define OFPROTO_DPIF_UPCALL_H

#define FLOW_MISS_MAX_BATCH 50

#include "dpif.h"
#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "ofproto-dpif-xlate.h"

struct dpif;
struct dpif_backer;

/* udif is responsible for retrieving upcalls from the kernel, processing miss
 * upcalls, and handing more complex ones up to the main ofproto-dpif
 * module. */

struct udpif *udpif_create(struct dpif_backer *, struct dpif *);
void udpif_recv_set(struct udpif *, size_t n_workers, bool enable);
void udpif_destroy(struct udpif *);

void udpif_wait(struct udpif *);

void udpif_revalidate(struct udpif *);

/* udpif can handle some upcalls on its own.  Others need the main ofproto_dpif
 * code to handle them.  This interface passes upcalls not handled by udpif up
 * to the ofproto_dpif main thread. */

/* Type of an upcall. */
enum upcall_type {
    /* Handled internally by udpif code.  Not returned by upcall_next().*/
    BAD_UPCALL,                 /* Some kind of bug somewhere. */
    MISS_UPCALL,                /* A flow miss.  */

    /* Require main thread's involvement.  May be returned by upcall_next(). */
    SFLOW_UPCALL,               /* sFlow sample. */
    FLOW_SAMPLE_UPCALL,         /* Per-flow sampling. */
    IPFIX_UPCALL                /* Per-bridge sampling. */
};

/* An upcall. */
struct upcall {
    struct list list_node;          /* For queuing upcalls. */

    enum upcall_type type;          /* Classification. */

    /* Raw upcall plus data for keeping track of the memory backing it. */
    struct dpif_upcall dpif_upcall; /* As returned by dpif_recv() */
    struct ofpbuf upcall_buf;       /* Owns some data in 'dpif_upcall'. */
    uint64_t upcall_stub[512 / 8];  /* Buffer to reduce need for malloc(). */
};

struct upcall *upcall_next(struct udpif *);
void upcall_destroy(struct upcall *);

/* udpif figures out how to forward packets, and does forward them, but it
 * can't set up datapath flows on its own.  This interface passes packet
 * forwarding data from udpif to the higher level ofproto_dpif to allow the
 * latter to set up datapath flows. */

/* Flow miss batching.
 *
 * Some dpifs implement operations faster when you hand them off in a batch.
 * To allow batching, "struct flow_miss" queues the dpif-related work needed
 * for a given flow.  Each "struct flow_miss" corresponds to sending one or
 * more packets, plus possibly installing the flow in the dpif. */
struct flow_miss {
    struct hmap_node hmap_node;
    struct ofproto_dpif *ofproto;

    struct flow flow;
    enum odp_key_fitness key_fitness;
    const struct nlattr *key;
    size_t key_len;
    struct list packets;
    enum dpif_upcall_type upcall_type;
    struct dpif_flow_stats stats;

    struct xlate_out xout;

    struct list upcalls;
};

struct flow_miss_batch {
    struct list list_node;

    struct flow_miss miss_buf[FLOW_MISS_MAX_BATCH];
    struct hmap misses;

    unsigned int reval_seq;
};

struct flow_miss_batch *flow_miss_batch_next(struct udpif *);
void flow_miss_batch_destroy(struct flow_miss_batch *);

/* Drop keys are odp flow keys which have drop flows installed in the kernel.
 * These are datapath flows which have no associated ofproto, if they did we
 * would use facets.
 *
 * udpif can't install drop flows by itself.  This interfaces allows udpif to
 * pass the drop flows up to ofproto_dpif to get it to install them. */
struct drop_key {
    struct hmap_node hmap_node;
    struct list list_node;
    struct nlattr *key;
    size_t key_len;
};

struct drop_key *drop_key_next(struct udpif *);
void drop_key_destroy(struct drop_key *);
void udpif_drop_key_clear(struct udpif *);

#endif /* ofproto-dpif-upcall.h */
