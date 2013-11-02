/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
 * limitations under the License.  */

#include <config.h>
#include "ofproto-dpif-upcall.h"

#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>

#include "connmgr.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "dpif.h"
#include "fail-open.h"
#include "guarded-list.h"
#include "latch.h"
#include "seq.h"
#include "list.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "ofproto-dpif-ipfix.h"
#include "ofproto-dpif-sflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "vlog.h"

#define MAX_QUEUE_LENGTH 512

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_upcall);

COVERAGE_DEFINE(drop_queue_overflow);
COVERAGE_DEFINE(upcall_queue_overflow);
COVERAGE_DEFINE(fmb_queue_overflow);
COVERAGE_DEFINE(fmb_queue_revalidated);

/* A thread that processes each upcall handed to it by the dispatcher thread,
 * forwards the upcall's packet, and then queues it to the main ofproto_dpif
 * to possibly set up a kernel flow as a cache. */
struct handler {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */

    struct ovs_mutex mutex;            /* Mutex guarding the following. */

    /* Atomic queue of unprocessed upcalls. */
    struct list upcalls OVS_GUARDED;
    size_t n_upcalls OVS_GUARDED;

    size_t n_new_upcalls;              /* Only changed by the dispatcher. */
    bool need_signal;                  /* Only changed by the dispatcher. */

    pthread_cond_t wake_cond;          /* Wakes 'thread' while holding
                                          'mutex'. */
};

/* An upcall handler for ofproto_dpif.
 *
 * udpif is implemented as a "dispatcher" thread that reads upcalls from the
 * kernel.  It processes each upcall just enough to figure out its next
 * destination.  For a "miss" upcall (MISS_UPCALL), this is one of several
 * "handler" threads (see struct handler).  Other upcalls are queued to the
 * main ofproto_dpif. */
struct udpif {
    struct dpif *dpif;                 /* Datapath handle. */
    struct dpif_backer *backer;        /* Opaque dpif_backer pointer. */

    uint32_t secret;                   /* Random seed for upcall hash. */

    pthread_t dispatcher;              /* Dispatcher thread ID. */

    struct handler *handlers;          /* Upcall handlers. */
    size_t n_handlers;

    /* Queues to pass up to ofproto-dpif. */
    struct guarded_list drop_keys; /* "struct drop key"s. */
    struct guarded_list fmbs;      /* "struct flow_miss_batch"es. */

    /* Number of times udpif_revalidate() has been called. */
    atomic_uint reval_seq;

    struct seq *wait_seq;

    struct latch exit_latch; /* Tells child threads to exit. */
};

enum upcall_type {
    BAD_UPCALL,                 /* Some kind of bug somewhere. */
    MISS_UPCALL,                /* A flow miss.  */
    SFLOW_UPCALL,               /* sFlow sample. */
    FLOW_SAMPLE_UPCALL,         /* Per-flow sampling. */
    IPFIX_UPCALL                /* Per-bridge sampling. */
};

struct upcall {
    struct list list_node;          /* For queuing upcalls. */
    struct flow_miss *flow_miss;    /* This upcall's flow_miss. */

    /* Raw upcall plus data for keeping track of the memory backing it. */
    struct dpif_upcall dpif_upcall; /* As returned by dpif_recv() */
    struct ofpbuf upcall_buf;       /* Owns some data in 'dpif_upcall'. */
    uint64_t upcall_stub[512 / 8];  /* Buffer to reduce need for malloc(). */
};

static void upcall_destroy(struct upcall *);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void recv_upcalls(struct udpif *);
static void handle_upcalls(struct udpif *, struct list *upcalls);
static void miss_destroy(struct flow_miss *);
static void *udpif_dispatcher(void *);
static void *udpif_upcall_handler(void *);

struct udpif *
udpif_create(struct dpif_backer *backer, struct dpif *dpif)
{
    struct udpif *udpif = xzalloc(sizeof *udpif);

    udpif->dpif = dpif;
    udpif->backer = backer;
    udpif->secret = random_uint32();
    udpif->wait_seq = seq_create();
    latch_init(&udpif->exit_latch);
    guarded_list_init(&udpif->drop_keys);
    guarded_list_init(&udpif->fmbs);
    atomic_init(&udpif->reval_seq, 0);

    return udpif;
}

void
udpif_destroy(struct udpif *udpif)
{
    struct flow_miss_batch *fmb;
    struct drop_key *drop_key;

    udpif_recv_set(udpif, 0, false);

    while ((drop_key = drop_key_next(udpif))) {
        drop_key_destroy(drop_key);
    }

    while ((fmb = flow_miss_batch_next(udpif))) {
        flow_miss_batch_destroy(fmb);
    }

    guarded_list_destroy(&udpif->drop_keys);
    guarded_list_destroy(&udpif->fmbs);
    latch_destroy(&udpif->exit_latch);
    seq_destroy(udpif->wait_seq);
    free(udpif);
}

/* Tells 'udpif' to begin or stop handling flow misses depending on the value
 * of 'enable'.  'n_handlers' is the number of upcall_handler threads to
 * create.  Passing 'n_handlers' as zero is equivalent to passing 'enable' as
 * false. */
void
udpif_recv_set(struct udpif *udpif, size_t n_handlers, bool enable)
{
    n_handlers = enable ? n_handlers : 0;
    n_handlers = MIN(n_handlers, 64);

    /* Stop the old threads (if any). */
    if (udpif->handlers && udpif->n_handlers != n_handlers) {
        size_t i;

        latch_set(&udpif->exit_latch);

        /* Wake the handlers so they can exit. */
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            ovs_mutex_lock(&handler->mutex);
            xpthread_cond_signal(&handler->wake_cond);
            ovs_mutex_unlock(&handler->mutex);
        }

        xpthread_join(udpif->dispatcher, NULL);
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];
            struct upcall *miss, *next;

            xpthread_join(handler->thread, NULL);

            ovs_mutex_lock(&handler->mutex);
            LIST_FOR_EACH_SAFE (miss, next, list_node, &handler->upcalls) {
                list_remove(&miss->list_node);
                upcall_destroy(miss);
            }
            ovs_mutex_unlock(&handler->mutex);
            ovs_mutex_destroy(&handler->mutex);

            xpthread_cond_destroy(&handler->wake_cond);
        }
        latch_poll(&udpif->exit_latch);

        free(udpif->handlers);
        udpif->handlers = NULL;
        udpif->n_handlers = 0;
    }

    /* Start new threads (if necessary). */
    if (!udpif->handlers && n_handlers) {
        size_t i;

        udpif->n_handlers = n_handlers;
        udpif->handlers = xzalloc(udpif->n_handlers * sizeof *udpif->handlers);
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            handler->udpif = udpif;
            list_init(&handler->upcalls);
            handler->need_signal = false;
            xpthread_cond_init(&handler->wake_cond, NULL);
            ovs_mutex_init(&handler->mutex);
            xpthread_create(&handler->thread, NULL, udpif_upcall_handler,
                            handler);
        }
        xpthread_create(&udpif->dispatcher, NULL, udpif_dispatcher, udpif);
    }
}

void
udpif_wait(struct udpif *udpif)
{
    uint64_t seq = seq_read(udpif->wait_seq);
    if (!guarded_list_is_empty(&udpif->drop_keys) ||
        !guarded_list_is_empty(&udpif->fmbs)) {
        poll_immediate_wake();
    } else {
        seq_wait(udpif->wait_seq, seq);
    }
}

/* Notifies 'udpif' that something changed which may render previous
 * xlate_actions() results invalid. */
void
udpif_revalidate(struct udpif *udpif)
{
    struct flow_miss_batch *fmb, *next_fmb;
    unsigned int junk;
    struct list fmbs;

    /* Since we remove each miss on revalidation, their statistics won't be
     * accounted to the appropriate 'facet's in the upper layer.  In most
     * cases, this is alright because we've already pushed the stats to the
     * relevant rules.  However, NetFlow requires absolute packet counts on
     * 'facet's which could now be incorrect. */
    atomic_add(&udpif->reval_seq, 1, &junk);

    guarded_list_pop_all(&udpif->fmbs, &fmbs);
    LIST_FOR_EACH_SAFE (fmb, next_fmb, list_node, &fmbs) {
        list_remove(&fmb->list_node);
        flow_miss_batch_destroy(fmb);
    }

    udpif_drop_key_clear(udpif);
}

/* Destroys and deallocates 'upcall'. */
static void
upcall_destroy(struct upcall *upcall)
{
    if (upcall) {
        ofpbuf_uninit(&upcall->upcall_buf);
        free(upcall);
    }
}

/* Retrieves the next batch of processed flow misses for 'udpif' to install.
 * The caller is responsible for destroying it with flow_miss_batch_destroy().
 */
struct flow_miss_batch *
flow_miss_batch_next(struct udpif *udpif)
{
    int i;

    for (i = 0; i < 50; i++) {
        struct flow_miss_batch *next;
        unsigned int reval_seq;
        struct list *next_node;

        next_node = guarded_list_pop_front(&udpif->fmbs);
        if (!next_node) {
            break;
        }

        next = CONTAINER_OF(next_node, struct flow_miss_batch, list_node);
        atomic_read(&udpif->reval_seq, &reval_seq);
        if (next->reval_seq == reval_seq) {
            return next;
        }

        flow_miss_batch_destroy(next);
    }

    return NULL;
}

/* Destroys and deallocates 'fmb'. */
void
flow_miss_batch_destroy(struct flow_miss_batch *fmb)
{
    struct flow_miss *miss, *next;
    struct upcall *upcall, *next_upcall;

    if (!fmb) {
        return;
    }

    HMAP_FOR_EACH_SAFE (miss, next, hmap_node, &fmb->misses) {
        hmap_remove(&fmb->misses, &miss->hmap_node);
        miss_destroy(miss);
    }

    LIST_FOR_EACH_SAFE (upcall, next_upcall, list_node, &fmb->upcalls) {
        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }

    hmap_destroy(&fmb->misses);
    free(fmb);
}

/* Retrieves the next drop key which ofproto-dpif needs to process.  The caller
 * is responsible for destroying it with drop_key_destroy(). */
struct drop_key *
drop_key_next(struct udpif *udpif)
{
    struct list *next = guarded_list_pop_front(&udpif->drop_keys);
    return next ? CONTAINER_OF(next, struct drop_key, list_node) : NULL;
}

/* Destroys and deallocates 'drop_key'. */
void
drop_key_destroy(struct drop_key *drop_key)
{
    if (drop_key) {
        free(drop_key->key);
        free(drop_key);
    }
}

/* Clears all drop keys waiting to be processed by drop_key_next(). */
void
udpif_drop_key_clear(struct udpif *udpif)
{
    struct drop_key *drop_key, *next;
    struct list list;

    guarded_list_pop_all(&udpif->drop_keys, &list);
    LIST_FOR_EACH_SAFE (drop_key, next, list_node, &list) {
        list_remove(&drop_key->list_node);
        drop_key_destroy(drop_key);
    }
}

/* The dispatcher thread is responsible for receiving upcalls from the kernel,
 * assigning them to a upcall_handler thread. */
static void *
udpif_dispatcher(void *arg)
{
    struct udpif *udpif = arg;

    set_subprogram_name("dispatcher");
    while (!latch_is_set(&udpif->exit_latch)) {
        recv_upcalls(udpif);
        dpif_recv_wait(udpif->dpif);
        latch_wait(&udpif->exit_latch);
        poll_block();
    }

    return NULL;
}

/* The miss handler thread is responsible for processing miss upcalls retrieved
 * by the dispatcher thread.  Once finished it passes the processed miss
 * upcalls to ofproto-dpif where they're installed in the datapath. */
static void *
udpif_upcall_handler(void *arg)
{
    struct handler *handler = arg;

    set_subprogram_name("upcall_%u", ovsthread_id_self());
    for (;;) {
        struct list misses = LIST_INITIALIZER(&misses);
        size_t i;

        ovs_mutex_lock(&handler->mutex);

        if (latch_is_set(&handler->udpif->exit_latch)) {
            ovs_mutex_unlock(&handler->mutex);
            return NULL;
        }

        if (!handler->n_upcalls) {
            ovs_mutex_cond_wait(&handler->wake_cond, &handler->mutex);
        }

        for (i = 0; i < FLOW_MISS_MAX_BATCH; i++) {
            if (handler->n_upcalls) {
                handler->n_upcalls--;
                list_push_back(&misses, list_pop_front(&handler->upcalls));
            } else {
                break;
            }
        }
        ovs_mutex_unlock(&handler->mutex);

        handle_upcalls(handler->udpif, &misses);

        coverage_clear();
    }
}

static void
miss_destroy(struct flow_miss *miss)
{
    xlate_out_uninit(&miss->xout);
}

static enum upcall_type
classify_upcall(const struct upcall *upcall)
{
    const struct dpif_upcall *dpif_upcall = &upcall->dpif_upcall;
    union user_action_cookie cookie;
    size_t userdata_len;

    /* First look at the upcall type. */
    switch (dpif_upcall->type) {
    case DPIF_UC_ACTION:
        break;

    case DPIF_UC_MISS:
        return MISS_UPCALL;

    case DPIF_N_UC_TYPES:
    default:
        VLOG_WARN_RL(&rl, "upcall has unexpected type %"PRIu32,
                     dpif_upcall->type);
        return BAD_UPCALL;
    }

    /* "action" upcalls need a closer look. */
    if (!dpif_upcall->userdata) {
        VLOG_WARN_RL(&rl, "action upcall missing cookie");
        return BAD_UPCALL;
    }
    userdata_len = nl_attr_get_size(dpif_upcall->userdata);
    if (userdata_len < sizeof cookie.type
        || userdata_len > sizeof cookie) {
        VLOG_WARN_RL(&rl, "action upcall cookie has unexpected size %zu",
                     userdata_len);
        return BAD_UPCALL;
    }
    memset(&cookie, 0, sizeof cookie);
    memcpy(&cookie, nl_attr_get(dpif_upcall->userdata), userdata_len);
    if (userdata_len == sizeof cookie.sflow
        && cookie.type == USER_ACTION_COOKIE_SFLOW) {
        return SFLOW_UPCALL;
    } else if (userdata_len == sizeof cookie.slow_path
               && cookie.type == USER_ACTION_COOKIE_SLOW_PATH) {
        return MISS_UPCALL;
    } else if (userdata_len == sizeof cookie.flow_sample
               && cookie.type == USER_ACTION_COOKIE_FLOW_SAMPLE) {
        return FLOW_SAMPLE_UPCALL;
    } else if (userdata_len == sizeof cookie.ipfix
               && cookie.type == USER_ACTION_COOKIE_IPFIX) {
        return IPFIX_UPCALL;
    } else {
        VLOG_WARN_RL(&rl, "invalid user cookie of type %"PRIu16
                     " and size %zu", cookie.type, userdata_len);
        return BAD_UPCALL;
    }
}

static void
recv_upcalls(struct udpif *udpif)
{
    int n;

    for (;;) {
        uint32_t hash = udpif->secret;
        struct handler *handler;
        struct upcall *upcall;
        size_t n_bytes, left;
        struct nlattr *nla;
        int error;

        upcall = xmalloc(sizeof *upcall);
        ofpbuf_use_stub(&upcall->upcall_buf, upcall->upcall_stub,
                        sizeof upcall->upcall_stub);
        error = dpif_recv(udpif->dpif, &upcall->dpif_upcall,
                          &upcall->upcall_buf);
        if (error) {
            upcall_destroy(upcall);
            break;
        }

        n_bytes = 0;
        NL_ATTR_FOR_EACH (nla, left, upcall->dpif_upcall.key,
                          upcall->dpif_upcall.key_len) {
            enum ovs_key_attr type = nl_attr_type(nla);
            if (type == OVS_KEY_ATTR_IN_PORT
                || type == OVS_KEY_ATTR_TCP
                || type == OVS_KEY_ATTR_UDP) {
                if (nl_attr_get_size(nla) == 4) {
                    hash = mhash_add(hash, nl_attr_get_u32(nla));
                    n_bytes += 4;
                } else {
                    VLOG_WARN_RL(&rl,
                                 "Netlink attribute with incorrect size.");
                }
            }
        }
        hash =  mhash_finish(hash, n_bytes);

        handler = &udpif->handlers[hash % udpif->n_handlers];

        ovs_mutex_lock(&handler->mutex);
        if (handler->n_upcalls < MAX_QUEUE_LENGTH) {
            list_push_back(&handler->upcalls, &upcall->list_node);
            if (handler->n_upcalls == 0) {
                handler->need_signal = true;
            }
            handler->n_upcalls++;
            if (handler->need_signal &&
                handler->n_upcalls >= FLOW_MISS_MAX_BATCH) {
                handler->need_signal = false;
                xpthread_cond_signal(&handler->wake_cond);
            }
            ovs_mutex_unlock(&handler->mutex);
            if (!VLOG_DROP_DBG(&rl)) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                odp_flow_key_format(upcall->dpif_upcall.key,
                                    upcall->dpif_upcall.key_len,
                                    &ds);
                VLOG_DBG("dispatcher: enqueue (%s)", ds_cstr(&ds));
                ds_destroy(&ds);
            }
        } else {
            ovs_mutex_unlock(&handler->mutex);
            COVERAGE_INC(upcall_queue_overflow);
            upcall_destroy(upcall);
        }
    }

    for (n = 0; n < udpif->n_handlers; ++n) {
        struct handler *handler = &udpif->handlers[n];

        if (handler->need_signal) {
            handler->need_signal = false;
            ovs_mutex_lock(&handler->mutex);
            xpthread_cond_signal(&handler->wake_cond);
            ovs_mutex_unlock(&handler->mutex);
        }
    }
}

static struct flow_miss *
flow_miss_find(struct hmap *todo, const struct ofproto_dpif *ofproto,
               const struct flow *flow, uint32_t hash)
{
    struct flow_miss *miss;

    HMAP_FOR_EACH_WITH_HASH (miss, hmap_node, hash, todo) {
        if (miss->ofproto == ofproto && flow_equal(&miss->flow, flow)) {
            return miss;
        }
    }

    return NULL;
}

static void
handle_upcalls(struct udpif *udpif, struct list *upcalls)
{
    struct dpif_op *opsp[FLOW_MISS_MAX_BATCH];
    struct dpif_op ops[FLOW_MISS_MAX_BATCH];
    struct upcall *upcall, *next;
    struct flow_miss_batch *fmb;
    size_t n_misses, n_ops, i;
    struct flow_miss *miss;
    unsigned int reval_seq;
    enum upcall_type type;
    bool fail_open;

    /* Extract the flow from each upcall.  Construct in fmb->misses a hash
     * table that maps each unique flow to a 'struct flow_miss'.
     *
     * Most commonly there is a single packet per flow_miss, but there are
     * several reasons why there might be more than one, e.g.:
     *
     *   - The dpif packet interface does not support TSO (or UFO, etc.), so a
     *     large packet sent to userspace is split into a sequence of smaller
     *     ones.
     *
     *   - A stream of quickly arriving packets in an established "slow-pathed"
     *     flow.
     *
     *   - Rarely, a stream of quickly arriving packets in a flow not yet
     *     established.  (This is rare because most protocols do not send
     *     multiple back-to-back packets before receiving a reply from the
     *     other end of the connection, which gives OVS a chance to set up a
     *     datapath flow.)
     */
    fmb = xmalloc(sizeof *fmb);
    atomic_read(&udpif->reval_seq, &fmb->reval_seq);
    hmap_init(&fmb->misses);
    list_init(&fmb->upcalls);
    n_misses = 0;
    LIST_FOR_EACH_SAFE (upcall, next, list_node, upcalls) {
        struct dpif_upcall *dupcall = &upcall->dpif_upcall;
        struct ofpbuf *packet = dupcall->packet;
        struct flow_miss *miss = &fmb->miss_buf[n_misses];
        struct flow_miss *existing_miss;
        struct ofproto_dpif *ofproto;
        struct dpif_sflow *sflow;
        struct dpif_ipfix *ipfix;
        odp_port_t odp_in_port;
        struct flow flow;
        int error;

        error = xlate_receive(udpif->backer, packet, dupcall->key,
                              dupcall->key_len, &flow, &miss->key_fitness,
                              &ofproto, &odp_in_port);
        if (error) {
            if (error == ENODEV) {
                struct drop_key *drop_key;

                /* Received packet on datapath port for which we couldn't
                 * associate an ofproto.  This can happen if a port is removed
                 * while traffic is being received.  Print a rate-limited
                 * message in case it happens frequently.  Install a drop flow
                 * so that future packets of the flow are inexpensively dropped
                 * in the kernel. */
                VLOG_INFO_RL(&rl, "received packet on unassociated datapath "
                             "port %"PRIu32, odp_in_port);

                drop_key = xmalloc(sizeof *drop_key);
                drop_key->key = xmemdup(dupcall->key, dupcall->key_len);
                drop_key->key_len = dupcall->key_len;

                if (guarded_list_push_back(&udpif->drop_keys,
                                           &drop_key->list_node,
                                           MAX_QUEUE_LENGTH)) {
                    seq_change(udpif->wait_seq);
                } else {
                    COVERAGE_INC(drop_queue_overflow);
                    drop_key_destroy(drop_key);
                }
            }
            list_remove(&upcall->list_node);
            upcall_destroy(upcall);
            continue;
        }

        type = classify_upcall(upcall);
        if (type == MISS_UPCALL) {
            uint32_t hash;

            flow_extract(packet, flow.skb_priority, flow.pkt_mark,
                         &flow.tunnel, &flow.in_port, &miss->flow);

            hash = flow_hash(&miss->flow, 0);
            existing_miss = flow_miss_find(&fmb->misses, ofproto, &miss->flow,
                                           hash);
            if (!existing_miss) {
                hmap_insert(&fmb->misses, &miss->hmap_node, hash);
                miss->ofproto = ofproto;
                miss->key = dupcall->key;
                miss->key_len = dupcall->key_len;
                miss->upcall_type = dupcall->type;
                miss->stats.n_packets = 0;
                miss->stats.n_bytes = 0;
                miss->stats.used = time_msec();
                miss->stats.tcp_flags = 0;

                n_misses++;
            } else {
                miss = existing_miss;
            }
            miss->stats.tcp_flags |= packet_get_tcp_flags(packet, &miss->flow);
            miss->stats.n_bytes += packet->size;
            miss->stats.n_packets++;

            upcall->flow_miss = miss;
            continue;
        }

        switch (type) {
        case SFLOW_UPCALL:
            sflow = xlate_get_sflow(ofproto);
            if (sflow) {
                union user_action_cookie cookie;

                memset(&cookie, 0, sizeof cookie);
                memcpy(&cookie, nl_attr_get(dupcall->userdata),
                       sizeof cookie.sflow);
                dpif_sflow_received(sflow, dupcall->packet, &flow, odp_in_port,
                                    &cookie);
                dpif_sflow_unref(sflow);
            }
            break;
        case IPFIX_UPCALL:
            ipfix = xlate_get_ipfix(ofproto);
            if (ipfix) {
                dpif_ipfix_bridge_sample(ipfix, dupcall->packet, &flow);
                dpif_ipfix_unref(ipfix);
            }
            break;
        case FLOW_SAMPLE_UPCALL:
            ipfix = xlate_get_ipfix(ofproto);
            if (ipfix) {
                union user_action_cookie cookie;

                memset(&cookie, 0, sizeof cookie);
                memcpy(&cookie, nl_attr_get(dupcall->userdata),
                       sizeof cookie.flow_sample);

                /* The flow reflects exactly the contents of the packet.
                 * Sample the packet using it. */
                dpif_ipfix_flow_sample(ipfix, dupcall->packet, &flow,
                                       cookie.flow_sample.collector_set_id,
                                       cookie.flow_sample.probability,
                                       cookie.flow_sample.obs_domain_id,
                                       cookie.flow_sample.obs_point_id);
                dpif_ipfix_unref(ipfix);
            }
            break;
        case BAD_UPCALL:
            break;
        case MISS_UPCALL:
            NOT_REACHED();
        }

        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }

    /* Initialize each 'struct flow_miss's ->xout.
     *
     * We do this per-flow_miss rather than per-packet because, most commonly,
     * all the packets in a flow can use the same translation.
     *
     * We can't do this in the previous loop because we need the TCP flags for
     * all the packets in each miss. */
    fail_open = false;
    HMAP_FOR_EACH (miss, hmap_node, &fmb->misses) {
        struct xlate_in xin;

        xlate_in_init(&xin, miss->ofproto, &miss->flow, NULL,
                      miss->stats.tcp_flags, NULL);
        xin.may_learn = true;
        xin.resubmit_stats = &miss->stats;
        xlate_actions(&xin, &miss->xout);
        fail_open = fail_open || miss->xout.fail_open;
    }

    /* Now handle the packets individually in order of arrival.  In the common
     * case each packet of a miss can share the same actions, but slow-pathed
     * packets need to be translated individually:
     *
     *   - For SLOW_CFM, SLOW_LACP, SLOW_STP, and SLOW_BFD, translation is what
     *     processes received packets for these protocols.
     *
     *   - For SLOW_CONTROLLER, translation sends the packet to the OpenFlow
     *     controller.
     *
     * The loop fills 'ops' with an array of operations to execute in the
     * datapath. */
    n_ops = 0;
    LIST_FOR_EACH (upcall, list_node, upcalls) {
        struct flow_miss *miss = upcall->flow_miss;
        struct ofpbuf *packet = upcall->dpif_upcall.packet;

        if (miss->xout.slow) {
            struct xlate_in xin;

            xlate_in_init(&xin, miss->ofproto, &miss->flow, NULL, 0, packet);
            xlate_actions_for_side_effects(&xin);
        }

        if (miss->xout.odp_actions.size) {
            struct dpif_op *op;

            if (miss->flow.in_port.ofp_port
                != vsp_realdev_to_vlandev(miss->ofproto,
                                          miss->flow.in_port.ofp_port,
                                          miss->flow.vlan_tci)) {
                /* This packet was received on a VLAN splinter port.  We
                 * added a VLAN to the packet to make the packet resemble
                 * the flow, but the actions were composed assuming that
                 * the packet contained no VLAN.  So, we must remove the
                 * VLAN header from the packet before trying to execute the
                 * actions. */
                eth_pop_vlan(packet);
            }

            op = &ops[n_ops++];
            op->type = DPIF_OP_EXECUTE;
            op->u.execute.key = miss->key;
            op->u.execute.key_len = miss->key_len;
            op->u.execute.packet = packet;
            op->u.execute.actions = miss->xout.odp_actions.data;
            op->u.execute.actions_len = miss->xout.odp_actions.size;
            op->u.execute.needs_help = (miss->xout.slow & SLOW_ACTION) != 0;
        }
    }

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i];
    }
    dpif_operate(udpif->dpif, opsp, n_ops);

    /* Special case for fail-open mode.
     *
     * If we are in fail-open mode, but we are connected to a controller too,
     * then we should send the packet up to the controller in the hope that it
     * will try to set up a flow and thereby allow us to exit fail-open.
     *
     * See the top-level comment in fail-open.c for more information. */
    if (fail_open) {
        LIST_FOR_EACH (upcall, list_node, upcalls) {
            struct flow_miss *miss = upcall->flow_miss;
            struct ofpbuf *packet = upcall->dpif_upcall.packet;
            struct ofproto_packet_in *pin;

            pin = xmalloc(sizeof *pin);
            pin->up.packet = xmemdup(packet->data, packet->size);
            pin->up.packet_len = packet->size;
            pin->up.reason = OFPR_NO_MATCH;
            pin->up.table_id = 0;
            pin->up.cookie = OVS_BE64_MAX;
            flow_get_metadata(&miss->flow, &pin->up.fmd);
            pin->send_len = 0; /* Not used for flow table misses. */
            pin->generated_by_table_miss = false;
            ofproto_dpif_send_packet_in(miss->ofproto, pin);
        }
    }

    list_move(&fmb->upcalls, upcalls);

    atomic_read(&udpif->reval_seq, &reval_seq);
    if (reval_seq != fmb->reval_seq) {
        COVERAGE_INC(fmb_queue_revalidated);
        flow_miss_batch_destroy(fmb);
    } else if (!guarded_list_push_back(&udpif->fmbs, &fmb->list_node,
                                       MAX_QUEUE_LENGTH)) {
        COVERAGE_INC(fmb_queue_overflow);
        flow_miss_batch_destroy(fmb);
    } else {
        seq_change(udpif->wait_seq);
    }
}
