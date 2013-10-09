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
#include "ofproto-dpif.h"
#include "packets.h"
#include "poll-loop.h"
#include "vlog.h"

#define MAX_QUEUE_LENGTH 512

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_upcall);

COVERAGE_DEFINE(upcall_queue_overflow);
COVERAGE_DEFINE(drop_queue_overflow);
COVERAGE_DEFINE(miss_queue_overflow);
COVERAGE_DEFINE(fmb_queue_overflow);
COVERAGE_DEFINE(fmb_queue_revalidated);

/* A thread that processes each upcall handed to it by the dispatcher thread,
 * forwards the upcall's packet, and then queues it to the main ofproto_dpif
 * to possibly set up a kernel flow as a cache. */
struct handler {
    struct udpif *udpif;               /* Parent udpif. */
    pthread_t thread;                  /* Thread ID. */

    struct ovs_mutex mutex;            /* Mutex guarding the following. */

    /* Atomic queue of unprocessed miss upcalls. */
    struct list upcalls OVS_GUARDED;
    size_t n_upcalls OVS_GUARDED;

    size_t n_new_upcalls;              /* Only changed by the dispatcher. */

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

    struct handler *handlers;          /* Miss handlers. */
    size_t n_handlers;

    /* Queues to pass up to ofproto-dpif. */
    struct guarded_list drop_keys; /* "struct drop key"s. */
    struct guarded_list upcalls;   /* "struct upcall"s. */
    struct guarded_list fmbs;      /* "struct flow_miss_batch"es. */

    /* Number of times udpif_revalidate() has been called. */
    atomic_uint reval_seq;

    struct seq *wait_seq;

    struct latch exit_latch; /* Tells child threads to exit. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void recv_upcalls(struct udpif *);
static void handle_miss_upcalls(struct udpif *, struct list *upcalls);
static void miss_destroy(struct flow_miss *);
static void *udpif_dispatcher(void *);
static void *udpif_miss_handler(void *);

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
    guarded_list_init(&udpif->upcalls);
    guarded_list_init(&udpif->fmbs);
    atomic_init(&udpif->reval_seq, 0);

    return udpif;
}

void
udpif_destroy(struct udpif *udpif)
{
    struct flow_miss_batch *fmb;
    struct drop_key *drop_key;
    struct upcall *upcall;

    udpif_recv_set(udpif, 0, false);

    while ((drop_key = drop_key_next(udpif))) {
        drop_key_destroy(drop_key);
    }

    while ((upcall = upcall_next(udpif))) {
        upcall_destroy(upcall);
    }

    while ((fmb = flow_miss_batch_next(udpif))) {
        flow_miss_batch_destroy(fmb);
    }

    guarded_list_destroy(&udpif->drop_keys);
    guarded_list_destroy(&udpif->upcalls);
    guarded_list_destroy(&udpif->fmbs);
    latch_destroy(&udpif->exit_latch);
    seq_destroy(udpif->wait_seq);
    free(udpif);
}

/* Tells 'udpif' to begin or stop handling flow misses depending on the value
 * of 'enable'.  'n_handlers' is the number of miss_handler threads to create.
 * Passing 'n_handlers' as zero is equivalent to passing 'enable' as false. */
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
            xpthread_cond_init(&handler->wake_cond, NULL);
            ovs_mutex_init(&handler->mutex);
            xpthread_create(&handler->thread, NULL, udpif_miss_handler, handler);
        }
        xpthread_create(&udpif->dispatcher, NULL, udpif_dispatcher, udpif);
    }
}

void
udpif_wait(struct udpif *udpif)
{
    uint64_t seq = seq_read(udpif->wait_seq);
    if (!guarded_list_is_empty(&udpif->drop_keys) ||
        !guarded_list_is_empty(&udpif->upcalls) ||
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

/* Retreives the next upcall which ofproto-dpif is responsible for handling.
 * The caller is responsible for destroying the returned upcall with
 * upcall_destroy(). */
struct upcall *
upcall_next(struct udpif *udpif)
{
    struct list *next = guarded_list_pop_front(&udpif->upcalls);
    return next ? CONTAINER_OF(next, struct upcall, list_node) : NULL;
}

/* Destroys and deallocates 'upcall'. */
void
upcall_destroy(struct upcall *upcall)
{
    if (upcall) {
        ofpbuf_uninit(&upcall->upcall_buf);
        free(upcall);
    }
}

/* Retreives the next batch of processed flow misses for 'udpif' to install.
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

    if (!fmb) {
        return;
    }

    HMAP_FOR_EACH_SAFE (miss, next, hmap_node, &fmb->misses) {
        hmap_remove(&fmb->misses, &miss->hmap_node);
        miss_destroy(miss);
    }

    hmap_destroy(&fmb->misses);
    free(fmb);
}

/* Retreives the next drop key which ofproto-dpif needs to process.  The caller
 * is responsible for destroying it with drop_key_destroy(). */
struct drop_key *
drop_key_next(struct udpif *udpif)
{
    struct list *next = guarded_list_pop_front(&udpif->drop_keys);
    return next ? CONTAINER_OF(next, struct drop_key, list_node) : NULL;
}

/* Destorys and deallocates 'drop_key'. */
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

/* The dispatcher thread is responsible for receving upcalls from the kernel,
 * assigning the miss upcalls to a miss_handler thread, and assigning the more
 * complex ones to ofproto-dpif directly. */
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

/* The miss handler thread is responsible for processing miss upcalls retreived
 * by the dispatcher thread.  Once finished it passes the processed miss
 * upcalls to ofproto-dpif where they're installed in the datapath. */
static void *
udpif_miss_handler(void *arg)
{
    struct list misses = LIST_INITIALIZER(&misses);
    struct handler *handler = arg;

    set_subprogram_name("miss_handler");
    for (;;) {
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

        handle_miss_upcalls(handler->udpif, &misses);
    }
}

static void
miss_destroy(struct flow_miss *miss)
{
    struct upcall *upcall, *next;

    LIST_FOR_EACH_SAFE (upcall, next, list_node, &miss->upcalls) {
        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }
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
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);
    size_t n_udpif_new_upcalls = 0;
    struct handler *handler;
    int n;

    for (;;) {
        struct upcall *upcall;
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

        upcall->type = classify_upcall(upcall);
        if (upcall->type == BAD_UPCALL) {
            upcall_destroy(upcall);
        } else if (upcall->type == MISS_UPCALL) {
            struct dpif_upcall *dupcall = &upcall->dpif_upcall;
            uint32_t hash = udpif->secret;
            struct nlattr *nla;
            size_t n_bytes, left;

            n_bytes = 0;
            NL_ATTR_FOR_EACH (nla, left, dupcall->key, dupcall->key_len) {
                enum ovs_key_attr type = nl_attr_type(nla);
                if (type == OVS_KEY_ATTR_IN_PORT
                    || type == OVS_KEY_ATTR_TCP
                    || type == OVS_KEY_ATTR_UDP) {
                    if (nl_attr_get_size(nla) == 4) {
                        ovs_be32 attr = nl_attr_get_be32(nla);
                        hash = mhash_add(hash, (OVS_FORCE uint32_t) attr);
                        n_bytes += 4;
                    } else {
                        VLOG_WARN("Netlink attribute with incorrect size.");
                    }
                }
            }
            hash =  mhash_finish(hash, n_bytes);

            handler = &udpif->handlers[hash % udpif->n_handlers];

            ovs_mutex_lock(&handler->mutex);
            if (handler->n_upcalls < MAX_QUEUE_LENGTH) {
                list_push_back(&handler->upcalls, &upcall->list_node);
                handler->n_new_upcalls = ++handler->n_upcalls;

                if (handler->n_new_upcalls >= FLOW_MISS_MAX_BATCH) {
                    xpthread_cond_signal(&handler->wake_cond);
                }
                ovs_mutex_unlock(&handler->mutex);
                if (!VLOG_DROP_DBG(&rl)) {
                    struct ds ds = DS_EMPTY_INITIALIZER;

                    odp_flow_key_format(upcall->dpif_upcall.key,
                                        upcall->dpif_upcall.key_len,
                                        &ds);
                    VLOG_DBG("dispatcher: miss enqueue (%s)", ds_cstr(&ds));
                    ds_destroy(&ds);
                }
            } else {
                ovs_mutex_unlock(&handler->mutex);
                COVERAGE_INC(miss_queue_overflow);
                upcall_destroy(upcall);
            }
        } else {
            size_t len;

            len = guarded_list_push_back(&udpif->upcalls, &upcall->list_node,
                                         MAX_QUEUE_LENGTH);
            if (len > 0) {
                n_udpif_new_upcalls = len;
                if (n_udpif_new_upcalls >= FLOW_MISS_MAX_BATCH) {
                    seq_change(udpif->wait_seq);
                }
            } else {
                COVERAGE_INC(upcall_queue_overflow);
                upcall_destroy(upcall);
            }
        }
    }
    for (n = 0; n < udpif->n_handlers; ++n) {
        handler = &udpif->handlers[n];
        if (handler->n_new_upcalls) {
            handler->n_new_upcalls = 0;
            ovs_mutex_lock(&handler->mutex);
            xpthread_cond_signal(&handler->wake_cond);
            ovs_mutex_unlock(&handler->mutex);
        }
    }
    if (n_udpif_new_upcalls) {
        seq_change(udpif->wait_seq);
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

/* Executes flow miss 'miss'.  May add any required datapath operations
 * to 'ops', incrementing '*n_ops' for each new op. */
static void
execute_flow_miss(struct flow_miss *miss, struct dpif_op *ops, size_t *n_ops)
{
    struct ofproto_dpif *ofproto = miss->ofproto;
    struct ofpbuf *packet;
    struct xlate_in xin;

    memset(&miss->stats, 0, sizeof miss->stats);
    miss->stats.used = time_msec();
    LIST_FOR_EACH (packet, list_node, &miss->packets) {
        miss->stats.tcp_flags |= packet_get_tcp_flags(packet, &miss->flow);
        miss->stats.n_bytes += packet->size;
        miss->stats.n_packets++;
    }

    xlate_in_init(&xin, ofproto, &miss->flow, NULL, miss->stats.tcp_flags,
                  NULL);
    xin.may_learn = true;
    xin.resubmit_stats = &miss->stats;
    xlate_actions(&xin, &miss->xout);

    if (miss->xout.fail_open) {
        LIST_FOR_EACH (packet, list_node, &miss->packets) {
            struct ofputil_packet_in *pin;

            /* Extra-special case for fail-open mode.
             *
             * We are in fail-open mode and the packet matched the fail-open
             * rule, but we are connected to a controller too.  We should send
             * the packet up to the controller in the hope that it will try to
             * set up a flow and thereby allow us to exit fail-open.
             *
             * See the top-level comment in fail-open.c for more information. */
            pin = xmalloc(sizeof(*pin));
            pin->packet = xmemdup(packet->data, packet->size);
            pin->packet_len = packet->size;
            pin->reason = OFPR_NO_MATCH;
            pin->controller_id = 0;
            pin->table_id = 0;
            pin->cookie = 0;
            pin->send_len = 0; /* Not used for flow table misses. */
            flow_get_metadata(&miss->flow, &pin->fmd);
            ofproto_dpif_send_packet_in(ofproto, pin);
        }
    }

    if (miss->xout.slow) {
        LIST_FOR_EACH (packet, list_node, &miss->packets) {
            struct xlate_in xin;

            xlate_in_init(&xin, miss->ofproto, &miss->flow, NULL, 0, packet);
            xlate_actions_for_side_effects(&xin);
        }
    }

    if (miss->xout.odp_actions.size) {
        LIST_FOR_EACH (packet, list_node, &miss->packets) {
            struct dpif_op *op = &ops[*n_ops];
            struct dpif_execute *execute = &op->u.execute;

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

            op->type = DPIF_OP_EXECUTE;
            execute->key = miss->key;
            execute->key_len = miss->key_len;
            execute->packet = packet;
            execute->actions = miss->xout.odp_actions.data;
            execute->actions_len = miss->xout.odp_actions.size;

            (*n_ops)++;
        }
    }
}

static void
handle_miss_upcalls(struct udpif *udpif, struct list *upcalls)
{
    struct dpif_op *opsp[FLOW_MISS_MAX_BATCH];
    struct dpif_op ops[FLOW_MISS_MAX_BATCH];
    struct upcall *upcall, *next;
    struct flow_miss_batch *fmb;
    size_t n_upcalls, n_ops, i;
    struct flow_miss *miss;
    unsigned int reval_seq;

    /* Construct the to-do list.
     *
     * This just amounts to extracting the flow from each packet and sticking
     * the packets that have the same flow in the same "flow_miss" structure so
     * that we can process them together. */
    fmb = xmalloc(sizeof *fmb);
    atomic_read(&udpif->reval_seq, &fmb->reval_seq);
    hmap_init(&fmb->misses);
    n_upcalls = 0;
    LIST_FOR_EACH_SAFE (upcall, next, list_node, upcalls) {
        struct dpif_upcall *dupcall = &upcall->dpif_upcall;
        struct flow_miss *miss = &fmb->miss_buf[n_upcalls];
        struct flow_miss *existing_miss;
        struct ofproto_dpif *ofproto;
        odp_port_t odp_in_port;
        struct flow flow;
        uint32_t hash;
        int error;

        error = xlate_receive(udpif->backer, dupcall->packet, dupcall->key,
                              dupcall->key_len, &flow, &miss->key_fitness,
                              &ofproto, &odp_in_port);

        if (error == ENODEV) {
            struct drop_key *drop_key;

            /* Received packet on datapath port for which we couldn't
             * associate an ofproto.  This can happen if a port is removed
             * while traffic is being received.  Print a rate-limited message
             * in case it happens frequently.  Install a drop flow so
             * that future packets of the flow are inexpensively dropped
             * in the kernel. */
            VLOG_INFO_RL(&rl, "received packet on unassociated datapath port "
                              "%"PRIu32, odp_in_port);

            drop_key = xmalloc(sizeof *drop_key);
            drop_key->key = xmemdup(dupcall->key, dupcall->key_len);
            drop_key->key_len = dupcall->key_len;

            if (guarded_list_push_back(&udpif->drop_keys, &drop_key->list_node,
                                       MAX_QUEUE_LENGTH)) {
                seq_change(udpif->wait_seq);
            } else {
                COVERAGE_INC(drop_queue_overflow);
                drop_key_destroy(drop_key);
            }
            continue;
        } else if (error) {
            continue;
        }

        flow_extract(dupcall->packet, flow.skb_priority, flow.pkt_mark,
                     &flow.tunnel, &flow.in_port, &miss->flow);

        /* Add other packets to a to-do list. */
        hash = flow_hash(&miss->flow, 0);
        existing_miss = flow_miss_find(&fmb->misses, ofproto, &miss->flow, hash);
        if (!existing_miss) {
            hmap_insert(&fmb->misses, &miss->hmap_node, hash);
            miss->ofproto = ofproto;
            miss->key = dupcall->key;
            miss->key_len = dupcall->key_len;
            miss->upcall_type = dupcall->type;
            list_init(&miss->packets);
            list_init(&miss->upcalls);

            n_upcalls++;
        } else {
            miss = existing_miss;
        }
        list_push_back(&miss->packets, &dupcall->packet->list_node);

        list_remove(&upcall->list_node);
        list_push_back(&miss->upcalls, &upcall->list_node);
    }

    LIST_FOR_EACH_SAFE (upcall, next, list_node, upcalls) {
        list_remove(&upcall->list_node);
        upcall_destroy(upcall);
    }

    /* Process each element in the to-do list, constructing the set of
     * operations to batch. */
    n_ops = 0;
    HMAP_FOR_EACH (miss, hmap_node, &fmb->misses) {
        execute_flow_miss(miss, ops, &n_ops);
    }
    ovs_assert(n_ops <= ARRAY_SIZE(ops));

    /* Execute batch. */
    for (i = 0; i < n_ops; i++) {
        opsp[i] = &ops[i];
    }
    dpif_operate(udpif->dpif, opsp, n_ops);

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
