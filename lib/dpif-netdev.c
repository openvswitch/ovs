/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
 * limitations under the License.
 */

#include <config.h>
#include "dpif.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "classifier.h"
#include "csum.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hmap.h"
#include "latch.h"
#include "list.h"
#include "meta-flow.h"
#include "netdev.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* By default, choose a priority in the middle. */
#define NETDEV_RULE_PRIORITY 0x8000

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

/* Queues. */
enum { N_QUEUES = 2 };          /* Number of queues for dpif_recv(). */
enum { MAX_QUEUE_LEN = 128 };   /* Maximum number of packets per queue. */
enum { QUEUE_MASK = MAX_QUEUE_LEN - 1 };
BUILD_ASSERT_DECL(IS_POW2(MAX_QUEUE_LEN));

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

struct dp_netdev_upcall {
    struct dpif_upcall upcall;  /* Queued upcall information. */
    struct ofpbuf buf;          /* ofpbuf instance for upcall.packet. */
};

/* A queue passing packets from a struct dp_netdev to its clients.
 *
 *
 * Thread-safety
 * =============
 *
 * Any access at all requires the owning 'dp_netdev''s queue_mutex. */
struct dp_netdev_queue {
    struct dp_netdev_upcall upcalls[MAX_QUEUE_LEN] OVS_GUARDED;
    unsigned int head OVS_GUARDED;
    unsigned int tail OVS_GUARDED;
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_rwlock
 *    flow_mutex
 *    cls.rwlock
 *    queue_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Flows.
     *
     * Readers of 'cls' and 'flow_table' must take a 'cls->rwlock' read lock.
     *
     * Writers of 'cls' and 'flow_table' must take the 'flow_mutex' and then
     * the 'cls->rwlock' write lock.  (The outer 'flow_mutex' allows writers to
     * atomically perform multiple operations on 'cls' and 'flow_table'.)
     */
    struct ovs_mutex flow_mutex;
    struct classifier cls;      /* Classifier.  Protected by cls.rwlock. */
    struct hmap flow_table OVS_GUARDED; /* Flow table. */

    /* Queues.
     *
     * Everything in 'queues' is protected by 'queue_mutex'. */
    struct ovs_mutex queue_mutex;
    struct dp_netdev_queue queues[N_QUEUES];
    struct seq *queue_seq;      /* Incremented whenever a packet is queued. */

    /* Statistics.
     *
     * ovsthread_counter is internally synchronized. */
    struct ovsthread_counter *n_hit;    /* Number of flow table matches. */
    struct ovsthread_counter *n_missed; /* Number of flow table misses. */
    struct ovsthread_counter *n_lost;   /* Number of misses not passed up. */

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_rwlock'. */
    struct ovs_rwlock port_rwlock;
    struct hmap ports OVS_GUARDED;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* Forwarding threads. */
    struct latch exit_latch;
    struct dp_forwarder *forwarders;
    size_t n_forwarders;
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQ_RDLOCK(dp->port_rwlock);

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    odp_port_t port_no;
    struct netdev *netdev;
    struct netdev_saved_flags *sf;
    struct netdev_rx *rx;
    char *type;                 /* Port type as requested by user. */
};

/* A flow in dp_netdev's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its dp_netdev's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed by code that
 * holds a read-lock or write-lock on 'cls->rwlock' or that owns a reference to
 * 'flow->ref_cnt' (or both).  Code that needs to hold onto a flow for a while
 * should take 'cls->rwlock', find the flow it needs, increment 'flow->ref_cnt'
 * with dpif_netdev_flow_ref(), and drop 'cls->rwlock'.
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' (that's 'cls->rwlock') and it doesn't
 * protect members of 'flow' from modification (that's 'flow->mutex').
 *
 * 'flow->mutex' protects the members of 'flow' from modification.  It doesn't
 * protect the flow from being deleted from 'cls' (that's 'cls->rwlock') and it
 * doesn't prevent the flow from being freed (that's 'flow->ref_cnt').
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    /* Packet classification. */
    const struct cls_rule cr;   /* In owning dp_netdev's 'cls'. */

    /* Hash table index by unmasked flow. */
    const struct hmap_node node; /* In owning dp_netdev's 'flow_table'. */
    const struct flow flow;      /* The flow that created this entry. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    /* Protects members marked OVS_GUARDED.
     *
     * Acquire after datapath's flow_mutex. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(dp_netdev_mutex);

    /* Statistics.
     *
     * Reading or writing these members requires 'mutex'. */
    long long int used OVS_GUARDED; /* Last used time, in monotonic msecs. */
    long long int packet_count OVS_GUARDED; /* Number of packets matched. */
    long long int byte_count OVS_GUARDED;   /* Number of bytes matched. */
    uint16_t tcp_flags OVS_GUARDED; /* Bitwise-OR of seen tcp_flags values. */

    /* Actions.
     *
     * Reading 'actions' requires 'mutex'.
     * Writing 'actions' requires 'mutex' and (to allow for transactions) the
     * datapath's flow_mutex. */
    struct dp_netdev_actions *actions OVS_GUARDED;
};

static struct dp_netdev_flow *dp_netdev_flow_ref(
    const struct dp_netdev_flow *);
static void dp_netdev_flow_unref(struct dp_netdev_flow *);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' may be accessed without a risk of being
 * freed by code that holds a read-lock or write-lock on 'flow->mutex' (where
 * 'flow' is the dp_netdev_flow for which 'flow->actions == actions') or that
 * owns a reference to 'actions->ref_cnt' (or both). */
struct dp_netdev_actions {
    struct ovs_refcount ref_cnt;

    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    struct nlattr *actions;     /* Sequence of OVS_ACTION_ATTR_* attributes. */
    unsigned int size;          /* Size of 'actions', in bytes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_actions_ref(
    const struct dp_netdev_actions *);
void dp_netdev_actions_unref(struct dp_netdev_actions *);

/* A thread that receives packets from some ports, looks them up in the flow
 * table, and executes the actions it finds. */
struct dp_forwarder {
    struct dp_netdev *dp;
    pthread_t thread;
    char *name;
    uint32_t min_hash, max_hash;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int do_del_port(struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static int dp_netdev_output_userspace(struct dp_netdev *dp, struct ofpbuf *,
                                    int queue_no, const struct flow *,
                                    const struct nlattr *userdata)
    OVS_EXCLUDED(dp->queue_mutex);
static void dp_netdev_execute_actions(struct dp_netdev *dp,
                                      const struct flow *, struct ofpbuf *,
                                      struct pkt_metadata *,
                                      const struct nlattr *actions,
                                      size_t actions_len)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static void dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                                 struct pkt_metadata *)
    OVS_REQ_RDLOCK(dp->port_rwlock);
static void dp_netdev_set_threads(struct dp_netdev *, int n);

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif->dpif_class->open == dpif_netdev_open);
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

static int
dpif_netdev_enumerate(struct sset *all_dps)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy"
                  : "tap";
}

static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    uint32_t port_no;

    if (dp->class != &dpif_netdev_class) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev *dp;
    int error;
    int i;

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_netdevs, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_init(&dp->destroyed);

    ovs_mutex_init(&dp->flow_mutex);
    classifier_init(&dp->cls, NULL);
    hmap_init(&dp->flow_table);

    ovs_mutex_init(&dp->queue_mutex);
    ovs_mutex_lock(&dp->queue_mutex);
    for (i = 0; i < N_QUEUES; i++) {
        dp->queues[i].head = dp->queues[i].tail = 0;
    }
    ovs_mutex_unlock(&dp->queue_mutex);
    dp->queue_seq = seq_create();

    dp->n_hit = ovsthread_counter_create();
    dp->n_missed = ovsthread_counter_create();
    dp->n_lost = ovsthread_counter_create();

    ovs_rwlock_init(&dp->port_rwlock);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    latch_init(&dp->exit_latch);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = do_add_port(dp, name, "internal", ODPP_LOCAL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }
    dp_netdev_set_threads(dp, 2);

    *dpp = dp;
    return 0;
}

static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    } else {
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_netdev(dp);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_purge_queues(struct dp_netdev *dp)
{
    int i;

    ovs_mutex_lock(&dp->queue_mutex);
    for (i = 0; i < N_QUEUES; i++) {
        struct dp_netdev_queue *q = &dp->queues[i];

        while (q->tail != q->head) {
            struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];
            ofpbuf_uninit(&u->upcall.packet);
            ofpbuf_uninit(&u->buf);
        }
    }
    ovs_mutex_unlock(&dp->queue_mutex);
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;

    shash_find_and_delete(&dp_netdevs, dp->name);

    dp_netdev_set_threads(dp, 0);
    free(dp->forwarders);

    dp_netdev_flow_flush(dp);
    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port->port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
    ovsthread_counter_destroy(dp->n_hit);
    ovsthread_counter_destroy(dp->n_missed);
    ovsthread_counter_destroy(dp->n_lost);

    dp_netdev_purge_queues(dp);
    seq_destroy(dp->queue_seq);
    ovs_mutex_destroy(&dp->queue_mutex);

    classifier_destroy(&dp->cls);
    hmap_destroy(&dp->flow_table);
    ovs_mutex_destroy(&dp->flow_mutex);
    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    atomic_flag_destroy(&dp->destroyed);
    ovs_refcount_destroy(&dp->ref_cnt);
    latch_destroy(&dp->exit_latch);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_rwlock_rdlock(&dp->cls.rwlock);
    stats->n_flows = hmap_count(&dp->flow_table);
    ovs_rwlock_unlock(&dp->cls.rwlock);

    stats->n_hit = ovsthread_counter_read(dp->n_hit);
    stats->n_missed = ovsthread_counter_read(dp->n_missed);
    stats->n_lost = ovsthread_counter_read(dp->n_lost);
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    struct netdev *netdev;
    struct netdev_rx *rx;
    enum netdev_flags flags;
    const char *open_type;
    int error;

    /* XXX reject devices already in some dp_netdev. */

    /* Open and validate network device. */
    open_type = dpif_netdev_port_open_type(dp->class, type);
    error = netdev_open(devname, open_type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        netdev_close(netdev);
        return EINVAL;
    }

    error = netdev_rx_open(netdev, &rx);
    if (error
        && !(error == EOPNOTSUPP && dpif_netdev_class_is_dummy(dp->class))) {
        VLOG_ERR("%s: cannot receive packets on this network device (%s)",
                 devname, ovs_strerror(errno));
        netdev_close(netdev);
        return error;
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        netdev_rx_close(rx);
        netdev_close(netdev);
        return error;
    }

    port = xmalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->sf = sf;
    port->rx = rx;
    port->type = xstrdup(type);

    hmap_insert(&dp->ports, &port->node, hash_int(odp_to_u32(port_no), 0));
    seq_change(dp->port_seq);

    return 0;
}

static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (!error) {
        *port_nop = port_no;
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = port_no == ODPP_LOCAL ? EINVAL : do_del_port(dp, port_no);
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_IN_BUCKET (port, node, hash_int(odp_to_u32(port_no), 0),
                             &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENOENT;
    }
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }
    return ENOENT;
}

static int
do_del_port(struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        return error;
    }

    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);
    netdev_rx_close(port->rx);
    free(port->type);
    free(port);

    return 0;
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static void
dp_netdev_remove_flow(struct dp_netdev *dp, struct dp_netdev_flow *flow)
    OVS_REQ_WRLOCK(dp->cls.rwlock)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct cls_rule *cr = CONST_CAST(struct cls_rule *, &flow->cr);
    struct hmap_node *node = CONST_CAST(struct hmap_node *, &flow->node);

    classifier_remove(&dp->cls, cr);
    hmap_remove(&dp->flow_table, node);
    dp_netdev_flow_unref(flow);
}

static struct dp_netdev_flow *
dp_netdev_flow_ref(const struct dp_netdev_flow *flow_)
{
    struct dp_netdev_flow *flow = CONST_CAST(struct dp_netdev_flow *, flow_);
    if (flow) {
        ovs_refcount_ref(&flow->ref_cnt);
    }
    return flow;
}

static void
dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (flow && ovs_refcount_unref(&flow->ref_cnt) == 1) {
        cls_rule_destroy(CONST_CAST(struct cls_rule *, &flow->cr));
        ovs_mutex_lock(&flow->mutex);
        dp_netdev_actions_unref(flow->actions);
        ovs_mutex_unlock(&flow->mutex);
        ovs_mutex_destroy(&flow->mutex);
        free(flow);
    }
}

static void
dp_netdev_flow_flush(struct dp_netdev *dp)
{
    struct dp_netdev_flow *netdev_flow, *next;

    ovs_mutex_lock(&dp->flow_mutex);
    ovs_rwlock_wrlock(&dp->cls.rwlock);
    HMAP_FOR_EACH_SAFE (netdev_flow, next, node, &dp->flow_table) {
        dp_netdev_remove_flow(dp, netdev_flow);
    }
    ovs_rwlock_unlock(&dp->cls.rwlock);
    ovs_mutex_unlock(&dp->flow_mutex);
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_flow_flush(dp);
    return 0;
}

struct dp_netdev_port_state {
    uint32_t bucket;
    uint32_t offset;
    char *name;
};

static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    node = hmap_at_position(&dp->ports, &state->bucket, &state->offset);
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct cls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const struct flow *flow)
    OVS_EXCLUDED(dp->cls.rwlock)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_rwlock_rdlock(&dp->cls.rwlock);
    netdev_flow = dp_netdev_flow_cast(classifier_lookup(&dp->cls, flow, NULL));
    dp_netdev_flow_ref(netdev_flow);
    ovs_rwlock_unlock(&dp->cls.rwlock);

    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_find_flow(const struct dp_netdev *dp, const struct flow *flow)
    OVS_REQ_RDLOCK(dp->cls.rwlock)
{
    struct dp_netdev_flow *netdev_flow;

    HMAP_FOR_EACH_WITH_HASH (netdev_flow, node, flow_hash(flow, 0),
                             &dp->flow_table) {
        if (flow_equal(&netdev_flow->flow, flow)) {
            return dp_netdev_flow_ref(netdev_flow);
        }
    }

    return NULL;
}

static void
get_dpif_flow_stats(struct dp_netdev_flow *netdev_flow,
                    struct dpif_flow_stats *stats)
    OVS_REQ_RDLOCK(netdev_flow->mutex)
{
    stats->n_packets = netdev_flow->packet_count;
    stats->n_bytes = netdev_flow->byte_count;
    stats->used = netdev_flow->used;
    stats->tcp_flags = netdev_flow->tcp_flags;
}

static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow *mask)
{
    if (mask_key_len) {
        if (odp_flow_key_to_mask(mask_key, mask_key_len, mask, flow)) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true);
                VLOG_ERR("internal error parsing flow mask %s", ds_cstr(&s));
                ds_destroy(&s);
            }

            return EINVAL;
        }
        /* Force unwildcard the in_port. */
        mask->in_port.odp_port = u32_to_odp(UINT32_MAX);
    } else {
        enum mf_field_id id;
        /* No mask key, unwildcard everything except fields whose
         * prerequisities are not met. */
        memset(mask, 0x0, sizeof *mask);

        for (id = 0; id < MFF_N_IDS; ++id) {
            /* Skip registers and metadata. */
            if (!(id >= MFF_REG0 && id < MFF_REG0 + FLOW_N_REGS)
                && id != MFF_METADATA) {
                const struct mf_field *mf = mf_from_id(id);
                if (mf_are_prereqs_ok(mf, flow)) {
                    mf_mask_field(mf, mask);
                }
            }
        }
    }

    return 0;
}

static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow)
{
    odp_port_t in_port;

    if (odp_flow_key_to_flow(key, key_len, flow)) {
        /* This should not happen: it indicates that odp_flow_key_from_flow()
         * and odp_flow_key_to_flow() disagree on the acceptable form of a
         * flow.  Log the problem as an error, with enough details to enable
         * debugging. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
            VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
            ds_destroy(&s);
        }

        return EINVAL;
    }

    in_port = flow->in_port.odp_port;
    if (!is_valid_port_number(in_port) && in_port != ODPP_NONE) {
        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_get(const struct dpif *dpif,
                     const struct nlattr *nl_key, size_t nl_key_len,
                     struct ofpbuf **actionsp, struct dpif_flow_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(nl_key, nl_key_len, &key);
    if (error) {
        return error;
    }

    ovs_rwlock_rdlock(&dp->cls.rwlock);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    ovs_rwlock_unlock(&dp->cls.rwlock);

    if (netdev_flow) {
        struct dp_netdev_actions *actions = NULL;

        ovs_mutex_lock(&netdev_flow->mutex);
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
        if (actionsp) {
            actions = dp_netdev_actions_ref(netdev_flow->actions);
        }
        ovs_mutex_unlock(&netdev_flow->mutex);

        dp_netdev_flow_unref(netdev_flow);

        if (actionsp) {
            *actionsp = ofpbuf_clone_data(actions->actions, actions->size);
            dp_netdev_actions_unref(actions);
        }
    } else {
        error = ENOENT;
    }

    return error;
}

static int
dp_netdev_flow_add(struct dp_netdev *dp, const struct flow *flow,
                   const struct flow_wildcards *wc,
                   const struct nlattr *actions,
                   size_t actions_len)
    OVS_REQUIRES(dp->flow_mutex)
{
    struct dp_netdev_flow *netdev_flow;
    struct match match;

    netdev_flow = xzalloc(sizeof *netdev_flow);
    *CONST_CAST(struct flow *, &netdev_flow->flow) = *flow;
    ovs_refcount_init(&netdev_flow->ref_cnt);

    ovs_mutex_init(&netdev_flow->mutex);
    ovs_mutex_lock(&netdev_flow->mutex);

    netdev_flow->actions = dp_netdev_actions_create(actions, actions_len);

    match_init(&match, flow, wc);
    cls_rule_init(CONST_CAST(struct cls_rule *, &netdev_flow->cr),
                  &match, NETDEV_RULE_PRIORITY);
    ovs_rwlock_wrlock(&dp->cls.rwlock);
    classifier_insert(&dp->cls,
                      CONST_CAST(struct cls_rule *, &netdev_flow->cr));
    hmap_insert(&dp->flow_table,
                CONST_CAST(struct hmap_node *, &netdev_flow->node),
                flow_hash(flow, 0));
    ovs_rwlock_unlock(&dp->cls.rwlock);

    ovs_mutex_unlock(&netdev_flow->mutex);

    return 0;
}

static void
clear_stats(struct dp_netdev_flow *netdev_flow)
    OVS_REQUIRES(netdev_flow->mutex)
{
    netdev_flow->used = 0;
    netdev_flow->packet_count = 0;
    netdev_flow->byte_count = 0;
    netdev_flow->tcp_flags = 0;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    struct flow_wildcards wc;
    int error;

    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &flow);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &flow, &wc.masks);
    if (error) {
        return error;
    }

    ovs_mutex_lock(&dp->flow_mutex);
    netdev_flow = dp_netdev_lookup_flow(dp, &flow);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            if (hmap_count(&dp->flow_table) < MAX_FLOWS) {
                if (put->stats) {
                    memset(put->stats, 0, sizeof *put->stats);
                }
                error = dp_netdev_flow_add(dp, &flow, &wc, put->actions,
                                           put->actions_len);
            } else {
                error = EFBIG;
            }
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY
            && flow_equal(&flow, &netdev_flow->flow)) {
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            ovs_mutex_lock(&netdev_flow->mutex);
            old_actions = netdev_flow->actions;
            netdev_flow->actions = new_actions;
            if (put->stats) {
                get_dpif_flow_stats(netdev_flow, put->stats);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                clear_stats(netdev_flow);
            }
            ovs_mutex_unlock(&netdev_flow->mutex);

            dp_netdev_actions_unref(old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
        dp_netdev_flow_unref(netdev_flow);
    }
    ovs_mutex_unlock(&dp->flow_mutex);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(del->key, del->key_len, &key);
    if (error) {
        return error;
    }

    ovs_mutex_lock(&dp->flow_mutex);
    ovs_rwlock_wrlock(&dp->cls.rwlock);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    if (netdev_flow) {
        if (del->stats) {
            ovs_mutex_lock(&netdev_flow->mutex);
            get_dpif_flow_stats(netdev_flow, del->stats);
            ovs_mutex_unlock(&netdev_flow->mutex);
        }
        dp_netdev_remove_flow(dp, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_rwlock_unlock(&dp->cls.rwlock);
    ovs_mutex_unlock(&dp->flow_mutex);

    return error;
}

struct dp_netdev_flow_state {
    uint32_t bucket;
    uint32_t offset;
    struct dp_netdev_actions *actions;
    struct odputil_keybuf keybuf;
    struct odputil_keybuf maskbuf;
    struct dpif_flow_stats stats;
};

static int
dpif_netdev_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    struct dp_netdev_flow_state *state;

    *statep = state = xmalloc(sizeof *state);
    state->bucket = 0;
    state->offset = 0;
    state->actions = NULL;
    return 0;
}

static int
dpif_netdev_flow_dump_next(const struct dpif *dpif, void *state_,
                           const struct nlattr **key, size_t *key_len,
                           const struct nlattr **mask, size_t *mask_len,
                           const struct nlattr **actions, size_t *actions_len,
                           const struct dpif_flow_stats **stats)
{
    struct dp_netdev_flow_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct hmap_node *node;

    ovs_rwlock_rdlock(&dp->cls.rwlock);
    node = hmap_at_position(&dp->flow_table, &state->bucket, &state->offset);
    if (node) {
        netdev_flow = CONTAINER_OF(node, struct dp_netdev_flow, node);
        dp_netdev_flow_ref(netdev_flow);
    }
    ovs_rwlock_unlock(&dp->cls.rwlock);
    if (!node) {
        return EOF;
    }

    if (key) {
        struct ofpbuf buf;

        ofpbuf_use_stack(&buf, &state->keybuf, sizeof state->keybuf);
        odp_flow_key_from_flow(&buf, &netdev_flow->flow,
                               netdev_flow->flow.in_port.odp_port);

        *key = buf.data;
        *key_len = buf.size;
    }

    if (key && mask) {
        struct ofpbuf buf;
        struct flow_wildcards wc;

        ofpbuf_use_stack(&buf, &state->maskbuf, sizeof state->maskbuf);
        minimask_expand(&netdev_flow->cr.match.mask, &wc);
        odp_flow_key_from_mask(&buf, &wc.masks, &netdev_flow->flow,
                               odp_to_u32(wc.masks.in_port.odp_port));

        *mask = buf.data;
        *mask_len = buf.size;
    }

    if (actions || stats) {
        dp_netdev_actions_unref(state->actions);
        state->actions = NULL;

        ovs_mutex_lock(&netdev_flow->mutex);
        if (actions) {
            state->actions = dp_netdev_actions_ref(netdev_flow->actions);
            *actions = state->actions->actions;
            *actions_len = state->actions->size;
        }
        if (stats) {
            get_dpif_flow_stats(netdev_flow, &state->stats);
            *stats = &state->stats;
        }
        ovs_mutex_unlock(&netdev_flow->mutex);
    }

    dp_netdev_flow_unref(netdev_flow);

    return 0;
}

static int
dpif_netdev_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_flow_state *state = state_;

    dp_netdev_actions_unref(state->actions);
    free(state);
    return 0;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct pkt_metadata *md = &execute->md;
    struct flow key;

    if (execute->packet->size < ETH_HEADER_LEN ||
        execute->packet->size > UINT16_MAX) {
        return EINVAL;
    }

    /* Extract flow key. */
    flow_extract(execute->packet, md->skb_priority, md->pkt_mark, &md->tunnel,
                 (union flow_in_port *)&md->in_port, &key);

    ovs_rwlock_rdlock(&dp->port_rwlock);
    dp_netdev_execute_actions(dp, &key, execute->packet, md, execute->actions,
                              execute->actions_len);
    ovs_rwlock_unlock(&dp->port_rwlock);

    return 0;
}

static int
dpif_netdev_recv_set(struct dpif *dpif OVS_UNUSED, bool enable OVS_UNUSED)
{
    return 0;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}

static struct dp_netdev_queue *
find_nonempty_queue(struct dp_netdev *dp)
    OVS_REQUIRES(dp->queue_mutex)
{
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct dp_netdev_queue *q = &dp->queues[i];
        if (q->head != q->tail) {
            return q;
        }
    }
    return NULL;
}

static int
dpif_netdev_recv(struct dpif *dpif, struct dpif_upcall *upcall,
                 struct ofpbuf *buf)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_queue *q;
    int error;

    ovs_mutex_lock(&dp->queue_mutex);
    q = find_nonempty_queue(dp);
    if (q) {
        struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];

        *upcall = u->upcall;

        ofpbuf_uninit(buf);
        *buf = u->buf;

        error = 0;
    } else {
        error = EAGAIN;
    }
    ovs_mutex_unlock(&dp->queue_mutex);

    return error;
}

static void
dpif_netdev_recv_wait(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint64_t seq;

    ovs_mutex_lock(&dp->queue_mutex);
    seq = seq_read(dp->queue_seq);
    if (find_nonempty_queue(dp)) {
        poll_immediate_wake();
    } else {
        seq_wait(dp->queue_seq, seq);
    }
    ovs_mutex_unlock(&dp->queue_mutex);
}

static void
dpif_netdev_recv_purge(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);

    dp_netdev_purge_queues(dpif_netdev->dp);
}

/* Creates and returns a new 'struct dp_netdev_actions', with a reference count
 * of 1, whose actions are a copy of from the 'ofpacts_len' bytes of
 * 'ofpacts'. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions);
    ovs_refcount_init(&netdev_actions->ref_cnt);
    netdev_actions->actions = xmemdup(actions, size);
    netdev_actions->size = size;

    return netdev_actions;
}

/* Increments 'actions''s refcount. */
struct dp_netdev_actions *
dp_netdev_actions_ref(const struct dp_netdev_actions *actions_)
{
    struct dp_netdev_actions *actions;

    actions = CONST_CAST(struct dp_netdev_actions *, actions_);
    if (actions) {
        ovs_refcount_ref(&actions->ref_cnt);
    }
    return actions;
}

/* Decrements 'actions''s refcount and frees 'actions' if the refcount reaches
 * 0. */
void
dp_netdev_actions_unref(struct dp_netdev_actions *actions)
{
    if (actions && ovs_refcount_unref(&actions->ref_cnt) == 1) {
        free(actions->actions);
        free(actions);
    }
}

static void *
dp_forwarder_main(void *f_)
{
    struct dp_forwarder *f = f_;
    struct dp_netdev *dp = f->dp;
    struct ofpbuf packet;

    f->name = xasprintf("forwarder_%u", ovsthread_id_self());
    set_subprogram_name("%s", f->name);

    ofpbuf_init(&packet, 0);
    while (!latch_is_set(&dp->exit_latch)) {
        bool received_anything;
        int i;

        ovs_rwlock_rdlock(&dp->port_rwlock);
        for (i = 0; i < 50; i++) {
            struct dp_netdev_port *port;

            received_anything = false;
            HMAP_FOR_EACH (port, node, &f->dp->ports) {
                if (port->rx
                    && port->node.hash >= f->min_hash
                    && port->node.hash <= f->max_hash) {
                    int buf_size;
                    int error;
                    int mtu;

                    if (netdev_get_mtu(port->netdev, &mtu)) {
                        mtu = ETH_PAYLOAD_MAX;
                    }
                    buf_size = DP_NETDEV_HEADROOM + VLAN_ETH_HEADER_LEN + mtu;

                    ofpbuf_clear(&packet);
                    ofpbuf_reserve_with_tailroom(&packet, DP_NETDEV_HEADROOM,
                                                 buf_size);

                    error = netdev_rx_recv(port->rx, &packet);
                    if (!error) {
                        struct pkt_metadata md
                            = PKT_METADATA_INITIALIZER(port->port_no);
                        dp_netdev_port_input(dp, &packet, &md);

                        received_anything = true;
                    } else if (error != EAGAIN && error != EOPNOTSUPP) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(1, 5);

                        VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                                    netdev_get_name(port->netdev),
                                    ovs_strerror(error));
                    }
                }
            }

            if (!received_anything) {
                break;
            }
        }

        if (received_anything) {
            poll_immediate_wake();
        } else {
            struct dp_netdev_port *port;

            HMAP_FOR_EACH (port, node, &f->dp->ports)
                if (port->rx
                    && port->node.hash >= f->min_hash
                    && port->node.hash <= f->max_hash) {
                    netdev_rx_wait(port->rx);
                }
            seq_wait(dp->port_seq, seq_read(dp->port_seq));
            latch_wait(&dp->exit_latch);
        }
        ovs_rwlock_unlock(&dp->port_rwlock);

        poll_block();
    }
    ofpbuf_uninit(&packet);

    free(f->name);

    return NULL;
}

static void
dp_netdev_set_threads(struct dp_netdev *dp, int n)
{
    int i;

    if (n == dp->n_forwarders) {
        return;
    }

    /* Stop existing threads. */
    latch_set(&dp->exit_latch);
    for (i = 0; i < dp->n_forwarders; i++) {
        struct dp_forwarder *f = &dp->forwarders[i];

        xpthread_join(f->thread, NULL);
    }
    latch_poll(&dp->exit_latch);
    free(dp->forwarders);

    /* Start new threads. */
    dp->forwarders = xmalloc(n * sizeof *dp->forwarders);
    dp->n_forwarders = n;
    for (i = 0; i < n; i++) {
        struct dp_forwarder *f = &dp->forwarders[i];

        f->dp = dp;
        f->min_hash = UINT32_MAX / n * i;
        f->max_hash = UINT32_MAX / n * (i + 1) - 1;
        if (i == n - 1) {
            f->max_hash = UINT32_MAX;
        }
        xpthread_create(&f->thread, NULL, dp_forwarder_main, f);
    }
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow,
                    const struct ofpbuf *packet)
    OVS_REQUIRES(netdev_flow->mutex)
{
    netdev_flow->used = time_msec();
    netdev_flow->packet_count++;
    netdev_flow->byte_count += packet->size;
    netdev_flow->tcp_flags |= packet_get_tcp_flags(packet, &netdev_flow->flow);
}

static void
dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                     struct pkt_metadata *md)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow key;

    if (packet->size < ETH_HEADER_LEN) {
        return;
    }
    flow_extract(packet, md->skb_priority, md->pkt_mark, &md->tunnel,
                 (union flow_in_port *)&md->in_port, &key);
    netdev_flow = dp_netdev_lookup_flow(dp, &key);
    if (netdev_flow) {
        struct dp_netdev_actions *actions;

        ovs_mutex_lock(&netdev_flow->mutex);
        dp_netdev_flow_used(netdev_flow, packet);
        actions = dp_netdev_actions_ref(netdev_flow->actions);
        ovs_mutex_unlock(&netdev_flow->mutex);

        dp_netdev_execute_actions(dp, &key, packet, md,
                                  actions->actions, actions->size);
        dp_netdev_actions_unref(actions);
        ovsthread_counter_inc(dp->n_hit, 1);
    } else {
        ovsthread_counter_inc(dp->n_missed, 1);
        dp_netdev_output_userspace(dp, packet, DPIF_UC_MISS, &key, NULL);
    }
}

static int
dp_netdev_output_userspace(struct dp_netdev *dp, struct ofpbuf *packet,
                           int queue_no, const struct flow *flow,
                           const struct nlattr *userdata)
    OVS_EXCLUDED(dp->queue_mutex)
{
    struct dp_netdev_queue *q = &dp->queues[queue_no];
    int error;

    ovs_mutex_lock(&dp->queue_mutex);
    if (q->head - q->tail < MAX_QUEUE_LEN) {
        struct dp_netdev_upcall *u = &q->upcalls[q->head++ & QUEUE_MASK];
        struct dpif_upcall *upcall = &u->upcall;
        struct ofpbuf *buf = &u->buf;
        size_t buf_size;

        upcall->type = queue_no;

        /* Allocate buffer big enough for everything. */
        buf_size = ODPUTIL_FLOW_KEY_BYTES;
        if (userdata) {
            buf_size += NLA_ALIGN(userdata->nla_len);
        }
        ofpbuf_init(buf, buf_size);

        /* Put ODP flow. */
        odp_flow_key_from_flow(buf, flow, flow->in_port.odp_port);
        upcall->key = buf->data;
        upcall->key_len = buf->size;

        /* Put userdata. */
        if (userdata) {
            upcall->userdata = ofpbuf_put(buf, userdata,
                                          NLA_ALIGN(userdata->nla_len));
        }

        /* Steal packet data. */
        ovs_assert(packet->source == OFPBUF_MALLOC);
        upcall->packet = *packet;
        ofpbuf_use(packet, NULL, 0);

        seq_change(dp->queue_seq);

        error = 0;
    } else {
        ovsthread_counter_inc(dp->n_lost, 1);
        error = ENOBUFS;
    }
    ovs_mutex_unlock(&dp->queue_mutex);

    return error;
}

struct dp_netdev_execute_aux {
    struct dp_netdev *dp;
    const struct flow *key;
};

static void
dp_execute_cb(void *aux_, struct ofpbuf *packet,
              const struct pkt_metadata *md OVS_UNUSED,
              const struct nlattr *a, bool may_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    int type = nl_attr_type(a);
    struct dp_netdev_port *p;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        p = dp_netdev_lookup_port(aux->dp, u32_to_odp(nl_attr_get_u32(a)));
        if (p) {
            netdev_send(p->netdev, packet);
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE: {
        const struct nlattr *userdata;

        userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);

        /* Make a copy if we are not allowed to steal the packet's data. */
        if (!may_steal) {
            packet = ofpbuf_clone_with_headroom(packet, DP_NETDEV_HEADROOM);
        }
        dp_netdev_output_userspace(aux->dp, packet, DPIF_UC_ACTION, aux->key,
                                   userdata);
        if (!may_steal) {
            ofpbuf_uninit(packet);
        }
        break;
    }
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }
}

static void
dp_netdev_execute_actions(struct dp_netdev *dp, const struct flow *key,
                          struct ofpbuf *packet, struct pkt_metadata *md,
                          const struct nlattr *actions, size_t actions_len)
    OVS_REQ_RDLOCK(dp->port_rwlock)
{
    struct dp_netdev_execute_aux aux = {dp, key};

    odp_execute_actions(&aux, packet, md, actions, actions_len, dp_execute_cb);
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    NULL,                       /* run */
    NULL,                       /* wait */
    dpif_netdev_get_stats,
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_get,
    dpif_netdev_flow_put,
    dpif_netdev_flow_del,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_start,
    dpif_netdev_flow_dump_next,
    dpif_netdev_flow_dump_done,
    dpif_netdev_execute,
    NULL,                       /* operate */
    dpif_netdev_recv_set,
    dpif_netdev_queue_to_priority,
    dpif_netdev_recv,
    dpif_netdev_recv_wait,
    dpif_netdev_recv_purge,
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }
    hmap_remove(&dp->ports, &port->node);
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_int(odp_to_u32(port_no), 0));
    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_rwlock_unlock(&dp->port_rwlock);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

void
dpif_dummy_register(bool override)
{
    if (override) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (!dp_unregister_provider(type)) {
                dpif_dummy_register__(type);
            }
        }
        sset_destroy(&types);
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "DP PORT NEW-NUMBER",
                             3, 3, dpif_dummy_change_port_number, NULL);
}
