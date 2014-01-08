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

struct dp_netdev_upcall {
    struct dpif_upcall upcall;  /* Queued upcall information. */
    struct ofpbuf buf;          /* ofpbuf instance for upcall.packet. */
};

struct dp_netdev_queue {
    struct dp_netdev_upcall upcalls[MAX_QUEUE_LEN];
    unsigned int head, tail;
};

/* Datapath based on the network device interface from netdev.h. */
struct dp_netdev {
    const struct dpif_class *class;
    char *name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    struct dp_netdev_queue queues[N_QUEUES];
    struct classifier cls;      /* Classifier. */
    struct hmap flow_table;     /* Flow table. */
    struct seq *queue_seq;      /* Incremented whenever a packet is queued. */

    /* Statistics. */
    struct ovsthread_counter *n_hit;    /* Number of flow table matches. */
    struct ovsthread_counter *n_missed; /* Number of flow table misses. */
    struct ovsthread_counter *n_lost;   /* Number of misses not passed up. */

    /* Ports. */
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */
};

static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *,
                                                    odp_port_t);

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    odp_port_t port_no;
    struct netdev *netdev;
    struct netdev_saved_flags *sf;
    struct netdev_rx *rx;
    char *type;                 /* Port type as requested by user. */
};

/* A flow in dp_netdev's 'flow_table'. */
struct dp_netdev_flow {
    /* Packet classification. */
    struct cls_rule cr;         /* In owning dp_netdev's 'cls'. */

    /* Hash table index by unmasked flow.*/
    struct hmap_node node;      /* In owning dp_netdev's 'flow_table'. */
    struct flow flow;           /* The flow that created this entry. */

    /* Statistics. */
    long long int used;         /* Last used time, in monotonic msecs. */
    long long int packet_count; /* Number of packets matched. */
    long long int byte_count;   /* Number of bytes matched. */
    uint16_t tcp_flags;         /* Bitwise-OR of seen tcp_flags values. */

    /* Actions. */
    struct dp_netdev_actions *actions;
};

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

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

/* All netdev-based datapaths. */
static struct shash dp_netdevs = SHASH_INITIALIZER(&dp_netdevs);

/* Global lock for all data. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

static int get_port_by_number(struct dp_netdev *, odp_port_t port_no,
                              struct dp_netdev_port **portp);
static int get_port_by_name(struct dp_netdev *, const char *devname,
                            struct dp_netdev_port **portp);
static void dp_netdev_free(struct dp_netdev *);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *, const char *devname,
                       const char *type, odp_port_t port_no);
static int do_del_port(struct dp_netdev *, odp_port_t port_no);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static int dp_netdev_output_userspace(struct dp_netdev *, struct ofpbuf *,
                                    int queue_no, const struct flow *,
                                    const struct nlattr *userdata);
static void dp_netdev_execute_actions(struct dp_netdev *, const struct flow *,
                                      struct ofpbuf *, struct pkt_metadata *,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                                 struct pkt_metadata *md);

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
{
    struct dp_netdev *dp;
    int error;
    int i;

    dp = xzalloc(sizeof *dp);
    dp->class = class;
    dp->name = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_init(&dp->destroyed);
    for (i = 0; i < N_QUEUES; i++) {
        dp->queues[i].head = dp->queues[i].tail = 0;
    }
    dp->queue_seq = seq_create();
    classifier_init(&dp->cls, NULL);
    hmap_init(&dp->flow_table);

    dp->n_hit = ovsthread_counter_create();
    dp->n_missed = ovsthread_counter_create();
    dp->n_lost = ovsthread_counter_create();

    hmap_init(&dp->ports);
    dp->port_seq = seq_create();

    error = do_add_port(dp, name, "internal", ODPP_LOCAL);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    shash_add(&dp_netdevs, name, dp);

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

    for (i = 0; i < N_QUEUES; i++) {
        struct dp_netdev_queue *q = &dp->queues[i];

        while (q->tail != q->head) {
            struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];
            ofpbuf_uninit(&u->upcall.packet);
            ofpbuf_uninit(&u->buf);
        }
    }
}

static void
dp_netdev_free(struct dp_netdev *dp)
{
    struct dp_netdev_port *port, *next;

    dp_netdev_flow_flush(dp);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port->port_no);
    }
    ovsthread_counter_destroy(dp->n_hit);
    ovsthread_counter_destroy(dp->n_missed);
    ovsthread_counter_destroy(dp->n_lost);
    dp_netdev_purge_queues(dp);
    seq_destroy(dp->queue_seq);
    classifier_destroy(&dp->cls);
    hmap_destroy(&dp->flow_table);
    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    atomic_flag_destroy(&dp->destroyed);
    ovs_refcount_destroy(&dp->ref_cnt);
    free(dp->name);
    free(dp);
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);

    if (ovs_refcount_unref(&dp->ref_cnt) == 1) {
        shash_find_and_delete(&dp_netdevs, dp->name);
        dp_netdev_free(dp);
    }
    free(dpif);

    ovs_mutex_unlock(&dp_netdev_mutex);
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

    ovs_mutex_lock(&dp_netdev_mutex);
    stats->n_flows = hmap_count(&dp->flow_table);
    stats->n_hit = ovsthread_counter_read(dp->n_hit);
    stats->n_missed = ovsthread_counter_read(dp->n_missed);
    stats->n_lost = ovsthread_counter_read(dp->n_lost);
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
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

    ovs_mutex_lock(&dp_netdev_mutex);
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
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    error = port_no == ODPP_LOCAL ? EINVAL : do_del_port(dp, port_no);
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
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

    ovs_mutex_lock(&dp_netdev_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_free_flow(struct dp_netdev *dp, struct dp_netdev_flow *netdev_flow)
{
    ovs_rwlock_wrlock(&dp->cls.rwlock);
    classifier_remove(&dp->cls, &netdev_flow->cr);
    ovs_rwlock_unlock(&dp->cls.rwlock);
    cls_rule_destroy(&netdev_flow->cr);

    hmap_remove(&dp->flow_table, &netdev_flow->node);
    free(netdev_flow->actions);
    free(netdev_flow);
}

static void
dp_netdev_flow_flush(struct dp_netdev *dp)
{
    struct dp_netdev_flow *netdev_flow, *next;

    HMAP_FOR_EACH_SAFE (netdev_flow, next, node, &dp->flow_table) {
        dp_netdev_free_flow(dp, netdev_flow);
    }
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    dp_netdev_flow_flush(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);

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

    ovs_mutex_lock(&dp_netdev_mutex);
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
    ovs_mutex_unlock(&dp_netdev_mutex);

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

    ovs_mutex_lock(&dp_netdev_mutex);
    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    ovs_mutex_lock(&dp_netdev_mutex);
    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
    ovs_mutex_unlock(&dp_netdev_mutex);
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const struct flow *flow)
{
    struct cls_rule *cr;

    ovs_rwlock_wrlock(&dp->cls.rwlock);
    cr = classifier_lookup(&dp->cls, flow, NULL);
    ovs_rwlock_unlock(&dp->cls.rwlock);

    return (cr
            ? CONTAINER_OF(cr, struct dp_netdev_flow, cr)
            : NULL);
}

static struct dp_netdev_flow *
dp_netdev_find_flow(const struct dp_netdev *dp, const struct flow *flow)
{
    struct dp_netdev_flow *netdev_flow;

    HMAP_FOR_EACH_WITH_HASH (netdev_flow, node, flow_hash(flow, 0),
                             &dp->flow_table) {
        if (flow_equal(&netdev_flow->flow, flow)) {
            return netdev_flow;
        }
    }
    return NULL;
}

static void
get_dpif_flow_stats(struct dp_netdev_flow *netdev_flow,
                    struct dpif_flow_stats *stats)
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

    ovs_mutex_lock(&dp_netdev_mutex);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
        if (actionsp) {
            *actionsp = ofpbuf_clone_data(netdev_flow->actions->actions,
                                          netdev_flow->actions->size);
        }
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static int
dp_netdev_flow_add(struct dp_netdev *dp, const struct flow *flow,
                   const struct flow_wildcards *wc,
                   const struct nlattr *actions,
                   size_t actions_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct match match;

    netdev_flow = xzalloc(sizeof *netdev_flow);
    netdev_flow->flow = *flow;
    netdev_flow->actions = dp_netdev_actions_create(actions, actions_len);

    match_init(&match, flow, wc);
    cls_rule_init(&netdev_flow->cr, &match, NETDEV_RULE_PRIORITY);
    ovs_rwlock_wrlock(&dp->cls.rwlock);
    classifier_insert(&dp->cls, &netdev_flow->cr);
    ovs_rwlock_unlock(&dp->cls.rwlock);

    hmap_insert(&dp->flow_table, &netdev_flow->node, flow_hash(flow, 0));
    return 0;
}

static void
clear_stats(struct dp_netdev_flow *netdev_flow)
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

    ovs_mutex_lock(&dp_netdev_mutex);
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
            dp_netdev_actions_unref(netdev_flow->actions);
            netdev_flow->actions = dp_netdev_actions_create(put->actions,
                                                            put->actions_len);
            if (put->stats) {
                get_dpif_flow_stats(netdev_flow, put->stats);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                clear_stats(netdev_flow);
            }
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

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

    ovs_mutex_lock(&dp_netdev_mutex);
    netdev_flow = dp_netdev_find_flow(dp, &key);
    if (netdev_flow) {
        if (del->stats) {
            get_dpif_flow_stats(netdev_flow, del->stats);
        }
        dp_netdev_free_flow(dp, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

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

    ovs_mutex_lock(&dp_netdev_mutex);
    node = hmap_at_position(&dp->flow_table, &state->bucket, &state->offset);
    if (!node) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        return EOF;
    }

    netdev_flow = CONTAINER_OF(node, struct dp_netdev_flow, node);

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

    if (actions) {
        dp_netdev_actions_unref(state->actions);
        state->actions = dp_netdev_actions_ref(netdev_flow->actions);
        *actions = state->actions->actions;
        *actions_len = state->actions->size;
    }

    if (stats) {
        get_dpif_flow_stats(netdev_flow, &state->stats);
        *stats = &state->stats;
    }

    ovs_mutex_unlock(&dp_netdev_mutex);
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
    ovs_mutex_lock(&dp_netdev_mutex);
    dp_netdev_execute_actions(dp, &key, execute->packet, md, execute->actions,
                              execute->actions_len);
    ovs_mutex_unlock(&dp_netdev_mutex);
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
find_nonempty_queue(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
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
    struct dp_netdev_queue *q;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    q = find_nonempty_queue(dpif);
    if (q) {
        struct dp_netdev_upcall *u = &q->upcalls[q->tail++ & QUEUE_MASK];

        *upcall = u->upcall;

        ofpbuf_uninit(buf);
        *buf = u->buf;

        error = 0;
    } else {
        error = EAGAIN;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dpif_netdev_recv_wait(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint64_t seq;

    ovs_mutex_lock(&dp_netdev_mutex);
    seq = seq_read(dp->queue_seq);
    if (find_nonempty_queue(dpif)) {
        poll_immediate_wake();
    } else {
        seq_wait(dp->queue_seq, seq);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
}

static void
dpif_netdev_recv_purge(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    ovs_mutex_lock(&dp_netdev_mutex);
    dp_netdev_purge_queues(dpif_netdev->dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
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

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow,
                    const struct ofpbuf *packet)
{
    netdev_flow->used = time_msec();
    netdev_flow->packet_count++;
    netdev_flow->byte_count += packet->size;
    netdev_flow->tcp_flags |= packet_get_tcp_flags(packet, &netdev_flow->flow);
}

static void
dp_netdev_port_input(struct dp_netdev *dp, struct ofpbuf *packet,
                     struct pkt_metadata *md)
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

        dp_netdev_flow_used(netdev_flow, packet);
        actions = dp_netdev_actions_ref(netdev_flow->actions);
        dp_netdev_execute_actions(dp, &key, packet, md,
                                  actions->actions, actions->size);
        dp_netdev_actions_unref(actions);
        ovsthread_counter_inc(dp->n_hit, 1);
    } else {
        ovsthread_counter_inc(dp->n_missed, 1);
        dp_netdev_output_userspace(dp, packet, DPIF_UC_MISS, &key, NULL);
    }
}

static void
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    struct ofpbuf packet;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = get_dp_netdev(dpif);
    ofpbuf_init(&packet, 0);

    HMAP_FOR_EACH (port, node, &dp->ports) {
        int buf_size;
        int error;
        int mtu;

        error = netdev_get_mtu(port->netdev, &mtu);
        if (error) {
            mtu = ETH_PAYLOAD_MAX;
        }
        buf_size = DP_NETDEV_HEADROOM + VLAN_ETH_HEADER_LEN + mtu;

        ofpbuf_clear(&packet);
        ofpbuf_reserve_with_tailroom(&packet, DP_NETDEV_HEADROOM, buf_size);

        error = port->rx ? netdev_rx_recv(port->rx, &packet) : EOPNOTSUPP;
        if (!error) {
            struct pkt_metadata md = PKT_METADATA_INITIALIZER(port->port_no);
            dp_netdev_port_input(dp, &packet, &md);
        } else if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                        netdev_get_name(port->netdev), ovs_strerror(error));
        }
    }
    ofpbuf_uninit(&packet);
    ovs_mutex_unlock(&dp_netdev_mutex);
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;

    /* There is a race here, if thread A calls dpif_netdev_wait(dpif) and
     * thread B calls dpif_port_add(dpif) or dpif_port_remove(dpif) before
     * A makes it to poll_block().
     *
     * But I think it doesn't matter:
     *
     *     - In the dpif_port_add() case, A will not wake up when a packet
     *       arrives on the new port, but this would also happen if the
     *       ordering were reversed.
     *
     *     - In the dpif_port_remove() case, A might wake up spuriously, but
     *       that is harmless. */

    ovs_mutex_lock(&dp_netdev_mutex);
    HMAP_FOR_EACH (port, node, &get_dp_netdev(dpif)->ports) {
        if (port->rx) {
            netdev_rx_wait(port->rx);
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
}

static void
dp_netdev_output_port(struct dp_netdev *dp, struct ofpbuf *packet,
                      odp_port_t out_port)
{
    struct dp_netdev_port *p = dp_netdev_lookup_port(dp, out_port);
    if (p) {
        netdev_send(p->netdev, packet);
    }
}

static int
dp_netdev_output_userspace(struct dp_netdev *dp, struct ofpbuf *packet,
                           int queue_no, const struct flow *flow,
                           const struct nlattr *userdata)
{
    struct dp_netdev_queue *q = &dp->queues[queue_no];
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

        return 0;
    } else {
        ovsthread_counter_inc(dp->n_lost, 1);
        return ENOBUFS;
    }
}

struct dp_netdev_execute_aux {
    struct dp_netdev *dp;
    const struct flow *key;
};

static void
dp_execute_cb(void *aux_, struct ofpbuf *packet,
              const struct pkt_metadata *md OVS_UNUSED,
              const struct nlattr *a, bool may_steal)
{
    struct dp_netdev_execute_aux *aux = aux_;
    int type = nl_attr_type(a);

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        dp_netdev_output_port(aux->dp, packet, u32_to_odp(nl_attr_get_u32(a)));
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
    dpif_netdev_run,
    dpif_netdev_wait,
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

    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }

    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        return;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        return;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        return;
    }
    hmap_remove(&dp->ports, &port->node);
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_int(odp_to_u32(port_no), 0));
    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);
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
