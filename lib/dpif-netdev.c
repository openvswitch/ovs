/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
enum { MAX_PORTS = 256 };       /* Maximum number of ports. */
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
    int open_cnt;
    bool destroyed;
    int max_mtu;                /* Maximum MTU of any port added so far. */

    struct dp_netdev_queue queues[N_QUEUES];
    struct classifier cls;      /* Classifier. */
    struct hmap flow_table;     /* Flow table. */
    struct seq *queue_seq;      /* Incremented whenever a packet is queued. */

    /* Statistics. */
    long long int n_hit;        /* Number of flow table matches. */
    long long int n_missed;     /* Number of flow table misses. */
    long long int n_lost;       /* Number of misses not passed to client. */

    /* Ports. */
    struct dp_netdev_port *ports[MAX_PORTS];
    struct list port_list;
    struct seq *port_seq;       /* Incremented whenever a port changes. */
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;         /* Index into dp_netdev's 'ports'. */
    struct list node;           /* Element in dp_netdev's 'port_list'. */
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
    struct nlattr *actions;
    size_t actions_len;
};

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
                                      struct ofpbuf *,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_port_input(struct dp_netdev *dp,
                                 struct dp_netdev_port *port,
                                 struct ofpbuf *packet);

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

    dp->open_cnt++;

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
                if (port_no > 0 && port_no < MAX_PORTS
                    && !dp->ports[port_no]) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no < MAX_PORTS; port_no++) {
        if (!dp->ports[port_no]) {
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
    dp->open_cnt = 0;
    dp->max_mtu = ETH_PAYLOAD_MAX;
    for (i = 0; i < N_QUEUES; i++) {
        dp->queues[i].head = dp->queues[i].tail = 0;
    }
    dp->queue_seq = seq_create();
    classifier_init(&dp->cls, NULL);
    hmap_init(&dp->flow_table);
    list_init(&dp->port_list);
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
    LIST_FOR_EACH_SAFE (port, next, node, &dp->port_list) {
        do_del_port(dp, port->port_no);
    }
    dp_netdev_purge_queues(dp);
    seq_destroy(dp->queue_seq);
    classifier_destroy(&dp->cls);
    hmap_destroy(&dp->flow_table);
    seq_destroy(dp->port_seq);
    free(dp->name);
    free(dp);
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);

    ovs_assert(dp->open_cnt > 0);
    if (--dp->open_cnt == 0 && dp->destroyed) {
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

    ovs_mutex_lock(&dp_netdev_mutex);
    dp->destroyed = true;
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    stats->n_flows = hmap_count(&dp->flow_table);
    stats->n_hit = dp->n_hit;
    stats->n_missed = dp->n_missed;
    stats->n_lost = dp->n_lost;
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
    int mtu;
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

    error = netdev_get_mtu(netdev, &mtu);
    if (!error && mtu > dp->max_mtu) {
        dp->max_mtu = mtu;
    }

    list_push_back(&dp->port_list, &port->node);
    dp->ports[odp_to_u32(port_no)] = port;
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
        uint32_t port_idx = odp_to_u32(*port_nop);
        if (port_idx >= MAX_PORTS) {
            error = EFBIG;
        } else if (dp->ports[port_idx]) {
            error = EBUSY;
        } else {
            error = 0;
            port_no = *port_nop;
        }
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
    return odp_to_u32(port_no) < MAX_PORTS;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp->ports[odp_to_u32(port_no)];
        return *portp ? 0 : ENOENT;
    }
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
{
    struct dp_netdev_port *port;

    LIST_FOR_EACH (port, node, &dp->port_list) {
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

    list_remove(&port->node);
    dp->ports[odp_to_u32(port_no)] = NULL;
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

static uint32_t
dpif_netdev_get_max_ports(const struct dpif *dpif OVS_UNUSED)
{
    return MAX_PORTS;
}

static void
dp_netdev_free_flow(struct dp_netdev *dp, struct dp_netdev_flow *netdev_flow)
{
    fat_rwlock_wrlock(&dp->cls.rwlock);
    classifier_remove(&dp->cls, &netdev_flow->cr);
    fat_rwlock_unlock(&dp->cls.rwlock);
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
    odp_port_t port_no;
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
    uint32_t port_idx;

    ovs_mutex_lock(&dp_netdev_mutex);
    for (port_idx = odp_to_u32(state->port_no);
         port_idx < MAX_PORTS; port_idx++) {
        struct dp_netdev_port *port = dp->ports[port_idx];
        if (port) {
            free(state->name);
            state->name = xstrdup(netdev_get_name(port->netdev));
            dpif_port->name = state->name;
            dpif_port->type = port->type;
            dpif_port->port_no = port->port_no;
            state->port_no = u32_to_odp(port_idx + 1);
            ovs_mutex_unlock(&dp_netdev_mutex);

            return 0;
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return EOF;
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

    fat_rwlock_wrlock(&dp->cls.rwlock);
    cr = classifier_lookup(&dp->cls, flow, NULL);
    fat_rwlock_unlock(&dp->cls.rwlock);

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

    /* Force unwildcard the in_port.
     *
     * We need to do this even in the case where we unwildcard "everything"
     * above because "everything" only includes the 16-bit OpenFlow port number
     * mask->in_port.ofp_port, which only covers half of the 32-bit datapath
     * port number mask->in_port.odp_port. */
    mask->in_port.odp_port = u32_to_odp(UINT32_MAX);

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
            *actionsp = ofpbuf_clone_data(netdev_flow->actions,
                                          netdev_flow->actions_len);
        }
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static int
set_flow_actions(struct dp_netdev_flow *netdev_flow,
                 const struct nlattr *actions, size_t actions_len)
{
    netdev_flow->actions = xrealloc(netdev_flow->actions, actions_len);
    netdev_flow->actions_len = actions_len;
    memcpy(netdev_flow->actions, actions, actions_len);
    return 0;
}

static int
dp_netdev_flow_add(struct dp_netdev *dp, const struct flow *flow,
                   const struct flow_wildcards *wc,
                   const struct nlattr *actions,
                   size_t actions_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct match match;
    int error;

    netdev_flow = xzalloc(sizeof *netdev_flow);
    netdev_flow->flow = *flow;

    match_init(&match, flow, wc);
    cls_rule_init(&netdev_flow->cr, &match, NETDEV_RULE_PRIORITY);
    fat_rwlock_wrlock(&dp->cls.rwlock);
    classifier_insert(&dp->cls, &netdev_flow->cr);
    fat_rwlock_unlock(&dp->cls.rwlock);

    error = set_flow_actions(netdev_flow, actions, actions_len);
    if (error) {
        fat_rwlock_wrlock(&dp->cls.rwlock);
        classifier_remove(&dp->cls, &netdev_flow->cr);
        fat_rwlock_unlock(&dp->cls.rwlock);
        cls_rule_destroy(&netdev_flow->cr);

        free(netdev_flow);
        return error;
    }

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
            error = set_flow_actions(netdev_flow, put->actions,
                                     put->actions_len);
            if (!error) {
                if (put->stats) {
                    get_dpif_flow_stats(netdev_flow, put->stats);
                }
                if (put->flags & DPIF_FP_ZERO_STATS) {
                    clear_stats(netdev_flow);
                }
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
    struct nlattr *actions;
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
        free(state->actions);
        state->actions = xmemdup(netdev_flow->actions,
                         netdev_flow->actions_len);

        *actions = state->actions;
        *actions_len = netdev_flow->actions_len;
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

    free(state->actions);
    free(state);
    return 0;
}

static int
dpif_netdev_execute(struct dpif *dpif, const struct dpif_execute *execute)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct flow md;
    int error;

    if (execute->packet->size < ETH_HEADER_LEN ||
        execute->packet->size > UINT16_MAX) {
        return EINVAL;
    }

    /* Get packet metadata. */
    error = dpif_netdev_flow_from_nlattrs(execute->key, execute->key_len, &md);
    if (!error) {
        struct flow key;

        /* Extract flow key. */
        flow_extract(execute->packet, md.skb_priority, md.pkt_mark, &md.tunnel,
                     &md.in_port, &key);
        ovs_mutex_lock(&dp_netdev_mutex);
        dp_netdev_execute_actions(dp, &key, execute->packet,
                                  execute->actions, execute->actions_len);
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
    return error;
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

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow,
                    const struct ofpbuf *packet,
                    const struct flow *key)
{
    netdev_flow->used = time_msec();
    netdev_flow->packet_count++;
    netdev_flow->byte_count += packet->size;
    netdev_flow->tcp_flags |= packet_get_tcp_flags(packet, key);
}

static void
dp_netdev_port_input(struct dp_netdev *dp, struct dp_netdev_port *port,
                     struct ofpbuf *packet)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow key;
    union flow_in_port in_port_;

    if (packet->size < ETH_HEADER_LEN) {
        return;
    }
    in_port_.odp_port = port->port_no;
    flow_extract(packet, 0, 0, NULL, &in_port_, &key);
    netdev_flow = dp_netdev_lookup_flow(dp, &key);
    if (netdev_flow) {
        dp_netdev_flow_used(netdev_flow, packet, &key);
        dp_netdev_execute_actions(dp, &key, packet,
                                  netdev_flow->actions,
                                  netdev_flow->actions_len);
        dp->n_hit++;
    } else {
        dp->n_missed++;
        dp_netdev_output_userspace(dp, packet, DPIF_UC_MISS, &key, NULL);
    }
}

static void
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    struct ofpbuf packet;
    size_t buf_size;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = get_dp_netdev(dpif);
    ofpbuf_init(&packet, 0);

    buf_size = DP_NETDEV_HEADROOM + VLAN_ETH_HEADER_LEN + dp->max_mtu;

    LIST_FOR_EACH (port, node, &dp->port_list) {
        int error;

        /* Reset packet contents. Packet data may have been stolen. */
        ofpbuf_clear(&packet);
        ofpbuf_reserve_with_tailroom(&packet, DP_NETDEV_HEADROOM, buf_size);

        error = port->rx ? netdev_rx_recv(port->rx, &packet) : EOPNOTSUPP;
        if (!error) {
            dp_netdev_port_input(dp, port, &packet);
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
    LIST_FOR_EACH (port, node, &get_dp_netdev(dpif)->port_list) {
        if (port->rx) {
            netdev_rx_wait(port->rx);
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
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
        dp->n_lost++;
        return ENOBUFS;
    }
}

struct dp_netdev_execute_aux {
    struct dp_netdev *dp;
    const struct flow *key;
};

static void
dp_netdev_action_output(void *aux_, struct ofpbuf *packet,
                        const struct flow *flow OVS_UNUSED,
                        odp_port_t out_port)
{
    struct dp_netdev_execute_aux *aux = aux_;
    struct dp_netdev_port *p = aux->dp->ports[odp_to_u32(out_port)];
    if (p) {
        netdev_send(p->netdev, packet);
    }
}

static void
dp_netdev_action_userspace(void *aux_, struct ofpbuf *packet,
                           const struct flow *flow OVS_UNUSED,
                           const struct nlattr *a, bool may_steal)
{
    struct dp_netdev_execute_aux *aux = aux_;
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
}

static void
dp_netdev_execute_actions(struct dp_netdev *dp, const struct flow *key,
                          struct ofpbuf *packet,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = {dp, key};
    struct flow md = *key;   /* Packet metadata, may be modified by actions. */

    odp_execute_actions(&aux, packet, &md, actions, actions_len,
                        dp_netdev_action_output, dp_netdev_action_userspace);
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
    dpif_netdev_get_max_ports,
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
    int port_no;

    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }

    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        return;
    }

    port_no = atoi(argv[3]);
    if (port_no <= 0 || port_no >= MAX_PORTS) {
        unixctl_command_reply_error(conn, "bad port number");
        return;
    }
    if (dp->ports[port_no]) {
        unixctl_command_reply_error(conn, "port number already in use");
        return;
    }
    dp->ports[odp_to_u32(port->port_no)] = NULL;
    dp->ports[port_no] = port;
    port->port_no = u32_to_odp(port_no);
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
