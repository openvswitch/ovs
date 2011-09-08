/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#include <assert.h>
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

#include "csum.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

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

struct dp_netdev_queue {
    struct dpif_upcall *upcalls[MAX_QUEUE_LEN];
    unsigned int head, tail;
};

/* Datapath based on the network device interface from netdev.h. */
struct dp_netdev {
    const struct dpif_class *class;
    char *name;
    int open_cnt;
    bool destroyed;

    bool drop_frags;            /* Drop all IP fragments, if true. */
    struct dp_netdev_queue queues[N_QUEUES];
    struct hmap flow_table;     /* Flow table. */

    /* Statistics. */
    long long int n_frags;      /* Number of dropped IP fragments. */
    long long int n_hit;        /* Number of flow table matches. */
    long long int n_missed;     /* Number of flow table misses. */
    long long int n_lost;       /* Number of misses not passed to client. */

    /* Ports. */
    int n_ports;
    struct dp_netdev_port *ports[MAX_PORTS];
    struct list port_list;
    unsigned int serial;
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    int port_no;                /* Index into dp_netdev's 'ports'. */
    struct list node;           /* Element in dp_netdev's 'port_list'. */
    struct netdev *netdev;
    bool internal;              /* Internal port? */
};

/* A flow in dp_netdev's 'flow_table'. */
struct dp_netdev_flow {
    struct hmap_node node;      /* Element in dp_netdev's 'flow_table'. */
    struct flow key;

    /* Statistics. */
    long long int used;         /* Last used time, in monotonic msecs. */
    long long int packet_count; /* Number of packets matched. */
    long long int byte_count;   /* Number of bytes matched. */
    ovs_be16 tcp_ctl;           /* Bitwise-OR of seen tcp_ctl values. */

    /* Actions. */
    struct nlattr *actions;
    size_t actions_len;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    int listen_mask;
    unsigned int dp_serial;
};

/* All netdev-based datapaths. */
static struct shash dp_netdevs = SHASH_INITIALIZER(&dp_netdevs);

/* Maximum port MTU seen so far. */
static int max_mtu = ETH_PAYLOAD_MAX;

static int get_port_by_number(struct dp_netdev *, uint16_t port_no,
                              struct dp_netdev_port **portp);
static int get_port_by_name(struct dp_netdev *, const char *devname,
                            struct dp_netdev_port **portp);
static void dp_netdev_free(struct dp_netdev *);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *, const char *devname,
                       const char *type, uint16_t port_no);
static int do_del_port(struct dp_netdev *, uint16_t port_no);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static int dp_netdev_output_userspace(struct dp_netdev *, const struct ofpbuf *,
                                    int queue_no, const struct flow *,
                                    uint64_t arg);
static int dp_netdev_execute_actions(struct dp_netdev *,
                                     struct ofpbuf *, struct flow *,
                                     const struct nlattr *actions,
                                     size_t actions_len);

static struct dpif_class dpif_dummy_class;

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    assert(dpif->dpif_class->open == dpif_netdev_open);
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
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
    dpif->listen_mask = 0;
    dpif->dp_serial = dp->serial;

    return &dpif->dpif;
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
    dp->drop_frags = false;
    for (i = 0; i < N_QUEUES; i++) {
        dp->queues[i].head = dp->queues[i].tail = 0;
    }
    hmap_init(&dp->flow_table);
    list_init(&dp->port_list);
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

    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        if (!create) {
            return ENODEV;
        } else {
            int error = create_dp_netdev(name, class, &dp);
            if (error) {
                return error;
            }
            assert(dp != NULL);
        }
    } else {
        if (dp->class != class) {
            return EINVAL;
        } else if (create) {
            return EEXIST;
        }
    }

    *dpifp = create_dpif_netdev(dp);
    return 0;
}

static void
dp_netdev_purge_queues(struct dp_netdev *dp)
{
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct dp_netdev_queue *q = &dp->queues[i];

        while (q->tail != q->head) {
            struct dpif_upcall *upcall = q->upcalls[q->tail++ & QUEUE_MASK];

            ofpbuf_delete(upcall->packet);
            free(upcall);
        }
    }
}

static void
dp_netdev_free(struct dp_netdev *dp)
{
    dp_netdev_flow_flush(dp);
    while (dp->n_ports > 0) {
        struct dp_netdev_port *port = CONTAINER_OF(
            dp->port_list.next, struct dp_netdev_port, node);
        do_del_port(dp, port->port_no);
    }
    dp_netdev_purge_queues(dp);
    hmap_destroy(&dp->flow_table);
    free(dp->name);
    free(dp);
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    assert(dp->open_cnt > 0);
    if (--dp->open_cnt == 0 && dp->destroyed) {
        shash_find_and_delete(&dp_netdevs, dp->name);
        dp_netdev_free(dp);
    }
    free(dpif);
}

static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->destroyed = true;
    return 0;
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct odp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    memset(stats, 0, sizeof *stats);
    stats->n_frags = dp->n_frags;
    stats->n_hit = dp->n_hit;
    stats->n_missed = dp->n_missed;
    stats->n_lost = dp->n_lost;
    return 0;
}

static int
dpif_netdev_get_drop_frags(const struct dpif *dpif, bool *drop_fragsp)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *drop_fragsp = dp->drop_frags;
    return 0;
}

static int
dpif_netdev_set_drop_frags(struct dpif *dpif, bool drop_frags)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->drop_frags = drop_frags;
    return 0;
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            uint16_t port_no)
{
    struct dp_netdev_port *port;
    struct netdev_options netdev_options;
    struct netdev *netdev;
    bool internal;
    int mtu;
    int error;

    /* XXX reject devices already in some dp_netdev. */
    if (type[0] == '\0' || !strcmp(type, "system")) {
        internal = false;
    } else if (!strcmp(type, "internal")) {
        internal = true;
    } else {
        VLOG_WARN("%s: unsupported port type %s", devname, type);
        return EINVAL;
    }

    /* Open and validate network device. */
    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = devname;
    netdev_options.ethertype = NETDEV_ETH_TYPE_ANY;
    if (dp->class == &dpif_dummy_class) {
        netdev_options.type = "dummy";
    } else if (internal) {
        netdev_options.type = "tap";
    }

    error = netdev_open(&netdev_options, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject loopback devices */
    /* XXX reject non-Ethernet devices */

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, false);
    if (error) {
        netdev_close(netdev);
        return error;
    }

    port = xmalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->internal = internal;

    netdev_get_mtu(netdev, &mtu);
    if (mtu != INT_MAX && mtu > max_mtu) {
        max_mtu = mtu;
    }

    list_push_back(&dp->port_list, &port->node);
    dp->ports[port_no] = port;
    dp->n_ports++;
    dp->serial++;

    return 0;
}

static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     uint16_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int port_no;

    for (port_no = 0; port_no < MAX_PORTS; port_no++) {
        if (!dp->ports[port_no]) {
            *port_nop = port_no;
            return do_add_port(dp, netdev_get_name(netdev),
                               netdev_get_type(netdev), port_no);
        }
    }
    return EFBIG;
}

static int
dpif_netdev_port_del(struct dpif *dpif, uint16_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return port_no == ODPP_LOCAL ? EINVAL : do_del_port(dp, port_no);
}

static bool
is_valid_port_number(uint16_t port_no)
{
    return port_no < MAX_PORTS;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   uint16_t port_no, struct dp_netdev_port **portp)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp->ports[port_no];
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
do_del_port(struct dp_netdev *dp, uint16_t port_no)
{
    struct dp_netdev_port *port;
    char *name;
    int error;

    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        return error;
    }

    list_remove(&port->node);
    dp->ports[port->port_no] = NULL;
    dp->n_ports--;
    dp->serial++;

    name = xstrdup(netdev_get_name(port->netdev));
    netdev_close(port->netdev);

    free(name);
    free(port);

    return 0;
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->internal ? "internal" : "system");
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_number(dp, port_no, &port);
    if (!error) {
        answer_port_query(port, dpif_port);
    }
    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_name(dp, devname, &port);
    if (!error) {
        answer_port_query(port, dpif_port);
    }
    return error;
}

static int
dpif_netdev_get_max_ports(const struct dpif *dpif OVS_UNUSED)
{
    return MAX_PORTS;
}

static void
dp_netdev_free_flow(struct dp_netdev *dp, struct dp_netdev_flow *flow)
{
    hmap_remove(&dp->flow_table, &flow->node);
    free(flow->actions);
    free(flow);
}

static void
dp_netdev_flow_flush(struct dp_netdev *dp)
{
    struct dp_netdev_flow *flow, *next;

    HMAP_FOR_EACH_SAFE (flow, next, node, &dp->flow_table) {
        dp_netdev_free_flow(dp, flow);
    }
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_flow_flush(dp);
    return 0;
}

struct dp_netdev_port_state {
    uint32_t port_no;
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
    uint32_t port_no;

    for (port_no = state->port_no; port_no < MAX_PORTS; port_no++) {
        struct dp_netdev_port *port = dp->ports[port_no];
        if (port) {
            free(state->name);
            state->name = xstrdup(netdev_get_name(port->netdev));
            dpif_port->name = state->name;
            dpif_port->type = port->internal ? "internal" : "system";
            dpif_port->port_no = port->port_no;
            state->port_no = port_no + 1;
            return 0;
        }
    }
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
    if (dpif->dp_serial != dpif->dp->serial) {
        dpif->dp_serial = dpif->dp->serial;
        return ENOBUFS;
    } else {
        return EAGAIN;
    }
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    if (dpif->dp_serial != dpif->dp->serial) {
        poll_immediate_wake();
    }
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const struct flow *key)
{
    struct dp_netdev_flow *flow;

    HMAP_FOR_EACH_WITH_HASH (flow, node, flow_hash(key, 0), &dp->flow_table) {
        if (flow_equal(&flow->key, key)) {
            return flow;
        }
    }
    return NULL;
}

static void
get_dpif_flow_stats(struct dp_netdev_flow *flow, struct dpif_flow_stats *stats)
{
    stats->n_packets = flow->packet_count;
    stats->n_bytes = flow->byte_count;
    stats->used = flow->used;
    stats->tcp_flags = TCP_FLAGS(flow->tcp_ctl);
}

static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow)
{
    if (odp_flow_key_to_flow(key, key_len, flow)) {
        /* This should not happen: it indicates that odp_flow_key_from_flow()
         * and odp_flow_key_to_flow() disagree on the acceptable form of a
         * flow.  Log the problem as an error, with enough details to enable
         * debugging. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!VLOG_DROP_ERR(&rl)) {
            struct ds s;

            ds_init(&s);
            odp_flow_key_format(key, key_len, &s);
            VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
            ds_destroy(&s);
        }

        return EINVAL;
    }

    if (flow->in_port < OFPP_MAX
        ? flow->in_port >= MAX_PORTS
        : flow->in_port != OFPP_LOCAL && flow->in_port != OFPP_NONE) {
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
    struct dp_netdev_flow *flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(nl_key, nl_key_len, &key);
    if (error) {
        return error;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (!flow) {
        return ENOENT;
    }

    if (stats) {
        get_dpif_flow_stats(flow, stats);
    }
    if (actionsp) {
        *actionsp = ofpbuf_clone_data(flow->actions, flow->actions_len);
    }
    return 0;
}

static int
dpif_netdev_validate_actions(const struct nlattr *actions,
                             size_t actions_len, bool *mutates)
{
    const struct nlattr *a;
    unsigned int left;

    *mutates = false;
    NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
        uint16_t type = nl_attr_type(a);
        int len = odp_action_len(type);

        if (len != nl_attr_get_size(a)) {
            return EINVAL;
        }

        switch (type) {
        case ODP_ACTION_ATTR_OUTPUT:
            if (nl_attr_get_u32(a) >= MAX_PORTS) {
                return EINVAL;
            }
            break;

        case ODP_ACTION_ATTR_USERSPACE:
            break;

        case ODP_ACTION_ATTR_SET_DL_TCI:
            *mutates = true;
            if (nl_attr_get_be16(a) & htons(VLAN_CFI)) {
                return EINVAL;
            }
            break;

        case ODP_ACTION_ATTR_SET_NW_TOS:
            *mutates = true;
            if (nl_attr_get_u8(a) & IP_ECN_MASK) {
                return EINVAL;
            }
            break;

        case ODP_ACTION_ATTR_STRIP_VLAN:
        case ODP_ACTION_ATTR_SET_DL_SRC:
        case ODP_ACTION_ATTR_SET_DL_DST:
        case ODP_ACTION_ATTR_SET_NW_SRC:
        case ODP_ACTION_ATTR_SET_NW_DST:
        case ODP_ACTION_ATTR_SET_TP_SRC:
        case ODP_ACTION_ATTR_SET_TP_DST:
            *mutates = true;
            break;

        case ODP_ACTION_ATTR_SET_TUNNEL:
        case ODP_ACTION_ATTR_SET_PRIORITY:
        case ODP_ACTION_ATTR_POP_PRIORITY:
        default:
            return EOPNOTSUPP;
        }
    }
    return 0;
}

static int
set_flow_actions(struct dp_netdev_flow *flow,
                 const struct nlattr *actions, size_t actions_len)
{
    bool mutates;
    int error;

    error = dpif_netdev_validate_actions(actions, actions_len, &mutates);
    if (error) {
        return error;
    }

    flow->actions = xrealloc(flow->actions, actions_len);
    flow->actions_len = actions_len;
    memcpy(flow->actions, actions, actions_len);
    return 0;
}

static int
add_flow(struct dpif *dpif, const struct flow *key,
         const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    int error;

    flow = xzalloc(sizeof *flow);
    flow->key = *key;

    error = set_flow_actions(flow, actions, actions_len);
    if (error) {
        free(flow);
        return error;
    }

    hmap_insert(&dp->flow_table, &flow->node, flow_hash(&flow->key, 0));
    return 0;
}

static void
clear_stats(struct dp_netdev_flow *flow)
{
    flow->used = 0;
    flow->packet_count = 0;
    flow->byte_count = 0;
    flow->tcp_ctl = 0;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, enum dpif_flow_put_flags flags,
                    const struct nlattr *nl_key, size_t nl_key_len,
                    const struct nlattr *actions, size_t actions_len,
                    struct dpif_flow_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(nl_key, nl_key_len, &key);
    if (error) {
        return error;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (!flow) {
        if (flags & DPIF_FP_CREATE) {
            if (hmap_count(&dp->flow_table) < MAX_FLOWS) {
                if (stats) {
                    memset(stats, 0, sizeof *stats);
                }
                return add_flow(dpif, &key, actions, actions_len);
            } else {
                return EFBIG;
            }
        } else {
            return ENOENT;
        }
    } else {
        if (flags & DPIF_FP_MODIFY) {
            int error = set_flow_actions(flow, actions, actions_len);
            if (!error) {
                if (stats) {
                    get_dpif_flow_stats(flow, stats);
                }
                if (flags & DPIF_FP_ZERO_STATS) {
                    clear_stats(flow);
                }
            }
            return error;
        } else {
            return EEXIST;
        }
    }
}

static int
dpif_netdev_flow_del(struct dpif *dpif,
                     const struct nlattr *nl_key, size_t nl_key_len,
                     struct dpif_flow_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(nl_key, nl_key_len, &key);
    if (error) {
        return error;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (flow) {
        if (stats) {
            get_dpif_flow_stats(flow, stats);
        }
        dp_netdev_free_flow(dp, flow);
        return 0;
    } else {
        return ENOENT;
    }
}

struct dp_netdev_flow_state {
    uint32_t bucket;
    uint32_t offset;
    struct nlattr *actions;
    struct odputil_keybuf keybuf;
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
                           const struct nlattr **actions, size_t *actions_len,
                           const struct dpif_flow_stats **stats)
{
    struct dp_netdev_flow_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct hmap_node *node;

    node = hmap_at_position(&dp->flow_table, &state->bucket, &state->offset);
    if (!node) {
        return EOF;
    }

    flow = CONTAINER_OF(node, struct dp_netdev_flow, node);

    if (key) {
        struct ofpbuf buf;

        ofpbuf_use_stack(&buf, &state->keybuf, sizeof state->keybuf);
        odp_flow_key_from_flow(&buf, &flow->key);

        *key = buf.data;
        *key_len = buf.size;
    }

    if (actions) {
        free(state->actions);
        state->actions = xmemdup(flow->actions, flow->actions_len);

        *actions = state->actions;
        *actions_len = flow->actions_len;
    }

    if (stats) {
        get_dpif_flow_stats(flow, &state->stats);
        *stats = &state->stats;
    }

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
dpif_netdev_execute(struct dpif *dpif,
                    const struct nlattr *key_attrs, size_t key_len,
                    const struct nlattr *actions, size_t actions_len,
                    const struct ofpbuf *packet)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct ofpbuf copy;
    bool mutates;
    struct flow key;
    int error;

    if (packet->size < ETH_HEADER_LEN || packet->size > UINT16_MAX) {
        return EINVAL;
    }

    error = dpif_netdev_validate_actions(actions, actions_len, &mutates);
    if (error) {
        return error;
    }

    if (mutates) {
        /* We need a deep copy of 'packet' since we're going to modify its
         * data. */
        ofpbuf_init(&copy, DP_NETDEV_HEADROOM + packet->size);
        ofpbuf_reserve(&copy, DP_NETDEV_HEADROOM);
        ofpbuf_put(&copy, packet->data, packet->size);
    } else {
        /* We still need a shallow copy of 'packet', even though we won't
         * modify its data, because flow_extract() modifies packet->l2, etc.
         * We could probably get away with modifying those but it's more polite
         * if we don't. */
        copy = *packet;
    }

    flow_extract(&copy, 0, -1, &key);
    error = dpif_netdev_flow_from_nlattrs(key_attrs, key_len, &key);
    if (!error) {
        error = dp_netdev_execute_actions(dp, &copy, &key,
                                          actions, actions_len);
    }
    if (mutates) {
        ofpbuf_uninit(&copy);
    }
    return error;
}

static int
dpif_netdev_recv_get_mask(const struct dpif *dpif, int *listen_mask)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    *listen_mask = dpif_netdev->listen_mask;
    return 0;
}

static int
dpif_netdev_recv_set_mask(struct dpif *dpif, int listen_mask)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    dpif_netdev->listen_mask = listen_mask;
    return 0;
}

static struct dp_netdev_queue *
find_nonempty_queue(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int mask = dpif_netdev->listen_mask;
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct dp_netdev_queue *q = &dp->queues[i];
        if (q->head != q->tail && mask & (1u << i)) {
            return q;
        }
    }
    return NULL;
}

static int
dpif_netdev_recv(struct dpif *dpif, struct dpif_upcall *upcall)
{
    struct dp_netdev_queue *q = find_nonempty_queue(dpif);
    if (q) {
        struct dpif_upcall *u = q->upcalls[q->tail++ & QUEUE_MASK];
        *upcall = *u;
        free(u);

        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_netdev_recv_wait(struct dpif *dpif)
{
    if (find_nonempty_queue(dpif)) {
        poll_immediate_wake();
    } else {
        /* No messages ready to be received, and dp_wait() will ensure that we
         * wake up to queue new messages, so there is nothing to do. */
    }
}

static void
dpif_netdev_recv_purge(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    dp_netdev_purge_queues(dpif_netdev->dp);
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *flow, struct flow *key,
                    const struct ofpbuf *packet)
{
    flow->used = time_msec();
    flow->packet_count++;
    flow->byte_count += packet->size;
    if (key->dl_type == htons(ETH_TYPE_IP) && key->nw_proto == IPPROTO_TCP) {
        struct tcp_header *th = packet->l4;
        flow->tcp_ctl |= th->tcp_ctl;
    }
}

static void
dp_netdev_port_input(struct dp_netdev *dp, struct dp_netdev_port *port,
                     struct ofpbuf *packet)
{
    struct dp_netdev_flow *flow;
    struct flow key;

    if (packet->size < ETH_HEADER_LEN) {
        return;
    }
    if (flow_extract(packet, 0, port->port_no, &key) && dp->drop_frags) {
        dp->n_frags++;
        return;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (flow) {
        dp_netdev_flow_used(flow, &key, packet);
        dp_netdev_execute_actions(dp, packet, &key,
                                  flow->actions, flow->actions_len);
        dp->n_hit++;
    } else {
        dp->n_missed++;
        dp_netdev_output_userspace(dp, packet, DPIF_UC_MISS, &key, 0);
    }
}

static void
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    struct ofpbuf packet;

    ofpbuf_init(&packet, DP_NETDEV_HEADROOM + VLAN_ETH_HEADER_LEN + max_mtu);

    LIST_FOR_EACH (port, node, &dp->port_list) {
        int error;

        /* Reset packet contents. */
        ofpbuf_clear(&packet);
        ofpbuf_reserve(&packet, DP_NETDEV_HEADROOM);

        error = netdev_recv(port->netdev, &packet);
        if (!error) {
            dp_netdev_port_input(dp, port, &packet);
        } else if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                        netdev_get_name(port->netdev), strerror(error));
        }
    }
    ofpbuf_uninit(&packet);
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;

    LIST_FOR_EACH (port, node, &dp->port_list) {
        netdev_recv_wait(port->netdev);
    }
}

static void
dp_netdev_strip_vlan(struct ofpbuf *packet)
{
    struct vlan_eth_header *veh = packet->l2;
    if (packet->size >= sizeof *veh
        && veh->veth_type == htons(ETH_TYPE_VLAN)) {
        struct eth_header tmp;

        memcpy(tmp.eth_dst, veh->veth_dst, ETH_ADDR_LEN);
        memcpy(tmp.eth_src, veh->veth_src, ETH_ADDR_LEN);
        tmp.eth_type = veh->veth_next_type;

        ofpbuf_pull(packet, VLAN_HEADER_LEN);
        packet->l2 = (char*)packet->l2 + VLAN_HEADER_LEN;
        memcpy(packet->data, &tmp, sizeof tmp);
    }
}

static void
dp_netdev_set_dl_src(struct ofpbuf *packet, const uint8_t dl_addr[ETH_ADDR_LEN])
{
    struct eth_header *eh = packet->l2;
    memcpy(eh->eth_src, dl_addr, sizeof eh->eth_src);
}

static void
dp_netdev_set_dl_dst(struct ofpbuf *packet, const uint8_t dl_addr[ETH_ADDR_LEN])
{
    struct eth_header *eh = packet->l2;
    memcpy(eh->eth_dst, dl_addr, sizeof eh->eth_dst);
}

static bool
is_ip(const struct ofpbuf *packet, const struct flow *key)
{
    return key->dl_type == htons(ETH_TYPE_IP) && packet->l4;
}

static void
dp_netdev_set_nw_addr(struct ofpbuf *packet, const struct flow *key,
                      const struct nlattr *a)
{
    if (is_ip(packet, key)) {
        struct ip_header *nh = packet->l3;
        ovs_be32 ip = nl_attr_get_be32(a);
        uint16_t type = nl_attr_type(a);
        ovs_be32 *field;

        field = type == ODP_ACTION_ATTR_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
        if (key->nw_proto == IPPROTO_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            th->tcp_csum = recalc_csum32(th->tcp_csum, *field, ip);
        } else if (key->nw_proto == IPPROTO_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            if (uh->udp_csum) {
                uh->udp_csum = recalc_csum32(uh->udp_csum, *field, ip);
                if (!uh->udp_csum) {
                    uh->udp_csum = htons(0xffff);
                }
            }
        }
        nh->ip_csum = recalc_csum32(nh->ip_csum, *field, ip);
        *field = ip;
    }
}

static void
dp_netdev_set_nw_tos(struct ofpbuf *packet, const struct flow *key,
                     uint8_t nw_tos)
{
    if (is_ip(packet, key)) {
        struct ip_header *nh = packet->l3;
        uint8_t *field = &nh->ip_tos;

        /* Set the DSCP bits and preserve the ECN bits. */
        uint8_t new = nw_tos | (nh->ip_tos & IP_ECN_MASK);

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons((uint16_t)*field),
                htons((uint16_t) new));
        *field = new;
    }
}

static void
dp_netdev_set_tp_port(struct ofpbuf *packet, const struct flow *key,
                      const struct nlattr *a)
{
	if (is_ip(packet, key)) {
        uint16_t type = nl_attr_type(a);
        ovs_be16 port = nl_attr_get_be16(a);
        ovs_be16 *field;

        if (key->nw_proto == IPPROTO_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            field = (type == ODP_ACTION_ATTR_SET_TP_SRC
                     ? &th->tcp_src : &th->tcp_dst);
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, port);
            *field = port;
        } else if (key->nw_proto == IPPROTO_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            field = (type == ODP_ACTION_ATTR_SET_TP_SRC
                     ? &uh->udp_src : &uh->udp_dst);
            uh->udp_csum = recalc_csum16(uh->udp_csum, *field, port);
            *field = port;
        } else {
            return;
        }
    }
}

static void
dp_netdev_output_port(struct dp_netdev *dp, struct ofpbuf *packet,
                      uint16_t out_port)
{
    struct dp_netdev_port *p = dp->ports[out_port];
    if (p) {
        netdev_send(p->netdev, packet);
    }
}

static int
dp_netdev_output_userspace(struct dp_netdev *dp, const struct ofpbuf *packet,
                         int queue_no, const struct flow *flow, uint64_t arg)
{
    struct dp_netdev_queue *q = &dp->queues[queue_no];
    struct dpif_upcall *upcall;
    struct ofpbuf *buf;
    size_t key_len;

    if (q->head - q->tail >= MAX_QUEUE_LEN) {
        dp->n_lost++;
        return ENOBUFS;
    }

    buf = ofpbuf_new(ODPUTIL_FLOW_KEY_BYTES + 2 + packet->size);
    odp_flow_key_from_flow(buf, flow);
    key_len = buf->size;
    ofpbuf_pull(buf, key_len);
    ofpbuf_reserve(buf, 2);
    ofpbuf_put(buf, packet->data, packet->size);

    upcall = xzalloc(sizeof *upcall);
    upcall->type = queue_no;
    upcall->packet = buf;
    upcall->key = buf->base;
    upcall->key_len = key_len;
    upcall->userdata = arg;

    q->upcalls[q->head++ & QUEUE_MASK] = upcall;

    return 0;
}

static int
dp_netdev_execute_actions(struct dp_netdev *dp,
                          struct ofpbuf *packet, struct flow *key,
                          const struct nlattr *actions,
                          size_t actions_len)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        switch (nl_attr_type(a)) {
        case ODP_ACTION_ATTR_OUTPUT:
            dp_netdev_output_port(dp, packet, nl_attr_get_u32(a));
            break;

        case ODP_ACTION_ATTR_USERSPACE:
            dp_netdev_output_userspace(dp, packet, DPIF_UC_ACTION,
                                     key, nl_attr_get_u64(a));
            break;

        case ODP_ACTION_ATTR_SET_DL_TCI:
            eth_set_vlan_tci(packet, nl_attr_get_be16(a));
            break;

        case ODP_ACTION_ATTR_STRIP_VLAN:
            dp_netdev_strip_vlan(packet);
            break;

        case ODP_ACTION_ATTR_SET_DL_SRC:
            dp_netdev_set_dl_src(packet, nl_attr_get_unspec(a, ETH_ADDR_LEN));
            break;

        case ODP_ACTION_ATTR_SET_DL_DST:
            dp_netdev_set_dl_dst(packet, nl_attr_get_unspec(a, ETH_ADDR_LEN));
            break;

        case ODP_ACTION_ATTR_SET_NW_SRC:
        case ODP_ACTION_ATTR_SET_NW_DST:
            dp_netdev_set_nw_addr(packet, key, a);
            break;

        case ODP_ACTION_ATTR_SET_NW_TOS:
            dp_netdev_set_nw_tos(packet, key, nl_attr_get_u8(a));
            break;

        case ODP_ACTION_ATTR_SET_TP_SRC:
        case ODP_ACTION_ATTR_SET_TP_DST:
            dp_netdev_set_tp_port(packet, key, a);
            break;
        }
    }
    return 0;
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    NULL,                       /* enumerate */
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    dpif_netdev_get_drop_frags,
    dpif_netdev_set_drop_frags,
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    dpif_netdev_get_max_ports,
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
    dpif_netdev_recv_get_mask,
    dpif_netdev_recv_set_mask,
    NULL,                       /* get_sflow_probability */
    NULL,                       /* set_sflow_probability */
    NULL,                       /* queue_to_priority */
    dpif_netdev_recv,
    dpif_netdev_recv_wait,
    dpif_netdev_recv_purge,
};

void
dpif_dummy_register(void)
{
    if (!dpif_dummy_class.type) {
        dpif_dummy_class = dpif_netdev_class;
        dpif_dummy_class.type = "dummy";
        dp_register_provider(&dpif_dummy_class);
    }
}
