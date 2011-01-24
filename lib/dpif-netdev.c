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
enum { N_QUEUES = 2 };          /* Number of queues for dpif_recv(). */
enum { MAX_QUEUE_LEN = 100 };   /* Maximum number of packets per queue. */
enum { MAX_PORTS = 256 };       /* Maximum number of ports. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

/* Datapath based on the network device interface from netdev.h. */
struct dp_netdev {
    const struct dpif_class *class;
    char *name;
    int open_cnt;
    bool destroyed;

    bool drop_frags;            /* Drop all IP fragments, if true. */
    struct list queues[N_QUEUES]; /* Contain ofpbufs queued for dpif_recv(). */
    size_t queue_len[N_QUEUES]; /* Number of packets in each queue. */
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
    struct timespec used;       /* Last used time. */
    long long int packet_count; /* Number of packets matched. */
    long long int byte_count;   /* Number of bytes matched. */
    uint16_t tcp_ctl;           /* Bitwise-OR of seen tcp_ctl values. */

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
static int dp_netdev_output_control(struct dp_netdev *, const struct ofpbuf *,
                                    int queue_no, int port_no, uint64_t arg);
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
        list_init(&dp->queues[i]);
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
dp_netdev_free(struct dp_netdev *dp)
{
    int i;

    dp_netdev_flow_flush(dp);
    while (dp->n_ports > 0) {
        struct dp_netdev_port *port = CONTAINER_OF(
            dp->port_list.next, struct dp_netdev_port, node);
        do_del_port(dp, port->port_no);
    }
    for (i = 0; i < N_QUEUES; i++) {
        ofpbuf_list_delete(&dp->queues[i]);
    }
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
    stats->n_flows = hmap_count(&dp->flow_table);
    stats->cur_capacity = hmap_capacity(&dp->flow_table);
    stats->max_capacity = MAX_FLOWS;
    stats->n_ports = dp->n_ports;
    stats->max_ports = MAX_PORTS;
    stats->n_frags = dp->n_frags;
    stats->n_hit = dp->n_hit;
    stats->n_missed = dp->n_missed;
    stats->n_lost = dp->n_lost;
    stats->max_miss_queue = MAX_QUEUE_LEN;
    stats->max_action_queue = MAX_QUEUE_LEN;
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
    if (mtu > max_mtu) {
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
answer_port_query(const struct dp_netdev_port *port, struct odp_port *odp_port)
{
    memset(odp_port, 0, sizeof *odp_port);
    ovs_strlcpy(odp_port->devname, netdev_get_name(port->netdev),
                sizeof odp_port->devname);
    odp_port->port = port->port_no;
    strcpy(odp_port->type, port->internal ? "internal" : "system");
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                                 struct odp_port *odp_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_number(dp, port_no, &port);
    if (!error) {
        answer_port_query(port, odp_port);
    }
    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct odp_port *odp_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    error = get_port_by_name(dp, devname, &port);
    if (!error) {
        answer_port_query(port, odp_port);
    }
    return error;
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

static int
dpif_netdev_port_list(const struct dpif *dpif, struct odp_port *ports, int n)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int i;

    i = 0;
    LIST_FOR_EACH (port, node, &dp->port_list) {
        struct odp_port *odp_port = &ports[i];
        if (i >= n) {
            break;
        }
        answer_port_query(port, odp_port);
        i++;
    }
    return dp->n_ports;
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

/* The caller must fill in odp_flow->key itself. */
static void
answer_flow_query(struct dp_netdev_flow *flow, uint32_t query_flags,
                  struct odp_flow *odp_flow)
{
    if (flow) {
        odp_flow->stats.n_packets = flow->packet_count;
        odp_flow->stats.n_bytes = flow->byte_count;
        odp_flow->stats.used_sec = flow->used.tv_sec;
        odp_flow->stats.used_nsec = flow->used.tv_nsec;
        odp_flow->stats.tcp_flags = TCP_FLAGS(flow->tcp_ctl);
        odp_flow->stats.reserved = 0;
        odp_flow->stats.error = 0;
        if (odp_flow->actions_len > 0) {
            memcpy(odp_flow->actions, flow->actions,
                   MIN(odp_flow->actions_len, flow->actions_len));
            odp_flow->actions_len = flow->actions_len;
        }

        if (query_flags & ODPFF_ZERO_TCP_FLAGS) {
            flow->tcp_ctl = 0;
        }

    } else {
        odp_flow->stats.error = ENOENT;
    }
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

    return 0;
}

static int
dpif_netdev_flow_get(const struct dpif *dpif, struct odp_flow flows[], int n)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int i;

    for (i = 0; i < n; i++) {
        struct odp_flow *odp_flow = &flows[i];
        struct flow key;
        int error;

        error = dpif_netdev_flow_from_nlattrs(odp_flow->key, odp_flow->key_len,
                                              &key);
        if (error) {
            return error;
        }

        answer_flow_query(dp_netdev_lookup_flow(dp, &key),
                          odp_flow->flags, odp_flow);
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
        case ODPAT_OUTPUT:
            if (nl_attr_get_u32(a) >= MAX_PORTS) {
                return EINVAL;
            }
            break;

        case ODPAT_CONTROLLER:
        case ODPAT_DROP_SPOOFED_ARP:
            break;

        case ODPAT_SET_DL_TCI:
            *mutates = true;
            if (nl_attr_get_be16(a) & htons(VLAN_CFI)) {
                return EINVAL;
            }
            break;

        case ODPAT_SET_NW_TOS:
            *mutates = true;
            if (nl_attr_get_u8(a) & IP_ECN_MASK) {
                return EINVAL;
            }
            break;

        case ODPAT_STRIP_VLAN:
        case ODPAT_SET_DL_SRC:
        case ODPAT_SET_DL_DST:
        case ODPAT_SET_NW_SRC:
        case ODPAT_SET_NW_DST:
        case ODPAT_SET_TP_SRC:
        case ODPAT_SET_TP_DST:
            *mutates = true;
            break;

        case ODPAT_SET_TUNNEL:
        case ODPAT_SET_PRIORITY:
        case ODPAT_POP_PRIORITY:
        default:
            return EOPNOTSUPP;
        }
    }
    return 0;
}

static int
set_flow_actions(struct dp_netdev_flow *flow, struct odp_flow *odp_flow)
{
    bool mutates;
    int error;

    error = dpif_netdev_validate_actions(odp_flow->actions,
                                         odp_flow->actions_len, &mutates);
    if (error) {
        return error;
    }

    flow->actions = xrealloc(flow->actions, odp_flow->actions_len);
    flow->actions_len = odp_flow->actions_len;
    memcpy(flow->actions, odp_flow->actions, odp_flow->actions_len);
    return 0;
}

static int
add_flow(struct dpif *dpif, const struct flow *key, struct odp_flow *odp_flow)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    int error;

    flow = xzalloc(sizeof *flow);
    flow->key = *key;

    error = set_flow_actions(flow, odp_flow);
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
    flow->used.tv_sec = 0;
    flow->used.tv_nsec = 0;
    flow->packet_count = 0;
    flow->byte_count = 0;
    flow->tcp_ctl = 0;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, struct odp_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(put->flow.key, put->flow.key_len,
                                          &key);
    if (error) {
        return error;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (!flow) {
        if (put->flags & ODPPF_CREATE) {
            if (hmap_count(&dp->flow_table) < MAX_FLOWS) {
                return add_flow(dpif, &key, &put->flow);
            } else {
                return EFBIG;
            }
        } else {
            return ENOENT;
        }
    } else {
        if (put->flags & ODPPF_MODIFY) {
            int error = set_flow_actions(flow, &put->flow);
            if (!error && put->flags & ODPPF_ZERO_STATS) {
                clear_stats(flow);
            }
            return error;
        } else {
            return EEXIST;
        }
    }
}


static int
dpif_netdev_flow_del(struct dpif *dpif, struct odp_flow *odp_flow)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct flow key;
    int error;

    error = dpif_netdev_flow_from_nlattrs(odp_flow->key, odp_flow->key_len,
                                          &key);
    if (error) {
        return error;
    }

    flow = dp_netdev_lookup_flow(dp, &key);
    if (flow) {
        answer_flow_query(flow, 0, odp_flow);
        dp_netdev_free_flow(dp, flow);
        return 0;
    } else {
        return ENOENT;
    }
}

struct dp_netdev_flow_state {
    uint32_t bucket;
    uint32_t offset;
};

static int
dpif_netdev_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_flow_state));
    return 0;
}

static int
dpif_netdev_flow_dump_next(const struct dpif *dpif, void *state_,
                           struct odp_flow *odp_flow)
{
    struct dp_netdev_flow_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    struct hmap_node *node;
    struct ofpbuf key;

    node = hmap_at_position(&dp->flow_table, &state->bucket, &state->offset);
    if (!node) {
        return EOF;
    }

    flow = CONTAINER_OF(node, struct dp_netdev_flow, node);

    ofpbuf_use_stack(&key, odp_flow->key, odp_flow->key_len);
    odp_flow_key_from_flow(&key, &flow->key);
    odp_flow->key_len = key.size;
    ofpbuf_uninit(&key);

    answer_flow_query(flow, 0, odp_flow);

    return 0;
}

static int
dpif_netdev_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *state)
{
    free(state);
    return 0;
}

static int
dpif_netdev_execute(struct dpif *dpif,
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
    error = dp_netdev_execute_actions(dp, &copy, &key, actions, actions_len);
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
    if (!(listen_mask & ~ODPL_ALL)) {
        dpif_netdev->listen_mask = listen_mask;
        return 0;
    } else {
        return EINVAL;
    }
}

static int
find_nonempty_queue(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int mask = dpif_netdev->listen_mask;
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct list *queue = &dp->queues[i];
        if (!list_is_empty(queue) && mask & (1u << i)) {
            return i;
        }
    }
    return -1;
}

static int
dpif_netdev_recv(struct dpif *dpif, struct ofpbuf **bufp)
{
    int queue_idx = find_nonempty_queue(dpif);
    if (queue_idx >= 0) {
        struct dp_netdev *dp = get_dp_netdev(dpif);

        *bufp = ofpbuf_from_list(list_pop_front(&dp->queues[queue_idx]));
        dp->queue_len[queue_idx]--;

        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_netdev_recv_wait(struct dpif *dpif)
{
    if (find_nonempty_queue(dpif) >= 0) {
        poll_immediate_wake();
    } else {
        /* No messages ready to be received, and dp_wait() will ensure that we
         * wake up to queue new messages, so there is nothing to do. */
    }
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *flow, struct flow *key,
                    const struct ofpbuf *packet)
{
    time_timespec(&flow->used);
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
        dp_netdev_output_control(dp, packet, _ODPL_MISS_NR, port->port_no, 0);
    }
}

static void
dp_netdev_run(void)
{
    struct shash_node *node;
    struct ofpbuf packet;

    ofpbuf_init(&packet, DP_NETDEV_HEADROOM + VLAN_ETH_HEADER_LEN + max_mtu);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        struct dp_netdev_port *port;

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
    }
    ofpbuf_uninit(&packet);
}

static void
dp_netdev_wait(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        struct dp_netdev_port *port;

        LIST_FOR_EACH (port, node, &dp->port_list) {
            netdev_recv_wait(port->netdev);
        }
    }
}


/* Modify the TCI field of 'packet'.  If a VLAN tag is present, its TCI field
 * is replaced by 'tci'.  If a VLAN tag is not present, one is added with the
 * TCI field set to 'tci'.
 */
static void
dp_netdev_set_dl_tci(struct ofpbuf *packet, uint16_t tci)
{
    struct vlan_eth_header *veh;
    struct eth_header *eh;

    eh = packet->l2;
    if (packet->size >= sizeof(struct vlan_eth_header)
        && eh->eth_type == htons(ETH_TYPE_VLAN)) {
        veh = packet->l2;
        veh->veth_tci = tci;
    } else {
        /* Insert new 802.1Q header. */
        struct vlan_eth_header tmp;
        memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
        memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
        tmp.veth_type = htons(ETH_TYPE_VLAN);
        tmp.veth_tci = tci;
        tmp.veth_next_type = eh->eth_type;

        veh = ofpbuf_push_uninit(packet, VLAN_HEADER_LEN);
        memcpy(veh, &tmp, sizeof tmp);
        packet->l2 = (char*)packet->l2 - VLAN_HEADER_LEN;
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
        uint32_t *field;

        field = type == ODPAT_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
        if (key->nw_proto == IP_TYPE_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            th->tcp_csum = recalc_csum32(th->tcp_csum, *field, ip);
        } else if (key->nw_proto == IP_TYPE_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            if (uh->udp_csum) {
                uh->udp_csum = recalc_csum32(uh->udp_csum, *field, ip);
                if (!uh->udp_csum) {
                    uh->udp_csum = 0xffff;
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
        uint16_t *field;

        if (key->nw_proto == IPPROTO_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            field = type == ODPAT_SET_TP_SRC ? &th->tcp_src : &th->tcp_dst;
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, port);
            *field = port;
        } else if (key->nw_proto == IPPROTO_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            field = type == ODPAT_SET_TP_SRC ? &uh->udp_src : &uh->udp_dst;
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
dp_netdev_output_control(struct dp_netdev *dp, const struct ofpbuf *packet,
                         int queue_no, int port_no, uint64_t arg)
{
    struct odp_msg *header;
    struct ofpbuf *msg;
    size_t msg_size;

    if (dp->queue_len[queue_no] >= MAX_QUEUE_LEN) {
        dp->n_lost++;
        return ENOBUFS;
    }

    msg_size = sizeof *header + packet->size;
    msg = ofpbuf_new_with_headroom(msg_size, DPIF_RECV_MSG_PADDING);
    header = ofpbuf_put_uninit(msg, sizeof *header);
    header->type = queue_no;
    header->length = msg_size;
    header->port = port_no;
    header->arg = arg;
    ofpbuf_put(msg, packet->data, packet->size);
    list_push_back(&dp->queues[queue_no], &msg->list_node);
    dp->queue_len[queue_no]++;

    return 0;
}

/* Returns true if 'packet' is an invalid Ethernet+IPv4 ARP packet: one with
 * screwy or truncated header fields or one whose inner and outer Ethernet
 * address differ. */
static bool
dp_netdev_is_spoofed_arp(struct ofpbuf *packet, const struct flow *key)
{
    struct arp_eth_header *arp;
    struct eth_header *eth;
    ptrdiff_t l3_size;

    if (key->dl_type != htons(ETH_TYPE_ARP)) {
        return false;
    }

    l3_size = (char *) ofpbuf_end(packet) - (char *) packet->l3;
    if (l3_size < sizeof(struct arp_eth_header)) {
        return true;
    }

    eth = packet->l2;
    arp = packet->l3;
    return (arp->ar_hrd != htons(ARP_HRD_ETHERNET)
            || arp->ar_pro != htons(ARP_PRO_IP)
            || arp->ar_hln != ETH_HEADER_LEN
            || arp->ar_pln != 4
            || !eth_addr_equals(arp->ar_sha, eth->eth_src));
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
        case ODPAT_OUTPUT:
            dp_netdev_output_port(dp, packet, nl_attr_get_u32(a));
            break;

        case ODPAT_CONTROLLER:
            dp_netdev_output_control(dp, packet, _ODPL_ACTION_NR,
                                     key->in_port, nl_attr_get_u64(a));
            break;

        case ODPAT_SET_DL_TCI:
            dp_netdev_set_dl_tci(packet, nl_attr_get_be16(a));
            break;

        case ODPAT_STRIP_VLAN:
            dp_netdev_strip_vlan(packet);
            break;

        case ODPAT_SET_DL_SRC:
            dp_netdev_set_dl_src(packet, nl_attr_get_unspec(a, ETH_ADDR_LEN));
            break;

        case ODPAT_SET_DL_DST:
            dp_netdev_set_dl_dst(packet, nl_attr_get_unspec(a, ETH_ADDR_LEN));
            break;

        case ODPAT_SET_NW_SRC:
        case ODPAT_SET_NW_DST:
            dp_netdev_set_nw_addr(packet, key, a);
            break;

        case ODPAT_SET_NW_TOS:
            dp_netdev_set_nw_tos(packet, key, nl_attr_get_u8(a));
            break;

        case ODPAT_SET_TP_SRC:
        case ODPAT_SET_TP_DST:
            dp_netdev_set_tp_port(packet, key, a);
            break;

        case ODPAT_DROP_SPOOFED_ARP:
            if (dp_netdev_is_spoofed_arp(packet, key)) {
                return 0;
            }
        }
    }
    return 0;
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    dp_netdev_run,
    dp_netdev_wait,
    NULL,                       /* enumerate */
    dpif_netdev_open,
    dpif_netdev_close,
    NULL,                       /* get_all_names */
    dpif_netdev_destroy,
    dpif_netdev_get_stats,
    dpif_netdev_get_drop_frags,
    dpif_netdev_set_drop_frags,
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    dpif_netdev_port_list,
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
