/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "csum.h"
#include "dpif-provider.h"
#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "queue.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev)

/* Configuration parameters. */
enum { N_QUEUES = 2 };          /* Number of queues for dpif_recv(). */
enum { MAX_QUEUE_LEN = 100 };   /* Maximum number of packets per queue. */
enum { N_GROUPS = 16 };         /* Number of port groups. */
enum { MAX_PORTS = 256 };       /* Maximum number of ports. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

/* Datapath based on the network device interface from netdev.h. */
struct dp_netdev {
    struct list node;
    int dp_idx;
    int open_cnt;
    bool destroyed;

    bool drop_frags;            /* Drop all IP fragments, if true. */
    struct ovs_queue queues[N_QUEUES]; /* Messages queued for dpif_recv(). */
    struct hmap flow_table;     /* Flow table. */
    struct odp_port_group groups[N_GROUPS];

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
    bool internal;              /* Internal port (as ODP_PORT_INTERNAL)? */
};

/* A flow in dp_netdev's 'flow_table'. */
struct dp_netdev_flow {
    struct hmap_node node;      /* Element in dp_netdev's 'flow_table'. */
    flow_t key;

    /* Statistics. */
    struct timespec used;       /* Last used time. */
    long long int packet_count; /* Number of packets matched. */
    long long int byte_count;   /* Number of bytes matched. */
    uint16_t tcp_ctl;           /* Bitwise-OR of seen tcp_ctl values. */

    /* Actions. */
    union odp_action *actions;
    unsigned int n_actions;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    int listen_mask;
    unsigned int dp_serial;
};

/* All netdev-based datapaths. */
static struct dp_netdev *dp_netdevs[256];
struct list dp_netdev_list = LIST_INITIALIZER(&dp_netdev_list);
enum { N_DP_NETDEVS = ARRAY_SIZE(dp_netdevs) };

/* Maximum port MTU seen so far. */
static int max_mtu = ETH_PAYLOAD_MAX;

static int get_port_by_number(struct dp_netdev *, uint16_t port_no,
                              struct dp_netdev_port **portp);
static int get_port_by_name(struct dp_netdev *, const char *devname,
                            struct dp_netdev_port **portp);
static void dp_netdev_free(struct dp_netdev *);
static void dp_netdev_flow_flush(struct dp_netdev *);
static int do_add_port(struct dp_netdev *, const char *devname, uint16_t flags,
                       uint16_t port_no);
static int do_del_port(struct dp_netdev *, uint16_t port_no);
static int dp_netdev_output_control(struct dp_netdev *, const struct ofpbuf *,
                                    int queue_no, int port_no, uint32_t arg);
static int dp_netdev_execute_actions(struct dp_netdev *,
                                     struct ofpbuf *, const flow_t *,
                                     const union odp_action *, int n);

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_netdev_class);
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

static int
name_to_dp_idx(const char *name)
{
    if (!strncmp(name, "dp", 2) && isdigit((unsigned char)name[2])) {
        int dp_idx = atoi(name + 2);
        if (dp_idx >= 0 && dp_idx < N_DP_NETDEVS) {
            return dp_idx;
        }
    }
    return -1;
}

static struct dp_netdev *
find_dp_netdev(const char *name)
{
    int dp_idx;
    size_t i;

    dp_idx = name_to_dp_idx(name);
    if (dp_idx >= 0) {
        return dp_netdevs[dp_idx];
    }

    for (i = 0; i < N_DP_NETDEVS; i++) {
        struct dp_netdev *dp = dp_netdevs[i];
        if (dp) {
            struct dp_netdev_port *port;
            if (!get_port_by_name(dp, name, &port)) {
                return dp;
            }
        }
    }
    return NULL;
}

static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    struct dpif_netdev *dpif;
    char *dpname;

    dp->open_cnt++;

    dpname = xasprintf("dp%d", dp->dp_idx);
    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, &dpif_netdev_class, dpname, dp->dp_idx, dp->dp_idx);
    dpif->dp = dp;
    dpif->listen_mask = 0;
    dpif->dp_serial = dp->serial;
    free(dpname);

    return &dpif->dpif;
}

static int
create_dp_netdev(const char *name, int dp_idx, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;
    int i;

    if (dp_netdevs[dp_idx]) {
        return EBUSY;
    }

    /* Create datapath. */
    dp_netdevs[dp_idx] = dp = xzalloc(sizeof *dp);
    list_push_back(&dp_netdev_list, &dp->node);
    dp->dp_idx = dp_idx;
    dp->open_cnt = 0;
    dp->drop_frags = false;
    for (i = 0; i < N_QUEUES; i++) {
        queue_init(&dp->queues[i]);
    }
    hmap_init(&dp->flow_table);
    for (i = 0; i < N_GROUPS; i++) {
        dp->groups[i].ports = NULL;
        dp->groups[i].n_ports = 0;
        dp->groups[i].group = i;
    }
    list_init(&dp->port_list);
    error = do_add_port(dp, name, ODP_PORT_INTERNAL, ODPP_LOCAL);
    if (error) {
        dp_netdev_free(dp);
        return ENODEV;
    }

    *dpifp = create_dpif_netdev(dp);
    return 0;
}

static int
dpif_netdev_open(const char *name, const char *type OVS_UNUSED, bool create,
                 struct dpif **dpifp)
{
    if (create) {
        if (find_dp_netdev(name)) {
            return EEXIST;
        } else {
            int dp_idx = name_to_dp_idx(name);
            if (dp_idx >= 0) {
                return create_dp_netdev(name, dp_idx, dpifp);
            } else {
                /* Scan for unused dp_idx number. */
                for (dp_idx = 0; dp_idx < N_DP_NETDEVS; dp_idx++) {
                    int error = create_dp_netdev(name, dp_idx, dpifp);
                    if (error != EBUSY) {
                        return error;
                    }
                }

                /* All datapath numbers in use. */
                return ENOBUFS;
            }
        }
    } else {
        struct dp_netdev *dp = find_dp_netdev(name);
        if (dp) {
            *dpifp = create_dpif_netdev(dp);
            return 0;
        } else {
            return ENODEV;
        }
    }
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
        queue_destroy(&dp->queues[i]);
    }
    hmap_destroy(&dp->flow_table);
    for (i = 0; i < N_GROUPS; i++) {
        free(dp->groups[i].ports);
    }
    dp_netdevs[dp->dp_idx] = NULL;
    list_remove(&dp->node);
    free(dp);
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    assert(dp->open_cnt > 0);
    if (--dp->open_cnt == 0 && dp->destroyed) {
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
    stats->max_groups = N_GROUPS;
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
do_add_port(struct dp_netdev *dp, const char *devname, uint16_t flags,
            uint16_t port_no)
{
    bool internal = (flags & ODP_PORT_INTERNAL) != 0;
    struct dp_netdev_port *port;
    struct netdev_options netdev_options;
    struct netdev *netdev;
    int mtu;
    int error;

    /* XXX reject devices already in some dp_netdev. */

    /* Open and validate network device. */
    memset(&netdev_options, 0, sizeof netdev_options);
    netdev_options.name = devname;
    netdev_options.ethertype = NETDEV_ETH_TYPE_ANY;
    if (internal) {
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
dpif_netdev_port_add(struct dpif *dpif, const char *devname, uint16_t flags,
                     uint16_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int port_no;

    for (port_no = 0; port_no < MAX_PORTS; port_no++) {
        if (!dp->ports[port_no]) {
            *port_nop = port_no;
            return do_add_port(dp, devname, flags, port_no);
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

    LIST_FOR_EACH (port, struct dp_netdev_port, node, &dp->port_list) {
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
    odp_port->flags = port->internal ? ODP_PORT_INTERNAL : 0;
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

    HMAP_FOR_EACH_SAFE (flow, next, struct dp_netdev_flow, node,
                        &dp->flow_table) {
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
    LIST_FOR_EACH (port, struct dp_netdev_port, node, &dp->port_list) {
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

static int
get_port_group(const struct dpif *dpif, int group_no,
               struct odp_port_group **groupp)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (group_no >= 0 && group_no < N_GROUPS) {
        *groupp = &dp->groups[group_no];
        return 0;
    } else {
        *groupp = NULL;
        return EINVAL;
    }
}

static int
dpif_netdev_port_group_get(const struct dpif *dpif, int group_no,
                           uint16_t ports[], int n)
{
    struct odp_port_group *group;
    int error;

    if (n < 0) {
        return -EINVAL;
    }

    error = get_port_group(dpif, group_no, &group);
    if (!error) {
        memcpy(ports, group->ports, MIN(n, group->n_ports) * sizeof *ports);
        return group->n_ports;
    } else {
        return -error;
    }
}

static int
dpif_netdev_port_group_set(struct dpif *dpif, int group_no,
                           const uint16_t ports[], int n)
{
    struct odp_port_group *group;
    int error;

    if (n < 0 || n > MAX_PORTS) {
        return EINVAL;
    }

    error = get_port_group(dpif, group_no, &group);
    if (!error) {
        free(group->ports);
        group->ports = xmemdup(ports, n * sizeof *group->ports);
        group->n_ports = n;
        group->group = group_no;
    }
    return error;
}

static struct dp_netdev_flow *
dp_netdev_lookup_flow(const struct dp_netdev *dp, const flow_t *key)
{
    struct dp_netdev_flow *flow;

    assert(!key->reserved[0] && !key->reserved[1] && !key->reserved[2]);
    HMAP_FOR_EACH_WITH_HASH (flow, struct dp_netdev_flow, node,
                             flow_hash(key, 0), &dp->flow_table) {
        if (flow_equal(&flow->key, key)) {
            return flow;
        }
    }
    return NULL;
}

static void
answer_flow_query(struct dp_netdev_flow *flow, uint32_t query_flags,
                  struct odp_flow *odp_flow)
{
    if (flow) {
        odp_flow->key = flow->key;
        odp_flow->stats.n_packets = flow->packet_count;
        odp_flow->stats.n_bytes = flow->byte_count;
        odp_flow->stats.used_sec = flow->used.tv_sec;
        odp_flow->stats.used_nsec = flow->used.tv_nsec;
        odp_flow->stats.tcp_flags = TCP_FLAGS(flow->tcp_ctl);
        odp_flow->stats.reserved = 0;
        odp_flow->stats.error = 0;
        if (odp_flow->n_actions > 0) {
            unsigned int n = MIN(odp_flow->n_actions, flow->n_actions);
            memcpy(odp_flow->actions, flow->actions,
                   n * sizeof *odp_flow->actions);
            odp_flow->n_actions = flow->n_actions;
        }

        if (query_flags & ODPFF_ZERO_TCP_FLAGS) {
            flow->tcp_ctl = 0;
        }

    } else {
        odp_flow->stats.error = ENOENT;
    }
}

static int
dpif_netdev_flow_get(const struct dpif *dpif, struct odp_flow flows[], int n)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int i;

    for (i = 0; i < n; i++) {
        struct odp_flow *odp_flow = &flows[i];
        answer_flow_query(dp_netdev_lookup_flow(dp, &odp_flow->key),
                          odp_flow->flags, odp_flow);
    }
    return 0;
}

static int
dpif_netdev_validate_actions(const union odp_action *actions, int n_actions,
                             bool *mutates)
{
    unsigned int i;

    *mutates = false;
    for (i = 0; i < n_actions; i++) {
        const union odp_action *a = &actions[i];
        switch (a->type) {
        case ODPAT_OUTPUT:
            if (a->output.port >= MAX_PORTS) {
                return EINVAL;
            }
            break;

        case ODPAT_OUTPUT_GROUP:
            *mutates = true;
            if (a->output_group.group >= N_GROUPS) {
                return EINVAL;
            }
            break;

        case ODPAT_CONTROLLER:
            break;

        case ODPAT_SET_VLAN_VID:
            *mutates = true;
            if (a->vlan_vid.vlan_vid & htons(~VLAN_VID_MASK)) {
                return EINVAL;
            }
            break;

        case ODPAT_SET_VLAN_PCP:
            *mutates = true;
            if (a->vlan_pcp.vlan_pcp & ~(VLAN_PCP_MASK >> VLAN_PCP_SHIFT)) {
                return EINVAL;
            }
            break;

        case ODPAT_SET_NW_TOS:
            *mutates = true;
            if (a->nw_tos.nw_tos & IP_ECN_MASK) {
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

        default:
            return EOPNOTSUPP;
        }
    }
    return 0;
}

static int
set_flow_actions(struct dp_netdev_flow *flow, struct odp_flow *odp_flow)
{
    size_t n_bytes;
    bool mutates;
    int error;

    if (odp_flow->n_actions >= 4096 / sizeof *odp_flow->actions) {
        return EINVAL;
    }
    error = dpif_netdev_validate_actions(odp_flow->actions,
                                         odp_flow->n_actions, &mutates);
    if (error) {
        return error;
    }

    n_bytes = odp_flow->n_actions * sizeof *flow->actions;
    flow->actions = xrealloc(flow->actions, n_bytes);
    flow->n_actions = odp_flow->n_actions;
    memcpy(flow->actions, odp_flow->actions, n_bytes);
    return 0;
}

static int
add_flow(struct dpif *dpif, struct odp_flow *odp_flow)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    int error;

    flow = xzalloc(sizeof *flow);
    flow->key = odp_flow->key;
    memset(flow->key.reserved, 0, sizeof flow->key.reserved);

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

    flow = dp_netdev_lookup_flow(dp, &put->flow.key);
    if (!flow) {
        if (put->flags & ODPPF_CREATE) {
            if (hmap_count(&dp->flow_table) < MAX_FLOWS) {
                return add_flow(dpif, &put->flow);
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

    flow = dp_netdev_lookup_flow(dp, &odp_flow->key);
    if (flow) {
        answer_flow_query(flow, 0, odp_flow);
        dp_netdev_free_flow(dp, flow);
        return 0;
    } else {
        return ENOENT;
    }
}

static int
dpif_netdev_flow_list(const struct dpif *dpif, struct odp_flow flows[], int n)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *flow;
    int i;

    i = 0;
    HMAP_FOR_EACH (flow, struct dp_netdev_flow, node, &dp->flow_table) {
        if (i >= n) {
            break;
        }
        answer_flow_query(flow, 0, &flows[i++]);
    }
    return hmap_count(&dp->flow_table);
}

static int
dpif_netdev_execute(struct dpif *dpif, uint16_t in_port,
                    const union odp_action actions[], int n_actions,
                    const struct ofpbuf *packet)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct ofpbuf copy;
    bool mutates;
    flow_t flow;
    int error;

    if (packet->size < ETH_HEADER_LEN || packet->size > UINT16_MAX) {
        return EINVAL;
    }

    error = dpif_netdev_validate_actions(actions, n_actions, &mutates);
    if (error) {
        return error;
    }

    if (mutates) {
        /* We need a deep copy of 'packet' since we're going to modify its
         * data. */
        ofpbuf_init(&copy, DP_NETDEV_HEADROOM + packet->size);
        copy.data = (char*)copy.base + DP_NETDEV_HEADROOM;
        ofpbuf_put(&copy, packet->data, packet->size);
    } else {
        /* We still need a shallow copy of 'packet', even though we won't
         * modify its data, because flow_extract() modifies packet->l2, etc.
         * We could probably get away with modifying those but it's more polite
         * if we don't. */
        copy = *packet;
    }
    flow_extract(&copy, 0, in_port, &flow);
    error = dp_netdev_execute_actions(dp, &copy, &flow, actions, n_actions);
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

static struct ovs_queue *
find_nonempty_queue(struct dpif *dpif)
{
    struct dpif_netdev *dpif_netdev = dpif_netdev_cast(dpif);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int mask = dpif_netdev->listen_mask;
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct ovs_queue *q = &dp->queues[i];
        if (q->n && mask & (1u << i)) {
            return q;
        }
    }
    return NULL;
}

static int
dpif_netdev_recv(struct dpif *dpif, struct ofpbuf **bufp)
{
    struct ovs_queue *q = find_nonempty_queue(dpif);
    if (q) {
        *bufp = queue_pop_head(q);
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_netdev_recv_wait(struct dpif *dpif)
{
    struct ovs_queue *q = find_nonempty_queue(dpif);
    if (q) {
        poll_immediate_wake();
    } else {
        /* No messages ready to be received, and dp_wait() will ensure that we
         * wake up to queue new messages, so there is nothing to do. */
    }
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *flow, const flow_t *key,
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
    flow_t key;

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
                                  flow->actions, flow->n_actions);
        dp->n_hit++;
    } else {
        dp->n_missed++;
        dp_netdev_output_control(dp, packet, _ODPL_MISS_NR, port->port_no, 0);
    }
}

static void
dp_netdev_run(void)
{
    struct ofpbuf packet;
    struct dp_netdev *dp;

    ofpbuf_init(&packet, DP_NETDEV_HEADROOM + max_mtu);
    LIST_FOR_EACH (dp, struct dp_netdev, node, &dp_netdev_list) {
        struct dp_netdev_port *port;

        LIST_FOR_EACH (port, struct dp_netdev_port, node, &dp->port_list) {
            int error;

            /* Reset packet contents. */
            packet.data = (char*)packet.base + DP_NETDEV_HEADROOM;
            packet.size = 0;

            error = netdev_recv(port->netdev, &packet);
            if (!error) {
                dp_netdev_port_input(dp, port, &packet);
            } else if (error != EAGAIN) {
                struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
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
    struct dp_netdev *dp;

    LIST_FOR_EACH (dp, struct dp_netdev, node, &dp_netdev_list) {
        struct dp_netdev_port *port;
        LIST_FOR_EACH (port, struct dp_netdev_port, node, &dp->port_list) {
            netdev_recv_wait(port->netdev);
        }
    }
}


/* Modify the TCI field of 'packet'.  If a VLAN tag is not present, one
 * is added with the TCI field set to 'tci'.  If a VLAN tag is present,
 * then 'mask' bits are cleared before 'tci' is logically OR'd into the
 * TCI field.
 *
 * Note that the function does not ensure that 'tci' does not affect
 * bits outside of 'mask'.
 */
static void
dp_netdev_modify_vlan_tci(struct ofpbuf *packet, uint16_t tci, uint16_t mask)
{
    struct vlan_eth_header *veh;
    struct eth_header *eh;

    eh = packet->l2;
    if (packet->size >= sizeof(struct vlan_eth_header)
        && eh->eth_type == htons(ETH_TYPE_VLAN)) {
        /* Clear 'mask' bits, but maintain other TCI bits. */
        veh = packet->l2;
        veh->veth_tci &= ~htons(mask);
        veh->veth_tci |= htons(tci);
    } else {
        /* Insert new 802.1Q header. */
        struct eth_header *eh = packet->l2;
        struct vlan_eth_header tmp;
        memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
        memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
        tmp.veth_type = htons(ETH_TYPE_VLAN);
        tmp.veth_tci = htons(tci);
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

        packet->size -= VLAN_HEADER_LEN;
        packet->data = (char*)packet->data + VLAN_HEADER_LEN;
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
is_ip(const struct ofpbuf *packet, const flow_t *key)
{
    return key->dl_type == htons(ETH_TYPE_IP) && packet->l4;
}

static void
dp_netdev_set_nw_addr(struct ofpbuf *packet, const flow_t *key,
                      const struct odp_action_nw_addr *a)
{
    if (is_ip(packet, key)) {
        struct ip_header *nh = packet->l3;
        uint32_t *field;

        field = a->type == ODPAT_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
        if (key->nw_proto == IP_TYPE_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            th->tcp_csum = recalc_csum32(th->tcp_csum, *field, a->nw_addr);
        } else if (key->nw_proto == IP_TYPE_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            if (uh->udp_csum) {
                uh->udp_csum = recalc_csum32(uh->udp_csum, *field, a->nw_addr);
                if (!uh->udp_csum) {
                    uh->udp_csum = 0xffff;
                }
            }
        }
        nh->ip_csum = recalc_csum32(nh->ip_csum, *field, a->nw_addr);
        *field = a->nw_addr;
    }
}

static void
dp_netdev_set_nw_tos(struct ofpbuf *packet, const flow_t *key,
                     const struct odp_action_nw_tos *a)
{
    if (is_ip(packet, key)) {
        struct ip_header *nh = packet->l3;
        uint8_t *field = &nh->ip_tos;

        /* Set the DSCP bits and preserve the ECN bits. */
        uint8_t new = a->nw_tos | (nh->ip_tos & IP_ECN_MASK);

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons((uint16_t)*field),
                htons((uint16_t)a->nw_tos));
        *field = new;
    }
}

static void
dp_netdev_set_tp_port(struct ofpbuf *packet, const flow_t *key,
                      const struct odp_action_tp_port *a)
{
	if (is_ip(packet, key)) {
        uint16_t *field;
        if (key->nw_proto == IPPROTO_TCP && packet->l7) {
            struct tcp_header *th = packet->l4;
            field = a->type == ODPAT_SET_TP_SRC ? &th->tcp_src : &th->tcp_dst;
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, a->tp_port);
            *field = a->tp_port;
        } else if (key->nw_proto == IPPROTO_UDP && packet->l7) {
            struct udp_header *uh = packet->l4;
            field = a->type == ODPAT_SET_TP_SRC ? &uh->udp_src : &uh->udp_dst;
            uh->udp_csum = recalc_csum16(uh->udp_csum, *field, a->tp_port);
            *field = a->tp_port;
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

static void
dp_netdev_output_group(struct dp_netdev *dp, uint16_t group, uint16_t in_port,
                       struct ofpbuf *packet)
{
    struct odp_port_group *g = &dp->groups[group];
    int i;

    for (i = 0; i < g->n_ports; i++) {
        uint16_t out_port = g->ports[i];
        if (out_port != in_port) {
            dp_netdev_output_port(dp, packet, out_port);
        }
    }
}

static int
dp_netdev_output_control(struct dp_netdev *dp, const struct ofpbuf *packet,
                         int queue_no, int port_no, uint32_t arg)
{
    struct ovs_queue *q = &dp->queues[queue_no];
    struct odp_msg *header;
    struct ofpbuf *msg;
    size_t msg_size;

    if (q->n >= MAX_QUEUE_LEN) {
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
    queue_push_tail(q, msg);

    return 0;
}

/* Returns true if 'packet' is an invalid Ethernet+IPv4 ARP packet: one with
 * screwy or truncated header fields or one whose inner and outer Ethernet
 * address differ. */
static bool
dp_netdev_is_spoofed_arp(struct ofpbuf *packet, const struct odp_flow_key *key)
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
                          struct ofpbuf *packet, const flow_t *key,
                          const union odp_action *actions, int n_actions)
{
    int i;
    for (i = 0; i < n_actions; i++) {
        const union odp_action *a = &actions[i];

        switch (a->type) {
        case ODPAT_OUTPUT:
            dp_netdev_output_port(dp, packet, a->output.port);
            break;

        case ODPAT_OUTPUT_GROUP:
            dp_netdev_output_group(dp, a->output_group.group, key->in_port,
                                   packet);
            break;

        case ODPAT_CONTROLLER:
            dp_netdev_output_control(dp, packet, _ODPL_ACTION_NR,
                                     key->in_port, a->controller.arg);
            break;

        case ODPAT_SET_VLAN_VID:
            dp_netdev_modify_vlan_tci(packet, ntohs(a->vlan_vid.vlan_vid),
                                      VLAN_VID_MASK);
            break;

        case ODPAT_SET_VLAN_PCP:
            dp_netdev_modify_vlan_tci(packet,
                                      a->vlan_pcp.vlan_pcp << VLAN_PCP_SHIFT,
                                      VLAN_PCP_MASK);
            break;

        case ODPAT_STRIP_VLAN:
            dp_netdev_strip_vlan(packet);
            break;

        case ODPAT_SET_DL_SRC:
            dp_netdev_set_dl_src(packet, a->dl_addr.dl_addr);
            break;

        case ODPAT_SET_DL_DST:
            dp_netdev_set_dl_dst(packet, a->dl_addr.dl_addr);
            break;

        case ODPAT_SET_NW_SRC:
        case ODPAT_SET_NW_DST:
            dp_netdev_set_nw_addr(packet, key, &a->nw_addr);
            break;

        case ODPAT_SET_NW_TOS:
            dp_netdev_set_nw_tos(packet, key, &a->nw_tos);
            break;

        case ODPAT_SET_TP_SRC:
        case ODPAT_SET_TP_DST:
            dp_netdev_set_tp_port(packet, key, &a->tp_port);
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
    dpif_netdev_port_group_get,
    dpif_netdev_port_group_set,
    dpif_netdev_flow_get,
    dpif_netdev_flow_put,
    dpif_netdev_flow_del,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_list,
    dpif_netdev_execute,
    dpif_netdev_recv_get_mask,
    dpif_netdev_recv_set_mask,
    NULL,                       /* get_sflow_probability */
    NULL,                       /* set_sflow_probability */
    NULL,                       /* queue_to_priority */
    dpif_netdev_recv,
    dpif_netdev_recv_wait,
};
