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
#include "xfif.h"

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
#include "flow.h"
#include "hmap.h"
#include "list.h"
#include "netdev.h"
#include "xflow-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "queue.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"
#include "xfif-provider.h"

VLOG_DEFINE_THIS_MODULE(xfif_netdev)

/* Configuration parameters. */
enum { N_QUEUES = 2 };          /* Number of queues for xfif_recv(). */
enum { MAX_QUEUE_LEN = 100 };   /* Maximum number of packets per queue. */
enum { N_GROUPS = 16 };         /* Number of port groups. */
enum { MAX_PORTS = 256 };       /* Maximum number of ports. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { XF_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

/* Datapath based on the network device interface from netdev.h. */
struct xf_netdev {
    struct list node;
    int xf_idx;
    int open_cnt;
    bool destroyed;

    bool drop_frags;            /* Drop all IP fragments, if true. */
    struct ovs_queue queues[N_QUEUES]; /* Messages queued for xfif_recv(). */
    struct hmap flow_table;     /* Flow table. */
    struct xflow_port_group groups[N_GROUPS];

    /* Statistics. */
    long long int n_frags;      /* Number of dropped IP fragments. */
    long long int n_hit;        /* Number of flow table matches. */
    long long int n_missed;     /* Number of flow table misses. */
    long long int n_lost;       /* Number of misses not passed to client. */

    /* Ports. */
    int n_ports;
    struct xf_netdev_port *ports[MAX_PORTS];
    struct list port_list;
    unsigned int serial;
};

/* A port in a netdev-based datapath. */
struct xf_netdev_port {
    int port_no;                /* Index into xf_netdev's 'ports'. */
    struct list node;           /* Element in xf_netdev's 'port_list'. */
    struct netdev *netdev;
    bool internal;              /* Internal port (as XFLOW_PORT_INTERNAL)? */
};

/* A flow in xf_netdev's 'flow_table'. */
struct xf_netdev_flow {
    struct hmap_node node;      /* Element in xf_netdev's 'flow_table'. */
    struct xflow_key key;

    /* Statistics. */
    struct timespec used;       /* Last used time. */
    long long int packet_count; /* Number of packets matched. */
    long long int byte_count;   /* Number of bytes matched. */
    uint8_t ip_tos;             /* IP TOS value. */
    uint16_t tcp_ctl;           /* Bitwise-OR of seen tcp_ctl values. */

    /* Actions. */
    union xflow_action *actions;
    unsigned int n_actions;
};

/* Interface to netdev-based datapath. */
struct xfif_netdev {
    struct xfif xfif;
    struct xf_netdev *xf;
    int listen_mask;
    unsigned int xf_serial;
};

/* All netdev-based datapaths. */
static struct xf_netdev *xf_netdevs[256];
struct list xf_netdev_list = LIST_INITIALIZER(&xf_netdev_list);
enum { N_XF_NETDEVS = ARRAY_SIZE(xf_netdevs) };

/* Maximum port MTU seen so far. */
static int max_mtu = ETH_PAYLOAD_MAX;

static int get_port_by_number(struct xf_netdev *, uint16_t port_no,
                              struct xf_netdev_port **portp);
static int get_port_by_name(struct xf_netdev *, const char *devname,
                            struct xf_netdev_port **portp);
static void xf_netdev_free(struct xf_netdev *);
static void xf_netdev_flow_flush(struct xf_netdev *);
static int do_add_port(struct xf_netdev *, const char *devname, uint16_t flags,
                       uint16_t port_no);
static int do_del_port(struct xf_netdev *, uint16_t port_no);
static int xf_netdev_output_control(struct xf_netdev *, const struct ofpbuf *,
                                    int queue_no, int port_no, uint32_t arg);
static int xf_netdev_execute_actions(struct xf_netdev *,
                                     struct ofpbuf *, struct xflow_key *,
                                     const union xflow_action *, int n);

static struct xfif_netdev *
xfif_netdev_cast(const struct xfif *xfif)
{
    xfif_assert_class(xfif, &xfif_netdev_class);
    return CONTAINER_OF(xfif, struct xfif_netdev, xfif);
}

static struct xf_netdev *
get_xf_netdev(const struct xfif *xfif)
{
    return xfif_netdev_cast(xfif)->xf;
}

static int
name_to_xf_idx(const char *name)
{
    if (!strncmp(name, "xf", 2) && isdigit((unsigned char)name[2])) {
        int xf_idx = atoi(name + 2);
        if (xf_idx >= 0 && xf_idx < N_XF_NETDEVS) {
            return xf_idx;
        }
    }
    return -1;
}

static struct xf_netdev *
find_xf_netdev(const char *name)
{
    int xf_idx;
    size_t i;

    xf_idx = name_to_xf_idx(name);
    if (xf_idx >= 0) {
        return xf_netdevs[xf_idx];
    }

    for (i = 0; i < N_XF_NETDEVS; i++) {
        struct xf_netdev *xf = xf_netdevs[i];
        if (xf) {
            struct xf_netdev_port *port;
            if (!get_port_by_name(xf, name, &port)) {
                return xf;
            }
        }
    }
    return NULL;
}

static struct xfif *
create_xfif_netdev(struct xf_netdev *xf)
{
    struct xfif_netdev *xfif;
    char *xfname;

    xf->open_cnt++;

    xfname = xasprintf("xf%d", xf->xf_idx);
    xfif = xmalloc(sizeof *xfif);
    xfif_init(&xfif->xfif, &xfif_netdev_class, xfname, xf->xf_idx, xf->xf_idx);
    xfif->xf = xf;
    xfif->listen_mask = 0;
    xfif->xf_serial = xf->serial;
    free(xfname);

    return &xfif->xfif;
}

static int
create_xf_netdev(const char *name, int xf_idx, struct xfif **xfifp)
{
    struct xf_netdev *xf;
    int error;
    int i;

    if (xf_netdevs[xf_idx]) {
        return EBUSY;
    }

    /* Create datapath. */
    xf_netdevs[xf_idx] = xf = xzalloc(sizeof *xf);
    list_push_back(&xf_netdev_list, &xf->node);
    xf->xf_idx = xf_idx;
    xf->open_cnt = 0;
    xf->drop_frags = false;
    for (i = 0; i < N_QUEUES; i++) {
        queue_init(&xf->queues[i]);
    }
    hmap_init(&xf->flow_table);
    for (i = 0; i < N_GROUPS; i++) {
        xf->groups[i].ports = NULL;
        xf->groups[i].n_ports = 0;
        xf->groups[i].group = i;
    }
    list_init(&xf->port_list);
    error = do_add_port(xf, name, XFLOW_PORT_INTERNAL, XFLOWP_LOCAL);
    if (error) {
        xf_netdev_free(xf);
        return ENODEV;
    }

    *xfifp = create_xfif_netdev(xf);
    return 0;
}

static int
xfif_netdev_open(const char *name, const char *type OVS_UNUSED, bool create,
                 struct xfif **xfifp)
{
    if (create) {
        if (find_xf_netdev(name)) {
            return EEXIST;
        } else {
            int xf_idx = name_to_xf_idx(name);
            if (xf_idx >= 0) {
                return create_xf_netdev(name, xf_idx, xfifp);
            } else {
                /* Scan for unused xf_idx number. */
                for (xf_idx = 0; xf_idx < N_XF_NETDEVS; xf_idx++) {
                    int error = create_xf_netdev(name, xf_idx, xfifp);
                    if (error != EBUSY) {
                        return error;
                    }
                }

                /* All datapath numbers in use. */
                return ENOBUFS;
            }
        }
    } else {
        struct xf_netdev *xf = find_xf_netdev(name);
        if (xf) {
            *xfifp = create_xfif_netdev(xf);
            return 0;
        } else {
            return ENODEV;
        }
    }
}

static void
xf_netdev_free(struct xf_netdev *xf)
{
    int i;

    xf_netdev_flow_flush(xf);
    while (xf->n_ports > 0) {
        struct xf_netdev_port *port = CONTAINER_OF(
            xf->port_list.next, struct xf_netdev_port, node);
        do_del_port(xf, port->port_no);
    }
    for (i = 0; i < N_QUEUES; i++) {
        queue_destroy(&xf->queues[i]);
    }
    hmap_destroy(&xf->flow_table);
    for (i = 0; i < N_GROUPS; i++) {
        free(xf->groups[i].ports);
    }
    xf_netdevs[xf->xf_idx] = NULL;
    list_remove(&xf->node);
    free(xf);
}

static void
xfif_netdev_close(struct xfif *xfif)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    assert(xf->open_cnt > 0);
    if (--xf->open_cnt == 0 && xf->destroyed) {
        xf_netdev_free(xf);
    }
    free(xfif);
}

static int
xfif_netdev_destroy(struct xfif *xfif)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    xf->destroyed = true;
    return 0;
}

static int
xfif_netdev_get_stats(const struct xfif *xfif, struct xflow_stats *stats)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    memset(stats, 0, sizeof *stats);
    stats->n_flows = hmap_count(&xf->flow_table);
    stats->cur_capacity = hmap_capacity(&xf->flow_table);
    stats->max_capacity = MAX_FLOWS;
    stats->n_ports = xf->n_ports;
    stats->max_ports = MAX_PORTS;
    stats->max_groups = N_GROUPS;
    stats->n_frags = xf->n_frags;
    stats->n_hit = xf->n_hit;
    stats->n_missed = xf->n_missed;
    stats->n_lost = xf->n_lost;
    stats->max_miss_queue = MAX_QUEUE_LEN;
    stats->max_action_queue = MAX_QUEUE_LEN;
    return 0;
}

static int
xfif_netdev_get_drop_frags(const struct xfif *xfif, bool *drop_fragsp)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    *drop_fragsp = xf->drop_frags;
    return 0;
}

static int
xfif_netdev_set_drop_frags(struct xfif *xfif, bool drop_frags)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    xf->drop_frags = drop_frags;
    return 0;
}

static int
do_add_port(struct xf_netdev *xf, const char *devname, uint16_t flags,
            uint16_t port_no)
{
    bool internal = (flags & XFLOW_PORT_INTERNAL) != 0;
    struct xf_netdev_port *port;
    struct netdev_options netdev_options;
    struct netdev *netdev;
    int mtu;
    int error;

    /* XXX reject devices already in some xf_netdev. */

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

    list_push_back(&xf->port_list, &port->node);
    xf->ports[port_no] = port;
    xf->n_ports++;
    xf->serial++;

    return 0;
}

static int
xfif_netdev_port_add(struct xfif *xfif, const char *devname, uint16_t flags,
                     uint16_t *port_nop)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    int port_no;

    for (port_no = 0; port_no < MAX_PORTS; port_no++) {
        if (!xf->ports[port_no]) {
            *port_nop = port_no;
            return do_add_port(xf, devname, flags, port_no);
        }
    }
    return EFBIG;
}

static int
xfif_netdev_port_del(struct xfif *xfif, uint16_t port_no)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    return port_no == XFLOWP_LOCAL ? EINVAL : do_del_port(xf, port_no);
}

static bool
is_valid_port_number(uint16_t port_no)
{
    return port_no < MAX_PORTS;
}

static int
get_port_by_number(struct xf_netdev *xf,
                   uint16_t port_no, struct xf_netdev_port **portp)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = xf->ports[port_no];
        return *portp ? 0 : ENOENT;
    }
}

static int
get_port_by_name(struct xf_netdev *xf,
                 const char *devname, struct xf_netdev_port **portp)
{
    struct xf_netdev_port *port;

    LIST_FOR_EACH (port, struct xf_netdev_port, node, &xf->port_list) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }
    return ENOENT;
}

static int
do_del_port(struct xf_netdev *xf, uint16_t port_no)
{
    struct xf_netdev_port *port;
    char *name;
    int error;

    error = get_port_by_number(xf, port_no, &port);
    if (error) {
        return error;
    }

    list_remove(&port->node);
    xf->ports[port->port_no] = NULL;
    xf->n_ports--;
    xf->serial++;

    name = xstrdup(netdev_get_name(port->netdev));
    netdev_close(port->netdev);

    free(name);
    free(port);

    return 0;
}

static void
answer_port_query(const struct xf_netdev_port *port, struct xflow_port *xflow_port)
{
    memset(xflow_port, 0, sizeof *xflow_port);
    ovs_strlcpy(xflow_port->devname, netdev_get_name(port->netdev),
                sizeof xflow_port->devname);
    xflow_port->port = port->port_no;
    xflow_port->flags = port->internal ? XFLOW_PORT_INTERNAL : 0;
}

static int
xfif_netdev_port_query_by_number(const struct xfif *xfif, uint16_t port_no,
                                 struct xflow_port *xflow_port)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_port *port;
    int error;

    error = get_port_by_number(xf, port_no, &port);
    if (!error) {
        answer_port_query(port, xflow_port);
    }
    return error;
}

static int
xfif_netdev_port_query_by_name(const struct xfif *xfif, const char *devname,
                               struct xflow_port *xflow_port)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_port *port;
    int error;

    error = get_port_by_name(xf, devname, &port);
    if (!error) {
        answer_port_query(port, xflow_port);
    }
    return error;
}

static void
xf_netdev_free_flow(struct xf_netdev *xf, struct xf_netdev_flow *flow)
{
    hmap_remove(&xf->flow_table, &flow->node);
    free(flow->actions);
    free(flow);
}

static void
xf_netdev_flow_flush(struct xf_netdev *xf)
{
    struct xf_netdev_flow *flow, *next;

    HMAP_FOR_EACH_SAFE (flow, next, struct xf_netdev_flow, node,
                        &xf->flow_table) {
        xf_netdev_free_flow(xf, flow);
    }
}

static int
xfif_netdev_flow_flush(struct xfif *xfif)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    xf_netdev_flow_flush(xf);
    return 0;
}

static int
xfif_netdev_port_list(const struct xfif *xfif, struct xflow_port *ports, int n)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_port *port;
    int i;

    i = 0;
    LIST_FOR_EACH (port, struct xf_netdev_port, node, &xf->port_list) {
        struct xflow_port *xflow_port = &ports[i];
        if (i >= n) {
            break;
        }
        answer_port_query(port, xflow_port);
        i++;
    }
    return xf->n_ports;
}

static int
xfif_netdev_port_poll(const struct xfif *xfif_, char **devnamep OVS_UNUSED)
{
    struct xfif_netdev *xfif = xfif_netdev_cast(xfif_);
    if (xfif->xf_serial != xfif->xf->serial) {
        xfif->xf_serial = xfif->xf->serial;
        return ENOBUFS;
    } else {
        return EAGAIN;
    }
}

static void
xfif_netdev_port_poll_wait(const struct xfif *xfif_)
{
    struct xfif_netdev *xfif = xfif_netdev_cast(xfif_);
    if (xfif->xf_serial != xfif->xf->serial) {
        poll_immediate_wake();
    }
}

static int
get_port_group(const struct xfif *xfif, int group_no,
               struct xflow_port_group **groupp)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);

    if (group_no >= 0 && group_no < N_GROUPS) {
        *groupp = &xf->groups[group_no];
        return 0;
    } else {
        *groupp = NULL;
        return EINVAL;
    }
}

static int
xfif_netdev_port_group_get(const struct xfif *xfif, int group_no,
                           uint16_t ports[], int n)
{
    struct xflow_port_group *group;
    int error;

    if (n < 0) {
        return -EINVAL;
    }

    error = get_port_group(xfif, group_no, &group);
    if (!error) {
        memcpy(ports, group->ports, MIN(n, group->n_ports) * sizeof *ports);
        return group->n_ports;
    } else {
        return -error;
    }
}

static int
xfif_netdev_port_group_set(struct xfif *xfif, int group_no,
                           const uint16_t ports[], int n)
{
    struct xflow_port_group *group;
    int error;

    if (n < 0 || n > MAX_PORTS) {
        return EINVAL;
    }

    error = get_port_group(xfif, group_no, &group);
    if (!error) {
        free(group->ports);
        group->ports = xmemdup(ports, n * sizeof *group->ports);
        group->n_ports = n;
        group->group = group_no;
    }
    return error;
}

static struct xf_netdev_flow *
xf_netdev_lookup_flow(const struct xf_netdev *xf,
                      const struct xflow_key *key)
{
    struct xf_netdev_flow *flow;

    HMAP_FOR_EACH_WITH_HASH (flow, struct xf_netdev_flow, node,
                             xflow_key_hash(key, 0), &xf->flow_table) {
        if (xflow_key_equal(&flow->key, key)) {
            return flow;
        }
    }
    return NULL;
}

static void
answer_flow_query(struct xf_netdev_flow *flow, uint32_t query_flags,
                  struct xflow_flow *xflow_flow)
{
    if (flow) {
        xflow_flow->key = flow->key;
        xflow_flow->stats.n_packets = flow->packet_count;
        xflow_flow->stats.n_bytes = flow->byte_count;
        xflow_flow->stats.used_sec = flow->used.tv_sec;
        xflow_flow->stats.used_nsec = flow->used.tv_nsec;
        xflow_flow->stats.tcp_flags = TCP_FLAGS(flow->tcp_ctl);
        xflow_flow->stats.ip_tos = flow->ip_tos;
        xflow_flow->stats.error = 0;
        if (xflow_flow->n_actions > 0) {
            unsigned int n = MIN(xflow_flow->n_actions, flow->n_actions);
            memcpy(xflow_flow->actions, flow->actions,
                   n * sizeof *xflow_flow->actions);
            xflow_flow->n_actions = flow->n_actions;
        }

        if (query_flags & XFLOWFF_ZERO_TCP_FLAGS) {
            flow->tcp_ctl = 0;
        }

    } else {
        xflow_flow->stats.error = ENOENT;
    }
}

static int
xfif_netdev_flow_get(const struct xfif *xfif, struct xflow_flow flows[], int n)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    int i;

    for (i = 0; i < n; i++) {
        struct xflow_flow *xflow_flow = &flows[i];
        answer_flow_query(xf_netdev_lookup_flow(xf, &xflow_flow->key),
                          xflow_flow->flags, xflow_flow);
    }
    return 0;
}

static int
xfif_netdev_validate_actions(const union xflow_action *actions, int n_actions,
                             bool *mutates)
{
    unsigned int i;

    *mutates = false;
    for (i = 0; i < n_actions; i++) {
        const union xflow_action *a = &actions[i];
        switch (a->type) {
        case XFLOWAT_OUTPUT:
            if (a->output.port >= MAX_PORTS) {
                return EINVAL;
            }
            break;

        case XFLOWAT_OUTPUT_GROUP:
            *mutates = true;
            if (a->output_group.group >= N_GROUPS) {
                return EINVAL;
            }
            break;

        case XFLOWAT_CONTROLLER:
            break;

        case XFLOWAT_SET_DL_TCI:
            *mutates = true;
            if (a->dl_tci.mask != htons(VLAN_VID_MASK)
                && a->dl_tci.mask != htons(VLAN_PCP_MASK)
                && a->dl_tci.mask != htons(VLAN_VID_MASK | VLAN_PCP_MASK)) {
                return EINVAL;
            }
            if (a->dl_tci.tci & ~a->dl_tci.mask){
                return EINVAL;
            }
            break;

        case XFLOWAT_SET_NW_TOS:
            *mutates = true;
            if (a->nw_tos.nw_tos & IP_ECN_MASK) {
                return EINVAL;
            }
            break;

        case XFLOWAT_STRIP_VLAN:
        case XFLOWAT_SET_DL_SRC:
        case XFLOWAT_SET_DL_DST:
        case XFLOWAT_SET_NW_SRC:
        case XFLOWAT_SET_NW_DST:
        case XFLOWAT_SET_TP_SRC:
        case XFLOWAT_SET_TP_DST:
            *mutates = true;
            break;

        default:
            return EOPNOTSUPP;
        }
    }
    return 0;
}

static int
set_flow_actions(struct xf_netdev_flow *flow, struct xflow_flow *xflow_flow)
{
    size_t n_bytes;
    bool mutates;
    int error;

    if (xflow_flow->n_actions >= 4096 / sizeof *xflow_flow->actions) {
        return EINVAL;
    }
    error = xfif_netdev_validate_actions(xflow_flow->actions,
                                         xflow_flow->n_actions, &mutates);
    if (error) {
        return error;
    }

    n_bytes = xflow_flow->n_actions * sizeof *flow->actions;
    flow->actions = xrealloc(flow->actions, n_bytes);
    flow->n_actions = xflow_flow->n_actions;
    memcpy(flow->actions, xflow_flow->actions, n_bytes);
    return 0;
}

static int
add_flow(struct xfif *xfif, struct xflow_flow *xflow_flow)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_flow *flow;
    int error;

    flow = xzalloc(sizeof *flow);
    flow->key = xflow_flow->key;

    error = set_flow_actions(flow, xflow_flow);
    if (error) {
        free(flow);
        return error;
    }

    hmap_insert(&xf->flow_table, &flow->node,
                xflow_key_hash(&flow->key, 0));
    return 0;
}

static void
clear_stats(struct xf_netdev_flow *flow)
{
    flow->used.tv_sec = 0;
    flow->used.tv_nsec = 0;
    flow->packet_count = 0;
    flow->byte_count = 0;
    flow->ip_tos = 0;
    flow->tcp_ctl = 0;
}

static int
xfif_netdev_flow_put(struct xfif *xfif, struct xflow_flow_put *put)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_flow *flow;

    flow = xf_netdev_lookup_flow(xf, &put->flow.key);
    if (!flow) {
        if (put->flags & XFLOWPF_CREATE) {
            if (hmap_count(&xf->flow_table) < MAX_FLOWS) {
                return add_flow(xfif, &put->flow);
            } else {
                return EFBIG;
            }
        } else {
            return ENOENT;
        }
    } else {
        if (put->flags & XFLOWPF_MODIFY) {
            int error = set_flow_actions(flow, &put->flow);
            if (!error && put->flags & XFLOWPF_ZERO_STATS) {
                clear_stats(flow);
            }
            return error;
        } else {
            return EEXIST;
        }
    }
}


static int
xfif_netdev_flow_del(struct xfif *xfif, struct xflow_flow *xflow_flow)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_flow *flow;

    flow = xf_netdev_lookup_flow(xf, &xflow_flow->key);
    if (flow) {
        answer_flow_query(flow, 0, xflow_flow);
        xf_netdev_free_flow(xf, flow);
        return 0;
    } else {
        return ENOENT;
    }
}

static int
xfif_netdev_flow_list(const struct xfif *xfif, struct xflow_flow flows[], int n)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct xf_netdev_flow *flow;
    int i;

    i = 0;
    HMAP_FOR_EACH (flow, struct xf_netdev_flow, node, &xf->flow_table) {
        if (i >= n) {
            break;
        }
        answer_flow_query(flow, 0, &flows[i++]);
    }
    return hmap_count(&xf->flow_table);
}

static int
xfif_netdev_execute(struct xfif *xfif, uint16_t in_port,
                    const union xflow_action actions[], int n_actions,
                    const struct ofpbuf *packet)
{
    struct xf_netdev *xf = get_xf_netdev(xfif);
    struct ofpbuf copy;
    bool mutates;
    struct xflow_key key;
    flow_t flow;
    int error;

    if (packet->size < ETH_HEADER_LEN || packet->size > UINT16_MAX) {
        return EINVAL;
    }

    error = xfif_netdev_validate_actions(actions, n_actions, &mutates);
    if (error) {
        return error;
    }

    if (mutates) {
        /* We need a deep copy of 'packet' since we're going to modify its
         * data. */
        ofpbuf_init(&copy, XF_NETDEV_HEADROOM + packet->size);
        copy.data = (char*)copy.base + XF_NETDEV_HEADROOM;
        ofpbuf_put(&copy, packet->data, packet->size);
    } else {
        /* We still need a shallow copy of 'packet', even though we won't
         * modify its data, because flow_extract() modifies packet->l2, etc.
         * We could probably get away with modifying those but it's more polite
         * if we don't. */
        copy = *packet;
    }
    flow_extract(&copy, 0, in_port, &flow);
    xflow_key_from_flow(&key, &flow);
    error = xf_netdev_execute_actions(xf, &copy, &key, actions, n_actions);
    if (mutates) {
        ofpbuf_uninit(&copy);
    }
    return error;
}

static int
xfif_netdev_recv_get_mask(const struct xfif *xfif, int *listen_mask)
{
    struct xfif_netdev *xfif_netdev = xfif_netdev_cast(xfif);
    *listen_mask = xfif_netdev->listen_mask;
    return 0;
}

static int
xfif_netdev_recv_set_mask(struct xfif *xfif, int listen_mask)
{
    struct xfif_netdev *xfif_netdev = xfif_netdev_cast(xfif);
    if (!(listen_mask & ~XFLOWL_ALL)) {
        xfif_netdev->listen_mask = listen_mask;
        return 0;
    } else {
        return EINVAL;
    }
}

static struct ovs_queue *
find_nonempty_queue(struct xfif *xfif)
{
    struct xfif_netdev *xfif_netdev = xfif_netdev_cast(xfif);
    struct xf_netdev *xf = get_xf_netdev(xfif);
    int mask = xfif_netdev->listen_mask;
    int i;

    for (i = 0; i < N_QUEUES; i++) {
        struct ovs_queue *q = &xf->queues[i];
        if (q->n && mask & (1u << i)) {
            return q;
        }
    }
    return NULL;
}

static int
xfif_netdev_recv(struct xfif *xfif, struct ofpbuf **bufp)
{
    struct ovs_queue *q = find_nonempty_queue(xfif);
    if (q) {
        *bufp = queue_pop_head(q);
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
xfif_netdev_recv_wait(struct xfif *xfif)
{
    struct ovs_queue *q = find_nonempty_queue(xfif);
    if (q) {
        poll_immediate_wake();
    } else {
        /* No messages ready to be received, and xf_wait() will ensure that we
         * wake up to queue new messages, so there is nothing to do. */
    }
}

static void
xf_netdev_flow_used(struct xf_netdev_flow *flow,
                    const struct xflow_key *key,
                    const struct ofpbuf *packet)
{
    time_timespec(&flow->used);
    flow->packet_count++;
    flow->byte_count += packet->size;
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *nh = packet->l3;
        flow->ip_tos = nh->ip_tos;

        if (key->nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = packet->l4;
            flow->tcp_ctl |= th->tcp_ctl;
        }
    }
}

static void
xf_netdev_port_input(struct xf_netdev *xf, struct xf_netdev_port *port,
                     struct ofpbuf *packet)
{
    struct xf_netdev_flow *flow;
    struct xflow_key key;
    flow_t f;

    if (flow_extract(packet, 0, port->port_no, &f) && xf->drop_frags) {
        xf->n_frags++;
        return;
    }
    xflow_key_from_flow(&key, &f);

    flow = xf_netdev_lookup_flow(xf, &key);
    if (flow) {
        xf_netdev_flow_used(flow, &key, packet);
        xf_netdev_execute_actions(xf, packet, &key,
                                  flow->actions, flow->n_actions);
        xf->n_hit++;
    } else {
        xf->n_missed++;
        xf_netdev_output_control(xf, packet, _XFLOWL_MISS_NR, port->port_no, 0);
    }
}

static void
xf_netdev_run(void)
{
    struct ofpbuf packet;
    struct xf_netdev *xf;

    ofpbuf_init(&packet, XF_NETDEV_HEADROOM + max_mtu);
    LIST_FOR_EACH (xf, struct xf_netdev, node, &xf_netdev_list) {
        struct xf_netdev_port *port;

        LIST_FOR_EACH (port, struct xf_netdev_port, node, &xf->port_list) {
            int error;

            /* Reset packet contents. */
            packet.data = (char*)packet.base + XF_NETDEV_HEADROOM;
            packet.size = 0;

            error = netdev_recv(port->netdev, &packet);
            if (!error) {
                xf_netdev_port_input(xf, port, &packet);
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
xf_netdev_wait(void)
{
    struct xf_netdev *xf;

    LIST_FOR_EACH (xf, struct xf_netdev, node, &xf_netdev_list) {
        struct xf_netdev_port *port;
        LIST_FOR_EACH (port, struct xf_netdev_port, node, &xf->port_list) {
            netdev_recv_wait(port->netdev);
        }
    }
}


/* Modify or add a 802.1Q header in 'packet' according to 'a'. */
static void
xf_netdev_set_dl_tci(struct ofpbuf *packet, struct xflow_key *key,
                     const struct xflow_action_dl_tci *a)
{
    struct vlan_eth_header *veh;

    if (key->dl_tci) {
        veh = packet->l2;
        veh->veth_tci = (veh->veth_tci & ~a->mask) | a->tci;
    } else {
        /* Insert new 802.1Q header. */
        struct eth_header *eh = packet->l2;
        struct vlan_eth_header tmp;
        memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
        memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
        tmp.veth_type = htons(ETH_TYPE_VLAN);
        tmp.veth_tci = htons(a->tci);
        tmp.veth_next_type = eh->eth_type;

        veh = ofpbuf_push_uninit(packet, VLAN_HEADER_LEN);
        memcpy(veh, &tmp, sizeof tmp);
        packet->l2 = (char*)packet->l2 - VLAN_HEADER_LEN;
    }

    key->dl_tci = veh->veth_tci | htons(XFLOW_TCI_PRESENT);
}

static void
xf_netdev_strip_vlan(struct ofpbuf *packet, struct xflow_key *key)
{
    struct vlan_eth_header *veh = packet->l2;
    if (veh->veth_type == htons(ETH_TYPE_VLAN)) {
        struct eth_header tmp;

        memcpy(tmp.eth_dst, veh->veth_dst, ETH_ADDR_LEN);
        memcpy(tmp.eth_src, veh->veth_src, ETH_ADDR_LEN);
        tmp.eth_type = veh->veth_next_type;

        packet->size -= VLAN_HEADER_LEN;
        packet->data = (char*)packet->data + VLAN_HEADER_LEN;
        packet->l2 = (char*)packet->l2 + VLAN_HEADER_LEN;
        memcpy(packet->data, &tmp, sizeof tmp);

        key->dl_tci = htons(0);
    }
}

static void
xf_netdev_set_dl_src(struct ofpbuf *packet,
                     const uint8_t dl_addr[ETH_ADDR_LEN])
{
    struct eth_header *eh = packet->l2;
    memcpy(eh->eth_src, dl_addr, sizeof eh->eth_src);
}

static void
xf_netdev_set_dl_dst(struct ofpbuf *packet,
                     const uint8_t dl_addr[ETH_ADDR_LEN])
{
    struct eth_header *eh = packet->l2;
    memcpy(eh->eth_dst, dl_addr, sizeof eh->eth_dst);
}

static void
xf_netdev_set_nw_addr(struct ofpbuf *packet, const struct xflow_key *key,
                      const struct xflow_action_nw_addr *a)
{
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *nh = packet->l3;
        uint32_t *field;

        field = a->type == XFLOWAT_SET_NW_SRC ? &nh->ip_src : &nh->ip_dst;
        if (key->nw_proto == IP_TYPE_TCP) {
            struct tcp_header *th = packet->l4;
            th->tcp_csum = recalc_csum32(th->tcp_csum, *field, a->nw_addr);
        } else if (key->nw_proto == IP_TYPE_UDP) {
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
xf_netdev_set_nw_tos(struct ofpbuf *packet, const struct xflow_key *key,
                     const struct xflow_action_nw_tos *a)
{
    if (key->dl_type == htons(ETH_TYPE_IP)) {
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
xf_netdev_set_tp_port(struct ofpbuf *packet, const struct xflow_key *key,
                      const struct xflow_action_tp_port *a)
{
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        uint16_t *field;
        if (key->nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = packet->l4;
            field = a->type == XFLOWAT_SET_TP_SRC ? &th->tcp_src : &th->tcp_dst;
            th->tcp_csum = recalc_csum16(th->tcp_csum, *field, a->tp_port);
            *field = a->tp_port;
        } else if (key->nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = packet->l4;
            field = a->type == XFLOWAT_SET_TP_SRC ? &uh->udp_src : &uh->udp_dst;
            uh->udp_csum = recalc_csum16(uh->udp_csum, *field, a->tp_port);
            *field = a->tp_port;
        } else {
            return;
        }
    }
}

static void
xf_netdev_output_port(struct xf_netdev *xf, struct ofpbuf *packet,
                      uint16_t out_port)
{
    struct xf_netdev_port *p = xf->ports[out_port];
    if (p) {
        netdev_send(p->netdev, packet);
    }
}

static void
xf_netdev_output_group(struct xf_netdev *xf, uint16_t group, uint16_t in_port,
                       struct ofpbuf *packet)
{
    struct xflow_port_group *g = &xf->groups[group];
    int i;

    for (i = 0; i < g->n_ports; i++) {
        uint16_t out_port = g->ports[i];
        if (out_port != in_port) {
            xf_netdev_output_port(xf, packet, out_port);
        }
    }
}

static int
xf_netdev_output_control(struct xf_netdev *xf, const struct ofpbuf *packet,
                         int queue_no, int port_no, uint32_t arg)
{
    struct ovs_queue *q = &xf->queues[queue_no];
    struct xflow_msg *header;
    struct ofpbuf *msg;
    size_t msg_size;

    if (q->n >= MAX_QUEUE_LEN) {
        xf->n_lost++;
        return ENOBUFS;
    }

    msg_size = sizeof *header + packet->size;
    msg = ofpbuf_new(msg_size + XFIF_RECV_MSG_PADDING);
    header = ofpbuf_put_uninit(msg, sizeof *header);
    ofpbuf_reserve(msg, XFIF_RECV_MSG_PADDING);
    header->type = queue_no;
    header->length = msg_size;
    header->port = port_no;
    header->arg = arg;
    ofpbuf_put(msg, packet->data, packet->size);
    queue_push_tail(q, msg);

    return 0;
}

static int
xf_netdev_execute_actions(struct xf_netdev *xf,
                          struct ofpbuf *packet, struct xflow_key *key,
                          const union xflow_action *actions, int n_actions)
{
    int i;
    for (i = 0; i < n_actions; i++) {
        const union xflow_action *a = &actions[i];

        switch (a->type) {
        case XFLOWAT_OUTPUT:
            xf_netdev_output_port(xf, packet, a->output.port);
            break;

        case XFLOWAT_OUTPUT_GROUP:
            xf_netdev_output_group(xf, a->output_group.group, key->in_port,
                                   packet);
            break;

        case XFLOWAT_CONTROLLER:
            xf_netdev_output_control(xf, packet, _XFLOWL_ACTION_NR,
                                     key->in_port, a->controller.arg);
            break;

        case XFLOWAT_SET_DL_TCI:
            xf_netdev_set_dl_tci(packet, key, &a->dl_tci);
            break;

        case XFLOWAT_STRIP_VLAN:
            xf_netdev_strip_vlan(packet, key);
            break;

        case XFLOWAT_SET_DL_SRC:
            xf_netdev_set_dl_src(packet, a->dl_addr.dl_addr);
            break;

        case XFLOWAT_SET_DL_DST:
            xf_netdev_set_dl_dst(packet, a->dl_addr.dl_addr);
            break;

        case XFLOWAT_SET_NW_SRC:
        case XFLOWAT_SET_NW_DST:
            xf_netdev_set_nw_addr(packet, key, &a->nw_addr);
            break;

        case XFLOWAT_SET_NW_TOS:
            xf_netdev_set_nw_tos(packet, key, &a->nw_tos);
            break;

        case XFLOWAT_SET_TP_SRC:
        case XFLOWAT_SET_TP_DST:
            xf_netdev_set_tp_port(packet, key, &a->tp_port);
            break;
        }
    }
    return 0;
}

const struct xfif_class xfif_netdev_class = {
    "netdev",
    xf_netdev_run,
    xf_netdev_wait,
    NULL,                       /* enumerate */
    xfif_netdev_open,
    xfif_netdev_close,
    NULL,                       /* get_all_names */
    xfif_netdev_destroy,
    xfif_netdev_get_stats,
    xfif_netdev_get_drop_frags,
    xfif_netdev_set_drop_frags,
    xfif_netdev_port_add,
    xfif_netdev_port_del,
    xfif_netdev_port_query_by_number,
    xfif_netdev_port_query_by_name,
    xfif_netdev_port_list,
    xfif_netdev_port_poll,
    xfif_netdev_port_poll_wait,
    xfif_netdev_port_group_get,
    xfif_netdev_port_group_set,
    xfif_netdev_flow_get,
    xfif_netdev_flow_put,
    xfif_netdev_flow_del,
    xfif_netdev_flow_flush,
    xfif_netdev_flow_list,
    xfif_netdev_execute,
    xfif_netdev_recv_get_mask,
    xfif_netdev_recv_set_mask,
    NULL,                       /* get_sflow_probability */
    NULL,                       /* set_sflow_probability */
    xfif_netdev_recv,
    xfif_netdev_recv_wait,
};
