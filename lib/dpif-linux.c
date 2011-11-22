/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#include "dpif-linux.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netdev-linux.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "openvswitch/datapath-compat.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "shash.h"
#include "sset.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_linux);

enum { LRU_MAX_PORTS = 1024 };
enum { LRU_MASK = LRU_MAX_PORTS - 1};
BUILD_ASSERT_DECL(IS_POW2(LRU_MAX_PORTS));

enum { N_UPCALL_SOCKS = 16 };
BUILD_ASSERT_DECL(IS_POW2(N_UPCALL_SOCKS));
BUILD_ASSERT_DECL(N_UPCALL_SOCKS <= 32); /* We use a 32-bit word as a mask. */

/* This ethtool flag was introduced in Linux 2.6.24, so it might be
 * missing if we have old headers. */
#define ETH_FLAG_LRO      (1 << 15)    /* LRO is enabled */

struct dpif_linux_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    int dp_ifindex;

    /* Attributes. */
    const char *name;                  /* OVS_DP_ATTR_NAME. */
    const uint32_t *upcall_pid;        /* OVS_DP_UPCALL_PID. */
    struct ovs_dp_stats stats;         /* OVS_DP_ATTR_STATS. */
};

static void dpif_linux_dp_init(struct dpif_linux_dp *);
static int dpif_linux_dp_from_ofpbuf(struct dpif_linux_dp *,
                                     const struct ofpbuf *);
static void dpif_linux_dp_dump_start(struct nl_dump *);
static int dpif_linux_dp_transact(const struct dpif_linux_dp *request,
                                  struct dpif_linux_dp *reply,
                                  struct ofpbuf **bufp);
static int dpif_linux_dp_get(const struct dpif *, struct dpif_linux_dp *reply,
                             struct ofpbuf **bufp);

struct dpif_linux_flow {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    unsigned int nlmsg_flags;
    int dp_ifindex;

    /* Attributes.
     *
     * The 'stats' member points to 64-bit data that might only be aligned on
     * 32-bit boundaries, so get_unaligned_u64() should be used to access its
     * values.
     *
     * If 'actions' is nonnull then OVS_FLOW_ATTR_ACTIONS will be included in
     * the Netlink version of the command, even if actions_len is zero. */
    const struct nlattr *key;           /* OVS_FLOW_ATTR_KEY. */
    size_t key_len;
    const struct nlattr *actions;       /* OVS_FLOW_ATTR_ACTIONS. */
    size_t actions_len;
    const struct ovs_flow_stats *stats; /* OVS_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* OVS_FLOW_ATTR_TCP_FLAGS. */
    const ovs_32aligned_u64 *used;      /* OVS_FLOW_ATTR_USED. */
    bool clear;                         /* OVS_FLOW_ATTR_CLEAR. */
};

static void dpif_linux_flow_init(struct dpif_linux_flow *);
static int dpif_linux_flow_from_ofpbuf(struct dpif_linux_flow *,
                                       const struct ofpbuf *);
static void dpif_linux_flow_to_ofpbuf(const struct dpif_linux_flow *,
                                      struct ofpbuf *);
static int dpif_linux_flow_transact(struct dpif_linux_flow *request,
                                    struct dpif_linux_flow *reply,
                                    struct ofpbuf **bufp);
static void dpif_linux_flow_get_stats(const struct dpif_linux_flow *,
                                      struct dpif_flow_stats *);

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int dp_ifindex;

    /* Upcall messages. */
    struct nl_sock *upcall_socks[N_UPCALL_SOCKS];
    uint32_t ready_mask;        /* 1-bit for each sock with unread messages. */
    unsigned int listen_mask;   /* Mask of DPIF_UC_* bits. */
    int epoll_fd;               /* epoll fd that includes the upcall socks. */

    /* Change notification. */
    struct sset changed_ports;  /* Ports that have changed. */
    struct nln_notifier *port_notifier;
    bool change_error;

    /* Queue of unused ports. */
    unsigned long *lru_bitmap;
    uint16_t lru_ports[LRU_MAX_PORTS];
    size_t lru_head;
    size_t lru_tail;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for OVS. */
static int ovs_datapath_family;
static int ovs_vport_family;
static int ovs_flow_family;
static int ovs_packet_family;

/* Generic Netlink socket. */
static struct nl_sock *genl_sock;
static struct nln *nln = NULL;

static int dpif_linux_init(void);
static void open_dpif(const struct dpif_linux_dp *, struct dpif **);
static bool dpif_linux_nln_parse(struct ofpbuf *, void *);
static void dpif_linux_port_changed(const void *vport, void *dpif);
static uint32_t dpif_linux_port_get_pid__(const struct dpif *,
                                          uint16_t port_no,
                                          enum dpif_upcall_type);

static void dpif_linux_vport_to_ofpbuf(const struct dpif_linux_vport *,
                                       struct ofpbuf *);
static int dpif_linux_vport_from_ofpbuf(struct dpif_linux_vport *,
                                        const struct ofpbuf *);

static struct dpif_linux *
dpif_linux_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_linux_class);
    return CONTAINER_OF(dpif, struct dpif_linux, dpif);
}

static void
dpif_linux_push_port(struct dpif_linux *dp, uint16_t port)
{
    if (port < LRU_MAX_PORTS && !bitmap_is_set(dp->lru_bitmap, port)) {
        bitmap_set1(dp->lru_bitmap, port);
        dp->lru_ports[dp->lru_head++ & LRU_MASK] = port;
    }
}

static uint32_t
dpif_linux_pop_port(struct dpif_linux *dp)
{
    uint16_t port;

    if (dp->lru_head == dp->lru_tail) {
        return UINT32_MAX;
    }

    port = dp->lru_ports[dp->lru_tail++ & LRU_MASK];
    bitmap_set0(dp->lru_bitmap, port);
    return port;
}

static int
dpif_linux_enumerate(struct sset *all_dps)
{
    struct nl_dump dump;
    struct ofpbuf msg;
    int error;

    error = dpif_linux_init();
    if (error) {
        return error;
    }

    dpif_linux_dp_dump_start(&dump);
    while (nl_dump_next(&dump, &msg)) {
        struct dpif_linux_dp dp;

        if (!dpif_linux_dp_from_ofpbuf(&dp, &msg)) {
            sset_add(all_dps, dp.name);
        }
    }
    return nl_dump_done(&dump);
}

static int
dpif_linux_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                bool create, struct dpif **dpifp)
{
    struct dpif_linux_dp dp_request, dp;
    struct ofpbuf *buf;
    uint32_t upcall_pid;
    int error;

    error = dpif_linux_init();
    if (error) {
        return error;
    }

    /* Create or look up datapath. */
    dpif_linux_dp_init(&dp_request);
    if (create) {
        dp_request.cmd = OVS_DP_CMD_NEW;
        upcall_pid = 0;
        dp_request.upcall_pid = &upcall_pid;
    } else {
        dp_request.cmd = OVS_DP_CMD_GET;
    }
    dp_request.name = name;
    error = dpif_linux_dp_transact(&dp_request, &dp, &buf);
    if (error) {
        return error;
    }

    open_dpif(&dp, dpifp);
    ofpbuf_delete(buf);
    return 0;
}

static void
open_dpif(const struct dpif_linux_dp *dp, struct dpif **dpifp)
{
    struct dpif_linux *dpif;
    int i;

    dpif = xzalloc(sizeof *dpif);
    dpif->port_notifier = nln_notifier_create(nln, dpif_linux_port_changed,
                                              dpif);
    dpif->epoll_fd = -1;

    dpif_init(&dpif->dpif, &dpif_linux_class, dp->name,
              dp->dp_ifindex, dp->dp_ifindex);

    dpif->dp_ifindex = dp->dp_ifindex;
    sset_init(&dpif->changed_ports);
    *dpifp = &dpif->dpif;

    dpif->lru_bitmap = bitmap_allocate(LRU_MAX_PORTS);
    bitmap_set1(dpif->lru_bitmap, OVSP_LOCAL);
    for (i = 1; i < LRU_MAX_PORTS; i++) {
        dpif_linux_push_port(dpif, i);
    }
}

static void
destroy_upcall_socks(struct dpif_linux *dpif)
{
    int i;

    if (dpif->epoll_fd >= 0) {
        close(dpif->epoll_fd);
        dpif->epoll_fd = -1;
    }
    for (i = 0; i < N_UPCALL_SOCKS; i++) {
        nl_sock_destroy(dpif->upcall_socks[i]);
        dpif->upcall_socks[i] = NULL;
    }
}

static void
dpif_linux_close(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    nln_notifier_destroy(dpif->port_notifier);
    destroy_upcall_socks(dpif);
    sset_destroy(&dpif->changed_ports);
    free(dpif->lru_bitmap);
    free(dpif);
}

static int
dpif_linux_destroy(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp dp;

    dpif_linux_dp_init(&dp);
    dp.cmd = OVS_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_linux_dp_transact(&dp, NULL, NULL);
}

static void
dpif_linux_run(struct dpif *dpif OVS_UNUSED)
{
    if (nln) {
        nln_run(nln);
    }
}

static void
dpif_linux_wait(struct dpif *dpif OVS_UNUSED)
{
    if (nln) {
        nln_wait(nln);
    }
}

static int
dpif_linux_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    struct dpif_linux_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_dp_get(dpif_, &dp, &buf);
    if (!error) {
        stats->n_hit    = dp.stats.n_hit;
        stats->n_missed = dp.stats.n_missed;
        stats->n_lost   = dp.stats.n_lost;
        stats->n_flows  = dp.stats.n_flows;
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_port_add(struct dpif *dpif_, struct netdev *netdev,
                    uint16_t *port_nop)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    const char *name = netdev_get_name(netdev);
    const char *type = netdev_get_type(netdev);
    struct dpif_linux_vport request, reply;
    const struct ofpbuf *options;
    struct ofpbuf *buf;
    int error;

    dpif_linux_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = netdev_vport_get_vport_type(netdev);
    if (request.type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(dpif_), name, type);
        return EINVAL;
    }
    request.name = name;

    options = netdev_vport_get_options(netdev);
    if (options && options->size) {
        request.options = options->data;
        request.options_len = options->size;
    }

    if (request.type == OVS_VPORT_TYPE_NETDEV) {
        netdev_linux_ethtool_set_flag(netdev, ETH_FLAG_LRO, "LRO", false);
    }

    /* Loop until we find a port that isn't used. */
    do {
        uint32_t upcall_pid;

        request.port_no = dpif_linux_pop_port(dpif);
        upcall_pid = dpif_linux_port_get_pid__(dpif_, request.port_no,
                                               DPIF_UC_MISS);
        request.upcall_pid = &upcall_pid;
        error = dpif_linux_vport_transact(&request, &reply, &buf);

        if (!error) {
            *port_nop = reply.port_no;
            VLOG_DBG("%s: assigning port %"PRIu32" to netlink pid %"PRIu32,
                     dpif_name(dpif_), request.port_no, upcall_pid);
        }
        ofpbuf_delete(buf);
    } while (request.port_no != UINT32_MAX
             && (error == EBUSY || error == EFBIG));

    return error;
}

static int
dpif_linux_port_del(struct dpif *dpif_, uint16_t port_no)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_vport vport;
    int error;

    dpif_linux_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_DEL;
    vport.dp_ifindex = dpif->dp_ifindex;
    vport.port_no = port_no;
    error = dpif_linux_vport_transact(&vport, NULL, NULL);

    if (!error) {
        dpif_linux_push_port(dpif, port_no);
    }
    return error;
}

static int
dpif_linux_port_query__(const struct dpif *dpif, uint32_t port_no,
                        const char *port_name, struct dpif_port *dpif_port)
{
    struct dpif_linux_vport request;
    struct dpif_linux_vport reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif_linux_cast(dpif)->dp_ifindex;
    request.port_no = port_no;
    request.name = port_name;

    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (!error) {
        dpif_port->name = xstrdup(reply.name);
        dpif_port->type = xstrdup(netdev_vport_get_netdev_type(&reply));
        dpif_port->port_no = reply.port_no;
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                                struct dpif_port *dpif_port)
{
    return dpif_linux_port_query__(dpif, port_no, NULL, dpif_port);
}

static int
dpif_linux_port_query_by_name(const struct dpif *dpif, const char *devname,
                              struct dpif_port *dpif_port)
{
    return dpif_linux_port_query__(dpif, 0, devname, dpif_port);
}

static int
dpif_linux_get_max_ports(const struct dpif *dpif OVS_UNUSED)
{
    /* If the datapath increases its range of supported ports, then it should
     * start reporting that. */
    return 1024;
}

static uint32_t
dpif_linux_port_get_pid__(const struct dpif *dpif_, uint16_t port_no,
                          enum dpif_upcall_type upcall_type)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (!(dpif->listen_mask & (1u << upcall_type))) {
        return 0;
    } else {
        int idx = port_no & (N_UPCALL_SOCKS - 1);
        return nl_sock_pid(dpif->upcall_socks[idx]);
    }
}

static uint32_t
dpif_linux_port_get_pid(const struct dpif *dpif, uint16_t port_no)
{
    return dpif_linux_port_get_pid__(dpif, port_no, DPIF_UC_ACTION);
}

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow flow;

    dpif_linux_flow_init(&flow);
    flow.cmd = OVS_FLOW_CMD_DEL;
    flow.dp_ifindex = dpif->dp_ifindex;
    return dpif_linux_flow_transact(&flow, NULL, NULL);
}

struct dpif_linux_port_state {
    struct nl_dump dump;
    unsigned long *port_bitmap; /* Ports in the datapath. */
    bool complete;              /* Dump completed without error. */
};

static int
dpif_linux_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_port_state *state;
    struct dpif_linux_vport request;
    struct ofpbuf *buf;

    *statep = state = xmalloc(sizeof *state);
    state->port_bitmap = bitmap_allocate(LRU_MAX_PORTS);
    state->complete = false;

    dpif_linux_vport_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_linux_vport_to_ofpbuf(&request, buf);
    nl_dump_start(&state->dump, genl_sock, buf);
    ofpbuf_delete(buf);

    return 0;
}

static int
dpif_linux_port_dump_next(const struct dpif *dpif OVS_UNUSED, void *state_,
                          struct dpif_port *dpif_port)
{
    struct dpif_linux_port_state *state = state_;
    struct dpif_linux_vport vport;
    struct ofpbuf buf;
    int error;

    if (!nl_dump_next(&state->dump, &buf)) {
        state->complete = true;
        return EOF;
    }

    error = dpif_linux_vport_from_ofpbuf(&vport, &buf);
    if (error) {
        return error;
    }

    if (vport.port_no < LRU_MAX_PORTS) {
        bitmap_set1(state->port_bitmap, vport.port_no);
    }

    dpif_port->name = (char *) vport.name;
    dpif_port->type = (char *) netdev_vport_get_netdev_type(&vport);
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_linux_port_dump_done(const struct dpif *dpif_, void *state_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_port_state *state = state_;
    int error = nl_dump_done(&state->dump);

    if (state->complete) {
        uint16_t i;

        for (i = 0; i < LRU_MAX_PORTS; i++) {
            if (!bitmap_is_set(state->port_bitmap, i)) {
                dpif_linux_push_port(dpif, i);
            }
        }
    }

    free(state->port_bitmap);
    free(state);
    return error;
}

static int
dpif_linux_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (dpif->change_error) {
        dpif->change_error = false;
        sset_clear(&dpif->changed_ports);
        return ENOBUFS;
    } else if (!sset_is_empty(&dpif->changed_ports)) {
        *devnamep = sset_pop(&dpif->changed_ports);
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_linux_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    if (!sset_is_empty(&dpif->changed_ports) || dpif->change_error) {
        poll_immediate_wake();
    }
}

static int
dpif_linux_flow_get__(const struct dpif *dpif_,
                      const struct nlattr *key, size_t key_len,
                      struct dpif_linux_flow *reply, struct ofpbuf **bufp)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow request;

    dpif_linux_flow_init(&request);
    request.cmd = OVS_FLOW_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.key = key;
    request.key_len = key_len;
    return dpif_linux_flow_transact(&request, reply, bufp);
}

static int
dpif_linux_flow_get(const struct dpif *dpif_,
                    const struct nlattr *key, size_t key_len,
                    struct ofpbuf **actionsp, struct dpif_flow_stats *stats)
{
    struct dpif_linux_flow reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_flow_get__(dpif_, key, key_len, &reply, &buf);
    if (!error) {
        if (stats) {
            dpif_linux_flow_get_stats(&reply, stats);
        }
        if (actionsp) {
            buf->data = (void *) reply.actions;
            buf->size = reply.actions_len;
            *actionsp = buf;
        } else {
            ofpbuf_delete(buf);
        }
    }
    return error;
}

static void
dpif_linux_init_flow_put(struct dpif *dpif_, enum dpif_flow_put_flags flags,
                         const struct nlattr *key, size_t key_len,
                         const struct nlattr *actions, size_t actions_len,
                         struct dpif_linux_flow *request)
{
    static struct nlattr dummy_action;

    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    dpif_linux_flow_init(request);
    request->cmd = (flags & DPIF_FP_CREATE
                    ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET);
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = actions ? actions : &dummy_action;
    request->actions_len = actions_len;
    if (flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    request->nlmsg_flags = flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}

static int
dpif_linux_flow_put(struct dpif *dpif_, enum dpif_flow_put_flags flags,
                    const struct nlattr *key, size_t key_len,
                    const struct nlattr *actions, size_t actions_len,
                    struct dpif_flow_stats *stats)
{
    struct dpif_linux_flow request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_init_flow_put(dpif_, flags, key, key_len, actions, actions_len,
                             &request);
    error = dpif_linux_flow_transact(&request,
                                     stats ? &reply : NULL,
                                     stats ? &buf : NULL);
    if (!error && stats) {
        dpif_linux_flow_get_stats(&reply, stats);
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_flow_del(struct dpif *dpif_,
                    const struct nlattr *key, size_t key_len,
                    struct dpif_flow_stats *stats)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_flow_init(&request);
    request.cmd = OVS_FLOW_CMD_DEL;
    request.dp_ifindex = dpif->dp_ifindex;
    request.key = key;
    request.key_len = key_len;
    error = dpif_linux_flow_transact(&request,
                                     stats ? &reply : NULL,
                                     stats ? &buf : NULL);
    if (!error && stats) {
        dpif_linux_flow_get_stats(&reply, stats);
        ofpbuf_delete(buf);
    }
    return error;
}

struct dpif_linux_flow_state {
    struct nl_dump dump;
    struct dpif_linux_flow flow;
    struct dpif_flow_stats stats;
    struct ofpbuf *buf;
};

static int
dpif_linux_flow_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow_state *state;
    struct dpif_linux_flow request;
    struct ofpbuf *buf;

    *statep = state = xmalloc(sizeof *state);

    dpif_linux_flow_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_linux_flow_to_ofpbuf(&request, buf);
    nl_dump_start(&state->dump, genl_sock, buf);
    ofpbuf_delete(buf);

    state->buf = NULL;

    return 0;
}

static int
dpif_linux_flow_dump_next(const struct dpif *dpif_ OVS_UNUSED, void *state_,
                          const struct nlattr **key, size_t *key_len,
                          const struct nlattr **actions, size_t *actions_len,
                          const struct dpif_flow_stats **stats)
{
    struct dpif_linux_flow_state *state = state_;
    struct ofpbuf buf;
    int error;

    do {
        ofpbuf_delete(state->buf);
        state->buf = NULL;

        if (!nl_dump_next(&state->dump, &buf)) {
            return EOF;
        }

        error = dpif_linux_flow_from_ofpbuf(&state->flow, &buf);
        if (error) {
            return error;
        }

        if (actions && !state->flow.actions) {
            error = dpif_linux_flow_get__(dpif_, state->flow.key,
                                          state->flow.key_len,
                                          &state->flow, &state->buf);
            if (error == ENOENT) {
                VLOG_DBG("dumped flow disappeared on get");
            } else if (error) {
                VLOG_WARN("error fetching dumped flow: %s", strerror(error));
            }
        }
    } while (error);

    if (actions) {
        *actions = state->flow.actions;
        *actions_len = state->flow.actions_len;
    }
    if (key) {
        *key = state->flow.key;
        *key_len = state->flow.key_len;
    }
    if (stats) {
        dpif_linux_flow_get_stats(&state->flow, &state->stats);
        *stats = &state->stats;
    }
    return error;
}

static int
dpif_linux_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dpif_linux_flow_state *state = state_;
    int error = nl_dump_done(&state->dump);
    ofpbuf_delete(state->buf);
    free(state);
    return error;
}

static struct ofpbuf *
dpif_linux_encode_execute(int dp_ifindex,
                          const struct nlattr *key, size_t key_len,
                          const struct nlattr *actions, size_t actions_len,
                          const struct ofpbuf *packet)
{
    struct ovs_header *execute;
    struct ofpbuf *buf;

    buf = ofpbuf_new(128 + actions_len + packet->size);

    nl_msg_put_genlmsghdr(buf, 0, ovs_packet_family, NLM_F_REQUEST,
                          OVS_PACKET_CMD_EXECUTE, OVS_PACKET_VERSION);

    execute = ofpbuf_put_uninit(buf, sizeof *execute);
    execute->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_PACKET, packet->data, packet->size);
    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_KEY, key, key_len);
    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_ACTIONS, actions, actions_len);

    return buf;
}

static int
dpif_linux_execute__(int dp_ifindex, const struct nlattr *key, size_t key_len,
                     const struct nlattr *actions, size_t actions_len,
                     const struct ofpbuf *packet)
{
    struct ofpbuf *request;
    int error;

    request = dpif_linux_encode_execute(dp_ifindex,
                                        key, key_len, actions, actions_len,
                                        packet);
    error = nl_sock_transact(genl_sock, request, NULL);
    ofpbuf_delete(request);

    return error;
}

static int
dpif_linux_execute(struct dpif *dpif_,
                   const struct nlattr *key, size_t key_len,
                   const struct nlattr *actions, size_t actions_len,
                   const struct ofpbuf *packet)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    return dpif_linux_execute__(dpif->dp_ifindex, key, key_len,
                                actions, actions_len, packet);
}

static void
dpif_linux_operate(struct dpif *dpif_, union dpif_op **ops, size_t n_ops)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct nl_transaction **txnsp;
    struct nl_transaction *txns;
    size_t i;

    txns = xmalloc(n_ops * sizeof *txns);
    for (i = 0; i < n_ops; i++) {
        struct nl_transaction *txn = &txns[i];
        union dpif_op *op = ops[i];

        if (op->type == DPIF_OP_FLOW_PUT) {
            struct dpif_flow_put *put = &op->flow_put;
            struct dpif_linux_flow request;

            dpif_linux_init_flow_put(dpif_, put->flags, put->key, put->key_len,
                                     put->actions, put->actions_len,
                                     &request);
            if (put->stats) {
                request.nlmsg_flags |= NLM_F_ECHO;
            }
            txn->request = ofpbuf_new(1024);
            dpif_linux_flow_to_ofpbuf(&request, txn->request);
        } else if (op->type == DPIF_OP_EXECUTE) {
            struct dpif_execute *execute = &op->execute;

            txn->request = dpif_linux_encode_execute(
                dpif->dp_ifindex, execute->key, execute->key_len,
                execute->actions, execute->actions_len, execute->packet);
        } else {
            NOT_REACHED();
        }
    }

    txnsp = xmalloc(n_ops * sizeof *txnsp);
    for (i = 0; i < n_ops; i++) {
        txnsp[i] = &txns[i];
    }

    nl_sock_transact_multiple(genl_sock, txnsp, n_ops);

    free(txnsp);

    for (i = 0; i < n_ops; i++) {
        struct nl_transaction *txn = &txns[i];
        union dpif_op *op = ops[i];

        if (op->type == DPIF_OP_FLOW_PUT) {
            struct dpif_flow_put *put = &op->flow_put;
            int error = txn->error;

            if (!error && put->stats) {
                struct dpif_linux_flow reply;

                error = dpif_linux_flow_from_ofpbuf(&reply, txn->reply);
                if (!error) {
                    dpif_linux_flow_get_stats(&reply, put->stats);
                }
            }
            put->error = error;
        } else if (op->type == DPIF_OP_EXECUTE) {
            struct dpif_execute *execute = &op->execute;

            execute->error = txn->error;
        } else {
            NOT_REACHED();
        }

        ofpbuf_delete(txn->request);
        ofpbuf_delete(txn->reply);
    }
    free(txns);
}

static int
dpif_linux_recv_get_mask(const struct dpif *dpif_, int *listen_mask)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    *listen_mask = dpif->listen_mask;
    return 0;
}

static void
set_upcall_pids(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_port_dump port_dump;
    struct dpif_port port;
    int error;

    DPIF_PORT_FOR_EACH (&port, &port_dump, &dpif->dpif) {
        uint32_t upcall_pid = dpif_linux_port_get_pid__(dpif_, port.port_no,
                                                        DPIF_UC_MISS);
        struct dpif_linux_vport vport_request;

        dpif_linux_vport_init(&vport_request);
        vport_request.cmd = OVS_VPORT_CMD_SET;
        vport_request.dp_ifindex = dpif->dp_ifindex;
        vport_request.port_no = port.port_no;
        vport_request.upcall_pid = &upcall_pid;
        error = dpif_linux_vport_transact(&vport_request, NULL, NULL);
        if (!error) {
            VLOG_DBG("%s: assigning port %"PRIu32" to netlink pid %"PRIu32,
                     dpif_name(&dpif->dpif), vport_request.port_no,
                     upcall_pid);
        } else {
            VLOG_WARN_RL(&error_rl, "%s: failed to set upcall pid on port: %s",
                         dpif_name(&dpif->dpif), strerror(error));
        }
    }
}

static int
dpif_linux_recv_set_mask(struct dpif *dpif_, int listen_mask)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (listen_mask == dpif->listen_mask) {
        return 0;
    }

    if (!listen_mask) {
        destroy_upcall_socks(dpif);
    } else if (!dpif->listen_mask) {
        int i;
        int error;

        dpif->epoll_fd = epoll_create(N_UPCALL_SOCKS);
        if (dpif->epoll_fd < 0) {
            return errno;
        }

        for (i = 0; i < N_UPCALL_SOCKS; i++) {
            struct epoll_event event;

            error = nl_sock_create(NETLINK_GENERIC, &dpif->upcall_socks[i]);
            if (error) {
                destroy_upcall_socks(dpif);
                return error;
            }

            event.events = EPOLLIN;
            event.data.u32 = i;
            if (epoll_ctl(dpif->epoll_fd, EPOLL_CTL_ADD,
                          nl_sock_fd(dpif->upcall_socks[i]), &event) < 0) {
                error = errno;
                destroy_upcall_socks(dpif);
                return error;
            }
        }

        dpif->ready_mask = 0;
    }

    dpif->listen_mask = listen_mask;
    set_upcall_pids(dpif_);

    return 0;
}

static int
dpif_linux_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                             uint32_t queue_id, uint32_t *priority)
{
    if (queue_id < 0xf000) {
        *priority = TC_H_MAKE(1 << 16, queue_id + 1);
        return 0;
    } else {
        return EINVAL;
    }
}

static int
parse_odp_packet(struct ofpbuf *buf, struct dpif_upcall *upcall,
                 int *dp_ifindex)
{
    static const struct nl_policy ovs_packet_policy[] = {
        /* Always present. */
        [OVS_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [OVS_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* OVS_PACKET_CMD_ACTION only. */
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_U64, .optional = true },
    };

    struct ovs_header *ovs_header;
    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;
    int type;

    ofpbuf_use_const(&b, buf->data, buf->size);

    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_packet_family
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    type = (genl->cmd == OVS_PACKET_CMD_MISS ? DPIF_UC_MISS
            : genl->cmd == OVS_PACKET_CMD_ACTION ? DPIF_UC_ACTION
            : -1);
    if (type < 0) {
        return EINVAL;
    }

    memset(upcall, 0, sizeof *upcall);
    upcall->type = type;
    upcall->packet = buf;
    upcall->packet->data = (void *) nl_attr_get(a[OVS_PACKET_ATTR_PACKET]);
    upcall->packet->size = nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]);
    upcall->key = (void *) nl_attr_get(a[OVS_PACKET_ATTR_KEY]);
    upcall->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    upcall->userdata = (a[OVS_PACKET_ATTR_USERDATA]
                        ? nl_attr_get_u64(a[OVS_PACKET_ATTR_USERDATA])
                        : 0);
    *dp_ifindex = ovs_header->dp_ifindex;

    return 0;
}

static int
dpif_linux_recv(struct dpif *dpif_, struct dpif_upcall *upcall)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int read_tries = 0;

    if (!dpif->listen_mask) {
       return EAGAIN;
    }

    if (!dpif->ready_mask) {
        struct epoll_event events[N_UPCALL_SOCKS];
        int retval;
        int i;

        do {
            retval = epoll_wait(dpif->epoll_fd, events, N_UPCALL_SOCKS, 0);
        } while (retval < 0 && errno == EINTR);
        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "epoll_wait failed (%s)", strerror(errno));
        }

        for (i = 0; i < retval; i++) {
            dpif->ready_mask |= 1u << events[i].data.u32;
        }
    }

    while (dpif->ready_mask) {
        int indx = ffs(dpif->ready_mask) - 1;
        struct nl_sock *upcall_sock = dpif->upcall_socks[indx];

        dpif->ready_mask &= ~(1u << indx);

        for (;;) {
            struct ofpbuf *buf;
            int dp_ifindex;
            int error;

            if (++read_tries > 50) {
                return EAGAIN;
            }

            error = nl_sock_recv(upcall_sock, &buf, false);
            if (error == EAGAIN) {
                break;
            } else if (error) {
                return error;
            }

            error = parse_odp_packet(buf, upcall, &dp_ifindex);
            if (!error
                && dp_ifindex == dpif->dp_ifindex
                && dpif->listen_mask & (1u << upcall->type)) {
                return 0;
            }

            ofpbuf_delete(buf);
            if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}

static void
dpif_linux_recv_wait(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (!dpif->listen_mask) {
       return;
    }

    poll_fd_wait(dpif->epoll_fd, POLLIN);
}

static void
dpif_linux_recv_purge(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int i;

    if (!dpif->listen_mask) {
       return;
    }

    for (i = 0; i < N_UPCALL_SOCKS; i++) {
        nl_sock_drain(dpif->upcall_socks[i]);
    }
}

const struct dpif_class dpif_linux_class = {
    "system",
    dpif_linux_enumerate,
    dpif_linux_open,
    dpif_linux_close,
    dpif_linux_destroy,
    dpif_linux_run,
    dpif_linux_wait,
    dpif_linux_get_stats,
    dpif_linux_port_add,
    dpif_linux_port_del,
    dpif_linux_port_query_by_number,
    dpif_linux_port_query_by_name,
    dpif_linux_get_max_ports,
    dpif_linux_port_get_pid,
    dpif_linux_port_dump_start,
    dpif_linux_port_dump_next,
    dpif_linux_port_dump_done,
    dpif_linux_port_poll,
    dpif_linux_port_poll_wait,
    dpif_linux_flow_get,
    dpif_linux_flow_put,
    dpif_linux_flow_del,
    dpif_linux_flow_flush,
    dpif_linux_flow_dump_start,
    dpif_linux_flow_dump_next,
    dpif_linux_flow_dump_done,
    dpif_linux_execute,
    dpif_linux_operate,
    dpif_linux_recv_get_mask,
    dpif_linux_recv_set_mask,
    dpif_linux_queue_to_priority,
    dpif_linux_recv,
    dpif_linux_recv_wait,
    dpif_linux_recv_purge,
};

static int
dpif_linux_init(void)
{
    static int error = -1;

    if (error < 0) {
        unsigned int ovs_vport_mcgroup;

        error = nl_lookup_genl_family(OVS_DATAPATH_FAMILY,
                                      &ovs_datapath_family);
        if (error) {
            VLOG_ERR("Generic Netlink family '%s' does not exist. "
                     "The Open vSwitch kernel module is probably not loaded.",
                     OVS_DATAPATH_FAMILY);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_VPORT_FAMILY, &ovs_vport_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_FLOW_FAMILY, &ovs_flow_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(OVS_PACKET_FAMILY,
                                          &ovs_packet_family);
        }
        if (!error) {
            error = nl_sock_create(NETLINK_GENERIC, &genl_sock);
        }
        if (!error) {
            error = nl_lookup_genl_mcgroup(OVS_VPORT_FAMILY, OVS_VPORT_MCGROUP,
                                           &ovs_vport_mcgroup,
                                           OVS_VPORT_MCGROUP_FALLBACK_ID);
        }
        if (!error) {
            static struct dpif_linux_vport vport;
            nln = nln_create(NETLINK_GENERIC, ovs_vport_mcgroup,
                             dpif_linux_nln_parse, &vport);
        }
    }

    return error;
}

bool
dpif_linux_is_internal_device(const char *name)
{
    struct dpif_linux_vport reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_vport_get(name, &reply, &buf);
    if (!error) {
        ofpbuf_delete(buf);
    } else if (error != ENODEV && error != ENOENT) {
        VLOG_WARN_RL(&error_rl, "%s: vport query failed (%s)",
                     name, strerror(error));
    }

    return reply.type == OVS_VPORT_TYPE_INTERNAL;
}

int
dpif_linux_vport_send(int dp_ifindex, uint32_t port_no,
                      const void *data, size_t size)
{
    struct ofpbuf actions, key, packet;
    struct odputil_keybuf keybuf;
    struct flow flow;
    uint64_t action;

    ofpbuf_use_const(&packet, data, size);
    flow_extract(&packet, 0, htonll(0), 0, &flow);

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &flow);

    ofpbuf_use_stack(&actions, &action, sizeof action);
    nl_msg_put_u32(&actions, OVS_ACTION_ATTR_OUTPUT, port_no);

    return dpif_linux_execute__(dp_ifindex, key.data, key.size,
                                actions.data, actions.size, &packet);
}

static bool
dpif_linux_nln_parse(struct ofpbuf *buf, void *vport_)
{
    struct dpif_linux_vport *vport = vport_;
    return dpif_linux_vport_from_ofpbuf(vport, buf) == 0;
}

static void
dpif_linux_port_changed(const void *vport_, void *dpif_)
{
    const struct dpif_linux_vport *vport = vport_;
    struct dpif_linux *dpif = dpif_;

    if (vport) {
        if (vport->dp_ifindex == dpif->dp_ifindex
            && (vport->cmd == OVS_VPORT_CMD_NEW
                || vport->cmd == OVS_VPORT_CMD_DEL
                || vport->cmd == OVS_VPORT_CMD_SET)) {
            VLOG_DBG("port_changed: dpif:%s vport:%s cmd:%"PRIu8,
                     dpif->dpif.full_name, vport->name, vport->cmd);
            sset_add(&dpif->changed_ports, vport->name);
        }
    } else {
        dpif->change_error = true;
    }
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'vport'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'vport' will contain pointers into 'buf', so the caller should not free
 * 'buf' while 'vport' is still in use. */
static int
dpif_linux_vport_from_ofpbuf(struct dpif_linux_vport *vport,
                             const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_vport_policy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_vport_stats),
                                   .optional = true },
        [OVS_VPORT_ATTR_ADDRESS] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_ADDR_LEN,
                                     .max_len = ETH_ADDR_LEN,
                                     .optional = true },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(ovs_vport_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_vport_init(vport);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_vport_family
        || !nl_policy_parse(&b, 0, ovs_vport_policy, a,
                            ARRAY_SIZE(ovs_vport_policy))) {
        return EINVAL;
    }

    vport->cmd = genl->cmd;
    vport->dp_ifindex = ovs_header->dp_ifindex;
    vport->port_no = nl_attr_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);
    vport->type = nl_attr_get_u32(a[OVS_VPORT_ATTR_TYPE]);
    vport->name = nl_attr_get_string(a[OVS_VPORT_ATTR_NAME]);
    if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
        vport->upcall_pid = nl_attr_get(a[OVS_VPORT_ATTR_UPCALL_PID]);
    }
    if (a[OVS_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[OVS_VPORT_ATTR_STATS]);
    }
    if (a[OVS_VPORT_ATTR_ADDRESS]) {
        vport->address = nl_attr_get(a[OVS_VPORT_ATTR_ADDRESS]);
    }
    if (a[OVS_VPORT_ATTR_OPTIONS]) {
        vport->options = nl_attr_get(a[OVS_VPORT_ATTR_OPTIONS]);
        vport->options_len = nl_attr_get_size(a[OVS_VPORT_ATTR_OPTIONS]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'vport'. */
static void
dpif_linux_vport_to_ofpbuf(const struct dpif_linux_vport *vport,
                           struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_vport_family, NLM_F_REQUEST | NLM_F_ECHO,
                          vport->cmd, OVS_VPORT_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = vport->dp_ifindex;

    if (vport->port_no != UINT32_MAX) {
        nl_msg_put_u32(buf, OVS_VPORT_ATTR_PORT_NO, vport->port_no);
    }

    if (vport->type != OVS_VPORT_TYPE_UNSPEC) {
        nl_msg_put_u32(buf, OVS_VPORT_ATTR_TYPE, vport->type);
    }

    if (vport->name) {
        nl_msg_put_string(buf, OVS_VPORT_ATTR_NAME, vport->name);
    }

    if (vport->upcall_pid) {
        nl_msg_put_u32(buf, OVS_VPORT_ATTR_UPCALL_PID, *vport->upcall_pid);
    }

    if (vport->stats) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_STATS,
                          vport->stats, sizeof *vport->stats);
    }

    if (vport->address) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_ADDRESS,
                          vport->address, ETH_ADDR_LEN);
    }

    if (vport->options) {
        nl_msg_put_nested(buf, OVS_VPORT_ATTR_OPTIONS,
                          vport->options, vport->options_len);
    }
}

/* Clears 'vport' to "empty" values. */
void
dpif_linux_vport_init(struct dpif_linux_vport *vport)
{
    memset(vport, 0, sizeof *vport);
    vport->port_no = UINT32_MAX;
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be an ovs_vport also, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
int
dpif_linux_vport_transact(const struct dpif_linux_vport *request,
                          struct dpif_linux_vport *reply,
                          struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    assert((reply != NULL) == (bufp != NULL));

    error = dpif_linux_init();
    if (error) {
        if (reply) {
            *bufp = NULL;
            dpif_linux_vport_init(reply);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    dpif_linux_vport_to_ofpbuf(request, request_buf);
    error = nl_sock_transact(genl_sock, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_linux_vport_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_linux_vport_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

/* Obtains information about the kernel vport named 'name' and stores it into
 * '*reply' and '*bufp'.  The caller must free '*bufp' when the reply is no
 * longer needed ('reply' will contain pointers into '*bufp').  */
int
dpif_linux_vport_get(const char *name, struct dpif_linux_vport *reply,
                     struct ofpbuf **bufp)
{
    struct dpif_linux_vport request;

    dpif_linux_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.name = name;

    return dpif_linux_vport_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'dp'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'dp' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'dp' is still in use. */
static int
dpif_linux_dp_from_ofpbuf(struct dpif_linux_dp *dp, const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_datapath_policy[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_DP_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_dp_stats),
                                .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(ovs_datapath_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_dp_init(dp);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_datapath_family
        || !nl_policy_parse(&b, 0, ovs_datapath_policy, a,
                            ARRAY_SIZE(ovs_datapath_policy))) {
        return EINVAL;
    }

    dp->cmd = genl->cmd;
    dp->dp_ifindex = ovs_header->dp_ifindex;
    dp->name = nl_attr_get_string(a[OVS_DP_ATTR_NAME]);
    if (a[OVS_DP_ATTR_STATS]) {
        /* Can't use structure assignment because Netlink doesn't ensure
         * sufficient alignment for 64-bit members. */
        memcpy(&dp->stats, nl_attr_get(a[OVS_DP_ATTR_STATS]),
               sizeof dp->stats);
    }

    return 0;
}

/* Appends to 'buf' the Generic Netlink message described by 'dp'. */
static void
dpif_linux_dp_to_ofpbuf(const struct dpif_linux_dp *dp, struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_datapath_family,
                          NLM_F_REQUEST | NLM_F_ECHO, dp->cmd,
                          OVS_DATAPATH_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = dp->dp_ifindex;

    if (dp->name) {
        nl_msg_put_string(buf, OVS_DP_ATTR_NAME, dp->name);
    }

    if (dp->upcall_pid) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_UPCALL_PID, *dp->upcall_pid);
    }

    /* Skip OVS_DP_ATTR_STATS since we never have a reason to serialize it. */
}

/* Clears 'dp' to "empty" values. */
static void
dpif_linux_dp_init(struct dpif_linux_dp *dp)
{
    memset(dp, 0, sizeof *dp);
}

static void
dpif_linux_dp_dump_start(struct nl_dump *dump)
{
    struct dpif_linux_dp request;
    struct ofpbuf *buf;

    dpif_linux_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;

    buf = ofpbuf_new(1024);
    dpif_linux_dp_to_ofpbuf(&request, buf);
    nl_dump_start(dump, genl_sock, buf);
    ofpbuf_delete(buf);
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be of the same form, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
static int
dpif_linux_dp_transact(const struct dpif_linux_dp *request,
                       struct dpif_linux_dp *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_linux_dp_to_ofpbuf(request, request_buf);
    error = nl_sock_transact(genl_sock, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_linux_dp_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_linux_dp_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

/* Obtains information about 'dpif_' and stores it into '*reply' and '*bufp'.
 * The caller must free '*bufp' when the reply is no longer needed ('reply'
 * will contain pointers into '*bufp').  */
static int
dpif_linux_dp_get(const struct dpif *dpif_, struct dpif_linux_dp *reply,
                  struct ofpbuf **bufp)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp request;

    dpif_linux_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    return dpif_linux_dp_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'flow'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'flow' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'flow' is still in use. */
static int
dpif_linux_flow_from_ofpbuf(struct dpif_linux_flow *flow,
                            const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_flow_policy[] = {
        [OVS_FLOW_ATTR_KEY] = { .type = NL_A_NESTED },
        [OVS_FLOW_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_flow_stats),
                                  .optional = true },
        [OVS_FLOW_ATTR_TCP_FLAGS] = { .type = NL_A_U8, .optional = true },
        [OVS_FLOW_ATTR_USED] = { .type = NL_A_U64, .optional = true },
        /* The kernel never uses OVS_FLOW_ATTR_CLEAR. */
    };

    struct nlattr *a[ARRAY_SIZE(ovs_flow_policy)];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_flow_init(flow);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_flow_family
        || !nl_policy_parse(&b, 0, ovs_flow_policy, a,
                            ARRAY_SIZE(ovs_flow_policy))) {
        return EINVAL;
    }

    flow->nlmsg_flags = nlmsg->nlmsg_flags;
    flow->dp_ifindex = ovs_header->dp_ifindex;
    flow->key = nl_attr_get(a[OVS_FLOW_ATTR_KEY]);
    flow->key_len = nl_attr_get_size(a[OVS_FLOW_ATTR_KEY]);
    if (a[OVS_FLOW_ATTR_ACTIONS]) {
        flow->actions = nl_attr_get(a[OVS_FLOW_ATTR_ACTIONS]);
        flow->actions_len = nl_attr_get_size(a[OVS_FLOW_ATTR_ACTIONS]);
    }
    if (a[OVS_FLOW_ATTR_STATS]) {
        flow->stats = nl_attr_get(a[OVS_FLOW_ATTR_STATS]);
    }
    if (a[OVS_FLOW_ATTR_TCP_FLAGS]) {
        flow->tcp_flags = nl_attr_get(a[OVS_FLOW_ATTR_TCP_FLAGS]);
    }
    if (a[OVS_FLOW_ATTR_USED]) {
        flow->used = nl_attr_get(a[OVS_FLOW_ATTR_USED]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'flow'. */
static void
dpif_linux_flow_to_ofpbuf(const struct dpif_linux_flow *flow,
                          struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_flow_family,
                          NLM_F_REQUEST | flow->nlmsg_flags,
                          flow->cmd, OVS_FLOW_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = flow->dp_ifindex;

    if (flow->key_len) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_KEY, flow->key, flow->key_len);
    }

    if (flow->actions || flow->actions_len) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS,
                          flow->actions, flow->actions_len);
    }

    /* We never need to send these to the kernel. */
    assert(!flow->stats);
    assert(!flow->tcp_flags);
    assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_CLEAR);
    }
}

/* Clears 'flow' to "empty" values. */
static void
dpif_linux_flow_init(struct dpif_linux_flow *flow)
{
    memset(flow, 0, sizeof *flow);
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be a flow also, which is decoded and
 * stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the reply
 * is no longer needed ('reply' will contain pointers into '*bufp'). */
static int
dpif_linux_flow_transact(struct dpif_linux_flow *request,
                         struct dpif_linux_flow *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    assert((reply != NULL) == (bufp != NULL));

    if (reply) {
        request->nlmsg_flags |= NLM_F_ECHO;
    }

    request_buf = ofpbuf_new(1024);
    dpif_linux_flow_to_ofpbuf(request, request_buf);
    error = nl_sock_transact(genl_sock, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_linux_flow_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_linux_flow_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

static void
dpif_linux_flow_get_stats(const struct dpif_linux_flow *flow,
                          struct dpif_flow_stats *stats)
{
    if (flow->stats) {
        stats->n_packets = get_unaligned_u64(&flow->stats->n_packets);
        stats->n_bytes = get_unaligned_u64(&flow->stats->n_bytes);
    } else {
        stats->n_packets = 0;
        stats->n_bytes = 0;
    }
    stats->used = flow->used ? get_32aligned_u64(flow->used) : 0;
    stats->tcp_flags = flow->tcp_flags ? *flow->tcp_flags : 0;
}
