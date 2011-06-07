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
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netdev-linux.h"
#include "netdev-vport.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "rtnetlink-link.h"
#include "shash.h"
#include "sset.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_linux);

enum { LRU_MAX_PORTS = 1024 };
enum { LRU_MASK = LRU_MAX_PORTS - 1};
BUILD_ASSERT_DECL(IS_POW2(LRU_MAX_PORTS));

struct dpif_linux_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct odp_header. */
    int dp_ifindex;

    /* Attributes. */
    const char *name;                  /* ODP_DP_ATTR_NAME. */
    struct odp_stats stats;            /* ODP_DP_ATTR_STATS. */
    enum odp_frag_handling ipv4_frags; /* ODP_DP_ATTR_IPV4_FRAGS. */
    const uint32_t *sampling;          /* ODP_DP_ATTR_SAMPLING. */
    uint32_t mcgroups[DPIF_N_UC_TYPES]; /* ODP_DP_ATTR_MCGROUPS. */
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

    /* struct odp_header. */
    unsigned int nlmsg_flags;
    int dp_ifindex;

    /* Attributes.
     *
     * The 'stats' and 'used' members point to 64-bit data that might only be
     * aligned on 32-bit boundaries, so get_unaligned_u64() should be used to
     * access their values.
     *
     * If 'actions' is nonnull then ODP_FLOW_ATTR_ACTIONS will be included in
     * the Netlink version of the command, even if actions_len is zero. */
    const struct nlattr *key;           /* ODP_FLOW_ATTR_KEY. */
    size_t key_len;
    const struct nlattr *actions;       /* ODP_FLOW_ATTR_ACTIONS. */
    size_t actions_len;
    const struct odp_flow_stats *stats; /* ODP_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* ODP_FLOW_ATTR_TCP_FLAGS. */
    const uint64_t *used;               /* ODP_FLOW_ATTR_USED. */
    bool clear;                         /* ODP_FLOW_ATTR_CLEAR. */
};

static void dpif_linux_flow_init(struct dpif_linux_flow *);
static int dpif_linux_flow_from_ofpbuf(struct dpif_linux_flow *,
                                       const struct ofpbuf *);
static void dpif_linux_flow_to_ofpbuf(const struct dpif_linux_flow *,
                                      struct ofpbuf *);
static int dpif_linux_flow_transact(const struct dpif_linux_flow *request,
                                    struct dpif_linux_flow *reply,
                                    struct ofpbuf **bufp);
static void dpif_linux_flow_get_stats(const struct dpif_linux_flow *,
                                      struct dpif_flow_stats *);

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int dp_ifindex;

    /* Multicast group messages. */
    struct nl_sock *mc_sock;
    uint32_t mcgroups[DPIF_N_UC_TYPES];
    unsigned int listen_mask;

    /* Change notification. */
    struct sset changed_ports;  /* Ports that have changed. */
    struct rtnetlink_notifier port_notifier;
    bool change_error;

    /* Queue of unused ports. */
    unsigned long *lru_bitmap;
    uint16_t lru_ports[LRU_MAX_PORTS];
    size_t lru_head;
    size_t lru_tail;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for ODP. */
static int odp_datapath_family;
static int odp_vport_family;
static int odp_flow_family;
static int odp_packet_family;

/* Generic Netlink socket. */
static struct nl_sock *genl_sock;

static int dpif_linux_init(void);
static int open_dpif(const struct dpif_linux_dp *, struct dpif **);
static void dpif_linux_port_changed(const struct rtnetlink_link_change *,
                                    void *dpif);

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
    int error;

    error = dpif_linux_init();
    if (error) {
        return error;
    }

    /* Create or look up datapath. */
    dpif_linux_dp_init(&dp_request);
    dp_request.cmd = create ? ODP_DP_CMD_NEW : ODP_DP_CMD_GET;
    dp_request.name = name;
    error = dpif_linux_dp_transact(&dp_request, &dp, &buf);
    if (error) {
        return error;
    }
    error = open_dpif(&dp, dpifp);
    ofpbuf_delete(buf);

    return error;
}

static int
open_dpif(const struct dpif_linux_dp *dp, struct dpif **dpifp)
{
    struct dpif_linux *dpif;
    int error;
    int i;

    dpif = xmalloc(sizeof *dpif);
    error = rtnetlink_link_notifier_register(&dpif->port_notifier,
                                             dpif_linux_port_changed, dpif);
    if (error) {
        goto error_free;
    }

    dpif_init(&dpif->dpif, &dpif_linux_class, dp->name,
              dp->dp_ifindex, dp->dp_ifindex);

    dpif->mc_sock = NULL;
    for (i = 0; i < DPIF_N_UC_TYPES; i++) {
        dpif->mcgroups[i] = dp->mcgroups[i];
    }
    dpif->listen_mask = 0;
    dpif->dp_ifindex = dp->dp_ifindex;
    sset_init(&dpif->changed_ports);
    dpif->change_error = false;
    *dpifp = &dpif->dpif;

    dpif->lru_head = dpif->lru_tail = 0;
    dpif->lru_bitmap = bitmap_allocate(LRU_MAX_PORTS);
    bitmap_set1(dpif->lru_bitmap, ODPP_LOCAL);
    for (i = 1; i < LRU_MAX_PORTS; i++) {
        dpif_linux_push_port(dpif, i);
    }
    return 0;

error_free:
    free(dpif);
    return error;
}

static void
dpif_linux_close(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    nl_sock_destroy(dpif->mc_sock);
    rtnetlink_link_notifier_unregister(&dpif->port_notifier);
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
    dp.cmd = ODP_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_linux_dp_transact(&dp, NULL, NULL);
}

static int
dpif_linux_get_stats(const struct dpif *dpif_, struct odp_stats *stats)
{
    struct dpif_linux_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_dp_get(dpif_, &dp, &buf);
    if (!error) {
        *stats = dp.stats;
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_get_drop_frags(const struct dpif *dpif_, bool *drop_fragsp)
{
    struct dpif_linux_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_dp_get(dpif_, &dp, &buf);
    if (!error) {
        *drop_fragsp = dp.ipv4_frags == ODP_DP_FRAG_DROP;
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_set_drop_frags(struct dpif *dpif_, bool drop_frags)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp dp;

    dpif_linux_dp_init(&dp);
    dp.cmd = ODP_DP_CMD_SET;
    dp.dp_ifindex = dpif->dp_ifindex;
    dp.ipv4_frags = drop_frags ? ODP_DP_FRAG_DROP : ODP_DP_FRAG_ZERO;
    return dpif_linux_dp_transact(&dp, NULL, NULL);
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
    request.cmd = ODP_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = netdev_vport_get_vport_type(netdev);
    if (request.type == ODP_VPORT_TYPE_UNSPEC) {
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

    /* Loop until we find a port that isn't used. */
    do {
        request.port_no = dpif_linux_pop_port(dpif);
        error = dpif_linux_vport_transact(&request, &reply, &buf);

        if (!error) {
            *port_nop = reply.port_no;
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
    vport.cmd = ODP_VPORT_CMD_DEL;
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
    request.cmd = ODP_VPORT_CMD_GET;
    request.dp_ifindex = dpif_linux_cast(dpif)->dp_ifindex;
    request.port_no = port_no;
    request.name = port_name;

    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (!error) {
        dpif_port->name = xstrdup(reply.name);
        dpif_port->type = xstrdup(netdev_vport_get_netdev_type(&reply));
        dpif_port->port_no = reply.port_no;
        if (reply.stats) {
            netdev_stats_from_rtnl_link_stats64(&dpif_port->stats,
                                                reply.stats);
        } else {
            memset(&dpif_port->stats, 0xff, sizeof dpif_port->stats);
        }
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

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow flow;

    dpif_linux_flow_init(&flow);
    flow.cmd = ODP_FLOW_CMD_DEL;
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
    request.cmd = ODP_DP_CMD_GET;
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
    if (vport.stats) {
        netdev_stats_from_rtnl_link_stats64(&dpif_port->stats, vport.stats);
    } else {
        memset(&dpif_port->stats, 0xff, sizeof dpif_port->stats);
    }
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
    } else {
        rtnetlink_link_notifier_wait();
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
    request.cmd = ODP_FLOW_CMD_GET;
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

static int
dpif_linux_flow_put(struct dpif *dpif_, enum dpif_flow_put_flags flags,
                    const struct nlattr *key, size_t key_len,
                    const struct nlattr *actions, size_t actions_len,
                    struct dpif_flow_stats *stats)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow request, reply;
    struct nlattr dummy_action;
    struct ofpbuf *buf;
    int error;

    dpif_linux_flow_init(&request);
    request.cmd = flags & DPIF_FP_CREATE ? ODP_FLOW_CMD_NEW : ODP_FLOW_CMD_SET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.key = key;
    request.key_len = key_len;
    /* Ensure that ODP_FLOW_ATTR_ACTIONS will always be included. */
    request.actions = actions ? actions : &dummy_action;
    request.actions_len = actions_len;
    if (flags & DPIF_FP_ZERO_STATS) {
        request.clear = true;
    }
    request.nlmsg_flags = flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
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
    request.cmd = ODP_FLOW_CMD_DEL;
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
    request.cmd = ODP_DP_CMD_GET;
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

static int
dpif_linux_execute__(int dp_ifindex,
                     const struct nlattr *key, size_t key_len,
                     const struct nlattr *actions, size_t actions_len,
                     const struct ofpbuf *packet)
{
    struct odp_header *execute;
    struct ofpbuf *buf;
    int error;

    buf = ofpbuf_new(128 + actions_len + packet->size);

    nl_msg_put_genlmsghdr(buf, 0, odp_packet_family, NLM_F_REQUEST,
                          ODP_PACKET_CMD_EXECUTE, 1);

    execute = ofpbuf_put_uninit(buf, sizeof *execute);
    execute->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, ODP_PACKET_ATTR_PACKET, packet->data, packet->size);
    nl_msg_put_unspec(buf, ODP_PACKET_ATTR_KEY, key, key_len);
    nl_msg_put_unspec(buf, ODP_PACKET_ATTR_ACTIONS, actions, actions_len);

    error = nl_sock_transact(genl_sock, buf, NULL);
    ofpbuf_delete(buf);
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

static int
dpif_linux_recv_get_mask(const struct dpif *dpif_, int *listen_mask)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    *listen_mask = dpif->listen_mask;
    return 0;
}

static int
dpif_linux_recv_set_mask(struct dpif *dpif_, int listen_mask)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int error;
    int i;

    if (listen_mask == dpif->listen_mask) {
        return 0;
    } else if (!listen_mask) {
        nl_sock_destroy(dpif->mc_sock);
        dpif->mc_sock = NULL;
        dpif->listen_mask = 0;
        return 0;
    } else if (!dpif->mc_sock) {
        error = nl_sock_create(NETLINK_GENERIC, &dpif->mc_sock);
        if (error) {
            return error;
        }
    }

    /* Unsubscribe from old groups. */
    for (i = 0; i < DPIF_N_UC_TYPES; i++) {
        if (dpif->listen_mask & (1u << i)) {
            nl_sock_leave_mcgroup(dpif->mc_sock, dpif->mcgroups[i]);
        }
    }

    /* Update listen_mask. */
    dpif->listen_mask = listen_mask;

    /* Subscribe to new groups. */
    error = 0;
    for (i = 0; i < DPIF_N_UC_TYPES; i++) {
        if (dpif->listen_mask & (1u << i)) {
            int retval;

            retval = nl_sock_join_mcgroup(dpif->mc_sock, dpif->mcgroups[i]);
            if (retval) {
                error = retval;
            }
        }
    }
    return error;
}

static int
dpif_linux_get_sflow_probability(const struct dpif *dpif_,
                                 uint32_t *probability)
{
    struct dpif_linux_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_linux_dp_get(dpif_, &dp, &buf);
    if (!error) {
        *probability = dp.sampling ? *dp.sampling : 0;
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_set_sflow_probability(struct dpif *dpif_, uint32_t probability)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp dp;

    dpif_linux_dp_init(&dp);
    dp.cmd = ODP_DP_CMD_SET;
    dp.dp_ifindex = dpif->dp_ifindex;
    dp.sampling = &probability;
    return dpif_linux_dp_transact(&dp, NULL, NULL);
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
    static const struct nl_policy odp_packet_policy[] = {
        /* Always present. */
        [ODP_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [ODP_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* ODP_PACKET_CMD_ACTION only. */
        [ODP_PACKET_ATTR_USERDATA] = { .type = NL_A_U64, .optional = true },

        /* ODP_PACKET_CMD_SAMPLE only. */
        [ODP_PACKET_ATTR_SAMPLE_POOL] = { .type = NL_A_U32, .optional = true },
        [ODP_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
    };

    struct odp_header *odp_header;
    struct nlattr *a[ARRAY_SIZE(odp_packet_policy)];
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;
    int type;

    ofpbuf_use_const(&b, buf->data, buf->size);

    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    odp_header = ofpbuf_try_pull(&b, sizeof *odp_header);
    if (!nlmsg || !genl || !odp_header
        || nlmsg->nlmsg_type != odp_packet_family
        || !nl_policy_parse(&b, 0, odp_packet_policy, a,
                            ARRAY_SIZE(odp_packet_policy))) {
        return EINVAL;
    }

    type = (genl->cmd == ODP_PACKET_CMD_MISS ? DPIF_UC_MISS
            : genl->cmd == ODP_PACKET_CMD_ACTION ? DPIF_UC_ACTION
            : genl->cmd == ODP_PACKET_CMD_SAMPLE ? DPIF_UC_SAMPLE
            : -1);
    if (type < 0) {
        return EINVAL;
    }

    memset(upcall, 0, sizeof *upcall);
    upcall->type = type;
    upcall->packet = buf;
    upcall->packet->data = (void *) nl_attr_get(a[ODP_PACKET_ATTR_PACKET]);
    upcall->packet->size = nl_attr_get_size(a[ODP_PACKET_ATTR_PACKET]);
    upcall->key = (void *) nl_attr_get(a[ODP_PACKET_ATTR_KEY]);
    upcall->key_len = nl_attr_get_size(a[ODP_PACKET_ATTR_KEY]);
    upcall->userdata = (a[ODP_PACKET_ATTR_USERDATA]
                        ? nl_attr_get_u64(a[ODP_PACKET_ATTR_USERDATA])
                        : 0);
    upcall->sample_pool = (a[ODP_PACKET_ATTR_SAMPLE_POOL]
                        ? nl_attr_get_u32(a[ODP_PACKET_ATTR_SAMPLE_POOL])
                           : 0);
    if (a[ODP_PACKET_ATTR_ACTIONS]) {
        upcall->actions = (void *) nl_attr_get(a[ODP_PACKET_ATTR_ACTIONS]);
        upcall->actions_len = nl_attr_get_size(a[ODP_PACKET_ATTR_ACTIONS]);
    }

    *dp_ifindex = odp_header->dp_ifindex;

    return 0;
}

static int
dpif_linux_recv(struct dpif *dpif_, struct dpif_upcall *upcall)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct ofpbuf *buf;
    int error;
    int i;

    if (!dpif->mc_sock) {
        return EAGAIN;
    }

    for (i = 0; i < 50; i++) {
        int dp_ifindex;

        error = nl_sock_recv(dpif->mc_sock, &buf, false);
        if (error) {
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

    return EAGAIN;
}

static void
dpif_linux_recv_wait(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    if (dpif->mc_sock) {
        nl_sock_wait(dpif->mc_sock, POLLIN);
    }
}

static void
dpif_linux_recv_purge(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (dpif->mc_sock) {
        nl_sock_drain(dpif->mc_sock);
    }
}

const struct dpif_class dpif_linux_class = {
    "system",
    dpif_linux_enumerate,
    dpif_linux_open,
    dpif_linux_close,
    dpif_linux_destroy,
    NULL,                       /* run */
    NULL,                       /* wait */
    dpif_linux_get_stats,
    dpif_linux_get_drop_frags,
    dpif_linux_set_drop_frags,
    dpif_linux_port_add,
    dpif_linux_port_del,
    dpif_linux_port_query_by_number,
    dpif_linux_port_query_by_name,
    dpif_linux_get_max_ports,
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
    dpif_linux_recv_get_mask,
    dpif_linux_recv_set_mask,
    dpif_linux_get_sflow_probability,
    dpif_linux_set_sflow_probability,
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
        error = nl_lookup_genl_family(ODP_DATAPATH_FAMILY,
                                      &odp_datapath_family);
        if (error) {
            VLOG_ERR("Generic Netlink family '%s' does not exist. "
                     "The Open vSwitch kernel module is probably not loaded.",
                     ODP_DATAPATH_FAMILY);
        }
        if (!error) {
            error = nl_lookup_genl_family(ODP_VPORT_FAMILY, &odp_vport_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(ODP_FLOW_FAMILY, &odp_flow_family);
        }
        if (!error) {
            error = nl_lookup_genl_family(ODP_PACKET_FAMILY,
                                          &odp_packet_family);
        }
        if (!error) {
            error = nl_sock_create(NETLINK_GENERIC, &genl_sock);
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

    return reply.type == ODP_VPORT_TYPE_INTERNAL;
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
    flow_extract(&packet, htonll(0), 0, &flow);

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    odp_flow_key_from_flow(&key, &flow);

    ofpbuf_use_stack(&actions, &action, sizeof action);
    nl_msg_put_u32(&actions, ODP_ACTION_ATTR_OUTPUT, port_no);

    return dpif_linux_execute__(dp_ifindex, key.data, key.size,
                                actions.data, actions.size, &packet);
}

static void
dpif_linux_port_changed(const struct rtnetlink_link_change *change,
                        void *dpif_)
{
    struct dpif_linux *dpif = dpif_;

    if (change) {
        if (change->master_ifindex == dpif->dp_ifindex
            && (change->nlmsg_type == RTM_NEWLINK
                || change->nlmsg_type == RTM_DELLINK))
        {
            /* Our datapath changed, either adding a new port or deleting an
             * existing one. */
            sset_add(&dpif->changed_ports, change->ifname);
        }
    } else {
        dpif->change_error = true;
    }
}

/* Parses the contents of 'buf', which contains a "struct odp_header" followed
 * by Netlink attributes, into 'vport'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'vport' will contain pointers into 'buf', so the caller should not free
 * 'buf' while 'vport' is still in use. */
static int
dpif_linux_vport_from_ofpbuf(struct dpif_linux_vport *vport,
                             const struct ofpbuf *buf)
{
    static const struct nl_policy odp_vport_policy[] = {
        [ODP_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [ODP_VPORT_ATTR_TYPE] = { .type = NL_A_U32 },
        [ODP_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [ODP_VPORT_ATTR_STATS] = { .type = NL_A_UNSPEC,
                                   .min_len = sizeof(struct rtnl_link_stats64),
                                   .max_len = sizeof(struct rtnl_link_stats64),
                                   .optional = true },
        [ODP_VPORT_ATTR_ADDRESS] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_ADDR_LEN,
                                     .max_len = ETH_ADDR_LEN,
                                     .optional = true },
        [ODP_VPORT_ATTR_MTU] = { .type = NL_A_U32, .optional = true },
        [ODP_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = true },
        [ODP_VPORT_ATTR_IFINDEX] = { .type = NL_A_U32, .optional = true },
        [ODP_VPORT_ATTR_IFLINK] = { .type = NL_A_U32, .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(odp_vport_policy)];
    struct odp_header *odp_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_vport_init(vport);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    odp_header = ofpbuf_try_pull(&b, sizeof *odp_header);
    if (!nlmsg || !genl || !odp_header
        || nlmsg->nlmsg_type != odp_vport_family
        || !nl_policy_parse(&b, 0, odp_vport_policy, a,
                            ARRAY_SIZE(odp_vport_policy))) {
        return EINVAL;
    }

    vport->cmd = genl->cmd;
    vport->dp_ifindex = odp_header->dp_ifindex;
    vport->port_no = nl_attr_get_u32(a[ODP_VPORT_ATTR_PORT_NO]);
    vport->type = nl_attr_get_u32(a[ODP_VPORT_ATTR_TYPE]);
    vport->name = nl_attr_get_string(a[ODP_VPORT_ATTR_NAME]);
    if (a[ODP_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[ODP_VPORT_ATTR_STATS]);
    }
    if (a[ODP_VPORT_ATTR_ADDRESS]) {
        vport->address = nl_attr_get(a[ODP_VPORT_ATTR_ADDRESS]);
    }
    if (a[ODP_VPORT_ATTR_MTU]) {
        vport->mtu = nl_attr_get_u32(a[ODP_VPORT_ATTR_MTU]);
    } else {
        vport->mtu = INT_MAX;
    }
    if (a[ODP_VPORT_ATTR_OPTIONS]) {
        vport->options = nl_attr_get(a[ODP_VPORT_ATTR_OPTIONS]);
        vport->options_len = nl_attr_get_size(a[ODP_VPORT_ATTR_OPTIONS]);
    }
    if (a[ODP_VPORT_ATTR_IFINDEX]) {
        vport->ifindex = nl_attr_get_u32(a[ODP_VPORT_ATTR_IFINDEX]);
    }
    if (a[ODP_VPORT_ATTR_IFLINK]) {
        vport->iflink = nl_attr_get_u32(a[ODP_VPORT_ATTR_IFLINK]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct odp_header"
 * followed by Netlink attributes corresponding to 'vport'. */
static void
dpif_linux_vport_to_ofpbuf(const struct dpif_linux_vport *vport,
                           struct ofpbuf *buf)
{
    struct odp_header *odp_header;

    nl_msg_put_genlmsghdr(buf, 0, odp_vport_family, NLM_F_REQUEST | NLM_F_ECHO,
                          vport->cmd, 1);

    odp_header = ofpbuf_put_uninit(buf, sizeof *odp_header);
    odp_header->dp_ifindex = vport->dp_ifindex;

    if (vport->port_no != UINT32_MAX) {
        nl_msg_put_u32(buf, ODP_VPORT_ATTR_PORT_NO, vport->port_no);
    }

    if (vport->type != ODP_VPORT_TYPE_UNSPEC) {
        nl_msg_put_u32(buf, ODP_VPORT_ATTR_TYPE, vport->type);
    }

    if (vport->name) {
        nl_msg_put_string(buf, ODP_VPORT_ATTR_NAME, vport->name);
    }

    if (vport->stats) {
        nl_msg_put_unspec(buf, ODP_VPORT_ATTR_STATS,
                          vport->stats, sizeof *vport->stats);
    }

    if (vport->address) {
        nl_msg_put_unspec(buf, ODP_VPORT_ATTR_ADDRESS,
                          vport->address, ETH_ADDR_LEN);
    }

    if (vport->mtu && vport->mtu != INT_MAX) {
        nl_msg_put_u32(buf, ODP_VPORT_ATTR_MTU, vport->mtu);
    }

    if (vport->options) {
        nl_msg_put_nested(buf, ODP_VPORT_ATTR_OPTIONS,
                          vport->options, vport->options_len);
    }

    if (vport->ifindex) {
        nl_msg_put_u32(buf, ODP_VPORT_ATTR_IFINDEX, vport->ifindex);
    }

    if (vport->iflink) {
        nl_msg_put_u32(buf, ODP_VPORT_ATTR_IFLINK, vport->iflink);
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
 * result of the command is expected to be an odp_vport also, which is decoded
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
    request.cmd = ODP_VPORT_CMD_GET;
    request.name = name;

    return dpif_linux_vport_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct odp_header" followed
 * by Netlink attributes, into 'dp'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'dp' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'dp' is still in use. */
static int
dpif_linux_dp_from_ofpbuf(struct dpif_linux_dp *dp, const struct ofpbuf *buf)
{
    static const struct nl_policy odp_datapath_policy[] = {
        [ODP_DP_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [ODP_DP_ATTR_STATS] = { .type = NL_A_UNSPEC,
                                .min_len = sizeof(struct odp_stats),
                                .max_len = sizeof(struct odp_stats),
                                .optional = true },
        [ODP_DP_ATTR_IPV4_FRAGS] = { .type = NL_A_U32, .optional = true },
        [ODP_DP_ATTR_SAMPLING] = { .type = NL_A_U32, .optional = true },
        [ODP_DP_ATTR_MCGROUPS] = { .type = NL_A_NESTED, .optional = true },
    };

    struct nlattr *a[ARRAY_SIZE(odp_datapath_policy)];
    struct odp_header *odp_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_dp_init(dp);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    odp_header = ofpbuf_try_pull(&b, sizeof *odp_header);
    if (!nlmsg || !genl || !odp_header
        || nlmsg->nlmsg_type != odp_datapath_family
        || !nl_policy_parse(&b, 0, odp_datapath_policy, a,
                            ARRAY_SIZE(odp_datapath_policy))) {
        return EINVAL;
    }

    dp->cmd = genl->cmd;
    dp->dp_ifindex = odp_header->dp_ifindex;
    dp->name = nl_attr_get_string(a[ODP_DP_ATTR_NAME]);
    if (a[ODP_DP_ATTR_STATS]) {
        /* Can't use structure assignment because Netlink doesn't ensure
         * sufficient alignment for 64-bit members. */
        memcpy(&dp->stats, nl_attr_get(a[ODP_DP_ATTR_STATS]),
               sizeof dp->stats);
    }
    if (a[ODP_DP_ATTR_IPV4_FRAGS]) {
        dp->ipv4_frags = nl_attr_get_u32(a[ODP_DP_ATTR_IPV4_FRAGS]);
    }
    if (a[ODP_DP_ATTR_SAMPLING]) {
        dp->sampling = nl_attr_get(a[ODP_DP_ATTR_SAMPLING]);
    }

    if (a[ODP_DP_ATTR_MCGROUPS]) {
        static const struct nl_policy odp_mcgroup_policy[] = {
            [ODP_PACKET_CMD_MISS] = { .type = NL_A_U32, .optional = true },
            [ODP_PACKET_CMD_ACTION] = { .type = NL_A_U32, .optional = true },
            [ODP_PACKET_CMD_SAMPLE] = { .type = NL_A_U32, .optional = true },
        };

        struct nlattr *mcgroups[ARRAY_SIZE(odp_mcgroup_policy)];

        if (!nl_parse_nested(a[ODP_DP_ATTR_MCGROUPS], odp_mcgroup_policy,
                             mcgroups, ARRAY_SIZE(odp_mcgroup_policy))) {
            return EINVAL;
        }

        if (mcgroups[ODP_PACKET_CMD_MISS]) {
            dp->mcgroups[DPIF_UC_MISS]
                = nl_attr_get_u32(mcgroups[ODP_PACKET_CMD_MISS]);
        }
        if (mcgroups[ODP_PACKET_CMD_ACTION]) {
            dp->mcgroups[DPIF_UC_ACTION]
                = nl_attr_get_u32(mcgroups[ODP_PACKET_CMD_ACTION]);
        }
        if (mcgroups[ODP_PACKET_CMD_SAMPLE]) {
            dp->mcgroups[DPIF_UC_SAMPLE]
                = nl_attr_get_u32(mcgroups[ODP_PACKET_CMD_SAMPLE]);
        }
    }

    return 0;
}

/* Appends to 'buf' the Generic Netlink message described by 'dp'. */
static void
dpif_linux_dp_to_ofpbuf(const struct dpif_linux_dp *dp, struct ofpbuf *buf)
{
    struct odp_header *odp_header;

    nl_msg_put_genlmsghdr(buf, 0, odp_datapath_family,
                          NLM_F_REQUEST | NLM_F_ECHO, dp->cmd, 1);

    odp_header = ofpbuf_put_uninit(buf, sizeof *odp_header);
    odp_header->dp_ifindex = dp->dp_ifindex;

    if (dp->name) {
        nl_msg_put_string(buf, ODP_DP_ATTR_NAME, dp->name);
    }

    /* Skip ODP_DP_ATTR_STATS since we never have a reason to serialize it. */

    if (dp->ipv4_frags) {
        nl_msg_put_u32(buf, ODP_DP_ATTR_IPV4_FRAGS, dp->ipv4_frags);
    }

    if (dp->sampling) {
        nl_msg_put_u32(buf, ODP_DP_ATTR_SAMPLING, *dp->sampling);
    }
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
    request.cmd = ODP_DP_CMD_GET;

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
    request.cmd = ODP_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    return dpif_linux_dp_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct odp_header" followed
 * by Netlink attributes, into 'flow'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'flow' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'flow' is still in use. */
static int
dpif_linux_flow_from_ofpbuf(struct dpif_linux_flow *flow,
                            const struct ofpbuf *buf)
{
    static const struct nl_policy odp_flow_policy[] = {
        [ODP_FLOW_ATTR_KEY] = { .type = NL_A_NESTED },
        [ODP_FLOW_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [ODP_FLOW_ATTR_STATS] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct odp_flow_stats),
                                  .max_len = sizeof(struct odp_flow_stats),
                                  .optional = true },
        [ODP_FLOW_ATTR_TCP_FLAGS] = { .type = NL_A_U8, .optional = true },
        [ODP_FLOW_ATTR_USED] = { .type = NL_A_U64, .optional = true },
        /* The kernel never uses ODP_FLOW_ATTR_CLEAR. */
    };

    struct nlattr *a[ARRAY_SIZE(odp_flow_policy)];
    struct odp_header *odp_header;
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;

    dpif_linux_flow_init(flow);

    ofpbuf_use_const(&b, buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    odp_header = ofpbuf_try_pull(&b, sizeof *odp_header);
    if (!nlmsg || !genl || !odp_header
        || nlmsg->nlmsg_type != odp_flow_family
        || !nl_policy_parse(&b, 0, odp_flow_policy, a,
                            ARRAY_SIZE(odp_flow_policy))) {
        return EINVAL;
    }

    flow->nlmsg_flags = nlmsg->nlmsg_flags;
    flow->dp_ifindex = odp_header->dp_ifindex;
    flow->key = nl_attr_get(a[ODP_FLOW_ATTR_KEY]);
    flow->key_len = nl_attr_get_size(a[ODP_FLOW_ATTR_KEY]);
    if (a[ODP_FLOW_ATTR_ACTIONS]) {
        flow->actions = nl_attr_get(a[ODP_FLOW_ATTR_ACTIONS]);
        flow->actions_len = nl_attr_get_size(a[ODP_FLOW_ATTR_ACTIONS]);
    }
    if (a[ODP_FLOW_ATTR_STATS]) {
        flow->stats = nl_attr_get(a[ODP_FLOW_ATTR_STATS]);
    }
    if (a[ODP_FLOW_ATTR_TCP_FLAGS]) {
        flow->tcp_flags = nl_attr_get(a[ODP_FLOW_ATTR_TCP_FLAGS]);
    }
    if (a[ODP_FLOW_ATTR_USED]) {
        flow->used = nl_attr_get(a[ODP_FLOW_ATTR_USED]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct odp_header"
 * followed by Netlink attributes corresponding to 'flow'. */
static void
dpif_linux_flow_to_ofpbuf(const struct dpif_linux_flow *flow,
                          struct ofpbuf *buf)
{
    struct odp_header *odp_header;

    nl_msg_put_genlmsghdr(buf, 0, odp_flow_family,
                          NLM_F_REQUEST | NLM_F_ECHO | flow->nlmsg_flags,
                          flow->cmd, 1);

    odp_header = ofpbuf_put_uninit(buf, sizeof *odp_header);
    odp_header->dp_ifindex = flow->dp_ifindex;

    if (flow->key_len) {
        nl_msg_put_unspec(buf, ODP_FLOW_ATTR_KEY, flow->key, flow->key_len);
    }

    if (flow->actions || flow->actions_len) {
        nl_msg_put_unspec(buf, ODP_FLOW_ATTR_ACTIONS,
                          flow->actions, flow->actions_len);
    }

    /* We never need to send these to the kernel. */
    assert(!flow->stats);
    assert(!flow->tcp_flags);
    assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, ODP_FLOW_ATTR_CLEAR);
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
dpif_linux_flow_transact(const struct dpif_linux_flow *request,
                         struct dpif_linux_flow *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    assert((reply != NULL) == (bufp != NULL));

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
    stats->used = flow->used ? get_unaligned_u64(flow->used) : 0;
    stats->tcp_flags = flow->tcp_flags ? *flow->tcp_flags : 0;
}

