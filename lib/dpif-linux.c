/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_linux);
enum { MAX_PORTS = USHRT_MAX };

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
    const uint32_t *upcall_pid;        /* OVS_DP_ATTR_UPCALL_PID. */
    uint32_t user_features;            /* OVS_DP_ATTR_USER_FEATURES */
    struct ovs_dp_stats stats;         /* OVS_DP_ATTR_STATS. */
    struct ovs_dp_megaflow_stats megaflow_stats;
                                       /* OVS_DP_ATTR_MEGAFLOW_STATS.*/
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
    const struct nlattr *mask;          /* OVS_FLOW_ATTR_MASK. */
    size_t mask_len;
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

/* One of the dpif channels between the kernel and userspace. */
struct dpif_channel {
    struct nl_sock *sock;       /* Netlink socket. */
    long long int last_poll;    /* Last time this channel was polled. */
};

static void report_loss(struct dpif *, struct dpif_channel *);

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int dp_ifindex;

    /* Upcall messages. */
    struct ovs_mutex upcall_lock;
    int uc_array_size;          /* Size of 'channels' and 'epoll_events'. */
    struct dpif_channel *channels;
    struct epoll_event *epoll_events;
    int epoll_fd;               /* epoll fd that includes channel socks. */
    int n_events;               /* Num events returned by epoll_wait(). */
    int event_offset;           /* Offset into 'epoll_events'. */

    /* Change notification. */
    struct nl_sock *port_notifier; /* vport multicast group subscriber. */
    bool refresh_channels;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by dpif_linux_init(). */
static int ovs_datapath_family;
static int ovs_vport_family;
static int ovs_flow_family;
static int ovs_packet_family;

/* Generic Netlink multicast groups for OVS.
 *
 * Initialized by dpif_linux_init(). */
static unsigned int ovs_vport_mcgroup;

static int dpif_linux_init(void);
static int open_dpif(const struct dpif_linux_dp *, struct dpif **);
static uint32_t dpif_linux_port_get_pid(const struct dpif *,
                                        odp_port_t port_no);
static int dpif_linux_refresh_channels(struct dpif *);

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
        /* Use OVS_DP_CMD_SET to report user features */
        dp_request.cmd = OVS_DP_CMD_SET;
    }
    dp_request.name = name;
    dp_request.user_features |= OVS_DP_F_UNALIGNED;
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

    dpif = xzalloc(sizeof *dpif);
    dpif->port_notifier = NULL;
    ovs_mutex_init(&dpif->upcall_lock);
    dpif->epoll_fd = -1;

    dpif_init(&dpif->dpif, &dpif_linux_class, dp->name,
              dp->dp_ifindex, dp->dp_ifindex);

    dpif->dp_ifindex = dp->dp_ifindex;
    *dpifp = &dpif->dpif;

    return 0;
}

static void
destroy_channels(struct dpif_linux *dpif)
{
    unsigned int i;

    if (dpif->epoll_fd < 0) {
        return;
    }

    for (i = 0; i < dpif->uc_array_size; i++ ) {
        struct dpif_linux_vport vport_request;
        struct dpif_channel *ch = &dpif->channels[i];
        uint32_t upcall_pid = 0;

        if (!ch->sock) {
            continue;
        }

        epoll_ctl(dpif->epoll_fd, EPOLL_CTL_DEL, nl_sock_fd(ch->sock), NULL);

        /* Turn off upcalls. */
        dpif_linux_vport_init(&vport_request);
        vport_request.cmd = OVS_VPORT_CMD_SET;
        vport_request.dp_ifindex = dpif->dp_ifindex;
        vport_request.port_no = u32_to_odp(i);
        vport_request.upcall_pid = &upcall_pid;
        dpif_linux_vport_transact(&vport_request, NULL, NULL);

        nl_sock_destroy(ch->sock);
    }

    free(dpif->channels);
    dpif->channels = NULL;
    dpif->uc_array_size = 0;

    free(dpif->epoll_events);
    dpif->epoll_events = NULL;
    dpif->n_events = dpif->event_offset = 0;

    /* Don't close dpif->epoll_fd since that would cause other threads that
     * call dpif_recv_wait(dpif) to wait on an arbitrary fd or a closed fd. */
}

static int
add_channel(struct dpif_linux *dpif, odp_port_t port_no, struct nl_sock *sock)
{
    struct epoll_event event;
    uint32_t port_idx = odp_to_u32(port_no);

    if (dpif->epoll_fd < 0) {
        return 0;
    }

    /* We assume that the datapath densely chooses port numbers, which
     * can therefore be used as an index into an array of channels. */
    if (port_idx >= dpif->uc_array_size) {
        uint32_t new_size = port_idx + 1;
        uint32_t i;

        if (new_size > MAX_PORTS) {
            VLOG_WARN_RL(&error_rl, "%s: datapath port %"PRIu32" too big",
                         dpif_name(&dpif->dpif), port_no);
            return EFBIG;
        }

        dpif->channels = xrealloc(dpif->channels,
                                  new_size * sizeof *dpif->channels);
        for (i = dpif->uc_array_size; i < new_size; i++) {
            dpif->channels[i].sock = NULL;
        }

        dpif->epoll_events = xrealloc(dpif->epoll_events,
                                      new_size * sizeof *dpif->epoll_events);
        dpif->uc_array_size = new_size;
    }

    memset(&event, 0, sizeof event);
    event.events = EPOLLIN;
    event.data.u32 = port_idx;
    if (epoll_ctl(dpif->epoll_fd, EPOLL_CTL_ADD, nl_sock_fd(sock),
                  &event) < 0) {
        return errno;
    }

    nl_sock_destroy(dpif->channels[port_idx].sock);
    dpif->channels[port_idx].sock = sock;
    dpif->channels[port_idx].last_poll = LLONG_MIN;

    return 0;
}

static void
del_channel(struct dpif_linux *dpif, odp_port_t port_no)
{
    struct dpif_channel *ch;
    uint32_t port_idx = odp_to_u32(port_no);

    if (dpif->epoll_fd < 0 || port_idx >= dpif->uc_array_size) {
        return;
    }

    ch = &dpif->channels[port_idx];
    if (!ch->sock) {
        return;
    }

    epoll_ctl(dpif->epoll_fd, EPOLL_CTL_DEL, nl_sock_fd(ch->sock), NULL);
    dpif->event_offset = dpif->n_events = 0;

    nl_sock_destroy(ch->sock);
    ch->sock = NULL;
}

static void
dpif_linux_close(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    nl_sock_destroy(dpif->port_notifier);
    destroy_channels(dpif);
    if (dpif->epoll_fd >= 0) {
        close(dpif->epoll_fd);
    }
    ovs_mutex_destroy(&dpif->upcall_lock);
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
dpif_linux_run(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    if (dpif->refresh_channels) {
        dpif->refresh_channels = false;
        dpif_linux_refresh_channels(dpif_);
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
        stats->n_masks  = dp.megaflow_stats.n_masks;
        stats->n_mask_hit  = dp.megaflow_stats.n_mask_hit;
        ofpbuf_delete(buf);
    }
    return error;
}

static const char *
get_vport_type(const struct dpif_linux_vport *vport)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    switch (vport->type) {
    case OVS_VPORT_TYPE_NETDEV: {
        const char *type = netdev_get_type_from_name(vport->name);

        return type ? type : "system";
    }

    case OVS_VPORT_TYPE_INTERNAL:
        return "internal";

    case OVS_VPORT_TYPE_GRE:
        return "gre";

    case OVS_VPORT_TYPE_GRE64:
        return "gre64";

    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";

    case OVS_VPORT_TYPE_LISP:
        return "lisp";

    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
        break;
    }

    VLOG_WARN_RL(&rl, "dp%d: port `%s' has unsupported type %u",
                 vport->dp_ifindex, vport->name, (unsigned int) vport->type);
    return "unknown";
}

static enum ovs_vport_type
netdev_to_ovs_vport_type(const struct netdev *netdev)
{
    const char *type = netdev_get_type(netdev);

    if (!strcmp(type, "tap") || !strcmp(type, "system")) {
        return OVS_VPORT_TYPE_NETDEV;
    } else if (!strcmp(type, "internal")) {
        return OVS_VPORT_TYPE_INTERNAL;
    } else if (strstr(type, "gre64")) {
        return OVS_VPORT_TYPE_GRE64;
    } else if (strstr(type, "gre")) {
        return OVS_VPORT_TYPE_GRE;
    } else if (!strcmp(type, "vxlan")) {
        return OVS_VPORT_TYPE_VXLAN;
    } else if (!strcmp(type, "lisp")) {
        return OVS_VPORT_TYPE_LISP;
    } else {
        return OVS_VPORT_TYPE_UNSPEC;
    }
}

static int
dpif_linux_port_add__(struct dpif *dpif_, struct netdev *netdev,
                      odp_port_t *port_nop)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name = netdev_vport_get_dpif_port(netdev,
                                                  namebuf, sizeof namebuf);
    const char *type = netdev_get_type(netdev);
    struct dpif_linux_vport request, reply;
    struct nl_sock *sock = NULL;
    uint32_t upcall_pid;
    struct ofpbuf *buf;
    uint64_t options_stub[64 / 8];
    struct ofpbuf options;
    int error;

    if (dpif->epoll_fd >= 0) {
        error = nl_sock_create(NETLINK_GENERIC, &sock);
        if (error) {
            return error;
        }
    }

    dpif_linux_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = netdev_to_ovs_vport_type(netdev);
    if (request.type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(dpif_), name, type);
        nl_sock_destroy(sock);
        return EINVAL;
    }
    request.name = name;

    if (request.type == OVS_VPORT_TYPE_NETDEV) {
        netdev_linux_ethtool_set_flag(netdev, ETH_FLAG_LRO, "LRO", false);
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg && tnl_cfg->dst_port != 0) {
        ofpbuf_use_stack(&options, options_stub, sizeof options_stub);
        nl_msg_put_u16(&options, OVS_TUNNEL_ATTR_DST_PORT,
                       ntohs(tnl_cfg->dst_port));
        request.options = options.data;
        request.options_len = options.size;
    }

    request.port_no = *port_nop;
    upcall_pid = sock ? nl_sock_pid(sock) : 0;
    request.upcall_pid = &upcall_pid;

    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
        VLOG_DBG("%s: assigning port %"PRIu32" to netlink pid %"PRIu32,
                 dpif_name(dpif_), reply.port_no, upcall_pid);
    } else {
        if (error == EBUSY && *port_nop != ODPP_NONE) {
            VLOG_INFO("%s: requested port %"PRIu32" is in use",
                      dpif_name(dpif_), *port_nop);
        }
        nl_sock_destroy(sock);
        ofpbuf_delete(buf);
        return error;
    }
    ofpbuf_delete(buf);

    if (sock) {
        error = add_channel(dpif, *port_nop, sock);
        if (error) {
            VLOG_INFO("%s: could not add channel for port %s",
                      dpif_name(dpif_), name);

            /* Delete the port. */
            dpif_linux_vport_init(&request);
            request.cmd = OVS_VPORT_CMD_DEL;
            request.dp_ifindex = dpif->dp_ifindex;
            request.port_no = *port_nop;
            dpif_linux_vport_transact(&request, NULL, NULL);

            nl_sock_destroy(sock);
            return error;
        }
    }

    return 0;
}

static int
dpif_linux_port_add(struct dpif *dpif_, struct netdev *netdev,
                    odp_port_t *port_nop)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int error;

    ovs_mutex_lock(&dpif->upcall_lock);
    error = dpif_linux_port_add__(dpif_, netdev, port_nop);
    ovs_mutex_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_linux_port_del__(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_vport vport;
    int error;

    dpif_linux_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_DEL;
    vport.dp_ifindex = dpif->dp_ifindex;
    vport.port_no = port_no;
    error = dpif_linux_vport_transact(&vport, NULL, NULL);

    del_channel(dpif, port_no);

    return error;
}

static int
dpif_linux_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int error;

    ovs_mutex_lock(&dpif->upcall_lock);
    error = dpif_linux_port_del__(dpif_, port_no);
    ovs_mutex_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_linux_port_query__(const struct dpif *dpif, odp_port_t port_no,
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
        if (reply.dp_ifindex != request.dp_ifindex) {
            /* A query by name reported that 'port_name' is in some datapath
             * other than 'dpif', but the caller wants to know about 'dpif'. */
            error = ENODEV;
        } else if (dpif_port) {
            dpif_port->name = xstrdup(reply.name);
            dpif_port->type = xstrdup(get_vport_type(&reply));
            dpif_port->port_no = reply.port_no;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_linux_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
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

static uint32_t
dpif_linux_get_max_ports(const struct dpif *dpif OVS_UNUSED)
{
    return MAX_PORTS;
}

static uint32_t
dpif_linux_port_get_pid(const struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    uint32_t port_idx = odp_to_u32(port_no);
    uint32_t pid = 0;

    ovs_mutex_lock(&dpif->upcall_lock);
    if (dpif->epoll_fd >= 0) {
        /* The ODPP_NONE "reserved" port number uses the "ovs-system"'s
         * channel, since it is not heavily loaded. */
        uint32_t idx = port_idx >= dpif->uc_array_size ? 0 : port_idx;
        const struct nl_sock *sock = dpif->channels[idx].sock;
        pid = sock ? nl_sock_pid(sock) : 0;
    }
    ovs_mutex_unlock(&dpif->upcall_lock);

    return pid;
}

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow flow;

    dpif_linux_flow_init(&flow);
    flow.cmd = OVS_FLOW_CMD_DEL;
    flow.dp_ifindex = dpif->dp_ifindex;
    return dpif_linux_flow_transact(&flow, NULL, NULL);
}

struct dpif_linux_port_state {
    struct nl_dump dump;
};

static void
dpif_linux_port_dump_start__(const struct dpif *dpif_, struct nl_dump *dump)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_vport request;
    struct ofpbuf *buf;

    dpif_linux_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_linux_vport_to_ofpbuf(&request, buf);
    nl_dump_start(dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);
}

static int
dpif_linux_port_dump_start(const struct dpif *dpif, void **statep)
{
    struct dpif_linux_port_state *state;

    *statep = state = xmalloc(sizeof *state);
    dpif_linux_port_dump_start__(dpif, &state->dump);

    return 0;
}

static int
dpif_linux_port_dump_next__(const struct dpif *dpif_, struct nl_dump *dump,
                            struct dpif_linux_vport *vport)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct ofpbuf buf;
    int error;

    if (!nl_dump_next(dump, &buf)) {
        return EOF;
    }

    error = dpif_linux_vport_from_ofpbuf(vport, &buf);
    if (error) {
        VLOG_WARN_RL(&error_rl, "%s: failed to parse vport record (%s)",
                     dpif_name(&dpif->dpif), ovs_strerror(error));
    }
    return error;
}

static int
dpif_linux_port_dump_next(const struct dpif *dpif OVS_UNUSED, void *state_,
                          struct dpif_port *dpif_port)
{
    struct dpif_linux_port_state *state = state_;
    struct dpif_linux_vport vport;
    int error;

    error = dpif_linux_port_dump_next__(dpif, &state->dump, &vport);
    if (error) {
        return error;
    }
    dpif_port->name = CONST_CAST(char *, vport.name);
    dpif_port->type = CONST_CAST(char *, get_vport_type(&vport));
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_linux_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_linux_port_state *state = state_;
    int error = nl_dump_done(&state->dump);

    free(state);
    return error;
}

static int
dpif_linux_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    /* Lazily create the Netlink socket to listen for notifications. */
    if (!dpif->port_notifier) {
        struct nl_sock *sock;
        int error;

        error = nl_sock_create(NETLINK_GENERIC, &sock);
        if (error) {
            return error;
        }

        error = nl_sock_join_mcgroup(sock, ovs_vport_mcgroup);
        if (error) {
            nl_sock_destroy(sock);
            return error;
        }
        dpif->port_notifier = sock;

        /* We have no idea of the current state so report that everything
         * changed. */
        return ENOBUFS;
    }

    for (;;) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(dpif->port_notifier, &buf, false);
        if (!error) {
            struct dpif_linux_vport vport;

            error = dpif_linux_vport_from_ofpbuf(&vport, &buf);
            if (!error) {
                if (vport.dp_ifindex == dpif->dp_ifindex
                    && (vport.cmd == OVS_VPORT_CMD_NEW
                        || vport.cmd == OVS_VPORT_CMD_DEL
                        || vport.cmd == OVS_VPORT_CMD_SET)) {
                    VLOG_DBG("port_changed: dpif:%s vport:%s cmd:%"PRIu8,
                             dpif->dpif.full_name, vport.name, vport.cmd);
                    if (vport.cmd == OVS_VPORT_CMD_DEL) {
                        dpif->refresh_channels = true;
                    }
                    *devnamep = xstrdup(vport.name);
                    ofpbuf_uninit(&buf);
                    return 0;
                }
            }
        } else if (error != EAGAIN) {
            VLOG_WARN_RL(&rl, "error reading or parsing netlink (%s)",
                         ovs_strerror(error));
            nl_sock_drain(dpif->port_notifier);
            error = ENOBUFS;
        }

        ofpbuf_uninit(&buf);
        if (error) {
            return error;
        }
    }
}

static void
dpif_linux_port_poll_wait(const struct dpif *dpif_)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (dpif->port_notifier) {
        nl_sock_wait(dpif->port_notifier, POLLIN);
    } else {
        poll_immediate_wake();
    }
}

static int
dpif_linux_flow_get__(const struct dpif *dpif_,
                      const struct nlattr *key, size_t key_len,
                      struct dpif_linux_flow *reply, struct ofpbuf **bufp)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);
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
            buf->data = CONST_CAST(struct nlattr *, reply.actions);
            buf->size = reply.actions_len;
            *actionsp = buf;
        } else {
            ofpbuf_delete(buf);
        }
    }
    return error;
}

static void
dpif_linux_init_flow_put(struct dpif *dpif_, const struct dpif_flow_put *put,
                         struct dpif_linux_flow *request)
{
    static const struct nlattr dummy_action;

    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    dpif_linux_flow_init(request);
    request->cmd = (put->flags & DPIF_FP_CREATE
                    ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET);
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = put->key;
    request->key_len = put->key_len;
    request->mask = put->mask;
    request->mask_len = put->mask_len;
    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = (put->actions
                        ? put->actions
                        : CONST_CAST(struct nlattr *, &dummy_action));
    request->actions_len = put->actions_len;
    if (put->flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    request->nlmsg_flags = put->flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}

static int
dpif_linux_flow_put(struct dpif *dpif_, const struct dpif_flow_put *put)
{
    struct dpif_linux_flow request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_init_flow_put(dpif_, put, &request);
    error = dpif_linux_flow_transact(&request,
                                     put->stats ? &reply : NULL,
                                     put->stats ? &buf : NULL);
    if (!error && put->stats) {
        dpif_linux_flow_get_stats(&reply, put->stats);
        ofpbuf_delete(buf);
    }
    return error;
}

static void
dpif_linux_init_flow_del(struct dpif *dpif_, const struct dpif_flow_del *del,
                         struct dpif_linux_flow *request)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    dpif_linux_flow_init(request);
    request->cmd = OVS_FLOW_CMD_DEL;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = del->key;
    request->key_len = del->key_len;
}

static int
dpif_linux_flow_del(struct dpif *dpif_, const struct dpif_flow_del *del)
{
    struct dpif_linux_flow request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_init_flow_del(dpif_, del, &request);
    error = dpif_linux_flow_transact(&request,
                                     del->stats ? &reply : NULL,
                                     del->stats ? &buf : NULL);
    if (!error && del->stats) {
        dpif_linux_flow_get_stats(&reply, del->stats);
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
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow_state *state;
    struct dpif_linux_flow request;
    struct ofpbuf *buf;

    *statep = state = xmalloc(sizeof *state);

    dpif_linux_flow_init(&request);
    request.cmd = OVS_FLOW_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_linux_flow_to_ofpbuf(&request, buf);
    nl_dump_start(&state->dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);

    state->buf = NULL;

    return 0;
}

static int
dpif_linux_flow_dump_next(const struct dpif *dpif_ OVS_UNUSED, void *state_,
                          const struct nlattr **key, size_t *key_len,
                          const struct nlattr **mask, size_t *mask_len,
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
                VLOG_WARN("error fetching dumped flow: %s",
                          ovs_strerror(error));
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
    if (mask) {
        *mask = state->flow.mask;
        *mask_len = state->flow.mask ? state->flow.mask_len : 0;
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

static void
dpif_linux_encode_execute(int dp_ifindex, const struct dpif_execute *d_exec,
                          struct ofpbuf *buf)
{
    struct ovs_header *k_exec;

    ofpbuf_prealloc_tailroom(buf, (64
                                   + d_exec->packet->size
                                   + d_exec->key_len
                                   + d_exec->actions_len));

    nl_msg_put_genlmsghdr(buf, 0, ovs_packet_family, NLM_F_REQUEST,
                          OVS_PACKET_CMD_EXECUTE, OVS_PACKET_VERSION);

    k_exec = ofpbuf_put_uninit(buf, sizeof *k_exec);
    k_exec->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_PACKET,
                      d_exec->packet->data, d_exec->packet->size);
    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_KEY, d_exec->key, d_exec->key_len);
    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_ACTIONS,
                      d_exec->actions, d_exec->actions_len);
}

static int
dpif_linux_execute__(int dp_ifindex, const struct dpif_execute *execute)
{
    uint64_t request_stub[1024 / 8];
    struct ofpbuf request;
    int error;

    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);
    dpif_linux_encode_execute(dp_ifindex, execute, &request);
    error = nl_transact(NETLINK_GENERIC, &request, NULL);
    ofpbuf_uninit(&request);

    return error;
}

static int
dpif_linux_execute(struct dpif *dpif_, const struct dpif_execute *execute)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    return dpif_linux_execute__(dpif->dp_ifindex, execute);
}

#define MAX_OPS 50

static void
dpif_linux_operate__(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    const struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    struct op_auxdata {
        struct nl_transaction txn;

        struct ofpbuf request;
        uint64_t request_stub[1024 / 8];

        struct ofpbuf reply;
        uint64_t reply_stub[1024 / 8];
    } auxes[MAX_OPS];

    struct nl_transaction *txnsp[MAX_OPS];
    size_t i;

    ovs_assert(n_ops <= MAX_OPS);
    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_execute *execute;
        struct dpif_linux_flow flow;

        ofpbuf_use_stub(&aux->request,
                        aux->request_stub, sizeof aux->request_stub);
        aux->txn.request = &aux->request;

        ofpbuf_use_stub(&aux->reply, aux->reply_stub, sizeof aux->reply_stub);
        aux->txn.reply = NULL;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            dpif_linux_init_flow_put(dpif_, put, &flow);
            if (put->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_linux_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            dpif_linux_init_flow_del(dpif_, del, &flow);
            if (del->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_linux_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_EXECUTE:
            execute = &op->u.execute;
            dpif_linux_encode_execute(dpif->dp_ifindex, execute,
                                      &aux->request);
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    for (i = 0; i < n_ops; i++) {
        txnsp[i] = &auxes[i].txn;
    }
    nl_transact_multiple(NETLINK_GENERIC, txnsp, n_ops);

    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct nl_transaction *txn = &auxes[i].txn;
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;

        op->error = txn->error;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            if (put->stats) {
                if (!op->error) {
                    struct dpif_linux_flow reply;

                    op->error = dpif_linux_flow_from_ofpbuf(&reply,
                                                            txn->reply);
                    if (!op->error) {
                        dpif_linux_flow_get_stats(&reply, put->stats);
                    }
                }

                if (op->error) {
                    memset(put->stats, 0, sizeof *put->stats);
                }
            }
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            if (del->stats) {
                if (!op->error) {
                    struct dpif_linux_flow reply;

                    op->error = dpif_linux_flow_from_ofpbuf(&reply,
                                                            txn->reply);
                    if (!op->error) {
                        dpif_linux_flow_get_stats(&reply, del->stats);
                    }
                }

                if (op->error) {
                    memset(del->stats, 0, sizeof *del->stats);
                }
            }
            break;

        case DPIF_OP_EXECUTE:
            break;

        default:
            OVS_NOT_REACHED();
        }

        ofpbuf_uninit(&aux->request);
        ofpbuf_uninit(&aux->reply);
    }
}

static void
dpif_linux_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    while (n_ops > 0) {
        size_t chunk = MIN(n_ops, MAX_OPS);
        dpif_linux_operate__(dpif, ops, chunk);
        ops += chunk;
        n_ops -= chunk;
    }
}

/* Synchronizes 'dpif->channels' with the set of vports currently in 'dpif' in
 * the kernel, by adding a new channel for any kernel vport that lacks one and
 * deleting any channels that have no backing kernel vports. */
static int
dpif_linux_refresh_channels(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    unsigned long int *keep_channels;
    struct dpif_linux_vport vport;
    size_t keep_channels_nbits;
    struct nl_dump dump;
    int retval = 0;
    size_t i;

    /* To start with, we need an epoll fd. */
    if (dpif->epoll_fd < 0) {
        dpif->epoll_fd = epoll_create(10);
        if (dpif->epoll_fd < 0) {
            return errno;
        }
    }

    keep_channels_nbits = dpif->uc_array_size;
    keep_channels = bitmap_allocate(keep_channels_nbits);

    dpif->n_events = dpif->event_offset = 0;

    dpif_linux_port_dump_start__(dpif_, &dump);
    while (!dpif_linux_port_dump_next__(dpif_, &dump, &vport)) {
        uint32_t port_no = odp_to_u32(vport.port_no);
        struct nl_sock *sock = (port_no < dpif->uc_array_size
                                ? dpif->channels[port_no].sock
                                : NULL);
        bool new_sock = !sock;
        int error;

        if (new_sock) {
            error = nl_sock_create(NETLINK_GENERIC, &sock);
            if (error) {
                retval = error;
                goto error;
            }
        }

        /* Configure the vport to deliver misses to 'sock'. */
        if (!vport.upcall_pid || *vport.upcall_pid != nl_sock_pid(sock)) {
            uint32_t upcall_pid = nl_sock_pid(sock);
            struct dpif_linux_vport vport_request;

            dpif_linux_vport_init(&vport_request);
            vport_request.cmd = OVS_VPORT_CMD_SET;
            vport_request.dp_ifindex = dpif->dp_ifindex;
            vport_request.port_no = vport.port_no;
            vport_request.upcall_pid = &upcall_pid;
            error = dpif_linux_vport_transact(&vport_request, NULL, NULL);
            if (!error) {
                VLOG_DBG("%s: assigning port %"PRIu32" to netlink pid %"PRIu32,
                         dpif_name(&dpif->dpif), vport_request.port_no,
                         upcall_pid);
            } else {
                VLOG_WARN_RL(&error_rl,
                             "%s: failed to set upcall pid on port: %s",
                             dpif_name(&dpif->dpif), ovs_strerror(error));

                if (error != ENODEV && error != ENOENT) {
                    retval = error;
                } else {
                    /* The vport isn't really there, even though the dump says
                     * it is.  Probably we just hit a race after a port
                     * disappeared. */
                }
                goto error;
            }
        }

        if (new_sock) {
            error = add_channel(dpif, vport.port_no, sock);
            if (error) {
                VLOG_INFO("%s: could not add channel for port %s",
                          dpif_name(dpif_), vport.name);
                retval = error;
                goto error;
            }
        }

        if (port_no < keep_channels_nbits) {
            bitmap_set1(keep_channels, port_no);
        }
        continue;

    error:
        nl_sock_destroy(sock);
    }
    nl_dump_done(&dump);

    /* Discard any saved channels that we didn't reuse. */
    for (i = 0; i < keep_channels_nbits; i++) {
        if (!bitmap_is_set(keep_channels, i)) {
            nl_sock_destroy(dpif->channels[i].sock);
            dpif->channels[i].sock = NULL;
        }
    }
    free(keep_channels);

    return retval;
}

static int
dpif_linux_recv_set__(struct dpif *dpif_, bool enable)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if ((dpif->epoll_fd >= 0) == enable) {
        return 0;
    } else if (!enable) {
        destroy_channels(dpif);
        return 0;
    } else {
        return dpif_linux_refresh_channels(dpif_);
    }
}

static int
dpif_linux_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int error;

    ovs_mutex_lock(&dpif->upcall_lock);
    error = dpif_linux_recv_set__(dpif_, enable);
    ovs_mutex_unlock(&dpif->upcall_lock);

    return error;
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
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_UNSPEC, .optional = true },
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

    /* (Re)set ALL fields of '*upcall' on successful return. */
    upcall->type = type;
    upcall->key = CONST_CAST(struct nlattr *,
                             nl_attr_get(a[OVS_PACKET_ATTR_KEY]));
    upcall->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    upcall->userdata = a[OVS_PACKET_ATTR_USERDATA];

    /* Allow overwriting the netlink attribute header without reallocating. */
    ofpbuf_use_stub(&upcall->packet,
                    CONST_CAST(struct nlattr *,
                               nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                    nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                    sizeof(struct nlattr));
    upcall->packet.data = (char *)upcall->packet.data + sizeof(struct nlattr);
    upcall->packet.size = nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]);

    *dp_ifindex = ovs_header->dp_ifindex;

    return 0;
}

static int
dpif_linux_recv__(struct dpif *dpif_, struct dpif_upcall *upcall,
                  struct ofpbuf *buf)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int read_tries = 0;

    if (dpif->epoll_fd < 0) {
       return EAGAIN;
    }

    if (dpif->event_offset >= dpif->n_events) {
        int retval;

        dpif->event_offset = dpif->n_events = 0;

        do {
            retval = epoll_wait(dpif->epoll_fd, dpif->epoll_events,
                                dpif->uc_array_size, 0);
        } while (retval < 0 && errno == EINTR);
        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "epoll_wait failed (%s)", ovs_strerror(errno));
        } else if (retval > 0) {
            dpif->n_events = retval;
        }
    }

    while (dpif->event_offset < dpif->n_events) {
        int idx = dpif->epoll_events[dpif->event_offset].data.u32;
        struct dpif_channel *ch = &dpif->channels[idx];

        dpif->event_offset++;

        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > 50) {
                return EAGAIN;
            }

            error = nl_sock_recv(ch->sock, buf, false);
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                report_loss(dpif_, ch);
                continue;
            }

            ch->last_poll = time_msec();
            if (error) {
                if (error == EAGAIN) {
                    break;
                }
                return error;
            }

            error = parse_odp_packet(buf, upcall, &dp_ifindex);
            if (!error && dp_ifindex == dpif->dp_ifindex) {
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}

static int
dpif_linux_recv(struct dpif *dpif_, struct dpif_upcall *upcall,
                struct ofpbuf *buf)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int error;

    ovs_mutex_lock(&dpif->upcall_lock);
    error = dpif_linux_recv__(dpif_, upcall, buf);
    ovs_mutex_unlock(&dpif->upcall_lock);

    return error;
}

static void
dpif_linux_recv_wait(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    ovs_mutex_lock(&dpif->upcall_lock);
    if (dpif->epoll_fd >= 0) {
        poll_fd_wait(dpif->epoll_fd, POLLIN);
    }
    ovs_mutex_unlock(&dpif->upcall_lock);
}

static void
dpif_linux_recv_purge(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    ovs_mutex_lock(&dpif->upcall_lock);
    if (dpif->epoll_fd >= 0) {
        struct dpif_channel *ch;

        for (ch = dpif->channels; ch < &dpif->channels[dpif->uc_array_size];
             ch++) {
            if (ch->sock) {
                nl_sock_drain(ch->sock);
            }
        }
    }
    ovs_mutex_unlock(&dpif->upcall_lock);
}

const struct dpif_class dpif_linux_class = {
    "system",
    dpif_linux_enumerate,
    NULL,
    dpif_linux_open,
    dpif_linux_close,
    dpif_linux_destroy,
    dpif_linux_run,
    NULL,                       /* wait */
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
    dpif_linux_recv_set,
    dpif_linux_queue_to_priority,
    dpif_linux_recv,
    dpif_linux_recv_wait,
    dpif_linux_recv_purge,
};

static int
dpif_linux_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int error;

    if (ovsthread_once_start(&once)) {
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
            error = nl_lookup_genl_mcgroup(OVS_VPORT_FAMILY, OVS_VPORT_MCGROUP,
                                           &ovs_vport_mcgroup);
        }

        ovsthread_once_done(&once);
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
                     name, ovs_strerror(error));
    }

    return reply.type == OVS_VPORT_TYPE_INTERNAL;
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
    vport->port_no = nl_attr_get_odp_port(a[OVS_VPORT_ATTR_PORT_NO]);
    vport->type = nl_attr_get_u32(a[OVS_VPORT_ATTR_TYPE]);
    vport->name = nl_attr_get_string(a[OVS_VPORT_ATTR_NAME]);
    if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
        vport->upcall_pid = nl_attr_get(a[OVS_VPORT_ATTR_UPCALL_PID]);
    }
    if (a[OVS_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[OVS_VPORT_ATTR_STATS]);
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

    if (vport->port_no != ODPP_NONE) {
        nl_msg_put_odp_port(buf, OVS_VPORT_ATTR_PORT_NO, vport->port_no);
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
    vport->port_no = ODPP_NONE;
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

    ovs_assert((reply != NULL) == (bufp != NULL));

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
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
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
        [OVS_DP_ATTR_MEGAFLOW_STATS] = {
                        NL_POLICY_FOR(struct ovs_dp_megaflow_stats),
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

    if (a[OVS_DP_ATTR_MEGAFLOW_STATS]) {
        /* Can't use structure assignment because Netlink doesn't ensure
         * sufficient alignment for 64-bit members. */
        memcpy(&dp->megaflow_stats, nl_attr_get(a[OVS_DP_ATTR_MEGAFLOW_STATS]),
               sizeof dp->megaflow_stats);
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

    if (dp->user_features) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_USER_FEATURES, dp->user_features);
    }

    /* Skip OVS_DP_ATTR_STATS since we never have a reason to serialize it. */
}

/* Clears 'dp' to "empty" values. */
static void
dpif_linux_dp_init(struct dpif_linux_dp *dp)
{
    memset(dp, 0, sizeof *dp);
    dp->megaflow_stats.n_masks = UINT32_MAX;
    dp->megaflow_stats.n_mask_hit = UINT64_MAX;
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
    nl_dump_start(dump, NETLINK_GENERIC, buf);
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

    ovs_assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_linux_dp_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        dpif_linux_dp_init(reply);
        if (!error) {
            error = dpif_linux_dp_from_ofpbuf(reply, *bufp);
        }
        if (error) {
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
        [OVS_FLOW_ATTR_MASK] = { .type = NL_A_NESTED, .optional = true },
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

    if (a[OVS_FLOW_ATTR_MASK]) {
        flow->mask = nl_attr_get(a[OVS_FLOW_ATTR_MASK]);
        flow->mask_len = nl_attr_get_size(a[OVS_FLOW_ATTR_MASK]);
    }
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

    if (flow->mask_len) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_MASK, flow->mask, flow->mask_len);
    }

    if (flow->actions || flow->actions_len) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS,
                          flow->actions, flow->actions_len);
    }

    /* We never need to send these to the kernel. */
    ovs_assert(!flow->stats);
    ovs_assert(!flow->tcp_flags);
    ovs_assert(!flow->used);

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

    ovs_assert((reply != NULL) == (bufp != NULL));

    if (reply) {
        request->nlmsg_flags |= NLM_F_ECHO;
    }

    request_buf = ofpbuf_new(1024);
    dpif_linux_flow_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
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

/* Logs information about a packet that was recently lost in 'ch' (in
 * 'dpif_'). */
static void
report_loss(struct dpif *dpif_, struct dpif_channel *ch)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct ds s;

    if (VLOG_DROP_WARN(&rl)) {
        return;
    }

    ds_init(&s);
    if (ch->last_poll != LLONG_MIN) {
        ds_put_format(&s, " (last polled %lld ms ago)",
                      time_msec() - ch->last_poll);
    }

    VLOG_WARN("%s: lost packet on channel %"PRIdPTR"%s",
              dpif_name(dpif_), ch - dpif->channels, ds_cstr(&s));
    ds_destroy(&s);
}
