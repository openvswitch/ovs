/*
 * Copyright (c) 2008-2018 Nicira, Inc.
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

#include "dpif-netlink.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-netlink-rtnl.h"
#include "dpif-provider.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "netdev-linux.h"
#include "netdev-offload.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netdev.h"
#include "netlink-conntrack.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "netnsid.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/flow.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/thread.h"
#include "openvswitch/usdt-probes.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "random.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netlink);
#ifdef _WIN32
#include "wmi.h"
enum { WINDOWS = 1 };
#else
enum { WINDOWS = 0 };
#endif
enum { MAX_PORTS = USHRT_MAX };

/* This ethtool flag was introduced in Linux 2.6.24, so it might be
 * missing if we have old headers. */
#define ETH_FLAG_LRO      (1 << 15)    /* LRO is enabled */

#define FLOW_DUMP_MAX_BATCH 50
#define OPERATE_MAX_OPS 50

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)
#endif

#define OVS_DP_F_UNSUPPORTED (1u << 31);

/* This PID is not used by the kernel datapath when using dispatch per CPU,
 * but it is required to be set (not zero). */
#define DPIF_NETLINK_PER_CPU_PID UINT32_MAX
struct dpif_netlink_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct ovs_header. */
    int dp_ifindex;

    /* Attributes. */
    const char *name;                  /* OVS_DP_ATTR_NAME. */
    const uint32_t *upcall_pid;        /* OVS_DP_ATTR_UPCALL_PID. */
    uint32_t user_features;            /* OVS_DP_ATTR_USER_FEATURES */
    uint32_t cache_size;               /* OVS_DP_ATTR_MASKS_CACHE_SIZE */
    const struct ovs_dp_stats *stats;  /* OVS_DP_ATTR_STATS. */
    const struct ovs_dp_megaflow_stats *megaflow_stats;
                                       /* OVS_DP_ATTR_MEGAFLOW_STATS.*/
    const uint32_t *upcall_pids;       /* OVS_DP_ATTR_PER_CPU_PIDS */
    uint32_t n_upcall_pids;
};

static void dpif_netlink_dp_init(struct dpif_netlink_dp *);
static int dpif_netlink_dp_from_ofpbuf(struct dpif_netlink_dp *,
                                       const struct ofpbuf *);
static void dpif_netlink_dp_dump_start(struct nl_dump *);
static int dpif_netlink_dp_transact(const struct dpif_netlink_dp *request,
                                    struct dpif_netlink_dp *reply,
                                    struct ofpbuf **bufp);
static int dpif_netlink_dp_get(const struct dpif *,
                               struct dpif_netlink_dp *reply,
                               struct ofpbuf **bufp);
static int
dpif_netlink_set_features(struct dpif *dpif_, uint32_t new_features);

static void
dpif_netlink_unixctl_dispatch_mode(struct unixctl_conn *conn, int argc,
                                   const char *argv[], void *aux);

struct dpif_netlink_flow {
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
    ovs_u128 ufid;                      /* OVS_FLOW_ATTR_FLOW_ID. */
    bool ufid_present;                  /* Is there a UFID? */
    bool ufid_terse;                    /* Skip serializing key/mask/acts? */
    const struct ovs_flow_stats *stats; /* OVS_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* OVS_FLOW_ATTR_TCP_FLAGS. */
    const ovs_32aligned_u64 *used;      /* OVS_FLOW_ATTR_USED. */
    bool clear;                         /* OVS_FLOW_ATTR_CLEAR. */
    bool probe;                         /* OVS_FLOW_ATTR_PROBE. */
};

static void dpif_netlink_flow_init(struct dpif_netlink_flow *);
static int dpif_netlink_flow_from_ofpbuf(struct dpif_netlink_flow *,
                                         const struct ofpbuf *);
static void dpif_netlink_flow_to_ofpbuf(const struct dpif_netlink_flow *,
                                        struct ofpbuf *);
static int dpif_netlink_flow_transact(struct dpif_netlink_flow *request,
                                      struct dpif_netlink_flow *reply,
                                      struct ofpbuf **bufp);
static void dpif_netlink_flow_get_stats(const struct dpif_netlink_flow *,
                                        struct dpif_flow_stats *);
static void dpif_netlink_flow_to_dpif_flow(struct dpif_flow *,
                                           const struct dpif_netlink_flow *);

/* One of the dpif channels between the kernel and userspace. */
struct dpif_channel {
    struct nl_sock *sock;       /* Netlink socket. */
    long long int last_poll;    /* Last time this channel was polled. */
};

#ifdef _WIN32
#define VPORT_SOCK_POOL_SIZE 1
/* On Windows, there is no native support for epoll.  There are equivalent
 * interfaces though, that are not used currently.  For simpicity, a pool of
 * netlink sockets is used.  Each socket is represented by 'struct
 * dpif_windows_vport_sock'.  Since it is a pool, multiple OVS ports may be
 * sharing the same socket.  In the future, we can add a reference count and
 * such fields. */
struct dpif_windows_vport_sock {
    struct nl_sock *nl_sock;    /* netlink socket. */
};
#endif

struct dpif_handler {
    /* per-vport dispatch mode. */
    struct epoll_event *epoll_events;
    int epoll_fd;                 /* epoll fd that includes channel socks. */
    int n_events;                 /* Num events returned by epoll_wait(). */
    int event_offset;             /* Offset into 'epoll_events'. */

    /* per-cpu dispatch mode. */
    struct nl_sock *sock;         /* Each handler thread holds one netlink
                                     socket. */

#ifdef _WIN32
    /* Pool of sockets. */
    struct dpif_windows_vport_sock *vport_sock_pool;
    size_t last_used_pool_idx; /* Index to aid in allocating a
                                  socket in the pool to a port. */
#endif
};

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_netlink {
    struct dpif dpif;
    int dp_ifindex;
    uint32_t user_features;

    /* Upcall messages. */
    struct fat_rwlock upcall_lock;
    struct dpif_handler *handlers;
    uint32_t n_handlers;           /* Num of upcall handlers. */

    /* Per-vport dispatch mode. */
    struct dpif_channel *channels; /* Array of channels for each port. */
    int uc_array_size;             /* Size of 'handler->channels' and */
                                   /* 'handler->epoll_events'. */

    /* Change notification. */
    struct nl_sock *port_notifier; /* vport multicast group subscriber. */
    bool refresh_channels;
};

static void report_loss(struct dpif_netlink *, struct dpif_channel *,
                        uint32_t ch_idx, uint32_t handler_id);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by dpif_netlink_init(). */
static int ovs_datapath_family;
static int ovs_vport_family;
static int ovs_flow_family;
static int ovs_packet_family;
static int ovs_meter_family;
static int ovs_ct_limit_family;

/* Generic Netlink multicast groups for OVS.
 *
 * Initialized by dpif_netlink_init(). */
static unsigned int ovs_vport_mcgroup;

/* If true, tunnel devices are created using OVS compat/genetlink.
 * If false, tunnel devices are created with rtnetlink and using light weight
 * tunnels. If we fail to create the tunnel the rtnetlink+LWT, then we fallback
 * to using the compat interface. */
static bool ovs_tunnels_out_of_tree = true;

static int dpif_netlink_init(void);
static int open_dpif(const struct dpif_netlink_dp *, struct dpif **);
static uint32_t dpif_netlink_port_get_pid(const struct dpif *,
                                          odp_port_t port_no);
static void dpif_netlink_handler_uninit(struct dpif_handler *handler);
static int dpif_netlink_refresh_handlers_vport_dispatch(struct dpif_netlink *,
                                                        uint32_t n_handlers);
static void destroy_all_channels(struct dpif_netlink *);
static int dpif_netlink_refresh_handlers_cpu_dispatch(struct dpif_netlink *);
static void destroy_all_handlers(struct dpif_netlink *);

static void dpif_netlink_vport_to_ofpbuf(const struct dpif_netlink_vport *,
                                         struct ofpbuf *);
static int dpif_netlink_vport_from_ofpbuf(struct dpif_netlink_vport *,
                                          const struct ofpbuf *);
static int dpif_netlink_port_query__(const struct dpif_netlink *dpif,
                                     odp_port_t port_no, const char *port_name,
                                     struct dpif_port *dpif_port);
static void vport_del_channels(struct dpif_netlink *, odp_port_t);

static int
create_nl_sock(struct dpif_netlink *dpif OVS_UNUSED, struct nl_sock **sockp)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
#ifndef _WIN32
    return nl_sock_create(NETLINK_GENERIC, sockp);
#else
    /* Pick netlink sockets to use in a round-robin fashion from each
     * handler's pool of sockets. */
    struct dpif_handler *handler = &dpif->handlers[0];
    struct dpif_windows_vport_sock *sock_pool = handler->vport_sock_pool;
    size_t index = handler->last_used_pool_idx;

    /* A pool of sockets is allocated when the handler is initialized. */
    if (sock_pool == NULL) {
        *sockp = NULL;
        return EINVAL;
    }

    ovs_assert(index < VPORT_SOCK_POOL_SIZE);
    *sockp = sock_pool[index].nl_sock;
    ovs_assert(*sockp);
    index = (index == VPORT_SOCK_POOL_SIZE - 1) ? 0 : index + 1;
    handler->last_used_pool_idx = index;
    return 0;
#endif
}

static void
close_nl_sock(struct nl_sock *sock)
{
#ifndef _WIN32
    nl_sock_destroy(sock);
#endif
}

static struct dpif_netlink *
dpif_netlink_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_netlink_class);
    return CONTAINER_OF(dpif, struct dpif_netlink, dpif);
}

static inline bool
dpif_netlink_upcall_per_cpu(const struct dpif_netlink *dpif) {
    return !!((dpif)->user_features & OVS_DP_F_DISPATCH_UPCALL_PER_CPU);
}

static int
dpif_netlink_enumerate(struct sset *all_dps,
                       const struct dpif_class *dpif_class OVS_UNUSED)
{
    struct nl_dump dump;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf msg, buf;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return error;
    }

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    dpif_netlink_dp_dump_start(&dump);
    while (nl_dump_next(&dump, &msg, &buf)) {
        struct dpif_netlink_dp dp;

        if (!dpif_netlink_dp_from_ofpbuf(&dp, &msg)) {
            sset_add(all_dps, dp.name);
        }
    }
    ofpbuf_uninit(&buf);
    return nl_dump_done(&dump);
}

static int
dpif_netlink_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                  bool create, struct dpif **dpifp)
{
    struct dpif_netlink_dp dp_request, dp;
    struct ofpbuf *buf;
    uint32_t upcall_pid;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return error;
    }

    /* Create or look up datapath. */
    dpif_netlink_dp_init(&dp_request);
    upcall_pid = 0;
    dp_request.upcall_pid = &upcall_pid;
    dp_request.name = name;

    if (create) {
        dp_request.cmd = OVS_DP_CMD_NEW;
    } else {
        dp_request.cmd = OVS_DP_CMD_GET;

        error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);
        if (error) {
            return error;
        }
        dp_request.user_features = dp.user_features;
        ofpbuf_delete(buf);

        /* Use OVS_DP_CMD_SET to report user features */
        dp_request.cmd = OVS_DP_CMD_SET;
    }

    /* Some older kernels will not reject unknown features. This will cause
     * 'ovs-vswitchd' to incorrectly assume a feature is supported. In order to
     * test for that, we attempt to set a feature that we know is not supported
     * by any kernel. If this feature is not rejected, we can assume we are
     * running on one of these older kernels.
     */
    dp_request.user_features |= OVS_DP_F_UNALIGNED;
    dp_request.user_features |= OVS_DP_F_VPORT_PIDS;
    dp_request.user_features |= OVS_DP_F_UNSUPPORTED;
    error = dpif_netlink_dp_transact(&dp_request, NULL, NULL);
    if (error) {
        /* The Open vSwitch kernel module has two modes for dispatching
         * upcalls: per-vport and per-cpu.
         *
         * When dispatching upcalls per-vport, the kernel will
         * send the upcall via a Netlink socket that has been selected based on
         * the vport that received the packet that is causing the upcall.
         *
         * When dispatching upcall per-cpu, the kernel will send the upcall via
         * a Netlink socket that has been selected based on the cpu that
         * received the packet that is causing the upcall.
         *
         * First we test to see if the kernel module supports per-cpu
         * dispatching (the preferred method). If it does not support per-cpu
         * dispatching, we fall back to the per-vport dispatch mode.
         */
        dp_request.user_features &= ~OVS_DP_F_UNSUPPORTED;
        dp_request.user_features &= ~OVS_DP_F_VPORT_PIDS;
        dp_request.user_features |= OVS_DP_F_DISPATCH_UPCALL_PER_CPU;
        error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);
        if (error == EOPNOTSUPP) {
            dp_request.user_features &= ~OVS_DP_F_DISPATCH_UPCALL_PER_CPU;
            dp_request.user_features |= OVS_DP_F_VPORT_PIDS;
            error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);
        }
        if (error) {
            return error;
        }

        error = open_dpif(&dp, dpifp);
        dpif_netlink_set_features(*dpifp, OVS_DP_F_TC_RECIRC_SHARING);
    } else {
        VLOG_INFO("Kernel does not correctly support feature negotiation. "
                  "Using standard features.");
        dp_request.cmd = OVS_DP_CMD_SET;
        dp_request.user_features = 0;
        dp_request.user_features |= OVS_DP_F_UNALIGNED;
        dp_request.user_features |= OVS_DP_F_VPORT_PIDS;
        error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);
        if (error) {
            return error;
        }
        error = open_dpif(&dp, dpifp);
    }

    ofpbuf_delete(buf);

    if (create) {
        VLOG_INFO("Datapath dispatch mode: %s",
                  dpif_netlink_upcall_per_cpu(dpif_netlink_cast(*dpifp)) ?
                  "per-cpu" : "per-vport");
    }

    return error;
}

static int
open_dpif(const struct dpif_netlink_dp *dp, struct dpif **dpifp)
{
    struct dpif_netlink *dpif;

    dpif = xzalloc(sizeof *dpif);
    dpif->port_notifier = NULL;
    fat_rwlock_init(&dpif->upcall_lock);

    dpif_init(&dpif->dpif, &dpif_netlink_class, dp->name,
              dp->dp_ifindex, dp->dp_ifindex);

    dpif->dp_ifindex = dp->dp_ifindex;
    dpif->user_features = dp->user_features;
    *dpifp = &dpif->dpif;

    return 0;
}

#ifdef _WIN32
static void
vport_delete_sock_pool(struct dpif_handler *handler)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if (handler->vport_sock_pool) {
        uint32_t i;
        struct dpif_windows_vport_sock *sock_pool =
            handler->vport_sock_pool;

        for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
            if (sock_pool[i].nl_sock) {
                nl_sock_unsubscribe_packets(sock_pool[i].nl_sock);
                nl_sock_destroy(sock_pool[i].nl_sock);
                sock_pool[i].nl_sock = NULL;
            }
        }

        free(handler->vport_sock_pool);
        handler->vport_sock_pool = NULL;
    }
}

static int
vport_create_sock_pool(struct dpif_handler *handler)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    struct dpif_windows_vport_sock *sock_pool;
    size_t i;
    int error = 0;

    sock_pool = xzalloc(VPORT_SOCK_POOL_SIZE * sizeof *sock_pool);
    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        error = nl_sock_create(NETLINK_GENERIC, &sock_pool[i].nl_sock);
        if (error) {
            goto error;
        }

        /* Enable the netlink socket to receive packets.  This is equivalent to
         * calling nl_sock_join_mcgroup() to receive events. */
        error = nl_sock_subscribe_packets(sock_pool[i].nl_sock);
        if (error) {
           goto error;
        }
    }

    handler->vport_sock_pool = sock_pool;
    handler->last_used_pool_idx = 0;
    return 0;

error:
    vport_delete_sock_pool(handler);
    return error;
}
#endif /* _WIN32 */

/* Given the port number 'port_idx', extracts the pid of netlink socket
 * associated to the port and assigns it to 'upcall_pid'. */
static bool
vport_get_pid(struct dpif_netlink *dpif, uint32_t port_idx,
              uint32_t *upcall_pid)
{
    /* Since the nl_sock can only be assigned in either all
     * or none "dpif" channels, the following check
     * would suffice. */
    if (!dpif->channels[port_idx].sock) {
        return false;
    }
    ovs_assert(!WINDOWS || dpif->n_handlers <= 1);

    *upcall_pid = nl_sock_pid(dpif->channels[port_idx].sock);

    return true;
}

static int
vport_add_channel(struct dpif_netlink *dpif, odp_port_t port_no,
                  struct nl_sock *sock)
{
    struct epoll_event event;
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i;
    int error;

    if (dpif->handlers == NULL) {
        close_nl_sock(sock);
        return 0;
    }

    /* We assume that the datapath densely chooses port numbers, which can
     * therefore be used as an index into 'channels' and 'epoll_events' of
     * 'dpif'. */
    if (port_idx >= dpif->uc_array_size) {
        uint32_t new_size = port_idx + 1;

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

        for (i = 0; i < dpif->n_handlers; i++) {
            struct dpif_handler *handler = &dpif->handlers[i];

            handler->epoll_events = xrealloc(handler->epoll_events,
                new_size * sizeof *handler->epoll_events);

        }
        dpif->uc_array_size = new_size;
    }

    vport_del_channels(dpif, port_no);

    memset(&event, 0, sizeof event);
    event.events = EPOLLIN | EPOLLEXCLUSIVE;
    event.data.u32 = port_idx;

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

#ifndef _WIN32
        if (epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, nl_sock_fd(sock),
                      &event) < 0) {
            error = errno;
            goto error;
        }
#endif
    }
    dpif->channels[port_idx].sock = sock;
    dpif->channels[port_idx].last_poll = LLONG_MIN;

    return 0;

error:
#ifndef _WIN32
    while (i--) {
        epoll_ctl(dpif->handlers[i].epoll_fd, EPOLL_CTL_DEL,
                  nl_sock_fd(sock), NULL);
    }
#endif
    dpif->channels[port_idx].sock = NULL;

    return error;
}

static void
vport_del_channels(struct dpif_netlink *dpif, odp_port_t port_no)
{
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i;

    if (!dpif->handlers || port_idx >= dpif->uc_array_size
        || !dpif->channels[port_idx].sock) {
        return;
    }

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];
#ifndef _WIN32
        epoll_ctl(handler->epoll_fd, EPOLL_CTL_DEL,
                  nl_sock_fd(dpif->channels[port_idx].sock), NULL);
#endif
        handler->event_offset = handler->n_events = 0;
    }
#ifndef _WIN32
    nl_sock_destroy(dpif->channels[port_idx].sock);
#endif
    dpif->channels[port_idx].sock = NULL;
}

static void
destroy_all_channels(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    unsigned int i;

    if (!dpif->handlers) {
        return;
    }

    for (i = 0; i < dpif->uc_array_size; i++ ) {
        struct dpif_netlink_vport vport_request;
        uint32_t upcall_pids = 0;

        if (!dpif->channels[i].sock) {
            continue;
        }

        /* Turn off upcalls. */
        dpif_netlink_vport_init(&vport_request);
        vport_request.cmd = OVS_VPORT_CMD_SET;
        vport_request.dp_ifindex = dpif->dp_ifindex;
        vport_request.port_no = u32_to_odp(i);
        vport_request.n_upcall_pids = 1;
        vport_request.upcall_pids = &upcall_pids;
        dpif_netlink_vport_transact(&vport_request, NULL, NULL);

        vport_del_channels(dpif, u32_to_odp(i));
    }

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

        dpif_netlink_handler_uninit(handler);
        free(handler->epoll_events);
    }
    free(dpif->channels);
    free(dpif->handlers);
    dpif->handlers = NULL;
    dpif->channels = NULL;
    dpif->n_handlers = 0;
    dpif->uc_array_size = 0;
}

static void
destroy_all_handlers(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    int i = 0;

    if (!dpif->handlers) {
        return;
    }
    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];
        close_nl_sock(handler->sock);
    }
    free(dpif->handlers);
    dpif->handlers = NULL;
    dpif->n_handlers = 0;
}

static void
dpif_netlink_close(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    nl_sock_destroy(dpif->port_notifier);

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        destroy_all_handlers(dpif);
    } else {
        destroy_all_channels(dpif);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    fat_rwlock_destroy(&dpif->upcall_lock);
    free(dpif);
}

static int
dpif_netlink_destroy(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp dp;

    dpif_netlink_dp_init(&dp);
    dp.cmd = OVS_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_netlink_dp_transact(&dp, NULL, NULL);
}

static bool
dpif_netlink_run(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    if (!dpif_netlink_upcall_per_cpu(dpif)) {
        if (dpif->refresh_channels) {
            dpif->refresh_channels = false;
            fat_rwlock_wrlock(&dpif->upcall_lock);
            dpif_netlink_refresh_handlers_vport_dispatch(dpif,
                                                         dpif->n_handlers);
            fat_rwlock_unlock(&dpif->upcall_lock);
        }
    }
    return false;
}

static int
dpif_netlink_get_stats(const struct dpif *dpif_, struct dpif_dp_stats *stats)
{
    struct dpif_netlink_dp dp;
    struct ofpbuf *buf;
    int error;

    error = dpif_netlink_dp_get(dpif_, &dp, &buf);
    if (!error) {
        memset(stats, 0, sizeof *stats);

        if (dp.stats) {
            stats->n_hit    = get_32aligned_u64(&dp.stats->n_hit);
            stats->n_missed = get_32aligned_u64(&dp.stats->n_missed);
            stats->n_lost   = get_32aligned_u64(&dp.stats->n_lost);
            stats->n_flows  = get_32aligned_u64(&dp.stats->n_flows);
        }

        if (dp.megaflow_stats) {
            stats->n_masks = dp.megaflow_stats->n_masks;
            stats->n_mask_hit = get_32aligned_u64(
                &dp.megaflow_stats->n_mask_hit);
            stats->n_cache_hit = get_32aligned_u64(
                &dp.megaflow_stats->n_cache_hit);

            if (!stats->n_cache_hit) {
                /* Old kernels don't use this field and always
                 * report zero instead.  Disable this stat. */
                stats->n_cache_hit = UINT64_MAX;
            }
        } else {
            stats->n_masks = UINT32_MAX;
            stats->n_mask_hit = UINT64_MAX;
            stats->n_cache_hit = UINT64_MAX;
        }
        ofpbuf_delete(buf);
    }
    return error;
}

static int
dpif_netlink_set_handler_pids(struct dpif *dpif_, const uint32_t *upcall_pids,
                              uint32_t n_upcall_pids)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int largest_cpu_id = ovs_numa_get_largest_core_id();
    struct dpif_netlink_dp request, reply;
    struct ofpbuf *bufp;

    uint32_t *corrected;
    int error, i, n_cores;

    if (largest_cpu_id == OVS_NUMA_UNSPEC) {
        largest_cpu_id = -1;
    }

    /* Some systems have non-continuous cpu core ids.  count_total_cores()
     * would return an accurate number, however, this number cannot be used.
     * e.g. If the largest core_id of a system is cpu9, but the system only
     * has 4 cpus then the OVS kernel module would throw a "CPU mismatch"
     * warning.  With the MAX() in place in this example we send an array of
     * size 10 and prevent the warning.  This has no bearing on the number of
     * threads created.
     */
    n_cores = MAX(count_total_cores(), largest_cpu_id + 1);
    VLOG_DBG("Dispatch mode(per-cpu): Setting up handler PIDs for %d cores",
             n_cores);

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_SET;
    request.name = dpif_->base_name;
    request.dp_ifindex = dpif->dp_ifindex;
    request.user_features = dpif->user_features |
                            OVS_DP_F_DISPATCH_UPCALL_PER_CPU;

    corrected = xcalloc(n_cores, sizeof *corrected);

    for (i = 0; i < n_cores; i++) {
        corrected[i] = upcall_pids[i % n_upcall_pids];
    }
    request.upcall_pids = corrected;
    request.n_upcall_pids = n_cores;

    error = dpif_netlink_dp_transact(&request, &reply, &bufp);
    if (!error) {
        dpif->user_features = reply.user_features;
        ofpbuf_delete(bufp);
        if (!dpif_netlink_upcall_per_cpu(dpif)) {
            error = -EOPNOTSUPP;
        }
    }
    free(corrected);
    return error;
}

static int
dpif_netlink_set_features(struct dpif *dpif_, uint32_t new_features)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp request, reply;
    struct ofpbuf *bufp;
    int error;

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_SET;
    request.name = dpif_->base_name;
    request.dp_ifindex = dpif->dp_ifindex;
    request.user_features = dpif->user_features | new_features;

    error = dpif_netlink_dp_transact(&request, &reply, &bufp);
    if (!error) {
        dpif->user_features = reply.user_features;
        ofpbuf_delete(bufp);
        if (!(dpif->user_features & new_features)) {
            return -EOPNOTSUPP;
        }
    }

    return error;
}

static const char *
get_vport_type(const struct dpif_netlink_vport *vport)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    switch (vport->type) {
    case OVS_VPORT_TYPE_NETDEV: {
        const char *type = netdev_get_type_from_name(vport->name);

        return type ? type : "system";
    }

    case OVS_VPORT_TYPE_INTERNAL:
        return "internal";

    case OVS_VPORT_TYPE_GENEVE:
        return "geneve";

    case OVS_VPORT_TYPE_GRE:
        return "gre";

    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";

    case OVS_VPORT_TYPE_ERSPAN:
        return "erspan";

    case OVS_VPORT_TYPE_IP6ERSPAN:
        return "ip6erspan";

    case OVS_VPORT_TYPE_IP6GRE:
        return "ip6gre";

    case OVS_VPORT_TYPE_GTPU:
        return "gtpu";

    case OVS_VPORT_TYPE_SRV6:
        return "srv6";

    case OVS_VPORT_TYPE_BAREUDP:
        return "bareudp";

    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
        break;
    }

    VLOG_WARN_RL(&rl, "dp%d: port `%s' has unsupported type %u",
                 vport->dp_ifindex, vport->name, (unsigned int) vport->type);
    return "unknown";
}

enum ovs_vport_type
netdev_to_ovs_vport_type(const char *type)
{
    if (!strcmp(type, "tap") || !strcmp(type, "system")) {
        return OVS_VPORT_TYPE_NETDEV;
    } else if (!strcmp(type, "internal")) {
        return OVS_VPORT_TYPE_INTERNAL;
    } else if (!strcmp(type, "geneve")) {
        return OVS_VPORT_TYPE_GENEVE;
    } else if (!strcmp(type, "vxlan")) {
        return OVS_VPORT_TYPE_VXLAN;
    } else if (!strcmp(type, "erspan")) {
        return OVS_VPORT_TYPE_ERSPAN;
    } else if (!strcmp(type, "ip6erspan")) {
        return OVS_VPORT_TYPE_IP6ERSPAN;
    } else if (!strcmp(type, "ip6gre")) {
        return OVS_VPORT_TYPE_IP6GRE;
    } else if (!strcmp(type, "gre")) {
        return OVS_VPORT_TYPE_GRE;
    } else if (!strcmp(type, "gtpu")) {
        return OVS_VPORT_TYPE_GTPU;
    } else if (!strcmp(type, "srv6")) {
        return OVS_VPORT_TYPE_SRV6;
    } else if (!strcmp(type, "bareudp")) {
        return OVS_VPORT_TYPE_BAREUDP;
    } else {
        return OVS_VPORT_TYPE_UNSPEC;
    }
}

static int
dpif_netlink_port_add__(struct dpif_netlink *dpif, const char *name,
                        enum ovs_vport_type type,
                        struct ofpbuf *options,
                        odp_port_t *port_nop)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    struct dpif_netlink_vport request, reply;
    struct ofpbuf *buf;
    struct nl_sock *sock = NULL;
    uint32_t upcall_pids = 0;
    int error = 0;

    /* per-cpu dispatch mode does not require a socket per vport. */
    if (!dpif_netlink_upcall_per_cpu(dpif)) {
        if (dpif->handlers) {
            error = create_nl_sock(dpif, &sock);
            if (error) {
                return error;
            }
        }
        if (sock) {
            upcall_pids = nl_sock_pid(sock);
        }
    }

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = type;
    request.name = name;

    request.port_no = *port_nop;
    request.n_upcall_pids = 1;
    request.upcall_pids = &upcall_pids;

    if (options) {
        request.options = options->data;
        request.options_len = options->size;
    }

    error = dpif_netlink_vport_transact(&request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
    } else {
        if (error == EBUSY && *port_nop != ODPP_NONE) {
            VLOG_INFO("%s: requested port %"PRIu32" is in use",
                      dpif_name(&dpif->dpif), *port_nop);
        }

        close_nl_sock(sock);
        goto exit;
    }

    if (!dpif_netlink_upcall_per_cpu(dpif)) {
        error = vport_add_channel(dpif, *port_nop, sock);
        if (error) {
            VLOG_INFO("%s: could not add channel for port %s",
                        dpif_name(&dpif->dpif), name);

            /* Delete the port. */
            dpif_netlink_vport_init(&request);
            request.cmd = OVS_VPORT_CMD_DEL;
            request.dp_ifindex = dpif->dp_ifindex;
            request.port_no = *port_nop;
            dpif_netlink_vport_transact(&request, NULL, NULL);
            close_nl_sock(sock);
            goto exit;
        }
    }

exit:
    ofpbuf_delete(buf);

    return error;
}

static int
dpif_netlink_port_add_compat(struct dpif_netlink *dpif, struct netdev *netdev,
                             odp_port_t *port_nop)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *type = netdev_get_type(netdev);
    uint64_t options_stub[64 / 8];
    enum ovs_vport_type ovs_type;
    struct ofpbuf options;
    const char *name;

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    ovs_type = netdev_to_ovs_vport_type(netdev_get_type(netdev));
    if (ovs_type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(&dpif->dpif), name, type);
        return EINVAL;
    }

    if (ovs_type == OVS_VPORT_TYPE_NETDEV) {
#ifdef _WIN32
        /* XXX : Map appropiate Windows handle */
#else
        netdev_linux_ethtool_set_flag(netdev, ETH_FLAG_LRO, "LRO", false);
#endif
    }

#ifdef _WIN32
    if (ovs_type == OVS_VPORT_TYPE_INTERNAL) {
        if (!create_wmi_port(name)){
            VLOG_ERR("Could not create wmi internal port with name:%s", name);
            return EINVAL;
        };
    }
#endif

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg && (tnl_cfg->dst_port != 0 || tnl_cfg->exts)) {
        ofpbuf_use_stack(&options, options_stub, sizeof options_stub);
        if (tnl_cfg->dst_port) {
            nl_msg_put_u16(&options, OVS_TUNNEL_ATTR_DST_PORT,
                           ntohs(tnl_cfg->dst_port));
        }
        if (tnl_cfg->exts) {
            size_t ext_ofs;
            int i;

            ext_ofs = nl_msg_start_nested(&options, OVS_TUNNEL_ATTR_EXTENSION);
            for (i = 0; i < 32; i++) {
                if (tnl_cfg->exts & (UINT32_C(1) << i)) {
                    nl_msg_put_flag(&options, i);
                }
            }
            nl_msg_end_nested(&options, ext_ofs);
        }
        return dpif_netlink_port_add__(dpif, name, ovs_type, &options,
                                       port_nop);
    } else {
        return dpif_netlink_port_add__(dpif, name, ovs_type, NULL, port_nop);
    }

}

static int
dpif_netlink_rtnl_port_create_and_add(struct dpif_netlink *dpif,
                                      struct netdev *netdev,
                                      odp_port_t *port_nop)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name;
    int error;

    error = dpif_netlink_rtnl_port_create(netdev);
    if (error) {
        if (error != EOPNOTSUPP) {
            VLOG_WARN_RL(&rl, "Failed to create %s with rtnetlink: %s",
                         netdev_get_name(netdev), ovs_strerror(error));
        }
        return error;
    }

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    error = dpif_netlink_port_add__(dpif, name, OVS_VPORT_TYPE_NETDEV, NULL,
                                    port_nop);
    if (error) {
        dpif_netlink_rtnl_port_destroy(name, netdev_get_type(netdev));
    }
    return error;
}

static int
dpif_netlink_port_add(struct dpif *dpif_, struct netdev *netdev,
                      odp_port_t *port_nop)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error = EOPNOTSUPP;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (!ovs_tunnels_out_of_tree) {
        error = dpif_netlink_rtnl_port_create_and_add(dpif, netdev, port_nop);
    }
    if (error) {
        error = dpif_netlink_port_add_compat(dpif, netdev, port_nop);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_port_del__(struct dpif_netlink *dpif, odp_port_t port_no)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    struct dpif_netlink_vport vport;
    struct dpif_port dpif_port;
    int error;

    error = dpif_netlink_port_query__(dpif, port_no, NULL, &dpif_port);
    if (error) {
        return error;
    }

    dpif_netlink_vport_init(&vport);
    vport.cmd = OVS_VPORT_CMD_DEL;
    vport.dp_ifindex = dpif->dp_ifindex;
    vport.port_no = port_no;
#ifdef _WIN32
    if (!strcmp(dpif_port.type, "internal")) {
        if (!delete_wmi_port(dpif_port.name)) {
            VLOG_ERR("Could not delete wmi port with name: %s",
                     dpif_port.name);
        };
    }
#endif
    error = dpif_netlink_vport_transact(&vport, NULL, NULL);

    vport_del_channels(dpif, port_no);

    if (!error && !ovs_tunnels_out_of_tree) {
        error = dpif_netlink_rtnl_port_destroy(dpif_port.name, dpif_port.type);
        if (error == EOPNOTSUPP) {
            error = 0;
        }
    }

    dpif_port_destroy(&dpif_port);

    return error;
}

static int
dpif_netlink_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_netlink_port_del__(dpif, port_no);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_port_query__(const struct dpif_netlink *dpif, odp_port_t port_no,
                          const char *port_name, struct dpif_port *dpif_port)
{
    struct dpif_netlink_vport request;
    struct dpif_netlink_vport reply;
    struct ofpbuf *buf;
    int error;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;
    request.port_no = port_no;
    request.name = port_name;

    error = dpif_netlink_vport_transact(&request, &reply, &buf);
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
dpif_netlink_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                                  struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    return dpif_netlink_port_query__(dpif, port_no, NULL, dpif_port);
}

static int
dpif_netlink_port_query_by_name(const struct dpif *dpif_, const char *devname,
                              struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    return dpif_netlink_port_query__(dpif, 0, devname, dpif_port);
}

static uint32_t
dpif_netlink_port_get_pid__(const struct dpif_netlink *dpif,
                            odp_port_t port_no)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    uint32_t port_idx = odp_to_u32(port_no);
    uint32_t pid = 0;

    if (dpif->handlers && dpif->uc_array_size > 0) {
        /* The ODPP_NONE "reserved" port number uses the "ovs-system"'s
         * channel, since it is not heavily loaded. */
        uint32_t idx = port_idx >= dpif->uc_array_size ? 0 : port_idx;

        /* Needs to check in case the socket pointer is changed in between
         * the holding of upcall_lock.  A known case happens when the main
         * thread deletes the vport while the handler thread is handling
         * the upcall from that port. */
        if (dpif->channels[idx].sock) {
            pid = nl_sock_pid(dpif->channels[idx].sock);
        }
    }

    return pid;
}

static uint32_t
dpif_netlink_port_get_pid(const struct dpif *dpif_, odp_port_t port_no)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    uint32_t ret;

    /* In per-cpu dispatch mode, vports do not have an associated PID */
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        /* In per-cpu dispatch mode, this will be ignored as kernel space will
         * select the PID before sending to user space. We set to
         * DPIF_NETLINK_PER_CPU_PID as 0 is rejected by kernel space as an
         * invalid PID.
         */
        return DPIF_NETLINK_PER_CPU_PID;
    }

    fat_rwlock_rdlock(&dpif->upcall_lock);
    ret = dpif_netlink_port_get_pid__(dpif, port_no);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return ret;
}

static int
dpif_netlink_flow_flush(struct dpif *dpif_)
{
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif_));
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_flow flow;

    dpif_netlink_flow_init(&flow);
    flow.cmd = OVS_FLOW_CMD_DEL;
    flow.dp_ifindex = dpif->dp_ifindex;

    if (netdev_is_flow_api_enabled()) {
        netdev_ports_flow_flush(dpif_type_str);
    }

    return dpif_netlink_flow_transact(&flow, NULL, NULL);
}

struct dpif_netlink_port_state {
    struct nl_dump dump;
    struct ofpbuf buf;
};

static void
dpif_netlink_port_dump_start__(const struct dpif_netlink *dpif,
                               struct nl_dump *dump)
{
    struct dpif_netlink_vport request;
    struct ofpbuf *buf;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    buf = ofpbuf_new(1024);
    dpif_netlink_vport_to_ofpbuf(&request, buf);
    nl_dump_start(dump, NETLINK_GENERIC, buf);
    ofpbuf_delete(buf);
}

static int
dpif_netlink_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_port_state *state;

    *statep = state = xmalloc(sizeof *state);
    dpif_netlink_port_dump_start__(dpif, &state->dump);

    ofpbuf_init(&state->buf, NL_DUMP_BUFSIZE);
    return 0;
}

static int
dpif_netlink_port_dump_next__(const struct dpif_netlink *dpif,
                              struct nl_dump *dump,
                              struct dpif_netlink_vport *vport,
                              struct ofpbuf *buffer)
{
    struct ofpbuf buf;
    int error;

    if (!nl_dump_next(dump, &buf, buffer)) {
        return EOF;
    }

    error = dpif_netlink_vport_from_ofpbuf(vport, &buf);
    if (error) {
        VLOG_WARN_RL(&error_rl, "%s: failed to parse vport record (%s)",
                     dpif_name(&dpif->dpif), ovs_strerror(error));
    }
    return error;
}

static int
dpif_netlink_port_dump_next(const struct dpif *dpif_, void *state_,
                            struct dpif_port *dpif_port)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_port_state *state = state_;
    struct dpif_netlink_vport vport;
    int error;

    error = dpif_netlink_port_dump_next__(dpif, &state->dump, &vport,
                                          &state->buf);
    if (error) {
        return error;
    }
    dpif_port->name = CONST_CAST(char *, vport.name);
    dpif_port->type = CONST_CAST(char *, get_vport_type(&vport));
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_netlink_port_dump_done(const struct dpif *dpif_ OVS_UNUSED, void *state_)
{
    struct dpif_netlink_port_state *state = state_;
    int error = nl_dump_done(&state->dump);

    ofpbuf_uninit(&state->buf);
    free(state);
    return error;
}

static int
dpif_netlink_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

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
        error = nl_sock_recv(dpif->port_notifier, &buf, NULL, false);
        if (!error) {
            struct dpif_netlink_vport vport;

            error = dpif_netlink_vport_from_ofpbuf(&vport, &buf);
            if (!error) {
                if (vport.dp_ifindex == dpif->dp_ifindex
                    && (vport.cmd == OVS_VPORT_CMD_NEW
                        || vport.cmd == OVS_VPORT_CMD_DEL
                        || vport.cmd == OVS_VPORT_CMD_SET)) {
                    VLOG_DBG("port_changed: dpif:%s vport:%s cmd:%"PRIu8,
                             dpif->dpif.full_name, vport.name, vport.cmd);
                    if (vport.cmd == OVS_VPORT_CMD_DEL && dpif->handlers) {
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
dpif_netlink_port_poll_wait(const struct dpif *dpif_)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    if (dpif->port_notifier) {
        nl_sock_wait(dpif->port_notifier, POLLIN);
    } else {
        poll_immediate_wake();
    }
}

static void
dpif_netlink_flow_init_ufid(struct dpif_netlink_flow *request,
                            const ovs_u128 *ufid, bool terse)
{
    if (ufid) {
        request->ufid = *ufid;
        request->ufid_present = true;
    } else {
        request->ufid_present = false;
    }
    request->ufid_terse = terse;
}

static void
dpif_netlink_init_flow_get__(const struct dpif_netlink *dpif,
                             const struct nlattr *key, size_t key_len,
                             const ovs_u128 *ufid, bool terse,
                             struct dpif_netlink_flow *request)
{
    dpif_netlink_flow_init(request);
    request->cmd = OVS_FLOW_CMD_GET;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    dpif_netlink_flow_init_ufid(request, ufid, terse);
}

static void
dpif_netlink_init_flow_get(const struct dpif_netlink *dpif,
                           const struct dpif_flow_get *get,
                           struct dpif_netlink_flow *request)
{
    dpif_netlink_init_flow_get__(dpif, get->key, get->key_len, get->ufid,
                                 false, request);
}

static int
dpif_netlink_flow_get__(const struct dpif_netlink *dpif,
                        const struct nlattr *key, size_t key_len,
                        const ovs_u128 *ufid, bool terse,
                        struct dpif_netlink_flow *reply, struct ofpbuf **bufp)
{
    struct dpif_netlink_flow request;

    dpif_netlink_init_flow_get__(dpif, key, key_len, ufid, terse, &request);
    return dpif_netlink_flow_transact(&request, reply, bufp);
}

static int
dpif_netlink_flow_get(const struct dpif_netlink *dpif,
                      const struct dpif_netlink_flow *flow,
                      struct dpif_netlink_flow *reply, struct ofpbuf **bufp)
{
    return dpif_netlink_flow_get__(dpif, flow->key, flow->key_len,
                                   flow->ufid_present ? &flow->ufid : NULL,
                                   false, reply, bufp);
}

static void
dpif_netlink_init_flow_put(struct dpif_netlink *dpif,
                           const struct dpif_flow_put *put,
                           struct dpif_netlink_flow *request)
{
    static const struct nlattr dummy_action;

    dpif_netlink_flow_init(request);
    request->cmd = (put->flags & DPIF_FP_CREATE
                    ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET);
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = put->key;
    request->key_len = put->key_len;
    request->mask = put->mask;
    request->mask_len = put->mask_len;
    dpif_netlink_flow_init_ufid(request, put->ufid, false);

    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = (put->actions
                        ? put->actions
                        : CONST_CAST(struct nlattr *, &dummy_action));
    request->actions_len = put->actions_len;
    if (put->flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    if (put->flags & DPIF_FP_PROBE) {
        request->probe = true;
    }
    request->nlmsg_flags = put->flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}

static void
dpif_netlink_init_flow_del__(struct dpif_netlink *dpif,
                             const struct nlattr *key, size_t key_len,
                             const ovs_u128 *ufid, bool terse,
                             struct dpif_netlink_flow *request)
{
    dpif_netlink_flow_init(request);
    request->cmd = OVS_FLOW_CMD_DEL;
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = key;
    request->key_len = key_len;
    dpif_netlink_flow_init_ufid(request, ufid, terse);
}

static void
dpif_netlink_init_flow_del(struct dpif_netlink *dpif,
                           const struct dpif_flow_del *del,
                           struct dpif_netlink_flow *request)
{
    dpif_netlink_init_flow_del__(dpif, del->key, del->key_len,
                                 del->ufid, del->terse, request);
}

struct dpif_netlink_flow_dump {
    struct dpif_flow_dump up;
    struct nl_dump nl_dump;
    atomic_int status;
    struct netdev_flow_dump **netdev_dumps;
    int netdev_dumps_num;                    /* Number of netdev_flow_dumps */
    struct ovs_mutex netdev_lock;            /* Guards the following. */
    int netdev_current_dump OVS_GUARDED;     /* Shared current dump */
    struct dpif_flow_dump_types types;       /* Type of dump */
};

static struct dpif_netlink_flow_dump *
dpif_netlink_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netlink_flow_dump, up);
}

static void
start_netdev_dump(const struct dpif *dpif_,
                  struct dpif_netlink_flow_dump *dump)
{
    ovs_mutex_init(&dump->netdev_lock);

    if (!(dump->types.netdev_flows)) {
        dump->netdev_dumps_num = 0;
        dump->netdev_dumps = NULL;
        return;
    }

    ovs_mutex_lock(&dump->netdev_lock);
    dump->netdev_current_dump = 0;
    dump->netdev_dumps
        = netdev_ports_flow_dump_create(dpif_normalize_type(dpif_type(dpif_)),
                                        &dump->netdev_dumps_num,
                                        dump->up.terse);
    ovs_mutex_unlock(&dump->netdev_lock);
}

static void
dpif_netlink_populate_flow_dump_types(struct dpif_netlink_flow_dump *dump,
                                      struct dpif_flow_dump_types *types)
{
    if (!types) {
        dump->types.ovs_flows = true;
        dump->types.netdev_flows = true;
    } else {
        memcpy(&dump->types, types, sizeof *types);
    }
}

static struct dpif_flow_dump *
dpif_netlink_flow_dump_create(const struct dpif *dpif_, bool terse,
                              struct dpif_flow_dump_types *types)
{
    const struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_flow_dump *dump;
    struct dpif_netlink_flow request;
    struct ofpbuf *buf;

    dump = xmalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);

    dpif_netlink_populate_flow_dump_types(dump, types);

    if (dump->types.ovs_flows) {
        dpif_netlink_flow_init(&request);
        request.cmd = OVS_FLOW_CMD_GET;
        request.dp_ifindex = dpif->dp_ifindex;
        request.ufid_present = false;
        request.ufid_terse = terse;

        buf = ofpbuf_new(1024);
        dpif_netlink_flow_to_ofpbuf(&request, buf);
        nl_dump_start(&dump->nl_dump, NETLINK_GENERIC, buf);
        ofpbuf_delete(buf);
    }
    atomic_init(&dump->status, 0);
    dump->up.terse = terse;

    start_netdev_dump(dpif_, dump);

    return &dump->up;
}

static int
dpif_netlink_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netlink_flow_dump *dump = dpif_netlink_flow_dump_cast(dump_);
    unsigned int nl_status = 0;
    int dump_status;

    if (dump->types.ovs_flows) {
        nl_status = nl_dump_done(&dump->nl_dump);
    }

    for (int i = 0; i < dump->netdev_dumps_num; i++) {
        int err = netdev_flow_dump_destroy(dump->netdev_dumps[i]);

        if (err != 0 && err != EOPNOTSUPP) {
            VLOG_ERR("failed dumping netdev: %s", ovs_strerror(err));
        }
    }

    free(dump->netdev_dumps);
    ovs_mutex_destroy(&dump->netdev_lock);

    /* No other thread has access to 'dump' at this point. */
    atomic_read_relaxed(&dump->status, &dump_status);
    free(dump);
    return dump_status ? dump_status : nl_status;
}

struct dpif_netlink_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netlink_flow_dump *dump;
    struct dpif_netlink_flow flow;
    struct dpif_flow_stats stats;
    struct ofpbuf nl_flows;     /* Always used to store flows. */
    struct ofpbuf *nl_actions;  /* Used if kernel does not supply actions. */
    int netdev_dump_idx;        /* This thread current netdev dump index */
    bool netdev_done;           /* If we are finished dumping netdevs */

    /* (Key/Mask/Actions) Buffers for netdev dumping */
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf actbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_netlink_flow_dump_thread *
dpif_netlink_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netlink_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netlink_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netlink_flow_dump *dump = dpif_netlink_flow_dump_cast(dump_);
    struct dpif_netlink_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    ofpbuf_init(&thread->nl_flows, NL_DUMP_BUFSIZE);
    thread->nl_actions = NULL;
    thread->netdev_dump_idx = 0;
    thread->netdev_done = !(thread->netdev_dump_idx < dump->netdev_dumps_num);

    return &thread->up;
}

static void
dpif_netlink_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netlink_flow_dump_thread *thread
        = dpif_netlink_flow_dump_thread_cast(thread_);

    ofpbuf_uninit(&thread->nl_flows);
    ofpbuf_delete(thread->nl_actions);
    free(thread);
}

static void
dpif_netlink_flow_to_dpif_flow(struct dpif_flow *dpif_flow,
                               const struct dpif_netlink_flow *datapath_flow)
{
    dpif_flow->key = datapath_flow->key;
    dpif_flow->key_len = datapath_flow->key_len;
    dpif_flow->mask = datapath_flow->mask;
    dpif_flow->mask_len = datapath_flow->mask_len;
    dpif_flow->actions = datapath_flow->actions;
    dpif_flow->actions_len = datapath_flow->actions_len;
    dpif_flow->ufid_present = datapath_flow->ufid_present;
    dpif_flow->pmd_id = PMD_ID_NULL;
    if (datapath_flow->ufid_present) {
        dpif_flow->ufid = datapath_flow->ufid;
    } else {
        ovs_assert(datapath_flow->key && datapath_flow->key_len);
        odp_flow_key_hash(datapath_flow->key, datapath_flow->key_len,
                          &dpif_flow->ufid);
    }
    dpif_netlink_flow_get_stats(datapath_flow, &dpif_flow->stats);
    dpif_flow->attrs.offloaded = false;
    dpif_flow->attrs.dp_layer = "ovs";
    dpif_flow->attrs.dp_extra_info = NULL;
}

/* The design is such that all threads are working together on the first dump
 * to the last, in order (at first they all on dump 0).
 * When the first thread finds that the given dump is finished,
 * they all move to the next. If two or more threads find the same dump
 * is finished at the same time, the first one will advance the shared
 * netdev_current_dump and the others will catch up. */
static void
dpif_netlink_advance_netdev_dump(struct dpif_netlink_flow_dump_thread *thread)
{
    struct dpif_netlink_flow_dump *dump = thread->dump;

    ovs_mutex_lock(&dump->netdev_lock);
    /* if we haven't finished (dumped everything) */
    if (dump->netdev_current_dump < dump->netdev_dumps_num) {
        /* if we are the first to find that current dump is finished
         * advance it. */
        if (thread->netdev_dump_idx == dump->netdev_current_dump) {
            thread->netdev_dump_idx = ++dump->netdev_current_dump;
            /* did we just finish the last dump? done. */
            if (dump->netdev_current_dump == dump->netdev_dumps_num) {
                thread->netdev_done = true;
            }
        } else {
            /* otherwise, we are behind, catch up */
            thread->netdev_dump_idx = dump->netdev_current_dump;
        }
    } else {
        /* some other thread finished */
        thread->netdev_done = true;
    }
    ovs_mutex_unlock(&dump->netdev_lock);
}

static int
dpif_netlink_netdev_match_to_dpif_flow(struct match *match,
                                       struct ofpbuf *key_buf,
                                       struct ofpbuf *mask_buf,
                                       struct nlattr *actions,
                                       struct dpif_flow_stats *stats,
                                       struct dpif_flow_attrs *attrs,
                                       ovs_u128 *ufid,
                                       struct dpif_flow *flow,
                                       bool terse)
{
    memset(flow, 0, sizeof *flow);

    if (!terse) {
        struct odp_flow_key_parms odp_parms = {
            .flow = &match->flow,
            .mask = &match->wc.masks,
            .support = {
                .max_vlan_headers = 2,
                .recirc = true,
                .ct_state = true,
                .ct_zone = true,
                .ct_mark = true,
                .ct_label = true,
            },
        };
        size_t offset;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        flow->actions = nl_attr_get(actions);
        flow->actions_len = nl_attr_get_size(actions);
    }

    /* Stats */
    memcpy(&flow->stats, stats, sizeof *stats);

    /* UFID */
    flow->ufid_present = true;
    flow->ufid = *ufid;

    flow->pmd_id = PMD_ID_NULL;

    memcpy(&flow->attrs, attrs, sizeof *attrs);

    return 0;
}

static int
dpif_netlink_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                            struct dpif_flow *flows, int max_flows)
{
    struct dpif_netlink_flow_dump_thread *thread
        = dpif_netlink_flow_dump_thread_cast(thread_);
    struct dpif_netlink_flow_dump *dump = thread->dump;
    struct dpif_netlink *dpif = dpif_netlink_cast(thread->up.dpif);
    int n_flows;

    ofpbuf_delete(thread->nl_actions);
    thread->nl_actions = NULL;

    n_flows = 0;
    max_flows = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

    while (!thread->netdev_done && n_flows < max_flows) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[n_flows];
        struct odputil_keybuf *keybuf = &thread->keybuf[n_flows];
        struct odputil_keybuf *actbuf = &thread->actbuf[n_flows];
        struct ofpbuf key, mask, act;
        struct dpif_flow *f = &flows[n_flows];
        int cur = thread->netdev_dump_idx;
        struct netdev_flow_dump *netdev_dump = dump->netdev_dumps[cur];
        struct match match;
        struct nlattr *actions;
        struct dpif_flow_stats stats;
        struct dpif_flow_attrs attrs;
        ovs_u128 ufid;
        bool has_next;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&act, actbuf, sizeof *actbuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        has_next = netdev_flow_dump_next(netdev_dump, &match,
                                        &actions, &stats, &attrs,
                                        &ufid,
                                        &thread->nl_flows,
                                        &act);
        if (has_next) {
            dpif_netlink_netdev_match_to_dpif_flow(&match,
                                                   &key, &mask,
                                                   actions,
                                                   &stats,
                                                   &attrs,
                                                   &ufid,
                                                   f,
                                                   dump->up.terse);
            n_flows++;
        } else {
            dpif_netlink_advance_netdev_dump(thread);
        }
    }

    if (!(dump->types.ovs_flows)) {
        return n_flows;
    }

    while (!n_flows
           || (n_flows < max_flows && thread->nl_flows.size)) {
        struct dpif_netlink_flow datapath_flow;
        struct ofpbuf nl_flow;
        int error;

        /* Try to grab another flow. */
        if (!nl_dump_next(&dump->nl_dump, &nl_flow, &thread->nl_flows)) {
            break;
        }

        /* Convert the flow to our output format. */
        error = dpif_netlink_flow_from_ofpbuf(&datapath_flow, &nl_flow);
        if (error) {
            atomic_store_relaxed(&dump->status, error);
            break;
        }

        if (dump->up.terse || datapath_flow.actions) {
            /* Common case: we don't want actions, or the flow includes
             * actions. */
            dpif_netlink_flow_to_dpif_flow(&flows[n_flows++], &datapath_flow);
        } else {
            /* Rare case: the flow does not include actions.  Retrieve this
             * individual flow again to get the actions. */
            error = dpif_netlink_flow_get(dpif, &datapath_flow,
                                          &datapath_flow, &thread->nl_actions);
            if (error == ENOENT) {
                VLOG_DBG("dumped flow disappeared on get");
                continue;
            } else if (error) {
                VLOG_WARN("error fetching dumped flow: %s",
                          ovs_strerror(error));
                atomic_store_relaxed(&dump->status, error);
                break;
            }

            /* Save this flow.  Then exit, because we only have one buffer to
             * handle this case. */
            dpif_netlink_flow_to_dpif_flow(&flows[n_flows++], &datapath_flow);
            break;
        }
    }
    return n_flows;
}

static void
dpif_netlink_encode_execute(int dp_ifindex, const struct dpif_execute *d_exec,
                            struct ofpbuf *buf)
{
    struct ovs_header *k_exec;
    size_t key_ofs;

    ofpbuf_prealloc_tailroom(buf, (64
                                   + dp_packet_size(d_exec->packet)
                                   + ODP_KEY_METADATA_SIZE
                                   + d_exec->actions_len));

    nl_msg_put_genlmsghdr(buf, 0, ovs_packet_family, NLM_F_REQUEST,
                          OVS_PACKET_CMD_EXECUTE, OVS_PACKET_VERSION);

    k_exec = ofpbuf_put_uninit(buf, sizeof *k_exec);
    k_exec->dp_ifindex = dp_ifindex;

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_PACKET,
                      dp_packet_data(d_exec->packet),
                      dp_packet_size(d_exec->packet));

    key_ofs = nl_msg_start_nested(buf, OVS_PACKET_ATTR_KEY);
    odp_key_from_dp_packet(buf, d_exec->packet);
    nl_msg_end_nested(buf, key_ofs);

    nl_msg_put_unspec(buf, OVS_PACKET_ATTR_ACTIONS,
                      d_exec->actions, d_exec->actions_len);
    if (d_exec->probe) {
        nl_msg_put_flag(buf, OVS_PACKET_ATTR_PROBE);
    }
    if (d_exec->mtu) {
        nl_msg_put_u16(buf, OVS_PACKET_ATTR_MRU, d_exec->mtu);
    }

    if (d_exec->hash) {
        nl_msg_put_u64(buf, OVS_PACKET_ATTR_HASH, d_exec->hash);
    }

    if (d_exec->upcall_pid) {
        nl_msg_put_u32(buf, OVS_PACKET_ATTR_UPCALL_PID, d_exec->upcall_pid);
    }
}

/* Executes, against 'dpif', up to the first 'n_ops' operations in 'ops'.
 * Returns the number actually executed (at least 1, if 'n_ops' is
 * positive). */
static size_t
dpif_netlink_operate__(struct dpif_netlink *dpif,
                       struct dpif_op **ops, size_t n_ops)
{
    struct op_auxdata {
        struct nl_transaction txn;

        struct ofpbuf request;
        uint64_t request_stub[1024 / 8];

        struct ofpbuf reply;
        uint64_t reply_stub[1024 / 8];
    } auxes[OPERATE_MAX_OPS];

    struct nl_transaction *txnsp[OPERATE_MAX_OPS];
    size_t i;

    n_ops = MIN(n_ops, OPERATE_MAX_OPS);
    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_flow_get *get;
        struct dpif_netlink_flow flow;

        ofpbuf_use_stub(&aux->request,
                        aux->request_stub, sizeof aux->request_stub);
        aux->txn.request = &aux->request;

        ofpbuf_use_stub(&aux->reply, aux->reply_stub, sizeof aux->reply_stub);
        aux->txn.reply = NULL;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->flow_put;
            dpif_netlink_init_flow_put(dpif, put, &flow);
            if (put->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);

            OVS_USDT_PROBE(dpif_netlink_operate__, op_flow_put,
                           dpif, put, &flow, &aux->request);
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->flow_del;
            dpif_netlink_init_flow_del(dpif, del, &flow);
            if (del->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);

            OVS_USDT_PROBE(dpif_netlink_operate__, op_flow_del,
                           dpif, del, &flow, &aux->request);
            break;

        case DPIF_OP_EXECUTE:
            /* Can't execute a packet that won't fit in a Netlink attribute. */
            if (OVS_UNLIKELY(nl_attr_oversized(
                                 dp_packet_size(op->execute.packet)))) {
                /* Report an error immediately if this is the first operation.
                 * Otherwise the easiest thing to do is to postpone to the next
                 * call (when this will be the first operation). */
                if (i == 0) {
                    VLOG_ERR_RL(&error_rl,
                                "dropping oversized %"PRIu32"-byte packet",
                                dp_packet_size(op->execute.packet));
                    op->error = ENOBUFS;
                    return 1;
                }
                n_ops = i;
            } else {
                dpif_netlink_encode_execute(dpif->dp_ifindex, &op->execute,
                                            &aux->request);

                OVS_USDT_PROBE(dpif_netlink_operate__, op_flow_execute,
                               dpif, &op->execute,
                               dp_packet_data(op->execute.packet),
                               dp_packet_size(op->execute.packet),
                               &aux->request);
            }
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->flow_get;
            dpif_netlink_init_flow_get(dpif, get, &flow);
            aux->txn.reply = get->buffer;
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);

            OVS_USDT_PROBE(dpif_netlink_operate__, op_flow_get,
                           dpif, get, &flow, &aux->request);
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
        struct dpif_flow_get *get;

        op->error = txn->error;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->flow_put;
            if (put->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, put->stats);
                    }
                }
            }
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->flow_del;
            if (del->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, del->stats);
                    }
                }
            }
            break;

        case DPIF_OP_EXECUTE:
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->flow_get;
            if (!op->error) {
                struct dpif_netlink_flow reply;

                op->error = dpif_netlink_flow_from_ofpbuf(&reply, txn->reply);
                if (!op->error) {
                    dpif_netlink_flow_to_dpif_flow(get->flow, &reply);
                }
            }
            break;

        default:
            OVS_NOT_REACHED();
        }

        ofpbuf_uninit(&aux->request);
        ofpbuf_uninit(&aux->reply);
    }

    return n_ops;
}

static int
parse_flow_get(struct dpif_netlink *dpif, struct dpif_flow_get *get)
{
    const char *dpif_type_str = dpif_normalize_type(dpif_type(&dpif->dpif));
    struct dpif_flow *dpif_flow = get->flow;
    struct match match;
    struct nlattr *actions;
    struct dpif_flow_stats stats;
    struct dpif_flow_attrs attrs;
    struct ofpbuf buf;
    uint64_t act_buf[1024 / 8];
    struct odputil_keybuf maskbuf;
    struct odputil_keybuf keybuf;
    struct odputil_keybuf actbuf;
    struct ofpbuf key, mask, act;
    int err;

    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);
    err = netdev_ports_flow_get(dpif_type_str, &match, &actions, get->ufid,
                                &stats, &attrs, &buf);
    if (err) {
        return err;
    }

    VLOG_DBG("found flow from netdev, translating to dpif flow");

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    ofpbuf_use_stack(&act, &actbuf, sizeof actbuf);
    ofpbuf_use_stack(&mask, &maskbuf, sizeof maskbuf);
    dpif_netlink_netdev_match_to_dpif_flow(&match, &key, &mask, actions,
                                           &stats, &attrs,
                                           (ovs_u128 *) get->ufid,
                                           dpif_flow,
                                           false);
    ofpbuf_put(get->buffer, nl_attr_get(actions), nl_attr_get_size(actions));
    dpif_flow->actions = ofpbuf_at(get->buffer, 0, 0);
    dpif_flow->actions_len = nl_attr_get_size(actions);

    return 0;
}

static int
parse_flow_put(struct dpif_netlink *dpif, struct dpif_flow_put *put)
{
    const char *dpif_type_str = dpif_normalize_type(dpif_type(&dpif->dpif));
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct match match;
    odp_port_t in_port;
    const struct nlattr *nla;
    size_t left;
    struct netdev *dev;
    struct offload_info info;
    int err;

    info.tc_modify_flow_deleted = false;
    if (put->flags & DPIF_FP_PROBE) {
        return EOPNOTSUPP;
    }

    err = parse_key_and_mask_to_match(put->key, put->key_len, put->mask,
                                      put->mask_len, &match);
    if (err) {
        return err;
    }

    in_port = match.flow.in_port.odp_port;
    dev = netdev_ports_get(in_port, dpif_type_str);
    if (!dev) {
        return EOPNOTSUPP;
    }

    /* Check the output port for a tunnel. */
    NL_ATTR_FOR_EACH(nla, left, put->actions, put->actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            struct netdev *outdev;
            odp_port_t out_port;

            out_port = nl_attr_get_odp_port(nla);
            outdev = netdev_ports_get(out_port, dpif_type_str);
            if (!outdev) {
                err = EOPNOTSUPP;
                goto out;
            }
            netdev_close(outdev);
        }
    }

    info.recirc_id_shared_with_tc = (dpif->user_features
                                     & OVS_DP_F_TC_RECIRC_SHARING);
    err = netdev_flow_put(dev, &match,
                          CONST_CAST(struct nlattr *, put->actions),
                          put->actions_len,
                          CONST_CAST(ovs_u128 *, put->ufid),
                          &info, put->stats);

    if (!err) {
        if (put->flags & DPIF_FP_MODIFY) {
            struct dpif_op *opp;
            struct dpif_op op;

            op.type = DPIF_OP_FLOW_DEL;
            op.flow_del.key = put->key;
            op.flow_del.key_len = put->key_len;
            op.flow_del.ufid = put->ufid;
            op.flow_del.pmd_id = put->pmd_id;
            op.flow_del.stats = NULL;
            op.flow_del.terse = false;

            opp = &op;
            dpif_netlink_operate__(dpif, &opp, 1);
        }

        VLOG_DBG("added flow");
    } else if (err != EEXIST) {
        struct netdev *oor_netdev = NULL;
        enum vlog_level level;
        if (err == ENOSPC && netdev_is_offload_rebalance_policy_enabled()) {
            /*
             * We need to set OOR on the input netdev (i.e, 'dev') for the
             * flow. But if the flow has a tunnel attribute (i.e, decap action,
             * with a virtual device like a VxLAN interface as its in-port),
             * then lookup and set OOR on the underlying tunnel (real) netdev.
             */
            oor_netdev = flow_get_tunnel_netdev(&match.flow.tunnel);
            if (!oor_netdev) {
                /* Not a 'tunnel' flow */
                oor_netdev = dev;
            }
            netdev_set_hw_info(oor_netdev, HW_INFO_TYPE_OOR, true);
        }
        level = (err == ENOSPC || err == EOPNOTSUPP) ? VLL_DBG : VLL_ERR;
        VLOG_RL(&rl, level, "failed to offload flow: %s: %s",
                ovs_strerror(err),
                (oor_netdev ? oor_netdev->name : dev->name));
    }

out:
    if (err && err != EEXIST && (put->flags & DPIF_FP_MODIFY)) {
        /* Modified rule can't be offloaded, try and delete from HW */
        int del_err = 0;

        if (!info.tc_modify_flow_deleted) {
            del_err = netdev_flow_del(dev, put->ufid, put->stats);
        }

        if (!del_err) {
            /* Delete from hw success, so old flow was offloaded.
             * Change flags to create the flow in kernel */
            put->flags &= ~DPIF_FP_MODIFY;
            put->flags |= DPIF_FP_CREATE;
        } else if (del_err != ENOENT) {
            VLOG_ERR_RL(&rl, "failed to delete offloaded flow: %s",
                        ovs_strerror(del_err));
            /* stop proccesing the flow in kernel */
            err = 0;
        }
    }

    netdev_close(dev);

    return err;
}

static int
try_send_to_netdev(struct dpif_netlink *dpif, struct dpif_op *op)
{
    int err = EOPNOTSUPP;

    switch (op->type) {
    case DPIF_OP_FLOW_PUT: {
        struct dpif_flow_put *put = &op->flow_put;

        if (!put->ufid) {
            break;
        }

        err = parse_flow_put(dpif, put);
        log_flow_put_message(&dpif->dpif, &this_module, put, 0);
        break;
    }
    case DPIF_OP_FLOW_DEL: {
        struct dpif_flow_del *del = &op->flow_del;

        if (!del->ufid) {
            break;
        }

        err = netdev_ports_flow_del(
                                dpif_normalize_type(dpif_type(&dpif->dpif)),
                                del->ufid,
                                del->stats);
        log_flow_del_message(&dpif->dpif, &this_module, del, 0);
        break;
    }
    case DPIF_OP_FLOW_GET: {
        struct dpif_flow_get *get = &op->flow_get;

        if (!op->flow_get.ufid) {
            break;
        }

        err = parse_flow_get(dpif, get);
        log_flow_get_message(&dpif->dpif, &this_module, get, 0);
        break;
    }
    case DPIF_OP_EXECUTE:
    default:
        break;
    }

    return err;
}

static void
dpif_netlink_operate_chunks(struct dpif_netlink *dpif, struct dpif_op **ops,
                            size_t n_ops)
{
    while (n_ops > 0) {
        size_t chunk = dpif_netlink_operate__(dpif, ops, n_ops);

        ops += chunk;
        n_ops -= chunk;
    }
}

static void
dpif_netlink_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops,
                     enum dpif_offload_type offload_type)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_op *new_ops[OPERATE_MAX_OPS];
    int count = 0;
    int i = 0;
    int err = 0;

    if (offload_type == DPIF_OFFLOAD_ALWAYS && !netdev_is_flow_api_enabled()) {
        VLOG_DBG("Invalid offload_type: %d", offload_type);
        return;
    }

    if (offload_type != DPIF_OFFLOAD_NEVER && netdev_is_flow_api_enabled()) {
        while (n_ops > 0) {
            count = 0;

            while (n_ops > 0 && count < OPERATE_MAX_OPS) {
                struct dpif_op *op = ops[i++];

                err = try_send_to_netdev(dpif, op);
                if (err && err != EEXIST) {
                    if (offload_type == DPIF_OFFLOAD_ALWAYS) {
                        /* We got an error while offloading an op. Since
                         * OFFLOAD_ALWAYS is specified, we stop further
                         * processing and return to the caller without
                         * invoking kernel datapath as fallback. But the
                         * interface requires us to process all n_ops; so
                         * return the same error in the remaining ops too.
                         */
                        op->error = err;
                        n_ops--;
                        while (n_ops > 0) {
                            op = ops[i++];
                            op->error = err;
                            n_ops--;
                        }
                        return;
                    }
                    new_ops[count++] = op;
                } else {
                    op->error = err;
                }

                n_ops--;
            }

            dpif_netlink_operate_chunks(dpif, new_ops, count);
        }
    } else if (offload_type != DPIF_OFFLOAD_ALWAYS) {
        dpif_netlink_operate_chunks(dpif, ops, n_ops);
    }
}

#if _WIN32
static void
dpif_netlink_handler_uninit(struct dpif_handler *handler)
{
    vport_delete_sock_pool(handler);
}

static int
dpif_netlink_handler_init(struct dpif_handler *handler)
{
    return vport_create_sock_pool(handler);
}
#else

static int
dpif_netlink_handler_init(struct dpif_handler *handler)
{
    handler->epoll_fd = epoll_create(10);
    return handler->epoll_fd < 0 ? errno : 0;
}

static void
dpif_netlink_handler_uninit(struct dpif_handler *handler)
{
    close(handler->epoll_fd);
}
#endif

/* Returns true if num is a prime number,
 * otherwise, return false.
 */
static bool
is_prime(uint32_t num)
{
    if (num == 2) {
        return true;
    }

    if (num < 2) {
        return false;
    }

    if (num % 2 == 0) {
        return false;
    }

    for (uint64_t i = 3; i * i <= num; i += 2) {
        if (num % i == 0) {
            return false;
        }
    }

    return true;
}

/* Returns start if start is a prime number.  Otherwise returns the next
 * prime greater than start.  Search is limited by UINT32_MAX.
 *
 * Returns 0 if no prime has been found between start and UINT32_MAX.
 */
static uint32_t
next_prime(uint32_t start)
{
    if (start <= 2) {
        return 2;
    }

    for (uint32_t i = start; i < UINT32_MAX; i++) {
        if (is_prime(i)) {
            return i;
        }
    }

    return 0;
}

/* Calculates and returns the number of handler threads needed based
 * the following formula:
 *
 * handlers_n = min(next_prime(active_cores + 1), total_cores)
 */
static uint32_t
dpif_netlink_calculate_n_handlers(void)
{
    uint32_t total_cores = count_total_cores();
    uint32_t n_handlers = count_cpu_cores();
    uint32_t next_prime_num;

    /* If not all cores are available to OVS, create additional handler
     * threads to ensure more fair distribution of load between them.
     */
    if (n_handlers < total_cores && total_cores > 2) {
        next_prime_num = next_prime(n_handlers + 1);
        n_handlers = MIN(next_prime_num, total_cores);
    }

    return MAX(n_handlers, 1);
}

static int
dpif_netlink_refresh_handlers_cpu_dispatch(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    int handler_id;
    int error = 0;
    uint32_t n_handlers;
    uint32_t *upcall_pids;

    n_handlers = dpif_netlink_calculate_n_handlers();
    if (dpif->n_handlers != n_handlers) {
        VLOG_DBG("Dispatch mode(per-cpu): initializing %d handlers",
                   n_handlers);
        destroy_all_handlers(dpif);
        upcall_pids = xzalloc(n_handlers * sizeof *upcall_pids);
        dpif->handlers = xzalloc(n_handlers * sizeof *dpif->handlers);
        for (handler_id = 0; handler_id < n_handlers; handler_id++) {
            struct dpif_handler *handler = &dpif->handlers[handler_id];
            error = create_nl_sock(dpif, &handler->sock);
            if (error) {
                VLOG_ERR("Dispatch mode(per-cpu): Cannot create socket for"
                         "handler %d", handler_id);
                continue;
            }
            upcall_pids[handler_id] = nl_sock_pid(handler->sock);
            VLOG_DBG("Dispatch mode(per-cpu): "
                      "handler %d has Netlink PID of %u",
                      handler_id, upcall_pids[handler_id]);
        }

        dpif->n_handlers = n_handlers;
        error = dpif_netlink_set_handler_pids(&dpif->dpif, upcall_pids,
                                              n_handlers);
        free(upcall_pids);
    }
    return error;
}

/* Synchronizes 'channels' in 'dpif->handlers'  with the set of vports
 * currently in 'dpif' in the kernel, by adding a new set of channels for
 * any kernel vport that lacks one and deleting any channels that have no
 * backing kernel vports. */
static int
dpif_netlink_refresh_handlers_vport_dispatch(struct dpif_netlink *dpif,
                                             uint32_t n_handlers)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    unsigned long int *keep_channels;
    struct dpif_netlink_vport vport;
    size_t keep_channels_nbits;
    struct nl_dump dump;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf buf;
    int retval = 0;
    size_t i;

    ovs_assert(!WINDOWS || n_handlers <= 1);
    ovs_assert(!WINDOWS || dpif->n_handlers <= 1);

    if (dpif->n_handlers != n_handlers) {
        destroy_all_channels(dpif);
        dpif->handlers = xzalloc(n_handlers * sizeof *dpif->handlers);
        for (i = 0; i < n_handlers; i++) {
            int error;
            struct dpif_handler *handler = &dpif->handlers[i];

            error = dpif_netlink_handler_init(handler);
            if (error) {
                size_t j;

                for (j = 0; j < i; j++) {
                    struct dpif_handler *tmp = &dpif->handlers[j];
                    dpif_netlink_handler_uninit(tmp);
                }
                free(dpif->handlers);
                dpif->handlers = NULL;

                return error;
            }
        }
        dpif->n_handlers = n_handlers;
    }

    for (i = 0; i < n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

        handler->event_offset = handler->n_events = 0;
    }

    keep_channels_nbits = dpif->uc_array_size;
    keep_channels = bitmap_allocate(keep_channels_nbits);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    dpif_netlink_port_dump_start__(dpif, &dump);
    while (!dpif_netlink_port_dump_next__(dpif, &dump, &vport, &buf)) {
        uint32_t port_no = odp_to_u32(vport.port_no);
        uint32_t upcall_pid;
        int error;

        if (port_no >= dpif->uc_array_size
            || !vport_get_pid(dpif, port_no, &upcall_pid)) {
            struct nl_sock *sock;
            error = create_nl_sock(dpif, &sock);

            if (error) {
                goto error;
            }

            error = vport_add_channel(dpif, vport.port_no, sock);
            if (error) {
                VLOG_INFO("%s: could not add channels for port %s",
                          dpif_name(&dpif->dpif), vport.name);
                nl_sock_destroy(sock);
                retval = error;
                goto error;
            }
            upcall_pid = nl_sock_pid(sock);
        }

        /* Configure the vport to deliver misses to 'sock'. */
        if (vport.upcall_pids[0] == 0
            || vport.n_upcall_pids != 1
            || upcall_pid != vport.upcall_pids[0]) {
            struct dpif_netlink_vport vport_request;

            dpif_netlink_vport_init(&vport_request);
            vport_request.cmd = OVS_VPORT_CMD_SET;
            vport_request.dp_ifindex = dpif->dp_ifindex;
            vport_request.port_no = vport.port_no;
            vport_request.n_upcall_pids = 1;
            vport_request.upcall_pids = &upcall_pid;
            error = dpif_netlink_vport_transact(&vport_request, NULL, NULL);
            if (error) {
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

        if (port_no < keep_channels_nbits) {
            bitmap_set1(keep_channels, port_no);
        }
        continue;

    error:
        vport_del_channels(dpif, vport.port_no);
    }
    nl_dump_done(&dump);
    ofpbuf_uninit(&buf);

    /* Discard any saved channels that we didn't reuse. */
    for (i = 0; i < keep_channels_nbits; i++) {
        if (!bitmap_is_set(keep_channels, i)) {
            vport_del_channels(dpif, u32_to_odp(i));
        }
    }
    free(keep_channels);

    return retval;
}

static int
dpif_netlink_recv_set_vport_dispatch(struct dpif_netlink *dpif, bool enable)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if ((dpif->handlers != NULL) == enable) {
        return 0;
    } else if (!enable) {
        destroy_all_channels(dpif);
        return 0;
    } else {
        return dpif_netlink_refresh_handlers_vport_dispatch(dpif, 1);
    }
}

static int
dpif_netlink_recv_set_cpu_dispatch(struct dpif_netlink *dpif, bool enable)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if ((dpif->handlers != NULL) == enable) {
        return 0;
    } else if (!enable) {
        destroy_all_handlers(dpif);
        return 0;
    } else {
        return dpif_netlink_refresh_handlers_cpu_dispatch(dpif);
    }
}

static int
dpif_netlink_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        error = dpif_netlink_recv_set_cpu_dispatch(dpif, enable);
    } else {
        error = dpif_netlink_recv_set_vport_dispatch(dpif, enable);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error = 0;

#ifdef _WIN32
    /* Multiple upcall handlers will be supported once kernel datapath supports
     * it. */
    if (n_handlers > 1) {
        return error;
    }
#endif

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (dpif->handlers) {
        if (dpif_netlink_upcall_per_cpu(dpif)) {
            error = dpif_netlink_refresh_handlers_cpu_dispatch(dpif);
        } else {
            error = dpif_netlink_refresh_handlers_vport_dispatch(dpif,
                                                                 n_handlers);
        }
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static bool
dpif_netlink_number_handlers_required(struct dpif *dpif_, uint32_t *n_handlers)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    if (dpif_netlink_upcall_per_cpu(dpif)) {
        *n_handlers = dpif_netlink_calculate_n_handlers();
        return true;
    }

    return false;
}

static int
dpif_netlink_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
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
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = true },
        [OVS_PACKET_ATTR_HASH] = { .type = NL_A_U64, .optional = true }
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_packet_family
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    int type = (genl->cmd == OVS_PACKET_CMD_MISS ? DPIF_UC_MISS
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
    odp_flow_key_hash(upcall->key, upcall->key_len, &upcall->ufid);
    upcall->userdata = a[OVS_PACKET_ATTR_USERDATA];
    upcall->out_tun_key = a[OVS_PACKET_ATTR_EGRESS_TUN_KEY];
    upcall->actions = a[OVS_PACKET_ATTR_ACTIONS];
    upcall->mru = a[OVS_PACKET_ATTR_MRU];
    upcall->hash = a[OVS_PACKET_ATTR_HASH];

    /* Allow overwriting the netlink attribute header without reallocating. */
    dp_packet_use_stub(&upcall->packet,
                    CONST_CAST(struct nlattr *,
                               nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                    nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                    sizeof(struct nlattr));
    dp_packet_set_data(&upcall->packet,
                    (char *)dp_packet_data(&upcall->packet) + sizeof(struct nlattr));
    dp_packet_set_size(&upcall->packet, nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]));

    if (nl_attr_find__(upcall->key, upcall->key_len, OVS_KEY_ATTR_ETHERNET)) {
        /* Ethernet frame */
        upcall->packet.packet_type = htonl(PT_ETH);
    } else {
        /* Non-Ethernet packet. Get the Ethertype from the NL attributes */
        ovs_be16 ethertype = 0;
        const struct nlattr *et_nla = nl_attr_find__(upcall->key,
                                                     upcall->key_len,
                                                     OVS_KEY_ATTR_ETHERTYPE);
        if (et_nla) {
            ethertype = nl_attr_get_be16(et_nla);
        }
        upcall->packet.packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                                    ntohs(ethertype));
        dp_packet_set_l3(&upcall->packet, dp_packet_data(&upcall->packet));
    }

    *dp_ifindex = ovs_header->dp_ifindex;

    return 0;
}

#ifdef _WIN32
#define PACKET_RECV_BATCH_SIZE 50
static int
dpif_netlink_recv_windows(struct dpif_netlink *dpif, uint32_t handler_id,
                          struct dpif_upcall *upcall, struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;
    struct dpif_windows_vport_sock *sock_pool;
    uint32_t i;

    if (!dpif->handlers) {
        return EAGAIN;
    }

    /* Only one handler is supported currently. */
    if (handler_id >= 1) {
        return EAGAIN;
    }

    if (handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];
    sock_pool = handler->vport_sock_pool;

    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > PACKET_RECV_BATCH_SIZE) {
                return EAGAIN;
            }

            error = nl_sock_recv(sock_pool[i].nl_sock, buf, NULL, false);
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                /* XXX: report_loss(dpif, ch, idx, handler_id); */
                continue;
            }

            /* XXX: ch->last_poll = time_msec(); */
            if (error) {
                if (error == EAGAIN) {
                    break;
                }
                return error;
            }

            error = parse_odp_packet(buf, upcall, &dp_ifindex);
            if (!error && dp_ifindex == dpif->dp_ifindex) {
                upcall->pid = 0;
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}
#else
static int
dpif_netlink_recv_cpu_dispatch(struct dpif_netlink *dpif, uint32_t handler_id,
                               struct dpif_upcall *upcall, struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;

    if (!dpif->handlers || handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];

    for (;;) {
        int dp_ifindex;
        int error;

        if (++read_tries > 50) {
            return EAGAIN;
        }
        error = nl_sock_recv(handler->sock, buf, NULL, false);
        if (error == ENOBUFS) {
            /* ENOBUFS typically means that we've received so many
             * packets that the buffer overflowed.  Try again
             * immediately because there's almost certainly a packet
             * waiting for us. */
            report_loss(dpif, NULL, 0, handler_id);
            continue;
        }

        if (error) {
            if (error == EAGAIN) {
                break;
            }
            return error;
        }

        error = parse_odp_packet(buf, upcall, &dp_ifindex);
        if (!error && dp_ifindex == dpif->dp_ifindex) {
            upcall->pid = nl_sock_pid(handler->sock);
            return 0;
        } else if (error) {
            return error;
        }
    }

    return EAGAIN;
}

static int
dpif_netlink_recv_vport_dispatch(struct dpif_netlink *dpif,
                                 uint32_t handler_id,
                                 struct dpif_upcall *upcall,
                                 struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;

    if (!dpif->handlers || handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];
    if (handler->event_offset >= handler->n_events) {
        int retval;

        handler->event_offset = handler->n_events = 0;

        do {
            retval = epoll_wait(handler->epoll_fd, handler->epoll_events,
                                dpif->uc_array_size, 0);
        } while (retval < 0 && errno == EINTR);

        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "epoll_wait failed (%s)", ovs_strerror(errno));
        } else if (retval > 0) {
            handler->n_events = retval;
        }
    }

    while (handler->event_offset < handler->n_events) {
        int idx = handler->epoll_events[handler->event_offset].data.u32;
        struct dpif_channel *ch = &dpif->channels[idx];

        handler->event_offset++;

        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > 50) {
                return EAGAIN;
            }

            error = nl_sock_recv(ch->sock, buf, NULL, false);
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                report_loss(dpif, ch, idx, handler_id);
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
                upcall->pid = nl_sock_pid(ch->sock);
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}
#endif

static int
dpif_netlink_recv(struct dpif *dpif_, uint32_t handler_id,
                  struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_rdlock(&dpif->upcall_lock);
#ifdef _WIN32
    error = dpif_netlink_recv_windows(dpif, handler_id, upcall, buf);
#else
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        error = dpif_netlink_recv_cpu_dispatch(dpif, handler_id, upcall, buf);
    } else {
        error = dpif_netlink_recv_vport_dispatch(dpif,
                                                 handler_id, upcall, buf);
    }
#endif
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

#ifdef _WIN32
static void
dpif_netlink_recv_wait_windows(struct dpif_netlink *dpif, uint32_t handler_id)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    uint32_t i;
    struct dpif_windows_vport_sock *sock_pool =
        dpif->handlers[handler_id].vport_sock_pool;

    /* Only one handler is supported currently. */
    if (handler_id >= 1) {
        return;
    }

    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        nl_sock_wait(sock_pool[i].nl_sock, POLLIN);
    }
}
#else

static void
dpif_netlink_recv_wait_vport_dispatch(struct dpif_netlink *dpif,
                                      uint32_t handler_id)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    if (dpif->handlers && handler_id < dpif->n_handlers) {
        struct dpif_handler *handler = &dpif->handlers[handler_id];

        poll_fd_wait(handler->epoll_fd, POLLIN);
    }
}

static void
dpif_netlink_recv_wait_cpu_dispatch(struct dpif_netlink *dpif,
                                    uint32_t handler_id)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    if (dpif->handlers && handler_id < dpif->n_handlers) {
        struct dpif_handler *handler = &dpif->handlers[handler_id];

        poll_fd_wait(nl_sock_fd(handler->sock), POLLIN);
    }
}
#endif

static void
dpif_netlink_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    fat_rwlock_rdlock(&dpif->upcall_lock);
#ifdef _WIN32
    dpif_netlink_recv_wait_windows(dpif, handler_id);
#else
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        dpif_netlink_recv_wait_cpu_dispatch(dpif, handler_id);
    } else {
        dpif_netlink_recv_wait_vport_dispatch(dpif, handler_id);
    }
#endif
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static void
dpif_netlink_recv_purge_vport_dispatch(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    if (dpif->handlers) {
        size_t i;

        if (!dpif->channels[0].sock) {
            return;
        }
        for (i = 0; i < dpif->uc_array_size; i++ ) {

            nl_sock_drain(dpif->channels[i].sock);
        }
    }
}

static void
dpif_netlink_recv_purge_cpu_dispatch(struct dpif_netlink *dpif)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    int handler_id;

    if (dpif->handlers) {
        for (handler_id = 0; handler_id < dpif->n_handlers; handler_id++) {
            struct dpif_handler *handler = &dpif->handlers[handler_id];
            nl_sock_drain(handler->sock);
        }
    }
}

static void
dpif_netlink_recv_purge(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    fat_rwlock_wrlock(&dpif->upcall_lock);
    if (dpif_netlink_upcall_per_cpu(dpif)) {
        dpif_netlink_recv_purge_cpu_dispatch(dpif);
    } else {
        dpif_netlink_recv_purge_vport_dispatch(dpif);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static char *
dpif_netlink_get_datapath_version(void)
{
    char *version_str = NULL;

#ifdef __linux__

#define MAX_VERSION_STR_SIZE 80
#define LINUX_DATAPATH_VERSION_FILE  "/sys/module/openvswitch/version"
    FILE *f;

    f = fopen(LINUX_DATAPATH_VERSION_FILE, "r");
    if (f) {
        char *newline;
        char version[MAX_VERSION_STR_SIZE];

        if (fgets(version, MAX_VERSION_STR_SIZE, f)) {
            newline = strchr(version, '\n');
            if (newline) {
                *newline = '\0';
            }
            version_str = xstrdup(version);
        }
        fclose(f);
    }
#endif

    return version_str;
}

struct dpif_netlink_ct_dump_state {
    struct ct_dpif_dump_state up;
    struct nl_ct_dump_state *nl_ct_dump;
};

static int
dpif_netlink_ct_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ct_dpif_dump_state **dump_,
                           const uint16_t *zone, int *ptot_bkts)
{
    struct dpif_netlink_ct_dump_state *dump;
    int err;

    dump = xzalloc(sizeof *dump);
    err = nl_ct_dump_start(&dump->nl_ct_dump, zone, ptot_bkts);
    if (err) {
        free(dump);
        return err;
    }

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netlink_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                          struct ct_dpif_dump_state *dump_,
                          struct ct_dpif_entry *entry)
{
    struct dpif_netlink_ct_dump_state *dump;

    INIT_CONTAINER(dump, dump_, up);

    return nl_ct_dump_next(dump->nl_ct_dump, entry);
}

static int
dpif_netlink_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                          struct ct_dpif_dump_state *dump_)
{
    struct dpif_netlink_ct_dump_state *dump;

    INIT_CONTAINER(dump, dump_, up);

    int err = nl_ct_dump_done(dump->nl_ct_dump);
    free(dump);
    return err;
}

static int
dpif_netlink_ct_flush(struct dpif *dpif OVS_UNUSED, const uint16_t *zone,
                      const struct ct_dpif_tuple *tuple)
{
    if (tuple) {
        return nl_ct_flush_tuple(tuple, zone ? *zone : 0);
    } else if (zone) {
        return nl_ct_flush_zone(*zone);
    } else {
        return nl_ct_flush();
    }
}

static int
dpif_netlink_ct_set_limits(struct dpif *dpif OVS_UNUSED,
                           const struct ovs_list *zone_limits)
{
    if (ovs_ct_limit_family < 0) {
        return EOPNOTSUPP;
    }

    struct ofpbuf *request = ofpbuf_new(NL_DUMP_BUFSIZE);
    nl_msg_put_genlmsghdr(request, 0, ovs_ct_limit_family,
                          NLM_F_REQUEST | NLM_F_ECHO, OVS_CT_LIMIT_CMD_SET,
                          OVS_CT_LIMIT_VERSION);

    struct ovs_header *ovs_header;
    ovs_header = ofpbuf_put_uninit(request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    size_t opt_offset;
    opt_offset = nl_msg_start_nested(request, OVS_CT_LIMIT_ATTR_ZONE_LIMIT);

    if (!ovs_list_is_empty(zone_limits)) {
        struct ct_dpif_zone_limit *zone_limit;

        LIST_FOR_EACH (zone_limit, node, zone_limits) {
            struct ovs_zone_limit req_zone_limit = {
                .zone_id = zone_limit->zone,
                .limit   = zone_limit->limit,
            };
            nl_msg_put(request, &req_zone_limit, sizeof req_zone_limit);
        }
    }
    nl_msg_end_nested(request, opt_offset);

    int err = nl_transact(NETLINK_GENERIC, request, NULL);
    ofpbuf_delete(request);
    return err;
}

static int
dpif_netlink_zone_limits_from_ofpbuf(const struct ofpbuf *buf,
                                     struct ovs_list *zone_limits)
{
    static const struct nl_policy ovs_ct_limit_policy[] = {
        [OVS_CT_LIMIT_ATTR_ZONE_LIMIT] = { .type = NL_A_NESTED,
                                           .optional = true },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *attr[ARRAY_SIZE(ovs_ct_limit_policy)];

    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_ct_limit_family
        || !nl_policy_parse(&b, 0, ovs_ct_limit_policy, attr,
                            ARRAY_SIZE(ovs_ct_limit_policy))) {
        return EINVAL;
    }


    if (!attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]) {
        return EINVAL;
    }

    int rem = NLA_ALIGN(
                nl_attr_get_size(attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]));
    const struct ovs_zone_limit *zone_limit =
                nl_attr_get(attr[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]);

    while (rem >= sizeof *zone_limit) {
        if (zone_limit->zone_id >= OVS_ZONE_LIMIT_DEFAULT_ZONE &&
            zone_limit->zone_id <= UINT16_MAX) {
            ct_dpif_push_zone_limit(zone_limits, zone_limit->zone_id,
                                    zone_limit->limit, zone_limit->count);
        }
        rem -= NLA_ALIGN(sizeof *zone_limit);
        zone_limit = ALIGNED_CAST(struct ovs_zone_limit *,
            (unsigned char *) zone_limit  + NLA_ALIGN(sizeof *zone_limit));
    }
    return 0;
}

static int
dpif_netlink_ct_get_limits(struct dpif *dpif OVS_UNUSED,
                           const struct ovs_list *zone_limits_request,
                           struct ovs_list *zone_limits_reply)
{
    if (ovs_ct_limit_family < 0) {
        return EOPNOTSUPP;
    }

    struct ofpbuf *request = ofpbuf_new(NL_DUMP_BUFSIZE);
    nl_msg_put_genlmsghdr(request, 0, ovs_ct_limit_family,
            NLM_F_REQUEST | NLM_F_ECHO, OVS_CT_LIMIT_CMD_GET,
            OVS_CT_LIMIT_VERSION);

    struct ovs_header *ovs_header;
    ovs_header = ofpbuf_put_uninit(request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    if (!ovs_list_is_empty(zone_limits_request)) {
        size_t opt_offset = nl_msg_start_nested(request,
                                                OVS_CT_LIMIT_ATTR_ZONE_LIMIT);

        struct ct_dpif_zone_limit *zone_limit;
        LIST_FOR_EACH (zone_limit, node, zone_limits_request) {
            struct ovs_zone_limit req_zone_limit = {
                .zone_id = zone_limit->zone,
            };
            nl_msg_put(request, &req_zone_limit, sizeof req_zone_limit);
        }

        nl_msg_end_nested(request, opt_offset);
    }

    struct ofpbuf *reply;
    int err = nl_transact(NETLINK_GENERIC, request, &reply);
    if (err) {
        goto out;
    }

    err = dpif_netlink_zone_limits_from_ofpbuf(reply, zone_limits_reply);

out:
    ofpbuf_delete(request);
    ofpbuf_delete(reply);
    return err;
}

static int
dpif_netlink_ct_del_limits(struct dpif *dpif OVS_UNUSED,
                           const struct ovs_list *zone_limits)
{
    if (ovs_ct_limit_family < 0) {
        return EOPNOTSUPP;
    }

    struct ofpbuf *request = ofpbuf_new(NL_DUMP_BUFSIZE);
    nl_msg_put_genlmsghdr(request, 0, ovs_ct_limit_family,
            NLM_F_REQUEST | NLM_F_ECHO, OVS_CT_LIMIT_CMD_DEL,
            OVS_CT_LIMIT_VERSION);

    struct ovs_header *ovs_header;
    ovs_header = ofpbuf_put_uninit(request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    if (!ovs_list_is_empty(zone_limits)) {
        size_t opt_offset =
            nl_msg_start_nested(request, OVS_CT_LIMIT_ATTR_ZONE_LIMIT);

        struct ct_dpif_zone_limit *zone_limit;
        LIST_FOR_EACH (zone_limit, node, zone_limits) {
            struct ovs_zone_limit req_zone_limit = {
                .zone_id = zone_limit->zone,
            };
            nl_msg_put(request, &req_zone_limit, sizeof req_zone_limit);
        }
        nl_msg_end_nested(request, opt_offset);
    }

    int err = nl_transact(NETLINK_GENERIC, request, NULL);

    ofpbuf_delete(request);
    return err;
}

#define NL_TP_NAME_PREFIX "ovs_tp_"

struct dpif_netlink_timeout_policy_protocol {
    uint16_t    l3num;
    uint8_t     l4num;
};

enum OVS_PACKED_ENUM dpif_netlink_support_timeout_policy_protocol {
    DPIF_NL_TP_AF_INET_TCP,
    DPIF_NL_TP_AF_INET_UDP,
    DPIF_NL_TP_AF_INET_ICMP,
    DPIF_NL_TP_AF_INET6_TCP,
    DPIF_NL_TP_AF_INET6_UDP,
    DPIF_NL_TP_AF_INET6_ICMPV6,
    DPIF_NL_TP_MAX
};

#define DPIF_NL_ALL_TP ((1UL << DPIF_NL_TP_MAX) - 1)


static struct dpif_netlink_timeout_policy_protocol tp_protos[] = {
    [DPIF_NL_TP_AF_INET_TCP] = { .l3num = AF_INET, .l4num = IPPROTO_TCP },
    [DPIF_NL_TP_AF_INET_UDP] = { .l3num = AF_INET, .l4num = IPPROTO_UDP },
    [DPIF_NL_TP_AF_INET_ICMP] = { .l3num = AF_INET, .l4num = IPPROTO_ICMP },
    [DPIF_NL_TP_AF_INET6_TCP] = { .l3num = AF_INET6, .l4num = IPPROTO_TCP },
    [DPIF_NL_TP_AF_INET6_UDP] = { .l3num = AF_INET6, .l4num = IPPROTO_UDP },
    [DPIF_NL_TP_AF_INET6_ICMPV6] = { .l3num = AF_INET6,
                                     .l4num = IPPROTO_ICMPV6 },
};

static void
dpif_netlink_format_tp_name(uint32_t id, uint16_t l3num, uint8_t l4num,
                            char **tp_name)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s%"PRIu32"_", NL_TP_NAME_PREFIX, id);
    ct_dpif_format_ipproto(&ds, l4num);

    if (l3num == AF_INET) {
        ds_put_cstr(&ds, "4");
    } else if (l3num == AF_INET6 && l4num != IPPROTO_ICMPV6) {
        ds_put_cstr(&ds, "6");
    }

    ovs_assert(ds.length < CTNL_TIMEOUT_NAME_MAX);

    *tp_name = ds_steal_cstr(&ds);
}

static int
dpif_netlink_ct_get_timeout_policy_name(struct dpif *dpif OVS_UNUSED,
                                        uint32_t tp_id, uint16_t dl_type,
                                        uint8_t nw_proto, char **tp_name,
                                        bool *is_generic)
{
    dpif_netlink_format_tp_name(tp_id,
                                dl_type == ETH_TYPE_IP ? AF_INET : AF_INET6,
                                nw_proto, tp_name);
    *is_generic = false;
    return 0;
}

static int
dpif_netlink_ct_get_features(struct dpif *dpif OVS_UNUSED,
                             enum ct_features *features)
{
    if (features != NULL) {
#ifndef _WIN32
        *features = CONNTRACK_F_ZERO_SNAT;
#else
        *features = 0;
#endif
    }
    return 0;
}

#define CT_DPIF_NL_TP_TCP_MAPPINGS                              \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, SYN_SENT, SYN_SENT)         \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, SYN_RECV, SYN_RECV)         \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, ESTABLISHED, ESTABLISHED)   \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, FIN_WAIT, FIN_WAIT)         \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, CLOSE_WAIT, CLOSE_WAIT)     \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, LAST_ACK, LAST_ACK)         \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, TIME_WAIT, TIME_WAIT)       \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, CLOSE, CLOSE)               \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, SYN_SENT2, SYN_SENT2)       \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, RETRANSMIT, RETRANS)        \
    CT_DPIF_NL_TP_MAPPING(TCP, TCP, UNACK, UNACK)

#define CT_DPIF_NL_TP_UDP_MAPPINGS                              \
    CT_DPIF_NL_TP_MAPPING(UDP, UDP, SINGLE, UNREPLIED)          \
    CT_DPIF_NL_TP_MAPPING(UDP, UDP, MULTIPLE, REPLIED)

#define CT_DPIF_NL_TP_ICMP_MAPPINGS                             \
    CT_DPIF_NL_TP_MAPPING(ICMP, ICMP, FIRST, TIMEOUT)

#define CT_DPIF_NL_TP_ICMPV6_MAPPINGS                           \
    CT_DPIF_NL_TP_MAPPING(ICMP, ICMPV6, FIRST, TIMEOUT)


#define CT_DPIF_NL_TP_MAPPING(PROTO1, PROTO2, ATTR1, ATTR2)     \
if (tp->present & (1 << CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1)) {  \
    nl_tp->present |= 1 << CTA_TIMEOUT_##PROTO2##_##ATTR2;      \
    nl_tp->attrs[CTA_TIMEOUT_##PROTO2##_##ATTR2] =              \
        tp->attrs[CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1];          \
}

static void
dpif_netlink_get_nl_tp_tcp_attrs(const struct ct_dpif_timeout_policy *tp,
                                 struct nl_ct_timeout_policy *nl_tp)
{
    CT_DPIF_NL_TP_TCP_MAPPINGS
}

static void
dpif_netlink_get_nl_tp_udp_attrs(const struct ct_dpif_timeout_policy *tp,
                                 struct nl_ct_timeout_policy *nl_tp)
{
    CT_DPIF_NL_TP_UDP_MAPPINGS
}

static void
dpif_netlink_get_nl_tp_icmp_attrs(const struct ct_dpif_timeout_policy *tp,
                                  struct nl_ct_timeout_policy *nl_tp)
{
    CT_DPIF_NL_TP_ICMP_MAPPINGS
}

static void
dpif_netlink_get_nl_tp_icmpv6_attrs(const struct ct_dpif_timeout_policy *tp,
                                    struct nl_ct_timeout_policy *nl_tp)
{
    CT_DPIF_NL_TP_ICMPV6_MAPPINGS
}

#undef CT_DPIF_NL_TP_MAPPING

static void
dpif_netlink_get_nl_tp_attrs(const struct ct_dpif_timeout_policy *tp,
                             uint8_t l4num, struct nl_ct_timeout_policy *nl_tp)
{
    nl_tp->present = 0;

    if (l4num == IPPROTO_TCP) {
        dpif_netlink_get_nl_tp_tcp_attrs(tp, nl_tp);
    } else if (l4num == IPPROTO_UDP) {
        dpif_netlink_get_nl_tp_udp_attrs(tp, nl_tp);
    } else if (l4num == IPPROTO_ICMP) {
        dpif_netlink_get_nl_tp_icmp_attrs(tp, nl_tp);
    } else if (l4num == IPPROTO_ICMPV6) {
        dpif_netlink_get_nl_tp_icmpv6_attrs(tp, nl_tp);
    }
}

#define CT_DPIF_NL_TP_MAPPING(PROTO1, PROTO2, ATTR1, ATTR2)                 \
if (nl_tp->present & (1 << CTA_TIMEOUT_##PROTO2##_##ATTR2)) {               \
    if (tp->present & (1 << CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1)) {          \
        if (tp->attrs[CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1] !=                \
            nl_tp->attrs[CTA_TIMEOUT_##PROTO2##_##ATTR2]) {                 \
            VLOG_WARN_RL(&error_rl, "Inconsistent timeout policy %s "       \
                         "attribute %s=%"PRIu32" while %s=%"PRIu32,         \
                         nl_tp->name, "CTA_TIMEOUT_"#PROTO2"_"#ATTR2,       \
                         nl_tp->attrs[CTA_TIMEOUT_##PROTO2##_##ATTR2],      \
                         "CT_DPIF_TP_ATTR_"#PROTO1"_"#ATTR1,                \
                         tp->attrs[CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1]);    \
        }                                                                   \
    } else {                                                                \
        tp->present |= 1 << CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1;             \
        tp->attrs[CT_DPIF_TP_ATTR_##PROTO1##_##ATTR1] =                     \
            nl_tp->attrs[CTA_TIMEOUT_##PROTO2##_##ATTR2];                   \
    }                                                                       \
}

static void
dpif_netlink_set_ct_dpif_tp_tcp_attrs(const struct nl_ct_timeout_policy *nl_tp,
                                      struct ct_dpif_timeout_policy *tp)
{
    CT_DPIF_NL_TP_TCP_MAPPINGS
}

static void
dpif_netlink_set_ct_dpif_tp_udp_attrs(const struct nl_ct_timeout_policy *nl_tp,
                                      struct ct_dpif_timeout_policy *tp)
{
    CT_DPIF_NL_TP_UDP_MAPPINGS
}

static void
dpif_netlink_set_ct_dpif_tp_icmp_attrs(
    const struct nl_ct_timeout_policy *nl_tp,
    struct ct_dpif_timeout_policy *tp)
{
    CT_DPIF_NL_TP_ICMP_MAPPINGS
}

static void
dpif_netlink_set_ct_dpif_tp_icmpv6_attrs(
    const struct nl_ct_timeout_policy *nl_tp,
    struct ct_dpif_timeout_policy *tp)
{
    CT_DPIF_NL_TP_ICMPV6_MAPPINGS
}

#undef CT_DPIF_NL_TP_MAPPING

static void
dpif_netlink_set_ct_dpif_tp_attrs(const struct nl_ct_timeout_policy *nl_tp,
                                  struct ct_dpif_timeout_policy *tp)
{
    if (nl_tp->l4num == IPPROTO_TCP) {
        dpif_netlink_set_ct_dpif_tp_tcp_attrs(nl_tp, tp);
    } else if (nl_tp->l4num == IPPROTO_UDP) {
        dpif_netlink_set_ct_dpif_tp_udp_attrs(nl_tp, tp);
    } else if (nl_tp->l4num == IPPROTO_ICMP) {
        dpif_netlink_set_ct_dpif_tp_icmp_attrs(nl_tp, tp);
    } else if (nl_tp->l4num == IPPROTO_ICMPV6) {
        dpif_netlink_set_ct_dpif_tp_icmpv6_attrs(nl_tp, tp);
    }
}

#ifdef _WIN32
static int
dpif_netlink_ct_set_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   const struct ct_dpif_timeout_policy *tp)
{
    return EOPNOTSUPP;
}

static int
dpif_netlink_ct_get_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   uint32_t tp_id,
                                   struct ct_dpif_timeout_policy *tp)
{
    return EOPNOTSUPP;
}

static int
dpif_netlink_ct_del_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   uint32_t tp_id)
{
    return EOPNOTSUPP;
}

static int
dpif_netlink_ct_timeout_policy_dump_start(struct dpif *dpif OVS_UNUSED,
                                          void **statep)
{
    return EOPNOTSUPP;
}

static int
dpif_netlink_ct_timeout_policy_dump_next(struct dpif *dpif OVS_UNUSED,
                                         void *state,
                                         struct ct_dpif_timeout_policy **tp)
{
    return EOPNOTSUPP;
}

static int
dpif_netlink_ct_timeout_policy_dump_done(struct dpif *dpif OVS_UNUSED,
                                         void *state)
{
    return EOPNOTSUPP;
}
#else
static int
dpif_netlink_ct_set_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   const struct ct_dpif_timeout_policy *tp)
{
    int err = 0;

    for (int i = 0; i < ARRAY_SIZE(tp_protos); ++i) {
        struct nl_ct_timeout_policy nl_tp;
        char *nl_tp_name;

        dpif_netlink_format_tp_name(tp->id, tp_protos[i].l3num,
                                    tp_protos[i].l4num, &nl_tp_name);
        ovs_strlcpy(nl_tp.name, nl_tp_name, sizeof nl_tp.name);
        free(nl_tp_name);

        nl_tp.l3num = tp_protos[i].l3num;
        nl_tp.l4num = tp_protos[i].l4num;
        dpif_netlink_get_nl_tp_attrs(tp, tp_protos[i].l4num, &nl_tp);
        err = nl_ct_set_timeout_policy(&nl_tp);
        if (err) {
            VLOG_WARN_RL(&error_rl, "failed to add timeout policy %s (%s)",
                         nl_tp.name, ovs_strerror(err));
            goto out;
        }
    }

out:
    return err;
}

static int
dpif_netlink_ct_get_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   uint32_t tp_id,
                                   struct ct_dpif_timeout_policy *tp)
{
    int err = 0;

    tp->id = tp_id;
    tp->present = 0;
    for (int i = 0; i < ARRAY_SIZE(tp_protos); ++i) {
        struct nl_ct_timeout_policy nl_tp;
        char *nl_tp_name;

        dpif_netlink_format_tp_name(tp_id, tp_protos[i].l3num,
                                    tp_protos[i].l4num, &nl_tp_name);
        err = nl_ct_get_timeout_policy(nl_tp_name, &nl_tp);

        if (err) {
            VLOG_WARN_RL(&error_rl, "failed to get timeout policy %s (%s)",
                         nl_tp_name, ovs_strerror(err));
            free(nl_tp_name);
            goto out;
        }
        free(nl_tp_name);
        dpif_netlink_set_ct_dpif_tp_attrs(&nl_tp, tp);
    }

out:
    return err;
}

/* Returns 0 if all the sub timeout policies are deleted or not exist in the
 * kernel.  Returns 1 if any sub timeout policy deletion failed. */
static int
dpif_netlink_ct_del_timeout_policy(struct dpif *dpif OVS_UNUSED,
                                   uint32_t tp_id)
{
    int ret = 0;

    for (int i = 0; i < ARRAY_SIZE(tp_protos); ++i) {
        char *nl_tp_name;
        dpif_netlink_format_tp_name(tp_id, tp_protos[i].l3num,
                                    tp_protos[i].l4num, &nl_tp_name);
        int err = nl_ct_del_timeout_policy(nl_tp_name);
        if (err == ENOENT) {
            err = 0;
        }
        if (err) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(6, 6);
            VLOG_INFO_RL(&rl, "failed to delete timeout policy %s (%s)",
                         nl_tp_name, ovs_strerror(err));
            ret = 1;
        }
        free(nl_tp_name);
    }

    return ret;
}

struct dpif_netlink_ct_timeout_policy_dump_state {
    struct nl_ct_timeout_policy_dump_state *nl_dump_state;
    struct hmap tp_dump_map;
};

struct dpif_netlink_tp_dump_node {
    struct      hmap_node hmap_node;      /* node in tp_dump_map. */
    struct      ct_dpif_timeout_policy *tp;
    uint32_t    l3_l4_present;
};

static struct dpif_netlink_tp_dump_node *
get_dpif_netlink_tp_dump_node_by_tp_id(uint32_t tp_id,
                                       struct hmap *tp_dump_map)
{
    struct dpif_netlink_tp_dump_node *tp_dump_node;

    HMAP_FOR_EACH_WITH_HASH (tp_dump_node, hmap_node, hash_int(tp_id, 0),
                             tp_dump_map) {
        if (tp_dump_node->tp->id == tp_id) {
            return tp_dump_node;
        }
    }
    return NULL;
}

static void
update_dpif_netlink_tp_dump_node(
    const struct nl_ct_timeout_policy *nl_tp,
    struct dpif_netlink_tp_dump_node *tp_dump_node)
{
    dpif_netlink_set_ct_dpif_tp_attrs(nl_tp, tp_dump_node->tp);
    for (int i = 0; i < DPIF_NL_TP_MAX; ++i) {
        if (nl_tp->l3num == tp_protos[i].l3num &&
            nl_tp->l4num == tp_protos[i].l4num) {
            tp_dump_node->l3_l4_present |= 1 << i;
            break;
        }
    }
}

static int
dpif_netlink_ct_timeout_policy_dump_start(struct dpif *dpif OVS_UNUSED,
                                          void **statep)
{
    struct dpif_netlink_ct_timeout_policy_dump_state *dump_state;

    *statep = dump_state = xzalloc(sizeof *dump_state);
    int err = nl_ct_timeout_policy_dump_start(&dump_state->nl_dump_state);
    if (err) {
        free(dump_state);
        return err;
    }
    hmap_init(&dump_state->tp_dump_map);
    return 0;
}

static void
get_and_cleanup_tp_dump_node(struct hmap *hmap,
                             struct dpif_netlink_tp_dump_node *tp_dump_node,
                             struct ct_dpif_timeout_policy *tp)
{
    hmap_remove(hmap, &tp_dump_node->hmap_node);
    *tp = *tp_dump_node->tp;
    free(tp_dump_node->tp);
    free(tp_dump_node);
}

static int
dpif_netlink_ct_timeout_policy_dump_next(struct dpif *dpif OVS_UNUSED,
                                         void *state,
                                         struct ct_dpif_timeout_policy *tp)
{
    struct dpif_netlink_ct_timeout_policy_dump_state *dump_state = state;
    struct dpif_netlink_tp_dump_node *tp_dump_node;
    int err;

    /* Dumps all the timeout policies in the kernel. */
    do {
        struct nl_ct_timeout_policy nl_tp;
        uint32_t tp_id;

        err =  nl_ct_timeout_policy_dump_next(dump_state->nl_dump_state,
                                              &nl_tp);
        if (err) {
            break;
        }

        /* We only interest in OVS installed timeout policies. */
        if (!ovs_scan(nl_tp.name, NL_TP_NAME_PREFIX"%"PRIu32, &tp_id)) {
            continue;
        }

        tp_dump_node = get_dpif_netlink_tp_dump_node_by_tp_id(
                            tp_id, &dump_state->tp_dump_map);
        if (!tp_dump_node) {
            tp_dump_node = xzalloc(sizeof *tp_dump_node);
            tp_dump_node->tp = xzalloc(sizeof *tp_dump_node->tp);
            tp_dump_node->tp->id = tp_id;
            hmap_insert(&dump_state->tp_dump_map, &tp_dump_node->hmap_node,
                        hash_int(tp_id, 0));
        }

        update_dpif_netlink_tp_dump_node(&nl_tp, tp_dump_node);

        /* Returns one ct_dpif_timeout_policy if we gather all the L3/L4
         * sub-pieces. */
        if (tp_dump_node->l3_l4_present == DPIF_NL_ALL_TP) {
            get_and_cleanup_tp_dump_node(&dump_state->tp_dump_map,
                                         tp_dump_node, tp);
            break;
        }
    } while (true);

    /* Dump the incomplete timeout policies. */
    if (err == EOF) {
        if (!hmap_is_empty(&dump_state->tp_dump_map)) {
            struct hmap_node *hmap_node = hmap_first(&dump_state->tp_dump_map);
            tp_dump_node = CONTAINER_OF(hmap_node,
                                        struct dpif_netlink_tp_dump_node,
                                        hmap_node);
            get_and_cleanup_tp_dump_node(&dump_state->tp_dump_map,
                                         tp_dump_node, tp);
            return 0;
        }
    }

    return err;
}

static int
dpif_netlink_ct_timeout_policy_dump_done(struct dpif *dpif OVS_UNUSED,
                                         void *state)
{
    struct dpif_netlink_ct_timeout_policy_dump_state *dump_state = state;
    struct dpif_netlink_tp_dump_node *tp_dump_node;

    int err = nl_ct_timeout_policy_dump_done(dump_state->nl_dump_state);
    HMAP_FOR_EACH_POP (tp_dump_node, hmap_node, &dump_state->tp_dump_map) {
        free(tp_dump_node->tp);
        free(tp_dump_node);
    }
    hmap_destroy(&dump_state->tp_dump_map);
    free(dump_state);
    return err;
}
#endif


/* Meters */

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Meter support was introduced in Linux 4.15.  In some versions of
 * Linux 4.15, 4.16, and 4.17, there was a bug that never set the id
 * when the meter was created, so all meters essentially had an id of
 * zero.  Check for that condition and disable meters on those kernels. */
static bool probe_broken_meters(struct dpif *);

static void
dpif_netlink_meter_init(struct dpif_netlink *dpif, struct ofpbuf *buf,
                        void *stub, size_t size, uint32_t command)
{
    ofpbuf_use_stub(buf, stub, size);

    nl_msg_put_genlmsghdr(buf, 0, ovs_meter_family, NLM_F_REQUEST | NLM_F_ECHO,
                          command, OVS_METER_VERSION);

    struct ovs_header *ovs_header;
    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = dpif->dp_ifindex;
}

/* Execute meter 'request' in the kernel datapath.  If the command
 * fails, returns a positive errno value.  Otherwise, stores the reply
 * in '*replyp', parses the policy according to 'reply_policy' into the
 * array of Netlink attribute in 'a', and returns 0.  On success, the
 * caller is responsible for calling ofpbuf_delete() on '*replyp'
 * ('replyp' will contain pointers into 'a'). */
static int
dpif_netlink_meter_transact(struct ofpbuf *request, struct ofpbuf **replyp,
                            const struct nl_policy *reply_policy,
                            struct nlattr **a, size_t size_a)
{
    int error = nl_transact(NETLINK_GENERIC, request, replyp);
    ofpbuf_uninit(request);

    if (error) {
        return error;
    }

    struct nlmsghdr *nlmsg = ofpbuf_try_pull(*replyp, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(*replyp, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(*replyp,
                                                    sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_meter_family
        || !nl_policy_parse(*replyp, 0, reply_policy, a, size_a)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_DBG_RL(&rl,
                    "Kernel module response to meter tranaction is invalid");
        return EINVAL;
    }
    return 0;
}

static void
dpif_netlink_meter_get_features(const struct dpif *dpif_,
                                struct ofputil_meter_features *features)
{
    if (probe_broken_meters(CONST_CAST(struct dpif *, dpif_))) {
        return;
    }

    struct ofpbuf buf, *msg;
    uint64_t stub[1024 / 8];

    static const struct nl_policy ovs_meter_features_policy[] = {
        [OVS_METER_ATTR_MAX_METERS] = { .type = NL_A_U32 },
        [OVS_METER_ATTR_MAX_BANDS] = { .type = NL_A_U32 },
        [OVS_METER_ATTR_BANDS] = { .type = NL_A_NESTED, .optional = true },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_meter_features_policy)];

    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    dpif_netlink_meter_init(dpif, &buf, stub, sizeof stub,
                            OVS_METER_CMD_FEATURES);
    if (dpif_netlink_meter_transact(&buf, &msg, ovs_meter_features_policy, a,
                                    ARRAY_SIZE(ovs_meter_features_policy))) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_INFO_RL(&rl,
                  "dpif_netlink_meter_transact OVS_METER_CMD_FEATURES failed");
        return;
    }

    features->max_meters = nl_attr_get_u32(a[OVS_METER_ATTR_MAX_METERS]);
    features->max_bands = nl_attr_get_u32(a[OVS_METER_ATTR_MAX_BANDS]);

    /* Bands is a nested attribute of zero or more nested
     * band attributes.  */
    if (a[OVS_METER_ATTR_BANDS]) {
        const struct nlattr *nla;
        size_t left;

        NL_NESTED_FOR_EACH (nla, left, a[OVS_METER_ATTR_BANDS]) {
            const struct nlattr *band_nla;
            size_t band_left;

            NL_NESTED_FOR_EACH (band_nla, band_left, nla) {
                if (nl_attr_type(band_nla) == OVS_BAND_ATTR_TYPE) {
                    if (nl_attr_get_size(band_nla) == sizeof(uint32_t)) {
                        switch (nl_attr_get_u32(band_nla)) {
                        case OVS_METER_BAND_TYPE_DROP:
                            features->band_types |= 1 << OFPMBT13_DROP;
                            break;
                        }
                    }
                }
            }
        }
    }
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;

    ofpbuf_delete(msg);
}

static int
dpif_netlink_meter_set__(struct dpif *dpif_, ofproto_meter_id meter_id,
                         struct ofputil_meter_config *config)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct ofpbuf buf, *msg;
    uint64_t stub[1024 / 8];

    static const struct nl_policy ovs_meter_set_response_policy[] = {
        [OVS_METER_ATTR_ID] = { .type = NL_A_U32 },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_meter_set_response_policy)];

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    for (size_t i = 0; i < config->n_bands; i++) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

    dpif_netlink_meter_init(dpif, &buf, stub, sizeof stub, OVS_METER_CMD_SET);

    nl_msg_put_u32(&buf, OVS_METER_ATTR_ID, meter_id.uint32);

    if (config->flags & OFPMF13_KBPS) {
        nl_msg_put_flag(&buf, OVS_METER_ATTR_KBPS);
    }

    size_t bands_offset = nl_msg_start_nested(&buf, OVS_METER_ATTR_BANDS);
    /* Bands */
    for (size_t i = 0; i < config->n_bands; ++i) {
        struct ofputil_meter_band * band = &config->bands[i];
        uint32_t band_type;

        size_t band_offset = nl_msg_start_nested(&buf, OVS_BAND_ATTR_UNSPEC);

        switch (band->type) {
        case OFPMBT13_DROP:
            band_type = OVS_METER_BAND_TYPE_DROP;
            break;
        default:
            band_type = OVS_METER_BAND_TYPE_UNSPEC;
        }
        nl_msg_put_u32(&buf, OVS_BAND_ATTR_TYPE, band_type);
        nl_msg_put_u32(&buf, OVS_BAND_ATTR_RATE, band->rate);
        nl_msg_put_u32(&buf, OVS_BAND_ATTR_BURST,
                       config->flags & OFPMF13_BURST ?
                       band->burst_size : band->rate);
        nl_msg_end_nested(&buf, band_offset);
    }
    nl_msg_end_nested(&buf, bands_offset);

    int error = dpif_netlink_meter_transact(&buf, &msg,
                                    ovs_meter_set_response_policy, a,
                                    ARRAY_SIZE(ovs_meter_set_response_policy));
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_INFO_RL(&rl,
                     "dpif_netlink_meter_transact OVS_METER_CMD_SET failed");
        return error;
    }

    if (nl_attr_get_u32(a[OVS_METER_ATTR_ID]) != meter_id.uint32) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_INFO_RL(&rl,
                     "Kernel returned a different meter id than requested");
    }
    ofpbuf_delete(msg);
    return 0;
}

static int
dpif_netlink_meter_set(struct dpif *dpif_, ofproto_meter_id meter_id,
                       struct ofputil_meter_config *config)
{
    int err;

    if (probe_broken_meters(dpif_)) {
        return ENOMEM;
    }

    err = dpif_netlink_meter_set__(dpif_, meter_id, config);
    if (!err && netdev_is_flow_api_enabled()) {
        meter_offload_set(meter_id, config);
    }

    return err;
}

/* Retrieve statistics and/or delete meter 'meter_id'.  Statistics are
 * stored in 'stats', if it is not null.  If 'command' is
 * OVS_METER_CMD_DEL, the meter is deleted and statistics are optionally
 * retrieved.  If 'command' is OVS_METER_CMD_GET, then statistics are
 * simply retrieved. */
static int
dpif_netlink_meter_get_stats(const struct dpif *dpif_,
                             ofproto_meter_id meter_id,
                             struct ofputil_meter_stats *stats,
                             uint16_t max_bands,
                             enum ovs_meter_cmd command)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct ofpbuf buf, *msg;
    uint64_t stub[1024 / 8];

    static const struct nl_policy ovs_meter_stats_policy[] = {
        [OVS_METER_ATTR_ID] = { .type = NL_A_U32, .optional = true},
        [OVS_METER_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_flow_stats),
                                   .optional = true},
        [OVS_METER_ATTR_BANDS] = { .type = NL_A_NESTED, .optional = true },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_meter_stats_policy)];

    dpif_netlink_meter_init(dpif, &buf, stub, sizeof stub, command);

    nl_msg_put_u32(&buf, OVS_METER_ATTR_ID, meter_id.uint32);

    int error = dpif_netlink_meter_transact(&buf, &msg,
                                            ovs_meter_stats_policy, a,
                                            ARRAY_SIZE(ovs_meter_stats_policy));
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_INFO_RL(&rl, "dpif_netlink_meter_transact %s failed",
                     command == OVS_METER_CMD_GET ? "get" : "del");
        return error;
    }

    if (stats
        && a[OVS_METER_ATTR_ID]
        && a[OVS_METER_ATTR_STATS]
        && nl_attr_get_u32(a[OVS_METER_ATTR_ID]) == meter_id.uint32) {
        /* return stats */
        const struct ovs_flow_stats *stat;
        const struct nlattr *nla;
        size_t left;

        stat = nl_attr_get(a[OVS_METER_ATTR_STATS]);
        stats->packet_in_count = get_32aligned_u64(&stat->n_packets);
        stats->byte_in_count = get_32aligned_u64(&stat->n_bytes);

        if (a[OVS_METER_ATTR_BANDS]) {
            size_t n_bands = 0;
            NL_NESTED_FOR_EACH (nla, left, a[OVS_METER_ATTR_BANDS]) {
                const struct nlattr *band_nla;
                band_nla = nl_attr_find_nested(nla, OVS_BAND_ATTR_STATS);
                if (band_nla && nl_attr_get_size(band_nla) \
                                == sizeof(struct ovs_flow_stats)) {
                    stat = nl_attr_get(band_nla);

                    if (n_bands < max_bands) {
                        stats->bands[n_bands].packet_count
                            = get_32aligned_u64(&stat->n_packets);
                        stats->bands[n_bands].byte_count
                            = get_32aligned_u64(&stat->n_bytes);
                        ++n_bands;
                    }
                } else {
                    stats->bands[n_bands].packet_count = 0;
                    stats->bands[n_bands].byte_count = 0;
                    ++n_bands;
                }
            }
            stats->n_bands = n_bands;
        } else {
            /* For a non-existent meter, return 0 stats. */
            stats->n_bands = 0;
        }
    }

    ofpbuf_delete(msg);
    return error;
}

static int
dpif_netlink_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats, uint16_t max_bands)
{
    int err;

    err = dpif_netlink_meter_get_stats(dpif, meter_id, stats, max_bands,
                                       OVS_METER_CMD_GET);
    if (!err && netdev_is_flow_api_enabled()) {
        meter_offload_get(meter_id, stats);
    }

    return err;
}

static int
dpif_netlink_meter_del(struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats, uint16_t max_bands)
{
    int err;

    err  = dpif_netlink_meter_get_stats(dpif, meter_id, stats,
                                        max_bands, OVS_METER_CMD_DEL);
    if (!err && netdev_is_flow_api_enabled()) {
        meter_offload_del(meter_id, stats);
    }

    return err;
}

static bool
probe_broken_meters__(struct dpif *dpif)
{
    /* This test is destructive if a probe occurs while ovs-vswitchd is
     * running (e.g., an ovs-dpctl meter command is called), so choose a
     * random high meter id to make this less likely to occur. */
    ofproto_meter_id id1 = { 54545401 };
    ofproto_meter_id id2 = { 54545402 };
    struct ofputil_meter_band band = {OFPMBT13_DROP, 0, 1, 0};
    struct ofputil_meter_config config1 = { 1, OFPMF13_KBPS, 1, &band};
    struct ofputil_meter_config config2 = { 2, OFPMF13_KBPS, 1, &band};

    /* Try adding two meters and make sure that they both come back with
     * the proper meter id.  Use the "__" version so that we don't cause
     * a recurve deadlock. */
    dpif_netlink_meter_set__(dpif, id1, &config1);
    dpif_netlink_meter_set__(dpif, id2, &config2);

    if (dpif_netlink_meter_get(dpif, id1, NULL, 0)
        || dpif_netlink_meter_get(dpif, id2, NULL, 0)) {
        VLOG_INFO("The kernel module has a broken meter implementation.");
        return true;
    }

    dpif_netlink_meter_del(dpif, id1, NULL, 0);
    dpif_netlink_meter_del(dpif, id2, NULL, 0);

    return false;
}

static bool
probe_broken_meters(struct dpif *dpif)
{
    /* This is a once-only test because currently OVS only has at most a single
     * Netlink capable datapath on any given platform. */
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    static bool broken_meters = false;
    if (ovsthread_once_start(&once)) {
        broken_meters = probe_broken_meters__(dpif);
        ovsthread_once_done(&once);
    }
    return broken_meters;
}


static int
dpif_netlink_cache_get_supported_levels(struct dpif *dpif_, uint32_t *levels)
{
    struct dpif_netlink_dp dp;
    struct ofpbuf *buf;
    int error;

    /* If available, in the kernel we support one level of cache.
     * Unfortunately, there is no way to detect if the older kernel module has
     * the cache feature.  For now, we only report the cache information if the
     * kernel module reports the OVS_DP_ATTR_MASKS_CACHE_SIZE attribute. */

    *levels = 0;
    error = dpif_netlink_dp_get(dpif_, &dp, &buf);
    if (!error) {

        if (dp.cache_size != UINT32_MAX) {
            *levels = 1;
        }
        ofpbuf_delete(buf);
    }

    return error;
}

static int
dpif_netlink_cache_get_name(struct dpif *dpif_ OVS_UNUSED, uint32_t level,
                            const char **name)
{
    if (level != 0) {
        return EINVAL;
    }

    *name = "masks-cache";
    return 0;
}

static int
dpif_netlink_cache_get_size(struct dpif *dpif_, uint32_t level, uint32_t *size)
{
    struct dpif_netlink_dp dp;
    struct ofpbuf *buf;
    int error;

    if (level != 0) {
        return EINVAL;
    }

    error = dpif_netlink_dp_get(dpif_, &dp, &buf);
    if (!error) {

        ofpbuf_delete(buf);

        if (dp.cache_size == UINT32_MAX) {
            return EOPNOTSUPP;
        }
        *size = dp.cache_size;
    }
    return error;
}

static int
dpif_netlink_cache_set_size(struct dpif *dpif_, uint32_t level, uint32_t size)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp request, reply;
    struct ofpbuf *bufp;
    int error;

    size = ROUND_UP_POW2(size);

    if (level != 0) {
        return EINVAL;
    }

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_SET;
    request.name = dpif_->base_name;
    request.dp_ifindex = dpif->dp_ifindex;
    request.cache_size = size;
    /* We need to set the dpif user_features, as the kernel module assumes the
     * OVS_DP_ATTR_USER_FEATURES attribute is always present. If not, it will
     * reset all the features. */
    request.user_features = dpif->user_features;

    error = dpif_netlink_dp_transact(&request, &reply, &bufp);
    if (!error) {
        ofpbuf_delete(bufp);
        if (reply.cache_size != size) {
            return EINVAL;
        }
    }

    return error;
}


const struct dpif_class dpif_netlink_class = {
    "system",
    false,                      /* cleanup_required */
    false,                      /* synced_dp_layers */
    NULL,                       /* init */
    dpif_netlink_enumerate,
    NULL,
    dpif_netlink_open,
    dpif_netlink_close,
    dpif_netlink_destroy,
    dpif_netlink_run,
    NULL,                       /* wait */
    dpif_netlink_get_stats,
    dpif_netlink_set_features,
    dpif_netlink_port_add,
    dpif_netlink_port_del,
    NULL,                       /* port_set_config */
    dpif_netlink_port_query_by_number,
    dpif_netlink_port_query_by_name,
    dpif_netlink_port_get_pid,
    dpif_netlink_port_dump_start,
    dpif_netlink_port_dump_next,
    dpif_netlink_port_dump_done,
    dpif_netlink_port_poll,
    dpif_netlink_port_poll_wait,
    dpif_netlink_flow_flush,
    dpif_netlink_flow_dump_create,
    dpif_netlink_flow_dump_destroy,
    dpif_netlink_flow_dump_thread_create,
    dpif_netlink_flow_dump_thread_destroy,
    dpif_netlink_flow_dump_next,
    dpif_netlink_operate,
    NULL,                       /* offload_stats_get */
    dpif_netlink_recv_set,
    dpif_netlink_handlers_set,
    dpif_netlink_number_handlers_required,
    NULL,                       /* set_config */
    dpif_netlink_queue_to_priority,
    dpif_netlink_recv,
    dpif_netlink_recv_wait,
    dpif_netlink_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    dpif_netlink_get_datapath_version, /* get_datapath_version */
    dpif_netlink_ct_dump_start,
    dpif_netlink_ct_dump_next,
    dpif_netlink_ct_dump_done,
    NULL,                       /* ct_exp_dump_start */
    NULL,                       /* ct_exp_dump_next */
    NULL,                       /* ct_exp_dump_done */
    dpif_netlink_ct_flush,
    NULL,                       /* ct_set_maxconns */
    NULL,                       /* ct_get_maxconns */
    NULL,                       /* ct_get_nconns */
    NULL,                       /* ct_set_tcp_seq_chk */
    NULL,                       /* ct_get_tcp_seq_chk */
    NULL,                       /* ct_set_sweep_interval */
    NULL,                       /* ct_get_sweep_interval */
    dpif_netlink_ct_set_limits,
    dpif_netlink_ct_get_limits,
    dpif_netlink_ct_del_limits,
    dpif_netlink_ct_set_timeout_policy,
    dpif_netlink_ct_get_timeout_policy,
    dpif_netlink_ct_del_timeout_policy,
    dpif_netlink_ct_timeout_policy_dump_start,
    dpif_netlink_ct_timeout_policy_dump_next,
    dpif_netlink_ct_timeout_policy_dump_done,
    dpif_netlink_ct_get_timeout_policy_name,
    dpif_netlink_ct_get_features,
    NULL,                       /* ipf_set_enabled */
    NULL,                       /* ipf_set_min_frag */
    NULL,                       /* ipf_set_max_nfrags */
    NULL,                       /* ipf_get_status */
    NULL,                       /* ipf_dump_start */
    NULL,                       /* ipf_dump_next */
    NULL,                       /* ipf_dump_done */
    dpif_netlink_meter_get_features,
    dpif_netlink_meter_set,
    dpif_netlink_meter_get,
    dpif_netlink_meter_del,
    NULL,                       /* bond_add */
    NULL,                       /* bond_del */
    NULL,                       /* bond_stats_get */
    dpif_netlink_cache_get_supported_levels,
    dpif_netlink_cache_get_name,
    dpif_netlink_cache_get_size,
    dpif_netlink_cache_set_size,
};

static int
dpif_netlink_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int error;

    if (ovsthread_once_start(&once)) {
        error = nl_lookup_genl_family(OVS_DATAPATH_FAMILY,
                                      &ovs_datapath_family);
        if (error) {
            VLOG_INFO("Generic Netlink family '%s' does not exist. "
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
        if (!error) {
            if (nl_lookup_genl_family(OVS_METER_FAMILY, &ovs_meter_family)) {
                VLOG_INFO("The kernel module does not support meters.");
            }
        }
        if (nl_lookup_genl_family(OVS_CT_LIMIT_FAMILY,
                                  &ovs_ct_limit_family) < 0) {
            VLOG_INFO("Generic Netlink family '%s' does not exist. "
                      "Please update the Open vSwitch kernel module to enable "
                      "the conntrack limit feature.", OVS_CT_LIMIT_FAMILY);
        }

        ovs_tunnels_out_of_tree = dpif_netlink_rtnl_probe_oot_tunnels();

        unixctl_command_register("dpif-netlink/dispatch-mode", "", 0, 0,
                                 dpif_netlink_unixctl_dispatch_mode, NULL);

        ovsthread_once_done(&once);
    }

    return error;
}

bool
dpif_netlink_is_internal_device(const char *name)
{
    struct dpif_netlink_vport reply;
    struct ofpbuf *buf;
    int error;

    error = dpif_netlink_vport_get(name, &reply, &buf);
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
dpif_netlink_vport_from_ofpbuf(struct dpif_netlink_vport *vport,
                             const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_vport_policy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC },
        [OVS_VPORT_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_vport_stats),
                                   .optional = true },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_VPORT_ATTR_NETNSID] = { .type = NL_A_U32, .optional = true },
        [OVS_VPORT_ATTR_UPCALL_STATS] = { .type = NL_A_NESTED,
                                          .optional = true },
    };

    dpif_netlink_vport_init(vport);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_vport_policy)];
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
        vport->n_upcall_pids = nl_attr_get_size(a[OVS_VPORT_ATTR_UPCALL_PID])
                               / (sizeof *vport->upcall_pids);
        vport->upcall_pids = nl_attr_get(a[OVS_VPORT_ATTR_UPCALL_PID]);

    }
    if (a[OVS_VPORT_ATTR_STATS]) {
        vport->stats = nl_attr_get(a[OVS_VPORT_ATTR_STATS]);
    }
    if (a[OVS_VPORT_ATTR_UPCALL_STATS]) {
        const struct nlattr *nla;
        size_t left;

        NL_NESTED_FOR_EACH (nla, left, a[OVS_VPORT_ATTR_UPCALL_STATS]) {
            if (nl_attr_type(nla) == OVS_VPORT_UPCALL_ATTR_SUCCESS) {
                vport->upcall_success = nl_attr_get_u64(nla);
            } else if (nl_attr_type(nla) == OVS_VPORT_UPCALL_ATTR_FAIL) {
                vport->upcall_fail = nl_attr_get_u64(nla);
            }
        }
    } else {
        vport->upcall_success = UINT64_MAX;
        vport->upcall_fail = UINT64_MAX;
    }
    if (a[OVS_VPORT_ATTR_OPTIONS]) {
        vport->options = nl_attr_get(a[OVS_VPORT_ATTR_OPTIONS]);
        vport->options_len = nl_attr_get_size(a[OVS_VPORT_ATTR_OPTIONS]);
    }
    if (a[OVS_VPORT_ATTR_NETNSID]) {
        netnsid_set(&vport->netnsid,
                    nl_attr_get_u32(a[OVS_VPORT_ATTR_NETNSID]));
    } else {
        netnsid_set_local(&vport->netnsid);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'vport'. */
static void
dpif_netlink_vport_to_ofpbuf(const struct dpif_netlink_vport *vport,
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

    if (vport->upcall_pids) {
        nl_msg_put_unspec(buf, OVS_VPORT_ATTR_UPCALL_PID,
                          vport->upcall_pids,
                          vport->n_upcall_pids * sizeof *vport->upcall_pids);
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
dpif_netlink_vport_init(struct dpif_netlink_vport *vport)
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
dpif_netlink_vport_transact(const struct dpif_netlink_vport *request,
                            struct dpif_netlink_vport *reply,
                            struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    error = dpif_netlink_init();
    if (error) {
        if (reply) {
            *bufp = NULL;
            dpif_netlink_vport_init(reply);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    dpif_netlink_vport_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_netlink_vport_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_netlink_vport_init(reply);
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
dpif_netlink_vport_get(const char *name, struct dpif_netlink_vport *reply,
                       struct ofpbuf **bufp)
{
    struct dpif_netlink_vport request;

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_GET;
    request.name = name;

    return dpif_netlink_vport_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'dp'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'dp' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'dp' is still in use. */
static int
dpif_netlink_dp_from_ofpbuf(struct dpif_netlink_dp *dp, const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_datapath_policy[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_DP_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_dp_stats),
                                .optional = true },
        [OVS_DP_ATTR_MEGAFLOW_STATS] = {
                        NL_POLICY_FOR(struct ovs_dp_megaflow_stats),
                        .optional = true },
        [OVS_DP_ATTR_USER_FEATURES] = {
                        .type = NL_A_U32,
                        .optional = true },
        [OVS_DP_ATTR_MASKS_CACHE_SIZE] = {
                        .type = NL_A_U32,
                        .optional = true },
    };

    dpif_netlink_dp_init(dp);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_datapath_policy)];
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
        dp->stats = nl_attr_get(a[OVS_DP_ATTR_STATS]);
    }

    if (a[OVS_DP_ATTR_MEGAFLOW_STATS]) {
        dp->megaflow_stats = nl_attr_get(a[OVS_DP_ATTR_MEGAFLOW_STATS]);
    }

    if (a[OVS_DP_ATTR_USER_FEATURES]) {
        dp->user_features = nl_attr_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
    }

    if (a[OVS_DP_ATTR_MASKS_CACHE_SIZE]) {
        dp->cache_size = nl_attr_get_u32(a[OVS_DP_ATTR_MASKS_CACHE_SIZE]);
    } else {
        dp->cache_size = UINT32_MAX;
    }

    return 0;
}

/* Appends to 'buf' the Generic Netlink message described by 'dp'. */
static void
dpif_netlink_dp_to_ofpbuf(const struct dpif_netlink_dp *dp, struct ofpbuf *buf)
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

    if (dp->upcall_pids) {
        nl_msg_put_unspec(buf, OVS_DP_ATTR_PER_CPU_PIDS, dp->upcall_pids,
                          sizeof *dp->upcall_pids * dp->n_upcall_pids);
    }

    if (dp->cache_size != UINT32_MAX) {
        nl_msg_put_u32(buf, OVS_DP_ATTR_MASKS_CACHE_SIZE, dp->cache_size);
    }

    /* Skip OVS_DP_ATTR_STATS since we never have a reason to serialize it. */
}

/* Clears 'dp' to "empty" values. */
static void
dpif_netlink_dp_init(struct dpif_netlink_dp *dp)
{
    memset(dp, 0, sizeof *dp);
    dp->cache_size = UINT32_MAX;
}

static void
dpif_netlink_dp_dump_start(struct nl_dump *dump)
{
    struct dpif_netlink_dp request;
    struct ofpbuf *buf;

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;

    buf = ofpbuf_new(1024);
    dpif_netlink_dp_to_ofpbuf(&request, buf);
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
dpif_netlink_dp_transact(const struct dpif_netlink_dp *request,
                         struct dpif_netlink_dp *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    request_buf = ofpbuf_new(1024);
    dpif_netlink_dp_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        dpif_netlink_dp_init(reply);
        if (!error) {
            error = dpif_netlink_dp_from_ofpbuf(reply, *bufp);
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
dpif_netlink_dp_get(const struct dpif *dpif_, struct dpif_netlink_dp *reply,
                    struct ofpbuf **bufp)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp request;

    dpif_netlink_dp_init(&request);
    request.cmd = OVS_DP_CMD_GET;
    request.dp_ifindex = dpif->dp_ifindex;

    return dpif_netlink_dp_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct ovs_header" followed
 * by Netlink attributes, into 'flow'.  Returns 0 if successful, otherwise a
 * positive errno value.
 *
 * 'flow' will contain pointers into 'buf', so the caller should not free 'buf'
 * while 'flow' is still in use. */
static int
dpif_netlink_flow_from_ofpbuf(struct dpif_netlink_flow *flow,
                              const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_flow_policy[__OVS_FLOW_ATTR_MAX] = {
        [OVS_FLOW_ATTR_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_MASK] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_FLOW_ATTR_STATS] = { NL_POLICY_FOR(struct ovs_flow_stats),
                                  .optional = true },
        [OVS_FLOW_ATTR_TCP_FLAGS] = { .type = NL_A_U8, .optional = true },
        [OVS_FLOW_ATTR_USED] = { .type = NL_A_U64, .optional = true },
        [OVS_FLOW_ATTR_UFID] = { .type = NL_A_U128, .optional = true },
        /* The kernel never uses OVS_FLOW_ATTR_CLEAR. */
        /* The kernel never uses OVS_FLOW_ATTR_PROBE. */
        /* The kernel never uses OVS_FLOW_ATTR_UFID_FLAGS. */
    };

    dpif_netlink_flow_init(flow);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_flow_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_flow_family
        || !nl_policy_parse(&b, 0, ovs_flow_policy, a,
                            ARRAY_SIZE(ovs_flow_policy))) {
        return EINVAL;
    }
    if (!a[OVS_FLOW_ATTR_KEY] && !a[OVS_FLOW_ATTR_UFID]) {
        return EINVAL;
    }

    flow->nlmsg_flags = nlmsg->nlmsg_flags;
    flow->dp_ifindex = ovs_header->dp_ifindex;
    if (a[OVS_FLOW_ATTR_KEY]) {
        flow->key = nl_attr_get(a[OVS_FLOW_ATTR_KEY]);
        flow->key_len = nl_attr_get_size(a[OVS_FLOW_ATTR_KEY]);
    }

    if (a[OVS_FLOW_ATTR_UFID]) {
        flow->ufid = nl_attr_get_u128(a[OVS_FLOW_ATTR_UFID]);
        flow->ufid_present = true;
    }
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


/*
 * If PACKET_TYPE attribute is present in 'data', it filters PACKET_TYPE out.
 * If the flow is not Ethernet, the OVS_KEY_ATTR_PACKET_TYPE is converted to
 * OVS_KEY_ATTR_ETHERTYPE. Puts 'data' to 'buf'.
 */
static void
put_exclude_packet_type(struct ofpbuf *buf, uint16_t type,
                        const struct nlattr *data, uint16_t data_len)
{
    const struct nlattr *packet_type;

    packet_type = nl_attr_find__(data, data_len, OVS_KEY_ATTR_PACKET_TYPE);

    if (packet_type) {
        /* exclude PACKET_TYPE Netlink attribute. */
        ovs_assert(NLA_ALIGN(packet_type->nla_len) == NL_A_U32_SIZE);
        size_t packet_type_len = NL_A_U32_SIZE;
        size_t first_chunk_size = (uint8_t *)packet_type - (uint8_t *)data;
        size_t second_chunk_size = data_len - first_chunk_size
                                   - packet_type_len;
        struct nlattr *next_attr = nl_attr_next(packet_type);
        size_t ofs;

        ofs = nl_msg_start_nested(buf, type);
        nl_msg_put(buf, data, first_chunk_size);
        nl_msg_put(buf, next_attr, second_chunk_size);
        if (!nl_attr_find__(data, data_len, OVS_KEY_ATTR_ETHERNET)) {
            ovs_be16 pt = pt_ns_type_be(nl_attr_get_be32(packet_type));
            const struct nlattr *nla;

            nla = nl_attr_find(buf, ofs + NLA_HDRLEN, OVS_KEY_ATTR_ETHERTYPE);
            if (nla) {
                ovs_be16 *ethertype;

                ethertype = CONST_CAST(ovs_be16 *, nl_attr_get(nla));
                *ethertype = pt;
            } else {
                nl_msg_put_be16(buf, OVS_KEY_ATTR_ETHERTYPE, pt);
            }
        }
        nl_msg_end_nested(buf, ofs);
    } else {
        nl_msg_put_unspec(buf, type, data, data_len);
    }
}

/* Appends to 'buf' (which must initially be empty) a "struct ovs_header"
 * followed by Netlink attributes corresponding to 'flow'. */
static void
dpif_netlink_flow_to_ofpbuf(const struct dpif_netlink_flow *flow,
                            struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_flow_family,
                          NLM_F_REQUEST | flow->nlmsg_flags,
                          flow->cmd, OVS_FLOW_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = flow->dp_ifindex;

    if (flow->ufid_present) {
        nl_msg_put_u128(buf, OVS_FLOW_ATTR_UFID, flow->ufid);
    }
    if (flow->ufid_terse) {
        nl_msg_put_u32(buf, OVS_FLOW_ATTR_UFID_FLAGS,
                       OVS_UFID_F_OMIT_KEY | OVS_UFID_F_OMIT_MASK
                       | OVS_UFID_F_OMIT_ACTIONS);
    }
    if (!flow->ufid_terse || !flow->ufid_present) {
        if (flow->key_len) {
            put_exclude_packet_type(buf, OVS_FLOW_ATTR_KEY, flow->key,
                                           flow->key_len);
        }
        if (flow->mask_len) {
            put_exclude_packet_type(buf, OVS_FLOW_ATTR_MASK, flow->mask,
                                           flow->mask_len);
        }
        if (flow->actions || flow->actions_len) {
            nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS,
                              flow->actions, flow->actions_len);
        }
    }

    /* We never need to send these to the kernel. */
    ovs_assert(!flow->stats);
    ovs_assert(!flow->tcp_flags);
    ovs_assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_CLEAR);
    }
    if (flow->probe) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_PROBE);
    }
}

/* Clears 'flow' to "empty" values. */
static void
dpif_netlink_flow_init(struct dpif_netlink_flow *flow)
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
dpif_netlink_flow_transact(struct dpif_netlink_flow *request,
                           struct dpif_netlink_flow *reply,
                           struct ofpbuf **bufp)
{
    struct ofpbuf *request_buf;
    int error;

    ovs_assert((reply != NULL) == (bufp != NULL));

    if (reply) {
        request->nlmsg_flags |= NLM_F_ECHO;
    }

    request_buf = ofpbuf_new(1024);
    dpif_netlink_flow_to_ofpbuf(request, request_buf);
    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (reply) {
        if (!error) {
            error = dpif_netlink_flow_from_ofpbuf(reply, *bufp);
        }
        if (error) {
            dpif_netlink_flow_init(reply);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }
    return error;
}

static void
dpif_netlink_flow_get_stats(const struct dpif_netlink_flow *flow,
                            struct dpif_flow_stats *stats)
{
    if (flow->stats) {
        stats->n_packets = get_32aligned_u64(&flow->stats->n_packets);
        stats->n_bytes = get_32aligned_u64(&flow->stats->n_bytes);
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
report_loss(struct dpif_netlink *dpif, struct dpif_channel *ch, uint32_t ch_idx,
            uint32_t handler_id)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct ds s;

    if (VLOG_DROP_WARN(&rl)) {
        return;
    }

    if (dpif_netlink_upcall_per_cpu(dpif)) {
        VLOG_WARN("%s: lost packet on handler %u",
                  dpif_name(&dpif->dpif), handler_id);
    } else {
        ds_init(&s);
        if (ch->last_poll != LLONG_MIN) {
            ds_put_format(&s, " (last polled %lld ms ago)",
                        time_msec() - ch->last_poll);
        }

        VLOG_WARN("%s: lost packet on port channel %u of handler %u%s",
                  dpif_name(&dpif->dpif), ch_idx, handler_id, ds_cstr(&s));
        ds_destroy(&s);
    }
}

static void
dpif_netlink_unixctl_dispatch_mode(struct unixctl_conn *conn,
                                   int argc OVS_UNUSED,
                                   const char *argv[] OVS_UNUSED,
                                   void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct nl_dump dump;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf msg, buf;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return;
    }

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    dpif_netlink_dp_dump_start(&dump);
    while (nl_dump_next(&dump, &msg, &buf)) {
        struct dpif_netlink_dp dp;
        if (!dpif_netlink_dp_from_ofpbuf(&dp, &msg)) {
            ds_put_format(&reply, "%s: ", dp.name);
            if (dp.user_features & OVS_DP_F_DISPATCH_UPCALL_PER_CPU) {
                ds_put_format(&reply, "per-cpu dispatch mode");
            } else {
                ds_put_format(&reply, "per-vport dispatch mode");
            }
            ds_put_format(&reply, "\n");
        }
    }
    ofpbuf_uninit(&buf);
    error = nl_dump_done(&dump);
    if (!error) {
        unixctl_command_reply(conn, ds_cstr(&reply));
    }

    ds_destroy(&reply);
}
