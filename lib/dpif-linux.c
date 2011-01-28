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
#include <linux/ethtool.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dpif-provider.h"
#include "netdev.h"
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
#include "svec.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_linux);

struct dpif_linux_dp {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* struct odp_header. */
    uint32_t dp_idx;

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
    /* ioctl command argument. */
    int cmd;

    /* struct odp_flow header. */
    unsigned int nlmsg_flags;
    uint32_t dp_idx;

    /* Attributes.
     *
     * The 'stats', 'used', and 'state' members point to 64-bit data that might
     * only be aligned on 32-bit boundaries, so get_unaligned_u64() should be
     * used to access their values. */
    const struct nlattr *key;           /* ODP_FLOW_ATTR_KEY. */
    size_t key_len;
    const struct nlattr *actions;       /* ODP_FLOW_ATTR_ACTIONS. */
    size_t actions_len;
    const struct odp_flow_stats *stats; /* ODP_FLOW_ATTR_STATS. */
    const uint8_t *tcp_flags;           /* ODP_FLOW_ATTR_TCP_FLAGS. */
    const uint64_t *used;               /* ODP_FLOW_ATTR_USED. */
    bool clear;                         /* ODP_FLOW_ATTR_CLEAR. */
    const uint64_t *state;              /* ODP_FLOW_ATTR_STATE. */
};

static void dpif_linux_flow_init(struct dpif_linux_flow *);
static int dpif_linux_flow_transact(const struct dpif_linux_flow *request,
                                    struct dpif_linux_flow *reply,
                                    struct ofpbuf **bufp);
static void dpif_linux_flow_get_stats(const struct dpif_linux_flow *,
                                      struct dpif_flow_stats *);

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int fd;

    /* Multicast group messages. */
    struct nl_sock *mc_sock;
    uint32_t mcgroups[DPIF_N_UC_TYPES];
    unsigned int listen_mask;

    /* Used by dpif_linux_get_all_names(). */
    char *local_ifname;
    int minor;

    /* Change notification. */
    int local_ifindex;          /* Ifindex of local port. */
    struct shash changed_ports;  /* Ports that have changed. */
    struct rtnetlink_notifier port_notifier;
    bool change_error;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

/* Generic Netlink family numbers for ODP. */
static int odp_datapath_family;
static int odp_vport_family;
static int odp_packet_family;

/* Generic Netlink socket. */
static struct nl_sock *genl_sock;

static int dpif_linux_init(void);
static int open_dpif(const struct dpif_linux_dp *,
                     const struct dpif_linux_vport *local_vport,
                     struct dpif **);
static int get_openvswitch_major(void);
static int open_minor(int minor, int *fdp);
static int make_openvswitch_device(int minor, char **fnp);
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

static int
dpif_linux_enumerate(struct svec *all_dps)
{
    struct nl_dump dump;
    struct ofpbuf msg;
    int major;
    int error;

    error = dpif_linux_init();
    if (error) {
        return error;
    }

    /* Check that the Open vSwitch module is loaded. */
    major = get_openvswitch_major();
    if (major < 0) {
        return -major;
    }

    dpif_linux_dp_dump_start(&dump);
    while (nl_dump_next(&dump, &msg)) {
        struct dpif_linux_dp dp;

        if (!dpif_linux_dp_from_ofpbuf(&dp, &msg)) {
            svec_add(all_dps, dp.name);
        }
    }
    return nl_dump_done(&dump);
}

static int
dpif_linux_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                bool create, struct dpif **dpifp)
{
    struct dpif_linux_vport vport_request, vport;
    struct dpif_linux_dp dp_request, dp;
    struct ofpbuf *buf;
    int minor;
    int error;

    error = dpif_linux_init();
    if (error) {
        return error;
    }

    minor = !strncmp(name, "dp", 2)
            && isdigit((unsigned char)name[2]) ? atoi(name + 2) : -1;

    /* Create or look up datapath. */
    dpif_linux_dp_init(&dp_request);
    dp_request.cmd = create ? ODP_DP_CMD_NEW : ODP_DP_CMD_GET;
    dp_request.dp_idx = minor;
    dp_request.name = minor < 0 ? name : NULL;
    error = dpif_linux_dp_transact(&dp_request, &dp, &buf);
    if (error) {
        return error;
    }
    ofpbuf_delete(buf);         /* Pointers inside 'dp' are now invalid! */

    /* Look up local port. */
    dpif_linux_vport_init(&vport_request);
    vport_request.cmd = ODP_VPORT_CMD_GET;
    vport_request.dp_idx = dp.dp_idx;
    vport_request.port_no = ODPP_LOCAL;
    vport_request.name = minor < 0 ? name : NULL;
    error = dpif_linux_vport_transact(&vport_request, &vport, &buf);
    if (error) {
        return error;
    } else if (vport.port_no != ODPP_LOCAL) {
        /* This is an Open vSwitch device but not the local port.  We
         * intentionally support only using the name of the local port as the
         * name of a datapath; otherwise, it would be too difficult to
         * enumerate all the names of a datapath. */
        error = EOPNOTSUPP;
    } else {
        error = open_dpif(&dp, &vport, dpifp);
    }
    ofpbuf_delete(buf);
    return error;
}

static int
open_dpif(const struct dpif_linux_dp *dp,
          const struct dpif_linux_vport *local_vport, struct dpif **dpifp)
{
    int dp_idx = local_vport->dp_idx;
    struct dpif_linux *dpif;
    char *name;
    int error;
    int fd;
    int i;

    error = open_minor(dp_idx, &fd);
    if (error) {
        goto error;
    }

    dpif = xmalloc(sizeof *dpif);
    error = rtnetlink_link_notifier_register(&dpif->port_notifier,
                                             dpif_linux_port_changed, dpif);
    if (error) {
        goto error_free;
    }

    name = xasprintf("dp%d", dp_idx);
    dpif_init(&dpif->dpif, &dpif_linux_class, name, dp_idx, dp_idx);
    free(name);

    dpif->fd = fd;
    dpif->mc_sock = NULL;
    for (i = 0; i < DPIF_N_UC_TYPES; i++) {
        dpif->mcgroups[i] = dp->mcgroups[i];
    }
    dpif->listen_mask = 0;
    dpif->local_ifname = xstrdup(local_vport->name);
    dpif->local_ifindex = local_vport->ifindex;
    dpif->minor = dp_idx;
    shash_init(&dpif->changed_ports);
    dpif->change_error = false;
    *dpifp = &dpif->dpif;

    return 0;

error_free:
    free(dpif);
    close(fd);
error:
    return error;
}

static void
dpif_linux_close(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    rtnetlink_link_notifier_unregister(&dpif->port_notifier);
    shash_destroy(&dpif->changed_ports);
    free(dpif->local_ifname);
    close(dpif->fd);
    free(dpif);
}

static int
dpif_linux_get_all_names(const struct dpif *dpif_, struct svec *all_names)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    svec_add_nocopy(all_names, xasprintf("dp%d", dpif->minor));
    svec_add(all_names, dpif->local_ifname);
    return 0;
}

static int
dpif_linux_destroy(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp dp;

    dpif_linux_dp_init(&dp);
    dp.cmd = ODP_DP_CMD_DEL;
    dp.dp_idx = dpif->minor;
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
    dp.dp_idx = dpif->minor;
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
    request.dp_idx = dpif->minor;
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

    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
        ofpbuf_delete(buf);
    }

    return error;
}

static int
dpif_linux_port_del(struct dpif *dpif_, uint16_t port_no)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_vport vport;

    dpif_linux_vport_init(&vport);
    vport.cmd = ODP_VPORT_CMD_DEL;
    vport.dp_idx = dpif->minor;
    vport.port_no = port_no;
    return dpif_linux_vport_transact(&vport, NULL, NULL);
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
    request.dp_idx = dpif_linux_cast(dpif)->minor;
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

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    return ioctl(dpif->fd, ODP_FLOW_FLUSH, dpif->minor) ? errno : 0;
}

struct dpif_linux_port_state {
    struct nl_dump dump;
};

static int
dpif_linux_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_port_state *state;
    struct dpif_linux_vport request;
    struct ofpbuf *buf;

    *statep = state = xmalloc(sizeof *state);

    dpif_linux_vport_init(&request);
    request.cmd = ODP_DP_CMD_GET;
    request.dp_idx = dpif->minor;

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
        return EOF;
    }

    error = dpif_linux_vport_from_ofpbuf(&vport, &buf);
    if (error) {
        return error;
    }

    dpif_port->name = (char *) vport.name;
    dpif_port->type = (char *) netdev_vport_get_netdev_type(&vport);
    dpif_port->port_no = vport.port_no;
    return 0;
}

static int
dpif_linux_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
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

    if (dpif->change_error) {
        dpif->change_error = false;
        shash_clear(&dpif->changed_ports);
        return ENOBUFS;
    } else if (!shash_is_empty(&dpif->changed_ports)) {
        struct shash_node *node = shash_first(&dpif->changed_ports);
        *devnamep = shash_steal(&dpif->changed_ports, node);
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_linux_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    if (!shash_is_empty(&dpif->changed_ports) || dpif->change_error) {
        poll_immediate_wake();
    } else {
        rtnetlink_link_notifier_wait();
    }
}

static int
dpif_linux_flow_get(const struct dpif *dpif_,
                    const struct nlattr *key, size_t key_len,
                    struct ofpbuf **actionsp, struct dpif_flow_stats *stats)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow request, reply;
    struct ofpbuf *buf;
    int error;

    dpif_linux_flow_init(&request);
    request.cmd = ODP_FLOW_GET;
    request.dp_idx = dpif->minor;
    request.key = key;
    request.key_len = key_len;
    error = dpif_linux_flow_transact(&request, &reply, &buf);
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
    struct ofpbuf *buf;
    int error;

    dpif_linux_flow_init(&request);
    request.cmd = flags & DPIF_FP_CREATE ? ODP_FLOW_NEW : ODP_FLOW_SET;
    request.dp_idx = dpif->minor;
    request.key = key;
    request.key_len = key_len;
    request.actions = actions;
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
    request.cmd = ODP_FLOW_DEL;
    request.dp_idx = dpif->minor;
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
    struct dpif_linux_flow flow;
    struct ofpbuf *buf;
    struct dpif_flow_stats stats;
};

static int
dpif_linux_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dpif_linux_flow_state));
    return 0;
}

static int
dpif_linux_flow_dump_next(const struct dpif *dpif_, void *state_,
                          const struct nlattr **key, size_t *key_len,
                          const struct nlattr **actions, size_t *actions_len,
                          const struct dpif_flow_stats **stats)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_flow_state *state = state_;
    struct ofpbuf *old_buf = state->buf;
    struct dpif_linux_flow request;
    int error;

    dpif_linux_flow_init(&request);
    request.cmd = ODP_FLOW_DUMP;
    request.dp_idx = dpif->minor;
    request.state = state->flow.state;
    error = dpif_linux_flow_transact(&request, &state->flow, &state->buf);
    ofpbuf_delete(old_buf);

    if (!error) {
        if (key) {
            *key = state->flow.key;
            *key_len = state->flow.key_len;
        }
        if (actions) {
            *actions = state->flow.actions;
            *actions_len = state->flow.actions_len;
        }
        if (stats) {
            dpif_linux_flow_get_stats(&state->flow, &state->stats);
            *stats = &state->stats;
        }
    }
    return error == ENODEV ? EOF : error;
}

static int
dpif_linux_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dpif_linux_flow_state *state = state_;

    ofpbuf_delete(state->buf);
    free(state);
    return 0;
}

static int
dpif_linux_execute(struct dpif *dpif_,
                   const struct nlattr *actions, size_t actions_len,
                   const struct ofpbuf *packet)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct odp_header *execute;
    struct ofpbuf *buf;
    int error;

    buf = ofpbuf_new(128 + actions_len + packet->size);

    nl_msg_put_genlmsghdr(buf, 0, odp_packet_family, NLM_F_REQUEST,
                          ODP_PACKET_CMD_EXECUTE, 1);

    execute = ofpbuf_put_uninit(buf, sizeof *execute);
    execute->dp_idx = dpif->minor;

    nl_msg_put_unspec(buf, ODP_PACKET_ATTR_PACKET, packet->data, packet->size);
    nl_msg_put_unspec(buf, ODP_PACKET_ATTR_ACTIONS, actions, actions_len);

    error = nl_sock_transact(genl_sock, buf, NULL);
    ofpbuf_delete(buf);
    return error;
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
    dp.dp_idx = dpif->minor;
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
                 uint32_t *dp_idx)
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

    *dp_idx = odp_header->dp_idx;

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
        uint32_t dp_idx;

        error = nl_sock_recv(dpif->mc_sock, &buf, false);
        if (error) {
            return error;
        }

        error = parse_odp_packet(buf, upcall, &dp_idx);
        if (!error
            && dp_idx == dpif->minor
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
    NULL,                       /* run */
    NULL,                       /* wait */
    dpif_linux_enumerate,
    dpif_linux_open,
    dpif_linux_close,
    dpif_linux_get_all_names,
    dpif_linux_destroy,
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

static int get_major(const char *target);

static int
dpif_linux_init(void)
{
    static int error = -1;

    if (error < 0) {
        error = nl_lookup_genl_family(ODP_DATAPATH_FAMILY,
                                      &odp_datapath_family);
        if (!error) {
            error = nl_lookup_genl_family(ODP_VPORT_FAMILY, &odp_vport_family);
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
    } else if (error != ENODEV) {
        VLOG_WARN_RL(&error_rl, "%s: vport query failed (%s)",
                     name, strerror(error));
    }

    return reply.type == ODP_VPORT_TYPE_INTERNAL;
}

static int
make_openvswitch_device(int minor, char **fnp)
{
    const char dirname[] = "/dev/net";
    int major;
    dev_t dev;
    struct stat s;
    char fn[128];

    *fnp = NULL;

    major = get_openvswitch_major();
    if (major < 0) {
        return -major;
    }
    dev = makedev(major, minor);

    sprintf(fn, "%s/dp%d", dirname, minor);
    if (!stat(fn, &s)) {
        if (!S_ISCHR(s.st_mode)) {
            VLOG_WARN_RL(&error_rl, "%s is not a character device, fixing",
                         fn);
        } else if (s.st_rdev != dev) {
            VLOG_WARN_RL(&error_rl,
                         "%s is device %u:%u but should be %u:%u, fixing",
                         fn, major(s.st_rdev), minor(s.st_rdev),
                         major(dev), minor(dev));
        } else {
            goto success;
        }
        if (unlink(fn)) {
            VLOG_WARN_RL(&error_rl, "%s: unlink failed (%s)",
                         fn, strerror(errno));
            return errno;
        }
    } else if (errno == ENOENT) {
        if (stat(dirname, &s)) {
            if (errno == ENOENT) {
                if (mkdir(dirname, 0755)) {
                    VLOG_WARN_RL(&error_rl, "%s: mkdir failed (%s)",
                                 dirname, strerror(errno));
                    return errno;
                }
            } else {
                VLOG_WARN_RL(&error_rl, "%s: stat failed (%s)",
                             dirname, strerror(errno));
                return errno;
            }
        }
    } else {
        VLOG_WARN_RL(&error_rl, "%s: stat failed (%s)", fn, strerror(errno));
        return errno;
    }

    /* The device needs to be created. */
    if (mknod(fn, S_IFCHR | 0700, dev)) {
        VLOG_WARN_RL(&error_rl,
                     "%s: creating character device %u:%u failed (%s)",
                     fn, major(dev), minor(dev), strerror(errno));
        return errno;
    }

success:
    *fnp = xstrdup(fn);
    return 0;
}

/* Return the major device number of the Open vSwitch device.  If it
 * cannot be determined, a negative errno is returned. */
static int
get_openvswitch_major(void)
{
    static int openvswitch_major = -1;
    if (openvswitch_major < 0) {
        openvswitch_major = get_major("openvswitch");
    }
    return openvswitch_major;
}

static int
get_major(const char *target)
{
    const char fn[] = "/proc/devices";
    char line[128];
    FILE *file;
    int ln;

    file = fopen(fn, "r");
    if (!file) {
        VLOG_ERR("opening %s failed (%s)", fn, strerror(errno));
        return -errno;
    }

    for (ln = 1; fgets(line, sizeof line, file); ln++) {
        char name[64];
        int major;

        if (!strncmp(line, "Character", 9) || line[0] == '\0') {
            /* Nothing to do. */
        } else if (!strncmp(line, "Block", 5)) {
            /* We only want character devices, so skip the rest of the file. */
            break;
        } else if (sscanf(line, "%d %63s", &major, name)) {
            if (!strcmp(name, target)) {
                fclose(file);
                return major;
            }
        } else {
            VLOG_WARN_ONCE("%s:%d: syntax error", fn, ln);
        }
    }

    fclose(file);

    VLOG_ERR("%s: %s major not found (is the module loaded?)", fn, target);
    return -ENODEV;
}

static int
open_minor(int minor, int *fdp)
{
    int error;
    char *fn;

    error = make_openvswitch_device(minor, &fn);
    if (error) {
        return error;
    }

    *fdp = open(fn, O_RDONLY | O_NONBLOCK);
    if (*fdp < 0) {
        error = errno;
        VLOG_WARN("%s: open failed (%s)", fn, strerror(error));
        free(fn);
        return error;
    }
    free(fn);
    return 0;
}

static void
dpif_linux_port_changed(const struct rtnetlink_link_change *change,
                        void *dpif_)
{
    struct dpif_linux *dpif = dpif_;

    if (change) {
        if (change->master_ifindex == dpif->local_ifindex
            && (change->nlmsg_type == RTM_NEWLINK
                || change->nlmsg_type == RTM_DELLINK))
        {
            /* Our datapath changed, either adding a new port or deleting an
             * existing one. */
            shash_add_once(&dpif->changed_ports, change->ifname, NULL);
        }
    } else {
        dpif->change_error = true;
    }
}

static int
get_dp0_fd(int *dp0_fdp)
{
    static int dp0_fd = -1;
    if (dp0_fd < 0) {
        int error;
        int fd;

        error = open_minor(0, &fd);
        if (error) {
            return error;
        }
        dp0_fd = fd;
    }
    *dp0_fdp = dp0_fd;
    return 0;
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
    vport->dp_idx = odp_header->dp_idx;
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
    odp_header->dp_idx = vport->dp_idx;

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

    if (vport->mtu) {
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
    vport->dp_idx = UINT32_MAX;
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
    dp->dp_idx = odp_header->dp_idx;
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
    odp_header->dp_idx = dp->dp_idx;

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
void
dpif_linux_dp_init(struct dpif_linux_dp *dp)
{
    memset(dp, 0, sizeof *dp);
    dp->dp_idx = -1;
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
int
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
int
dpif_linux_dp_get(const struct dpif *dpif_, struct dpif_linux_dp *reply,
                  struct ofpbuf **bufp)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct dpif_linux_dp request;

    dpif_linux_dp_init(&request);
    request.cmd = ODP_DP_CMD_GET;
    request.dp_idx = dpif->minor;

    return dpif_linux_dp_transact(&request, reply, bufp);
}

/* Parses the contents of 'buf', which contains a "struct odp_flow" followed by
 * Netlink attributes, into 'flow'.  Returns 0 if successful, otherwise a
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
        [ODP_FLOW_ATTR_STATE] = { .type = NL_A_U64, .optional = true },
    };

    struct odp_flow *odp_flow;
    struct nlattr *a[ARRAY_SIZE(odp_flow_policy)];

    dpif_linux_flow_init(flow);

    if (!nl_policy_parse(buf, sizeof *odp_flow, odp_flow_policy,
                         a, ARRAY_SIZE(odp_flow_policy))) {
        return EINVAL;
    }
    odp_flow = buf->data;

    flow->nlmsg_flags = odp_flow->nlmsg_flags;
    flow->dp_idx = odp_flow->dp_idx;
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
    if (a[ODP_FLOW_ATTR_STATE]) {
        flow->state = nl_attr_get(a[ODP_FLOW_ATTR_STATE]);
    }
    return 0;
}

/* Appends to 'buf' (which must initially be empty) a "struct odp_flow"
 * followed by Netlink attributes corresponding to 'flow'. */
static void
dpif_linux_flow_to_ofpbuf(const struct dpif_linux_flow *flow,
                          struct ofpbuf *buf)
{
    struct odp_flow *odp_flow;

    ofpbuf_reserve(buf, sizeof odp_flow);

    if (flow->key_len) {
        nl_msg_put_unspec(buf, ODP_FLOW_ATTR_KEY, flow->key, flow->key_len);
    }

    if (flow->actions_len) {
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

    if (flow->state) {
        nl_msg_put_u64(buf, ODP_FLOW_ATTR_STATE,
                       get_unaligned_u64(flow->state));
    }

    odp_flow = ofpbuf_push_uninit(buf, sizeof *odp_flow);
    odp_flow->nlmsg_flags = flow->nlmsg_flags;
    odp_flow->dp_idx = flow->dp_idx;
    odp_flow->len = buf->size;
    odp_flow->total_len = (char *) ofpbuf_end(buf) - (char *) buf->data;
}

/* Clears 'flow' to "empty" values. */
void
dpif_linux_flow_init(struct dpif_linux_flow *flow)
{
    memset(flow, 0, sizeof *flow);
}

/* Executes 'request' in the kernel datapath.  If the command fails, returns a
 * positive errno value.  Otherwise, if 'reply' and 'bufp' are null, returns 0
 * without doing anything else.  If 'reply' and 'bufp' are nonnull, then the
 * result of the command is expected to be an odp_flow also, which is decoded
 * and stored in '*reply' and '*bufp'.  The caller must free '*bufp' when the
 * reply is no longer needed ('reply' will contain pointers into '*bufp'). */
int
dpif_linux_flow_transact(const struct dpif_linux_flow *request,
                         struct dpif_linux_flow *reply, struct ofpbuf **bufp)
{
    struct ofpbuf *buf = NULL;
    int error;
    int fd;

    assert((reply != NULL) == (bufp != NULL));

    error = get_dp0_fd(&fd);
    if (error) {
        goto error;
    }

    buf = ofpbuf_new(1024);
    dpif_linux_flow_to_ofpbuf(request, buf);

    error = ioctl(fd, request->cmd, buf->data) ? errno : 0;
    if (error) {
        goto error;
    }

    if (bufp) {
        buf->size = ((struct odp_flow *) buf->data)->len;
        error = dpif_linux_flow_from_ofpbuf(reply, buf);
        if (error) {
            goto error;
        }
        *bufp = buf;
    } else {
        ofpbuf_delete(buf);
    }
    return 0;

error:
    ofpbuf_delete(buf);
    if (bufp) {
        memset(reply, 0, sizeof *reply);
        *bufp = NULL;
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

