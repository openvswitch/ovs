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
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_linux);

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int fd;

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

static int do_ioctl(const struct dpif *, int cmd, const void *arg);
static int open_dpif(const struct dpif_linux_vport *local_vport,
                     struct dpif **);
static int get_openvswitch_major(void);
static int create_minor(const char *name, int minor);
static int open_minor(int minor, int *fdp);
static int make_openvswitch_device(int minor, char **fnp);
static void dpif_linux_port_changed(const struct rtnetlink_link_change *,
                                    void *dpif);

static struct dpif_linux *
dpif_linux_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_linux_class);
    return CONTAINER_OF(dpif, struct dpif_linux, dpif);
}

static int
dpif_linux_enumerate(struct svec *all_dps)
{
    int major;
    int error;
    int i;

    /* Check that the Open vSwitch module is loaded. */
    major = get_openvswitch_major();
    if (major < 0) {
        return -major;
    }

    error = 0;
    for (i = 0; i < ODP_MAX; i++) {
        struct dpif *dpif;
        char devname[16];
        int retval;

        sprintf(devname, "dp%d", i);
        retval = dpif_open(devname, "system", &dpif);
        if (!retval) {
            svec_add(all_dps, devname);
            dpif_uninit(dpif, true);
        } else if (retval != ENODEV && !error) {
            error = retval;
        }
    }
    return error;
}

static int
dpif_linux_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                bool create, struct dpif **dpifp)
{
    struct dpif_linux_vport request, reply;
    struct ofpbuf *buf;
    int minor;
    int error;

    minor = !strncmp(name, "dp", 2)
            && isdigit((unsigned char)name[2]) ? atoi(name + 2) : -1;
    if (create) {
        if (minor >= 0) {
            error = create_minor(name, minor);
            if (error) {
                return error;
            }
        } else {
            /* Scan for unused minor number. */
            for (minor = 0; ; minor++) {
                if (minor >= ODP_MAX) {
                    /* All datapath numbers in use. */
                    return ENOBUFS;
                }

                error = create_minor(name, minor);
                if (!error) {
                    break;
                } else if (error != EBUSY) {
                    return error;
                }
            }
        }
    }

    dpif_linux_vport_init(&request);
    request.cmd = ODP_VPORT_GET;
    request.port_no = ODPP_LOCAL;
    if (minor >= 0) {
        request.dp_idx = minor;
    } else {
        request.name = name;
    }

    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (error) {
        return error;
    } else if (reply.port_no != ODPP_LOCAL) {
        /* This is an Open vSwitch device but not the local port.  We
         * intentionally support only using the name of the local port as the
         * name of a datapath; otherwise, it would be too difficult to
         * enumerate all the names of a datapath. */
        error = EOPNOTSUPP;
    } else {
        error = open_dpif(&reply, dpifp);
    }

    ofpbuf_delete(buf);
    return error;
}

static int
open_dpif(const struct dpif_linux_vport *local_vport, struct dpif **dpifp)
{
    int dp_idx = local_vport->dp_idx;
    struct dpif_linux *dpif;
    char *name;
    int error;
    int fd;

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
    return do_ioctl(dpif_, ODP_DP_DESTROY, NULL);
}

static int
dpif_linux_get_stats(const struct dpif *dpif_, struct odp_stats *stats)
{
    memset(stats, 0, sizeof *stats);
    return do_ioctl(dpif_, ODP_DP_STATS, stats);
}

static int
dpif_linux_get_drop_frags(const struct dpif *dpif_, bool *drop_fragsp)
{
    int drop_frags;
    int error;

    error = do_ioctl(dpif_, ODP_GET_DROP_FRAGS, &drop_frags);
    if (!error) {
        *drop_fragsp = drop_frags & 1;
    }
    return error;
}

static int
dpif_linux_set_drop_frags(struct dpif *dpif_, bool drop_frags)
{
    int drop_frags_int = drop_frags;
    return do_ioctl(dpif_, ODP_SET_DROP_FRAGS, &drop_frags_int);
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
    request.cmd = ODP_VPORT_NEW;
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
    vport.cmd = ODP_VPORT_DEL;
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
    request.cmd = ODP_VPORT_GET;
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
    return do_ioctl(dpif_, ODP_FLOW_FLUSH, NULL);
}

struct dpif_linux_port_state {
    struct ofpbuf *buf;
    uint32_t next;
};

static int
dpif_linux_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dpif_linux_port_state));
    return 0;
}

static int
dpif_linux_port_dump_next(const struct dpif *dpif, void *state_,
                          struct dpif_port *dpif_port)
{
    struct dpif_linux_port_state *state = state_;
    struct dpif_linux_vport request, reply;
    struct ofpbuf *buf;
    int error;

    ofpbuf_delete(state->buf);
    state->buf = NULL;

    dpif_linux_vport_init(&request);
    request.cmd = ODP_VPORT_DUMP;
    request.dp_idx = dpif_linux_cast(dpif)->minor;
    request.port_no = state->next;
    error = dpif_linux_vport_transact(&request, &reply, &buf);
    if (error) {
        return error == ENODEV ? EOF : error;
    } else {
        dpif_port->name = (char *) reply.name;
        dpif_port->type = (char *) netdev_vport_get_netdev_type(&reply);
        dpif_port->port_no = reply.port_no;
        state->buf = buf;
        state->next = reply.port_no + 1;
        return 0;
    }
}

static int
dpif_linux_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dpif_linux_port_state *state = state_;
    ofpbuf_delete(state->buf);
    free(state);
    return 0;
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
dpif_linux_flow_get(const struct dpif *dpif_, int flags,
                    const struct nlattr *key, size_t key_len,
                    struct ofpbuf **actionsp, struct odp_flow_stats *stats)
{
    struct ofpbuf *actions = NULL;
    struct odp_flow odp_flow;
    int error;

    memset(&odp_flow, 0, sizeof odp_flow);
    odp_flow.key = (struct nlattr *) key;
    odp_flow.key_len = key_len;
    if (actionsp) {
        actions = *actionsp = ofpbuf_new(65536);
        odp_flow.actions = actions->base;
        odp_flow.actions_len = actions->allocated;
    }
    odp_flow.flags = flags;

    error = do_ioctl(dpif_, ODP_FLOW_GET, &odp_flow);
    if (!error) {
        if (stats) {
            *stats = odp_flow.stats;
        }
        if (actions) {
            actions->size = odp_flow.actions_len;
            ofpbuf_trim(actions);
        }
    } else {
        if (actions) {
            ofpbuf_delete(actions);
        }
    }
    return error;
}

static int
dpif_linux_flow_put(struct dpif *dpif_, int flags,
                    const struct nlattr *key, size_t key_len,
                    const struct nlattr *actions, size_t actions_len,
                    struct odp_flow_stats *stats)
{
    struct odp_flow_put put;
    int error;

    memset(&put, 0, sizeof put);
    put.flow.key = (struct nlattr *) key;
    put.flow.key_len = key_len;
    put.flow.actions = (struct nlattr *) actions;
    put.flow.actions_len = actions_len;
    put.flow.flags = 0;
    put.flags = flags;
    error = do_ioctl(dpif_, ODP_FLOW_PUT, &put);
    if (!error && stats) {
        *stats = put.flow.stats;
    }
    return error;
}

static int
dpif_linux_flow_del(struct dpif *dpif_,
                    const struct nlattr *key, size_t key_len,
                    struct odp_flow_stats *stats)
{
    struct odp_flow odp_flow;
    int error;

    memset(&odp_flow, 0, sizeof odp_flow);
    odp_flow.key = (struct nlattr *) key;
    odp_flow.key_len = key_len;
    error = do_ioctl(dpif_, ODP_FLOW_DEL, &odp_flow);
    if (!error && stats) {
        *stats = odp_flow.stats;
    }
    return error;
}

struct dpif_linux_flow_state {
    struct odp_flow_dump dump;
    struct odp_flow flow;
    uint32_t keybuf[ODPUTIL_FLOW_KEY_U32S];
    uint32_t actionsbuf[65536 / sizeof(uint32_t)];
};

static int
dpif_linux_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    struct dpif_linux_flow_state *state;

    *statep = state = xmalloc(sizeof *state);
    state->dump.state[0] = 0;
    state->dump.state[1] = 0;
    state->dump.flow = &state->flow;
    return 0;
}

static int
dpif_linux_flow_dump_next(const struct dpif *dpif, void *state_,
                          const struct nlattr **key, size_t *key_len,
                          const struct nlattr **actions, size_t *actions_len,
                          const struct odp_flow_stats **stats)
{
    struct dpif_linux_flow_state *state = state_;
    int error;

    memset(&state->flow, 0, sizeof state->flow);
    state->flow.key = (struct nlattr *) state->keybuf;
    state->flow.key_len = sizeof state->keybuf;
    if (actions) {
        state->flow.actions = (struct nlattr *) state->actionsbuf;
        state->flow.actions_len = sizeof state->actionsbuf;
    }

    error = do_ioctl(dpif, ODP_FLOW_DUMP, &state->dump);
    if (!error) {
        if (state->flow.flags & ODPFF_EOF) {
            return EOF;
        }
        if (key) {
            *key = (const struct nlattr *) state->keybuf;
            *key_len = state->flow.key_len;
        }
        if (actions) {
            *actions = (const struct nlattr *) state->actionsbuf;
            *actions_len = state->flow.actions_len;
        }
        if (stats) {
            *stats = &state->flow.stats;
        }
    }
    return error;
}

static int
dpif_linux_flow_dump_done(const struct dpif *dpif OVS_UNUSED, void *state)
{
    free(state);
    return 0;
}

static int
dpif_linux_execute(struct dpif *dpif_,
                   const struct nlattr *actions, size_t actions_len,
                   const struct ofpbuf *buf)
{
    struct odp_execute execute;
    memset(&execute, 0, sizeof execute);
    execute.actions = (struct nlattr *) actions;
    execute.actions_len = actions_len;
    execute.data = buf->data;
    execute.length = buf->size;
    return do_ioctl(dpif_, ODP_EXECUTE, &execute);
}

static int
dpif_linux_recv_get_mask(const struct dpif *dpif_, int *listen_mask)
{
    return do_ioctl(dpif_, ODP_GET_LISTEN_MASK, listen_mask);
}

static int
dpif_linux_recv_set_mask(struct dpif *dpif_, int listen_mask)
{
    return do_ioctl(dpif_, ODP_SET_LISTEN_MASK, &listen_mask);
}

static int
dpif_linux_get_sflow_probability(const struct dpif *dpif_,
                                 uint32_t *probability)
{
    return do_ioctl(dpif_, ODP_GET_SFLOW_PROBABILITY, probability);
}

static int
dpif_linux_set_sflow_probability(struct dpif *dpif_, uint32_t probability)
{
    return do_ioctl(dpif_, ODP_SET_SFLOW_PROBABILITY, &probability);
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
parse_odp_packet(struct ofpbuf *buf, struct dpif_upcall *upcall)
{
    static const struct nl_policy odp_packet_policy[] = {
        /* Always present. */
        [ODP_PACKET_ATTR_TYPE] = { .type = NL_A_U32 },
        [ODP_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [ODP_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* _ODPL_ACTION_NR only. */
        [ODP_PACKET_ATTR_USERDATA] = { .type = NL_A_U64, .optional = true },

        /* _ODPL_SFLOW_NR only. */
        [ODP_PACKET_ATTR_SAMPLE_POOL] = { .type = NL_A_U32, .optional = true },
        [ODP_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
    };

    struct odp_packet *odp_packet = buf->data;
    struct nlattr *a[ARRAY_SIZE(odp_packet_policy)];

    if (!nl_policy_parse(buf, sizeof *odp_packet, odp_packet_policy,
                         a, ARRAY_SIZE(odp_packet_policy))) {
        return EINVAL;
    }

    memset(upcall, 0, sizeof *upcall);
    upcall->type = nl_attr_get_u32(a[ODP_PACKET_ATTR_TYPE]);
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

    return 0;
}

static int
dpif_linux_recv(struct dpif *dpif_, struct dpif_upcall *upcall)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    struct ofpbuf *buf;
    int retval;
    int error;

    buf = ofpbuf_new(65536);
    retval = read(dpif->fd, ofpbuf_tail(buf), ofpbuf_tailroom(buf));
    if (retval < 0) {
        error = errno;
        if (error != EAGAIN) {
            VLOG_WARN_RL(&error_rl, "%s: read failed: %s",
                         dpif_name(dpif_), strerror(error));
        }
    } else if (retval >= sizeof(struct odp_packet)) {
        struct odp_packet *odp_packet = buf->data;
        buf->size += retval;

        if (odp_packet->len <= retval) {
            error = parse_odp_packet(buf, upcall);
        } else {
            VLOG_WARN_RL(&error_rl, "%s: discarding message truncated "
                         "from %"PRIu32" bytes to %d",
                         dpif_name(dpif_), odp_packet->len, retval);
            error = ERANGE;
        }
    } else if (!retval) {
        VLOG_WARN_RL(&error_rl, "%s: unexpected end of file", dpif_name(dpif_));
        error = EPROTO;
    } else {
        VLOG_WARN_RL(&error_rl, "%s: discarding too-short message (%d bytes)",
                     dpif_name(dpif_), retval);
        error = ERANGE;
    }

    if (error) {
        ofpbuf_delete(buf);
    }
    return error;
}

static void
dpif_linux_recv_wait(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    poll_fd_wait(dpif->fd, POLLIN);
}

static void
dpif_linux_recv_purge(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    int i;

    /* This is somewhat bogus because it assumes that the following macros have
     * fixed values, but it's going to go away later.  */
#define DP_N_QUEUES 3
#define DP_MAX_QUEUE_LEN 100
    for (i = 0; i < DP_N_QUEUES * DP_MAX_QUEUE_LEN; i++) {
        /* Reading even 1 byte discards a whole datagram and saves time. */
        char buffer;

        if (read(dpif->fd, &buffer, 1) != 1) {
            break;
        }
    }
}

const struct dpif_class dpif_linux_class = {
    "system",
    NULL,
    NULL,
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

static int get_openvswitch_major(void);
static int get_major(const char *target);

static int
do_ioctl(const struct dpif *dpif_, int cmd, const void *arg)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    return ioctl(dpif->fd, cmd, arg) ? errno : 0;
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
create_minor(const char *name, int minor)
{
    int error;
    int fd;

    error = open_minor(minor, &fd);
    if (error) {
        return error;
    }

    error = ioctl(fd, ODP_DP_CREATE, name) ? errno : 0;
    close(fd);
    return error;
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

/* Parses the contents of 'buf', which contains a "struct odp_vport" followed
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

    struct odp_vport *odp_vport;
    struct nlattr *a[ARRAY_SIZE(odp_vport_policy)];

    dpif_linux_vport_init(vport);

    if (!nl_policy_parse(buf, sizeof *odp_vport, odp_vport_policy,
                         a, ARRAY_SIZE(odp_vport_policy))) {
        return EINVAL;
    }
    odp_vport = buf->data;

    vport->dp_idx = odp_vport->dp_idx;
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

/* Appends to 'buf' (which must initially be empty) a "struct odp_vport"
 * followed by Netlink attributes corresponding to 'vport'. */
static void
dpif_linux_vport_to_ofpbuf(const struct dpif_linux_vport *vport,
                           struct ofpbuf *buf)
{
    struct odp_vport *odp_vport;

    ofpbuf_reserve(buf, sizeof odp_vport);

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

    odp_vport = ofpbuf_push_uninit(buf, sizeof *odp_vport);
    odp_vport->dp_idx = vport->dp_idx;
    odp_vport->len = buf->size;
    odp_vport->total_len = (char *) ofpbuf_end(buf) - (char *) buf->data;
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
    static int dp0_fd = -1;
    struct ofpbuf *buf = NULL;
    int error;

    assert((reply != NULL) == (bufp != NULL));
    if (dp0_fd < 0) {
        int fd;

        error = open_minor(0, &fd);
        if (error) {
            goto error;
        }
        dp0_fd = fd;
    }

    buf = ofpbuf_new(1024);
    dpif_linux_vport_to_ofpbuf(request, buf);

    error = ioctl(dp0_fd, request->cmd, buf->data) ? errno : 0;
    if (error) {
        goto error;
    }

    if (bufp) {
        buf->size = ((struct odp_vport *) buf->data)->len;
        error = dpif_linux_vport_from_ofpbuf(reply, buf);
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

/* Obtains information about the kernel vport named 'name' and stores it into
 * '*reply' and '*bufp'.  The caller must free '*bufp' when the reply is no
 * longer needed ('reply' will contain pointers into '*bufp').  */
int
dpif_linux_vport_get(const char *name, struct dpif_linux_vport *reply,
                     struct ofpbuf **bufp)
{
    struct dpif_linux_vport request;

    dpif_linux_vport_init(&request);
    request.cmd = ODP_VPORT_GET;
    request.name = name;

    return dpif_linux_vport_transact(&request, reply, bufp);
}

