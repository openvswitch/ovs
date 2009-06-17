/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "util.h"
#include "valgrind.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpif

/* A datapath interface. */
struct dpif {
    char *name;
    unsigned int minor;
    int fd;
};

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

static int get_minor_from_name(const char *name, unsigned int *minor);
static int name_to_minor(const char *name, unsigned int *minor);
static int lookup_minor(const char *name, unsigned int *minor);
static int open_by_minor(unsigned int minor, struct dpif **dpifp);
static int make_openvswitch_device(unsigned int minor, char **fnp);
static void check_rw_odp_flow(struct odp_flow *);

int
dpif_open(const char *name, struct dpif **dpifp)
{
    struct dpif *dpif;
    unsigned int minor;
    int listen_mask;
    int error;

    *dpifp = NULL;

    error = name_to_minor(name, &minor);
    if (error) {
        return error;
    }

    error = open_by_minor(minor, &dpif);
    if (error) {
        return error;
    }

    /* We can open the device, but that doesn't mean that it's been created.
     * If it hasn't been, then any command other than ODP_DP_CREATE will
     * return ENODEV.  Try something innocuous. */
    listen_mask = 0;            /* Make Valgrind happy. */
    if (ioctl(dpif->fd, ODP_GET_LISTEN_MASK, &listen_mask)) {
        error = errno;
        if (error != ENODEV) {
            VLOG_WARN("%s: probe returned unexpected error: %s",
                      dpif_name(dpif), strerror(error));
        }
        dpif_close(dpif);
        return error;
    }
    *dpifp = dpif;
    return 0;
}

void
dpif_close(struct dpif *dpif)
{
    if (dpif) {
        free(dpif->name);
        close(dpif->fd);
        free(dpif);
    }
}

static int
do_ioctl(const struct dpif *dpif, int cmd, const char *cmd_name,
         const void *arg)
{
    int error = ioctl(dpif->fd, cmd, arg) ? errno : 0;
    if (cmd_name) {
        if (error) {
            VLOG_WARN_RL(&error_rl, "%s: ioctl(%s) failed (%s)",
                         dpif_name(dpif), cmd_name, strerror(error));
        } else {
            VLOG_DBG_RL(&dpmsg_rl, "%s: ioctl(%s): success",
                        dpif_name(dpif), cmd_name);
        }
    }
    return error;
}

int
dpif_create(const char *name, struct dpif **dpifp)
{
    unsigned int minor;
    int error;

    *dpifp = NULL;
    if (!get_minor_from_name(name, &minor)) {
        /* Minor was specified in 'name', go ahead and create it. */
        struct dpif *dpif;

        error = open_by_minor(minor, &dpif);
        if (error) {
            return error;
        }

        error = ioctl(dpif->fd, ODP_DP_CREATE, name) < 0 ? errno : 0;
        if (!error) {
            *dpifp = dpif;
        } else {
            dpif_close(dpif);
        }
        return error;
    } else {
        for (minor = 0; minor < ODP_MAX; minor++) {
            struct dpif *dpif;

            error = open_by_minor(minor, &dpif);
            if (error) {
                return error;
            }

            error = ioctl(dpif->fd, ODP_DP_CREATE, name) < 0 ? errno : 0;
            if (!error) {
                *dpifp = dpif;
                return 0;
            }
            dpif_close(dpif);
            if (error != EBUSY) {
                return error;
            }
        }
        return ENOBUFS;
    }
}

const char *
dpif_name(const struct dpif *dpif)
{
    return dpif->name;
}

int
dpif_delete(struct dpif *dpif)
{
    COVERAGE_INC(dpif_destroy);
    return do_ioctl(dpif, ODP_DP_DESTROY, "ODP_DP_DESTROY", NULL);
}

int
dpif_get_dp_stats(const struct dpif *dpif, struct odp_stats *stats)
{
    memset(stats, 0, sizeof *stats);
    return do_ioctl(dpif, ODP_DP_STATS, "ODP_DP_STATS", stats);
}

int
dpif_get_drop_frags(const struct dpif *dpif, bool *drop_frags)
{
    int tmp;
    int error = do_ioctl(dpif, ODP_GET_DROP_FRAGS, "ODP_GET_DROP_FRAGS", &tmp);
    *drop_frags = error ? tmp & 1 : false;
    return error;
}

int
dpif_set_drop_frags(struct dpif *dpif, bool drop_frags)
{
    int tmp = drop_frags;
    return do_ioctl(dpif, ODP_SET_DROP_FRAGS, "ODP_SET_DROP_FRAGS", &tmp);
}

int
dpif_get_listen_mask(const struct dpif *dpif, int *listen_mask)
{
    int error = do_ioctl(dpif, ODP_GET_LISTEN_MASK, "ODP_GET_LISTEN_MASK",
                         listen_mask);
    if (error) {
        *listen_mask = 0;
    }
    return error;
}

int
dpif_set_listen_mask(struct dpif *dpif, int listen_mask)
{
    return do_ioctl(dpif, ODP_SET_LISTEN_MASK, "ODP_SET_LISTEN_MASK",
                    &listen_mask);
}

int
dpif_purge(struct dpif *dpif)
{
    struct odp_stats stats;
    unsigned int i;
    int error;

    COVERAGE_INC(dpif_purge);

    error = dpif_get_dp_stats(dpif, &stats);
    if (error) {
        return error;
    }

    for (i = 0; i < stats.max_miss_queue + stats.max_action_queue; i++) {
        struct ofpbuf *buf;
        error = dpif_recv(dpif, &buf);
        if (error) {
            return error == EAGAIN ? 0 : error;
        }
        ofpbuf_delete(buf);
    }
    return 0;
}

int
dpif_port_add(struct dpif *dpif, const char *devname, uint16_t port_no,
              uint16_t flags)
{
    struct odp_port port;

    COVERAGE_INC(dpif_port_add);
    memset(&port, 0, sizeof port);
    strncpy(port.devname, devname, sizeof port.devname);
    port.port = port_no;
    port.flags = flags;
    if (!ioctl(dpif->fd, ODP_PORT_ADD, &port)) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu16,
                    dpif_name(dpif), devname, port_no);
        return 0;
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port %"PRIu16": %s",
                     dpif_name(dpif), devname, port_no, strerror(errno));
        return errno;
    }
}

int
dpif_port_del(struct dpif *dpif, uint16_t port_no)
{
    int tmp = port_no;
    COVERAGE_INC(dpif_port_del);
    return do_ioctl(dpif, ODP_PORT_DEL, "ODP_PORT_DEL", &tmp);
}

int
dpif_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                          struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    port->port = port_no;
    if (!ioctl(dpif->fd, ODP_PORT_QUERY, port)) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu16" is device %s",
                    dpif_name(dpif), port_no, port->devname);
        return 0;
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu16": %s",
                     dpif_name(dpif), port_no, strerror(errno));
        return errno;
    }
}

int
dpif_port_query_by_name(const struct dpif *dpif, const char *devname,
                        struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    strncpy(port->devname, devname, sizeof port->devname);
    if (!ioctl(dpif->fd, ODP_PORT_QUERY, port)) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu16,
                    dpif_name(dpif), devname, port->port);
        return 0;
    } else {
        /* Log level is DBG here because all the current callers are interested
         * in whether 'dpif' actually has a port 'devname', so that it's not an
         * issue worth logging if it doesn't. */
        VLOG_DBG_RL(&error_rl, "%s: failed to query port %s: %s",
                    dpif_name(dpif), devname, strerror(errno));
        return errno;
    }
}

int
dpif_port_get_name(struct dpif *dpif, uint16_t port_no,
                   char *name, size_t name_size)
{
    struct odp_port port;
    int error;

    assert(name_size > 0);

    error = dpif_port_query_by_number(dpif, port_no, &port);
    if (!error) {
        ovs_strlcpy(name, port.devname, name_size);
    } else {
        *name = '\0';
    }
    return error;
}

int
dpif_port_list(const struct dpif *dpif,
               struct odp_port **ports, size_t *n_ports)
{
    struct odp_portvec pv;
    struct odp_stats stats;
    int error;

    do {
        error = dpif_get_dp_stats(dpif, &stats);
        if (error) {
            goto error;
        }

        *ports = xcalloc(1, stats.n_ports * sizeof **ports);
        pv.ports = *ports;
        pv.n_ports = stats.n_ports;
        error = do_ioctl(dpif, ODP_PORT_LIST, "ODP_PORT_LIST", &pv);
        if (error) {
            free(*ports);
            goto error;
        }
    } while (pv.n_ports != stats.n_ports);
    *n_ports = pv.n_ports;
    return 0;

error:
    *ports = NULL;
    *n_ports = 0;
    return error;
}

int
dpif_port_group_set(struct dpif *dpif, uint16_t group,
                    const uint16_t ports[], size_t n_ports)
{
    struct odp_port_group pg;

    COVERAGE_INC(dpif_port_group_set);
    assert(n_ports <= UINT16_MAX);
    pg.group = group;
    pg.ports = (uint16_t *) ports;
    pg.n_ports = n_ports;
    return do_ioctl(dpif, ODP_PORT_GROUP_SET, "ODP_PORT_GROUP_SET", &pg);
}

int
dpif_port_group_get(const struct dpif *dpif, uint16_t group,
                    uint16_t **ports, size_t *n_ports)
{
    int error;

    *ports = NULL;
    *n_ports = 0;
    for (;;) {
        struct odp_port_group pg;
        pg.group = group;
        pg.ports = *ports;
        pg.n_ports = *n_ports;

        error = do_ioctl(dpif, ODP_PORT_GROUP_GET, "ODP_PORT_GROUP_GET", &pg);
        if (error) {
            /* Hard error. */
            free(*ports);
            *ports = NULL;
            *n_ports = 0;
            break;
        } else if (pg.n_ports <= *n_ports) {
            /* Success. */
            *n_ports = pg.n_ports;
            break;
        } else {
            /* Soft error: there were more ports than we expected in the
             * group.  Try again. */
            free(*ports);
            *ports = xcalloc(pg.n_ports, sizeof **ports);
            *n_ports = pg.n_ports;
        }
    }
    return error;
}

int
dpif_flow_flush(struct dpif *dpif)
{
    COVERAGE_INC(dpif_flow_flush);
    return do_ioctl(dpif, ODP_FLOW_FLUSH, "ODP_FLOW_FLUSH", NULL);
}

static enum vlog_level
flow_message_log_level(int error)
{
    return error ? VLL_WARN : VLL_DBG;
}

static bool
should_log_flow_message(int error)
{
    return !vlog_should_drop(THIS_MODULE, flow_message_log_level(error),
                             error ? &error_rl : &dpmsg_rl);
}

static void
log_flow_message(const struct dpif *dpif, int error,
                 const char *operation,
                 const flow_t *flow, const struct odp_flow_stats *stats,
                 const union odp_action *actions, size_t n_actions)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", dpif_name(dpif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", strerror(error));
    }
    flow_format(&ds, flow);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        format_odp_flow_stats(&ds, stats);
    }
    if (actions || n_actions) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, n_actions);
    }
    vlog(THIS_MODULE, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static int
do_flow_ioctl(const struct dpif *dpif, int cmd, struct odp_flow *flow,
              const char *operation, bool show_stats)
{
    int error = do_ioctl(dpif, cmd, NULL, flow);
    if (error && show_stats) {
        flow->n_actions = 0;
    }
    if (should_log_flow_message(error)) {
        log_flow_message(dpif, error, operation, &flow->key,
                         show_stats && !error ? &flow->stats : NULL,
                         flow->actions, flow->n_actions);
    }
    return error;
}

int
dpif_flow_put(struct dpif *dpif, struct odp_flow_put *put)
{
    int error = do_ioctl(dpif, ODP_FLOW_PUT, NULL, put);
    COVERAGE_INC(dpif_flow_put);
    if (should_log_flow_message(error)) {
        struct ds operation = DS_EMPTY_INITIALIZER;
        ds_put_cstr(&operation, "put");
        if (put->flags & ODPPF_CREATE) {
            ds_put_cstr(&operation, "[create]");
        }
        if (put->flags & ODPPF_MODIFY) {
            ds_put_cstr(&operation, "[modify]");
        }
        if (put->flags & ODPPF_ZERO_STATS) {
            ds_put_cstr(&operation, "[zero]");
        }
#define ODPPF_ALL (ODPPF_CREATE | ODPPF_MODIFY | ODPPF_ZERO_STATS)
        if (put->flags & ~ODPPF_ALL) {
            ds_put_format(&operation, "[%x]", put->flags & ~ODPPF_ALL);
        }
        log_flow_message(dpif, error, ds_cstr(&operation), &put->flow.key,
                         !error ? &put->flow.stats : NULL,
                         put->flow.actions, put->flow.n_actions);
        ds_destroy(&operation);
    }
    return error;
}

int
dpif_flow_del(struct dpif *dpif, struct odp_flow *flow)
{
    COVERAGE_INC(dpif_flow_del);
    check_rw_odp_flow(flow);
    memset(&flow->stats, 0, sizeof flow->stats);
    return do_flow_ioctl(dpif, ODP_FLOW_DEL, flow, "delete flow", true);
}

int
dpif_flow_get(const struct dpif *dpif, struct odp_flow *flow)
{
    COVERAGE_INC(dpif_flow_query);
    check_rw_odp_flow(flow);
    memset(&flow->stats, 0, sizeof flow->stats);
    return do_flow_ioctl(dpif, ODP_FLOW_GET, flow, "get flow", true);
}

int
dpif_flow_get_multiple(const struct dpif *dpif,
                       struct odp_flow flows[], size_t n)
{
    struct odp_flowvec fv;
    size_t i;

    COVERAGE_ADD(dpif_flow_query_multiple, n);
    fv.flows = flows;
    fv.n_flows = n;
    for (i = 0; i < n; i++) {
        check_rw_odp_flow(&flows[i]);
    }
    return do_ioctl(dpif, ODP_FLOW_GET_MULTIPLE, "ODP_FLOW_GET_MULTIPLE",
                    &fv);
}

int
dpif_flow_list(const struct dpif *dpif, struct odp_flow flows[], size_t n,
               size_t *n_out)
{
    struct odp_flowvec fv;
    uint32_t i;
    int error;

    COVERAGE_INC(dpif_flow_query_list);
    fv.flows = flows;
    fv.n_flows = n;
    if (RUNNING_ON_VALGRIND) {
        memset(flows, 0, n * sizeof *flows);
    } else {
        for (i = 0; i < n; i++) {
            flows[i].actions = NULL;
            flows[i].n_actions = 0;
        }
    }
    error = do_ioctl(dpif, ODP_FLOW_LIST, NULL, &fv);
    if (error) {
        *n_out = 0;
        VLOG_WARN_RL(&error_rl, "%s: flow list failed (%s)",
                     dpif_name(dpif), strerror(error));
    } else {
        COVERAGE_ADD(dpif_flow_query_list_n, fv.n_flows);
        *n_out = fv.n_flows;
        VLOG_DBG_RL(&dpmsg_rl, "%s: listed %zu flows",
                    dpif_name(dpif), *n_out);
    }
    return error;
}

int
dpif_flow_list_all(const struct dpif *dpif,
                   struct odp_flow **flowsp, size_t *np)
{
    struct odp_stats stats;
    struct odp_flow *flows;
    size_t n_flows;
    int error;

    *flowsp = NULL;
    *np = 0;

    error = dpif_get_dp_stats(dpif, &stats);
    if (error) {
        return error;
    }

    flows = xmalloc(sizeof *flows * stats.n_flows);
    error = dpif_flow_list(dpif, flows, stats.n_flows, &n_flows);
    if (error) {
        free(flows);
        return error;
    }

    if (stats.n_flows != n_flows) {
        VLOG_WARN_RL(&error_rl, "%s: datapath stats reported %"PRIu32" "
                     "flows but flow listing reported %zu",
                     dpif_name(dpif), stats.n_flows, n_flows);
    }
    *flowsp = flows;
    *np = n_flows;
    return 0;
}

int
dpif_execute(struct dpif *dpif, uint16_t in_port,
             const union odp_action actions[], size_t n_actions,
             const struct ofpbuf *buf)
{
    int error;

    COVERAGE_INC(dpif_execute);
    if (n_actions > 0) {
        struct odp_execute execute;
        memset(&execute, 0, sizeof execute);
        execute.in_port = in_port;
        execute.actions = (union odp_action *) actions;
        execute.n_actions = n_actions;
        execute.data = buf->data;
        execute.length = buf->size;
        error = do_ioctl(dpif, ODP_EXECUTE, NULL, &execute);
    } else {
        error = 0;
    }

    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet = ofp_packet_to_string(buf->data, buf->size, buf->size);
        ds_put_format(&ds, "%s: execute ", dpif_name(dpif));
        format_odp_actions(&ds, actions, n_actions);
        if (error) {
            ds_put_format(&ds, " failed (%s)", strerror(error));
        }
        ds_put_format(&ds, " on packet %s", packet);
        vlog(THIS_MODULE, error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
        free(packet);
    }
    return error;
}

int
dpif_recv(struct dpif *dpif, struct ofpbuf **bufp)
{
    struct ofpbuf *buf;
    int retval;
    int error;

    buf = ofpbuf_new(65536);
    retval = read(dpif->fd, ofpbuf_tail(buf), ofpbuf_tailroom(buf));
    if (retval < 0) {
        error = errno;
        if (error != EAGAIN) {
            VLOG_WARN_RL(&error_rl, "%s: read failed: %s",
                         dpif_name(dpif), strerror(error));
        }
    } else if (retval >= sizeof(struct odp_msg)) {
        struct odp_msg *msg = buf->data;
        if (msg->length <= retval) {
            buf->size += retval;
            if (VLOG_IS_DBG_ENABLED()) {
                void *payload = msg + 1;
                size_t length = buf->size - sizeof *msg;
                char *s = ofp_packet_to_string(payload, length, length);
                VLOG_DBG_RL(&dpmsg_rl, "%s: received %s message of length "
                            "%zu on port %"PRIu16": %s", dpif_name(dpif),
                            (msg->type == _ODPL_MISS_NR ? "miss"
                             : msg->type == _ODPL_ACTION_NR ? "action"
                             : "<unknown>"),
                            msg->length - sizeof(struct odp_msg),
                            msg->port, s);
                free(s);
            }
            *bufp = buf;
            COVERAGE_INC(dpif_recv);
            return 0;
        } else {
            VLOG_WARN_RL(&error_rl, "%s: discarding message truncated "
                         "from %zu bytes to %d",
                         dpif_name(dpif), msg->length, retval);
            error = ERANGE;
        }
    } else if (!retval) {
        VLOG_WARN_RL(&error_rl, "%s: unexpected end of file", dpif_name(dpif));
        error = EPROTO;
    } else {
        VLOG_WARN_RL(&error_rl,
                     "%s: discarding too-short message (%d bytes)",
                     dpif_name(dpif), retval);
        error = ERANGE;
    }

    *bufp = NULL;
    ofpbuf_delete(buf);
    return error;
}

void
dpif_recv_wait(struct dpif *dpif)
{
    poll_fd_wait(dpif->fd, POLLIN);
}

void
dpif_get_netflow_ids(const struct dpif *dpif,
                     uint8_t *engine_type, uint8_t *engine_id)
{
    *engine_type = *engine_id = dpif->minor;
}

struct dpifmon {
    struct dpif *dpif;
    struct nl_sock *sock;
    int local_ifindex;
};

int
dpifmon_create(const char *datapath_name, struct dpifmon **monp)
{
    struct dpifmon *mon;
    char local_name[IFNAMSIZ];
    int error;

    mon = *monp = xmalloc(sizeof *mon);

    error = dpif_open(datapath_name, &mon->dpif);
    if (error) {
        goto error;
    }
    error = dpif_port_get_name(mon->dpif, ODPP_LOCAL,
                               local_name, sizeof local_name);
    if (error) {
        goto error_close_dpif;
    }

    mon->local_ifindex = if_nametoindex(local_name);
    if (!mon->local_ifindex) {
        error = errno;
        VLOG_WARN("could not get ifindex of %s device: %s",
                  local_name, strerror(errno));
        goto error_close_dpif;
    }

    error = nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0, &mon->sock);
    if (error) {
        VLOG_WARN("could not create rtnetlink socket: %s", strerror(error));
        goto error_close_dpif;
    }

    return 0;

error_close_dpif:
    dpif_close(mon->dpif);
error:
    free(mon);
    *monp = NULL;
    return error;
}

void
dpifmon_destroy(struct dpifmon *mon)
{
    if (mon) {
        dpif_close(mon->dpif);
        nl_sock_destroy(mon->sock);
    }
}

int
dpifmon_poll(struct dpifmon *mon, char **devnamep)
{
    static struct vlog_rate_limit slow_rl = VLOG_RATE_LIMIT_INIT(1, 5);
    static const struct nl_policy rtnlgrp_link_policy[] = {
        [IFLA_IFNAME] = { .type = NL_A_STRING },
        [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
    struct ofpbuf *buf;
    int error;

    *devnamep = NULL;
again:
    error = nl_sock_recv(mon->sock, &buf, false);
    switch (error) {
    case 0:
        if (!nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                             rtnlgrp_link_policy,
                             attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
            VLOG_WARN_RL(&slow_rl, "received bad rtnl message");
            error = ENOBUFS;
        } else {
            const char *devname = nl_attr_get_string(attrs[IFLA_IFNAME]);
            bool for_us;

            if (attrs[IFLA_MASTER]) {
                uint32_t master_ifindex = nl_attr_get_u32(attrs[IFLA_MASTER]);
                for_us = master_ifindex == mon->local_ifindex;
            } else {
                /* It's for us if that device is one of our ports. */
                struct odp_port port;
                for_us = !dpif_port_query_by_name(mon->dpif, devname, &port);
            }

            if (!for_us) {
                /* Not for us, try again. */
                ofpbuf_delete(buf);
                COVERAGE_INC(dpifmon_poll_false_wakeup);
                goto again;
            }
            COVERAGE_INC(dpifmon_poll_changed);
            *devnamep = xstrdup(devname);
        }
        ofpbuf_delete(buf);
        break;

    case EAGAIN:
        /* Nothing to do. */
        break;

    case ENOBUFS:
        VLOG_WARN_RL(&slow_rl, "dpifmon socket overflowed");
        break;

    default:
        VLOG_WARN_RL(&slow_rl, "error on dpifmon socket: %s", strerror(error));
        break;
    }
    return error;
}

void
dpifmon_run(struct dpifmon *mon UNUSED)
{
    /* Nothing to do in this implementation. */
}

void
dpifmon_wait(struct dpifmon *mon)
{
    nl_sock_wait(mon->sock, POLLIN);
}

static int get_openvswitch_major(void);
static int get_major(const char *target, int default_major);

static int
lookup_minor(const char *name, unsigned int *minor)
{
    struct ethtool_drvinfo drvinfo;
    struct ifreq ifr;
    int error;
    int sock;

    *minor = -1;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        VLOG_WARN("socket(AF_INET) failed: %s", strerror(errno));
        error = errno;
        goto error;
    }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) &drvinfo;

    memset(&drvinfo, 0, sizeof drvinfo);
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    if (ioctl(sock, SIOCETHTOOL, &ifr)) {
        VLOG_WARN("ioctl(SIOCETHTOOL) failed: %s", strerror(errno));
        error = errno;
        goto error_close_sock;
    }

    if (strcmp(drvinfo.driver, "openvswitch")) {
        VLOG_WARN("%s is not an openvswitch device", name);
        error = EOPNOTSUPP;
        goto error_close_sock;
    }

    if (!isdigit(drvinfo.bus_info[0])) {
        VLOG_WARN("%s ethtool info does not contain an openvswitch minor",
                  name);
        error = EPROTOTYPE;
        goto error_close_sock;
    }

    *minor = atoi(drvinfo.bus_info);
    close(sock);
    return 0;

error_close_sock:
    close(sock);
error:
    return error;
}

static int
make_openvswitch_device(unsigned int minor, char **fnp)
{
    dev_t dev = makedev(get_openvswitch_major(), minor);
    const char dirname[] = "/dev/net";
    struct stat s;
    char fn[128];

    *fnp = NULL;
    sprintf(fn, "%s/dp%d", dirname, minor);
    if (!stat(fn, &s)) {
        if (!S_ISCHR(s.st_mode)) {
            VLOG_WARN_RL(&error_rl, "%s is not a character device, fixing",
                         fn);
        } else if (s.st_rdev != dev) {
            VLOG_WARN_RL(&error_rl,
                         "%s is device %u:%u instead of %u:%u, fixing",
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


static int
get_openvswitch_major(void)
{
    static unsigned int openvswitch_major;
    if (!openvswitch_major) {
        enum { DEFAULT_MAJOR = 248 };
        openvswitch_major = get_major("openvswitch", DEFAULT_MAJOR);
    }
    return openvswitch_major;
}

static int
get_major(const char *target, int default_major)
{
    const char fn[] = "/proc/devices";
    char line[128];
    FILE *file;
    int ln;

    file = fopen(fn, "r");
    if (!file) {
        VLOG_ERR("opening %s failed (%s)", fn, strerror(errno));
        goto error;
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
            static bool warned;
            if (!warned) {
                VLOG_WARN("%s:%d: syntax error", fn, ln);
            }
            warned = true;
        }
    }

    VLOG_ERR("%s: %s major not found (is the module loaded?), using "
             "default major %d", fn, target, default_major);
error:
    VLOG_INFO("using default major %d for %s", default_major, target);
    return default_major;
}

static int
name_to_minor(const char *name, unsigned int *minor)
{
    if (!get_minor_from_name(name, minor)) {
        return 0;
    }
    return lookup_minor(name, minor);
}

static int
get_minor_from_name(const char *name, unsigned int *minor)
{
    if (!strncmp(name, "dp", 2) && isdigit(name[2])) {
        *minor = atoi(name + 2);
        return 0;
    } else {
        return EINVAL;
    }
}

static int
open_by_minor(unsigned int minor, struct dpif **dpifp)
{
    struct dpif *dpif;
    int error;
    char *fn;
    int fd;

    *dpifp = NULL;
    error = make_openvswitch_device(minor, &fn);
    if (error) {
        return error;
    }

    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        error = errno;
        VLOG_WARN("%s: open failed (%s)", fn, strerror(error));
        free(fn);
        return error;
    }
    free(fn);

    dpif = xmalloc(sizeof *dpif);
    dpif->name = xasprintf("dp%u", dpif->minor);
    dpif->minor = minor;
    dpif->fd = fd;
    *dpifp = dpif;
    return 0;
}

/* There is a tendency to construct odp_flow objects on the stack and to
 * forget to properly initialize their "actions" and "n_actions" members.
 * When this happens, we get memory corruption because the kernel
 * writes through the random pointer that is in the "actions" member.
 *
 * This function attempts to combat the problem by:
 *
 *      - Forcing a segfault if "actions" points to an invalid region (instead
 *        of just getting back EFAULT, which can be easily missed in the log).
 *
 *      - Storing a distinctive value that is likely to cause an
 *        easy-to-identify error later if it is dereferenced, etc.
 *
 *      - Triggering a warning on uninitialized memory from Valgrind if
 *        "actions" or "n_actions" was not initialized.
 */
static void
check_rw_odp_flow(struct odp_flow *flow)
{
    if (flow->n_actions) {
        memset(&flow->actions[0], 0xcc, sizeof flow->actions[0]);
    }
}
