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
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "dpif-provider.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "svec.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpif_linux

/* Datapath interface for the openvswitch Linux kernel module. */
struct dpif_linux {
    struct dpif dpif;
    int fd;

    /* Used by dpif_linux_get_all_names(). */
    char *local_ifname;
    int minor;

    /* Change notification. */
    int local_ifindex;          /* Ifindex of local port. */
    struct svec changed_ports;  /* Ports that have changed. */
    struct rtnetlink_notifier port_notifier;
    bool change_error;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

static int do_ioctl(const struct dpif *, int cmd, const void *arg);
static int lookup_minor(const char *name, int *minor);
static int finish_open(struct dpif *, const char *local_ifname);
static int get_openvswitch_major(void);
static int create_minor(const char *name, int minor, struct dpif **dpifp);
static int open_minor(int minor, struct dpif **dpifp);
static int make_openvswitch_device(int minor, char **fnp);
static void dpif_linux_port_changed(const struct rtnetlink_change *,
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
        retval = dpif_open(devname, &dpif);
        if (!retval) {
            svec_add(all_dps, devname);
            dpif_close(dpif);
        } else if (retval != ENODEV && !error) {
            error = retval;
        }
    }
    return error;
}

static int
dpif_linux_open(const char *name UNUSED, char *suffix, bool create,
                struct dpif **dpifp)
{
    int minor;

    minor = !strncmp(name, "dp", 2)
            && isdigit((unsigned char)name[2]) ? atoi(name + 2) : -1;
    if (create) {
        if (minor >= 0) {
            return create_minor(suffix, minor, dpifp);
        } else {
            /* Scan for unused minor number. */
            for (minor = 0; minor < ODP_MAX; minor++) {
                int error = create_minor(suffix, minor, dpifp);
                if (error != EBUSY) {
                    return error;
                }
            }

            /* All datapath numbers in use. */
            return ENOBUFS;
        }
    } else {
        struct dpif_linux *dpif;
        struct odp_port port;
        int error;

        if (minor < 0) {
            error = lookup_minor(suffix, &minor);
            if (error) {
                return error;
            }
        }

        error = open_minor(minor, dpifp);
        if (error) {
            return error;
        }
        dpif = dpif_linux_cast(*dpifp);

        /* We need the local port's ifindex for the poll function.  Start by
         * getting the local port's name. */
        memset(&port, 0, sizeof port);
        port.port = ODPP_LOCAL;
        if (ioctl(dpif->fd, ODP_PORT_QUERY, &port)) {
            error = errno;
            if (error != ENODEV) {
                VLOG_WARN("%s: probe returned unexpected error: %s",
                          dpif_name(*dpifp), strerror(error));
            }
            dpif_close(*dpifp);
            return error;
        }

        /* Then use that to finish up opening. */
        return finish_open(&dpif->dpif, port.devname);
    }
}

static void
dpif_linux_close(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    rtnetlink_notifier_unregister(&dpif->port_notifier);
    svec_destroy(&dpif->changed_ports);
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
dpif_linux_delete(struct dpif *dpif_)
{
    return do_ioctl(dpif_, ODP_DP_DESTROY, NULL);
}

static int
dpif_linux_get_stats(const struct dpif *dpif_, struct odp_stats *stats)
{
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
dpif_linux_port_add(struct dpif *dpif_, const char *devname, uint16_t flags,
                    uint16_t *port_no)
{
    struct odp_port port;
    int error;

    memset(&port, 0, sizeof port);
    strncpy(port.devname, devname, sizeof port.devname);
    port.flags = flags;
    error = do_ioctl(dpif_, ODP_PORT_ADD, &port);
    if (!error) {
        *port_no = port.port;
    }
    return error;
}

static int
dpif_linux_port_del(struct dpif *dpif_, uint16_t port_no)
{
    int tmp = port_no;
    return do_ioctl(dpif_, ODP_PORT_DEL, &tmp);
}

static int
dpif_linux_port_query_by_number(const struct dpif *dpif_, uint16_t port_no,
                          struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    port->port = port_no;
    return do_ioctl(dpif_, ODP_PORT_QUERY, port);
}

static int
dpif_linux_port_query_by_name(const struct dpif *dpif_, const char *devname,
                              struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    strncpy(port->devname, devname, sizeof port->devname);
    return do_ioctl(dpif_, ODP_PORT_QUERY, port);
}

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    return do_ioctl(dpif_, ODP_FLOW_FLUSH, NULL);
}

static int
dpif_linux_port_list(const struct dpif *dpif_, struct odp_port *ports, int n)
{
    struct odp_portvec pv;
    int error;

    pv.ports = ports;
    pv.n_ports = n;
    error = do_ioctl(dpif_, ODP_PORT_LIST, &pv);
    return error ? -error : pv.n_ports;
}

static int
dpif_linux_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);

    if (dpif->change_error) {
        dpif->change_error = false;
        svec_clear(&dpif->changed_ports);
        return ENOBUFS;
    } else if (dpif->changed_ports.n) {
        *devnamep = dpif->changed_ports.names[--dpif->changed_ports.n];
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
dpif_linux_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    if (dpif->changed_ports.n || dpif->change_error) {
        poll_immediate_wake();
    } else {
        rtnetlink_notifier_wait();
    }
}

static int
dpif_linux_port_group_get(const struct dpif *dpif_, int group,
                          uint16_t ports[], int n)
{
    struct odp_port_group pg;
    int error;

    assert(n <= UINT16_MAX);
    pg.group = group;
    pg.ports = ports;
    pg.n_ports = n;
    error = do_ioctl(dpif_, ODP_PORT_GROUP_GET, &pg);
    return error ? -error : pg.n_ports;
}

static int
dpif_linux_port_group_set(struct dpif *dpif_, int group,
                          const uint16_t ports[], int n)
{
    struct odp_port_group pg;

    assert(n <= UINT16_MAX);
    pg.group = group;
    pg.ports = (uint16_t *) ports;
    pg.n_ports = n;
    return do_ioctl(dpif_, ODP_PORT_GROUP_SET, &pg);
}

static int
dpif_linux_flow_get(const struct dpif *dpif_, struct odp_flow flows[], int n)
{
    struct odp_flowvec fv;
    fv.flows = flows;
    fv.n_flows = n;
    return do_ioctl(dpif_, ODP_FLOW_GET, &fv);
}

static int
dpif_linux_flow_put(struct dpif *dpif_, struct odp_flow_put *put)
{
    return do_ioctl(dpif_, ODP_FLOW_PUT, put);
}

static int
dpif_linux_flow_del(struct dpif *dpif_, struct odp_flow *flow)
{
    return do_ioctl(dpif_, ODP_FLOW_DEL, flow);
}

static int
dpif_linux_flow_list(const struct dpif *dpif_, struct odp_flow flows[], int n)
{
    struct odp_flowvec fv;
    int error;

    fv.flows = flows;
    fv.n_flows = n;
    error = do_ioctl(dpif_, ODP_FLOW_LIST, &fv);
    return error ? -error : fv.n_flows;
}

static int
dpif_linux_execute(struct dpif *dpif_, uint16_t in_port,
                   const union odp_action actions[], int n_actions,
                   const struct ofpbuf *buf)
{
    struct odp_execute execute;
    memset(&execute, 0, sizeof execute);
    execute.in_port = in_port;
    execute.actions = (union odp_action *) actions;
    execute.n_actions = n_actions;
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
dpif_linux_recv(struct dpif *dpif_, struct ofpbuf **bufp)
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
    } else if (retval >= sizeof(struct odp_msg)) {
        struct odp_msg *msg = buf->data;
        if (msg->length <= retval) {
            buf->size += retval;
            *bufp = buf;
            return 0;
        } else {
            VLOG_WARN_RL(&error_rl, "%s: discarding message truncated "
                         "from %"PRIu32" bytes to %d",
                         dpif_name(dpif_), msg->length, retval);
            error = ERANGE;
        }
    } else if (!retval) {
        VLOG_WARN_RL(&error_rl, "%s: unexpected end of file", dpif_name(dpif_));
        error = EPROTO;
    } else {
        VLOG_WARN_RL(&error_rl,
                     "%s: discarding too-short message (%d bytes)",
                     dpif_name(dpif_), retval);
        error = ERANGE;
    }

    *bufp = NULL;
    ofpbuf_delete(buf);
    return error;
}

static void
dpif_linux_recv_wait(struct dpif *dpif_)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    poll_fd_wait(dpif->fd, POLLIN);
}

const struct dpif_class dpif_linux_class = {
    "",                         /* This is the default class. */
    "linux",
    NULL,
    NULL,
    dpif_linux_enumerate,
    dpif_linux_open,
    dpif_linux_close,
    dpif_linux_get_all_names,
    dpif_linux_delete,
    dpif_linux_get_stats,
    dpif_linux_get_drop_frags,
    dpif_linux_set_drop_frags,
    dpif_linux_port_add,
    dpif_linux_port_del,
    dpif_linux_port_query_by_number,
    dpif_linux_port_query_by_name,
    dpif_linux_port_list,
    dpif_linux_port_poll,
    dpif_linux_port_poll_wait,
    dpif_linux_port_group_get,
    dpif_linux_port_group_set,
    dpif_linux_flow_get,
    dpif_linux_flow_put,
    dpif_linux_flow_del,
    dpif_linux_flow_flush,
    dpif_linux_flow_list,
    dpif_linux_execute,
    dpif_linux_recv_get_mask,
    dpif_linux_recv_set_mask,
    dpif_linux_recv,
    dpif_linux_recv_wait,
};

static int get_openvswitch_major(void);
static int get_major(const char *target);

static int
do_ioctl(const struct dpif *dpif_, int cmd, const void *arg)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    return ioctl(dpif->fd, cmd, arg) ? errno : 0;
}

static int
lookup_minor(const char *name, int *minorp)
{
    struct ethtool_drvinfo drvinfo;
    int minor, port_no;
    struct ifreq ifr;
    int error;
    int sock;

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

    if (sscanf(drvinfo.bus_info, "%d.%d", &minor, &port_no) != 2) {
        VLOG_WARN("%s ethtool bus_info has unexpected format", name);
        error = EPROTOTYPE;
        goto error_close_sock;
    } else if (port_no != ODPP_LOCAL) {
        /* This is an Open vSwitch device but not the local port.  We
         * intentionally support only using the name of the local port as the
         * name of a datapath; otherwise, it would be too difficult to
         * enumerate all the names of a datapath. */
        error = EOPNOTSUPP;
        goto error_close_sock;
    }

    *minorp = minor;
    close(sock);
    return 0;

error_close_sock:
    close(sock);
error:
    return error;
}

static int
make_openvswitch_device(int minor, char **fnp)
{
    const char dirname[] = "/dev/net";
    int major;
    dev_t dev;
    struct stat s;
    char fn[128];

    major = get_openvswitch_major();
    if (major < 0) {
        return -major;
    }
    dev = makedev(major, minor);

    *fnp = NULL;
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
            static bool warned;
            if (!warned) {
                VLOG_WARN("%s:%d: syntax error", fn, ln);
            }
            warned = true;
        }
    }

    fclose(file);

    VLOG_ERR("%s: %s major not found (is the module loaded?)", fn, target);
    return -ENODEV;
}

static int
finish_open(struct dpif *dpif_, const char *local_ifname)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    dpif->local_ifname = strdup(local_ifname);
    dpif->local_ifindex = if_nametoindex(local_ifname);
    if (!dpif->local_ifindex) {
        int error = errno;
        dpif_close(dpif_);
        VLOG_WARN("could not get ifindex of %s device: %s",
                  local_ifname, strerror(errno));
        return error;
    }
    return 0;
}

static int
create_minor(const char *name, int minor, struct dpif **dpifp)
{
    int error = open_minor(minor, dpifp);
    if (!error) {
        error = do_ioctl(*dpifp, ODP_DP_CREATE, name);
        if (!error) {
            error = finish_open(*dpifp, name);
        } else {
            dpif_close(*dpifp);
        }
    }
    return error;
}

static int
open_minor(int minor, struct dpif **dpifp)
{
    int error;
    char *fn;
    int fd;

    error = make_openvswitch_device(minor, &fn);
    if (error) {
        return error;
    }

    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd >= 0) {
        struct dpif_linux *dpif = xmalloc(sizeof *dpif);
        error = rtnetlink_notifier_register(&dpif->port_notifier,
                                           dpif_linux_port_changed, dpif);
        if (!error) {
            char *name;

            name = xasprintf("dp%d", minor);
            dpif_init(&dpif->dpif, &dpif_linux_class, name, minor, minor);
            free(name);

            dpif->fd = fd;
            dpif->local_ifname = NULL;
            dpif->minor = minor;
            dpif->local_ifindex = 0;
            svec_init(&dpif->changed_ports);
            dpif->change_error = false;
            *dpifp = &dpif->dpif;
        } else {
            free(dpif);
        }
    } else {
        error = errno;
        VLOG_WARN("%s: open failed (%s)", fn, strerror(error));
    }
    free(fn);

    return error;
}

static void
dpif_linux_port_changed(const struct rtnetlink_change *change, void *dpif_)
{
    struct dpif_linux *dpif = dpif_;

    if (change) {
        if (change->master_ifindex == dpif->local_ifindex
            && (change->nlmsg_type == RTM_NEWLINK
                || change->nlmsg_type == RTM_DELLINK))
        {
            /* Our datapath changed, either adding a new port or deleting an
             * existing one. */
            if (!svec_contains(&dpif->changed_ports, change->ifname)) {
                svec_add(&dpif->changed_ports, change->ifname);
                svec_sort(&dpif->changed_ports);
            }
        }
    } else {
        dpif->change_error = true;
    }
}
