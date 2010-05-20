/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "netdev.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "shash.h"
#include "svec.h"
#include "util.h"
#include "xfif-provider.h"

#include "vlog.h"
#define THIS_MODULE VLM_xfif_linux

/* Datapath interface for the openvswitch Linux kernel module. */
struct xfif_linux {
    struct xfif xfif;
    int fd;

    /* Used by xfif_linux_get_all_names(). */
    char *local_ifname;
    int minor;

    /* Change notification. */
    int local_ifindex;          /* Ifindex of local port. */
    struct shash changed_ports;  /* Ports that have changed. */
    struct rtnetlink_notifier port_notifier;
    bool change_error;
};

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

static int do_ioctl(const struct xfif *, int cmd, const void *arg);
static int lookup_minor(const char *name, int *minor);
static int finish_open(struct xfif *, const char *local_ifname);
static int get_openvswitch_major(void);
static int create_minor(const char *name, int minor, struct xfif **xfifp);
static int open_minor(int minor, struct xfif **xfifp);
static int make_openvswitch_device(int minor, char **fnp);
static void xfif_linux_port_changed(const struct rtnetlink_change *,
                                    void *xfif);

static struct xfif_linux *
xfif_linux_cast(const struct xfif *xfif)
{
    xfif_assert_class(xfif, &xfif_linux_class);
    return CONTAINER_OF(xfif, struct xfif_linux, xfif);
}

static int
xfif_linux_enumerate(struct svec *all_dps)
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
    for (i = 0; i < XFLOW_MAX; i++) {
        struct xfif *xfif;
        char devname[16];
        int retval;

        sprintf(devname, "dp%d", i);
        retval = xfif_open(devname, "system", &xfif);
        if (!retval) {
            svec_add(all_dps, devname);
            xfif_uninit(xfif, true);
        } else if (retval != ENODEV && !error) {
            error = retval;
        }
    }
    return error;
}

static int
xfif_linux_open(const char *name, const char *type OVS_UNUSED, bool create,
                struct xfif **xfifp)
{
    int minor;

    minor = !strncmp(name, "dp", 2)
            && isdigit((unsigned char)name[2]) ? atoi(name + 2) : -1;
    if (create) {
        if (minor >= 0) {
            return create_minor(name, minor, xfifp);
        } else {
            /* Scan for unused minor number. */
            for (minor = 0; minor < XFLOW_MAX; minor++) {
                int error = create_minor(name, minor, xfifp);
                if (error != EBUSY) {
                    return error;
                }
            }

            /* All datapath numbers in use. */
            return ENOBUFS;
        }
    } else {
        struct xfif_linux *xfif;
        struct xflow_port port;
        int error;

        if (minor < 0) {
            error = lookup_minor(name, &minor);
            if (error) {
                return error;
            }
        }

        error = open_minor(minor, xfifp);
        if (error) {
            return error;
        }
        xfif = xfif_linux_cast(*xfifp);

        /* We need the local port's ifindex for the poll function.  Start by
         * getting the local port's name. */
        memset(&port, 0, sizeof port);
        port.port = XFLOWP_LOCAL;
        if (ioctl(xfif->fd, XFLOW_PORT_QUERY, &port)) {
            error = errno;
            if (error != ENODEV) {
                VLOG_WARN("%s: probe returned unexpected error: %s",
                          xfif_name(*xfifp), strerror(error));
            }
            xfif_uninit(*xfifp, true);
            return error;
        }

        /* Then use that to finish up opening. */
        return finish_open(&xfif->xfif, port.devname);
    }
}

static void
xfif_linux_close(struct xfif *xfif_)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    rtnetlink_notifier_unregister(&xfif->port_notifier);
    shash_destroy(&xfif->changed_ports);
    free(xfif->local_ifname);
    close(xfif->fd);
    free(xfif);
}

static int
xfif_linux_get_all_names(const struct xfif *xfif_, struct svec *all_names)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);

    svec_add_nocopy(all_names, xasprintf("dp%d", xfif->minor));
    svec_add(all_names, xfif->local_ifname);
    return 0;
}

static int
xfif_linux_destroy(struct xfif *xfif_)
{
    struct xflow_port *ports;
    size_t n_ports;
    int err;
    int i;

    err = xfif_port_list(xfif_, &ports, &n_ports);
    if (err) {
        return err;
    }

    for (i = 0; i < n_ports; i++) {
        if (ports[i].port != XFLOWP_LOCAL) {
            err = do_ioctl(xfif_, XFLOW_VPORT_DEL, ports[i].devname);
            if (err) {
                VLOG_WARN_RL(&error_rl, "%s: error deleting port %s (%s)",
                             xfif_name(xfif_), ports[i].devname, strerror(err));
            }
        }
    }

    free(ports);

    return do_ioctl(xfif_, XFLOW_DP_DESTROY, NULL);
}

static int
xfif_linux_get_stats(const struct xfif *xfif_, struct xflow_stats *stats)
{
    memset(stats, 0, sizeof *stats);
    return do_ioctl(xfif_, XFLOW_DP_STATS, stats);
}

static int
xfif_linux_get_drop_frags(const struct xfif *xfif_, bool *drop_fragsp)
{
    int drop_frags;
    int error;

    error = do_ioctl(xfif_, XFLOW_GET_DROP_FRAGS, &drop_frags);
    if (!error) {
        *drop_fragsp = drop_frags & 1;
    }
    return error;
}

static int
xfif_linux_set_drop_frags(struct xfif *xfif_, bool drop_frags)
{
    int drop_frags_int = drop_frags;
    return do_ioctl(xfif_, XFLOW_SET_DROP_FRAGS, &drop_frags_int);
}

static int
xfif_linux_port_add(struct xfif *xfif_, const char *devname, uint16_t flags,
                    uint16_t *port_no)
{
    struct xflow_port port;
    int error;

    memset(&port, 0, sizeof port);
    strncpy(port.devname, devname, sizeof port.devname);
    port.flags = flags;
    error = do_ioctl(xfif_, XFLOW_PORT_ATTACH, &port);
    if (!error) {
        *port_no = port.port;
    }
    return error;
}

static int
xfif_linux_port_del(struct xfif *xfif_, uint16_t port_no)
{
    int tmp = port_no;
    int err;
    struct xflow_port port;

    err = xfif_port_query_by_number(xfif_, port_no, &port);
    if (err) {
        return err;
    }

    err = do_ioctl(xfif_, XFLOW_PORT_DETACH, &tmp);
    if (err) {
        return err;
    }

    if (!netdev_is_open(port.devname)) {
        /* Try deleting the port if no one has it open.  This shouldn't
         * actually be necessary unless the config changed while we weren't
         * running but it won't hurt anything if the port is already gone. */
        do_ioctl(xfif_, XFLOW_VPORT_DEL, port.devname);
    }

    return 0;
}

static int
xfif_linux_port_query_by_number(const struct xfif *xfif_, uint16_t port_no,
                          struct xflow_port *port)
{
    memset(port, 0, sizeof *port);
    port->port = port_no;
    return do_ioctl(xfif_, XFLOW_PORT_QUERY, port);
}

static int
xfif_linux_port_query_by_name(const struct xfif *xfif_, const char *devname,
                              struct xflow_port *port)
{
    memset(port, 0, sizeof *port);
    strncpy(port->devname, devname, sizeof port->devname);
    return do_ioctl(xfif_, XFLOW_PORT_QUERY, port);
}

static int
xfif_linux_flow_flush(struct xfif *xfif_)
{
    return do_ioctl(xfif_, XFLOW_FLOW_FLUSH, NULL);
}

static int
xfif_linux_port_list(const struct xfif *xfif_, struct xflow_port *ports, int n)
{
    struct xflow_portvec pv;
    int error;

    pv.ports = ports;
    pv.n_ports = n;
    error = do_ioctl(xfif_, XFLOW_PORT_LIST, &pv);
    return error ? -error : pv.n_ports;
}

static int
xfif_linux_port_poll(const struct xfif *xfif_, char **devnamep)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);

    if (xfif->change_error) {
        xfif->change_error = false;
        shash_clear(&xfif->changed_ports);
        return ENOBUFS;
    } else if (!shash_is_empty(&xfif->changed_ports)) {
        struct shash_node *node = shash_first(&xfif->changed_ports);
        *devnamep = xstrdup(node->name);
        shash_delete(&xfif->changed_ports, node);
        return 0;
    } else {
        return EAGAIN;
    }
}

static void
xfif_linux_port_poll_wait(const struct xfif *xfif_)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    if (!shash_is_empty(&xfif->changed_ports) || xfif->change_error) {
        poll_immediate_wake();
    } else {
        rtnetlink_notifier_wait();
    }
}

static int
xfif_linux_port_group_get(const struct xfif *xfif_, int group,
                          uint16_t ports[], int n)
{
    struct xflow_port_group pg;
    int error;

    assert(n <= UINT16_MAX);
    pg.group = group;
    pg.ports = ports;
    pg.n_ports = n;
    error = do_ioctl(xfif_, XFLOW_PORT_GROUP_GET, &pg);
    return error ? -error : pg.n_ports;
}

static int
xfif_linux_port_group_set(struct xfif *xfif_, int group,
                          const uint16_t ports[], int n)
{
    struct xflow_port_group pg;

    assert(n <= UINT16_MAX);
    pg.group = group;
    pg.ports = (uint16_t *) ports;
    pg.n_ports = n;
    return do_ioctl(xfif_, XFLOW_PORT_GROUP_SET, &pg);
}

static int
xfif_linux_flow_get(const struct xfif *xfif_, struct xflow_flow flows[], int n)
{
    struct xflow_flowvec fv;
    fv.flows = flows;
    fv.n_flows = n;
    return do_ioctl(xfif_, XFLOW_FLOW_GET, &fv);
}

static int
xfif_linux_flow_put(struct xfif *xfif_, struct xflow_flow_put *put)
{
    return do_ioctl(xfif_, XFLOW_FLOW_PUT, put);
}

static int
xfif_linux_flow_del(struct xfif *xfif_, struct xflow_flow *flow)
{
    return do_ioctl(xfif_, XFLOW_FLOW_DEL, flow);
}

static int
xfif_linux_flow_list(const struct xfif *xfif_, struct xflow_flow flows[], int n)
{
    struct xflow_flowvec fv;
    int error;

    fv.flows = flows;
    fv.n_flows = n;
    error = do_ioctl(xfif_, XFLOW_FLOW_LIST, &fv);
    return error ? -error : fv.n_flows;
}

static int
xfif_linux_execute(struct xfif *xfif_, uint16_t in_port,
                   const union xflow_action actions[], int n_actions,
                   const struct ofpbuf *buf)
{
    struct xflow_execute execute;
    memset(&execute, 0, sizeof execute);
    execute.in_port = in_port;
    execute.actions = (union xflow_action *) actions;
    execute.n_actions = n_actions;
    execute.data = buf->data;
    execute.length = buf->size;
    return do_ioctl(xfif_, XFLOW_EXECUTE, &execute);
}

static int
xfif_linux_recv_get_mask(const struct xfif *xfif_, int *listen_mask)
{
    return do_ioctl(xfif_, XFLOW_GET_LISTEN_MASK, listen_mask);
}

static int
xfif_linux_recv_set_mask(struct xfif *xfif_, int listen_mask)
{
    return do_ioctl(xfif_, XFLOW_SET_LISTEN_MASK, &listen_mask);
}

static int
xfif_linux_get_sflow_probability(const struct xfif *xfif_,
                                 uint32_t *probability)
{
    return do_ioctl(xfif_, XFLOW_GET_SFLOW_PROBABILITY, probability);
}

static int
xfif_linux_set_sflow_probability(struct xfif *xfif_, uint32_t probability)
{
    return do_ioctl(xfif_, XFLOW_SET_SFLOW_PROBABILITY, &probability);
}

static int
xfif_linux_recv(struct xfif *xfif_, struct ofpbuf **bufp)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    struct ofpbuf *buf;
    int retval;
    int error;

    buf = ofpbuf_new(65536 + XFIF_RECV_MSG_PADDING);
    ofpbuf_reserve(buf, XFIF_RECV_MSG_PADDING);
    retval = read(xfif->fd, ofpbuf_tail(buf), ofpbuf_tailroom(buf));
    if (retval < 0) {
        error = errno;
        if (error != EAGAIN) {
            VLOG_WARN_RL(&error_rl, "%s: read failed: %s",
                         xfif_name(xfif_), strerror(error));
        }
    } else if (retval >= sizeof(struct xflow_msg)) {
        struct xflow_msg *msg = buf->data;
        if (msg->length <= retval) {
            buf->size += retval;
            *bufp = buf;
            return 0;
        } else {
            VLOG_WARN_RL(&error_rl, "%s: discarding message truncated "
                         "from %"PRIu32" bytes to %d",
                         xfif_name(xfif_), msg->length, retval);
            error = ERANGE;
        }
    } else if (!retval) {
        VLOG_WARN_RL(&error_rl, "%s: unexpected end of file", xfif_name(xfif_));
        error = EPROTO;
    } else {
        VLOG_WARN_RL(&error_rl,
                     "%s: discarding too-short message (%d bytes)",
                     xfif_name(xfif_), retval);
        error = ERANGE;
    }

    *bufp = NULL;
    ofpbuf_delete(buf);
    return error;
}

static void
xfif_linux_recv_wait(struct xfif *xfif_)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    poll_fd_wait(xfif->fd, POLLIN);
}

const struct xfif_class xfif_linux_class = {
    "system",
    NULL,
    NULL,
    xfif_linux_enumerate,
    xfif_linux_open,
    xfif_linux_close,
    xfif_linux_get_all_names,
    xfif_linux_destroy,
    xfif_linux_get_stats,
    xfif_linux_get_drop_frags,
    xfif_linux_set_drop_frags,
    xfif_linux_port_add,
    xfif_linux_port_del,
    xfif_linux_port_query_by_number,
    xfif_linux_port_query_by_name,
    xfif_linux_port_list,
    xfif_linux_port_poll,
    xfif_linux_port_poll_wait,
    xfif_linux_port_group_get,
    xfif_linux_port_group_set,
    xfif_linux_flow_get,
    xfif_linux_flow_put,
    xfif_linux_flow_del,
    xfif_linux_flow_flush,
    xfif_linux_flow_list,
    xfif_linux_execute,
    xfif_linux_recv_get_mask,
    xfif_linux_recv_set_mask,
    xfif_linux_get_sflow_probability,
    xfif_linux_set_sflow_probability,
    xfif_linux_recv,
    xfif_linux_recv_wait,
};

static int get_openvswitch_major(void);
static int get_major(const char *target);

static int
do_ioctl(const struct xfif *xfif_, int cmd, const void *arg)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    return ioctl(xfif->fd, cmd, arg) ? errno : 0;
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
    } else if (port_no != XFLOWP_LOCAL) {
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
finish_open(struct xfif *xfif_, const char *local_ifname)
{
    struct xfif_linux *xfif = xfif_linux_cast(xfif_);
    xfif->local_ifname = xstrdup(local_ifname);
    xfif->local_ifindex = if_nametoindex(local_ifname);
    if (!xfif->local_ifindex) {
        int error = errno;
        xfif_uninit(xfif_, true);
        VLOG_WARN("could not get ifindex of %s device: %s",
                  local_ifname, strerror(errno));
        return error;
    }
    return 0;
}

static int
create_minor(const char *name, int minor, struct xfif **xfifp)
{
    int error = open_minor(minor, xfifp);
    if (!error) {
        error = do_ioctl(*xfifp, XFLOW_DP_CREATE, name);
        if (!error) {
            error = finish_open(*xfifp, name);
        } else {
            xfif_uninit(*xfifp, true);
        }
    }
    return error;
}

static int
open_minor(int minor, struct xfif **xfifp)
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
        struct xfif_linux *xfif = xmalloc(sizeof *xfif);
        error = rtnetlink_notifier_register(&xfif->port_notifier,
                                           xfif_linux_port_changed, xfif);
        if (!error) {
            char *name;

            name = xasprintf("dp%d", minor);
            xfif_init(&xfif->xfif, &xfif_linux_class, name, minor, minor);
            free(name);

            xfif->fd = fd;
            xfif->local_ifname = NULL;
            xfif->minor = minor;
            xfif->local_ifindex = 0;
            shash_init(&xfif->changed_ports);
            xfif->change_error = false;
            *xfifp = &xfif->xfif;
        } else {
            free(xfif);
        }
    } else {
        error = errno;
        VLOG_WARN("%s: open failed (%s)", fn, strerror(error));
    }
    free(fn);

    return error;
}

static void
xfif_linux_port_changed(const struct rtnetlink_change *change, void *xfif_)
{
    struct xfif_linux *xfif = xfif_;

    if (change) {
        if (change->master_ifindex == xfif->local_ifindex
            && (change->nlmsg_type == RTM_NEWLINK
                || change->nlmsg_type == RTM_DELLINK))
        {
            /* Our datapath changed, either adding a new port or deleting an
             * existing one. */
            shash_add_once(&xfif->changed_ports, change->ifname, NULL);
        }
    } else {
        xfif->change_error = true;
    }
}
