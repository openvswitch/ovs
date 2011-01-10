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
#include "dpif.h"

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
static int lookup_minor(const char *name, int *minor);
static int finish_open(struct dpif *, const char *local_ifname);
static int get_openvswitch_major(void);
static int create_minor(const char *name, int minor, struct dpif **dpifp);
static int open_minor(int minor, struct dpif **dpifp);
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
    int minor;

    minor = !strncmp(name, "dp", 2)
            && isdigit((unsigned char)name[2]) ? atoi(name + 2) : -1;
    if (create) {
        if (minor >= 0) {
            return create_minor(name, minor, dpifp);
        } else {
            /* Scan for unused minor number. */
            for (minor = 0; minor < ODP_MAX; minor++) {
                int error = create_minor(name, minor, dpifp);
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
            error = lookup_minor(name, &minor);
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
        if (ioctl(dpif->fd, ODP_VPORT_QUERY, &port)) {
            error = errno;
            if (error != ENODEV) {
                VLOG_WARN("%s: probe returned unexpected error: %s",
                          dpif_name(*dpifp), strerror(error));
            }
            dpif_uninit(*dpifp, true);
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

static void
translate_vport_type_to_netdev_type(struct odp_port *port)
{
    char *type = port->type;

    if (!strcmp(type, "netdev")) {
        ovs_strlcpy(type, "system", sizeof port->type);
    } else if (!strcmp(type, "gre")) {
        const struct tnl_port_config *config;

        config = (struct tnl_port_config *)port->config;
        if (config->flags & TNL_F_IPSEC) {
            ovs_strlcpy(type, "ipsec_gre", sizeof port->type);
        }
    }
}

static void
translate_netdev_type_to_vport_type(struct odp_port *port)
{
    char *type = port->type;

    if (!strcmp(type, "system")) {
        ovs_strlcpy(type, "netdev", sizeof port->type);
    } else if (!strcmp(type, "ipsec_gre")) {
        ovs_strlcpy(type, "gre", sizeof port->type);
    }
}

static int
dpif_linux_port_add(struct dpif *dpif, struct netdev *netdev,
                    uint16_t *port_nop)
{
    const char *name = netdev_get_name(netdev);
    const char *type = netdev_get_type(netdev);
    struct odp_port port;
    int error;

    memset(&port, 0, sizeof port);
    strncpy(port.devname, name, sizeof port.devname);
    strncpy(port.type, type, sizeof port.type);
    netdev_vport_get_config(netdev, port.config);
    translate_netdev_type_to_vport_type(&port);

    error = do_ioctl(dpif, ODP_VPORT_ATTACH, &port);
    if (!error) {
        *port_nop = port.port;
    }

    return error;
}

static int
dpif_linux_port_del(struct dpif *dpif_, uint16_t port_no_)
{
    int port_no = port_no_;     /* Kernel expects an "int". */
    return do_ioctl(dpif_, ODP_VPORT_DETACH, &port_no);
}

static int
dpif_linux_port_query__(const struct dpif *dpif, struct odp_port *port)
{
    int error = do_ioctl(dpif, ODP_VPORT_QUERY, port);
    if (!error) {
        translate_vport_type_to_netdev_type(port);
    }
    return error;
}

static int
dpif_linux_port_query_by_number(const struct dpif *dpif, uint16_t port_no,
                                struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    port->port = port_no;
    return dpif_linux_port_query__(dpif, port);
}

static int
dpif_linux_port_query_by_name(const struct dpif *dpif, const char *devname,
                              struct odp_port *port)
{
    memset(port, 0, sizeof *port);
    strncpy(port->devname, devname, sizeof port->devname);
    return dpif_linux_port_query__(dpif, port);
}

static int
dpif_linux_flow_flush(struct dpif *dpif_)
{
    return do_ioctl(dpif_, ODP_FLOW_FLUSH, NULL);
}

static int
dpif_linux_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct odp_vport_dump));
    return 0;
}

static int
dpif_linux_port_dump_next(const struct dpif *dpif, void *state,
                          struct odp_port *port)
{
    struct odp_vport_dump *dump = state;
    int error;

    dump->port = port;
    error = do_ioctl(dpif, ODP_VPORT_DUMP, dump);
    if (error) {
        return error;
    } else if (port->devname[0] == '\0') {
        return EOF;
    } else {
        dump->port_no = port->port + 1;
        translate_vport_type_to_netdev_type(port);
        return 0;
    }
}

static int
dpif_linux_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state)
{
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
dpif_linux_flow_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct odp_flow_dump));
    return 0;
}

static int
dpif_linux_flow_dump_next(const struct dpif *dpif, void *state,
                          struct odp_flow *flow)
{
    struct odp_flow_dump *dump = state;
    int error;

    dump->flow = flow;
    error = do_ioctl(dpif, ODP_FLOW_DUMP, dump);
    return error ? error : flow->flags & ODPFF_EOF ? EOF : 0;
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
finish_open(struct dpif *dpif_, const char *local_ifname)
{
    struct dpif_linux *dpif = dpif_linux_cast(dpif_);
    dpif->local_ifname = xstrdup(local_ifname);
    dpif->local_ifindex = if_nametoindex(local_ifname);
    if (!dpif->local_ifindex) {
        int error = errno;
        dpif_uninit(dpif_, true);
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
            dpif_uninit(*dpifp, true);
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
        error = rtnetlink_link_notifier_register(&dpif->port_notifier,
                                                 dpif_linux_port_changed,
                                                 dpif);
        if (!error) {
            char *name;

            name = xasprintf("dp%d", minor);
            dpif_init(&dpif->dpif, &dpif_linux_class, name, minor, minor);
            free(name);

            dpif->fd = fd;
            dpif->local_ifname = NULL;
            dpif->minor = minor;
            dpif->local_ifindex = 0;
            shash_init(&dpif->changed_ports);
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
