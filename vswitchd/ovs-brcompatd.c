/* Copyright (c) 2008, 2009 Nicira Networks
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

#include <asm/param.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "cfg.h"
#include "command-line.h"
#include "coverage.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "fault.h"
#include "leak-checker.h"
#include "netdev.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openvswitch/brcompat-netlink.h"
#include "packets.h"
#include "poll-loop.h"
#include "process.h"
#include "signals.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_brcompatd


/* xxx Just hangs if datapath is rmmod/insmod.  Learn to reconnect? */

/* Actions to modify bridge compatibility configuration. */
enum bmc_action {
    BMC_ADD_DP,
    BMC_DEL_DP,
    BMC_ADD_PORT,
    BMC_DEL_PORT
};

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 60);

/* Maximum number of milliseconds to wait for the config file to be
 * unlocked.  If set to zero, no waiting will occur. */
static int lock_timeout = 500;

/* Maximum number of milliseconds to wait before pruning port entries that 
 * no longer exist.  If set to zero, ports are never pruned. */
static int prune_timeout = 5000;

/* Config file shared with ovs-vswitchd (usually ovs-vswitchd.conf). */
static char *config_file;

/* Shell command to execute (via popen()) to send a control command to the
 * running ovs-vswitchd process.  The string must contain one instance of %s,
 * which is replaced by the control command. */
static char *appctl_command;

/* Netlink socket to listen for interface changes. */
static struct nl_sock *rtnl_sock;

/* Netlink socket to bridge compatibility kernel module. */
static struct nl_sock *brc_sock;

/* The Generic Netlink family number used for bridge compatibility. */
static int brc_family;

static const struct nl_policy brc_multicast_policy[] = {
    [BRC_GENL_A_MC_GROUP] = {.type = NL_A_U32 }
};

static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
    [IFLA_MASTER] = { .type = NL_A_U32, .optional = true },
};

static int
lookup_brc_multicast_group(int *multicast_group)
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    struct nlattr *attrs[ARRAY_SIZE(brc_multicast_policy)];
    int retval;

    retval = nl_sock_create(NETLINK_GENERIC, 0, 0, 0, &sock);
    if (retval) {
        return retval;
    }
    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, sock, 0, brc_family,
            NLM_F_REQUEST, BRC_GENL_C_QUERY_MC, 1);
    retval = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (retval) {
        nl_sock_destroy(sock);
        return retval;
    }
    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         brc_multicast_policy, attrs,
                         ARRAY_SIZE(brc_multicast_policy))) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return EPROTO;
    }
    *multicast_group = nl_attr_get_u32(attrs[BRC_GENL_A_MC_GROUP]);
    nl_sock_destroy(sock);
    ofpbuf_delete(reply);

    return 0;
}

/* Opens a socket for brcompat notifications.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
brc_open(struct nl_sock **sock)
{
    int multicast_group = 0;
    int retval;

    retval = nl_lookup_genl_family(BRC_GENL_FAMILY_NAME, &brc_family);
    if (retval) {
        return retval;
    }

    retval = lookup_brc_multicast_group(&multicast_group);
    if (retval) {
        return retval;
    }

    retval = nl_sock_create(NETLINK_GENERIC, multicast_group, 0, 0, sock);
    if (retval) {
        return retval;
    }

    return 0;
}

static const struct nl_policy brc_dp_policy[] = {
    [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING },
};

static bool
bridge_exists(const char *name)
{
    return cfg_has_section("bridge.%s", name);
}

static int
execute_appctl_command(const char *unixctl_command, char **output)
{
    char *stdout_log, *stderr_log;
    int error, status;
    char *argv[5];

    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = xasprintf(appctl_command, unixctl_command);
    argv[3] = NULL;

    /* Run process and log status. */
    error = process_run_capture(argv, &stdout_log, &stderr_log, &status);
    if (error) {
        VLOG_ERR("failed to execute %s command via ovs-appctl: %s",
                 unixctl_command, strerror(error));
    } else if (status) {
        char *msg = process_status_msg(status);
        VLOG_ERR("ovs-appctl exited with error (%s)", msg);
        free(msg);
        error = ECHILD;
    }

    /* Deal with stdout_log. */
    if (output) {
        *output = stdout_log;
    } else {
        free(stdout_log);
    }

    /* Deal with stderr_log */
    if (stderr_log && *stderr_log) {
        VLOG_INFO("ovs-appctl wrote to stderr:\n%s", stderr_log);
    }
    free(stderr_log);

    free(argv[2]);

    return error;
}

static int
rewrite_and_reload_config(void)
{
    if (cfg_is_dirty()) {
        int error1 = cfg_write();
        int error2 = cfg_read();
        long long int reload_start = time_msec();
        int error3 = execute_appctl_command("vswitchd/reload", NULL);
        long long int elapsed = time_msec() - reload_start;
        COVERAGE_INC(brcompatd_reload);
        if (elapsed > 0) {
            VLOG_INFO("reload command executed in %lld ms", elapsed);
        }
        return error1 ? error1 : error2 ? error2 : error3;
    }
    return 0;
}

static void
do_get_bridge_parts(const char *bridge, struct svec *parts, int vlan,
                    bool break_down_bonds)
{
    struct svec ports;
    int i;

    svec_init(&ports);
    cfg_get_all_keys(&ports, "bridge.%s.port", bridge);
    for (i = 0; i < ports.n; i++) {
        const char *port_name = ports.names[i];
        if (vlan >= 0) {
            int port_vlan = cfg_get_vlan(0, "vlan.%s.tag", port_name);
            if (port_vlan < 0) {
                port_vlan = 0;
            }
            if (vlan != port_vlan) {
                continue;
            }
        }
        if (break_down_bonds && cfg_has_section("bonding.%s", port_name)) {
            struct svec slaves;
            svec_init(&slaves);
            cfg_get_all_keys(&slaves, "bonding.%s.slave", port_name);
            svec_append(parts, &slaves);
            svec_destroy(&slaves);
        } else {
            svec_add(parts, port_name);
        }
    }
    svec_destroy(&ports);
}

/* Add all the interfaces for 'bridge' to 'ifaces', breaking bonded interfaces
 * down into their constituent parts.
 *
 * If 'vlan' < 0, all interfaces on 'bridge' are reported.  If 'vlan' == 0,
 * then only interfaces for trunk ports or ports with implicit VLAN 0 are
 * reported.  If 'vlan' > 0, only interfaces with implicit VLAN 'vlan' are
 * reported.  */
static void
get_bridge_ifaces(const char *bridge, struct svec *ifaces, int vlan)
{
    do_get_bridge_parts(bridge, ifaces, vlan, true);
}

/* Add all the ports for 'bridge' to 'ports'.  Bonded ports are reported under
 * the bond name, not broken down into their constituent interfaces.
 *
 * If 'vlan' < 0, all ports on 'bridge' are reported.  If 'vlan' == 0, then
 * only trunk ports or ports with implicit VLAN 0 are reported.  If 'vlan' > 0,
 * only port with implicit VLAN 'vlan' are reported.  */
static void
get_bridge_ports(const char *bridge, struct svec *ports, int vlan)
{
    do_get_bridge_parts(bridge, ports, vlan, false);
}

/* Go through the configuration file and remove any ports that no longer
 * exist associated with a bridge. */
static void
prune_ports(void)
{
    int i, j;
    struct svec bridges, delete;

    if (cfg_lock(NULL, 0)) {
        /* Couldn't lock config file. */
        return;
    }

    svec_init(&bridges);
    svec_init(&delete);
    cfg_get_subsections(&bridges, "bridge");
    for (i=0; i<bridges.n; i++) {
        const char *br_name = bridges.names[i];
        struct svec ifaces;

        /* Check that each bridge interface exists. */
        svec_init(&ifaces);
        get_bridge_ifaces(br_name, &ifaces, -1);
        for (j = 0; j < ifaces.n; j++) {
            const char *iface_name = ifaces.names[j];

            /* The local port and internal ports are created and destroyed by
             * ovs-vswitchd itself, so don't bother checking for them at all.
             * In practice, they might not exist if ovs-vswitchd hasn't
             * finished reloading since the configuration file was updated. */
            if (!strcmp(iface_name, br_name)
                || cfg_get_bool(0, "iface.%s.internal", iface_name)) {
                continue;
            }

            if (!netdev_exists(iface_name)) {
                VLOG_INFO_RL(&rl, "removing dead interface %s from %s",
                             iface_name, br_name);
                svec_add(&delete, iface_name);
            }
        }
        svec_destroy(&ifaces);
    }
    svec_destroy(&bridges);

    if (delete.n) {
        size_t i;

        for (i = 0; i < delete.n; i++) {
            cfg_del_match("bridge.*.port=%s", delete.names[i]);
            cfg_del_match("bonding.*.slave=%s", delete.names[i]);
        }
        rewrite_and_reload_config();
        cfg_unlock();
    } else {
        cfg_unlock();
    }
    svec_destroy(&delete);
}

static int
add_bridge(const char *br_name)
{
    if (bridge_exists(br_name)) {
        VLOG_WARN("addbr %s: bridge %s exists", br_name, br_name);
        return EEXIST;
    } else if (netdev_exists(br_name)) {
        if (cfg_get_bool(0, "iface.%s.fake-bridge", br_name)) {
            VLOG_WARN("addbr %s: %s exists as a fake bridge",
                      br_name, br_name);
            return 0;
        } else {
            VLOG_WARN("addbr %s: cannot create bridge %s because a network "
                      "device named %s already exists",
                      br_name, br_name, br_name);
            return EEXIST;
        }
    }

    cfg_add_entry("bridge.%s.port=%s", br_name, br_name);
    VLOG_INFO("addbr %s: success", br_name);

    return 0;
}

static int 
del_bridge(const char *br_name)
{
    if (!bridge_exists(br_name)) {
        VLOG_WARN("delbr %s: no bridge named %s", br_name, br_name);
        return ENXIO;
    }

    cfg_del_section("bridge.%s", br_name);
    VLOG_INFO("delbr %s: success", br_name);

    return 0;
}

static int
parse_command(struct ofpbuf *buffer, uint32_t *seq, const char **br_name,
              const char **port_name, uint64_t *count, uint64_t *skip)
{
    static const struct nl_policy policy[] = {
        [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_PORT_NAME] = { .type = NL_A_STRING, .optional = true },
        [BRC_GENL_A_FDB_COUNT] = { .type = NL_A_U64, .optional = true },
        [BRC_GENL_A_FDB_SKIP] = { .type = NL_A_U64, .optional = true },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];

    if (!nl_policy_parse(buffer, NLMSG_HDRLEN + GENL_HDRLEN, policy,
                         attrs, ARRAY_SIZE(policy))
        || (br_name && !attrs[BRC_GENL_A_DP_NAME])
        || (port_name && !attrs[BRC_GENL_A_PORT_NAME])
        || (count && !attrs[BRC_GENL_A_FDB_COUNT])
        || (skip && !attrs[BRC_GENL_A_FDB_SKIP])) {
        return EINVAL;
    }

    *seq = ((struct nlmsghdr *) buffer->data)->nlmsg_seq;
    if (br_name) {
        *br_name = nl_attr_get_string(attrs[BRC_GENL_A_DP_NAME]);
    }
    if (port_name) {
        *port_name = nl_attr_get_string(attrs[BRC_GENL_A_PORT_NAME]);
    }
    if (count) {
        *count = nl_attr_get_u64(attrs[BRC_GENL_A_FDB_COUNT]);
    }
    if (skip) {
        *skip = nl_attr_get_u64(attrs[BRC_GENL_A_FDB_SKIP]);
    }
    return 0;
}

/* Composes and returns a reply to a request made by the datapath with Netlink
 * sequence number 'seq' and error code 'error'.  The caller may add additional
 * attributes to the message, then it may send it with send_reply(). */
static struct ofpbuf *
compose_reply(uint32_t seq, int error)
{
    struct ofpbuf *reply = ofpbuf_new(4096);
    nl_msg_put_genlmsghdr(reply, brc_sock, 32, brc_family, NLM_F_REQUEST,
                          BRC_GENL_C_DP_RESULT, 1);
    ((struct nlmsghdr *) reply->data)->nlmsg_seq = seq;
    nl_msg_put_u32(reply, BRC_GENL_A_ERR_CODE, error);
    return reply;
}

/* Sends 'reply' to the datapath and frees it. */
static void
send_reply(struct ofpbuf *reply)
{
    int retval = nl_sock_send(brc_sock, reply, false);
    if (retval) {
        VLOG_WARN_RL(&rl, "replying to brcompat request: %s",
                     strerror(retval));
    }
    ofpbuf_delete(reply);
}

/* Composes and sends a reply to a request made by the datapath with Netlink
 * sequence number 'seq' and error code 'error'. */
static void
send_simple_reply(uint32_t seq, int error)
{
    send_reply(compose_reply(seq, error));
}

static int
handle_bridge_cmd(struct ofpbuf *buffer, bool add)
{
    const char *br_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL);
    if (!error) {
        error = add ? add_bridge(br_name) : del_bridge(br_name);
        if (!error) {
            error = rewrite_and_reload_config();
        }
        send_simple_reply(seq, error);
    }
    return error;
}

static const struct nl_policy brc_port_policy[] = {
    [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING },
    [BRC_GENL_A_PORT_NAME] = { .type = NL_A_STRING },
};

static void
del_port(const char *br_name, const char *port_name)
{
    cfg_del_entry("bridge.%s.port=%s", br_name, port_name);
    cfg_del_match("bonding.*.slave=%s", port_name);
    cfg_del_match("vlan.%s.[!0-9]*", port_name);
}

static int
handle_port_cmd(struct ofpbuf *buffer, bool add)
{
    const char *cmd_name = add ? "add-if" : "del-if";
    const char *br_name, *port_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, &port_name, NULL, NULL);
    if (!error) {
        if (!bridge_exists(br_name)) {
            VLOG_WARN("%s %s %s: no bridge named %s",
                      cmd_name, br_name, port_name, br_name);
            error = EINVAL;
        } else if (!netdev_exists(port_name)) {
            VLOG_WARN("%s %s %s: no network device named %s",
                      cmd_name, br_name, port_name, port_name);
            error = EINVAL;
        } else {
            if (add) {
                cfg_add_entry("bridge.%s.port=%s", br_name, port_name);
            } else {
                del_port(br_name, port_name);
            }
            VLOG_INFO("%s %s %s: success", cmd_name, br_name, port_name);
            error = rewrite_and_reload_config();
        }
        send_simple_reply(seq, error);
    }

    return error;
}

/* Returns the name of the bridge that contains a port named 'port_name', as a
 * malloc'd string that the caller must free, or a null pointer if no bridge
 * contains a port named 'port_name'. */
static char *
get_bridge_containing_port(const char *port_name)
{
    struct svec matches;
    const char *start, *end;

    svec_init(&matches);
    cfg_get_matches(&matches, "bridge.*.port=%s", port_name);
    if (!matches.n) {
        return 0;
    }

    start = matches.names[0] + strlen("bridge.");
    end = strstr(start, ".port=");
    assert(end);
    return xmemdup0(start, end - start);
}

static int
linux_bridge_to_ovs_bridge(const char *linux_bridge,
                           char **ovs_bridge, int *br_vlan)
{
    if (bridge_exists(linux_bridge)) {
        /* Bridge name is the same.  We are interested in VLAN 0. */
        *ovs_bridge = xstrdup(linux_bridge);
        *br_vlan = 0;
        return 0;
    } else {
        /* No such Open vSwitch bridge 'linux_bridge', but there might be an
         * internal port named 'linux_bridge' on some other bridge
         * 'ovs_bridge'.  If so then we are interested in the VLAN assigned to
         * port 'linux_bridge' on the bridge named 'ovs_bridge'. */
        const char *port_name = linux_bridge;

        *ovs_bridge = get_bridge_containing_port(port_name);
        *br_vlan = cfg_get_vlan(0, "vlan.%s.tag", port_name);
        if (*ovs_bridge && *br_vlan >= 0) {
            return 0;
        } else {
            free(*ovs_bridge);
            return ENODEV;
        }
    }
}

static int
handle_fdb_query_cmd(struct ofpbuf *buffer)
{
    /* This structure is copied directly from the Linux 2.6.30 header files.
     * It would be more straightforward to #include <linux/if_bridge.h>, but
     * the 'port_hi' member was only introduced in Linux 2.6.26 and so systems
     * with old header files won't have it. */
    struct __fdb_entry {
        __u8 mac_addr[6];
        __u8 port_no;
        __u8 is_local;
        __u32 ageing_timer_value;
        __u8 port_hi;
        __u8 pad0;
        __u16 unused;
    };

    struct mac {
        uint8_t addr[6];
    };
    struct mac *local_macs;
    int n_local_macs;
    int i;

    /* Impedance matching between the vswitchd and Linux kernel notions of what
     * a bridge is.  The kernel only handles a single VLAN per bridge, but
     * vswitchd can deal with all the VLANs on a single bridge.  We have to
     * pretend that the former is the case even though the latter is the
     * implementation. */
    const char *linux_bridge;   /* Name used by brctl. */
    char *ovs_bridge;           /* Name used by ovs-vswitchd. */
    int br_vlan;                /* VLAN tag. */
    struct svec ifaces;

    struct ofpbuf query_data;
    struct ofpbuf *reply;
    char *unixctl_command;
    uint64_t count, skip;
    char *output;
    char *save_ptr;
    uint32_t seq;
    int error;

    /* Parse the command received from brcompat_mod. */
    error = parse_command(buffer, &seq, &linux_bridge, NULL, &count, &skip);
    if (error) {
        return error;
    }

    /* Figure out vswitchd bridge and VLAN. */
    cfg_read();
    error = linux_bridge_to_ovs_bridge(linux_bridge, &ovs_bridge, &br_vlan);
    if (error) {
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the forwarding database using ovs-appctl. */
    unixctl_command = xasprintf("fdb/show %s", ovs_bridge);
    error = execute_appctl_command(unixctl_command, &output);
    free(unixctl_command);
    if (error) {
        free(ovs_bridge);
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the MAC address for each interface on the bridge, so that we can
     * fill in the is_local field in the response. */
    svec_init(&ifaces);
    get_bridge_ifaces(ovs_bridge, &ifaces, br_vlan);
    local_macs = xmalloc(ifaces.n * sizeof *local_macs);
    n_local_macs = 0;
    for (i = 0; i < ifaces.n; i++) {
        const char *iface_name = ifaces.names[i];
        struct mac *mac = &local_macs[n_local_macs];
        struct netdev *netdev;

        error = netdev_open(iface_name, NETDEV_ETH_TYPE_NONE, &netdev);
        if (netdev) {
            if (!netdev_get_etheraddr(netdev, mac->addr)) {
                n_local_macs++;
            }
            netdev_close(netdev);
        }
    }
    svec_destroy(&ifaces);

    /* Parse the response from ovs-appctl and convert it to binary format to
     * pass back to the kernel. */
    ofpbuf_init(&query_data, sizeof(struct __fdb_entry) * 8);
    save_ptr = NULL;
    strtok_r(output, "\n", &save_ptr); /* Skip header line. */
    while (count > 0) {
        struct __fdb_entry *entry;
        int port, vlan, age;
        uint8_t mac[ETH_ADDR_LEN];
        char *line;
        bool is_local;

        line = strtok_r(NULL, "\n", &save_ptr);
        if (!line) {
            break;
        }

        if (sscanf(line, "%d %d "ETH_ADDR_SCAN_FMT" %d",
                   &port, &vlan, ETH_ADDR_SCAN_ARGS(mac), &age)
            != 2 + ETH_ADDR_SCAN_COUNT + 1) {
            struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "fdb/show output has invalid format: %s", line);
            continue;
        }

        if (vlan != br_vlan) {
            continue;
        }

        if (skip > 0) {
            skip--;
            continue;
        }

        /* Is this the MAC address of an interface on the bridge? */
        is_local = false;
        for (i = 0; i < n_local_macs; i++) {
            if (eth_addr_equals(local_macs[i].addr, mac)) {
                is_local = true;
                break;
            }
        }

        entry = ofpbuf_put_uninit(&query_data, sizeof *entry);
        memcpy(entry->mac_addr, mac, ETH_ADDR_LEN);
        entry->port_no = port & 0xff;
        entry->is_local = is_local;
        entry->ageing_timer_value = age * HZ;
        entry->port_hi = (port & 0xff00) >> 8;
        entry->pad0 = 0;
        entry->unused = 0;
        count--;
    }
    free(output);

    /* Compose and send reply to datapath. */
    reply = compose_reply(seq, 0);
    nl_msg_put_unspec(reply, BRC_GENL_A_FDB_DATA,
                      query_data.data, query_data.size);
    send_reply(reply);

    /* Free memory. */
    ofpbuf_uninit(&query_data);
    free(ovs_bridge);

    return 0;
}

static void
send_ifindex_reply(uint32_t seq, struct svec *ifaces)
{
    struct ofpbuf *reply;
    const char *iface;
    size_t n_indices;
    int *indices;
    size_t i;

    /* Make sure that any given interface only occurs once.  This shouldn't
     * happen, but who knows what people put into their configuration files. */
    svec_sort_unique(ifaces);

    /* Convert 'ifaces' into ifindexes. */
    n_indices = 0;
    indices = xmalloc(ifaces->n * sizeof *indices);
    SVEC_FOR_EACH (i, iface, ifaces) {
        int ifindex = if_nametoindex(iface);
        if (ifindex) {
            indices[n_indices++] = ifindex;
        }
    }

    /* Compose and send reply. */
    reply = compose_reply(seq, 0);
    nl_msg_put_unspec(reply, BRC_GENL_A_IFINDEXES,
                      indices, n_indices * sizeof *indices);
    send_reply(reply);

    /* Free memory. */
    free(indices);
}

static int
handle_get_bridges_cmd(struct ofpbuf *buffer)
{
    struct svec bridges;
    const char *br_name;
    size_t i;

    uint32_t seq;

    int error;

    /* Parse Netlink command.
     *
     * The command doesn't actually have any arguments, but we need the
     * sequence number to send the reply. */
    error = parse_command(buffer, &seq, NULL, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    /* Get all the real bridges and all the fake ones. */
    cfg_read();
    svec_init(&bridges);
    cfg_get_subsections(&bridges, "bridge");
    SVEC_FOR_EACH (i, br_name, &bridges) {
        const char *iface_name;
        struct svec ifaces;
        size_t j;

        svec_init(&ifaces);
        get_bridge_ifaces(br_name, &ifaces, -1);
        SVEC_FOR_EACH (j, iface_name, &ifaces) {
            if (cfg_get_bool(0, "iface.%s.fake-bridge", iface_name)) {
                svec_add(&bridges, iface_name);
            }
        }
        svec_destroy(&ifaces);
    }

    send_ifindex_reply(seq, &bridges);
    svec_destroy(&bridges);

    return 0;
}

static int
handle_get_ports_cmd(struct ofpbuf *buffer)
{
    uint32_t seq;

    const char *linux_bridge;
    char *ovs_bridge;
    int br_vlan;

    struct svec ports;

    int error;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &linux_bridge, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    cfg_read();
    error = linux_bridge_to_ovs_bridge(linux_bridge, &ovs_bridge, &br_vlan);
    if (error) {
        send_simple_reply(seq, error);
        return error;
    }

    svec_init(&ports);
    get_bridge_ports(ovs_bridge, &ports, br_vlan);
    svec_sort(&ports);
    svec_del(&ports, linux_bridge);
    send_ifindex_reply(seq, &ports); /* XXX bonds won't show up */
    svec_destroy(&ports);

    free(ovs_bridge);

    return 0;
}

static int
brc_recv_update(void)
{
    int retval;
    struct ofpbuf *buffer;
    struct genlmsghdr *genlmsghdr;


    buffer = NULL;
    do {
        ofpbuf_delete(buffer);
        retval = nl_sock_recv(brc_sock, &buffer, false);
    } while (retval == ENOBUFS
            || (!retval
                && (nl_msg_nlmsgerr(buffer, NULL)
                    || nl_msg_nlmsghdr(buffer)->nlmsg_type == NLMSG_DONE)));
    if (retval) {
        if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "brc_recv_update: %s", strerror(retval));
        }
        return retval;
    }

    genlmsghdr = nl_msg_genlmsghdr(buffer);
    if (!genlmsghdr) {
        VLOG_WARN_RL(&rl, "received packet too short for generic NetLink");
        goto error;
    }

    if (nl_msg_nlmsghdr(buffer)->nlmsg_type != brc_family) {
        VLOG_DBG_RL(&rl, "received type (%"PRIu16") != brcompat family (%d)",
                nl_msg_nlmsghdr(buffer)->nlmsg_type, brc_family);
        goto error;
    }

    if (cfg_lock(NULL, lock_timeout)) {
        /* Couldn't lock config file. */
        retval = EAGAIN;
        goto error;
    }

    switch (genlmsghdr->cmd) {
    case BRC_GENL_C_DP_ADD:
        retval = handle_bridge_cmd(buffer, true);
        break;

    case BRC_GENL_C_DP_DEL:
        retval = handle_bridge_cmd(buffer, false);
        break;

    case BRC_GENL_C_PORT_ADD:
        retval = handle_port_cmd(buffer, true);
        break;

    case BRC_GENL_C_PORT_DEL:
        retval = handle_port_cmd(buffer, false);
        break;

    case BRC_GENL_C_FDB_QUERY:
        retval = handle_fdb_query_cmd(buffer);
        break;

    case BRC_GENL_C_GET_BRIDGES:
        retval = handle_get_bridges_cmd(buffer);
        break;

    case BRC_GENL_C_GET_PORTS:
        retval = handle_get_ports_cmd(buffer);
        break;

    default:
        retval = EPROTO;
    }

    cfg_unlock();

error:
    ofpbuf_delete(buffer);
    return retval;
}

/* Check for interface configuration changes announced through RTNL. */
static void
rtnl_recv_update(void)
{
    struct ofpbuf *buf;

    int error = nl_sock_recv(rtnl_sock, &buf, false);
    if (error == EAGAIN) {
        /* Nothing to do. */
    } else if (error == ENOBUFS) {
        VLOG_WARN_RL(&rl, "network monitor socket overflowed");
    } else if (error) {
        VLOG_WARN_RL(&rl, "error on network monitor socket: %s", 
                strerror(error));
    } else {
        struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
        struct nlmsghdr *nlh;
        struct ifinfomsg *iim;

        nlh = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
        iim = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *iim);
        if (!iim) {
            VLOG_WARN_RL(&rl, "received bad rtnl message (no ifinfomsg)");
            ofpbuf_delete(buf);
            return;
        } 
    
        if (!nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                             rtnlgrp_link_policy,
                             attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
            VLOG_WARN_RL(&rl,"received bad rtnl message (policy)");
            ofpbuf_delete(buf);
            return;
        }
        if (nlh->nlmsg_type == RTM_DELLINK && attrs[IFLA_MASTER]) {
            const char *port_name = nl_attr_get_string(attrs[IFLA_IFNAME]);
            char br_name[IFNAMSIZ];
            uint32_t br_idx = nl_attr_get_u32(attrs[IFLA_MASTER]);

            if (!if_indextoname(br_idx, br_name)) {
                ofpbuf_delete(buf);
                return;
            }

            if (cfg_lock(NULL, lock_timeout)) {
                /* Couldn't lock config file. */
                /* xxx this should try again and print error msg. */
                ofpbuf_delete(buf);
                return;
            }

            if (!netdev_exists(port_name)) {
                /* Network device is really gone. */
                struct svec ports;

                VLOG_INFO("network device %s destroyed, "
                          "removing from bridge %s", port_name, br_name);

                svec_init(&ports);
                cfg_get_all_keys(&ports, "bridge.%s.port", br_name);
                svec_sort(&ports);
                if (svec_contains(&ports, port_name)) {
                    del_port(br_name, port_name);
                    rewrite_and_reload_config();
                }
                svec_destroy(&ports);
            } else {
                /* A network device by that name exists even though the kernel
                 * told us it had disappeared.  Probably, what happened was
                 * this:
                 *
                 *      1. Device destroyed.
                 *      2. Notification sent to us.
                 *      3. New device created with same name as old one.
                 *      4. ovs-brcompatd notified, removes device from bridge.
                 *
                 * There's no a priori reason that in this situation that the
                 * new device with the same name should remain in the bridge;
                 * on the contrary, that would be unexpected.  *But* there is
                 * one important situation where, if we do this, bad things
                 * happen.  This is the case of XenServer Tools version 5.0.0,
                 * which on boot of a Windows VM cause something like this to
                 * happen on the Xen host:
                 *
                 *      i. Create tap1.0 and vif1.0.
                 *      ii. Delete tap1.0.
                 *      iii. Delete vif1.0.
                 *      iv. Re-create vif1.0.
                 *
                 * (XenServer Tools 5.5.0 does not exhibit this behavior, and
                 * neither does a VM without Tools installed at all.@.)
                 *
                 * Steps iii and iv happen within a few seconds of each other.
                 * Step iv causes /etc/xensource/scripts/vif to run, which in
                 * turn calls ovs-cfg-mod to add the new device to the bridge.
                 * If step iv happens after step 4 (in our first list of
                 * steps), then all is well, but if it happens between 3 and 4
                 * (which can easily happen if ovs-brcompatd has to wait to
                 * lock the configuration file), then we will remove the new
                 * incarnation from the bridge instead of the old one!
                 *
                 * So, to avoid this problem, we do nothing here.  This is
                 * strictly incorrect except for this one particular case, and
                 * perhaps that will bite us someday.  If that happens, then we
                 * will have to somehow track network devices by ifindex, since
                 * a new device will have a new ifindex even if it has the same
                 * name as an old device.
                 */
                VLOG_INFO("kernel reported network device %s removed but "
                          "a device by that name exists (XS Tools 5.0.0?)",
                          port_name);
            }
            cfg_unlock();
        }
        ofpbuf_delete(buf);
    }
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    process_init();

    die_if_already_running();
    daemonize();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        ovs_fatal(retval, "could not listen for vlog connections");
    }

    if (brc_open(&brc_sock)) {
        ovs_fatal(0, "could not open brcompat socket.  Check "
                "\"brcompat\" kernel module.");
    }

    if (prune_timeout) {
        if (nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0, &rtnl_sock)) {
            ovs_fatal(0, "could not create rtnetlink socket");
        }
    }

    retval = cfg_read();
    if (retval) {
        ovs_fatal(retval, "could not read config file");
    }

    for (;;) {
        unixctl_server_run(unixctl);
        brc_recv_update();
        netdev_run();

        /* If 'prune_timeout' is non-zero, we actively prune from the
         * config file any 'bridge.<br_name>.port' entries that are no 
         * longer valid.  We use two methods: 
         *
         *   1) The kernel explicitly notifies us of removed ports
         *      through the RTNL messages.
         *
         *   2) We periodically check all ports associated with bridges
         *      to see if they no longer exist.
         */
        if (prune_timeout) {
            rtnl_recv_update();
            prune_ports();

            nl_sock_wait(rtnl_sock, POLLIN);
            poll_timer_wait(prune_timeout);
        }

        nl_sock_wait(brc_sock, POLLIN);
        unixctl_server_wait(unixctl);
        netdev_wait();
        poll_block();
    }

    return 0;
}

static void
validate_appctl_command(void)
{
    const char *p;
    int n;

    n = 0;
    for (p = strchr(appctl_command, '%'); p; p = strchr(p + 2, '%')) {
        if (p[1] == '%') {
            /* Nothing to do. */
        } else if (p[1] == 's') {
            n++;
        } else {
            ovs_fatal(0, "only '%%s' and '%%%%' allowed in --appctl-command");
        }
    }
    if (n != 1) {
        ovs_fatal(0, "'%%s' must appear exactly once in --appctl-command");
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_LOCK_TIMEOUT = UCHAR_MAX + 1,
        OPT_PRUNE_TIMEOUT,
        OPT_APPCTL_COMMAND,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",             no_argument, 0, 'h'},
        {"version",          no_argument, 0, 'V'},
        {"lock-timeout",     required_argument, 0, OPT_LOCK_TIMEOUT},
        {"prune-timeout",    required_argument, 0, OPT_PRUNE_TIMEOUT},
        {"appctl-command",   required_argument, 0, OPT_APPCTL_COMMAND},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    int error;

    appctl_command = xasprintf("%s/ovs-appctl %%s", ovs_bindir);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'H':
        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case OPT_LOCK_TIMEOUT:
            lock_timeout = atoi(optarg);
            break;

        case OPT_PRUNE_TIMEOUT:
            prune_timeout = atoi(optarg) * 1000;
            break;

        case OPT_APPCTL_COMMAND:
            appctl_command = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        LEAK_CHECKER_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    validate_appctl_command();

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        ovs_fatal(0, "exactly one non-option argument required; "
                "use --help for usage");
    }

    cfg_init();
    config_file = argv[0];
    error = cfg_set_file(config_file);
    if (error) {
        ovs_fatal(error, "failed to add configuration file \"%s\"", 
                config_file);
    }
}

static void
usage(void)
{
    printf("%s: bridge compatibility front-end for ovs-vswitchd\n"
           "usage: %s [OPTIONS] CONFIG\n"
           "CONFIG is the configuration file used by ovs-vswitchd.\n",
           program_name, program_name);
    printf("\nConfiguration options:\n"
           "  --appctl-command=COMMAND  shell command to run ovs-appctl\n"
           "  --prune-timeout=SECS    wait at most SECS before pruning ports\n"
           "  --lock-timeout=MSECS    wait at most MSECS for CONFIG to unlock\n"
          );
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    printf("\nThe default appctl command is:\n%s\n", appctl_command);
    exit(EXIT_SUCCESS);
}
