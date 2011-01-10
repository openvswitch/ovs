/* Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks
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

#include "command-line.h"
#include "coverage.h"
#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "json.h"
#include "leak-checker.h"
#include "netdev.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "openvswitch/brcompat-netlink.h"
#include "ovsdb-idl.h"
#include "packets.h"
#include "poll-loop.h"
#include "process.h"
#include "signals.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"
#include "vswitchd/vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(brcompatd);


/* xxx Just hangs if datapath is rmmod/insmod.  Learn to reconnect? */

/* Actions to modify bridge compatibility configuration. */
enum bmc_action {
    BMC_ADD_DP,
    BMC_DEL_DP,
    BMC_ADD_PORT,
    BMC_DEL_PORT
};

static const char *parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 60);

/* Maximum number of milliseconds to wait before pruning port entries that
 * no longer exist.  If set to zero, ports are never pruned. */
static int prune_timeout = 5000;

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

    retval = nl_sock_create(NETLINK_GENERIC, &sock);
    if (retval) {
        return retval;
    }
    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, brc_family,
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

    retval = nl_sock_create(NETLINK_GENERIC, sock);
    if (retval) {
        return retval;
    }

    retval = nl_sock_join_mcgroup(*sock, multicast_group);
    if (retval) {
        nl_sock_destroy(*sock);
        *sock = NULL;
    }
    return retval;
}

static const struct nl_policy brc_dp_policy[] = {
    [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING },
};

static struct ovsrec_bridge *
find_bridge(const struct ovsrec_open_vswitch *ovs, const char *br_name)
{
    size_t i;

    for (i = 0; i < ovs->n_bridges; i++) {
        if (!strcmp(br_name, ovs->bridges[i]->name)) {
            return ovs->bridges[i];
        }
    }

    return NULL;
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

static void
do_get_bridge_parts(const struct ovsrec_bridge *br, struct svec *parts,
                    int vlan, bool break_down_bonds)
{
    struct svec ports;
    size_t i, j;

    svec_init(&ports);
    for (i = 0; i < br->n_ports; i++) {
        const struct ovsrec_port *port = br->ports[i];

        svec_add(&ports, port->name);
        if (vlan >= 0) {
            int port_vlan = port->n_tag ? *port->tag : 0;
            if (vlan != port_vlan) {
                continue;
            }
        }
        if (break_down_bonds) {
            for (j = 0; j < port->n_interfaces; j++) {
                const struct ovsrec_interface *iface = port->interfaces[j];
                svec_add(parts, iface->name);
            }
        } else {
            svec_add(parts, port->name);
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
get_bridge_ifaces(const struct ovsrec_bridge *br, struct svec *ifaces,
                  int vlan)
{
    do_get_bridge_parts(br, ifaces, vlan, true);
}

/* Add all the ports for 'bridge' to 'ports'.  Bonded ports are reported under
 * the bond name, not broken down into their constituent interfaces.
 *
 * If 'vlan' < 0, all ports on 'bridge' are reported.  If 'vlan' == 0, then
 * only trunk ports or ports with implicit VLAN 0 are reported.  If 'vlan' > 0,
 * only port with implicit VLAN 'vlan' are reported.  */
static void
get_bridge_ports(const struct ovsrec_bridge *br, struct svec *ports,
                 int vlan)
{
    do_get_bridge_parts(br, ports, vlan, false);
}

static struct ovsdb_idl_txn *
txn_from_openvswitch(const struct ovsrec_open_vswitch *ovs)
{
    return ovsdb_idl_txn_get(&ovs->header_);
}

static bool
port_is_fake_bridge(const struct ovsrec_port *port)
{
    return (port->fake_bridge
            && port->tag
            && *port->tag >= 1 && *port->tag <= 4095);
}

static void
ovs_insert_bridge(const struct ovsrec_open_vswitch *ovs,
                  struct ovsrec_bridge *bridge)
{
    struct ovsrec_bridge **bridges;
    size_t i;

    bridges = xmalloc(sizeof *ovs->bridges * (ovs->n_bridges + 1));
    for (i = 0; i < ovs->n_bridges; i++) {
        bridges[i] = ovs->bridges[i];
    }
    bridges[ovs->n_bridges] = bridge;
    ovsrec_open_vswitch_set_bridges(ovs, bridges, ovs->n_bridges + 1);
    free(bridges);
}

static struct json *
where_uuid_equals(const struct uuid *uuid)
{
    return
        json_array_create_1(
            json_array_create_3(
                json_string_create("_uuid"),
                json_string_create("=="),
                json_array_create_2(
                    json_string_create("uuid"),
                    json_string_create_nocopy(
                        xasprintf(UUID_FMT, UUID_ARGS(uuid))))));
}

/* Commits 'txn'.  If 'wait_for_reload' is true, also waits for Open vSwitch to
   reload the configuration before returning.

   Returns EAGAIN if the caller should try the operation again, 0 on success,
   otherwise a positive errno value. */
static int
commit_txn(struct ovsdb_idl_txn *txn, bool wait_for_reload)
{
    struct ovsdb_idl *idl = ovsdb_idl_txn_get_idl (txn);
    enum ovsdb_idl_txn_status status;
    int64_t next_cfg = 0;

    if (wait_for_reload) {
        const struct ovsrec_open_vswitch *ovs = ovsrec_open_vswitch_first(idl);
        struct json *where = where_uuid_equals(&ovs->header_.uuid);
        ovsdb_idl_txn_increment(txn, "Open_vSwitch", "next_cfg", where);
        json_destroy(where);
    }
    status = ovsdb_idl_txn_commit_block(txn);
    if (wait_for_reload && status == TXN_SUCCESS) {
        next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    }
    ovsdb_idl_txn_destroy(txn);

    switch (status) {
    case TXN_INCOMPLETE:
        NOT_REACHED();

    case TXN_ABORTED:
        VLOG_ERR_RL(&rl, "OVSDB transaction unexpectedly aborted");
        return ECONNABORTED;

    case TXN_UNCHANGED:
        return 0;

    case TXN_SUCCESS:
        if (wait_for_reload) {
            for (;;) {
                /* We can't use 'ovs' any longer because ovsdb_idl_run() can
                 * destroy it. */
                const struct ovsrec_open_vswitch *ovs2;

                ovsdb_idl_run(idl);
                OVSREC_OPEN_VSWITCH_FOR_EACH (ovs2, idl) {
                    if (ovs2->cur_cfg >= next_cfg) {
                        goto done;
                    }
                }
                ovsdb_idl_wait(idl);
                poll_block();
            }
        done: ;
        }
        return 0;

    case TXN_TRY_AGAIN:
        VLOG_ERR_RL(&rl, "OVSDB transaction needs retry");
        return EAGAIN;

    case TXN_ERROR:
        VLOG_ERR_RL(&rl, "OVSDB transaction failed: %s",
                    ovsdb_idl_txn_get_error(txn));
        return EBUSY;

    default:
        NOT_REACHED();
    }
}

static int
add_bridge(struct ovsdb_idl *idl, const struct ovsrec_open_vswitch *ovs,
           const char *br_name)
{
    struct ovsrec_bridge *br;
    struct ovsrec_port *port;
    struct ovsrec_interface *iface;
    struct ovsdb_idl_txn *txn;

    if (find_bridge(ovs, br_name)) {
        VLOG_WARN("addbr %s: bridge %s exists", br_name, br_name);
        return EEXIST;
    } else if (netdev_exists(br_name)) {
        size_t i;

        for (i = 0; i < ovs->n_bridges; i++) {
            size_t j;
            struct ovsrec_bridge *br_cfg = ovs->bridges[i];

            for (j = 0; j < br_cfg->n_ports; j++) {
                if (port_is_fake_bridge(br_cfg->ports[j])) {
                    VLOG_WARN("addbr %s: %s exists as a fake bridge",
                              br_name, br_name);
                    return 0;
                }
            }
        }

        VLOG_WARN("addbr %s: cannot create bridge %s because a network "
                  "device named %s already exists",
                  br_name, br_name, br_name);
        return EEXIST;
    }

    txn = ovsdb_idl_txn_create(idl);

    ovsdb_idl_txn_add_comment(txn, "ovs-brcompatd: addbr %s", br_name);

    iface = ovsrec_interface_insert(txn_from_openvswitch(ovs));
    ovsrec_interface_set_name(iface, br_name);

    port = ovsrec_port_insert(txn_from_openvswitch(ovs));
    ovsrec_port_set_name(port, br_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    br = ovsrec_bridge_insert(txn_from_openvswitch(ovs));
    ovsrec_bridge_set_name(br, br_name);
    ovsrec_bridge_set_ports(br, &port, 1);

    ovs_insert_bridge(ovs, br);

    return commit_txn(txn, true);
}

static void
add_port(const struct ovsrec_open_vswitch *ovs,
         const struct ovsrec_bridge *br, const char *port_name)
{
    struct ovsrec_interface *iface;
    struct ovsrec_port *port;
    struct ovsrec_port **ports;
    size_t i;

    /* xxx Check conflicts? */
    iface = ovsrec_interface_insert(txn_from_openvswitch(ovs));
    ovsrec_interface_set_name(iface, port_name);

    port = ovsrec_port_insert(txn_from_openvswitch(ovs));
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    ports = xmalloc(sizeof *br->ports * (br->n_ports + 1));
    for (i = 0; i < br->n_ports; i++) {
        ports[i] = br->ports[i];
    }
    ports[br->n_ports] = port;
    ovsrec_bridge_set_ports(br, ports, br->n_ports + 1);
    free(ports);
}

/* Deletes 'port' from 'br'.
 *
 * After calling this function, 'port' must not be referenced again. */
static void
del_port(const struct ovsrec_bridge *br, const struct ovsrec_port *port)
{
    struct ovsrec_port **ports;
    size_t i, n;

    /* Remove 'port' from the bridge's list of ports. */
    ports = xmalloc(sizeof *br->ports * br->n_ports);
    for (i = n = 0; i < br->n_ports; i++) {
        if (br->ports[i] != port) {
            ports[n++] = br->ports[i];
        }
    }
    ovsrec_bridge_set_ports(br, ports, n);
    free(ports);

    /* Delete all of the port's interfaces. */
    for (i = 0; i < port->n_interfaces; i++) {
        ovsrec_interface_delete(port->interfaces[i]);
    }

    /* Delete the port itself. */
    ovsrec_port_delete(port);
}

/* Delete 'iface' from 'port' (which must be within 'br').  If 'iface' was
 * 'port''s only interface, delete 'port' from 'br' also.
 *
 * After calling this function, 'iface' must not be referenced again. */
static void
del_interface(const struct ovsrec_bridge *br,
              const struct ovsrec_port *port,
              const struct ovsrec_interface *iface)
{
    if (port->n_interfaces == 1) {
        del_port(br, port);
    } else {
        struct ovsrec_interface **ifaces;
        size_t i, n;

        ifaces = xmalloc(sizeof *port->interfaces * port->n_interfaces);
        for (i = n = 0; i < port->n_interfaces; i++) {
            if (port->interfaces[i] != iface) {
                ifaces[n++] = port->interfaces[i];
            }
        }
        ovsrec_port_set_interfaces(port, ifaces, n);
        free(ifaces);
        ovsrec_interface_delete(iface);
    }
}

/* Find and return a port within 'br' named 'port_name'. */
static const struct ovsrec_port *
find_port(const struct ovsrec_bridge *br, const char *port_name)
{
    size_t i;

    for (i = 0; i < br->n_ports; i++) {
        struct ovsrec_port *port = br->ports[i];
        if (!strcmp(port_name, port->name)) {
            return port;
        }
    }
    return NULL;
}

/* Find and return an interface within 'br' named 'iface_name'. */
static const struct ovsrec_interface *
find_interface(const struct ovsrec_bridge *br, const char *iface_name,
               struct ovsrec_port **portp)
{
    size_t i;

    for (i = 0; i < br->n_ports; i++) {
        struct ovsrec_port *port = br->ports[i];
        size_t j;

        for (j = 0; j < port->n_interfaces; j++) {
            struct ovsrec_interface *iface = port->interfaces[j];
            if (!strcmp(iface->name, iface_name)) {
                *portp = port;
                return iface;
            }
        }
    }

    *portp = NULL;
    return NULL;
}

static int
del_bridge(struct ovsdb_idl *idl,
           const struct ovsrec_open_vswitch *ovs, const char *br_name)
{
    struct ovsrec_bridge *br = find_bridge(ovs, br_name);
    struct ovsrec_bridge **bridges;
    struct ovsdb_idl_txn *txn;
    size_t i, n;

    if (!br) {
        VLOG_WARN("delbr %s: no bridge named %s", br_name, br_name);
        return ENXIO;
    }

    txn = ovsdb_idl_txn_create(idl);

    ovsdb_idl_txn_add_comment(txn, "ovs-brcompatd: delbr %s", br_name);

    /* Delete everything that the bridge points to, then delete the bridge
     * itself. */
    while (br->n_ports > 0) {
        del_port(br, br->ports[0]);
    }
    for (i = 0; i < br->n_mirrors; i++) {
        ovsrec_mirror_delete(br->mirrors[i]);
    }
    if (br->netflow) {
        ovsrec_netflow_delete(br->netflow);
    }
    if (br->sflow) {
        ovsrec_sflow_delete(br->sflow);
    }
    for (i = 0; i < br->n_controller; i++) {
        ovsrec_controller_delete(br->controller[i]);
    }

    /* Remove 'br' from the vswitch's list of bridges. */
    bridges = xmalloc(sizeof *ovs->bridges * ovs->n_bridges);
    for (i = n = 0; i < ovs->n_bridges; i++) {
        if (ovs->bridges[i] != br) {
            bridges[n++] = ovs->bridges[i];
        }
    }
    ovsrec_open_vswitch_set_bridges(ovs, bridges, n);
    free(bridges);

    /* Delete the bridge itself. */
    ovsrec_bridge_delete(br);

    return commit_txn(txn, true);
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
    nl_msg_put_genlmsghdr(reply, 32, brc_family, NLM_F_REQUEST,
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
handle_bridge_cmd(struct ovsdb_idl *idl,
                  const struct ovsrec_open_vswitch *ovs,
                  struct ofpbuf *buffer, bool add)
{
    const char *br_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL);
    if (!error) {
        int retval;

        do {
            retval = (add ? add_bridge : del_bridge)(idl, ovs, br_name);
            VLOG_INFO_RL(&rl, "%sbr %s: %s",
                         add ? "add" : "del", br_name, strerror(retval));
        } while (retval == EAGAIN);

        send_simple_reply(seq, error);
    }
    return error;
}

static const struct nl_policy brc_port_policy[] = {
    [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING },
    [BRC_GENL_A_PORT_NAME] = { .type = NL_A_STRING },
};

static int
handle_port_cmd(struct ovsdb_idl *idl,
                const struct ovsrec_open_vswitch *ovs,
                struct ofpbuf *buffer, bool add)
{
    const char *cmd_name = add ? "add-if" : "del-if";
    const char *br_name, *port_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, &port_name, NULL, NULL);
    if (!error) {
        struct ovsrec_bridge *br = find_bridge(ovs, br_name);

        if (!br) {
            VLOG_WARN("%s %s %s: no bridge named %s",
                      cmd_name, br_name, port_name, br_name);
            error = EINVAL;
        } else if (!netdev_exists(port_name)) {
            VLOG_WARN("%s %s %s: no network device named %s",
                      cmd_name, br_name, port_name, port_name);
            error = EINVAL;
        } else {
            do {
                struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);

                if (add) {
                    ovsdb_idl_txn_add_comment(txn, "ovs-brcompatd: add-if %s",
                                              port_name);
                    add_port(ovs, br, port_name);
                } else {
                    const struct ovsrec_port *port = find_port(br, port_name);
                    if (port) {
                        ovsdb_idl_txn_add_comment(txn,
                                                  "ovs-brcompatd: del-if %s",
                                                  port_name);
                        del_port(br, port);
                    }
                }

                error = commit_txn(txn, true);
                VLOG_INFO_RL(&rl, "%s %s %s: %s",
                             cmd_name, br_name, port_name, strerror(error));
            } while (error == EAGAIN);
        }
        send_simple_reply(seq, error);
    }

    return error;
}

/* The caller is responsible for freeing '*ovs_name' if the call is
 * successful. */
static int
linux_bridge_to_ovs_bridge(const struct ovsrec_open_vswitch *ovs,
                           const char *linux_name,
                           const struct ovsrec_bridge **ovs_bridge,
                           int *br_vlan)
{
    *ovs_bridge = find_bridge(ovs, linux_name);
    if (*ovs_bridge) {
        /* Bridge name is the same.  We are interested in VLAN 0. */
        *br_vlan = 0;
        return 0;
    } else {
        /* No such Open vSwitch bridge 'linux_name', but there might be an
         * internal port named 'linux_name' on some other bridge
         * 'ovs_bridge'.  If so then we are interested in the VLAN assigned to
         * port 'linux_name' on the bridge named 'ovs_bridge'. */
        size_t i, j;

        for (i = 0; i < ovs->n_bridges; i++) {
            const struct ovsrec_bridge *br = ovs->bridges[i];

            for (j = 0; j < br->n_ports; j++) {
                const struct ovsrec_port *port = br->ports[j];

                if (!strcmp(port->name, linux_name)) {
                    *ovs_bridge = br;
                    *br_vlan = port->n_tag ? *port->tag : -1;
                    return 0;
                }
            }

        }
        return ENODEV;
    }
}

static int
handle_fdb_query_cmd(const struct ovsrec_open_vswitch *ovs,
                     struct ofpbuf *buffer)
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
    const char *linux_name;   /* Name used by brctl. */
    const struct ovsrec_bridge *ovs_bridge;  /* Bridge used by ovs-vswitchd. */
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
    error = parse_command(buffer, &seq, &linux_name, NULL, &count, &skip);
    if (error) {
        return error;
    }

    /* Figure out vswitchd bridge and VLAN. */
    error = linux_bridge_to_ovs_bridge(ovs, linux_name,
                                       &ovs_bridge, &br_vlan);
    if (error) {
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the forwarding database using ovs-appctl. */
    unixctl_command = xasprintf("fdb/show %s", ovs_bridge->name);
    error = execute_appctl_command(unixctl_command, &output);
    free(unixctl_command);
    if (error) {
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

        error = netdev_open_default(iface_name, &netdev);
        if (!error) {
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
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
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
handle_get_bridges_cmd(const struct ovsrec_open_vswitch *ovs,
                       struct ofpbuf *buffer)
{
    struct svec bridges;
    size_t i, j;

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
    svec_init(&bridges);
    for (i = 0; i < ovs->n_bridges; i++) {
        const struct ovsrec_bridge *br = ovs->bridges[i];

        svec_add(&bridges, br->name);
        for (j = 0; j < br->n_ports; j++) {
            const struct ovsrec_port *port = br->ports[j];

            if (port->fake_bridge) {
                svec_add(&bridges, port->name);
            }
        }
    }

    send_ifindex_reply(seq, &bridges);
    svec_destroy(&bridges);

    return 0;
}

static int
handle_get_ports_cmd(const struct ovsrec_open_vswitch *ovs,
                     struct ofpbuf *buffer)
{
    uint32_t seq;

    const char *linux_name;
    const struct ovsrec_bridge *ovs_bridge;
    int br_vlan;

    struct svec ports;

    int error;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &linux_name, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    error = linux_bridge_to_ovs_bridge(ovs, linux_name,
                                       &ovs_bridge, &br_vlan);
    if (error) {
        send_simple_reply(seq, error);
        return error;
    }

    svec_init(&ports);
    get_bridge_ports(ovs_bridge, &ports, br_vlan);
    svec_sort(&ports);
    svec_del(&ports, linux_name);
    send_ifindex_reply(seq, &ports); /* XXX bonds won't show up */
    svec_destroy(&ports);

    return 0;
}

static void
brc_recv_update(struct ovsdb_idl *idl)
{
    int retval;
    struct ofpbuf *buffer;
    struct genlmsghdr *genlmsghdr;
    const struct ovsrec_open_vswitch *ovs;

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
        return;
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

    /* Get the Open vSwitch configuration.  Just drop the request on the floor
     * if a valid configuration doesn't exist.  (We could check this earlier,
     * but we want to drain pending Netlink messages even when there is no Open
     * vSwitch configuration.) */
    ovs = ovsrec_open_vswitch_first(idl);
    if (!ovs) {
        VLOG_WARN_RL(&rl, "could not find valid configuration to update");
        goto error;
    }

    switch (genlmsghdr->cmd) {
    case BRC_GENL_C_DP_ADD:
        handle_bridge_cmd(idl, ovs, buffer, true);
        break;

    case BRC_GENL_C_DP_DEL:
        handle_bridge_cmd(idl, ovs, buffer, false);
        break;

    case BRC_GENL_C_PORT_ADD:
        handle_port_cmd(idl, ovs, buffer, true);
        break;

    case BRC_GENL_C_PORT_DEL:
        handle_port_cmd(idl, ovs, buffer, false);
        break;

    case BRC_GENL_C_FDB_QUERY:
        handle_fdb_query_cmd(ovs, buffer);
        break;

    case BRC_GENL_C_GET_BRIDGES:
        handle_get_bridges_cmd(ovs, buffer);
        break;

    case BRC_GENL_C_GET_PORTS:
        handle_get_ports_cmd(ovs, buffer);
        break;

    default:
        VLOG_WARN_RL(&rl, "received unknown brc netlink command: %d\n",
                     genlmsghdr->cmd);
        break;
    }

error:
    ofpbuf_delete(buffer);
    return;
}

/* Check for interface configuration changes announced through RTNL. */
static void
rtnl_recv_update(struct ovsdb_idl *idl,
                 const struct ovsrec_open_vswitch *ovs)
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

            if (!netdev_exists(port_name)) {
                /* Network device is really gone. */
                struct ovsdb_idl_txn *txn;
                const struct ovsrec_interface *iface;
                struct ovsrec_port *port;
                struct ovsrec_bridge *br;

                VLOG_INFO("network device %s destroyed, "
                          "removing from bridge %s", port_name, br_name);

                br = find_bridge(ovs, br_name);
                if (!br) {
                    VLOG_WARN("no bridge named %s from which to remove %s",
                            br_name, port_name);
                    ofpbuf_delete(buf);
                    return;
                }

                txn = ovsdb_idl_txn_create(idl);

                iface = find_interface(br, port_name, &port);
                if (iface) {
                    del_interface(br, port, iface);
                    ovsdb_idl_txn_add_comment(txn,
                                              "ovs-brcompatd: destroy port %s",
                                              port_name);
                }

                commit_txn(txn, false);
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
        }
        ofpbuf_delete(buf);
    }
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct unixctl_server *unixctl;
    const char *remote;
    struct ovsdb_idl *idl;
    int retval;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_FACILITY, VLL_WARN);

    remote = parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    process_init();
    ovsrec_init();

    die_if_already_running();
    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (brc_open(&brc_sock)) {
        ovs_fatal(0, "could not open brcompat socket.  Check "
                "\"brcompat\" kernel module.");
    }

    if (prune_timeout) {
        int error;

        error = nl_sock_create(NETLINK_ROUTE, &rtnl_sock);
        if (error) {
            ovs_fatal(error, "could not create rtnetlink socket");
        }

        error = nl_sock_join_mcgroup(rtnl_sock, RTNLGRP_LINK);
        if (error) {
            ovs_fatal(error, "could not join RTNLGRP_LINK multicast group");
        }
    }

    daemonize_complete();

    idl = ovsdb_idl_create(remote, &ovsrec_idl_class, true);

    for (;;) {
        const struct ovsrec_open_vswitch *ovs;

        ovsdb_idl_run(idl);

        unixctl_server_run(unixctl);
        brc_recv_update(idl);

        ovs = ovsrec_open_vswitch_first(idl);
        if (!ovs && ovsdb_idl_has_ever_connected(idl)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "%s: database does not contain any Open vSwitch "
                         "configuration", remote);
        }
        netdev_run();

        /* If 'prune_timeout' is non-zero, we actively prune from the
         * configuration of port entries that are no longer valid.  We
         * use two methods:
         *
         *   1) The kernel explicitly notifies us of removed ports
         *      through the RTNL messages.
         *
         *   2) We periodically check all ports associated with bridges
         *      to see if they no longer exist.
         */
        if (ovs && prune_timeout) {
            rtnl_recv_update(idl, ovs);
            nl_sock_wait(rtnl_sock, POLLIN);
            poll_timer_wait(prune_timeout);
        }


        nl_sock_wait(brc_sock, POLLIN);
        ovsdb_idl_wait(idl);
        unixctl_server_wait(unixctl);
        netdev_wait();
        poll_block();
    }

    ovsdb_idl_destroy(idl);

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

static const char *
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PRUNE_TIMEOUT,
        OPT_APPCTL_COMMAND,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",             no_argument, 0, 'h'},
        {"version",          no_argument, 0, 'V'},
        {"prune-timeout",    required_argument, 0, OPT_PRUNE_TIMEOUT},
        {"appctl-command",   required_argument, 0, OPT_APPCTL_COMMAND},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    appctl_command = xasprintf("%s/ovs-appctl %%s", ovs_bindir());
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
        ovs_fatal(0, "database socket is non-option argument; "
                "use --help for usage");
    }

    return argv[0];
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
