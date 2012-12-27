/* Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <sys/wait.h>
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
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "openvswitch/brcompat-netlink.h"
#include "packets.h"
#include "poll-loop.h"
#include "process.h"
#include "rtnetlink-link.h"
#include "signals.h"
#include "sset.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(brcompatd);

/* xxx Just hangs if datapath is rmmod/insmod.  Learn to reconnect? */

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 60);

/* --appctl: Absolute path to ovs-appctl. */
static char *appctl_program;

/* --vsctl: Absolute path to ovs-vsctl. */
static char *vsctl_program;

/* Options that we should generally pass to ovs-vsctl. */
#define VSCTL_OPTIONS "--timeout=5", "-vconsole:warn"

/* Netlink socket to bridge compatibility kernel module. */
static struct nl_sock *brc_sock;

/* The Generic Netlink family number used for bridge compatibility. */
static int brc_family;

static const struct nl_policy brc_multicast_policy[] = {
    [BRC_GENL_A_MC_GROUP] = {.type = NL_A_U32 }
};

static char *
capture_vsctl_valist(const char *arg0, va_list args)
{
    char *stdout_log, *stderr_log;
    enum vlog_level log_level;
    struct svec argv;
    int status;
    char *msg;

    /* Compose arguments. */
    svec_init(&argv);
    svec_add(&argv, arg0);
    for (;;) {
        const char *arg = va_arg(args, const char *);
        if (!arg) {
            break;
        }
        svec_add(&argv, arg);
    }
    svec_terminate(&argv);

    /* Run process. */
    if (process_run_capture(argv.names, &stdout_log, &stderr_log, SIZE_MAX,
                            &status)) {
        svec_destroy(&argv);
        return NULL;
    }

    /* Log results. */
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        log_level = code == 0 ? VLL_DBG : code == 1 ? VLL_WARN : VLL_ERR;
    } else {
        log_level = VLL_ERR;
    }
    msg = process_status_msg(status);
    VLOG(log_level, "ovs-vsctl exited (%s)", msg);
    if (stdout_log && *stdout_log) {
        VLOG(log_level, "ovs-vsctl wrote to stdout:\n%s\n", stdout_log);
    }
    if (stderr_log && *stderr_log) {
        VLOG(log_level, "ovs-vsctl wrote to stderr:\n%s\n", stderr_log);
    }
    free(msg);

    svec_destroy(&argv);

    free(stderr_log);
    if (WIFEXITED(status) && !WEXITSTATUS(status)) {
        return stdout_log;
    } else {
        free(stdout_log);
        return NULL;
    }
}

static char * SENTINEL(0)
capture_vsctl(const char *arg0, ...)
{
    char *stdout_log;
    va_list args;

    va_start(args, arg0);
    stdout_log = capture_vsctl_valist(arg0, args);
    va_end(args);

    return stdout_log;
}

static bool SENTINEL(0)
run_vsctl(const char *arg0, ...)
{
    char *stdout_log;
    va_list args;
    bool ok;

    va_start(args, arg0);
    stdout_log = capture_vsctl_valist(arg0, args);
    va_end(args);

    ok = stdout_log != NULL;
    free(stdout_log);
    return ok;
}

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

/* Composes and returns a reply to a request made by the datapath with error
 * code 'error'.  The caller may add additional attributes to the message, then
 * it may send it with send_reply(). */
static struct ofpbuf *
compose_reply(int error)
{
    struct ofpbuf *reply = ofpbuf_new(4096);
    nl_msg_put_genlmsghdr(reply, 32, brc_family, NLM_F_REQUEST,
                          BRC_GENL_C_DP_RESULT, 1);
    nl_msg_put_u32(reply, BRC_GENL_A_ERR_CODE, error);
    return reply;
}

/* Sends 'reply' to the datapath, using sequence number 'nlmsg_seq', and frees
 * it. */
static void
send_reply(struct ofpbuf *reply, uint32_t nlmsg_seq)
{
    int retval = nl_sock_send_seq(brc_sock, reply, nlmsg_seq, false);
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
    send_reply(compose_reply(error), seq);
}

static int
handle_bridge_cmd(struct ofpbuf *buffer, bool add)
{
    const char *br_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, NULL, NULL, NULL);
    if (!error) {
        const char *vsctl_cmd = add ? "add-br" : "del-br";
        const char *brctl_cmd = add ? "addbr" : "delbr";
        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", vsctl_cmd, br_name,
                       "--", "comment", "ovs-brcompatd:", brctl_cmd, br_name,
                       (char *) NULL)) {
            error = add ? EEXIST : ENXIO;
        }
        send_simple_reply(seq, error);
    }
    return error;
}

static const struct nl_policy brc_port_policy[] = {
    [BRC_GENL_A_DP_NAME] = { .type = NL_A_STRING },
    [BRC_GENL_A_PORT_NAME] = { .type = NL_A_STRING },
};

static int
handle_port_cmd(struct ofpbuf *buffer, bool add)
{
    const char *br_name, *port_name;
    uint32_t seq;
    int error;

    error = parse_command(buffer, &seq, &br_name, &port_name, NULL, NULL);
    if (!error) {
        const char *vsctl_cmd = add ? "add-port" : "del-port";
        const char *brctl_cmd = add ? "addif" : "delif";
        if (!run_vsctl(vsctl_program, VSCTL_OPTIONS,
                       "--", vsctl_cmd, br_name, port_name,
                       "--", "comment", "ovs-brcompatd:", brctl_cmd,
                       br_name, port_name, (char *) NULL)) {
            error = EINVAL;
        }
        send_simple_reply(seq, error);
    }
    return error;
}

static char *
linux_bridge_to_ovs_bridge(const char *linux_name, int *br_vlanp)
{
    char *save_ptr = NULL;
    const char *br_name, *br_vlan;
    char *br_name_copy;
    char *output;

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS,
                           "--", "br-to-parent", linux_name,
                           "--", "br-to-vlan", linux_name,
                           (char *) NULL);
    if (!output) {
        return NULL;
    }

    br_name = strtok_r(output, " \t\r\n", &save_ptr);
    br_vlan = strtok_r(NULL, " \t\r\n", &save_ptr);
    if (!br_name || !br_vlan) {
        free(output);
        return NULL;
    }
    br_name_copy = xstrdup(br_name);
    *br_vlanp = atoi(br_vlan);

    free(output);

    return br_name_copy;
}

static void
get_bridge_ifaces(const char *br_name, struct sset *ifaces)
{
    char *save_ptr = NULL;
    char *output;
    char *iface;

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-ifaces",
                           br_name, (char *) NULL);
    if (!output) {
        return;
    }

    for (iface = strtok_r(output, " \t\r\n", &save_ptr); iface;
         iface = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        sset_add(ifaces, iface);
    }
    free(output);
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
    const char *linux_name;   /* Name used by brctl. */
    int br_vlan;                /* VLAN tag. */
    struct sset ifaces;

    struct ofpbuf query_data;
    const char *iface_name;
    struct ofpbuf *reply;
    uint64_t count, skip;
    char *br_name;
    char *output;
    char *save_ptr;
    uint32_t seq;
    int error;

    /* Parse the command received from brcompat. */
    error = parse_command(buffer, &seq, &linux_name, NULL, &count, &skip);
    if (error) {
        return error;
    }

    /* Figure out vswitchd bridge and VLAN. */
    br_name = linux_bridge_to_ovs_bridge(linux_name, &br_vlan);
    if (!br_name) {
        error = EINVAL;
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the forwarding database using ovs-appctl. */
    output = capture_vsctl(appctl_program, "fdb/show", br_name,
                           (char *) NULL);
    if (!output) {
        error = ECHILD;
        send_simple_reply(seq, error);
        return error;
    }

    /* Fetch the MAC address for each interface on the bridge, so that we can
     * fill in the is_local field in the response. */
    sset_init(&ifaces);
    get_bridge_ifaces(linux_name, &ifaces);
    local_macs = xmalloc(sset_count(&ifaces) * sizeof *local_macs);
    n_local_macs = 0;
    SSET_FOR_EACH (iface_name, &ifaces) {
        struct mac *mac = &local_macs[n_local_macs];
        struct netdev *netdev;

        error = netdev_open(iface_name, "system", &netdev);
        if (!error) {
            if (!netdev_get_etheraddr(netdev, mac->addr)) {
                n_local_macs++;
            }
            netdev_close(netdev);
        }
    }
    sset_destroy(&ifaces);

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
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_FDB_DATA,
                      query_data.data, query_data.size);
    send_reply(reply, seq);

    /* Free memory. */
    ofpbuf_uninit(&query_data);
    free(local_macs);

    return 0;
}

static void
send_ifindex_reply(uint32_t seq, char *output)
{
    size_t allocated_indices;
    char *save_ptr = NULL;
    struct ofpbuf *reply;
    const char *iface;
    size_t n_indices;
    int *indices;

    indices = NULL;
    n_indices = allocated_indices = 0;
    for (iface = strtok_r(output, " \t\r\n", &save_ptr); iface;
         iface = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        int ifindex;

        if (n_indices >= allocated_indices) {
            indices = x2nrealloc(indices, &allocated_indices, sizeof *indices);
        }

        ifindex = if_nametoindex(iface);
        if (ifindex) {
            indices[n_indices++] = ifindex;
        }
    }

    /* Compose and send reply. */
    reply = compose_reply(0);
    nl_msg_put_unspec(reply, BRC_GENL_A_IFINDEXES,
                      indices, n_indices * sizeof *indices);
    send_reply(reply, seq);

    /* Free memory. */
    free(indices);
}

static int
handle_get_bridges_cmd(struct ofpbuf *buffer)
{
    char *output;
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

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-br", (char *) NULL);
    if (!output) {
        return ENODEV;
    }

    send_ifindex_reply(seq, output);
    free(output);
    return 0;
}

static int
handle_get_ports_cmd(struct ofpbuf *buffer)
{
    const char *linux_name;
    uint32_t seq;
    char *output;
    int error;

    /* Parse Netlink command. */
    error = parse_command(buffer, &seq, &linux_name, NULL, NULL, NULL);
    if (error) {
        return error;
    }

    output = capture_vsctl(vsctl_program, VSCTL_OPTIONS, "list-ports", linux_name,
                           (char *) NULL);
    if (!output) {
        return ENODEV;
    }

    send_ifindex_reply(seq, output);
    free(output);
    return 0;
}

static bool
brc_recv_update__(struct ofpbuf *buffer)
{
    for (;;) {
        int retval = nl_sock_recv(brc_sock, buffer, false);
        switch (retval) {
        case 0:
            if (nl_msg_nlmsgerr(buffer, NULL)
                || nl_msg_nlmsghdr(buffer)->nlmsg_type == NLMSG_DONE) {
                break;
            }
            return true;

        case ENOBUFS:
            break;

        case EAGAIN:
            return false;

        default:
            VLOG_WARN_RL(&rl, "brc_recv_update: %s", strerror(retval));
            return false;
        }
    }
}

static void
brc_recv_update(void)
{
    struct genlmsghdr *genlmsghdr;
    uint64_t buffer_stub[1024 / 8];
    struct ofpbuf buffer;

    ofpbuf_use_stub(&buffer, buffer_stub, sizeof buffer_stub);
    if (!brc_recv_update__(&buffer)) {
        goto error;
    }

    genlmsghdr = nl_msg_genlmsghdr(&buffer);
    if (!genlmsghdr) {
        VLOG_WARN_RL(&rl, "received packet too short for generic NetLink");
        goto error;
    }

    if (nl_msg_nlmsghdr(&buffer)->nlmsg_type != brc_family) {
        VLOG_DBG_RL(&rl, "received type (%"PRIu16") != brcompat family (%d)",
                nl_msg_nlmsghdr(&buffer)->nlmsg_type, brc_family);
        goto error;
    }

    /* Service all pending network device notifications before executing the
     * command.  This is very important to avoid a race in a scenario like the
     * following, which is what happens with XenServer Tools version 5.0.0
     * during boot of a Windows VM:
     *
     *      1. Create tap1.0 and vif1.0.
     *      2. Delete tap1.0.
     *      3. Delete vif1.0.
     *      4. Re-create vif1.0.
     *
     * We must process the network device notification from step 3 before we
     * process the brctl command from step 4.  If we process them in the
     * reverse order, then step 4 completes as a no-op but step 3 then deletes
     * the port that was just added.
     *
     * (XenServer Tools 5.5.0 does not exhibit this behavior, and neither does
     * a VM without Tools installed at all.)
     */
    rtnetlink_link_run();

    switch (genlmsghdr->cmd) {
    case BRC_GENL_C_DP_ADD:
        handle_bridge_cmd(&buffer, true);
        break;

    case BRC_GENL_C_DP_DEL:
        handle_bridge_cmd(&buffer, false);
        break;

    case BRC_GENL_C_PORT_ADD:
        handle_port_cmd(&buffer, true);
        break;

    case BRC_GENL_C_PORT_DEL:
        handle_port_cmd(&buffer, false);
        break;

    case BRC_GENL_C_FDB_QUERY:
        handle_fdb_query_cmd(&buffer);
        break;

    case BRC_GENL_C_GET_BRIDGES:
        handle_get_bridges_cmd(&buffer);
        break;

    case BRC_GENL_C_GET_PORTS:
        handle_get_ports_cmd(&buffer);
        break;

    default:
        VLOG_WARN_RL(&rl, "received unknown brc netlink command: %d\n",
                     genlmsghdr->cmd);
        break;
    }

error:
    ofpbuf_uninit(&buffer);
}

static void
netdev_changed_cb(const struct rtnetlink_link_change *change,
                  void *aux OVS_UNUSED)
{
    char br_name[IFNAMSIZ];
    const char *port_name;

    if (!change) {
        VLOG_WARN_RL(&rl, "network monitor socket overflowed");
        return;
    }

    if (change->nlmsg_type != RTM_DELLINK || !change->master_ifindex) {
        return;
    }

    port_name = change->ifname;
    if (!if_indextoname(change->master_ifindex, br_name)) {
        return;
    }

    VLOG_INFO("network device %s destroyed, removing from bridge %s",
              port_name, br_name);

    run_vsctl(vsctl_program, VSCTL_OPTIONS,
              "--", "--if-exists", "del-port", port_name,
              "--", "comment", "ovs-brcompatd:", port_name, "disappeared",
              (char *) NULL);
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct nln_notifier *link_notifier;
    struct unixctl_server *unixctl;
    int retval;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_FACILITY, VLL_WARN);

    VLOG_WARN("Bridge compatibility is deprecated and may be removed "
              "no earlier than February 2013");
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    process_init();

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    if (brc_open(&brc_sock)) {
        VLOG_FATAL("could not open brcompat socket.  Check "
                   "\"brcompat\" kernel module.");
    }

    link_notifier = rtnetlink_link_notifier_create(netdev_changed_cb, NULL);

    daemonize_complete();

    for (;;) {
        unixctl_server_run(unixctl);
        rtnetlink_link_run();
        brc_recv_update();

        netdev_run();

        nl_sock_wait(brc_sock, POLLIN);
        unixctl_server_wait(unixctl);
        rtnetlink_link_wait();
        netdev_wait();
        poll_block();
    }

    rtnetlink_link_notifier_destroy(link_notifier);

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_APPCTL,
        OPT_VSCTL,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",             no_argument, NULL, 'h'},
        {"version",          no_argument, NULL, 'V'},
        {"appctl",           required_argument, NULL, OPT_APPCTL},
        {"vsctl",            required_argument, NULL, OPT_VSCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    const char *appctl = "ovs-appctl";
    const char *vsctl = "ovs-vsctl";

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case OPT_APPCTL:
            appctl = optarg;
            break;

        case OPT_VSCTL:
            vsctl = optarg;
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

    appctl_program = process_search_path(appctl);
    if (!appctl_program) {
        VLOG_FATAL("%s: not found in $PATH (use --appctl to specify an "
                   "alternate location)", appctl);
    }

    vsctl_program = process_search_path(vsctl);
    if (!vsctl_program) {
        VLOG_FATAL("%s: not found in $PATH (use --vsctl to specify an "
                   "alternate location)", vsctl);
    }

    if (argc != optind) {
        VLOG_FATAL("no non-option arguments are supported; "
                   "use --help for usage");
    }
}

static void
usage(void)
{
    printf("%s: bridge compatibility front-end for ovs-vswitchd\n"
           "usage: %s [OPTIONS]\n",
           program_name, program_name);
    printf("\nConfiguration options:\n"
           "  --appctl=PROGRAM        overrides $PATH for finding ovs-appctl\n"
           "  --vsctl=PROGRAM         overrides $PATH for finding ovs-vsctl\n"
          );
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
