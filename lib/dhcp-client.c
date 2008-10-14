/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "dhcp-client.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "csum.h"
#include "dhcp.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "sat-math.h"
#include "timeval.h"

#define THIS_MODULE VLM_dhcp_client
#include "vlog.h"

#define DHCLIENT_STATES                         \
    DHCLIENT_STATE(INIT, 1 << 0)                \
    DHCLIENT_STATE(INIT_REBOOT, 1 << 1)         \
    DHCLIENT_STATE(REBOOTING, 1 << 2)           \
    DHCLIENT_STATE(SELECTING, 1 << 3)           \
    DHCLIENT_STATE(REQUESTING, 1 << 4)          \
    DHCLIENT_STATE(BOUND, 1 << 5)               \
    DHCLIENT_STATE(RENEWING, 1 << 6)            \
    DHCLIENT_STATE(REBINDING, 1 << 7)           \
    DHCLIENT_STATE(RELEASED, 1 << 8)
enum dhclient_state {
#define DHCLIENT_STATE(NAME, VALUE) S_##NAME = VALUE,
    DHCLIENT_STATES
#undef DHCLIENT_STATE
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static const char *
state_name(enum dhclient_state state)
{
    switch (state) {
#define DHCLIENT_STATE(NAME, VALUE) case S_##NAME: return #NAME;
        DHCLIENT_STATES
#undef DHCLIENT_STATE
    }
    return "***ERROR***";
}

struct dhclient {
    /* Configuration. */
    struct netdev *netdev;

    void (*modify_request)(struct dhcp_msg *, void *aux);
    bool (*validate_offer)(const struct dhcp_msg *, void *aux);
    void *aux;

    /* DHCP state. */
    enum dhclient_state state;
    unsigned int state_entered; /* When we transitioned to this state. */
    uint32_t xid;               /* In host byte order. */
    uint32_t ipaddr, netmask, router;
    uint32_t server_ip;
    struct dhcp_msg *binding;
    bool changed;

    unsigned int retransmit, delay; /* Used by send_reliably(). */
    unsigned int max_timeout;

    unsigned int init_delay;    /* Used by S_INIT. */

    time_t lease_expiration;
    unsigned int bound_timeout;
    unsigned int renewing_timeout;
    unsigned int rebinding_timeout;

    /* Used by dhclient_run() and dhclient_wait() */
    unsigned int min_timeout;
    int received;

    /* Set when we send out a DHCPDISCOVER message. */
    uint32_t secs;

    struct ds s;
};

/* Minimum acceptable lease time, in seconds. */
#define MIN_ACCEPTABLE_LEASE 15

static void state_transition(struct dhclient *, enum dhclient_state);
static unsigned int elapsed_in_this_state(const struct dhclient *cli);
static bool timeout(struct dhclient *, unsigned int secs);

static void dhclient_msg_init(struct dhclient *, enum dhcp_msg_type,
                              struct dhcp_msg *);
static void send_reliably(struct dhclient *cli,
                          void (*make_packet)(struct dhclient *,
                                              struct dhcp_msg *));
static bool do_receive_msg(struct dhclient *, struct dhcp_msg *);
static void do_send_msg(struct dhclient *, const struct dhcp_msg *);
static bool receive_ack(struct dhclient *);

static unsigned int fuzz(unsigned int x, int max_fuzz);
static unsigned int calc_t2(unsigned int lease);
static unsigned int calc_t1(unsigned int lease, unsigned int t2);

static unsigned int clamp(unsigned int x, unsigned int min, unsigned int max);

/* Creates a new DHCP client to configure the network device 'netdev_name'
 * (e.g. "eth0").
 *
 * If 'modify_request' is non-null, then each DHCP message to discover or
 * request an address will be passed to it (along with auxiliary data 'aux').
 * It may then add any desired options to the message for transmission.
 *
 * If 'validate_offer' is non-null, then each DHCP message that offers an
 * address will be passed to it (along with auxiliary data 'aux') for
 * validation: if it returns true, the address will accepted; otherwise, it
 * will be rejected.
 *
 * The DHCP client will not start advertising for an IP address until
 * dhclient_init() is called.
 *
 * If successful, returns 0 and sets '*cli' to the new DHCP client.  Otherwise,
 * returns a positive errno value and sets '*cli' to a null pointer. */
int
dhclient_create(const char *netdev_name,
                void (*modify_request)(struct dhcp_msg *, void *aux),
                bool (*validate_offer)(const struct dhcp_msg *, void *aux),
                void *aux, struct dhclient **cli_)
{
    struct dhclient *cli;
    struct netdev *netdev;
    int error;

    *cli_ = NULL;

    error = netdev_open(netdev_name, ETH_TYPE_IP, &netdev);
    /* XXX install socket filter to catch only DHCP packets. */
    if (error) {
        VLOG_ERR("could not open %s network device: %s",
                 netdev_name, strerror(error));
        return error;
    }

    error = netdev_turn_flags_on(netdev, NETDEV_UP, false);
    if (error) {
        VLOG_ERR("could not bring %s device up: %s",
                 netdev_name, strerror(error));
        netdev_close(netdev);
        return error;
    }

    cli = xcalloc(1, sizeof *cli);
    cli->modify_request = modify_request;
    cli->validate_offer = validate_offer;
    cli->aux = aux;
    cli->netdev = netdev;
    cli->state = S_RELEASED;
    cli->state_entered = time_now();
    cli->xid = random_uint32();
    cli->ipaddr = 0;
    cli->server_ip = 0;
    cli->retransmit = cli->delay = 0;
    cli->max_timeout = 64;
    cli->min_timeout = 1;
    ds_init(&cli->s);
    cli->changed = true;
    *cli_ = cli;
    return 0;
}

/* Sets the maximum amount of timeout that 'cli' will wait for a reply from
 * the DHCP server before retransmitting, in seconds, to 'max_timeout'.  The
 * default is 64 seconds. */
void
dhclient_set_max_timeout(struct dhclient *cli, unsigned int max_timeout)
{
    cli->max_timeout = MAX(2, max_timeout);
}

/* Destroys 'cli' and frees all related resources. */
void
dhclient_destroy(struct dhclient *cli)
{
    if (cli) {
        dhcp_msg_uninit(cli->binding);
        free(cli->binding);
        netdev_close(cli->netdev);
        ds_destroy(&cli->s);
        free(cli);
    }
}

/* Returns the network device in use by 'cli'.  The caller must not destroy
 * the returned device. */
struct netdev *
dhclient_get_netdev(struct dhclient *cli)
{
    return cli->netdev;
}

/* Forces 'cli' into a (re)initialization state, in which no address is bound
 * but the client is advertising to obtain one.  If 'requested_ip' is nonzero,
 * then the client will attempt to re-bind to that IP address; otherwise, it
 * will not ask for any particular address. */
void
dhclient_init(struct dhclient *cli, uint32_t requested_ip)
{
    state_transition(cli, requested_ip ? S_INIT_REBOOT : S_INIT);
    cli->ipaddr = requested_ip;
    cli->min_timeout = 0;
    cli->init_delay = 0;
}

/* Forces 'cli' to release its bound IP address (if any).  The client will not
 * advertise for a new address until dhclient_init() is called again. */
void
dhclient_release(struct dhclient *cli)
{
    if (dhclient_is_bound(cli)) {
        struct dhcp_msg msg;
        dhclient_msg_init(cli, DHCPRELEASE, &msg);
        msg.ciaddr = cli->ipaddr;
        do_send_msg(cli, &msg);
        dhcp_msg_uninit(&msg);
    }
    state_transition(cli, S_RELEASED);
    cli->min_timeout = UINT_MAX;
}

static void
do_force_renew(struct dhclient *cli, int deadline)
{
    time_t now = time_now();
    unsigned int lease_left = sat_sub(cli->lease_expiration, now);
    if (lease_left <= deadline) {
        if (cli->state & (S_RENEWING | S_REBINDING)) {
            return;
        }
        deadline = lease_left;
    }
    if (cli->state & (S_BOUND | S_RENEWING)) {
        state_transition(cli, S_RENEWING);
        cli->renewing_timeout = deadline * 3 / 4;
        cli->rebinding_timeout = deadline * 1 / 4;
    } else {
        state_transition(cli, S_REBINDING);
        cli->rebinding_timeout = deadline;
    }
    cli->min_timeout = 0;
}

/* Forces 'cli' to attempt to renew the lease its current IP address (if any)
 * within 'deadline' seconds.  If the deadline is not met, then the client
 * gives up its IP address binding and re-starts the DHCP process. */
void
dhclient_force_renew(struct dhclient *cli, int deadline)
{
    /* Drain the receive queue so that we know that any DHCPACK we process is
     * freshly received. */
    netdev_drain(cli->netdev);

    switch (cli->state) {
    case S_INIT:
    case S_INIT_REBOOT:
    case S_REBOOTING:
    case S_SELECTING:
    case S_REQUESTING:
        break;

    case S_BOUND:
    case S_RENEWING:
    case S_REBINDING:
        do_force_renew(cli, deadline);
        break;

    case S_RELEASED:
        dhclient_init(cli, 0);
        break;
    }
}

/* Returns true if 'cli' is bound to an IP address, false otherwise. */
bool
dhclient_is_bound(const struct dhclient *cli)
{
    return cli->state & (S_BOUND | S_RENEWING | S_REBINDING);
}

/* Returns true if 'cli' has changed from bound to unbound, or vice versa, at
 * least once since the last time this function was called.  */
bool
dhclient_changed(struct dhclient *cli)
{
    bool changed = cli->changed;
    cli->changed = 0;
    return changed;
}

/* Returns 'cli''s current state, as a string.  The caller must not modify or
 * free the string. */
const char *
dhclient_get_state(const struct dhclient *cli)
{
    return state_name(cli->state);
}

/* Returns the number of seconds spent so far in 'cli''s current state. */
unsigned int
dhclient_get_state_elapsed(const struct dhclient *cli)
{
    return elapsed_in_this_state(cli);
}

/* If 'cli' is bound, returns the number of seconds remaining in its lease;
 * otherwise, returns 0. */
unsigned int
dhclient_get_lease_remaining(const struct dhclient *cli)
{
    return dhclient_is_bound(cli) ? cli->lease_expiration - time_now() : 0;
}

/* If 'cli' is bound to an IP address, returns that IP address; otherwise,
 * returns 0. */
uint32_t
dhclient_get_ip(const struct dhclient *cli)
{
    return dhclient_is_bound(cli) ? cli->ipaddr : 0;
}

/* If 'cli' is bound to an IP address, returns the netmask for that IP address;
 * otherwise, returns 0. */
uint32_t
dhclient_get_netmask(const struct dhclient *cli)
{
    return dhclient_is_bound(cli) ? cli->netmask : 0;
}

/* If 'cli' is bound to an IP address and 'cli' has a default gateway, returns
 * that default gateway; otherwise, returns 0. */
uint32_t
dhclient_get_router(const struct dhclient *cli)
{
    return dhclient_is_bound(cli) ? cli->router : 0;
}

/* If 'cli' is bound to an IP address, returns the DHCP message that was
 * received to obtain that IP address (so that the caller can obtain additional
 * options from it).  Otherwise, returns a null pointer. */
const struct dhcp_msg *
dhclient_get_config(const struct dhclient *cli)
{
    return dhclient_is_bound(cli) ? cli->binding : NULL;
}

/* Configures the network device backing 'cli' to the network address and other
 * parameters obtained via DHCP.  If no address is bound on 'cli', removes any
 * configured address from 'cli'.
 *
 * To use a dhclient as a regular DHCP client that binds and unbinds from IP
 * addresses in the usual fashion, call this function after dhclient_run() if
 * anything has changed, like so:
 *
 * dhclient_run(cli);
 * if (dhclient_changed(cli)) {
 *     dhclient_configure_netdev(cli);
 * }
 *
 */
int
dhclient_configure_netdev(struct dhclient *cli)
{
    struct in_addr addr = { dhclient_get_ip(cli) };
    struct in_addr mask = { dhclient_get_netmask(cli) };
    struct in_addr router = { dhclient_get_router(cli) };
    int error;

    error = netdev_set_in4(cli->netdev, addr, mask);
    if (error) {
        VLOG_ERR("could not set %s address "IP_FMT"/"IP_FMT": %s",
                 netdev_get_name(cli->netdev),
                 IP_ARGS(&addr.s_addr), IP_ARGS(&mask.s_addr),
                 strerror(error));
    }

    if (!error && router.s_addr) {
        error = netdev_add_router(cli->netdev, router);
        if (error) {
            VLOG_ERR("failed to add default route to "IP_FMT" on %s: %s",
                     IP_ARGS(&router), netdev_get_name(cli->netdev),
                     strerror(error));
        }
    }

    return error;
}

/* If 'cli' is bound and the binding includes DNS domain parameters, updates
 * /etc/resolv.conf will be updated to match the received parameters.  Returns
 * 0 if successful, otherwise a positive errno value. */
int
dhclient_update_resolv_conf(struct dhclient *cli)
{
    uint32_t dns_server;
    char *domain_name;
    bool has_domain_name;
    char new_name[128];
    FILE *old, *new;
    int i;

    if (!dhclient_is_bound(cli)) {
        return 0;
    }
    if (!dhcp_msg_get_ip(cli->binding, DHCP_CODE_DNS_SERVER, 0, &dns_server)) {
        VLOG_DBG("binding does not include any DNS servers");
        return 0;
    }

    sprintf(new_name, "/etc/resolv.conf.tmp%ld", (long int) getpid());
    new = fopen(new_name, "w");
    if (!new) {
        VLOG_WARN("%s: create: %s", new_name, strerror(errno));
        return errno;
    }

    domain_name = dhcp_msg_get_string(cli->binding, DHCP_CODE_DOMAIN_NAME);
    has_domain_name = domain_name != NULL;
    if (domain_name) {
        if (strspn(domain_name, "-_.0123456789abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == strlen(domain_name)) {
            fprintf(new, "domain %s\n", domain_name);
        } else {
            VLOG_WARN("ignoring invalid domain name %s", domain_name);
            has_domain_name = false;
        }
    } else {
        VLOG_DBG("binding does not include domain name");
    }
    free(domain_name);

    for (i = 0; dhcp_msg_get_ip(cli->binding, DHCP_CODE_DNS_SERVER,
                                i, &dns_server); i++) {
        fprintf(new, "nameserver "IP_FMT"\n", IP_ARGS(&dns_server));
    }

    old = fopen("/etc/resolv.conf", "r");
    if (old) {
        char line[128];

        while (fgets(line, sizeof line, old)) {
            char *kw = xmemdup0(line, strcspn(line, " \t\r\n"));
            if (strcmp(kw, "nameserver")
                && (!has_domain_name
                    || (strcmp(kw, "domain") && strcmp(kw, "search")))) {
                fputs(line, new);
            }
            free(kw);
        }
        fclose(old);
    } else {
        VLOG_DBG("/etc/resolv.conf: open: %s", strerror(errno));
    }

    if (fclose(new) < 0) {
        VLOG_WARN("%s: close: %s", new_name, strerror(errno));
        return errno;
    }

    if (rename(new_name, "/etc/resolv.conf") < 0) {
        VLOG_WARN("failed to rename %s to /etc/resolv.conf: %s",
                  new_name, strerror(errno));
        return errno;
    }

    return 0;
}

/* DHCP protocol. */

static void
make_dhcpdiscover(struct dhclient *cli, struct dhcp_msg *msg)
{
    cli->secs = elapsed_in_this_state(cli);
    dhclient_msg_init(cli, DHCPDISCOVER, msg);
    if (cli->ipaddr) {
        dhcp_msg_put_ip(msg, DHCP_CODE_REQUESTED_IP, cli->ipaddr);
    }
}

static void
make_dhcprequest(struct dhclient *cli, struct dhcp_msg *msg)
{
    dhclient_msg_init(cli, DHCPREQUEST, msg);
    msg->ciaddr = dhclient_get_ip(cli);
    if (cli->state == S_REQUESTING) {
        dhcp_msg_put_ip(msg, DHCP_CODE_SERVER_IDENTIFIER, cli->server_ip);
    }
    dhcp_msg_put_ip(msg, DHCP_CODE_REQUESTED_IP, cli->ipaddr);
}

static void
do_init(struct dhclient *cli, enum dhclient_state next_state)
{
    if (!cli->init_delay) {
        cli->init_delay = fuzz(2, 1);
    }
    if (timeout(cli, cli->init_delay)) {
        state_transition(cli, next_state);
    }
}

static void
dhclient_run_INIT(struct dhclient *cli)
{
    do_init(cli, S_SELECTING);
}

static void
dhclient_run_INIT_REBOOT(struct dhclient *cli)
{
    do_init(cli, S_REBOOTING);
}

static void
dhclient_run_REBOOTING(struct dhclient *cli)
{
    send_reliably(cli, make_dhcprequest);
    if (!receive_ack(cli) && timeout(cli, 60)) {
        state_transition(cli, S_INIT);
    }
}

static bool
dhcp_receive(struct dhclient *cli, unsigned int msgs, struct dhcp_msg *msg)
{
    while (do_receive_msg(cli, msg)) {
        if (msg->type < 0 || msg->type > 31 || !((1u << msg->type) & msgs)) {
            VLOG_DBG_RL(&rl, "received unexpected %s in %s state: %s",
                        dhcp_type_name(msg->type), state_name(cli->state),
                        dhcp_msg_to_string(msg, false, &cli->s));
        } else if (msg->xid != cli->xid) {
            VLOG_DBG_RL(&rl,
                        "ignoring %s with xid != %08"PRIx32" in %s state: %s",
                        dhcp_type_name(msg->type), msg->xid,
                        state_name(cli->state),
                        dhcp_msg_to_string(msg, false, &cli->s));
        } else {
            return true;
        }
        dhcp_msg_uninit(msg);
    }
    return false;
}

static bool
validate_offered_options(struct dhclient *cli, const struct dhcp_msg *msg)
{
    uint32_t lease, netmask;
    if (!dhcp_msg_get_secs(msg, DHCP_CODE_LEASE_TIME, 0, &lease)) {
        VLOG_WARN_RL(&rl, "%s lacks lease time: %s", dhcp_type_name(msg->type),
                     dhcp_msg_to_string(msg, false, &cli->s));
    } else if (!dhcp_msg_get_ip(msg, DHCP_CODE_SUBNET_MASK, 0, &netmask)) {
        VLOG_WARN_RL(&rl, "%s lacks netmask: %s", dhcp_type_name(msg->type),
                     dhcp_msg_to_string(msg, false, &cli->s));
    } else if (lease < MIN_ACCEPTABLE_LEASE) {
        VLOG_WARN_RL(&rl, "Ignoring %s with %"PRIu32"-second lease time: %s",
                     dhcp_type_name(msg->type), lease,
                     dhcp_msg_to_string(msg, false, &cli->s));
    } else if (cli->validate_offer && !cli->validate_offer(msg, cli->aux)) {
        VLOG_DBG_RL(&rl, "client validation hook refused offer: %s",
                    dhcp_msg_to_string(msg, false, &cli->s));
    } else {
        return true;
    }
    return false;
}

static void
dhclient_run_SELECTING(struct dhclient *cli)
{
    struct dhcp_msg msg;

    send_reliably(cli, make_dhcpdiscover);
    if (cli->server_ip && timeout(cli, 60)) {
        cli->server_ip = 0;
        state_transition(cli, S_INIT);
    }
    for (; dhcp_receive(cli, 1u << DHCPOFFER, &msg); dhcp_msg_uninit(&msg)) {
        if (!validate_offered_options(cli, &msg)) {
            continue;
        }
        if (!dhcp_msg_get_ip(&msg, DHCP_CODE_SERVER_IDENTIFIER,
                             0, &cli->server_ip)) {
            VLOG_WARN_RL(&rl, "DHCPOFFER lacks server identifier: %s",
                         dhcp_msg_to_string(&msg, false, &cli->s));
            continue;
        }

        VLOG_DBG_RL(&rl, "accepting DHCPOFFER: %s",
                    dhcp_msg_to_string(&msg, false, &cli->s));
        cli->ipaddr = msg.yiaddr;
        state_transition(cli, S_REQUESTING);
        break;
    }
}

static bool
same_binding(const struct dhcp_msg *old, const struct dhcp_msg *new)
{
    static const int codes[] = {
        DHCP_CODE_SUBNET_MASK,
        DHCP_CODE_ROUTER,
        DHCP_CODE_DNS_SERVER,
        DHCP_CODE_HOST_NAME,
        DHCP_CODE_DOMAIN_NAME,
        DHCP_CODE_IP_TTL,
        DHCP_CODE_MTU,
        DHCP_CODE_BROADCAST_ADDRESS,
        DHCP_CODE_STATIC_ROUTE,
        DHCP_CODE_ARP_CACHE_TIMEOUT,
        DHCP_CODE_ETHERNET_ENCAPSULATION,
        DHCP_CODE_TCP_TTL,
        DHCP_CODE_SERVER_IDENTIFIER,
        DHCP_CODE_OFP_CONTROLLER_VCONN,
        DHCP_CODE_OFP_PKI_URI,
    };
    int i;
    bool same = true;

    if (old->yiaddr != new->yiaddr) {
        VLOG_WARN("DHCP binding changed IP address from "IP_FMT" to "IP_FMT,
                  IP_ARGS(&old->yiaddr), IP_ARGS(&new->yiaddr));
        same = false;
    }
    for (i = 0; i < ARRAY_SIZE(codes); i++) {
        int code = codes[i];
        const struct dhcp_option *old_opt = &old->options[code];
        const struct dhcp_option *new_opt = &new->options[code];
        if (!dhcp_option_equals(old_opt, new_opt)) {
            struct ds old_string = DS_EMPTY_INITIALIZER;
            struct ds new_string = DS_EMPTY_INITIALIZER;
            VLOG_WARN("DHCP binding changed option from %s to %s",
                      dhcp_option_to_string(old_opt, code, &old_string),
                      dhcp_option_to_string(new_opt, code, &new_string));
            ds_destroy(&old_string);
            ds_destroy(&new_string);
            same = false;
        }
    }
    return same;
}

static bool
receive_ack(struct dhclient *cli)
{
    struct dhcp_msg msg;

    if (!dhcp_receive(cli, (1u << DHCPACK) | (1u << DHCPNAK), &msg)) {
        return false;
    } else if (msg.type == DHCPNAK) {
        dhcp_msg_uninit(&msg);
        state_transition(cli, S_INIT);
        return true;
    } else if (!validate_offered_options(cli, &msg)) {
        dhcp_msg_uninit(&msg);
        return false;
    } else {
        uint32_t lease = 0, t1 = 0, t2 = 0;

        if (cli->binding) {
            if (!same_binding(cli->binding, &msg)) {
                cli->changed = true;
            }
            dhcp_msg_uninit(cli->binding);
        } else {
            cli->binding = xmalloc(sizeof *cli->binding);
        }
        dhcp_msg_copy(cli->binding, &msg);

        dhcp_msg_get_secs(&msg, DHCP_CODE_LEASE_TIME, 0, &lease);
        dhcp_msg_get_secs(&msg, DHCP_CODE_T1, 0, &t1);
        dhcp_msg_get_secs(&msg, DHCP_CODE_T2, 0, &t2);
        assert(lease >= MIN_ACCEPTABLE_LEASE);

        if (!t2 || t2 >= lease) {
            t2 = calc_t2(lease);
        }
        if (!t1 || t1 >= t2) {
            t1 = calc_t1(lease, t2);
        }

        cli->lease_expiration = sat_add(time_now(), lease);
        cli->bound_timeout = t1;
        cli->renewing_timeout = t2 - t1;
        cli->rebinding_timeout = lease - t2;

        cli->ipaddr = msg.yiaddr;
        dhcp_msg_get_ip(&msg, DHCP_CODE_SUBNET_MASK, 0, &cli->netmask);
        if (!dhcp_msg_get_ip(&msg, DHCP_CODE_ROUTER, 0, &cli->router)) {
            cli->router = INADDR_ANY;
        }
        state_transition(cli, S_BOUND);
        VLOG_DBG("Bound: %s", dhcp_msg_to_string(&msg, false, &cli->s));
        return true;
    }
}

static void
dhclient_run_REQUESTING(struct dhclient *cli)
{
    send_reliably(cli, make_dhcprequest);
    if (!receive_ack(cli) && timeout(cli, 60)) {
        state_transition(cli, S_INIT);
    }
}

static void
dhclient_run_BOUND(struct dhclient *cli)
{
    if (timeout(cli, cli->bound_timeout)) {
        state_transition(cli, S_RENEWING);
    }
}

static void
dhclient_run_RENEWING(struct dhclient *cli)
{
    send_reliably(cli, make_dhcprequest);
    if (!receive_ack(cli) && timeout(cli, cli->renewing_timeout)) {
        state_transition(cli, S_REBINDING);
    }
}

static void
dhclient_run_REBINDING(struct dhclient *cli)
{
    send_reliably(cli, make_dhcprequest);
    if (!receive_ack(cli) && timeout(cli, cli->rebinding_timeout)) {
        state_transition(cli, S_INIT);
    }
}

static void
dhclient_run_RELEASED(struct dhclient *cli UNUSED)
{
    /* Nothing to do. */
}

/* Processes the DHCP protocol for 'cli'. */
void
dhclient_run(struct dhclient *cli)
{
    int old_state;
    do {
        old_state = cli->state;
        cli->min_timeout = UINT_MAX;
        cli->received = 0;
        switch (cli->state) {
#define DHCLIENT_STATE(NAME, VALUE) \
            case S_##NAME: dhclient_run_##NAME(cli); break;
            DHCLIENT_STATES
#undef DHCLIENT_STATE
        default:
            NOT_REACHED();
        }
    } while (cli->state != old_state);
}

/* Sets up poll timeouts to wake up the poll loop when 'cli' needs to do some
 * work. */
void
dhclient_wait(struct dhclient *cli)
{
    if (cli->min_timeout != UINT_MAX) {
        time_t now = time_now();
        unsigned int wake = sat_add(cli->state_entered, cli->min_timeout);
        if (wake <= now) {
            poll_immediate_wake();
        } else {
            poll_timer_wait(sat_mul(sat_sub(wake, now), 1000));
        }
    }
    /* Reset timeout to 1 second.  This will have no effect ordinarily, because
     * dhclient_run() will typically set it back to a higher value.  If,
     * however, the caller fails to call dhclient_run() before its next call to
     * dhclient_wait() we won't potentially block forever. */
    cli->min_timeout = 1;

    if (cli->state & (S_SELECTING | S_REQUESTING | S_RENEWING | S_REBINDING)) {
        netdev_recv_wait(cli->netdev);
    }
}

static void
state_transition(struct dhclient *cli, enum dhclient_state state)
{
    bool was_bound = dhclient_is_bound(cli);
    bool am_bound;
    if (cli->state != state) {
        VLOG_DBG("entering %s", state_name(state)); 
        cli->state = state;
    }
    cli->state_entered = time_now();
    cli->retransmit = cli->delay = 0;
    am_bound = dhclient_is_bound(cli);
    if (was_bound != am_bound) {
        cli->changed = true;
        if (am_bound) {
            assert(cli->binding != NULL);
            VLOG_WARN("%s: obtained address "IP_FMT", netmask "IP_FMT,
                      netdev_get_name(cli->netdev),
                      IP_ARGS(&cli->ipaddr), IP_ARGS(&cli->netmask));
            if (cli->router) {
                VLOG_WARN("%s: obtained default gateway "IP_FMT,
                          netdev_get_name(cli->netdev), IP_ARGS(&cli->router));
            }
        } else {
            dhcp_msg_uninit(cli->binding);
            free(cli->binding);
            cli->binding = NULL;

            VLOG_WARN("%s: network address unbound",
                      netdev_get_name(cli->netdev));
        }
    }
    if (cli->state & (S_SELECTING | S_REQUESTING | S_REBOOTING)) {
        netdev_drain(cli->netdev);
    }
}

static void
send_reliably(struct dhclient *cli,
              void (*make_packet)(struct dhclient *, struct dhcp_msg *))
{
    if (timeout(cli, cli->retransmit)) {
        struct dhcp_msg msg;
        make_packet(cli, &msg);
        if (cli->modify_request) {
            cli->modify_request(&msg, cli->aux);
        }
        do_send_msg(cli, &msg);
        cli->delay = MIN(cli->max_timeout, MAX(4, cli->delay * 2));
        cli->retransmit += fuzz(cli->delay, 1);
        timeout(cli, cli->retransmit);
        dhcp_msg_uninit(&msg);
     }
}

static void
dhclient_msg_init(struct dhclient *cli, enum dhcp_msg_type type,
                  struct dhcp_msg *msg)
{
    dhcp_msg_init(msg);
    msg->op = DHCP_BOOTREQUEST;
    msg->xid = cli->xid;
    msg->secs = cli->secs;
    msg->type = type;
    memcpy(msg->chaddr, netdev_get_etheraddr(cli->netdev), ETH_ADDR_LEN);
}

static unsigned int
elapsed_in_this_state(const struct dhclient *cli)
{
    return time_now() - cli->state_entered;
}

static bool
timeout(struct dhclient *cli, unsigned int secs)
{
    cli->min_timeout = MIN(cli->min_timeout, secs);
    return time_now() >= sat_add(cli->state_entered, secs);
}

static bool
do_receive_msg(struct dhclient *cli, struct dhcp_msg *msg)
{
    struct ofpbuf b;

    ofpbuf_init(&b, netdev_get_mtu(cli->netdev) + VLAN_ETH_HEADER_LEN);
    for (; cli->received < 50; cli->received++) {
        const struct ip_header *ip;
        const struct dhcp_header *dhcp;
        struct flow flow;
        int error;

        ofpbuf_clear(&b);
        error = netdev_recv(cli->netdev, &b);
        if (error) {
            goto drained;
        }

        flow_extract(&b, 0, &flow);
        if (flow.dl_type != htons(ETH_TYPE_IP)
            || flow.nw_proto != IP_TYPE_UDP
            || flow.tp_dst != htons(68)
            || !(eth_addr_is_broadcast(flow.dl_dst)
                 || eth_addr_equals(flow.dl_dst,
                                    netdev_get_etheraddr(cli->netdev)))) {
            continue;
        }

        ip = b.l3;
        if (IP_IS_FRAGMENT(ip->ip_frag_off)) {
            /* We don't do reassembly. */
            VLOG_WARN_RL(&rl, "ignoring fragmented DHCP datagram");
            continue;
        }

        dhcp = b.l7;
        if (!dhcp) {
            VLOG_WARN_RL(&rl, "ignoring DHCP datagram with missing payload");
            continue;
        }

        ofpbuf_pull(&b, (char *)b.l7 - (char*)b.data);
        error = dhcp_parse(msg, &b);
        if (!error) {
            if (VLOG_IS_DBG_ENABLED()) {
                VLOG_DBG_RL(&rl, "received %s",
                            dhcp_msg_to_string(msg, false, &cli->s)); 
            } else {
                VLOG_WARN_RL(&rl, "received %s", dhcp_type_name(msg->type));
            }
            ofpbuf_uninit(&b);
            return true;
        }
    }
    netdev_drain(cli->netdev);
drained:
    ofpbuf_uninit(&b);
    return false;
}

static void
do_send_msg(struct dhclient *cli, const struct dhcp_msg *msg)
{
    struct ofpbuf b;
    struct eth_header eh;
    struct ip_header nh;
    struct udp_header th;
    uint32_t udp_csum;
    int error;

    ofpbuf_init(&b, ETH_TOTAL_MAX);
    ofpbuf_reserve(&b, ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN);

    dhcp_assemble(msg, &b);

    memcpy(eh.eth_src, netdev_get_etheraddr(cli->netdev), ETH_ADDR_LEN);
    memcpy(eh.eth_dst, eth_addr_broadcast, ETH_ADDR_LEN);
    eh.eth_type = htons(ETH_TYPE_IP);

    nh.ip_ihl_ver = IP_IHL_VER(5, IP_VERSION);
    nh.ip_tos = 0;
    nh.ip_tot_len = htons(IP_HEADER_LEN + UDP_HEADER_LEN + b.size);
    /* We can't guarantee uniqueness of ip_id versus the host's, screwing up
     * fragment reassembly, so prevent fragmentation and use an all-zeros
     * ip_id.  RFC 791 doesn't say we can do this, but Linux does the same
     * thing for DF packets, so it must not screw anything up.  */
    nh.ip_id = 0;
    nh.ip_frag_off = htons(IP_DONT_FRAGMENT);
    nh.ip_ttl = 64;
    nh.ip_proto = IP_TYPE_UDP;
    nh.ip_csum = 0;
    nh.ip_src = dhclient_get_ip(cli);
    /* XXX need to use UDP socket for nonzero server IPs so that we can get
     * routing table support.
     *
     * if (...have server IP and in appropriate state...) {
     *    nh.ip_dst = cli->server_ip;
     * } else {
     *    nh.ip_dst = INADDR_BROADCAST;
     * }
     */
    nh.ip_dst = INADDR_BROADCAST;
    nh.ip_csum = csum(&nh, sizeof nh);

    th.udp_src = htons(66);
    th.udp_dst = htons(67);
    th.udp_len = htons(UDP_HEADER_LEN + b.size);
    th.udp_csum = 0;
    udp_csum = csum_add32(0, nh.ip_src);
    udp_csum = csum_add32(udp_csum, nh.ip_dst);
    udp_csum = csum_add16(udp_csum, IP_TYPE_UDP << 8);
    udp_csum = csum_add16(udp_csum, th.udp_len);
    udp_csum = csum_continue(udp_csum, &th, sizeof th);
    th.udp_csum = csum_finish(csum_continue(udp_csum, b.data, b.size));

    ofpbuf_push(&b, &th, sizeof th);
    ofpbuf_push(&b, &nh, sizeof nh);
    ofpbuf_push(&b, &eh, sizeof eh);

    /* Don't try to send the frame if it's too long for an Ethernet frame.  We
     * disregard the network device's actual MTU because we don't want the
     * frame to have to be discarded or fragmented if it travels over a regular
     * Ethernet at some point.  1500 bytes should be enough for anyone. */
    if (b.size <= ETH_TOTAL_MAX) {
        if (VLOG_IS_DBG_ENABLED()) {
            VLOG_DBG("sending %s", dhcp_msg_to_string(msg, false, &cli->s)); 
        } else {
            VLOG_WARN("sending %s", dhcp_type_name(msg->type));
        }
        error = netdev_send(cli->netdev, &b);
        if (error) {
            VLOG_ERR("send failed on %s: %s",
                     netdev_get_name(cli->netdev), strerror(error));
        }
    } else {
        VLOG_ERR("cannot send %zu-byte Ethernet frame", b.size);
    }

    ofpbuf_uninit(&b);
}

static unsigned int
fuzz(unsigned int x, int max_fuzz)
{
    /* Generate number in range [-max_fuzz, +max_fuzz]. */
    int fuzz = random_range(max_fuzz * 2 + 1) - max_fuzz;
    unsigned int y = x + fuzz;
    return fuzz >= 0 ? (y >= x ? y : UINT_MAX) : (y <= x ? y : 0);
}

static unsigned int
clamp(unsigned int x, unsigned int min, unsigned int max)
{
    return x < min ? min : x > max ? max : x;
}

static unsigned int
calc_t2(unsigned int lease)
{
    unsigned int base = lease * 0.875;
    return lease >= 60 ? clamp(fuzz(base, 10), 0, lease - 1) : base;
}

static unsigned int
calc_t1(unsigned int lease, unsigned int t2)
{
    unsigned int base = lease / 2;
    return lease >= 60 ? clamp(fuzz(base, 10), 0, t2 - 1) : base;
}
