/* Copyright (c) 2008, 2009, 2010 Nicira Networks, Inc.
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
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <pcre.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <term.h>
#include <unistd.h>
#include "command-line.h"
#include "daemon.h"
#include "dynamic-string.h"
#include "ezio.h"
#include "fatal-signal.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "process.h"
#include "random.h"
#include "rconn.h"
#include "socket-util.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_switchui
#include "vlog.h"

static void parse_options(int argc, char *argv[]);
static void usage(void);

static void initialize_terminal(void);
static void restore_terminal(void *aux);

enum priority {
    P_STATUS = 5,
    P_PROGRESS = 10,
    P_WARNING = 15,
    P_ERROR = 20,
    P_FATAL = 25
};

struct message;
static void emit(struct message **, enum priority, const char *, ...)
    PRINTF_FORMAT(3, 4);
static void emit_function(struct message **, enum priority,
                          void (*function)(void *aux), void *aux);
static int shown(struct message **);
static void clear_messages(void);
static bool empty_message(const struct message *);
static struct message *best_message(void);
static struct message *next_message(struct message *);
static struct message *prev_message(struct message *);
static void put_message(const struct message *);
static void message_shown(struct message *);
static void age_messages(void);

struct pair {
    char *name;
    char *value;
};

struct dict {
    struct pair *pairs;
    size_t n, max;
};

static void dict_init(struct dict *);
static void dict_add(struct dict *, const char *name, const char *value);
static void dict_add_nocopy(struct dict *, char *name, char *value);
static void dict_delete(struct dict *, const char *name);
static void dict_parse(struct dict *, const char *data, size_t nbytes);
static void dict_free(struct dict *);
static bool dict_lookup(const struct dict *,
                        const char *name, const char **value);
static int dict_get_int(const struct dict *, const char *name, int def);
static bool dict_get_bool(const struct dict *, const char *name, bool def);
static const char *dict_get_string(const struct dict *,
                                   const char *name, const char *def);
static uint32_t dict_get_ip(const struct dict *, const char *name);

static void addf(const char *format, ...) PRINTF_FORMAT(1, 2);

static void fetch_status(struct rconn *, struct dict *, long long int timeout);
static bool parse_reply(void *, struct dict *, uint32_t xid);
static void compose_messages(const struct dict *, struct rconn *rconn);

static void show_flows(struct rconn *);
static void show_dpid_ip(struct rconn *, const struct dict *);
static void show_ofproto_state(const struct dict *);
static void show_fail_open_state(const struct dict *);
static void show_discovery_state(const struct dict *);
static void show_remote_state(const struct dict *);
static void show_data_rates(struct rconn *, const struct dict *);

static void init_reboot_notifier(void);
static bool show_reboot_state(void);

static void show_string(const char *string);
static void block_until(long long timeout);
static void menu(const struct dict *);
static void drain_keyboard_buffer(void);

static const char *progress(void);

int
main(int argc, char *argv[])
{
    struct rconn *rconn;
    struct message *msg;
    int countdown = 5;
    bool user_selected;
    bool debug_mode;

    /* Tracking keystroke repeat counts. */
    int last_key = 0;
    long long int last_key_time = 0;
    int repeat_count = 0;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    vlog_set_levels(VLM_ANY_MODULE, VLF_CONSOLE, VLL_EMER);
    init_reboot_notifier();

    argc -= optind;
    argv += optind;
    if (argc != 1) {
        ovs_fatal(0, "exactly one non-option argument required; "
                  "use --help for help");
    }

    rconn = rconn_new(argv[0], 5, 5);

    die_if_already_running();
    daemonize();

    initialize_terminal();
    fatal_signal_add_hook(restore_terminal, NULL, true);

    msg = NULL;
    countdown = 0;
    user_selected = false;
    debug_mode = false;
    for (;;) {
        struct dict dict;
        long long timeout = time_msec() + 1000;

        clear_messages();

        dict_init(&dict);
        fetch_status(rconn, &dict, timeout);
        dict_add(&dict, "debug", debug_mode ? "true" : "false");
        compose_messages(&dict, rconn);

        if (countdown) {
            if (!empty_message(msg)) {
                countdown--;
            } else {
                msg = user_selected ? next_message(msg) : best_message();
                countdown = 5;
            }
        } else {
            msg = best_message();
            countdown = 5;
            user_selected = false;
        }
        if (!user_selected) {
            message_shown(msg);
        }

        do {
            for (;;) {
                int c = getch();
                if (c == ERR) {
                    break;
                }

                if (c != last_key || time_msec() > last_key_time + 250) {
                    repeat_count = 0;
                }
                last_key = c;
                last_key_time = time_msec();
                repeat_count++;

                if (c == KEY_DOWN || c == KEY_UP) {
                    msg = (c == KEY_DOWN ? next_message(msg)
                           : prev_message(msg));
                    countdown = 5;
                    user_selected = true;
                } else if (c == '\r' || c == '\n') {
                    countdown = 60;
                    user_selected = true;
                    if (repeat_count >= 20) {
                        debug_mode = !debug_mode;
                        show_string(debug_mode
                                    ? "Debug Mode\nEnabled"
                                    : "Debug Mode\nDisabled");
                    }
                } else if (c == '\b' || c == '\x7f' ||
                           c == '\x1b' || c == KEY_BACKSPACE || c == KEY_DC) {
                    menu(&dict);
                    drain_keyboard_buffer();
                    break;
                }
            }

            erase();
            curs_set(0);
            move(0, 0);
            put_message(msg);
            refresh();

            poll_fd_wait(STDIN_FILENO, POLLIN);
            poll_timer_wait(timeout - time_msec());
            poll_block();
        } while (time_msec() < timeout);
        age_messages();
        dict_free(&dict);
    }

    return 0;
}

static void
compose_messages(const struct dict *dict, struct rconn *rconn)
{
    if (!show_reboot_state()) {
        show_flows(rconn);
        show_dpid_ip(rconn, dict);
        show_ofproto_state(dict);
        show_fail_open_state(dict);
        show_discovery_state(dict);
        show_remote_state(dict);
        show_data_rates(rconn, dict);
    }
}

struct put_flows_data {
    struct rconn *rconn;
    uint32_t xid;
    uint32_t flow_count;
    bool got_reply;
};

static void
parse_flow_reply(void *data, struct put_flows_data *pfd)
{
    struct ofp_header *oh;
    struct ofp_stats_reply *rpy;
    struct ofp_aggregate_stats_reply *asr;
    const size_t min_size = sizeof *rpy + sizeof *asr;

    oh = data;
    if (ntohs(oh->length) < min_size) {
        VLOG_WARN("reply is too short (%"PRIu16")", ntohs(oh->length));
        return;
    }
    if (oh->xid != pfd->xid) {
        VLOG_WARN("xid 0x%08"PRIx32" != expected 0x%08"PRIx32,
                  oh->xid, pfd->xid);
        return;
    }
    if (oh->type != OFPT_STATS_REPLY) {
        VLOG_WARN("reply is wrong type %"PRIu8, oh->type);
        return;
    }

    rpy = data;
    if (rpy->type != htons(OFPST_AGGREGATE)) {
        VLOG_WARN("reply has wrong stat type ID %08"PRIx16, rpy->type);
        return;
    }

    asr = (struct ofp_aggregate_stats_reply *) rpy->body;
    pfd->flow_count = ntohl(asr->flow_count);
    pfd->got_reply = true;
}

static bool
have_icons(void)
{
    const char *dico = tigetstr("dico");
    return dico && dico != (const char *) -1;
}

static void
set_icon(int num, int r0, int r1, int r2, int r3, int r4, int r5, int r6,
         int r7)
{
    if (have_icons()) {
        putp(tparm(tigetstr("dico"), num, r0, r1, r2, r3, r4, r5, r6, r7));
    }
}

static void
set_repeated_icon(int num, int row)
{
    set_icon(num, row, row, row, row, row, row, row, row);
}

#if 0
static void
set_brick_icon(int num, int n_solid)
{
    const static int rows[6] = {_____, X____, XX___, XXX__, XXXX_, XXXXX};
    set_repeated_icon(num, rows[n_solid < 0 ? 0
                                : n_solid > 5 ? 5
                                : n_solid]);
}
#endif

static int
icon_char(int num, int alternate)
{
    return have_icons() ? 0x80 | num | A_ALTCHARSET : alternate;
}

static void
put_icon(int num, char alternate)
{
    addch(icon_char(num, alternate));
}

#if 0
static void
bar_graph(int n_chars, int n_pixels)
{
    int i;

    if (n_pixels < 0) {
        n_pixels = 0;
    } else if (n_pixels > n_chars * 5) {
        n_pixels = n_chars * 5;
    }

    if (n_pixels > 5) {
        set_brick_icon(0, 5);
        for (i = 0; i < n_pixels / 5; i++) {
            put_icon(0, "#");
        }
    }
    if (n_pixels % 5) {
        set_brick_icon(1, n_pixels % 5);
        put_icon(1, "#");
    }
}
#endif

static void
put_flows(void *pfd_)
{
    struct put_flows_data *pfd = pfd_;
    static struct rconn_packet_counter *counter;
    char host[64];

    if (!counter) {
        counter = rconn_packet_counter_create();
    }

    if (!pfd->xid) {
        struct ofp_stats_request *rq;
        struct ofp_aggregate_stats_request *asr;
        struct ofpbuf *b;

        pfd->xid = random_uint32();
        rq = make_openflow_xid(sizeof *rq, OFPT_STATS_REQUEST,
                               pfd->xid, &b);
        rq->type = htons(OFPST_AGGREGATE);
        rq->flags = htons(0);
        asr = ofpbuf_put_uninit(b, sizeof *asr);
        memset(asr, 0, sizeof *asr);
        asr->match.wildcards = htonl(OFPFW_ALL);
        asr->table_id = 0xff;
        asr->out_port = htons(OFPP_NONE);
        update_openflow_length(b);
        rconn_send_with_limit(pfd->rconn, b, counter, 10);
    }

    if (!pfd->got_reply) {
        int i;

        rconn_run(pfd->rconn);
        for (i = 0; i < 50; i++) {
            struct ofpbuf *b;

            b = rconn_recv(pfd->rconn);
            if (!b) {
                break;
            }

            parse_flow_reply(b->data, pfd);
            ofpbuf_delete(b);
            if (pfd->got_reply) {
                break;
            }
        }
    }

    gethostname(host, sizeof host);
    host[sizeof host - 1] = '\0';
    if (strlen(host) + 6 <= 16) {
        addf("Host: %s\n", host); 
    } else {
        addf("%s\n", host);
    }
    if (pfd->got_reply) {
        addf("Flows: %"PRIu32, pfd->flow_count);
    }

    if (!pfd->got_reply) {
        rconn_run_wait(pfd->rconn);
        rconn_recv_wait(pfd->rconn);
    }
}

static void
show_flows(struct rconn *rconn)
{
    static struct message *m;
    static struct put_flows_data pfd;

    memset(&pfd, 0, sizeof pfd);
    pfd.rconn = rconn;
    emit_function(&m, P_STATUS, put_flows, &pfd);

}

struct put_dpid_ip_data {
    struct rconn *rconn;
    uint32_t xid;
    uint64_t dpid;
    char ip[16];
    bool got_reply;
};

static void
parse_dp_reply(void *data, struct put_dpid_ip_data *pdid)
{
    struct ofp_switch_features *osf;
    struct ofp_header *oh;

    oh = data;
    if (ntohs(oh->length) < sizeof *osf) {
        VLOG_WARN("reply is too short (%"PRIu16")", ntohs(oh->length));
        return;
    }
    if (oh->xid != pdid->xid) {
        VLOG_WARN("xid 0x%08"PRIx32" != expected 0x%08"PRIx32,
                  oh->xid, pdid->xid);
        return;
    }
    if (oh->type != OFPT_FEATURES_REPLY) {
        VLOG_WARN("reply is wrong type %"PRIu8, oh->type);
        return;
    }

    osf = data;
    pdid->dpid = ntohll(osf->datapath_id);
    pdid->got_reply = true;
}

static void
put_dpid_id(void *pdid_)
{
    struct put_dpid_ip_data *pdid = pdid_;
    static struct rconn_packet_counter *counter;

    if (!counter) {
        counter = rconn_packet_counter_create();
    }

    if (!pdid->xid) {
        struct ofp_header *oh;
        struct ofpbuf *b;

        pdid->xid = random_uint32();
        oh = make_openflow_xid(sizeof *oh, OFPT_FEATURES_REQUEST,
                               pdid->xid, &b);
        rconn_send_with_limit(pdid->rconn, b, counter, 10);
    }

    if (!pdid->got_reply) {
        int i;

        rconn_run(pdid->rconn);
        for (i = 0; i < 50; i++) {
            struct ofpbuf *b;

            b = rconn_recv(pdid->rconn);
            if (!b) {
                break;
            }

            parse_dp_reply(b->data, pdid);
            ofpbuf_delete(b);
            if (pdid->got_reply) {
                break;
            }
        }
    }

    addf("DP: ");
    if (pdid->got_reply) {
        addf("%012"PRIx64, pdid->dpid);
    }
    addf("\nIP: %s", pdid->ip);

    if (!pdid->got_reply) {
        rconn_run_wait(pdid->rconn);
        rconn_recv_wait(pdid->rconn);
    }
}

static void
show_dpid_ip(struct rconn *rconn, const struct dict *dict)
{
    static struct message *m;
    static struct put_dpid_ip_data pdid;
    const char *is_connected, *local_ip;

    dict_lookup(dict, "local.is-connected", &is_connected);
    dict_lookup(dict, "remote.local-ip", &local_ip);
    if (!is_connected && !local_ip) {
        /* If we're not connected to the datapath and don't have a local IP,
         * then we won't have anything useful to show anyhow. */
        return;
    }

    memset(&pdid, 0, sizeof pdid);
    pdid.rconn = rconn;
    ovs_strlcpy(pdid.ip, local_ip ? local_ip : "", sizeof pdid.ip);
    emit_function(&m, P_STATUS, put_dpid_id, &pdid);
}

static size_t
dict_find(const struct dict *dict, const char *name)
{
    size_t i;

    for (i = 0; i < dict->n; i++) {
        const struct pair *p = &dict->pairs[i];
        if (!strcmp(p->name, name)) {
            return i;
        }
    }

    return SIZE_MAX;
}

static bool
dict_lookup(const struct dict *dict, const char *name, const char **value)
{
    size_t idx = dict_find(dict, name);
    if (idx != SIZE_MAX) {
        *value = dict->pairs[idx].value;
        return true;
    } else {
        *value = NULL;
        return false;
    }
}

static const char *
dict_get(const struct dict *dict, const char *name)
{
    const char *value;
    return dict_lookup(dict, name, &value) ? value : NULL;
}

static int
dict_get_int(const struct dict *dict, const char *name, int def)
{
    const char *value;
    return dict_lookup(dict, name, &value) ? atoi(value) : def;
}

static bool
dict_get_bool(const struct dict *dict, const char *name, bool def)
{
    const char *value;
    if (dict_lookup(dict, name, &value)) {
        if (!strcmp(value, "true")) {
            return true;
        }
        if (!strcmp(value, "false")) {
            return false;
        }
    }
    return def;
}

static const char *
dict_get_string(const struct dict *dict, const char *name, const char *def)
{
    const char *value;
    return dict_lookup(dict, name, &value) ? value : def;
}

static uint32_t
dict_get_ip(const struct dict *dict, const char *name)
{
    struct in_addr in;
    return (inet_aton(dict_get_string(dict, name, ""), &in) ? in.s_addr
            : htonl(0));
}

static void
addf(const char *format, ...)
{
    char buf[128];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof buf, format, args);
    va_end(args);

    addstr(buf);
}

static void
show_ofproto_state(const struct dict *dict)
{
    static struct message *msg;
    const char *is_connected;

    if (!dict_lookup(dict, "remote.is-connected", &is_connected)) {
        /* Secchan not running or not responding. */
        emit(&msg, P_ERROR, "Switch disabled");
    }
}

static const char *
discovery_state_label(const char *name)
{
    static struct dict *states;
    if (!states) {
        states = xmalloc(sizeof *states);
        dict_init(states);
        dict_add(states, "INIT", "Init");
        dict_add(states, "INIT_REBOOT", "Init");
        dict_add(states, "REBOOTING", "Init");
        dict_add(states, "SELECTING", "Searching");
        dict_add(states, "REQUESTING", "Requesting");
        dict_add(states, "BOUND", "Got");
        dict_add(states, "RENEWING", "Renewing");
        dict_add(states, "REBINDING", "Rebinding");
        dict_add(states, "RELEASED", "Released");
    }
    return dict_get_string(states, name, "Error");
}

static void
show_discovery_state(const struct dict *dict)
{
    static struct message *m_bound, *m_other;
    struct message **m;
    const char *state, *ip;
    enum priority priority;
    int state_elapsed;

    state = dict_get_string(dict, "discovery.state", NULL);
    if (!state) {
        return;
    }
    ip = dict_get_string(dict, "discovery.ip", NULL);
    state_elapsed = dict_get_int(dict, "discovery.state-elapsed", 0);

    if (!strcmp(state, "BOUND")) {
        m = &m_bound;
        priority = P_STATUS;
    } else {
        m = &m_other;
        priority = P_PROGRESS;
    }
    emit(m, priority, "Discovery %s\n%s",
         progress(), discovery_state_label(state));
    if (ip) {
        emit(m, priority, " %s", ip);
    }
}

static void
human_time(int seconds, char *buf, size_t size)
{
    const char *sign = "";
    if (seconds < 0) {
        sign = "-";
        seconds = seconds == INT_MIN ? INT_MAX : -seconds;
    }

    if (seconds <= 60) {
        snprintf(buf, size, "%s%d s", sign, seconds);
    } else if (seconds <= 60 * 60) {
        snprintf(buf, size, "%s%d min", sign, seconds / 60);
    } else if (seconds <= 60 * 60 * 24 * 2) {
        snprintf(buf, size, "%s%d h", sign, seconds / 60 / 60);
    } else {
        snprintf(buf, size, "%s%d days", sign, seconds / 60 / 60 / 24);
    }
}

static void
show_fail_open_state(const struct dict *dict)
{
    static struct message *m;
    int cur_duration, trigger_duration;

    if (!dict_get_bool(dict, "fail-open.triggered", false)) {
        return;
    }
    trigger_duration = dict_get_int(dict, "fail-open.trigger-duration", 0);
    cur_duration = dict_get_int(dict, "fail-open.current-duration", 0);
    if (shown(&m) < 5) {
        emit(&m, P_WARNING, "Failed open %s\nafter %d secs",
             progress(), trigger_duration);
    } else {
        char buf[16];
        human_time(cur_duration - trigger_duration, buf, sizeof buf);
        emit(&m, P_WARNING, "In fail open for\n%s now %s", buf, progress());
    }
}

static const char *
progress(void)
{
    return "..." + (3 - (unsigned int) time_now() % 4);
}

static void
show_remote_state(const struct dict *dict)
{
    bool debug_mode = dict_get_bool(dict, "debug", false);
    const char *state, *is_connected;

    state = dict_get_string(dict, "remote.state", NULL);
    if (!state) {
        return;
    }
    is_connected = dict_get_string(dict, "remote.is-connected", "false");
    if (!strcmp(is_connected, "true")) {
        if (debug_mode) {
            static struct message *m_connected;
            char buf[16];
            human_time(dict_get_int(dict, "remote.last-connection", 0),
                       buf, sizeof buf);
            emit(&m_connected, P_STATUS,
                 "Connected for\nlast %s %s", buf, progress());
        }

        if (!strcmp(state, "IDLE")) {
            static struct message *m_idle;
            emit(&m_idle, P_PROGRESS, "Sent idle probe");
        }

        if (debug_mode) {
            const char *name = dict_get_string(dict, "remote.name", NULL);
            if (name) {
                static struct message *m_name;
                emit(&m_name, P_STATUS, "Connected to\n%s", name);
            }
        }
    } else {
        int elapsed, backoff;
        const char *name, *error;

        elapsed = dict_get_int(dict, "remote.state-elapsed", 0);
        backoff = dict_get_int(dict, "remote.backoff", 0);
        name = dict_get_string(dict, "remote.name", "unknown");
        state = dict_get_string(dict, "remote.state", "VOID");
        error = dict_get_string(dict, "remote.last-connect-error", NULL);
        if (!strcmp(state, "VOID")) {
            static struct message *m;
            emit(&m, P_PROGRESS, "Controller not\nfound");
        } else if (!strcmp(state, "BACKOFF")) {
            static struct message *m[3];
            char buf[16];

            if (error) {
                emit(&m[0], P_PROGRESS, "Connect failed:\n%s", error);
            }
            emit(&m[2], P_STATUS, "Last connected\n%s ago", buf);
            emit(&m[1], P_PROGRESS,
                 "Disconnected\nReconnect in %d", backoff - elapsed);
            human_time(dict_get_int(dict, "remote.last-connection", 0),
                       buf, sizeof buf);
        } else if (!strcmp(state, "CONNECTING")) {
            static struct message *m;
            emit(&m, P_PROGRESS, "Connecting %s\n%s", progress(), name);
        }
    }
}

static void
fetch_status(struct rconn *rconn, struct dict *dict, long long timeout)
{
    static struct rconn_packet_counter *counter;
    static uint32_t xid;
    struct nicira_header *rq;
    struct ofpbuf *b;
    int retval;

    if (!counter) {
        counter = rconn_packet_counter_create();
    }
    if (!xid) {
        xid = random_uint32();
    }

    rq = make_openflow_xid(sizeof *rq, OFPT_VENDOR, ++xid, &b);
    rq->vendor = htonl(NX_VENDOR_ID);
    rq->subtype = htonl(NXT_STATUS_REQUEST);
    retval = rconn_send_with_limit(rconn, b, counter, 10);
    if (retval) {
        /* continue into the loop so that we pause for a while */
    }

    while (time_msec() < timeout) {
        int i;

        rconn_run(rconn);

        for (i = 0; i < 50; i++) {
            struct ofpbuf *b;
            bool got_reply;

            b = rconn_recv(rconn);
            if (!b) {
                break;
            }

            got_reply = parse_reply(b->data, dict, xid);
            ofpbuf_delete(b);
            if (got_reply) {
                return;
            }
        }

        rconn_run_wait(rconn);
        rconn_recv_wait(rconn);
        poll_timer_wait(timeout - time_msec());
        poll_block();
    }
}

static bool
parse_reply(void *data, struct dict *dict, uint32_t xid)
{
    struct ofp_header *oh;
    struct nicira_header *rpy;

    oh = data;
    if (ntohs(oh->length) < sizeof *rpy) {
        VLOG_WARN("reply is too short (%"PRIu16")", ntohs(oh->length));
        return false;
    }
    if (oh->xid != xid) {
        VLOG_WARN("xid 0x%08"PRIx32" != expected 0x%08"PRIx32, oh->xid, xid);
        return false;
    }
    if (oh->type != OFPT_VENDOR) {
        VLOG_WARN("reply is wrong type %"PRIu8, oh->type);
        return false;
    }

    rpy = data;
    if (rpy->vendor != htonl(NX_VENDOR_ID)) {
        VLOG_WARN("reply has wrong vendor ID %08"PRIx32, rpy->vendor);
        return false;
    }
    if (rpy->subtype != htonl(NXT_STATUS_REPLY)) {
        VLOG_WARN("reply has wrong subtype %08"PRIx32, rpy->subtype);
        return false;
    }

    dict_parse(dict, (const char *) (rpy + 1),
               ntohs(oh->length) - sizeof *rpy);
    return true;
}

static void
dict_parse(struct dict *dict, const char *data, size_t nbytes)
{
    char *save_ptr = NULL;
    char *copy, *name;

    copy = xmemdup0(data, nbytes);
    for (name = strtok_r(copy, "=", &save_ptr); name;
         name = strtok_r(NULL, "=", &save_ptr))
    {
        char *value = strtok_r(NULL, "\n", &save_ptr);
        if (!value) {
            break;
        }
        dict_add(dict, name, value);
    }
    free(copy);
}

static void
dict_init(struct dict *dict)
{
    dict->n = 0;
    dict->max = 16;
    dict->pairs = xmalloc(sizeof *dict->pairs * dict->max);
}

static void
dict_add(struct dict *dict, const char *name, const char *value)
{
    dict_add_nocopy(dict, xstrdup(name), xstrdup(value));
}

static void
dict_add_nocopy(struct dict *dict, char *name, char *value)
{
    struct pair *p;

    if (dict->n >= dict->max) {
        dict->max *= 2;
        dict->pairs = xrealloc(dict->pairs, sizeof *dict->pairs * dict->max);
    }
    p = &dict->pairs[dict->n++];
    p->name = name;
    p->value = value;
}

static void
dict_delete(struct dict *dict, const char *name)
{
    size_t idx;
    while ((idx = dict_find(dict, name)) != SIZE_MAX) {
        struct pair *pair = &dict->pairs[idx];
        free(pair->name);
        free(pair->value);
        dict->pairs[idx] = dict->pairs[--dict->n];
    }
}

static void
dict_free(struct dict *dict)
{
    if (dict) {
        size_t i;

        for (i = 0; i < dict->n; i++) {
            free(dict->pairs[i].name);
            free(dict->pairs[i].value);
        }
        free(dict->pairs);
    }
}

static void
initialize_terminal(void)
{
    initscr();
    cbreak();
    noecho();
    nonl();
    intrflush(stdscr, FALSE);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    typeahead(-1);
    scrollok(stdscr, TRUE);
}

static void
restore_terminal(void *aux UNUSED)
{
    endwin();
}

struct byte_count {
    long long int when;
    uint64_t tx_bytes;
};

struct show_rates_data {
    struct rconn *rconn;
    uint32_t xid;
    struct byte_count prev, now;
    bool got_reply;
};

static void
parse_port_reply(void *data, struct show_rates_data *rates)
{
    struct ofp_header *oh;
    struct ofp_stats_reply *rpy;
    struct ofp_port_stats *ops;
    size_t n_ports;
    size_t i;

    oh = data;
    if (ntohs(oh->length) < sizeof *rpy) {
        VLOG_WARN("reply is too short (%"PRIu16")", ntohs(oh->length));
        return;
    }
    if (oh->xid != rates->xid) {
        VLOG_WARN("xid 0x%08"PRIx32" != expected 0x%08"PRIx32,
                  oh->xid, rates->xid);
        return;
    }
    if (oh->type != OFPT_STATS_REPLY) {
        VLOG_WARN("reply is wrong type %"PRIu8, oh->type);
        return;
    }

    rpy = data;
    if (rpy->type != htons(OFPST_PORT)) {
        VLOG_WARN("reply has wrong stat type ID %08"PRIx16, rpy->type);
        return;
    }

    n_ports = ((ntohs(oh->length) - offsetof(struct ofp_stats_reply, body))
               / sizeof *ops);
    ops = (struct ofp_port_stats *) rpy->body;
    rates->prev = rates->now;
    rates->now.when = time_msec();
    rates->now.tx_bytes = UINT64_MAX;
    for (i = 0; i < n_ports; i++, ops++) {
        if (ops->tx_bytes != htonll(UINT64_MAX)) {
            if (rates->now.tx_bytes == UINT64_MAX) {
                rates->now.tx_bytes = 0;
            }
            rates->now.tx_bytes += ntohll(ops->tx_bytes);
        }
    }
    rates->got_reply = true;
}

static void
dump_graph(const bool graph[80])
{
    signed char icons[32];
    int n_icons = 3;
    int i;

    memset(icons, -1, sizeof icons);
    for (i = 0; i < 16; i++) {
        uint8_t row;
        int j;

        row = 0;
        for (j = 0; j < 5; j++) {
            row = (row << 1) | graph[i * 5 + j];
        }
        if (!row) {
            addch(' ');
            continue;
        }

        if (icons[row] < 0) {
            if (n_icons >= 8) {
                addch('X');
                continue;
            }
            set_repeated_icon(n_icons, row);
            icons[row] = n_icons++;
        }
        put_icon(icons[row], row == 0x1f ? '#' : ' ');
    }
}

static void
do_show_data_rates(void *rates_)
{
    struct show_rates_data *rates = rates_;
    static struct rconn_packet_counter *counter;
    bool graph[80];

    if (!counter) {
        counter = rconn_packet_counter_create();
    }
    if (!rates->xid) {
        struct ofp_stats_request *rq;
        struct ofp_port_stats_request *psr;
        struct ofpbuf *b;

        rates->xid = random_uint32();
        rq = make_openflow_xid(sizeof *rq, OFPT_STATS_REQUEST,
                               rates->xid, &b);
        rq->type = htons(OFPST_PORT);
        rq->flags = htons(0);
        psr = ofpbuf_put_uninit(b, sizeof *psr);
        memset(psr, 0, sizeof *psr);
        psr->port_no = htons(OFPP_NONE);
        update_openflow_length(b);
        rconn_send_with_limit(rates->rconn, b, counter, 10);
    }

    if (!rates->got_reply) {
        int i;

        rconn_run(rates->rconn);
        for (i = 0; i < 50; i++) {
            struct ofpbuf *b;

            b = rconn_recv(rates->rconn);
            if (!b) {
                break;
            }

            parse_port_reply(b->data, rates);
            ofpbuf_delete(b);
            if (rates->got_reply) {
                break;
            }
        }
    }

    set_icon(0,
             e_____,
             e_____,
             e_____,
             e__X__,
             e__X__,
             e__X_X,
             e__XX_,
             e__X_X);
    set_icon(1,
             e_____,
             e_____,
             e_____,
             eX___X,
             eXX_XX,
             eX_X_X,
             eX___X,
             eX___X);
    set_icon(2,
             e_____,
             e_____,
             e_____,
             e_XXX_,
             eX____,
             eX_XXX,
             eX___X,
             e_XXX_);

    memset(graph, 0, sizeof graph);
    graph[24] = 1;
    graph[48] = 1;
    graph[72] = 1;

    addstr("TX: ");
    put_icon(0, 'k');
    addstr("    ");
    put_icon(1, 'M');
    addstr("    ");
    put_icon(2, 'G');
    addch('\n');

    if (rates->now.tx_bytes != UINT64_MAX
        && rates->prev.tx_bytes != UINT64_MAX
        && rates->now.when - rates->prev.when > 500
        && time_msec() - rates->now.when < 2000)
    {
        uint64_t bits = (rates->now.tx_bytes - rates->prev.tx_bytes) * 8;
        uint64_t msecs = rates->now.when - rates->prev.when;
        double bps = (double) bits * 1000.0 / msecs;
        int pixels = bps > 0 ? log(bps) / log(10.0) * 8 + .5 : 0;
        if (pixels < 0) {
            pixels = 0;
        } else if (pixels > 80) {
            pixels = 80;
        }
        memset(graph, 1, pixels);
    }

    dump_graph(graph);

    if (!rates->got_reply) {
        rconn_run_wait(rates->rconn);
        rconn_recv_wait(rates->rconn);
    }
}

static void
show_data_rates(struct rconn *rconn, const struct dict *dict)
{
    static struct message *m;
    static struct show_rates_data rates;
    const char *is_connected, *local_ip;
    static bool inited = false;

    dict_lookup(dict, "local.is-connected", &is_connected);
    dict_lookup(dict, "remote.local-ip", &local_ip);
    if (!is_connected && !local_ip) {
        /* If we're not connected to the datapath and don't have a local IP,
         * then we won't have anything useful to show anyhow. */
        return;
    }

    rates.rconn = rconn;
    rates.xid = 0;
    rates.got_reply = false;
    if (!inited) {
        rates.now.tx_bytes = UINT64_MAX;
        rates.prev.tx_bytes = UINT64_MAX;
        inited = true;
    }
    emit_function(&m, P_STATUS, do_show_data_rates, &rates);
}

struct message {
    /* Content. */
    void (*function)(void *aux);
    void *aux;
    char string[128];

    size_t index;
    enum priority priority;
    int age;
    int shown;
};

static struct message **messages;
static size_t n_messages, allocated_messages;

static struct message *
allocate_message(struct message **msgp)
{
    if (!*msgp) {
        /* Allocate and initialize message. */
        *msgp = xcalloc(1, sizeof **msgp);
        (*msgp)->index = n_messages;

        /* Add to list of messages. */
        if (n_messages >= allocated_messages) {
            allocated_messages = 2 * allocated_messages + 1;
            messages = xrealloc(messages,
                                sizeof *messages * allocated_messages);
        }
        messages[n_messages++] = *msgp;
    }
    return *msgp;
}

static void
emit(struct message **msgp, enum priority priority, const char *format, ...)
{
    struct message *msg = allocate_message(msgp);
    va_list args;
    size_t length;

    msg->priority = priority;

    va_start(args, format);
    length = strlen(msg->string);
    vsnprintf(msg->string + length, sizeof msg->string - length, format, args);
    va_end(args);
}

static void
emit_function(struct message **msgp, enum priority priority,
              void (*function)(void *aux), void *aux)
{
    struct message *msg = allocate_message(msgp);
    msg->priority = priority;
    msg->function = function;
    msg->aux = aux;
}

static int
shown(struct message **msgp)
{
    struct message *msg = allocate_message(msgp);
    return msg->shown;
}

static void
clear_messages(void)
{
    size_t i;

    for (i = 0; i < n_messages; i++) {
        struct message *msg = messages[i];
        msg->string[0] = '\0';
        msg->function = NULL;
    }
}

static struct message *
best_message(void)
{
    struct message *best_msg;
    int best_score;
    size_t i;

    best_score = INT_MIN;
    best_msg = NULL;
    for (i = 0; i < n_messages; i++) {
        struct message *msg = messages[i];
        int score;

        if (empty_message(msg)) {
            continue;
        }

        score = msg->priority;
        if (!msg->shown) {
            score += msg->age;
        } else {
            score -= msg->shown;
        }
        if (score > best_score) {
            best_score = score;
            best_msg = msg;
        }
    }
    return best_msg;
}

static void
message_shown(struct message *msg)
{
    if (msg && msg->shown++ > 3600) {
        msg->shown = 0;
    }
}

static bool
empty_message(const struct message *msg) 
{
    return !msg || (!msg->string[0] && !msg->function);
}

static struct message *get_message(size_t index)
{
    assert(index <= n_messages || index == SIZE_MAX);
    return (index < n_messages ? messages[index]
            : index == SIZE_MAX ? messages[n_messages - 1]
            : messages[0]);
}

static struct message *
next_message(struct message *msg)
{
    struct message *p;

    for (p = get_message(msg->index + 1); p != msg;
         p = get_message(p->index + 1)) {
        if (!empty_message(p)) {
            break;
        }
    }
    return p;
}

static struct message *
prev_message(struct message *msg)
{
    struct message *p;

    for (p = get_message(msg->index - 1); p != msg;
         p = get_message(p->index - 1)) {
        if (!empty_message(p)) {
            break;
        }
    }
    return p;
}

static void
put_message(const struct message *m)
{
    if (m->string[0]) {
        addstr(m->string);
    } else if (m->function) {
        m->function(m->aux);
    }
}

static void
age_messages(void)
{
    size_t i;
    int load;

    load = 0;
    for (i = 0; i < n_messages; i++) {
        struct message *msg = messages[i];
        if (!empty_message(msg)) {
            load++;
        }
    }

    for (i = 0; i < n_messages; i++) {
        struct message *msg = messages[i];
        if (empty_message(msg)) {
            msg->age = msg->shown = 0;
        } else {
            if (msg->age && msg->age % 60 == 0) {
                msg->shown -= MAX(0, 5 - (load + 6) / 12);
                if (msg->shown < 0) {
                    msg->shown = 0;
                }
            }
            if (msg->age++ > 3600) {
                msg->age = 0;
            }
        }
    }
}

/* Set by SIGUSR1 handler. */
static volatile sig_atomic_t sigusr1_triggered;

/* The time after which we stop indicating that the switch is rebooting.
 * (This is just in case the reboot fails.) */
static time_t reboot_deadline = TIME_MIN;

static void sigusr1_handler(int);

static void
init_reboot_notifier(void)
{
    signal(SIGUSR1, sigusr1_handler);
}

static void
sigusr1_handler(int signr UNUSED)
{
    sigusr1_triggered = true;
}

static bool
show_reboot_state(void)
{
    if (sigusr1_triggered) {
        reboot_deadline = time_now() + 30;
        sigusr1_triggered = false;
    }
    if (time_now() < reboot_deadline) {
        static struct message *msg;
        emit(&msg, P_FATAL, "Rebooting");
        return true;
    }
    return false;
}

struct menu_item {
    char *text;
    void (*f)(const struct dict *);
    int id;
    bool enabled;
    int toggle;
};

struct menu {
    struct menu_item **items;
    size_t n_items, allocated_items;
};

static void menu_init(struct menu *);
static void menu_free(struct menu *);
static struct menu_item *menu_add_item(struct menu *, const char *text, ...)
    PRINTF_FORMAT(2, 3);
static int menu_show(const struct menu *, int start, bool select);

static void cmd_shell(const struct dict *);
static void cmd_show_version(const struct dict *);
static void cmd_configure(const struct dict *);
static void cmd_set_up_pki(const struct dict *);
static void cmd_browse_status(const struct dict *);
static void cmd_show_motto(const struct dict *);

static void
menu_init(struct menu *menu)
{
    memset(menu, 0, sizeof *menu);
}

static void
menu_free(struct menu *menu)
{
    size_t i;

    for (i = 0; i < menu->n_items; i++) {
        struct menu_item *item = menu->items[i];
        free(item->text);
        free(item);
    }
    free(menu->items);
}

static struct menu_item *
menu_add_item(struct menu *menu, const char *text, ...)
{
    struct menu_item *item;
    va_list args;

    if (menu->n_items >= menu->allocated_items) {
        menu->allocated_items = 2 * menu->allocated_items + 1;
        menu->items = xrealloc(menu->items,
                               sizeof *menu->items * menu->allocated_items);
    }
    item = menu->items[menu->n_items++] = xmalloc(sizeof *item);
    va_start(args, text);
    item->text = xvasprintf(text, args);
    va_end(args);
    item->f = NULL;
    item->id = -1;
    item->enabled = true;
    item->toggle = -1;
    return item;
}

static void
menu(const struct dict *dict)
{
    bool debug_mode = dict_get_bool(dict, "debug", false);
    struct menu menu;
    int choice;

    menu_init(&menu);
    menu_add_item(&menu, "Exit");
    menu_add_item(&menu, "Show Version")->f = cmd_show_version;
    menu_add_item(&menu, "Configure")->f = cmd_configure;
    menu_add_item(&menu, "Set up PKI")->f = cmd_set_up_pki;
    if (debug_mode) {
        menu_add_item(&menu, "Browse Status")->f = cmd_browse_status;
        menu_add_item(&menu, "Shell")->f = cmd_shell;
        menu_add_item(&menu, "Show Motto")->f = cmd_show_motto;
    }

    choice = menu_show(&menu, 0, true);
    if (choice >= 0) {
        void (*f)(const struct dict *) = menu.items[choice]->f;
        if (f) {
            (f)(dict);
        }
    }

    menu_free(&menu);
}

static int
menu_show(const struct menu *menu, int start, bool select)
{
    long long int adjust = LLONG_MAX;
    int min = 0, max = MAX(menu->n_items - 2, 0);
    int pos, selection;
    set_icon(0,
             eXX___,
             eXXX__,
             eXXXX_,
             eXXXXX,
             eXXXX_,
             eXXX__,
             eXX___,
             e_____);
    set_icon(1,
             eXXXXX,
             eX___X,
             eX___X,
             eX___X,
             eX___X,
             eX___X,
             eXXXXX,
             e_____);
    set_icon(2,
             eXXXXX,
             eX___X,
             eXX_XX,
             eX_X_X,
             eXX_XX,
             eX___X,
             eXXXXX,
             e_____);
    if (menu->n_items) {
        pos = MIN(menu->n_items - 1, MAX(0, start));
        selection = pos;
    } else {
        pos = 0;
        selection = -1;
    }
    for (;;) {
        int key;

        while ((key = getch()) != ERR) {
            switch (key) {
            case KEY_UP:
                if (select && selection > 0) {
                    selection--;
                    if (selection >= pos) {
                        break;
                    }
                }
                if (pos >= min) {
                    pos--;
                }
                break;

            case KEY_DOWN:
                if (select && selection < menu->n_items - 1) {
                    selection++;
                    if (selection <= pos + 1) {
                        break;
                    }
                }
                if (pos <= max) {
                    pos++;
                }
                break;

            case '\r': case '\n':
                if (select && selection >= 0 && selection < menu->n_items) {
                    struct menu_item *item = menu->items[selection];
                    if (!item->enabled) {
                        show_string("Item disabled");
                        break;
                    } else if (item->toggle >= 0) {
                        item->toggle = !item->toggle;
                        break;
                    }
                }
                return selection;

            case '\b': case '\x7f': case '\x1b':
            case KEY_BACKSPACE: case KEY_DC:
                return -1;
            }
            adjust = time_msec() + 1000;
        }
        if (time_msec() >= adjust && menu->n_items > 1) {
            if (pos < min) {
                pos = min;
            } else if (pos > max) {
                pos = max;
            }
        }

        erase();
        curs_set(0);
        move(0, 0);
        if (!menu->n_items) {
            addstr("[Empty]");
        } else {
            int idx;
            for (idx = pos; idx < pos + 2; idx++) {
                size_t width = 40;

                if (select) {
                    width--;
                    if (selection == idx) {
                        put_icon(0, '>');
                    } else {
                        addch(' ');
                    }
                }

                if (idx < 0) {
                    addstr("[Top]");
                } else if (idx >= menu->n_items) {
                    addstr("[Bottom]");
                } else {
                    const struct menu_item *item = menu->items[idx];
                    size_t length = strlen(item->text);
                    if (!item->enabled) {
                        width -= 2;
                        addch('(');
                    }
                    if (item->toggle >= 0) {
                        if (have_icons()) {
                            addch(icon_char(item->toggle ? 2 : 1, 0));
                            width--;
                        } else {
                            addstr(item->toggle ? "[X]" : "[ ]");
                            width -= 3;
                        }
                    }
                    addnstr(item->text, MIN(width, length));
                    if (!item->enabled) {
                        addch(')');
                    }
                }
                if (idx == pos) {
                    addch('\n');
                }
            }
        }
        refresh();

        if (pos < min || pos > max) {
            poll_timer_wait(adjust - time_msec());
        }
        poll_fd_wait(STDIN_FILENO, POLLIN);
        poll_block();
    }
}

static int
menu_show2(const struct menu *menu, int start, bool select)
{
    int pos;
    if (menu->n_items) {
        pos = MIN(menu->n_items - 1, MAX(0, start));
    } else {
        pos = -1;
    }
    set_icon(0,
             e__X__,
             e_XXX_,
             eXXXXX,
             e__X__,
             e__X__,
             e__X__,
             e__X__,
             e__X__);
    set_icon(1,
             e__X__,
             e__X__,
             e__X__,
             e__X__,
             e__X__,
             eXXXXX,
             e_XXX_,
             e__X__);
    for (;;) {
        int key;

        while ((key = getch()) != ERR) {
            switch (key) {
            case KEY_UP:
                if (pos > 0) {
                    pos--;
                }
                break;

            case KEY_DOWN:
                if (menu->n_items > 0 && pos < menu->n_items - 1) {
                    pos++;
                }
                break;

            case '\r': case '\n':
                if (select && !menu->items[pos]->enabled) {
                    show_string("Item disabled");
                    break;
                }
                return pos;

            case '\b': case '\x7f': case '\x1b':
            case KEY_BACKSPACE: case KEY_DC:
                return -1;
            }
        }

        erase();
        curs_set(0);
        move(0, 0);
        if (pos == -1) {
            addstr("[Empty]");
        } else {
            const struct menu_item *item = menu->items[pos];
            const char *line1 = item->text;
            size_t len1 = strcspn(line1, "\n");
            const char *line2 = line1[len1] ? &line1[len1 + 1] : "";
            size_t len2 = strcspn(line2, "\n");
            size_t width = 39 - 2 * !item->enabled;

            /* First line. */
            addch(pos > 0 ? icon_char(0, '^') : ' ');
            if (!item->enabled && len1) {
                addch('(');
            }
            addnstr(line1, MIN(len1, width));
            if (!item->enabled && len1) {
                addch(')');
            }
            addch('\n');

            /* Second line. */
            addch(pos < menu->n_items - 1 ? icon_char(1, 'V') : ' ');
            if (!item->enabled && len2) {
                addch('(');
            }
            addnstr(line2, MIN(len2, width));
            if (!item->enabled && len2) {
                addch(')');
            }
        }
        refresh();

        poll_fd_wait(STDIN_FILENO, POLLIN);
        poll_block();
    }
}

static bool
yesno(const char *title, bool def)
{
    bool answer = def;

    set_icon(0,
             eXX___,
             eXXX__,
             eXXXX_,
             eXXXXX,
             eXXXX_,
             eXXX__,
             eXX___,
             e_____);

    for (;;) {
        int key;

        while ((key = getch()) != ERR) {
            switch (key) {
            case KEY_UP:
            case KEY_DOWN:
            case KEY_LEFT:
            case KEY_RIGHT:
                answer = !answer;
                break;

            case 'y': case 'Y':
                answer = true;
                break;

            case 'n': case 'N':
                answer = false;
                break;

            case '\r': case '\n':
                return answer;
            }
        }

        erase();
        curs_set(0);
        move(0, 0);
        addstr(title);

        move(0, 12);
        addch(answer ? icon_char(0, '>') : ' ');
        addstr("Yes");

        move(1, 12);
        addch(!answer ? icon_char(0, '>') : ' ');
        addstr("No");

        refresh();

        poll_fd_wait(STDIN_FILENO, POLLIN);
        poll_block();
    }
}

static void
cmd_show_version(const struct dict *dict UNUSED)
{
    show_string(VERSION BUILDNR);
}

static void
cmd_browse_status(const struct dict *dict)
{
    struct menu menu;
    size_t i;

    menu_init(&menu);
    for (i = 0; i < dict->n; i++) {
        const struct pair *p = &dict->pairs[i];
        menu_add_item(&menu, "%s = %s", p->name, p->value); 
    }
    menu_show(&menu, 0, false);
    menu_free(&menu);
}

static void
cmd_shell(const struct dict *dict UNUSED)
{
    const char *home;

    erase();
    refresh();
    endwin();

    printf("Type ^D to exit\n");
    fflush(stdout);

    putenv("PS1=#");
    putenv("PS2=>");
    putenv("PS3=?");
    putenv("PS4=+");
    home = getenv("HOME");
    if (home) {
        chdir(home);
    }
    system("/bin/sh");
    initialize_terminal();
}

static void
cmd_show_motto(const struct dict *dict UNUSED)
{
    show_string("\"Just Add Ice\"");
}

static void
show_string(const char *string)
{
    VLOG_INFO("%s", string);
    erase();
    curs_set(0);
    move(0, 0);
    addstr(string);
    refresh();
    block_until(time_msec() + 5000);
}

static void
block_until(long long timeout)
{
    while (timeout > time_msec()) {
        poll_timer_wait(timeout - time_msec());
        poll_block();
    }
    drain_keyboard_buffer();
}

static void
drain_keyboard_buffer(void)
{
    while (getch() != ERR) {
        continue;
    }
}

static int
read_vars(const char *cmd, struct dict *dict)
{
    struct ds ds;
    FILE *stream;
    int status;

    stream = popen(cmd, "r");
    if (!stream) {
        VLOG_ERR("popen(\"%s\") failed: %s", cmd, strerror(errno));
        return errno;
    }

    dict_init(dict);
    ds_init(&ds);
    while (!ds_get_line(&ds, stream)) {
        const char *s = ds_cstr(&ds);
        const char *equals = strchr(s, '=');
        if (equals) {
            dict_add_nocopy(dict,
                            xmemdup0(s, equals - s), xstrdup(equals + 1));
        }
    }
    status = pclose(stream);
    if (status) {
        char *msg = process_status_msg(status);
        VLOG_ERR("pclose(\"%s\") reported subprocess failure: %s",
                 cmd, msg);
        free(msg);
        dict_free(dict);
        return ECHILD;
    }
    return 0;
}

static bool
run_and_report_failure(char **argv, const char *title)
{
    int null_fds[3] = {0, 1, 2};
    int status;
    int retval;
    char *s;

    s = process_escape_args(argv);
    VLOG_INFO("starting subprocess: %s", s);
    free(s);

    retval = process_run(argv, NULL, 0, null_fds, 3, &status);
    if (retval) {
        char *s = xasprintf("%s:\n%s", title, strerror(retval));
        show_string(s);
        free(s);
        return false;
    } else if (status) {
        char *msg = process_status_msg(status);
        char *s = xasprintf("%s:\n%s", title, msg);
        show_string(s);
        free(msg);
        free(s);
        return false;
    } else {
        VLOG_INFO("subprocess exited with status 0");
        return true;
    }
}

static int
do_load_config(const char *file_name, struct dict *dict)
{
    struct dict auto_vars;
    int retval;
    char *cmd;
    size_t i;

    /* Get the list of the variables that the shell sets automatically. */
    retval = read_vars("set -a && env", &auto_vars);
    if (retval) {
        return retval;
    }

    /* Get the variables from 'file_name'. */
    cmd = xasprintf("set -a && . '%s' && env", file_name);
    retval = read_vars(cmd, dict);
    free(cmd);
    if (retval) {
        dict_free(&auto_vars);
        return retval;
    }

    /* Subtract. */
    for (i = 0; i < auto_vars.n; i++) {
        dict_delete(dict, auto_vars.pairs[i].name);
    }
    dict_free(&auto_vars);
    return 0;
}

static bool
load_config(struct dict *dict)
{
    static const char default_file[] = "/etc/default/openflow-switch";
    int retval = do_load_config(default_file, dict);
    if (!retval) {
        return true;
    } else {
        char *s = xasprintf("Cfg load failed:\n%s", strerror(retval));
        show_string(s);
        free(s);
        return false;
    }
}

static bool
save_config(const struct svec *settings)
{
    struct svec argv;
    size_t i;
    bool ok;

    VLOG_INFO("Saving configuration:");
    for (i = 0; i < settings->n; i++) {
        VLOG_INFO("%s", settings->names[i]);
    }

    svec_init(&argv);
    svec_add(&argv, "/usr/share/openvswitch/commands/reconfigure");
    svec_append(&argv, settings);
    svec_terminate(&argv);
    ok = run_and_report_failure(argv.names, "Save failed");
    if (ok) {
        long long int timeout = time_msec() + 5000;

        erase();
        curs_set(0);
        move(0, 0);
        addstr("Saved.\nRestarting...");
        refresh();

        svec_clear(&argv);
        svec_add(&argv, "/bin/sh");
        svec_add(&argv, "-c");
        svec_add(&argv,
                 "/etc/init.d/openflow-switch restart >/dev/null 2>&1");
        svec_terminate(&argv);

        ok = run_and_report_failure(argv.names, "Restart failed");
        if (ok) {
            block_until(timeout);
        }
    }
    svec_destroy(&argv);

    if (ok) {
        VLOG_INFO("Save completed successfully");
    } else {
        VLOG_WARN("Save failed");
    }
    return ok;
}

static int
match(pcre *re, const char *string, int length)
{
    int ovec[999];
    int retval;

    retval = pcre_exec(re, NULL, string, length, 0, PCRE_PARTIAL,
                       ovec, ARRAY_SIZE(ovec));
    if (retval >= 0) {
        if (ovec[0] >= 0 && ovec[1] >= length) {
            /* 're' matched all of 'string'. */
            return 0;
        } else {
            /* 're' matched the initial part of 'string' but not all of it. */
            return PCRE_ERROR_NOMATCH;
        }
    } else {
        return retval;
    }
}

static void
figure_choices(pcre *re, struct ds *s, int pos, struct ds *choices)
{
    struct ds tmp;
    int retval;
    char c;

    ds_clear(choices);

    /* See whether the current string is a complete match. */
    if (!match(re, s->string, pos)) {
        ds_put_char(choices, '\n');
    }

    /* Then try all the other possibilities. */
    ds_init(&tmp);
    ds_put_buffer(&tmp, s->string, pos);
    for (c = 0x20; c < 0x7f; c++) {
        ds_put_char(&tmp, c);
        retval = match(re, tmp.string, pos + 1);
        if (retval == PCRE_ERROR_PARTIAL || !retval) {
            ds_put_char(choices, c);
        }
        tmp.length--;
    }
    ds_destroy(&tmp);

    if (!choices->length) {
        ds_put_char(choices, '\n');
    }
}

static void
figure_completion(pcre *re, struct ds *s)
{
    for (;;) {
        int found = -1;
        int c;

        /* See whether the current string is a complete match. */
        if (!match(re, s->string, s->length)) {
            return;
        }
        for (c = 0x20; c < 0x7f; c++) {
            int retval;

            ds_put_char(s, c);
            retval = match(re, s->string, s->length);
            s->length--;

            if (retval == PCRE_ERROR_PARTIAL || !retval) {
                if (found != -1) {
                    return;
                }
                found = c;
            }
        }
        if (found == -1) {
            return;
        }
        ds_put_char(s, found);
    }
}

#define OCTET_RE "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
#define IP_RE "("OCTET_RE"\\."OCTET_RE"\\."OCTET_RE"\\."OCTET_RE")"
#define PORT_RE                                 \
    "([0-9]|"                                   \
    "[1-9][0-9]|"                               \
    "[1-9][0-9][0-9]|"                          \
    "[1-9][0-9][0-9][0-9]|"                     \
    "[1-5][0-9][0-9][0-9][0-9]|"                \
    "6[1-4][0-9][0-9][0-9]|"                    \
    "65[1-4][0-9][0-9]|"                        \
    "655[1-2][0-9]|"                            \
    "6553[1-5])"
#define XOCTET_RE "[0-9A-F][0-9A-F]"
#define MAC_RE \
        XOCTET_RE":"XOCTET_RE":"XOCTET_RE":"\
        XOCTET_RE":"XOCTET_RE":"XOCTET_RE
#define NUM100_TO_99999_RE                      \
    "([1-9][0-9][0-9]|"                         \
    "[1-9][0-9][0-9][0-9]|"                     \
    "[1-9][0-9][0-9][0-9][0-9])"
#define NUM5_TO_99999_RE                        \
    "([5-9]|"                                   \
    "[1-9][0-9]|"                               \
    "[1-9][0-9][0-9]|"                          \
    "[1-9][0-9][0-9][0-9]|"                     \
    "[1-9][0-9][0-9][0-9][0-9])"
#define NUM1_TO_99999_RE                        \
    "([1-9]|"                                   \
    "[1-9][0-9]|"                               \
    "[1-9][0-9][0-9]|"                          \
    "[1-9][0-9][0-9][0-9]|"                     \
    "[1-9][0-9][0-9][0-9][0-9])"

static char *
prompt(const char *prompt, const char *initial, const char *pattern)
{
    struct ds ds;
    int pos, chidx;
    struct ds choices;
    const char *error;
    int erroffset;
    pcre *re;
    int retval;
    int okpartial;
    char *p;

    set_icon(0,
             e____X,
             e____X,
             e__X_X,
             e_X__X,
             eXXXXX,
             e_X___,
             e__X__,
             e_____);

    re = pcre_compile(pattern, PCRE_ANCHORED, &error, &erroffset, NULL);
    if (!re) {
        VLOG_ERR("PCRE error for pattern \"%s\" at offset %d: %s",
                 pattern, erroffset, error);
        return xstrdup(initial);
    }

    retval = pcre_fullinfo(re, NULL, PCRE_INFO_OKPARTIAL, &okpartial);
    assert(!retval);
    assert(okpartial);

    pos = 0;
    ds_init(&ds);
    ds_put_cstr(&ds, initial);
    ds_init(&choices);
    figure_choices(re, &ds, pos, &choices);
    p = memchr(choices.string, initial[0], choices.length);
    chidx = p ? p - choices.string : 0;
    for (;;) {
        int c, key;

        while ((key = getch()) != ERR) {
            switch (key) {
            case KEY_UP:
                if (choices.length > 1) {
                    if (++chidx >= choices.length) {
                        chidx = 0;
                    }
                    ds.string[pos] = choices.string[chidx];
                    ds_truncate(&ds, pos + 1);
                    figure_completion(re, &ds);
                }
                break;

            case KEY_DOWN:
                if (choices.length > 1) {
                    if (--chidx < 0) {
                        chidx = choices.length - 1;
                    }
                    ds.string[pos] = choices.string[chidx];
                    ds_truncate(&ds, pos + 1);
                    figure_completion(re, &ds);
                }
                break;

            case '\r': case '\n':
                if (choices.string[chidx] == '\n') {
                    ds_truncate(&ds, pos);
                    return ds_cstr(&ds);
                } else {
                    if (pos >= ds.length) {
                        pos++;
                        ds_put_char(&ds, choices.string[chidx]);
                        figure_choices(re, &ds, pos, &choices);
                        chidx = 0;
                        figure_completion(re, &ds);
                    } else {
                        pos = ds.length;
                        figure_choices(re, &ds, pos, &choices);
                        chidx = 0;
                        figure_completion(re, &ds);
                    }
                }
                break;

            case '\f':
                ds_truncate(&ds, pos + 1);
                figure_choices(re, &ds, pos, &choices);
                chidx = 0;
                break;

            case '\b': case '\x7f': case '\x1b':
            case KEY_BACKSPACE: case KEY_DC:
                if (pos) {
                    pos--;
                } else {
                    return xstrdup(initial);
                }
                figure_choices(re, &ds, pos, &choices);
                chidx = 0;
                if (pos < ds.length) {
                    p = memchr(choices.string, ds.string[pos],
                               choices.length);
                    if (p) {
                        chidx = p - choices.string;
                    }
                }
                break;

            default:
                if (key >= 0x20 && key < 0x7f) {
                    /* Check whether 'key' is valid and toggle case if
                     * necessary. */
                    if (!memchr(choices.string, key, choices.length)) {
                        if (memchr(choices.string, toupper(key),
                                   choices.length)) {
                            key = toupper(key);
                        } else if (memchr(choices.string, tolower(key),
                                          choices.length)) {
                            key = tolower(key);
                        } else {
                            break;
                        }
                    }

                    /* Insert 'key' and advance the position. */
                    if (pos >= ds.length) {
                        ds_put_char(&ds, key);
                    } else {
                        ds.string[pos] = key;
                    }
                    pos++;

                    if (choices.string[chidx] != key) {
                        ds_truncate(&ds, pos);
                    }
                    figure_choices(re, &ds, pos, &choices);
                    chidx = 0;
                    if (pos < ds.length) {
                        p = memchr(choices.string, ds.string[pos],
                                   choices.length);
                        if (p) {
                            chidx = p - choices.string;
                        }
                    }
                    figure_completion(re, &ds);
                }
            }
        }

        erase();
        curs_set(1);
        move(0, 0);
        addnstr(prompt, MIN(40, strlen(prompt)));

        c = choices.string[chidx];
        move(1, 0);
        addstr(ds_cstr(&ds));
        move(1, pos);
        if (c == '\n') {
            put_icon(0, '$');
        } else {
            addch(c);
        }
        move(1, pos);
        refresh();

        poll_fd_wait(STDIN_FILENO, POLLIN);
        poll_block();
    }
}

static void
prompt_ip(const char *title, uint32_t *ip)
{
    char *in = xasprintf(IP_FMT, IP_ARGS(ip));
    char *out = prompt(title, in, "^"IP_RE"$");
    *ip = inet_addr(out);
    free(in);
    free(out);
}

static void
abbreviate_netdevs(const struct svec *netdevs, struct ds *abbrev)
{
    size_t i;

    ds_init(abbrev);
    for (i = 0; i < netdevs->n; ) {
        size_t i_len = strlen(netdevs->names[i]);
        size_t j;

        for (j = i + 1; j < netdevs->n; j++) {
            size_t j_len = strlen(netdevs->names[j]);
            if (!i_len || !j_len || i_len != j_len
                || memcmp(netdevs->names[i], netdevs->names[j], i_len - 1)) {
                break;
            }
        }

        if (abbrev->length) {
            ds_put_char(abbrev, ' ');
        }
        if (j - i == 1) {
            ds_put_cstr(abbrev, netdevs->names[i]);
        } else {
            size_t k;

            ds_put_buffer(abbrev, netdevs->names[i], i_len - 1);
            ds_put_char(abbrev, '[');
            for (k = i; k < j; k++) {
                ds_put_char(abbrev, netdevs->names[k][i_len - 1]);
            }
            ds_put_char(abbrev, ']');
        }
        i = j;
    }
}

static void
choose_netdevs(struct svec *choices)
{
    struct svec netdevs;
    struct menu menu;
    size_t i;

    netdev_enumerate(&netdevs);
    svec_sort(&netdevs);

    menu_init(&menu);
    menu_add_item(&menu, "Exit");
    for (i = 0; i < netdevs.n; i++) {
        const char *name = netdevs.names[i];
        struct menu_item *item;
        struct netdev *netdev;
        int retval;

        if (!strncmp(name, "wmaster", strlen("wmaster"))
            || !strncmp(name, "of", strlen("of"))
            || !strcmp(name, "lo")) {
            continue;
        }

        retval = netdev_open(name, NETDEV_ETH_TYPE_NONE, &netdev);
        if (!retval) {
            bool exclude = netdev_get_in4(netdev, NULL, NULL) == 0;
            netdev_close(netdev);
            if (exclude) {
                continue;
            }
        }

        item = menu_add_item(&menu, "%s", name);
        item->toggle = svec_contains(choices, name);
    }
    if (menu.n_items > 1) {
        menu_show(&menu, 0, true);
    } else {
        show_string("No available\nbridge ports");
    }

    svec_clear(choices);
    for (i = 0; i < menu.n_items; i++) {
        struct menu_item *item = menu.items[i];
        if (item->toggle > 0) {
            svec_add(choices, item->text);
        }
    }

    menu_free(&menu);
}

static bool
is_datapath_id_in_dmi(void)
{
    FILE *dmidecode;
    char line[256];
    bool is_in_dmi;

    dmidecode = popen("dmidecode -s system-uuid", "r");
    if (!dmidecode) {
        return false;
    }
    is_in_dmi = fgets(line, sizeof line, dmidecode) && strstr(line, "-002320");
    fclose(dmidecode);
    return is_in_dmi;
}

struct switch_config {
    struct svec netdevs;
    enum { DISCOVERY, IN_BAND } mode;
    uint32_t switch_ip;
    uint32_t switch_mask;
    uint32_t switch_gw;
    enum { FAIL_DROP, FAIL_SWITCH } disconnected;
    bool stp;
    int rate_limit;
    int inactivity_probe;
    int max_backoff;
    char *controller_vconn;
    char *datapath_id;
};

static const char *
disconnected_string(int value)
{
#define FAIL_SWITCH_STRING "Switch packets"
#define FAIL_DROP_STRING "Drop packets"
    return value == FAIL_SWITCH ? FAIL_SWITCH_STRING : FAIL_DROP_STRING;
}

static void
cmd_configure(const struct dict *dict UNUSED)
{
    bool debug_mode = dict_get_bool(dict, "debug", false);
    struct dict config_dict;
    struct switch_config config;
    int start;

    if (!load_config(&config_dict)) {
        return;
    }
    svec_init(&config.netdevs);
    svec_parse_words(&config.netdevs,
                     dict_get_string(&config_dict, "NETDEVS", ""));
    config.mode = (!strcmp(dict_get_string(&config_dict, "MODE", "discovery"),
                           "in-band") ? IN_BAND : DISCOVERY);
    config.switch_ip = dict_get_ip(&config_dict, "SWITCH_IP");
    config.switch_mask = dict_get_ip(&config_dict, "SWITCH_NETMASK");
    config.switch_gw = dict_get_ip(&config_dict, "SWITCH_GATEWAY");
    config.controller_vconn = xstrdup(dict_get_string(&config_dict,
                                                      "CONTROLLER", ""));
    config.disconnected = (!strcmp(dict_get_string(&config_dict,
                                                   "DISCONNECTED_MODE", ""),
                                   "switch")
                           ? FAIL_SWITCH : FAIL_DROP);
    config.stp = !strcmp(dict_get_string(&config_dict, "stp", ""), "yes");
    config.rate_limit = dict_get_int(&config_dict, "RATE_LIMIT", -1);
    config.inactivity_probe = dict_get_int(&config_dict, "INACTIVITY_PROBE",
                                           -1);
    config.max_backoff = dict_get_int(&config_dict, "MAX_BACKOFF", -1);
    if (is_datapath_id_in_dmi()) {
        config.datapath_id = xstrdup("DMI");
    } else {
        const char *dpid = dict_get(&config_dict, "DATAPATH_ID");
        if (dpid) {
            struct ds ds = DS_EMPTY_INITIALIZER;
            const char *cp;
            for (cp = dpid; *cp != '\0'; cp++) {
                if (*cp != ':') {
                    ds_put_char(&ds, toupper((unsigned char) *cp));
                }
            }
            config.datapath_id = ds_cstr(&ds);
        } else {
            config.datapath_id = xstrdup("Random");
        }
    }
    dict_free(&config_dict);

    start = 0;
    while (start != -1) {
        enum {
            MENU_EXIT,
            MENU_NETDEVS,
            MENU_MODE,
            MENU_IP,
            MENU_NETMASK,
            MENU_GATEWAY,
            MENU_CONTROLLER,
            MENU_DISCONNECTED_MODE,
            MENU_DATAPATH_ID,
            MENU_STP,
            MENU_RATE_LIMIT,
            MENU_INACTIVITY_PROBE,
            MENU_MAX_BACKOFF,
        };

        struct ds ports;
        struct menu_item *item;
        struct menu menu;
        char *in, *out;
        uint32_t ip;

        menu_init(&menu);

        /* Exit. */
        item = menu_add_item(&menu, "Exit");
        item->id = MENU_EXIT;

        /* Bridge Ports. */
        abbreviate_netdevs(&config.netdevs, &ports);
        item = menu_add_item(&menu, "Bridge Ports:\n%s", ds_cstr(&ports));
        item->id = MENU_NETDEVS;
        ds_destroy(&ports);

        /* Mode. */
        item = menu_add_item(&menu, "Mode:\n%s",
                             (config.mode == DISCOVERY
                              ? "Discovery" : "In-Band"));
        item->id = MENU_MODE;

        /* IP address. */
        if (config.switch_ip == htonl(0)) {
            item = menu_add_item(&menu, "Switch IP Addr:\nDHCP");
        } else {
            item = menu_add_item(&menu, "Switch IP Addr:\n"IP_FMT,
                                 IP_ARGS(&config.switch_ip));
        }
        item->id = MENU_IP;
        item->enabled = config.mode == IN_BAND;

        /* Netmask. */
        item = menu_add_item(&menu, "Switch Netmask:\n"IP_FMT,
                             IP_ARGS(&config.switch_mask));
        item->id = MENU_NETMASK;
        item->enabled = config.mode == IN_BAND && config.switch_ip != htonl(0);

        /* Gateway. */
        item = menu_add_item(&menu, "Switch Gateway:\n"IP_FMT,
                             IP_ARGS(&config.switch_gw));
        item->id = MENU_GATEWAY;
        item->enabled = config.mode == IN_BAND && config.switch_ip != htonl(0);

        /* Controller. */
        item = menu_add_item(&menu, "Controller:\n%s",
                             config.controller_vconn);
        item->id = MENU_CONTROLLER;
        item->enabled = config.mode == IN_BAND;

        /* Disconnected mode. */
        item = menu_add_item(&menu, "If disconnected:\n%s\n",
                             disconnected_string(config.disconnected));
        item->id = MENU_DISCONNECTED_MODE;

        /* Datapath ID. */
        item = menu_add_item(&menu, "Datapath ID:\n%s", config.datapath_id);
        item->id = MENU_DATAPATH_ID;
        item->enabled = strcmp(config.datapath_id, "DMI");

        /* Spanning tree protocol. */
        if (debug_mode) {
            item = menu_add_item(&menu, "802.1D-1998 STP:\n%s",
                                 config.stp ? "Enabled" : "Disabled");
            item->id = MENU_STP;
        }

        /* Rate-limiting. */
        if (debug_mode) {
            if (config.rate_limit < 0) {
                item = menu_add_item(&menu, "Ctlr rate limit:\nDisabled");
            } else {
                item = menu_add_item(&menu, "Ctlr rate limit:\n%d/s",
                                     config.rate_limit);
            }
            item->id = MENU_RATE_LIMIT;
        }

        /* Inactivity probe. */
        if (debug_mode) {
            if (config.inactivity_probe < 0) {
                item = menu_add_item(&menu, "Activity probe:\nDefault");
            } else {
                item = menu_add_item(&menu, "Activity probe:\n%d s",
                                     config.inactivity_probe);
            }
            item->id = MENU_INACTIVITY_PROBE;
        }

        /* Max backoff. */
        if (debug_mode) {
            if (config.max_backoff < 0) {
                item = menu_add_item(&menu, "Max backoff:\nDefault");
            } else {
                item = menu_add_item(&menu, "Max backoff:\n%d s",
                                     config.max_backoff);
            }
            item->id = MENU_MAX_BACKOFF;
        }

        start = menu_show2(&menu, start, true);
        menu_free(&menu);

        in = out = NULL;
        switch (start) {
        case MENU_EXIT:
            start = -1;
            break;

        case MENU_NETDEVS:
            choose_netdevs(&config.netdevs);
            break;

        case MENU_MODE:
            out = prompt("Mode:",
                         config.mode == DISCOVERY ? "Discovery" : "In-Band",
                         "^(Discovery|In-Band)$");
            config.mode = !strcmp(out, "Discovery") ? DISCOVERY : IN_BAND;
            free(out);
            break;

        case MENU_IP:
            in = (config.switch_ip == htonl(0) ? xstrdup("DHCP")
                  : xasprintf(IP_FMT, IP_ARGS(&config.switch_ip)));
            out = prompt("Switch IP:", in, "^(DHCP|"IP_RE")$");
            ip = strcmp(out, "DHCP") ? inet_addr(out) : htonl(0);
            free(in);
            free(out);
            if (ip != config.switch_ip) {
                config.switch_ip = ip;
                if (ip != htonl(0)) {
                    uint32_t mask = guess_netmask(ip);
                    if (mask) {
                        config.switch_mask = mask;
                        config.switch_gw = (ip & mask) | htonl(1);
                    }
                }
            }
            break;

        case MENU_NETMASK:
            prompt_ip("Switch Netmask:", &config.switch_mask);
            break;

        case MENU_GATEWAY:
            prompt_ip("Switch Gateway:", &config.switch_gw);
            break;

        case MENU_CONTROLLER:
            out = prompt("Controller:", config.controller_vconn,
                         "^(tcp|ssl):"IP_RE"(:"PORT_RE")?$");
            free(config.controller_vconn);
            config.controller_vconn = out;
            break;

        case MENU_DISCONNECTED_MODE:
            out = prompt("If disconnected",
                         disconnected_string(config.disconnected),
                         "^("FAIL_DROP_STRING"|"FAIL_SWITCH_STRING")$");
            config.disconnected = (!strcmp(out, FAIL_DROP_STRING)
                                   ? FAIL_DROP : FAIL_SWITCH);
            free(out);
            break;

        case MENU_DATAPATH_ID:
            out = prompt("Datapath ID:", config.datapath_id,
                         "^Random|"MAC_RE"$");
            free(config.datapath_id);
            config.datapath_id = out;
            break;

        case MENU_STP:
            out = prompt("802.1D-1998 STP:",
                         config.stp ? "Enabled" : "Disabled",
                         "^(Enabled|Disabled)$");
            config.stp = !strcmp(out, "Enabled");
            free(out);
            break;

        case MENU_RATE_LIMIT:
            in = (config.rate_limit < 0
                  ? xstrdup("Disabled")
                  : xasprintf("%d/s", config.rate_limit));
            out = prompt("Ctlr rate limit:", in,
                         "^(Disabled|("NUM100_TO_99999_RE")/s)$");
            free(in);
            config.rate_limit
                    = isdigit((unsigned char)out[0]) ? atoi(out) : -1;
            free(out);
            break;

        case MENU_INACTIVITY_PROBE:
            in = (config.inactivity_probe < 0
                  ? xstrdup("Default")
                  : xasprintf("%d s", config.inactivity_probe));
            out = prompt("Activity probe:", in,
                         "^(Default|("NUM5_TO_99999_RE") s)$");
            free(in);
            config.inactivity_probe
                    = isdigit((unsigned char)out[0]) ? atoi(out) : -1;
            free(out);
            break;

        case MENU_MAX_BACKOFF:
            in = (config.max_backoff < 0
                  ? xstrdup("Default")
                  : xasprintf("%d s", config.max_backoff));
            out = prompt("Max backoff:", in,
                         "^(Default|("NUM1_TO_99999_RE") s)$");
            free(in);
            config.max_backoff
                    = isdigit((unsigned char)out[0]) ? atoi(out) : -1;
            free(out);
            break;
        }
    }

    if (yesno("Save\nChanges?", false)) {
        struct svec set;
        char *netdevs;

        svec_init(&set);
        netdevs = svec_join(&config.netdevs, " ", "");
        svec_add_nocopy(&set, xasprintf("NETDEVS=%s", netdevs));
        free(netdevs);
        svec_add(&set,
                 config.mode == IN_BAND ? "MODE=in-band" : "MODE=discovery");
        if (config.mode == IN_BAND) {
            if (config.switch_ip == htonl(0)) {
                svec_add(&set, "SWITCH_IP=dhcp");
            } else {
                svec_add_nocopy(&set, xasprintf("SWITCH_IP="IP_FMT,
                                                IP_ARGS(&config.switch_ip)));
                svec_add_nocopy(&set,
                                xasprintf("SWITCH_NETMASK="IP_FMT,
                                          IP_ARGS(&config.switch_mask)));
                svec_add_nocopy(&set, xasprintf("SWITCH_GATEWAY="IP_FMT,
                                                IP_ARGS(&config.switch_gw)));
                svec_add_nocopy(&set, xasprintf("CONTROLLER=%s",
                                                config.controller_vconn));
            }
        }
        svec_add(&set, (config.disconnected == FAIL_DROP
                        ? "DISCONNECTED_MODE=drop"
                        : "DISCONNECTED_MODE=switch"));
        svec_add_nocopy(&set, xasprintf("STP=%s", config.stp ? "yes" : "no"));
        if (config.rate_limit < 0) {
            svec_add(&set, "RATE_LIMIT=");
        } else {
            svec_add_nocopy(&set,
                            xasprintf("RATE_LIMIT=%d", config.rate_limit));
        }
        if (config.inactivity_probe < 0) {
            svec_add(&set, "INACTIVITY_PROBE=");
        } else {
            svec_add_nocopy(&set, xasprintf("INACTIVITY_PROBE=%d",
                                            config.inactivity_probe));
        }
        if (config.max_backoff < 0) {
            svec_add(&set, "MAX_BACKOFF=");
        } else {
            svec_add_nocopy(&set, xasprintf("MAX_BACKOFF=%d",
                                            config.max_backoff));
        }
        save_config(&set);
        svec_destroy(&set);
    }

    svec_destroy(&config.netdevs);
    free(config.controller_vconn);
    free(config.datapath_id);
}

static void
cmd_set_up_pki(const struct dict *dict UNUSED)
{
    static const char def_privkey_file[]
        = "/etc/openflow-switch/of0-privkey.pem";
    static const char def_cert_file[] = "/etc/openflow-switch/of0-cert.pem";
    static const char def_cacert_file[] = "/etc/openflow-switch/cacert.pem";
    struct dict config_dict;
    const char *privkey_file, *cert_file, *cacert_file;
    bool bootstrap;
    struct stat s;
    struct svec set;
    bool has_keys;

    if (!load_config(&config_dict)) {
        return;
    }
    privkey_file = dict_get_string(&config_dict, "PRIVKEY", def_privkey_file);
    cert_file = dict_get_string(&config_dict, "CERT", def_cert_file);
    cacert_file = dict_get_string(&config_dict, "CACERT", def_cacert_file);
    bootstrap = !strcmp(dict_get_string(&config_dict, "CACERT_MODE", "secure"),
                        "bootstrap");

    has_keys = !stat(privkey_file, &s) && !stat(cert_file, &s);
    if (!has_keys
        ? yesno("Generate\nkeys?", true)
        : yesno("Generate\nnew keys?", false)) {
        struct svec argv;
        bool ok;

        privkey_file = def_privkey_file;
        cert_file = def_cert_file;

        svec_init(&argv);
        svec_parse_words(&argv, "sh -c 'cd /etc/openflow-switch "
                         "&& ovs-pki --force req of0"
                         "&& ovs-pki --force self-sign of0'");
        svec_terminate(&argv);
        ok = run_and_report_failure(argv.names, "Key gen failed");
        svec_destroy(&argv);
        if (!ok) {
            return;
        }
        has_keys = true;
    }
    if (!has_keys) {
        return;
    }

    if (stat(cacert_file, &s) && errno == ENOENT) {
        bootstrap = yesno("Bootstrap\nCA cert?", bootstrap);
    } else if (yesno("Replace\nCA cert?", false)) {
        unlink(cacert_file);
        bootstrap = true;
    }

    svec_init(&set);
    svec_add_nocopy(&set, xasprintf("PRIVKEY=%s", privkey_file));
    svec_add_nocopy(&set, xasprintf("CERT=%s", cert_file));
    svec_add_nocopy(&set, xasprintf("CACERT=%s", cacert_file));
    svec_add_nocopy(&set, xasprintf("CACERT_MODE=%s",
                                    bootstrap ? "bootstrap" : "secure"));
    save_config(&set);
    svec_destroy(&set);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

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
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: OpenFlow switch monitoring user interface\n"
           "usage: %s [OPTIONS] SWITCH\n"
           "where SWITCH is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    printf("\nOptions:\n"
           "  -v, --verbose=MODULE:FACILITY:LEVEL  configure logging levels\n"
           "  -v, --verbose               set maximum verbosity level\n"
           "  -h, --help             display this help message\n"
           "  -V, --version          display version information\n");
    exit(EXIT_SUCCESS);
}
