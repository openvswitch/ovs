/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014 Nicira, Inc.
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
#undef NDEBUG
#include "stp.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include "dp-packet.h"
#include "openvswitch/ofpbuf.h"
#include "ovstest.h"
#include "packets.h"
#include "openvswitch/vlog.h"

struct bpdu {
    int port_no;
    void *data;
    size_t size;
};

struct bridge {
    struct test_case *tc;
    int id;
    bool reached;

    struct stp *stp;

    struct lan *ports[STP_MAX_PORTS];
    int n_ports;

#define RXQ_SIZE 16
    struct bpdu rxq[RXQ_SIZE];
    int rxq_head, rxq_tail;
};

struct lan_conn {
    struct bridge *bridge;
    int port_no;
};

struct lan {
    struct test_case *tc;
    const char *name;
    bool reached;
    struct lan_conn conns[16];
    int n_conns;
};

struct test_case {
    struct bridge *bridges[16];
    int n_bridges;
    struct lan *lans[26];
    int n_lans;
};

static const char *file_name;
static int line_number;
static char line[128];
static char *pos, *token;
static int n_warnings;

static struct test_case *
new_test_case(void)
{
    struct test_case *tc = xmalloc(sizeof *tc);
    tc->n_bridges = 0;
    tc->n_lans = 0;
    return tc;
}

static void
send_bpdu(struct dp_packet *pkt, int port_no, void *b_)
{
    struct bridge *b = b_;
    struct lan *lan;

    assert(port_no < b->n_ports);
    lan = b->ports[port_no];
    if (lan) {
        const void *data = dp_packet_l3(pkt);
        size_t size = (char *) dp_packet_tail(pkt) - (char *) data;
        int i;

        for (i = 0; i < lan->n_conns; i++) {
            struct lan_conn *conn = &lan->conns[i];
            if (conn->bridge != b || conn->port_no != port_no) {
                struct bridge *dst = conn->bridge;
                struct bpdu *bpdu = &dst->rxq[dst->rxq_head++ % RXQ_SIZE];
                assert(dst->rxq_head - dst->rxq_tail <= RXQ_SIZE);
                bpdu->data = xmemdup(data, size);
                bpdu->size = size;
                bpdu->port_no = conn->port_no;
            }
        }
    }
    dp_packet_delete(pkt);
}

static struct bridge *
new_bridge(struct test_case *tc, int id)
{
    struct bridge *b = xmalloc(sizeof *b);
    char name[16];
    b->tc = tc;
    b->id = id;
    snprintf(name, sizeof name, "stp%x", id);
    b->stp = stp_create(name, id, send_bpdu, b);
    assert(tc->n_bridges < ARRAY_SIZE(tc->bridges));
    b->n_ports = 0;
    b->rxq_head = b->rxq_tail = 0;
    tc->bridges[tc->n_bridges++] = b;
    return b;
}

static struct lan *
new_lan(struct test_case *tc, const char *name)
{
    struct lan *lan = xmalloc(sizeof *lan);
    lan->tc = tc;
    lan->name = xstrdup(name);
    lan->n_conns = 0;
    assert(tc->n_lans < ARRAY_SIZE(tc->lans));
    tc->lans[tc->n_lans++] = lan;
    return lan;
}

static void
reconnect_port(struct bridge *b, int port_no, struct lan *new_lan)
{
    struct lan *old_lan;
    int j;

    assert(port_no < b->n_ports);
    old_lan = b->ports[port_no];
    if (old_lan == new_lan) {
        return;
    }

    /* Disconnect from old_lan. */
    if (old_lan) {
        for (j = 0; j < old_lan->n_conns; j++) {
            struct lan_conn *c = &old_lan->conns[j];
            if (c->bridge == b && c->port_no == port_no) {
                memmove(c, c + 1, sizeof *c * (old_lan->n_conns - j - 1));
                old_lan->n_conns--;
                break;
            }
        }
    }

    /* Connect to new_lan. */
    b->ports[port_no] = new_lan;
    if (new_lan) {
        int conn_no = new_lan->n_conns++;
        assert(conn_no < ARRAY_SIZE(new_lan->conns));
        new_lan->conns[conn_no].bridge = b;
        new_lan->conns[conn_no].port_no = port_no;
    }
}

static void
new_port(struct bridge *b, struct lan *lan, int path_cost)
{
    int port_no = b->n_ports++;
    struct stp_port *p = stp_get_port(b->stp, port_no);
    assert(port_no < ARRAY_SIZE(b->ports));
    b->ports[port_no] = NULL;
    stp_port_set_path_cost(p, path_cost);
    stp_port_enable(p);
    reconnect_port(b, port_no, lan);
}

static void
dump(struct test_case *tc)
{
    int i;

    for (i = 0; i < tc->n_bridges; i++) {
        struct bridge *b = tc->bridges[i];
        struct stp *stp = b->stp;
        int j;

        printf("%s:", stp_get_name(stp));
        if (stp_is_root_bridge(stp)) {
            printf(" root");
        }
        printf("\n");
        for (j = 0; j < b->n_ports; j++) {
            struct stp_port *p = stp_get_port(stp, j);
            enum stp_state state = stp_port_get_state(p);

            printf("\tport %d", j);
            if (b->ports[j]) {
                printf(" (lan %s)", b->ports[j]->name);
            } else {
                printf(" (disconnected)");
            }
            printf(": %s", stp_state_name(state));
            if (p == stp_get_root_port(stp)) {
                printf(" (root port, root_path_cost=%u)", stp_get_root_path_cost(stp));
            }
            printf("\n");
        }
    }
}

static void dump_lan_tree(struct test_case *, struct lan *, int level);

static void
dump_bridge_tree(struct test_case *tc, struct bridge *b, int level)
{
    int i;

    if (b->reached) {
        return;
    }
    b->reached = true;
    for (i = 0; i < level; i++) {
        printf("\t");
    }
    printf("%s\n", stp_get_name(b->stp));
    for (i = 0; i < b->n_ports; i++) {
        struct lan *lan = b->ports[i];
        struct stp_port *p = stp_get_port(b->stp, i);
        if (stp_port_get_state(p) == STP_FORWARDING && lan) {
            dump_lan_tree(tc, lan, level + 1);
        }
    }
}

static void
dump_lan_tree(struct test_case *tc, struct lan *lan, int level)
{
    int i;

    if (lan->reached) {
        return;
    }
    lan->reached = true;
    for (i = 0; i < level; i++) {
        printf("\t");
    }
    printf("%s\n", lan->name);
    for (i = 0; i < lan->n_conns; i++) {
        struct bridge *b = lan->conns[i].bridge;
        dump_bridge_tree(tc, b, level + 1);
    }
}

static void
tree(struct test_case *tc)
{
    int i;

    for (i = 0; i < tc->n_bridges; i++) {
        struct bridge *b = tc->bridges[i];
        b->reached = false;
    }
    for (i = 0; i < tc->n_lans; i++) {
        struct lan *lan = tc->lans[i];
        lan->reached = false;
    }
    for (i = 0; i < tc->n_bridges; i++) {
        struct bridge *b = tc->bridges[i];
        struct stp *stp = b->stp;
        if (stp_is_root_bridge(stp)) {
            dump_bridge_tree(tc, b, 0);
        }
    }
}

static void
simulate(struct test_case *tc, int granularity)
{
    int time;

    for (time = 0; time < 1000 * 180; time += granularity) {
        int round_trips;
        int i;

        for (i = 0; i < tc->n_bridges; i++) {
            stp_tick(tc->bridges[i]->stp, granularity);
        }
        for (round_trips = 0; round_trips < granularity; round_trips++) {
            bool any = false;
            for (i = 0; i < tc->n_bridges; i++) {
                struct bridge *b = tc->bridges[i];
                for (; b->rxq_tail != b->rxq_head; b->rxq_tail++) {
                    struct bpdu *bpdu = &b->rxq[b->rxq_tail % RXQ_SIZE];
                    stp_received_bpdu(stp_get_port(b->stp, bpdu->port_no),
                                      bpdu->data, bpdu->size);
                    free(bpdu->data);
                    any = true;
                }
            }
            if (!any) {
                break;
            }
        }
    }
}

OVS_NO_RETURN static void
err(const char *message, ...)
    OVS_PRINTF_FORMAT(1, 2);

static void
err(const char *message, ...)
{
    va_list args;

    fprintf(stderr, "%s:%d:%"PRIdPTR": ", file_name, line_number, pos - line);
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    putc('\n', stderr);

    exit(EXIT_FAILURE);
}

static void
warn(const char *message, ...)
    OVS_PRINTF_FORMAT(1, 2);

static void
warn(const char *message, ...)
{
    va_list args;

    fprintf(stderr, "%s:%d: ", file_name, line_number);
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    putc('\n', stderr);

    n_warnings++;
}

static bool
get_token(void)
{
    char *start;

    while (isspace((unsigned char) *pos)) {
        pos++;
    }
    if (*pos == '\0') {
        free(token);
        token = NULL;
        return false;
    }

    start = pos;
    if (isalpha((unsigned char) *pos)) {
        while (isalpha((unsigned char) *++pos)) {
            continue;
        }
    } else if (isdigit((unsigned char) *pos)) {
        if (*pos == '0' && (pos[1] == 'x' || pos[1] == 'X')) {
            pos += 2;
            while (isxdigit((unsigned char) *pos)) {
                pos++;
            }
        } else {
            while (isdigit((unsigned char) *++pos)) {
                continue;
            }
        }
    } else {
        pos++;
    }

    free(token);
    token = xmemdup0(start, pos - start);
    return true;
}

static bool
get_int(int *intp)
{
    char *save_pos = pos;
    if (token && isdigit((unsigned char) *token)) {
        *intp = strtol(token, NULL, 0);
        get_token();
        return true;
    } else {
        pos = save_pos;
        return false;
    }
}

static bool
match(const char *want)
{
    if (token && !strcmp(want, token)) {
        get_token();
        return true;
    } else {
        return false;
    }
}

static int
must_get_int(void)
{
    int x;
    if (!get_int(&x)) {
        err("expected integer");
    }
    return x;
}

static void
must_match(const char *want)
{
    if (!match(want)) {
        err("expected \"%s\"", want);
    }
}

static void
test_stp_main(int argc, char *argv[])
{
    struct test_case *tc;
    FILE *input_file;
    int i;

    vlog_set_pattern(VLF_CONSOLE, "%c|%p|%m");
    vlog_set_levels(NULL, VLF_SYSLOG, VLL_OFF);

    if (argc != 2) {
        ovs_fatal(0, "usage: test-stp INPUT.STP");
    }
    file_name = argv[1];

    input_file = fopen(file_name, "r");
    if (!input_file) {
        ovs_fatal(errno, "error opening \"%s\"", file_name);
    }

    tc = new_test_case();
    for (i = 0; i < 26; i++) {
        char name[2];
        name[0] = 'a' + i;
        name[1] = '\0';
        new_lan(tc, name);
    }

    for (line_number = 1; fgets(line, sizeof line, input_file);
         line_number++)
    {
        char *newline, *hash;

        newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }
        hash = strchr(line, '#');
        if (hash) {
            *hash = '\0';
        }

        pos = line;
        if (!get_token()) {
            continue;
        }
        if (match("bridge")) {
            struct bridge *bridge;
            int bridge_no, port_no;

            bridge_no = must_get_int();
            if (bridge_no < tc->n_bridges) {
                bridge = tc->bridges[bridge_no];
            } else if (bridge_no == tc->n_bridges) {
                bridge = new_bridge(tc, must_get_int());
            } else {
                err("bridges must be numbered consecutively from 0");
            }
            if (match("^")) {
                stp_set_bridge_priority(bridge->stp, must_get_int());
            }

            if (match("=")) {
                for (port_no = 0; port_no < STP_MAX_PORTS; port_no++) {
                    struct stp_port *p = stp_get_port(bridge->stp, port_no);
                    if (!token || match("X")) {
                        stp_port_disable(p);
                    } else if (match("_")) {
                        /* Nothing to do. */
                    } else {
                        struct lan *lan;
                        int path_cost;

                        if (!strcmp(token, "0")) {
                            lan = NULL;
                        } else if (strlen(token) == 1
                                && islower((unsigned char)*token)) {
                            lan = tc->lans[*token - 'a'];
                        } else {
                            err("%s is not a valid LAN name "
                                "(0 or a lowercase letter)", token);
                        }
                        get_token();

                        path_cost = match(":") ? must_get_int() : 10;
                        if (port_no < bridge->n_ports) {
                            stp_port_set_path_cost(p, path_cost);
                            stp_port_enable(p);
                            reconnect_port(bridge, port_no, lan);
                        } else if (port_no == bridge->n_ports) {
                            new_port(bridge, lan, path_cost);
                        } else {
                            err("ports must be numbered consecutively");
                        }
                        if (match("^")) {
                            stp_port_set_priority(p, must_get_int());
                        }
                    }
                }
            }
        } else if (match("run")) {
            simulate(tc, must_get_int());
        } else if (match("dump")) {
            dump(tc);
        } else if (match("tree")) {
            tree(tc);
        } else if (match("check")) {
            struct bridge *b;
            struct stp *stp;
            int bridge_no, port_no;

            bridge_no = must_get_int();
            if (bridge_no >= tc->n_bridges) {
                err("no bridge numbered %d", bridge_no);
            }
            b = tc->bridges[bridge_no];
            stp = b->stp;

            must_match("=");

            if (match("rootid")) {
                uint64_t rootid;
                must_match(":");
                rootid = must_get_int();
                if (match("^")) {
                    rootid |= (uint64_t) must_get_int() << 48;
                } else {
                    rootid |= UINT64_C(0x8000) << 48;
                }
                if (stp_get_designated_root(stp) != rootid) {
                    warn("%s: root %"PRIx64", not %"PRIx64,
                         stp_get_name(stp), stp_get_designated_root(stp),
                         rootid);
                }
            }

            if (match("root")) {
                if (stp_get_root_path_cost(stp)) {
                    warn("%s: root path cost of root is %u but should be 0",
                         stp_get_name(stp), stp_get_root_path_cost(stp));
                }
                if (!stp_is_root_bridge(stp)) {
                    warn("%s: root is %"PRIx64", not %"PRIx64,
                         stp_get_name(stp),
                         stp_get_designated_root(stp), stp_get_bridge_id(stp));
                }
                for (port_no = 0; port_no < b->n_ports; port_no++) {
                    struct stp_port *p = stp_get_port(stp, port_no);
                    enum stp_state state = stp_port_get_state(p);
                    if (!(state & (STP_DISABLED | STP_FORWARDING))) {
                        warn("%s: root port %d in state %s",
                             stp_get_name(b->stp), port_no,
                             stp_state_name(state));
                    }
                }
            } else {
                for (port_no = 0; port_no < STP_MAX_PORTS; port_no++) {
                    struct stp_port *p = stp_get_port(stp, port_no);
                    enum stp_state state;
                    if (token == NULL || match("D")) {
                        state = STP_DISABLED;
                    } else if (match("B")) {
                        state = STP_BLOCKING;
                    } else if (match("Li")) {
                        state = STP_LISTENING;
                    } else if (match("Le")) {
                        state = STP_LEARNING;
                    } else if (match("F")) {
                        state = STP_FORWARDING;
                    } else if (match("_")) {
                        continue;
                    } else {
                        err("unknown port state %s", token);
                    }
                    if (stp_port_get_state(p) != state) {
                        warn("%s port %d: state is %s but should be %s",
                             stp_get_name(stp), port_no,
                             stp_state_name(stp_port_get_state(p)),
                             stp_state_name(state));
                    }
                    if (state == STP_FORWARDING) {
                        struct stp_port *root_port = stp_get_root_port(stp);
                        if (match(":")) {
                            int root_path_cost = must_get_int();
                            if (p != root_port) {
                                warn("%s: port %d is not the root port",
                                     stp_get_name(stp), port_no);
                                if (!root_port) {
                                    warn("%s: (there is no root port)",
                                         stp_get_name(stp));
                                } else {
                                    warn("%s: (port %d is the root port)",
                                         stp_get_name(stp),
                                         stp_port_no(root_port));
                                }
                            } else if (root_path_cost
                                       != stp_get_root_path_cost(stp)) {
                                warn("%s: root path cost is %u, should be %d",
                                     stp_get_name(stp),
                                     stp_get_root_path_cost(stp),
                                     root_path_cost);
                            }
                        } else if (p == root_port) {
                            warn("%s: port %d is the root port but "
                                 "not expected to be",
                                 stp_get_name(stp), port_no);
                        }
                    }
                }
            }
            if (n_warnings) {
                exit(EXIT_FAILURE);
            }
        }
        if (get_token()) {
            err("trailing garbage on line");
        }
    }
    free(token);

    for (i = 0; i < tc->n_lans; i++) {
        struct lan *lan = tc->lans[i];
        free(CONST_CAST(char *, lan->name));
        free(lan);
    }
    for (i = 0; i < tc->n_bridges; i++) {
        struct bridge *bridge = tc->bridges[i];
        stp_unref(bridge->stp);
        free(bridge);
    }
    free(tc);
    fclose(input_file);
}

OVSTEST_REGISTER("test-stp", test_stp_main);
