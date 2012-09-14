/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "command-line.h"
#include "daemon.h"
#include "dynamic-string.h"
#include "netflow.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

static unixctl_cb_func test_netflow_exit;

static void
print_netflow(struct ofpbuf *buf)
{
    const struct netflow_v5_header *hdr;
    int i;

    hdr = ofpbuf_try_pull(buf, sizeof *hdr);
    if (!hdr) {
        printf("truncated NetFlow packet header\n");
        return;
    }
    printf("header: v%"PRIu16", "
           "uptime %"PRIu32", "
           "now %"PRIu32".%09"PRIu32", "
           "seq %"PRIu32", "
           "engine %"PRIu8",%"PRIu8,
           ntohs(hdr->version),
           ntohl(hdr->sysuptime),
           ntohl(hdr->unix_secs), ntohl(hdr->unix_nsecs),
           ntohl(hdr->flow_seq),
           hdr->engine_type, hdr->engine_id);
    if (hdr->sampling_interval != htons(0)) {
        printf(", interval %"PRIu16, ntohs(hdr->sampling_interval));
    }
    putchar('\n');

    for (i = 0; i < ntohs(hdr->count); i++) {
        struct netflow_v5_record *rec;

        rec = ofpbuf_try_pull(buf, sizeof *rec);
        if (!rec) {
            printf("truncated NetFlow records\n");
            return;
        }

        printf("seq %"PRIu32": "IP_FMT" > "IP_FMT, ntohl(hdr->flow_seq),
               IP_ARGS(&rec->src_addr), IP_ARGS(&rec->dst_addr));

        printf(", if %"PRIu16" > %"PRIu16,
               ntohs(rec->input), ntohs(rec->output));

        printf(", %"PRIu32" pkts, %"PRIu32" bytes",
               ntohl(rec->packet_count), ntohl(rec->byte_count));

        switch (rec->ip_proto) {
        case IPPROTO_TCP:
            printf(", TCP %"PRIu16" > %"PRIu16,
                   ntohs(rec->src_port), ntohs(rec->dst_port));
            if (rec->tcp_flags) {
                struct ds s = DS_EMPTY_INITIALIZER;
                packet_format_tcp_flags(&s, rec->tcp_flags);
                printf(" %s", ds_cstr(&s));
                ds_destroy(&s);
            }
            break;

        case IPPROTO_UDP:
            printf(", UDP %"PRIu16" > %"PRIu16,
                   ntohs(rec->src_port), ntohs(rec->dst_port));
            break;

        case IPPROTO_ICMP:
            printf(", ICMP %"PRIu16":%"PRIu16,
                   ntohs(rec->dst_port) >> 8,
                   ntohs(rec->dst_port) & 0xff);
            if (rec->src_port != htons(0)) {
                printf(", src_port=%"PRIu16, ntohs(rec->src_port));
            }
            break;

        default:
            printf(", proto %"PRIu8, rec->ip_proto);
            break;
        }

        if (rec->ip_proto != IPPROTO_TCP && rec->tcp_flags != 0) {
            printf(", flags %"PRIx8, rec->tcp_flags);
        }

        if (rec->ip_proto != IPPROTO_TCP &&
            rec->ip_proto != IPPROTO_UDP &&
            rec->ip_proto != IPPROTO_ICMP) {
            if (rec->src_port != htons(0)) {
                printf(", src_port %"PRIu16, ntohs(rec->src_port));
            }
            if (rec->dst_port != htons(0)) {
                printf(", dst_port %"PRIu16, ntohs(rec->dst_port));
            }
        }

        if (rec->ip_tos) {
            printf(", TOS %"PRIx8, rec->ip_tos);
        }

        printf(", time %"PRIu32"...%"PRIu32,
               ntohl(rec->init_time), ntohl(rec->used_time));

        if (rec->nexthop != htonl(0)) {
            printf(", nexthop "IP_FMT, IP_ARGS(&rec->nexthop));
        }
        if (rec->src_as != htons(0) || rec->dst_as != htons(0)) {
            printf(", AS %"PRIu16" > %"PRIu16,
                   ntohs(rec->src_as), ntohs(rec->dst_as));
        }
        if (rec->src_mask != 0 || rec->dst_mask != 0) {
            printf(", mask %"PRIu8" > %"PRIu8, rec->src_mask, rec->dst_mask);
        }
        if (rec->pad1) {
            printf(", pad1 %"PRIu8, rec->pad1);
        }
        if (rec->pad[0] || rec->pad[1]) {
            printf(", pad %"PRIu8", %"PRIu8, rec->pad[0], rec->pad[1]);
        }
        putchar('\n');
    }

    if (buf->size) {
        printf("%zu extra bytes after last record\n", buf->size);
    }
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *server;
    enum { MAX_RECV = 1500 };
    const char *target;
    struct ofpbuf buf;
    bool exiting = false;
    int error;
    int sock;
    int n;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv);

    if (argc - optind != 1) {
        ovs_fatal(0, "exactly one non-option argument required "
                  "(use --help for help)");
    }
    target = argv[optind];

    sock = inet_open_passive(SOCK_DGRAM, target, 0, NULL, 0);
    if (sock < 0) {
        ovs_fatal(0, "%s: failed to open (%s)", argv[1], strerror(-sock));
    }

    daemon_save_fd(STDOUT_FILENO);
    daemonize_start();

    error = unixctl_server_create(NULL, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }
    unixctl_command_register("exit", "", 0, 0, test_netflow_exit, &exiting);

    daemonize_complete();

    ofpbuf_init(&buf, MAX_RECV);
    n = 0;
    for (;;) {
        int retval;

        unixctl_server_run(server);

        ofpbuf_clear(&buf);
        do {
            retval = read(sock, buf.data, buf.allocated);
        } while (retval < 0 && errno == EINTR);
        if (retval > 0) {
            ofpbuf_put_uninit(&buf, retval);
            if (n++ > 0) {
                putchar('\n');
            }
            print_netflow(&buf);
            fflush(stdout);
        }

        if (exiting) {
            break;
        }

        poll_fd_wait(sock, POLLIN);
        unixctl_server_wait(server);
        poll_block();
    }

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        DAEMON_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'v':
            vlog_set_verbosity(optarg);
            break;

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
    printf("%s: netflow collector test utility\n"
           "usage: %s [OPTIONS] PORT[:IP]\n"
           "where PORT is the UDP port to listen on and IP is optionally\n"
           "the IP address to listen on.\n",
           program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static void
test_netflow_exit(struct unixctl_conn *conn,
                  int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}
