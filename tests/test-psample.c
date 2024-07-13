/*
 * Copyright (c) 2024 Red Hat, Inc.
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
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/psample.h>

#include "command-line.h"
#include "dp-packet.h"
#include "util.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/types.h"
#include "openvswitch/uuid.h"
#include "openvswitch/vlog.h"
#include "ovstest.h"

VLOG_DEFINE_THIS_MODULE(test_psample);

static int psample_family = 0;
static uint32_t group_id = 0;
static bool has_filter;

static void usage(void)
{
    printf("%s: psample collector test utility\n"
           "usage: %s [OPTIONS] [GROUP]\n"
           "where GROUP is the psample group_id to listen on. "
           "If none is provided all events are printed.\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOther Options:\n"
           "  -h, --help               display this help message\n");
}

static void parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"group", required_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *tmp_short_options, *short_options;
    int ret = EXIT_SUCCESS;
    bool do_exit = false;

    tmp_short_options = ovs_cmdl_long_options_to_short_options(long_options);
    short_options = xasprintf("+%s", tmp_short_options);

    while (!do_exit) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }

        switch (option) {

        VLOG_OPTION_HANDLERS

        case 'h':
            usage();
            do_exit = true;
            ret = EXIT_SUCCESS;
            break;

        case '?':
            do_exit = true;
            ret = EXIT_FAILURE;
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    free(tmp_short_options);
    free(short_options);
    if (do_exit) {
        exit(ret);
    }
}

static int connect_psample_socket(struct nl_sock **sock)
{
    unsigned int psample_packet_mcgroup;
    int error;

    error = nl_lookup_genl_family(PSAMPLE_GENL_NAME , &psample_family);
    if (error) {
        VLOG_ERR("PSAMPLE_GENL_NAME not found: %s", ovs_strerror(error));
        return error;
    }

    error = nl_lookup_genl_mcgroup(PSAMPLE_GENL_NAME,
                                   PSAMPLE_NL_MCGRP_SAMPLE_NAME,
                                   &psample_packet_mcgroup);
    if (error) {
        VLOG_ERR("psample packet multicast group not found: %s",
                 ovs_strerror(error));
        return error;
    }

    error = nl_sock_create(NETLINK_GENERIC, sock);
    if (error) {
        VLOG_ERR("cannot create netlink socket: %s ", ovs_strerror(error));
        return error;
    }

    nl_sock_listen_all_nsid(*sock, true);

    error = nl_sock_join_mcgroup(*sock, psample_packet_mcgroup);
    if (error) {
        nl_sock_destroy(*sock);
        *sock = NULL;
        VLOG_ERR("cannot join psample multicast group: %s",
                 ovs_strerror(error));
        return error;
    }
    return 0;
}

/* Internal representation of a sample. */
struct sample {
    struct dp_packet packet;
    uint32_t group_id;
    uint32_t rate;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
    bool has_cookie;
};

static inline void
sample_clear(struct sample *sample)
{
    sample->group_id = 0;
    sample->obs_domain_id = 0;
    sample->obs_point_id = 0;
    sample->has_cookie = false;
    dp_packet_clear(&sample->packet);
}

static int
parse_psample(struct ofpbuf *buf, struct sample *sample)
{
    static const struct nl_policy psample_packet_policy[] = {
        [PSAMPLE_ATTR_SAMPLE_GROUP] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_SAMPLE_RATE] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_DATA] = { .type = NL_A_UNSPEC,
                                .optional = true },
        [PSAMPLE_ATTR_USER_COOKIE] = { .type = NL_A_UNSPEC,
                                       .optional = true },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct nlattr *attr;

    struct nlattr *a[ARRAY_SIZE(psample_packet_policy)];
    if (!nlmsg || !genl
        || !nl_policy_parse(&b, 0, psample_packet_policy, a,
                            ARRAY_SIZE(psample_packet_policy))) {
        return EINVAL;
    }

    attr = a[PSAMPLE_ATTR_DATA];
    if (attr) {
        dp_packet_push(&sample->packet, nl_attr_get(attr),
                       nl_attr_get_size(attr));
    }

    sample->group_id = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_GROUP]);
    sample->rate = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_RATE]);

    attr = a[PSAMPLE_ATTR_USER_COOKIE];
    if (attr && nl_attr_get_size(attr) ==
        sizeof sample->obs_domain_id + sizeof sample->obs_point_id) {
        const ovs_be32 *data = nl_attr_get(attr);

        sample->has_cookie = true;
        sample->obs_domain_id = ntohl(*data++);
        sample->obs_point_id = ntohl(*data);
    }
    return 0;
}

static void run(struct nl_sock *sock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct sample sample = {};
    int error;

    dp_packet_init(&sample.packet, 1500);

    fprintf(stdout, "Listening for psample events\n");
    fflush(stdout);

    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;

        sample_clear(&sample);

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(sock, &buf, NULL, true);

        if (error == ENOBUFS) {
            fprintf(stderr, "[missed events]\n");
            continue;
        } else if (error == EAGAIN) {
            continue;
        } else if (error) {
            VLOG_ERR_RL(&rl, "error reading samples: %i", error);
            continue;
        }

        error = parse_psample(&buf, &sample);
        if (error) {
            VLOG_ERR_RL(&rl, "error parsing samples: %i", error);
            continue;
        }

        if (!has_filter || sample.group_id == group_id) {
            fprintf(stdout, "group_id=0x%"PRIx32",prob=%"PRIu32" ",
                    sample.group_id, sample.rate);
            if (sample.has_cookie) {
                fprintf(stdout,
                        "obs_domain=0x%"PRIx32",obs_point=0x%"PRIx32" ",
                        sample.obs_domain_id, sample.obs_point_id);
            }
            ofp_print_dp_packet(stdout, &sample.packet);
        }
        fflush(stdout);
    }
}

static void
test_psample_main(int argc, char *argv[])
{
    struct nl_sock *sock;
    int error;

    parse_options(argc, argv);

    if (argc - optind > 1) {
        ovs_fatal(0, "at most one positional argument supported "
                  "(use --help for help)");
    } else if (argc - optind == 1) {
        if (!str_to_uint(argv[optind], 10, &group_id)) {
            ovs_fatal(0, "invalid group id");
        }
        has_filter = true;
    }

    error = connect_psample_socket(&sock);
    if (error) {
        ovs_fatal(error, "failed to connect to psample socket");
    }

    run(sock);
}

OVSTEST_REGISTER("test-psample", test_psample_main);
