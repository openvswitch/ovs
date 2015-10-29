/*
 * Copyright (c) 2015 Nicira, Inc.
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

#include <linux/netfilter/nfnetlink.h>

#include "ct-dpif.h"
#include "netlink-conntrack.h"
#include "netlink-notifier.h"
#include "ovstest.h"
#include "poll-loop.h"

/* Monitor command */
struct test_change {
    enum nl_ct_event_type type;
    struct ct_dpif_entry entry;
};

static bool
event_parse(struct ofpbuf *buf, void *change_)
{
    struct test_change *change = change_;

    return nl_ct_parse_entry(buf, &change->entry, &change->type);
}

static void
event_print(const void *change_, void *aux OVS_UNUSED)
{
    const struct test_change *change = change_;

    if (change) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        nl_ct_format_event_entry(&change->entry, change->type, &ds, true,
                                 true);
        printf("%s\n", ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

static void
test_nl_ct_monitor(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int groups [] = {
        NFNLGRP_CONNTRACK_DESTROY,
        NFNLGRP_CONNTRACK_NEW,
        NFNLGRP_CONNTRACK_UPDATE,
    };

    struct nln *nlns[ARRAY_SIZE(groups)];
    struct nln_notifier *notifiers[ARRAY_SIZE(groups)];

    struct test_change change;

    unsigned i;

    for (i = 0; i < ARRAY_SIZE(groups); i++) {
        nlns[i] = nln_create(NETLINK_NETFILTER, groups[i], event_parse,
                             &change);

        notifiers[i] = nln_notifier_create(nlns[i], event_print, NULL);
    }

    for (;;) {
        for (i = 0; i < ARRAY_SIZE(groups); i++) {
            nln_run(nlns[i]);
            nln_wait(nlns[i]);
        }
        poll_block();
    }

    for (i = 0; i < ARRAY_SIZE(groups); i++) {
        nln_notifier_destroy(notifiers[i]);
        nln_destroy(nlns[i]);
    }
}

/* Dump command */
static void
test_nl_ct_dump(struct ovs_cmdl_context *ctx)
{
    struct nl_ct_dump_state *dump;
    uint16_t zone, *pzone = NULL;
    struct ct_dpif_entry entry;
    int err;

    if (ctx->argc >= 2) {
        if (!ovs_scan(ctx->argv[1], "zone=%"SCNu16, &zone)) {
            ovs_fatal(0, "Error parsing zone= specifier");
        }
        pzone = &zone;
    }
    err = nl_ct_dump_start(&dump, pzone);
    if (err) {
        ovs_fatal(err, "Error creating conntrack netlink dump");
    }

    do {
        err = nl_ct_dump_next(dump, &entry);
        if (!err) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            ct_dpif_format_entry(&entry, &ds, true, true);
            printf("%s\n", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    } while (!err);

    if (err != EOF) {
        ovs_fatal(err, "Error dumping conntrack netlink entry");
    }
    nl_ct_dump_done(dump);
}

/* Flush command */
static void
test_nl_ct_flush(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int err;

    if (ctx->argc >= 2) {
        uint16_t zone;

        if (ovs_scan(ctx->argv[1], "zone=%"SCNu16, &zone)) {
            err = nl_ct_flush_zone(zone);
        } else {
            ovs_fatal(0, "Error parsing zone= specifier");
        }
    } else {
        err = nl_ct_flush();
    }
    if (err) {
        ovs_fatal(err, "Error flushing conntrack netlink");
    }
}

static const struct ovs_cmdl_command commands[] = {
    /* Linux netlink connection tracker interface test. */

    /* Prints all the entries in the connection table and exits. */
    {"dump", "[zone=zone]", 0, 1, test_nl_ct_dump},
    /* Listens to all the connection tracking events and prints them to
     * standard output until killed. */
    {"monitor", "", 0, 0, test_nl_ct_monitor},
    /* Flushes all the entries from all the tables.. */
    {"flush", "[zone=zone]", 0, 1, test_nl_ct_flush},

    {NULL, NULL, 0, 0, NULL},
};

static void
test_netlink_conntrack(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-netlink-conntrack", test_netlink_conntrack);
