/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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
#include "memory.h"
#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(memory);

/* The number of milliseconds before the first report of daemon memory usage,
 * and the number of milliseconds between checks for daemon memory growth.  */
#define MEMORY_CHECK_INTERVAL (10 * 1000)

/* When we should next check memory usage and possibly trigger a report. */
static long long int next_check;

/* The last time at which we reported memory usage, and the usage we reported
 * at that time. */
static long long int last_report;
static unsigned long int last_reported_maxrss;

/* Are we expecting a call to memory_report()? */
static bool want_report;

/* Unixctl connections waiting for responses. */
static struct unixctl_conn **conns;
static size_t n_conns;

static void memory_init(void);

/* Runs the memory monitor.
 *
 * The client should call memory_should_report() afterward.
 *
 * This function, and the remainder of this module's interface, should be
 * called from only a single thread. */
void
memory_run(void)
{
    struct rusage usage;
    long long int now;

    memory_init();

    /* Time for a check? */
    now = time_msec();
    if (now < next_check) {
        return;
    }
    next_check = now + MEMORY_CHECK_INTERVAL;

    /* Time for a report? */
    getrusage(RUSAGE_SELF, &usage);
    if (!last_reported_maxrss) {
        VLOG_INFO("%lu kB peak resident set size after %.1f seconds",
                  (unsigned long int) usage.ru_maxrss,
                  (now - time_boot_msec()) / 1000.0);
    } else if (usage.ru_maxrss >= last_reported_maxrss * 1.5) {
        VLOG_INFO("peak resident set size grew %.0f%% in last %.1f seconds, "
                  "from %lu kB to %lu kB",
                  ((double) usage.ru_maxrss / last_reported_maxrss - 1) * 100,
                  (now - last_report) / 1000.0,
                  last_reported_maxrss, (unsigned long int) usage.ru_maxrss);
    } else {
        return;
    }

    /* Request a report. */
    want_report = true;
    last_report = now;
    last_reported_maxrss = usage.ru_maxrss;
}

/* Causes the poll loop to wake up if the memory monitor needs to run. */
void
memory_wait(void)
{
    if (memory_should_report()) {
        poll_immediate_wake();
    }
}

/* Returns true if the caller should log some information about memory usage
 * (with memory_report()), false otherwise. */
bool
memory_should_report(void)
{
    return want_report || n_conns > 0;
}

static void
compose_report(const struct simap *usage, struct ds *s)
{
    const struct simap_node **nodes = simap_sort(usage);
    size_t n = simap_count(usage);
    size_t i;

    for (i = 0; i < n; i++) {
        const struct simap_node *node = nodes[i];

        ds_put_format(s, "%s:%u ", node->name, node->data);
    }
    ds_chomp(s, ' ');
    free(nodes);
}

/* Logs the contents of 'usage', as a collection of name-count pairs.
 *
 * 'usage' should capture large-scale statistics that one might reasonably
 * expect to correlate with memory usage.  For example, each OpenFlow flow
 * requires some memory, so ovs-vswitchd includes the total number of flows in
 * 'usage'. */
void
memory_report(const struct simap *usage)
{
    struct ds s;
    size_t i;

    ds_init(&s);
    compose_report(usage, &s);

    if (want_report) {
        if (s.length) {
            VLOG_INFO("%s", ds_cstr(&s));
        }
        want_report = false;
    }
    if (n_conns) {
        for (i = 0; i < n_conns; i++) {
            unixctl_command_reply(conns[i], ds_cstr(&s));
        }
        free(conns);
        conns = NULL;
        n_conns = 0;
    }

    ds_destroy(&s);
}

static void
memory_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    conns = xrealloc(conns, (n_conns + 1) * sizeof *conns);
    conns[n_conns++] = conn;
}

static void
memory_init(void)
{
    static bool inited = false;

    if (!inited) {
        inited = true;
        unixctl_command_register("memory/show", "", 0, 0,
                                 memory_unixctl_show, NULL);

        next_check = time_boot_msec() + MEMORY_CHECK_INTERVAL;
    }
}
