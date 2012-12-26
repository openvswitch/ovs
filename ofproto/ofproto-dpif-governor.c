/*
 * Copyright (c) 2012 Nicira, Inc.
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

#include "ofproto-dpif-governor.h"

#include <assert.h>
#include <stdlib.h>

#include "coverage.h"
#include "poll-loop.h"
#include "random.h"
#include "timeval.h"
#include "util.h"
#include "valgrind.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_governor);

/* Minimum number of observed packets before setting up a flow.
 *
 * This value seems OK empirically. */
#define FLOW_SETUP_THRESHOLD 5
BUILD_ASSERT_DECL(FLOW_SETUP_THRESHOLD > 1);
BUILD_ASSERT_DECL(FLOW_SETUP_THRESHOLD < 16);

/* Minimum and maximum size of a governor, in bytes. */
enum { MIN_SIZE = 16 * 1024 };
enum { MAX_SIZE = 256 * 1024 };
BUILD_ASSERT_DECL(IS_POW2(MIN_SIZE));
BUILD_ASSERT_DECL(IS_POW2(MAX_SIZE));

/* Minimum and maximum time to process the number of packets that make up a
 * given generation.  If a generation completes faster than the minimum time,
 * we double the table size (but no more than MAX_SIZE).  If a generation take
 * more than the maximum time to complete, we halve the table size (but no
 * smaller than MIN_SIZE). */
enum { MIN_ELAPSED = 1000 }; /* In milliseconds. */
enum { MAX_ELAPSED = 5000 }; /* In milliseconds. */

static void governor_new_generation(struct governor *, unsigned int size);

/* Creates and returns a new governor named 'name' (which is used only for log
 * messages). */
struct governor *
governor_create(const char *name)
{
    struct governor *g = xzalloc(sizeof *g);
    g->name = xstrdup(name);
    governor_new_generation(g, MIN_SIZE);
    return g;
}

/* Destroys 'g'. */
void
governor_destroy(struct governor *g)
{
    if (g) {
        VLOG_INFO("%s: disengaging", g->name);
        free(g->name);
        free(g->table);
        free(g);
    }
}

/* Performs periodic maintenance work on 'g'. */
void
governor_run(struct governor *g)
{
    if (time_msec() - g->start > MAX_ELAPSED) {
        if (g->size > MIN_SIZE) {
            governor_new_generation(g, g->size / 2);
        } else {
            /* Don't start a new generation (we'd never go idle). */
        }
    }
}

/* Arranges for the poll loop to wake up when 'g' needs to do some work. */
void
governor_wait(struct governor *g)
{
    if (g->size > MIN_SIZE) {
        poll_timer_wait_until(g->start + MAX_ELAPSED);
    }
}

/* Returns true if 'g' has been doing only a minimal amount of work and thus
 * the client should consider getting rid of it entirely.  */
bool
governor_is_idle(struct governor *g)
{
    return g->size == MIN_SIZE && time_msec() - g->start > MAX_ELAPSED;
}

/* Tests whether a flow whose hash is 'hash' and for which 'n' packets have
 * just arrived should be set up in the datapath or just processed on a
 * packet-by-packet basis.  Returns true to set up a datapath flow, false to
 * process the packets individually.
 *
 * One would expect 'n' to ordinarily be 1, if batching leads multiple packets
 * to be processed at a time then it could be greater. */
bool
governor_should_install_flow(struct governor *g, uint32_t hash, int n)
{
    int old_count, new_count;
    bool install_flow;
    uint8_t *e;

    assert(n > 0);

    /* Count these packets and begin a new generation if necessary. */
    g->n_packets += n;
    if (g->n_packets >= g->size / 4) {
        unsigned int new_size;
        long long elapsed;

        elapsed = time_msec() - g->start;
        new_size = (elapsed < MIN_ELAPSED && g->size < MAX_SIZE ? g->size * 2
                    : elapsed > MAX_ELAPSED && g->size > MIN_SIZE ? g->size / 2
                    : g->size);
        governor_new_generation(g, new_size);
    }

    /* If we've set up most of the flows we've seen, then we're wasting time
     * handling most packets one at a time, so in this case instead set up most
     * flows directly and use the remaining flows as a sample set to adjust our
     * criteria later.
     *
     * The definition of "most" is conservative, but the sample size is tuned
     * based on a few experiments with TCP_CRR mode in netperf. */
    if (g->n_setups >= g->n_flows - g->n_flows / 16
        && g->n_flows >= 64
        && hash & 0x3f) {
        g->n_shortcuts++;
        return true;
    }

    /* Do hash table processing.
     *
     * Even-numbered hash values use high-order nibbles.
     * Odd-numbered hash values use low-order nibbles. */
    e = &g->table[(hash >> 1) & (g->size - 1)];
    old_count = (hash & 1 ? *e >> 4 : *e & 0x0f);
    if (!old_count) {
        g->n_flows++;
    }
    new_count = n + old_count;
    if (new_count >= FLOW_SETUP_THRESHOLD) {
        g->n_setups++;
        install_flow = true;
        new_count = 0;
    } else {
        install_flow = false;
    }
    *e = hash & 1 ? (new_count << 4) | (*e & 0x0f) : (*e & 0xf0) | new_count;

    return install_flow;
}

/* Starts a new generation in 'g' with a table size of 'size' bytes.  'size'
 * must be a power of two between MIN_SIZE and MAX_SIZE, inclusive. */
static void
governor_new_generation(struct governor *g, unsigned int size)
{
    assert(size >= MIN_SIZE && size <= MAX_SIZE);
    assert(is_pow2(size));

    /* Allocate new table, if necessary. */
    if (g->size != size) {
        if (!g->size) {
            VLOG_INFO("%s: engaging governor with %u kB hash table",
                      g->name, size / 1024);
        } else {
            VLOG_INFO("%s: processed %u packets in %.2f s, "
                      "%s hash table to %u kB "
                      "(%u hashes, %u setups, %u shortcuts)",
                      g->name, g->n_packets,
                      (time_msec() - g->start) / 1000.0,
                      size > g->size ? "enlarging" : "shrinking",
                      size / 1024,
                      g->n_flows, g->n_setups, g->n_shortcuts);
        }

        free(g->table);
        g->table = xmalloc(size * sizeof *g->table);
        g->size = size;
    } else {
        VLOG_DBG("%s: processed %u packets in %.2f s with %u kB hash table "
                 "(%u hashes, %u setups, %u shortcuts)",
                 g->name, g->n_packets, (time_msec() - g->start) / 1000.0,
                 size / 1024, g->n_flows, g->n_setups, g->n_shortcuts);
    }

    /* Clear data for next generation. */
    memset(g->table, 0, size * sizeof *g->table);
    g->start = time_msec();
    g->n_packets = 0;
    g->n_flows /= 2;
    g->n_setups /= 2;
    g->n_shortcuts = 0;
}
