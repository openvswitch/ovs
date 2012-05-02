/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "coverage.h"
#include <inttypes.h>
#include <stdlib.h>
#include "dynamic-string.h"
#include "hash.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(coverage);

/* The coverage counters. */
#if USE_LINKER_SECTIONS
extern struct coverage_counter *__start_coverage[];
extern struct coverage_counter *__stop_coverage[];
#define coverage_counters __start_coverage
#define n_coverage_counters  (__stop_coverage - __start_coverage)
#else  /* !USE_LINKER_SECTIONS */
#define COVERAGE_COUNTER(NAME) COVERAGE_DEFINE__(NAME);
#include "coverage.def"
#undef COVERAGE_COUNTER

struct coverage_counter *coverage_counters[] = {
#define COVERAGE_COUNTER(NAME) &counter_##NAME,
#include "coverage.def"
#undef COVERAGE_COUNTER
};
#define n_coverage_counters ARRAY_SIZE(coverage_counters)
#endif  /* !USE_LINKER_SECTIONS */

static unsigned int epoch;

static void coverage_read(struct svec *);

static void
coverage_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct svec lines;
    char *reply;

    svec_init(&lines);
    coverage_read(&lines);
    reply = svec_join(&lines, "\n", "\n");
    unixctl_command_reply(conn, reply);
    free(reply);
    svec_destroy(&lines);
}

void
coverage_init(void)
{
    unixctl_command_register("coverage/show", "", 0, 0,
                             coverage_unixctl_show, NULL);
}

/* Sorts coverage counters in descending order by count, within equal counts
 * alphabetically by name. */
static int
compare_coverage_counters(const void *a_, const void *b_)
{
    const struct coverage_counter *const *ap = a_;
    const struct coverage_counter *const *bp = b_;
    const struct coverage_counter *a = *ap;
    const struct coverage_counter *b = *bp;
    if (a->count != b->count) {
        return a->count < b->count ? 1 : -1;
    } else {
        return strcmp(a->name, b->name);
    }
}

static uint32_t
coverage_hash(void)
{
    struct coverage_counter **c;
    uint32_t hash = 0;
    int n_groups, i;

    /* Sort coverage counters into groups with equal counts. */
    c = xmalloc(n_coverage_counters * sizeof *c);
    for (i = 0; i < n_coverage_counters; i++) {
        c[i] = coverage_counters[i];
    }
    qsort(c, n_coverage_counters, sizeof *c, compare_coverage_counters);

    /* Hash the names in each group along with the rank. */
    n_groups = 0;
    for (i = 0; i < n_coverage_counters; ) {
        int j;

        if (!c[i]->count) {
            break;
        }
        n_groups++;
        hash = hash_int(i, hash);
        for (j = i; j < n_coverage_counters; j++) {
            if (c[j]->count != c[i]->count) {
                break;
            }
            hash = hash_string(c[j]->name, hash);
        }
        i = j;
    }

    free(c);

    return hash_int(n_groups, hash);
}

static bool
coverage_hit(uint32_t hash)
{
    enum { HIT_BITS = 1024, BITS_PER_WORD = 32 };
    static uint32_t hit[HIT_BITS / BITS_PER_WORD];
    BUILD_ASSERT_DECL(IS_POW2(HIT_BITS));

    static long long int next_clear = LLONG_MIN;

    unsigned int bit_index = hash & (HIT_BITS - 1);
    unsigned int word_index = bit_index / BITS_PER_WORD;
    unsigned int word_mask = 1u << (bit_index % BITS_PER_WORD);

    /* Expire coverage hash suppression once a day. */
    if (time_msec() >= next_clear) {
        memset(hit, 0, sizeof hit);
        next_clear = time_msec() + 60 * 60 * 24 * 1000LL;
    }

    if (hit[word_index] & word_mask) {
        return true;
    } else {
        hit[word_index] |= word_mask;
        return false;
    }
}

/* Logs the coverage counters, unless a similar set of events has already been
 * logged.
 *
 * This function logs at log level VLL_INFO.  Use care before adjusting this
 * level, because depending on its configuration, syslogd can write changes
 * synchronously, which can cause the coverage messages to take several seconds
 * to write. */
void
coverage_log(void)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 3);

    if (!VLOG_DROP_INFO(&rl)) {
        uint32_t hash = coverage_hash();
        if (coverage_hit(hash)) {
            VLOG_INFO("Skipping details of duplicate event coverage for "
                      "hash=%08"PRIx32" in epoch %u", hash, epoch);
        } else {
            struct svec lines;
            const char *line;
            size_t i;

            svec_init(&lines);
            coverage_read(&lines);
            SVEC_FOR_EACH (i, line, &lines) {
                VLOG_INFO("%s", line);
            }
            svec_destroy(&lines);
        }
    }
}

static void
coverage_read_counter(struct svec *lines, const struct coverage_counter *c)
{
    svec_add_nocopy(lines, xasprintf("%-24s %5u / %9llu",
                                     c->name, c->count, c->count + c->total));
}

/* Adds coverage counter information to 'lines'. */
static void
coverage_read(struct svec *lines)
{
    size_t n_never_hit;
    uint32_t hash;
    size_t i;

    hash = coverage_hash();

    n_never_hit = 0;
    svec_add_nocopy(lines, xasprintf("Event coverage (epoch %u/entire run), "
                                     "hash=%08"PRIx32":", epoch, hash));
    for (i = 0; i < n_coverage_counters; i++) {
        struct coverage_counter *c = coverage_counters[i];
        if (c->count) {
            coverage_read_counter(lines, c);
        }
    }
    for (i = 0; i < n_coverage_counters; i++) {
        struct coverage_counter *c = coverage_counters[i];
        if (!c->count) {
            if (c->total) {
                coverage_read_counter(lines, c);
            } else {
                n_never_hit++;
            }
        }
    }
    svec_add_nocopy(lines, xasprintf("%zu events never hit", n_never_hit));
}

/* Advances to the next epoch of coverage, resetting all the counters to 0. */
void
coverage_clear(void)
{
    size_t i;

    epoch++;
    for (i = 0; i < n_coverage_counters; i++) {
        struct coverage_counter *c = coverage_counters[i];
        c->total += c->count;
        c->count = 0;
    }
}
