/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
static struct coverage_counter **coverage_counters = NULL;
static size_t n_coverage_counters = 0;
static size_t allocated_coverage_counters = 0;

static struct ovs_mutex coverage_mutex = OVS_MUTEX_INITIALIZER;

DEFINE_STATIC_PER_THREAD_DATA(long long int, coverage_clear_time, LLONG_MIN);
static long long int coverage_run_time = LLONG_MIN;

/* Index counter used to compute the moving average array's index. */
static unsigned int idx_count = 0;

static void coverage_read(struct svec *);
static unsigned int coverage_array_sum(const unsigned int *arr,
                                       const unsigned int len);

/* Registers a coverage counter with the coverage core */
void
coverage_counter_register(struct coverage_counter* counter)
{
    if (n_coverage_counters >= allocated_coverage_counters) {
        coverage_counters = x2nrealloc(coverage_counters,
                                       &allocated_coverage_counters,
                                       sizeof(struct coverage_counter*));
    }
    coverage_counters[n_coverage_counters++] = counter;
}

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

/* Sorts coverage counters in descending order by total, within equal
 * totals alphabetically by name. */
static int
compare_coverage_counters(const void *a_, const void *b_)
{
    const struct coverage_counter *const *ap = a_;
    const struct coverage_counter *const *bp = b_;
    const struct coverage_counter *a = *ap;
    const struct coverage_counter *b = *bp;
    if (a->total != b->total) {
        return a->total < b->total ? 1 : -1;
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

    /* Sort coverage counters into groups with equal totals. */
    c = xmalloc(n_coverage_counters * sizeof *c);
    ovs_mutex_lock(&coverage_mutex);
    for (i = 0; i < n_coverage_counters; i++) {
        c[i] = coverage_counters[i];
    }
    ovs_mutex_unlock(&coverage_mutex);
    qsort(c, n_coverage_counters, sizeof *c, compare_coverage_counters);

    /* Hash the names in each group along with the rank. */
    n_groups = 0;
    for (i = 0; i < n_coverage_counters; ) {
        int j;

        if (!c[i]->total) {
            break;
        }
        n_groups++;
        hash = hash_int(i, hash);
        for (j = i; j < n_coverage_counters; j++) {
            if (c[j]->total != c[i]->total) {
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
                      "hash=%08"PRIx32, hash);
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

/* Adds coverage counter information to 'lines'. */
static void
coverage_read(struct svec *lines)
{
    struct coverage_counter **c = coverage_counters;
    unsigned long long int *totals;
    size_t n_never_hit;
    uint32_t hash;
    size_t i;

    hash = coverage_hash();

    n_never_hit = 0;
    svec_add_nocopy(lines,
                    xasprintf("Event coverage, avg rate over last: %d "
                              "seconds, last minute, last hour,  "
                              "hash=%08"PRIx32":",
                              COVERAGE_RUN_INTERVAL/1000, hash));

    totals = xmalloc(n_coverage_counters * sizeof *totals);
    ovs_mutex_lock(&coverage_mutex);
    for (i = 0; i < n_coverage_counters; i++) {
        totals[i] = c[i]->total;
    }
    ovs_mutex_unlock(&coverage_mutex);

    for (i = 0; i < n_coverage_counters; i++) {
        if (totals[i]) {
            /* Shows the averaged per-second rates for the last
             * COVERAGE_RUN_INTERVAL interval, the last minute and
             * the last hour. */
            svec_add_nocopy(lines,
                xasprintf("%-24s %5.1f/sec %9.3f/sec "
                          "%13.4f/sec   total: %llu",
                          c[i]->name,
                          (c[i]->min[(idx_count - 1) % MIN_AVG_LEN]
                           * 1000.0 / COVERAGE_RUN_INTERVAL),
                          coverage_array_sum(c[i]->min, MIN_AVG_LEN) / 60.0,
                          coverage_array_sum(c[i]->hr,  HR_AVG_LEN) / 3600.0,
                          totals[i]));
        } else {
            n_never_hit++;
        }
    }

    svec_add_nocopy(lines, xasprintf("%"PRIuSIZE" events never hit", n_never_hit));
    free(totals);
}

/* Runs approximately every COVERAGE_CLEAR_INTERVAL amount of time to
 * synchronize per-thread counters with global counters. Every thread maintains
 * a separate timer to ensure all counters are periodically aggregated. */
void
coverage_clear(void)
{
    long long int now, *thread_time;

    now = time_msec();
    thread_time = coverage_clear_time_get();

    /* Initialize the coverage_clear_time. */
    if (*thread_time == LLONG_MIN) {
        *thread_time = now + COVERAGE_CLEAR_INTERVAL;
    }

    if (now >= *thread_time) {
        size_t i;

        ovs_mutex_lock(&coverage_mutex);
        for (i = 0; i < n_coverage_counters; i++) {
            struct coverage_counter *c = coverage_counters[i];
            c->total += c->count();
        }
        ovs_mutex_unlock(&coverage_mutex);
        *thread_time = now + COVERAGE_CLEAR_INTERVAL;
    }
}

/* Runs approximately every COVERAGE_RUN_INTERVAL amount of time to update the
 * coverage counters' 'min' and 'hr' array.  'min' array is for cumulating
 * per second counts into per minute count.  'hr' array is for cumulating per
 * minute counts into per hour count.  Every thread may call this function. */
void
coverage_run(void)
{
    /* Defines the moving average array index variables. */
    static unsigned int min_idx, hr_idx;
    struct coverage_counter **c = coverage_counters;
    long long int now;

    ovs_mutex_lock(&coverage_mutex);
    now = time_msec();
    /* Initialize the coverage_run_time. */
    if (coverage_run_time == LLONG_MIN) {
        coverage_run_time = now + COVERAGE_RUN_INTERVAL;
    }

    if (now >= coverage_run_time) {
        size_t i, j;
        /* Computes the number of COVERAGE_RUN_INTERVAL slots, since
         * it is possible that the actual run interval is multiple of
         * COVERAGE_RUN_INTERVAL. */
        int slots = (now - coverage_run_time) / COVERAGE_RUN_INTERVAL + 1;

        for (i = 0; i < n_coverage_counters; i++) {
            unsigned int count, portion;
            unsigned int m_idx = min_idx;
            unsigned int h_idx = hr_idx;
            unsigned int idx = idx_count;

            /* Computes the differences between the current total and the one
             * recorded in last invocation of coverage_run(). */
            count = c[i]->total - c[i]->last_total;
            c[i]->last_total = c[i]->total;
            /* The count over the time interval is evenly distributed
             * among slots by calculating the portion. */
            portion = count / slots;

            for (j = 0; j < slots; j++) {
                /* Updates the index variables. */
                /* The m_idx is increased from 0 to MIN_AVG_LEN - 1. Every
                 * time the m_idx finishes a cycle (a cycle is one minute),
                 * the h_idx is incremented by 1. */
                m_idx = idx % MIN_AVG_LEN;
                h_idx = idx / MIN_AVG_LEN;

                c[i]->min[m_idx] = portion + (j == (slots - 1)
                                              ? count % slots : 0);
                c[i]->hr[h_idx] = m_idx == 0
                                  ? c[i]->min[m_idx]
                                  : (c[i]->hr[h_idx] + c[i]->min[m_idx]);
                /* This is to guarantee that h_idx ranges from 0 to 59. */
                idx = (idx + 1) % (MIN_AVG_LEN * HR_AVG_LEN);
            }
        }

        /* Updates the global index variables. */
        idx_count = (idx_count + slots) % (MIN_AVG_LEN * HR_AVG_LEN);
        min_idx = idx_count % MIN_AVG_LEN;
        hr_idx  = idx_count / MIN_AVG_LEN;
        /* Updates the run time. */
        coverage_run_time = now + COVERAGE_RUN_INTERVAL;
    }
    ovs_mutex_unlock(&coverage_mutex);
}

static unsigned int
coverage_array_sum(const unsigned int *arr, const unsigned int len)
{
    unsigned int sum = 0;
    size_t i;

    ovs_mutex_lock(&coverage_mutex);
    for (i = 0; i < len; i++) {
        sum += arr[i];
    }
    ovs_mutex_unlock(&coverage_mutex);
    return sum;
}
