/* Copyright (c) 2017 Red Hat, Inc.
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

#include "stopwatch.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "unixctl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "ovs-thread.h"
#include <unistd.h>
#include "socket-util.h"
#include "util.h"
#include "latch.h"
#include "guarded-list.h"

VLOG_DEFINE_THIS_MODULE(stopwatch);

struct average {
    double average; /* Moving average */
    double alpha;   /* Weight given to new samples */
};

#define MARKERS 5

/* Number of samples to collect before reporting P-square calculated
 * percentile
 */
#define P_SQUARE_MIN 50

/* The naming of these fields is based on the naming used in the
 * P-square algorithm paper.
 */
struct percentile {
    int n[MARKERS];
    double n_prime[MARKERS];
    double q[MARKERS];
    double dn[MARKERS];
    unsigned long long samples[P_SQUARE_MIN];
    double percentile;
};

struct stopwatch {
    enum stopwatch_units units;
    unsigned long long n_samples;
    unsigned long long max;
    unsigned long long min;
    struct percentile pctl;
    struct average short_term;
    struct average long_term;
    unsigned long long sample_start;
    bool sample_in_progress;
};

enum stopwatch_op {
    OP_START_SAMPLE,
    OP_END_SAMPLE,
    OP_SYNC,
    OP_RESET,
    OP_SHUTDOWN,
};

struct stopwatch_packet {
    struct ovs_list list_node;
    enum stopwatch_op op;
    char name[32];
    unsigned long long time;
};

static struct shash stopwatches = SHASH_INITIALIZER(&stopwatches);
static struct ovs_mutex stopwatches_lock = OVS_MUTEX_INITIALIZER;
static pthread_cond_t stopwatches_sync = PTHREAD_COND_INITIALIZER;

static struct latch stopwatch_latch;
static struct guarded_list stopwatch_commands;
static pthread_t stopwatch_thread_id;

static const char *unit_name[] = {
    [SW_MS] = "msec",
    [SW_US] = "usec",
    [SW_NS] = "nsec",
};

/* Percentile value we are calculating */
#define P 0.95

static int
comp_samples(const void *left, const void *right)
{
    const double *left_d = left;
    const double *right_d = right;

    return (int) *right_d - *left_d;
}

/* Calculate the percentile using the P-square algorithm. For more
 * information, see https://www1.cse.wustl.edu/~jain/papers/ftp/psqr.pdf
 */
static void
calc_percentile(unsigned long long n_samples, struct percentile *pctl,
                unsigned long long new_sample)
{

    if (n_samples < P_SQUARE_MIN) {
        pctl->samples[n_samples - 1] = new_sample;
    }

    /* For the first MARKERS samples, we calculate the percentile
     * in the traditional way in the pct->q array.
     */
    if (n_samples <= MARKERS) {
        pctl->q[n_samples - 1] = new_sample;
        qsort(pctl->q, n_samples, sizeof *pctl->q, comp_samples);
        if (n_samples == MARKERS) {
            pctl->n[0] = 0;
            pctl->n[1] = 1;
            pctl->n[2] = 2;
            pctl->n[3] = 3;
            pctl->n[4] = 4;

            pctl->n_prime[0] = 0;
            pctl->n_prime[1] = 2 * P;
            pctl->n_prime[2] = 4 * P;
            pctl->n_prime[3] = 2 + 2 * P;
            pctl->n_prime[4] = 4;

            pctl->dn[0] = 0;
            pctl->dn[1] = P / 2;
            pctl->dn[2] = P;
            pctl->dn[3] = (1 + P) / 2;
            pctl->dn[4] = 1;
        }
        pctl->percentile = pctl->q[(int) P * n_samples];
        return;
    }

    /* From here on, update the markers using quadratic spline calculations */
    int k;
    if (new_sample < pctl->q[0]) {
        k = 0;
        pctl->q[0] = new_sample;
    } else if (new_sample < pctl->q[1]) {
        k = 0;
    } else if (new_sample < pctl->q[2]) {
        k = 1;
    } else if (new_sample < pctl->q[3]) {
        k = 2;
    } else if (new_sample <= pctl->q[4]) {
        k = 3;
    } else {
        k = 3;
        pctl->q[4] = new_sample;
    }

    for (int i = k + 1; i < MARKERS; i++) {
        pctl->n[i]++;
    }

    for (int i = 0; i < MARKERS; i++) {
        pctl->n_prime[i] += pctl->dn[i];
    }

    for (int i = 1; i < MARKERS - 1; i++) {
        double d = pctl->n_prime[i] - pctl->n[i];

        if ((d >= 1 && pctl->n[i + 1] - pctl->n[i] > 1) ||
            (d <= -1 && pctl->n[i - 1] - pctl->n[i] < -1)) {
            d = d >= 0 ? 1 : -1;

            double a = d / (pctl->n[i + 1] - pctl->n[i - 1]);
            double b = (pctl->n[i] - pctl->n[i - 1] + d) *
                (pctl->q[i + 1] - pctl->q[i]) / (pctl->n[i + 1] - pctl->n[i]);
            double c = (pctl->n[i + 1] - pctl->n[i] - d) *
                (pctl->q[i] - pctl->q[i - 1]) / (pctl->n[i] - pctl->n[i - 1]);

            double candidate = pctl->q[i] + a * (b + c);
            if (pctl->q[i - 1] < candidate && candidate < pctl->q[i + 1]) {
                pctl->q[i] = candidate;
            } else {
                pctl->q[i] = pctl->q[i] +
                    (d * (pctl->q[i + (int)d] - pctl->q[i]) /
                    (pctl->n[i +(int)d] - pctl->n[i]));
            }

            pctl->n[i] += d;
        }
    }

    /* Without enough samples, P-square is not very accurate. Until we reach
     * P_SQUARE_MIN, use a traditional calculation for the percentile.
     */
    if (n_samples < P_SQUARE_MIN) {
        qsort(pctl->samples, n_samples, sizeof *pctl->samples, comp_samples);
        pctl->percentile = pctl->samples[(int) (P * n_samples)];
    } else {
        pctl->percentile = pctl->q[2];
    }
}

static void
calc_average(struct average *avg, double new_sample)
{
    avg->average = new_sample * avg->alpha + (1 - avg->alpha) * avg->average;
}

static void
add_sample(struct stopwatch *sw, unsigned long long new_sample)
{
    if (new_sample > sw->max) {
        sw->max = new_sample;
    }

    if (new_sample < sw->min || sw->n_samples == 0) {
        sw->min = new_sample;
    }

    calc_percentile(sw->n_samples, &sw->pctl, new_sample);

    if (sw->n_samples++ == 0) {
        sw->short_term.average = sw->long_term.average = new_sample;
        return;
    }

    calc_average(&sw->short_term, new_sample);
    calc_average(&sw->long_term, new_sample);
}

static bool
stopwatch_get_stats_protected(const char *name,
                              struct stopwatch_stats *stats)
{
    struct stopwatch *perf;

    perf = shash_find_data(&stopwatches, name);
    if (!perf) {
        return false;
    }

    stats->count = perf->n_samples;
    stats->unit = perf->units;
    stats->max = perf->max;
    stats->min = perf->min;
    stats->pctl_95 = perf->pctl.percentile;
    stats->ewma_50 = perf->short_term.average;
    stats->ewma_1 = perf->long_term.average;

    return true;
}

bool
stopwatch_get_stats(const char *name, struct stopwatch_stats *stats)
{
    bool found = false;

    ovs_mutex_lock(&stopwatches_lock);
    found = stopwatch_get_stats_protected(name, stats);
    ovs_mutex_unlock(&stopwatches_lock);

    return found;
}

static void
stopwatch_print(struct stopwatch *sw, const char *name,
                  struct ds *s)
{
    ds_put_format(s, "Statistics for '%s'\n", name);

    const char *units = unit_name[sw->units];
    ds_put_format(s, "  Total samples: %llu\n", sw->n_samples);
    ds_put_format(s, "  Maximum: %llu %s\n", sw->max, units);
    ds_put_format(s, "  Minimum: %llu %s\n", sw->min, units);
    ds_put_format(s, "  95th percentile: %f %s\n",
                  sw->pctl.percentile, units);
    ds_put_format(s, "  Short term average: %f %s\n",
                  sw->short_term.average, units);
    ds_put_format(s, "  Long term average: %f %s\n",
                  sw->long_term.average, units);
}

static bool
stopwatch_show_protected(int argc, const char *argv[], struct ds *s)
{
    struct stopwatch *sw;

    if (argc > 1) {
        sw = shash_find_data(&stopwatches, argv[1]);
        if (!sw) {
            ds_put_cstr(s, "No such stopwatch");
            return false;
        }
        stopwatch_print(sw, argv[1], s);
    } else {
        struct shash_node *node;
        SHASH_FOR_EACH (node, &stopwatches) {
            sw = node->data;
            stopwatch_print(sw, node->name, s);
        }
    }

    return true;
}

static void
stopwatch_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[], void *aux OVS_UNUSED)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    bool success;

    ovs_mutex_lock(&stopwatches_lock);
    success = stopwatch_show_protected(argc, argv, &s);
    ovs_mutex_unlock(&stopwatches_lock);

    if (success) {
        unixctl_command_reply(conn, ds_cstr(&s));
    } else {
        unixctl_command_reply_error(conn, ds_cstr(&s));
    }
    ds_destroy(&s);
}

static struct stopwatch_packet *
stopwatch_packet_create(enum stopwatch_op op)
{
    struct stopwatch_packet *pkt;

    pkt = xzalloc(sizeof *pkt);
    pkt->op = op;

    return pkt;
}

static void
stopwatch_packet_write(struct stopwatch_packet *pkt)
{
    guarded_list_push_back(&stopwatch_commands, &pkt->list_node, SIZE_MAX);
    latch_set(&stopwatch_latch);
}

static void
stopwatch_reset(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[], void *aux OVS_UNUSED)
{
    struct stopwatch_packet *pkt = stopwatch_packet_create(OP_RESET);
    if (argc > 1) {
        ovs_strlcpy(pkt->name, argv[1], sizeof pkt->name);
    }
    stopwatch_packet_write(pkt);
    unixctl_command_reply(conn, "");
}

static void
stopwatch_start_sample_protected(const struct stopwatch_packet *pkt)
{
    struct stopwatch *sw = shash_find_data(&stopwatches, pkt->name);
    if (!sw || sw->sample_in_progress) {
        return;
    }

    sw->sample_start = pkt->time;
    sw->sample_in_progress = true;
}

static void
stopwatch_end_sample_protected(const struct stopwatch_packet *pkt)
{
    struct stopwatch *sw = shash_find_data(&stopwatches, pkt->name);
    if (!sw || !sw->sample_in_progress) {
        return;
    }

    add_sample(sw, pkt->time - sw->sample_start);
    sw->sample_in_progress = false;
}

static void reset_stopwatch(struct stopwatch *sw)
{
    sw->short_term.average = 0;
    sw->long_term.average = 0;
    sw->pctl.percentile = 0;
    sw->n_samples = 0;
    sw->max = 0;
    sw->min = 0;
    /* Don't reset sw->sample_start or sw->sample_in_progress.
     * This way, if a sample was currently in progress, it can be
     * concluded properly after the reset.
     */
}

static void
stopwatch_reset_protected(const struct stopwatch_packet *pkt)
{
    if (pkt->name[0]) {
        struct stopwatch *sw = shash_find_data(&stopwatches, pkt->name);
        if (!sw) {
            return;
        }
        reset_stopwatch(sw);
        return;
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, &stopwatches) {
        struct stopwatch *sw = node->data;
        reset_stopwatch(sw);
    }
}

static void *
stopwatch_thread(void *ign OVS_UNUSED)
{
    bool should_exit = false;

    while (!should_exit) {
        struct ovs_list command_list;
        struct stopwatch_packet *pkt;

        latch_poll(&stopwatch_latch);
        guarded_list_pop_all(&stopwatch_commands, &command_list);
        ovs_mutex_lock(&stopwatches_lock);
        LIST_FOR_EACH_POP (pkt, list_node, &command_list) {
            switch (pkt->op) {
            case OP_START_SAMPLE:
                stopwatch_start_sample_protected(pkt);
                break;
            case OP_END_SAMPLE:
                stopwatch_end_sample_protected(pkt);
                break;
            case OP_SYNC:
                xpthread_cond_signal(&stopwatches_sync);
                break;
            case OP_RESET:
                stopwatch_reset_protected(pkt);
                break;
            case OP_SHUTDOWN:
                should_exit = true;
                break;
            }
        }
        ovs_mutex_unlock(&stopwatches_lock);

        if (!should_exit) {
            latch_wait(&stopwatch_latch);
            poll_block();
        }
    }

    return NULL;
}

static void
stopwatch_exit(void)
{
    struct shash_node *node, *node_next;
    struct stopwatch_packet *pkt = stopwatch_packet_create(OP_SHUTDOWN);
    stopwatch_packet_write(pkt);
    xpthread_join(stopwatch_thread_id, NULL);

    /* Process is exiting and we have joined the only
     * other competing thread. We are now the sole owners
     * of all data in the file.
     */
    SHASH_FOR_EACH_SAFE (node, node_next, &stopwatches) {
        struct stopwatch *sw = node->data;
        shash_delete(&stopwatches, node);
        free(sw);
    }
    shash_destroy(&stopwatches);
    ovs_mutex_destroy(&stopwatches_lock);
    guarded_list_destroy(&stopwatch_commands);
    latch_destroy(&stopwatch_latch);
}

static void
do_init_stopwatch(void)
{
    unixctl_command_register("stopwatch/show", "[NAME]", 0, 1,
                             stopwatch_show, NULL);
    unixctl_command_register("stopwatch/reset", "[NAME]", 0, 1,
                             stopwatch_reset, NULL);
    guarded_list_init(&stopwatch_commands);
    latch_init(&stopwatch_latch);
    stopwatch_thread_id = ovs_thread_create(
        "stopwatch", stopwatch_thread, NULL);
    atexit(stopwatch_exit);
}

static void
stopwatch_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        do_init_stopwatch();
        ovsthread_once_done(&once);
    }
}

void
stopwatch_create(const char *name, enum stopwatch_units units)
{
    stopwatch_init();

    struct stopwatch *sw = xzalloc(sizeof *sw);
    sw->units = units;
    sw->short_term.alpha = 0.50;
    sw->long_term.alpha = 0.01;

    ovs_mutex_lock(&stopwatches_lock);
    shash_add(&stopwatches, name, sw);
    ovs_mutex_unlock(&stopwatches_lock);
}

void
stopwatch_start(const char *name, unsigned long long ts)
{
    struct stopwatch_packet *pkt = stopwatch_packet_create(OP_START_SAMPLE);
    ovs_strlcpy(pkt->name, name, sizeof pkt->name);
    pkt->time = ts;
    stopwatch_packet_write(pkt);
}

void
stopwatch_stop(const char *name, unsigned long long ts)
{
    struct stopwatch_packet *pkt = stopwatch_packet_create(OP_END_SAMPLE);
    ovs_strlcpy(pkt->name, name, sizeof pkt->name);
    pkt->time = ts;
    stopwatch_packet_write(pkt);
}

void
stopwatch_sync(void)
{
    struct stopwatch_packet *pkt = stopwatch_packet_create(OP_SYNC);
    ovs_mutex_lock(&stopwatches_lock);
    stopwatch_packet_write(pkt);
    ovs_mutex_cond_wait(&stopwatches_sync, &stopwatches_lock);
    ovs_mutex_unlock(&stopwatches_lock);
}
