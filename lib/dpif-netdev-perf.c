/*
 * Copyright (c) 2017 Ericsson AB.
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
#include <stdint.h>

#include "dpdk.h"
#include "dpif-netdev-perf.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-thread.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(pmd_perf);

#define ITER_US_THRESHOLD 250   /* Warning threshold for iteration duration
                                   in microseconds. */
#define VHOST_QUEUE_FULL 128    /* Size of the virtio TX queue. */
#define LOG_IT_BEFORE 5         /* Number of iterations to log before
                                   suspicious iteration. */
#define LOG_IT_AFTER 5          /* Number of iterations to log after
                                   suspicious iteration. */

bool log_enabled = false;
bool log_extend = false;
static uint32_t log_it_before = LOG_IT_BEFORE;
static uint32_t log_it_after = LOG_IT_AFTER;
static uint32_t log_us_thr = ITER_US_THRESHOLD;
uint32_t log_q_thr = VHOST_QUEUE_FULL;
uint64_t iter_cycle_threshold;

static struct vlog_rate_limit latency_rl = VLOG_RATE_LIMIT_INIT(600, 600);

static uint64_t tsc_hz = 1;

void
pmd_perf_estimate_tsc_frequency(void)
{
#ifdef DPDK_NETDEV
    if (dpdk_available()) {
        tsc_hz = rte_get_tsc_hz();
    }
    if (tsc_hz > 1) {
        VLOG_INFO("DPDK provided TSC frequency: %"PRIu64" KHz", tsc_hz / 1000);
        return;
    }
#endif
    struct ovs_numa_dump *affinity;
    struct pmd_perf_stats s;
    uint64_t start, stop;

    /* DPDK is not available or returned unreliable value.
     * Trying to estimate. */
    affinity = ovs_numa_thread_getaffinity_dump();
    if (affinity) {
        const struct ovs_numa_info_core *core;

        FOR_EACH_CORE_ON_DUMP (core, affinity) {
            /* Setting affinity to a single core from the affinity mask to
             * avoid re-scheduling to another core while sleeping. */
            ovs_numa_thread_setaffinity_core(core->core_id);
            break;
        }
    }

    memset(&s, 0, sizeof s);
    start = cycles_counter_update(&s);
    /* Using xnanosleep as it's interrupt resistant.
     * Sleeping only 100 ms to avoid holding the main thread for too long. */
    xnanosleep(1E8);
    stop = cycles_counter_update(&s);

    if (affinity) {
        /* Restoring previous affinity. */
        ovs_numa_thread_setaffinity_dump(affinity);
        ovs_numa_dump_destroy(affinity);
    }

    if (stop <= start) {
        VLOG_WARN("TSC source is unreliable.");
        tsc_hz = 1;
    } else {
        tsc_hz = (stop - start) * 10;
    }

    VLOG_INFO("Estimated TSC frequency: %"PRIu64" KHz", tsc_hz / 1000);
}

/* Histogram functions. */

static void
histogram_walls_set_lin(struct histogram *hist, uint32_t min, uint32_t max)
{
    int i;

    ovs_assert(min < max);
    for (i = 0; i < NUM_BINS-1; i++) {
        hist->wall[i] = min + (i * (max - min)) / (NUM_BINS - 2);
    }
    hist->wall[NUM_BINS-1] = UINT32_MAX;
}

static void
histogram_walls_set_log(struct histogram *hist, uint32_t min, uint32_t max)
{
    int i, start, bins, wall;
    double log_min, log_max;

    ovs_assert(min < max);
    if (min > 0) {
        log_min = log(min);
        log_max = log(max);
        start = 0;
        bins = NUM_BINS - 1;
    } else {
        hist->wall[0] = 0;
        log_min = log(1);
        log_max = log(max);
        start = 1;
        bins = NUM_BINS - 2;
    }
    wall = start;
    for (i = 0; i < bins; i++) {
        /* Make sure each wall is monotonically increasing. */
        wall = MAX(wall, exp(log_min + (i * (log_max - log_min)) / (bins-1)));
        hist->wall[start + i] = wall++;
    }
    if (hist->wall[NUM_BINS-2] < max) {
        hist->wall[NUM_BINS-2] = max;
    }
    hist->wall[NUM_BINS-1] = UINT32_MAX;
}

uint64_t
histogram_samples(const struct histogram *hist)
{
    uint64_t samples = 0;

    for (int i = 0; i < NUM_BINS; i++) {
        samples += hist->bin[i];
    }
    return samples;
}

static void
histogram_clear(struct histogram *hist)
{
    int i;

    for (i = 0; i < NUM_BINS; i++) {
        hist->bin[i] = 0;
    }
}

static void
history_init(struct history *h)
{
    memset(h, 0, sizeof(*h));
}

void
pmd_perf_stats_init(struct pmd_perf_stats *s)
{
    memset(s, 0, sizeof(*s));
    ovs_mutex_init(&s->stats_mutex);
    ovs_mutex_init(&s->clear_mutex);
    /* Logarithmic histogram for cycles/it ranging from 500 to 24M
     * (corresponding to 200 ns to 9.6 ms at 2.5 GHz TSC clock). */
    histogram_walls_set_log(&s->cycles, 500, 24000000);
    /* Logarithmic histogram for pkts/it ranging from 0 to 1000. */
    histogram_walls_set_log(&s->pkts, 0, 1000);
    /* Linear histogram for cycles/pkt ranging from 100 to 30K. */
    histogram_walls_set_lin(&s->cycles_per_pkt, 100, 30000);
    /* Linear histogram for pkts/rx batch ranging from 0 to 32,
     * the maximum rx batch size in OVS. */
    histogram_walls_set_lin(&s->pkts_per_batch, 0, 32);
    /* Linear histogram for upcalls/it ranging from 0 to 30. */
    histogram_walls_set_lin(&s->upcalls, 0, 30);
    /* Logarithmic histogram for cycles/upcall ranging from 1000 to 1M
     * (corresponding to 400 ns to 400 us at 2.5 GHz TSC clock). */
    histogram_walls_set_log(&s->cycles_per_upcall, 1000, 1000000);
    /* Log. histogram for max vhostuser queue fill level from 0 to 512.
     * 512 is the maximum fill level for a virtio queue with 1024
     * descriptors (maximum configurable length in Qemu), with the
     * DPDK 17.11 virtio PMD in the guest. */
    histogram_walls_set_log(&s->max_vhost_qfill, 0, 512);
    s->iteration_cnt = 0;
    s->start_ms = time_msec();
    s->log_susp_it = UINT32_MAX;
    s->log_begin_it = UINT32_MAX;
    s->log_end_it = UINT32_MAX;
    s->log_reason = NULL;
}

void
pmd_perf_format_overall_stats(struct ds *str, struct pmd_perf_stats *s,
                              double duration)
{
    uint64_t stats[PMD_N_STATS];
    double us_per_cycle = 1000000.0 / tsc_hz;

    if (duration == 0) {
        return;
    }

    pmd_perf_read_counters(s, stats);
    uint64_t tot_cycles = stats[PMD_CYCLES_ITER_IDLE] +
                          stats[PMD_CYCLES_ITER_BUSY];
    uint64_t rx_packets = stats[PMD_STAT_RECV];
    uint64_t tx_packets = stats[PMD_STAT_SENT_PKTS];
    uint64_t tx_batches = stats[PMD_STAT_SENT_BATCHES];
    uint64_t passes = stats[PMD_STAT_RECV] +
                      stats[PMD_STAT_RECIRC];
    uint64_t upcalls = stats[PMD_STAT_MISS];
    uint64_t upcall_cycles = stats[PMD_CYCLES_UPCALL];
    uint64_t tot_iter = histogram_samples(&s->pkts);
    uint64_t idle_iter = s->pkts.bin[0];
    uint64_t busy_iter = tot_iter >= idle_iter ? tot_iter - idle_iter : 0;

    ds_put_format(str,
            "  Iterations:        %12"PRIu64"  (%.2f us/it)\n"
            "  - Used TSC cycles: %12"PRIu64"  (%5.1f %% of total cycles)\n"
            "  - idle iterations: %12"PRIu64"  (%5.1f %% of used cycles)\n"
            "  - busy iterations: %12"PRIu64"  (%5.1f %% of used cycles)\n",
            tot_iter, tot_cycles * us_per_cycle / tot_iter,
            tot_cycles, 100.0 * (tot_cycles / duration) / tsc_hz,
            idle_iter,
            100.0 * stats[PMD_CYCLES_ITER_IDLE] / tot_cycles,
            busy_iter,
            100.0 * stats[PMD_CYCLES_ITER_BUSY] / tot_cycles);
    if (rx_packets > 0) {
        ds_put_format(str,
            "  Rx packets:        %12"PRIu64"  (%.0f Kpps, %.0f cycles/pkt)\n"
            "  Datapath passes:   %12"PRIu64"  (%.2f passes/pkt)\n"
            "  - EMC hits:        %12"PRIu64"  (%5.1f %%)\n"
            "  - SMC hits:        %12"PRIu64"  (%5.1f %%)\n"
            "  - Megaflow hits:   %12"PRIu64"  (%5.1f %%, %.2f "
                                                "subtbl lookups/hit)\n"
            "  - Upcalls:         %12"PRIu64"  (%5.1f %%, %.1f us/upcall)\n"
            "  - Lost upcalls:    %12"PRIu64"  (%5.1f %%)\n",
            rx_packets, (rx_packets / duration) / 1000,
            1.0 * stats[PMD_CYCLES_ITER_BUSY] / rx_packets,
            passes, rx_packets ? 1.0 * passes / rx_packets : 0,
            stats[PMD_STAT_EXACT_HIT],
            100.0 * stats[PMD_STAT_EXACT_HIT] / passes,
            stats[PMD_STAT_SMC_HIT],
            100.0 * stats[PMD_STAT_SMC_HIT] / passes,
            stats[PMD_STAT_MASKED_HIT],
            100.0 * stats[PMD_STAT_MASKED_HIT] / passes,
            stats[PMD_STAT_MASKED_HIT]
            ? 1.0 * stats[PMD_STAT_MASKED_LOOKUP] / stats[PMD_STAT_MASKED_HIT]
            : 0,
            upcalls, 100.0 * upcalls / passes,
            upcalls ? (upcall_cycles * us_per_cycle) / upcalls : 0,
            stats[PMD_STAT_LOST],
            100.0 * stats[PMD_STAT_LOST] / passes);
    } else {
        ds_put_format(str, "  Rx packets:        %12d\n", 0);
    }
    if (tx_packets > 0) {
        ds_put_format(str,
            "  Tx packets:        %12"PRIu64"  (%.0f Kpps)\n"
            "  Tx batches:        %12"PRIu64"  (%.2f pkts/batch)\n",
            tx_packets, (tx_packets / duration) / 1000,
            tx_batches, 1.0 * tx_packets / tx_batches);
    } else {
        ds_put_format(str, "  Tx packets:        %12d\n\n", 0);
    }
}

void
pmd_perf_format_histograms(struct ds *str, struct pmd_perf_stats *s)
{
    int i;

    ds_put_cstr(str, "Histograms\n");
    ds_put_format(str,
                  "   %-21s  %-21s  %-21s  %-21s  %-21s  %-21s  %-21s\n",
                  "cycles/it", "packets/it", "cycles/pkt", "pkts/batch",
                  "max vhost qlen", "upcalls/it", "cycles/upcall");
    for (i = 0; i < NUM_BINS-1; i++) {
        ds_put_format(str,
            "   %-9d %-11"PRIu64"  %-9d %-11"PRIu64"  %-9d %-11"PRIu64
            "  %-9d %-11"PRIu64"  %-9d %-11"PRIu64"  %-9d %-11"PRIu64
            "  %-9d %-11"PRIu64"\n",
            s->cycles.wall[i], s->cycles.bin[i],
            s->pkts.wall[i],s->pkts.bin[i],
            s->cycles_per_pkt.wall[i], s->cycles_per_pkt.bin[i],
            s->pkts_per_batch.wall[i], s->pkts_per_batch.bin[i],
            s->max_vhost_qfill.wall[i], s->max_vhost_qfill.bin[i],
            s->upcalls.wall[i], s->upcalls.bin[i],
            s->cycles_per_upcall.wall[i], s->cycles_per_upcall.bin[i]);
    }
    ds_put_format(str,
                  "   %-9s %-11"PRIu64"  %-9s %-11"PRIu64"  %-9s %-11"PRIu64
                  "  %-9s %-11"PRIu64"  %-9s %-11"PRIu64"  %-9s %-11"PRIu64
                  "  %-9s %-11"PRIu64"\n",
                  ">", s->cycles.bin[i],
                  ">", s->pkts.bin[i],
                  ">", s->cycles_per_pkt.bin[i],
                  ">", s->pkts_per_batch.bin[i],
                  ">", s->max_vhost_qfill.bin[i],
                  ">", s->upcalls.bin[i],
                  ">", s->cycles_per_upcall.bin[i]);
    if (s->totals.iterations > 0) {
        ds_put_cstr(str,
                    "-----------------------------------------------------"
                    "-----------------------------------------------------"
                    "------------------------------------------------\n");
        ds_put_format(str,
                      "   %-21s  %-21s  %-21s  %-21s  %-21s  %-21s  %-21s\n",
                      "cycles/it", "packets/it", "cycles/pkt", "pkts/batch",
                      "vhost qlen", "upcalls/it", "cycles/upcall");
        ds_put_format(str,
                      "   %-21"PRIu64"  %-21.5f  %-21"PRIu64
                      "  %-21.5f  %-21.5f  %-21.5f  %-21"PRIu32"\n",
                      s->totals.cycles / s->totals.iterations,
                      1.0 * s->totals.pkts / s->totals.iterations,
                      s->totals.pkts
                          ? s->totals.busy_cycles / s->totals.pkts : 0,
                      s->totals.batches
                          ? 1.0 * s->totals.pkts / s->totals.batches : 0,
                      1.0 * s->totals.max_vhost_qfill / s->totals.iterations,
                      1.0 * s->totals.upcalls / s->totals.iterations,
                      s->totals.upcalls
                          ? s->totals.upcall_cycles / s->totals.upcalls : 0);
    }
}

void
pmd_perf_format_iteration_history(struct ds *str, struct pmd_perf_stats *s,
                                  int n_iter)
{
    struct iter_stats *is;
    size_t index;
    int i;

    if (n_iter == 0) {
        return;
    }
    ds_put_format(str, "   %-17s   %-10s   %-10s   %-10s   %-10s   "
                  "%-10s   %-10s   %-10s\n",
                  "iter", "cycles", "packets", "cycles/pkt", "pkts/batch",
                  "vhost qlen", "upcalls", "cycles/upcall");
    for (i = 1; i <= n_iter; i++) {
        index = history_sub(s->iterations.idx, i);
        is = &s->iterations.sample[index];
        ds_put_format(str,
                      "   %-17"PRIu64"   %-11"PRIu64"  %-11"PRIu32
                      "  %-11"PRIu64"  %-11"PRIu32"  %-11"PRIu32
                      "  %-11"PRIu32"  %-11"PRIu32"\n",
                      is->timestamp,
                      is->cycles,
                      is->pkts,
                      is->pkts ? is->cycles / is->pkts : 0,
                      is->batches ? is->pkts / is->batches : 0,
                      is->max_vhost_qfill,
                      is->upcalls,
                      is->upcalls ? is->upcall_cycles / is->upcalls : 0);
    }
}

void
pmd_perf_format_ms_history(struct ds *str, struct pmd_perf_stats *s, int n_ms)
{
    struct iter_stats *is;
    size_t index;
    int i;

    if (n_ms == 0) {
        return;
    }
    ds_put_format(str,
                  "   %-12s   %-10s   %-10s   %-10s   %-10s"
                  "   %-10s   %-10s   %-10s   %-10s\n",
                  "ms", "iterations", "cycles/it", "Kpps", "cycles/pkt",
                  "pkts/batch", "vhost qlen", "upcalls", "cycles/upcall");
    for (i = 1; i <= n_ms; i++) {
        index = history_sub(s->milliseconds.idx, i);
        is = &s->milliseconds.sample[index];
        ds_put_format(str,
                      "   %-12"PRIu64"   %-11"PRIu32"  %-11"PRIu64
                      "  %-11"PRIu32"  %-11"PRIu64"  %-11"PRIu32
                      "  %-11"PRIu32"  %-11"PRIu32"  %-11"PRIu32"\n",
                      is->timestamp,
                      is->iterations,
                      is->iterations ? is->cycles / is->iterations : 0,
                      is->pkts,
                      is->pkts ? is->busy_cycles / is->pkts : 0,
                      is->batches ? is->pkts / is->batches : 0,
                      is->iterations
                          ? is->max_vhost_qfill / is->iterations : 0,
                      is->upcalls,
                      is->upcalls ? is->upcall_cycles / is->upcalls : 0);
    }
}

void
pmd_perf_read_counters(struct pmd_perf_stats *s,
                       uint64_t stats[PMD_N_STATS])
{
    uint64_t val;

    /* These loops subtracts reference values (.zero[*]) from the counters.
     * Since loads and stores are relaxed, it might be possible for a .zero[*]
     * value to be more recent than the current value we're reading from the
     * counter.  This is not a big problem, since these numbers are not
     * supposed to be 100% accurate, but we should at least make sure that
     * the result is not negative. */
    for (int i = 0; i < PMD_N_STATS; i++) {
        atomic_read_relaxed(&s->counters.n[i], &val);
        if (val > s->counters.zero[i]) {
            stats[i] = val - s->counters.zero[i];
        } else {
            stats[i] = 0;
        }
    }
}

/* This function clears the PMD performance counters from within the PMD
 * thread or from another thread when the PMD thread is not executing its
 * poll loop. */
void
pmd_perf_stats_clear_lock(struct pmd_perf_stats *s)
    OVS_REQUIRES(s->stats_mutex)
{
    ovs_mutex_lock(&s->clear_mutex);
    for (int i = 0; i < PMD_N_STATS; i++) {
        atomic_read_relaxed(&s->counters.n[i], &s->counters.zero[i]);
    }
    /* The following stats are only applicable in PMD thread and */
    memset(&s->current, 0 , sizeof(struct iter_stats));
    memset(&s->totals, 0 , sizeof(struct iter_stats));
    histogram_clear(&s->cycles);
    histogram_clear(&s->pkts);
    histogram_clear(&s->cycles_per_pkt);
    histogram_clear(&s->upcalls);
    histogram_clear(&s->cycles_per_upcall);
    histogram_clear(&s->pkts_per_batch);
    histogram_clear(&s->max_vhost_qfill);
    history_init(&s->iterations);
    history_init(&s->milliseconds);
    s->start_ms = time_msec();
    s->milliseconds.sample[0].timestamp = s->start_ms;
    s->log_susp_it = UINT32_MAX;
    s->log_begin_it = UINT32_MAX;
    s->log_end_it = UINT32_MAX;
    s->log_reason = NULL;
    /* Clearing finished. */
    s->clear = false;
    ovs_mutex_unlock(&s->clear_mutex);
}

/* This function can be called from the anywhere to clear the stats
 * of PMD and non-PMD threads. */
void
pmd_perf_stats_clear(struct pmd_perf_stats *s)
{
    if (ovs_mutex_trylock(&s->stats_mutex) == 0) {
        /* Locking successful. PMD not polling. */
        pmd_perf_stats_clear_lock(s);
        ovs_mutex_unlock(&s->stats_mutex);
    } else {
        /* Request the polling PMD to clear the stats. There is no need to
         * block here as stats retrieval is prevented during clearing. */
        s->clear = true;
    }
}

/* Functions recording PMD metrics per iteration. */

void
pmd_perf_start_iteration(struct pmd_perf_stats *s)
OVS_REQUIRES(s->stats_mutex)
{
    if (s->clear) {
        /* Clear the PMD stats before starting next iteration. */
        pmd_perf_stats_clear_lock(s);
    }
    s->iteration_cnt++;
    /* Initialize the current interval stats. */
    memset(&s->current, 0, sizeof(struct iter_stats));
    if (OVS_LIKELY(s->last_tsc)) {
        /* We assume here that last_tsc was updated immediately prior at
         * the end of the previous iteration, or just before the first
         * iteration. */
        s->start_tsc = s->last_tsc;
    } else {
        /* In case last_tsc has never been set before. */
        s->start_tsc = cycles_counter_update(s);
    }
}

void
pmd_perf_end_iteration(struct pmd_perf_stats *s, int rx_packets,
                       int tx_packets, bool full_metrics)
{
    uint64_t now_tsc = cycles_counter_update(s);
    struct iter_stats *cum_ms;
    uint64_t cycles, cycles_per_pkt = 0;
    char *reason = NULL;

    cycles = now_tsc - s->start_tsc;
    s->current.timestamp = s->iteration_cnt;
    s->current.cycles = cycles;
    s->current.pkts = rx_packets;

    if (rx_packets + tx_packets > 0) {
        pmd_perf_update_counter(s, PMD_CYCLES_ITER_BUSY, cycles);
    } else {
        pmd_perf_update_counter(s, PMD_CYCLES_ITER_IDLE, cycles);
    }
    /* Add iteration samples to histograms. */
    histogram_add_sample(&s->cycles, cycles);
    histogram_add_sample(&s->pkts, rx_packets);

    if (!full_metrics) {
        return;
    }

    s->counters.n[PMD_CYCLES_UPCALL] += s->current.upcall_cycles;

    if (rx_packets > 0) {
        cycles_per_pkt = cycles / rx_packets;
        histogram_add_sample(&s->cycles_per_pkt, cycles_per_pkt);
    }
    histogram_add_sample(&s->upcalls, s->current.upcalls);
    histogram_add_sample(&s->max_vhost_qfill, s->current.max_vhost_qfill);

    /* Add iteration samples to millisecond stats. */
    cum_ms = history_current(&s->milliseconds);
    cum_ms->iterations++;
    cum_ms->cycles += cycles;
    if (rx_packets > 0) {
        cum_ms->busy_cycles += cycles;
    }
    cum_ms->pkts += s->current.pkts;
    cum_ms->upcalls += s->current.upcalls;
    cum_ms->upcall_cycles += s->current.upcall_cycles;
    cum_ms->batches += s->current.batches;
    cum_ms->max_vhost_qfill += s->current.max_vhost_qfill;

    if (log_enabled) {
        /* Log suspicious iterations. */
        if (cycles > iter_cycle_threshold) {
            reason = "Excessive total cycles";
        } else if (s->current.max_vhost_qfill >= log_q_thr) {
            reason = "Vhost RX queue full";
        }
        if (OVS_UNLIKELY(reason)) {
            pmd_perf_set_log_susp_iteration(s, reason);
            cycles_counter_update(s);
        }

        /* Log iteration interval around suspicious iteration when reaching
         * the end of the range to be logged. */
        if (OVS_UNLIKELY(s->log_end_it == s->iterations.idx)) {
            pmd_perf_log_susp_iteration_neighborhood(s);
            cycles_counter_update(s);
        }
    }

    /* Store in iteration history. This advances the iteration idx and
     * clears the next slot in the iteration history. */
    history_store(&s->iterations, &s->current);

    if (now_tsc > s->next_check_tsc) {
        /* Check if ms is completed and store in milliseconds history. */
        uint64_t now = time_msec();
        if (now != cum_ms->timestamp) {
            /* Add ms stats to totals. */
            s->totals.iterations += cum_ms->iterations;
            s->totals.cycles += cum_ms->cycles;
            s->totals.busy_cycles += cum_ms->busy_cycles;
            s->totals.pkts += cum_ms->pkts;
            s->totals.upcalls += cum_ms->upcalls;
            s->totals.upcall_cycles += cum_ms->upcall_cycles;
            s->totals.batches += cum_ms->batches;
            s->totals.max_vhost_qfill += cum_ms->max_vhost_qfill;
            cum_ms = history_next(&s->milliseconds);
            cum_ms->timestamp = now;
        }
        /* Do the next check after 4 us (10K cycles at 2.5 GHz TSC clock). */
        s->next_check_tsc = cycles_counter_update(s) + tsc_hz / 250000;
    }
}

/* Delay logging of the suspicious iteration and the range of iterations
 * around it until after the last iteration in the range to be logged.
 * This avoids any distortion of the measurements through the cost of
 * logging itself. */

void
pmd_perf_set_log_susp_iteration(struct pmd_perf_stats *s,
                                char *reason)
{
    if (s->log_susp_it == UINT32_MAX) {
        /* No logging scheduled yet. */
        s->log_susp_it = s->iterations.idx;
        s->log_reason = reason;
        s->log_begin_it = history_sub(s->iterations.idx, log_it_before);
        s->log_end_it = history_add(s->iterations.idx, log_it_after + 1);
    } else if (log_extend) {
        /* Logging was initiated earlier, we log the previous suspicious
         * iteration now and extend the logging interval, if possible. */
        struct iter_stats *susp = &s->iterations.sample[s->log_susp_it];
        uint32_t new_end_it, old_range, new_range;

        VLOG_WARN_RL(&latency_rl,
                "Suspicious iteration (%s): iter=%"PRIu64
                " duration=%"PRIu64" us\n",
                s->log_reason,
                susp->timestamp,
                (1000000L * susp->cycles) / tsc_hz);

        new_end_it = history_add(s->iterations.idx, log_it_after + 1);
        new_range = history_sub(new_end_it, s->log_begin_it);
        old_range = history_sub(s->log_end_it, s->log_begin_it);
        if (new_range < old_range) {
            /* Extended range exceeds history length. */
            new_end_it = s->log_begin_it;
        }
        s->log_susp_it = s->iterations.idx;
        s->log_reason = reason;
        s->log_end_it = new_end_it;
    }
}

void
pmd_perf_log_susp_iteration_neighborhood(struct pmd_perf_stats *s)
{
    ovs_assert(s->log_reason != NULL);
    ovs_assert(s->log_susp_it != UINT32_MAX);

    struct ds log = DS_EMPTY_INITIALIZER;
    struct iter_stats *susp = &s->iterations.sample[s->log_susp_it];
    uint32_t range = history_sub(s->log_end_it, s->log_begin_it);

    VLOG_WARN_RL(&latency_rl,
                 "Suspicious iteration (%s): iter=%"PRIu64
                 " duration=%"PRIu64" us\n",
                 s->log_reason,
                 susp->timestamp,
                 (1000000L * susp->cycles) / tsc_hz);

    pmd_perf_format_iteration_history(&log, s, range);
    VLOG_WARN_RL(&latency_rl,
                 "Neighborhood of suspicious iteration:\n"
                 "%s", ds_cstr(&log));
    ds_destroy(&log);
    s->log_susp_it = s->log_end_it = s->log_begin_it = UINT32_MAX;
    s->log_reason = NULL;

    if (range > 100) {
        /* Reset to safe default values to avoid disturbance. */
        log_it_before = LOG_IT_BEFORE;
        log_it_after = LOG_IT_AFTER;
        log_extend = false;
    }
}

void
pmd_perf_log_set_cmd(struct unixctl_conn *conn,
                 int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    unsigned int it_before, it_after, us_thr, q_thr;
    bool on, extend;
    bool usage = false;

    on = log_enabled;
    extend = log_extend;
    it_before = log_it_before;
    it_after = log_it_after;
    q_thr = log_q_thr;
    us_thr = log_us_thr;

    while (argc > 1) {
        if (!strcmp(argv[1], "on")) {
            on = true;
            argc--;
            argv++;
        } else if (!strcmp(argv[1], "off")) {
            on = false;
            argc--;
            argv++;
        } else if (!strcmp(argv[1], "-e")) {
            extend = true;
            argc--;
            argv++;
        } else if (!strcmp(argv[1], "-ne")) {
            extend = false;
            argc--;
            argv++;
        } else if (!strcmp(argv[1], "-a") && argc > 2) {
            if (str_to_uint(argv[2], 10, &it_after)) {
                if (it_after > HISTORY_LEN - 2) {
                    it_after = HISTORY_LEN - 2;
                }
            } else {
                usage = true;
                break;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-b") && argc > 2) {
            if (str_to_uint(argv[2], 10, &it_before)) {
                if (it_before > HISTORY_LEN - 2) {
                    it_before = HISTORY_LEN - 2;
                }
            } else {
                usage = true;
                break;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-q") && argc > 2) {
            if (!str_to_uint(argv[2], 10, &q_thr)) {
                usage = true;
                break;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-us") && argc > 2) {
            if (!str_to_uint(argv[2], 10, &us_thr)) {
                usage = true;
                break;
            }
            argc -= 2;
            argv += 2;
        } else {
            usage = true;
            break;
        }
    }
    if (it_before + it_after > HISTORY_LEN - 2) {
        it_after = HISTORY_LEN - 2 - it_before;
    }

    if (usage) {
        unixctl_command_reply_error(conn,
                "Usage: ovs-appctl dpif-netdev/pmd-perf-log-set "
                "[on|off] [-b before] [-a after] [-e|-ne] "
                "[-us usec] [-q qlen]");
        return;
    }

    VLOG_INFO("pmd-perf-log-set: %s, before=%d, after=%d, extend=%s, "
              "us_thr=%d, q_thr=%d\n",
              on ? "on" : "off", it_before, it_after,
              extend ? "true" : "false", us_thr, q_thr);
    log_enabled = on;
    log_extend = extend;
    log_it_before = it_before;
    log_it_after = it_after;
    log_q_thr = q_thr;
    log_us_thr = us_thr;
    iter_cycle_threshold = (log_us_thr * tsc_hz) / 1000000L;

    unixctl_command_reply(conn, "");
}
