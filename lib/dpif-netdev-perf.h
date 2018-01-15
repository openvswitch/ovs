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

#ifndef DPIF_NETDEV_PERF_H
#define DPIF_NETDEV_PERF_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* This module encapsulates data structures and functions to maintain PMD
 * performance metrics such as packet counters, execution cycles. It
 * provides a clean API for dpif-netdev to initialize, update and read and
 * reset these metrics.
 */

/* Set of counter types maintained in pmd_perf_stats. */

enum pmd_stat_type {
    PMD_STAT_EXACT_HIT,     /* Packets that had an exact match (emc). */
    PMD_STAT_MASKED_HIT,    /* Packets that matched in the flow table. */
    PMD_STAT_MISS,          /* Packets that did not match and upcall was ok. */
    PMD_STAT_LOST,          /* Packets that did not match and upcall failed. */
                            /* The above statistics account for the total
                             * number of packet passes through the datapath
                             * pipeline and should not be overlapping with each
                             * other. */
    PMD_STAT_MASKED_LOOKUP, /* Number of subtable lookups for flow table
                               hits. Each MASKED_HIT hit will have >= 1
                               MASKED_LOOKUP(s). */
    PMD_STAT_RECV,          /* Packets entering the datapath pipeline from an
                             * interface. */
    PMD_STAT_RECIRC,        /* Packets reentering the datapath pipeline due to
                             * recirculation. */
    PMD_STAT_SENT_PKTS,     /* Packets that have been sent. */
    PMD_STAT_SENT_BATCHES,  /* Number of batches sent. */
    PMD_CYCLES_POLL_IDLE,   /* Cycles spent unsuccessful polling. */
    PMD_CYCLES_POLL_BUSY,   /* Cycles spent successfully polling and
                             * processing polled packets. */
    PMD_CYCLES_OVERHEAD,    /* Cycles spent for other tasks. */
    PMD_CYCLES_ITER_IDLE,   /* Cycles spent in idle iterations. */
    PMD_CYCLES_ITER_BUSY,   /* Cycles spent in busy iterations. */
    PMD_N_STATS
};

/* Array of PMD counters indexed by enum pmd_stat_type.
 * The n[] array contains the actual counter values since initialization
 * of the PMD. Counters are atomically updated from the PMD but are
 * read and cleared also from other processes. To clear the counters at
 * PMD run-time, the current counter values are copied over to the zero[]
 * array. To read counters we subtract zero[] value from n[]. */

struct pmd_counters {
    atomic_uint64_t n[PMD_N_STATS];     /* Value since _init(). */
    uint64_t zero[PMD_N_STATS];         /* Value at last _clear().  */
};

/* Container for all performance metrics of a PMD.
 * Part of the struct dp_netdev_pmd_thread. */

struct pmd_perf_stats {
    /* Start of the current PMD iteration in TSC cycles.*/
    uint64_t last_tsc;
    /* Set of PMD counters with their zero offsets. */
    struct pmd_counters counters;
};

void pmd_perf_stats_init(struct pmd_perf_stats *s);
void pmd_perf_stats_clear(struct pmd_perf_stats *s);
void pmd_perf_read_counters(struct pmd_perf_stats *s,
                            uint64_t stats[PMD_N_STATS]);

/* PMD performance counters are updated lock-less. For real PMDs
 * they are only updated from the PMD thread itself. In the case of the
 * NON-PMD they might be updated from multiple threads, but we can live
 * with losing a rare update as 100% accuracy is not required.
 * However, as counters are read for display from outside the PMD thread
 * with e.g. pmd-stats-show, we make sure that the 64-bit read and store
 * operations are atomic also on 32-bit systems so that readers cannot
 * not read garbage. On 64-bit systems this incurs no overhead. */

static inline void
pmd_perf_update_counter(struct pmd_perf_stats *s,
                        enum pmd_stat_type counter, int delta)
{
    uint64_t tmp;
    atomic_read_relaxed(&s->counters.n[counter], &tmp);
    tmp += delta;
    atomic_store_relaxed(&s->counters.n[counter], tmp);
}

static inline void
pmd_perf_start_iteration(struct pmd_perf_stats *s, uint64_t now_tsc)
{
    s->last_tsc = now_tsc;
}

static inline void
pmd_perf_end_iteration(struct pmd_perf_stats *s, uint64_t now_tsc,
                       int rx_packets)
{
    uint64_t cycles = now_tsc - s->last_tsc;

    if (rx_packets > 0) {
        pmd_perf_update_counter(s, PMD_CYCLES_ITER_BUSY, cycles);
    } else {
        pmd_perf_update_counter(s, PMD_CYCLES_ITER_IDLE, cycles);
    }
}

#ifdef  __cplusplus
}
#endif

#endif /* DPIF_NETDEV_PERF_H */
