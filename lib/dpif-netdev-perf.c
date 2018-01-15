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

#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "dpif-netdev-perf.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(pmd_perf);

void
pmd_perf_stats_init(struct pmd_perf_stats *s)
{
    memset(s, 0 , sizeof(*s));
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

void
pmd_perf_stats_clear(struct pmd_perf_stats *s)
{
    for (int i = 0; i < PMD_N_STATS; i++) {
        atomic_read_relaxed(&s->counters.n[i], &s->counters.zero[i]);
    }
}
