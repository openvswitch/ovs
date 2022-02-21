/*
 * Copyright (c) 2021 Intel.
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
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "dpif-netdev-private-thread.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"

VLOG_DEFINE_THIS_MODULE(dpif_mfex_extract_study);

static atomic_uint32_t mfex_study_pkts_count = MFEX_MAX_PKT_COUNT;

/* Struct to hold miniflow study stats. */
struct study_stats {
    uint32_t pkt_count;
    uint32_t impl_hitcount[MFEX_IMPL_MAX];
};

/* Define per thread data to hold the study stats. */
DEFINE_PER_THREAD_MALLOCED_DATA(struct study_stats *, study_stats);

/* Allocate per thread PMD pointer space for study_stats. */
static inline struct study_stats *
mfex_study_get_study_stats_ptr(void)
{
    struct study_stats *stats = study_stats_get();
    if (OVS_UNLIKELY(!stats)) {
        stats = xzalloc(sizeof *stats);
        study_stats_set_unsafe(stats);
    }
    return stats;
}

int
mfex_set_study_pkt_cnt(uint32_t pkt_cmp_count, const char *name)
{
    struct dpif_miniflow_extract_impl *miniflow_funcs;
    miniflow_funcs = dpif_mfex_impl_info_get();

    /* If the packet count is set and implementation called is study then
     * set packet counter to requested number else return -EINVAL.
     */
    if ((strcmp(miniflow_funcs[MFEX_IMPL_STUDY].name, name) == 0) &&
        (pkt_cmp_count != 0)) {

        atomic_store_relaxed(&mfex_study_pkts_count, pkt_cmp_count);
        return 0;
    }

    return -EINVAL;
}

uint32_t
mfex_study_traffic(struct dp_packet_batch *packets,
                   struct netdev_flow_key *keys,
                   uint32_t keys_size, odp_port_t in_port,
                   struct dp_netdev_pmd_thread *pmd_handle)
{
    uint32_t hitmask = 0;
    uint32_t mask = 0;
    struct dp_netdev_pmd_thread *pmd = pmd_handle;
    struct dpif_miniflow_extract_impl *miniflow_funcs;
    struct study_stats *stats = mfex_study_get_study_stats_ptr();
    miniflow_funcs = dpif_mfex_impl_info_get();

    /* Run traffic optimized miniflow_extract to collect the hitmask
     * to be compared after certain packets have been hit to choose
     * the best miniflow_extract version for that traffic.
     */
    for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
        if (!miniflow_funcs[i].available) {
            continue;
        }

        hitmask = miniflow_funcs[i].extract_func(packets, keys, keys_size,
                                                 in_port, pmd_handle);
        stats->impl_hitcount[i] += count_1bits(hitmask);

        /* If traffic is not classified then we dont overwrite the keys
         * array in minfiflow implementations so its safe to create a
         * mask for all those packets whose miniflow have been created.
         */
        mask |= hitmask;
    }

    stats->pkt_count += dp_packet_batch_size(packets);

    /* Choose the best implementation after a minimum packets have been
     * processed.
     */
    uint32_t study_cnt_pkts;
    atomic_read_relaxed(&mfex_study_pkts_count, &study_cnt_pkts);

    if (stats->pkt_count >= study_cnt_pkts) {
        uint32_t best_func_index = MFEX_IMPL_START_IDX;
        uint32_t max_hits = 0;
        for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
            if (stats->impl_hitcount[i] > max_hits) {
                max_hits = stats->impl_hitcount[i];
                best_func_index = i;
            }
        }

        /* If 50% of the packets hit, enable the function. */
        if (max_hits >= (mfex_study_pkts_count / 2)) {
            atomic_store_relaxed(&pmd->miniflow_extract_opt,
                                 miniflow_funcs[best_func_index].extract_func);
            VLOG_INFO("MFEX study chose impl %s: (hits %u/%u pkts)",
                      miniflow_funcs[best_func_index].name, max_hits,
                      stats->pkt_count);
        } else {
            /* Set the implementation to null for default miniflow. */
            atomic_store_relaxed(&pmd->miniflow_extract_opt,
                    miniflow_funcs[MFEX_IMPL_SCALAR].extract_func);
            VLOG_INFO("Not enough packets matched (%u/%u), disabling"
                      " optimized MFEX.", max_hits, stats->pkt_count);
        }

        /* In debug mode show stats for all the counters. */
        if (VLOG_IS_DBG_ENABLED()) {

            for (int i = MFEX_IMPL_START_IDX; i < MFEX_IMPL_MAX; i++) {
                VLOG_DBG("MFEX study results for implementation %s:"
                         " (hits %u/%u pkts)", miniflow_funcs[i].name,
                         stats->impl_hitcount[i], stats->pkt_count);
            }
        }

        /* Reset stats so that study function can be called again
         * for next traffic type and optimal function ptr can be
         * chosen.
         */
        memset(stats, 0, sizeof(struct study_stats));
    }
    return mask;
}
