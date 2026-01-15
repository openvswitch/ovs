/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#ifndef DPIF_OFFLOAD_H
#define DPIF_OFFLOAD_H

#include "dpif.h"

/* Forward declarations of private structures. */
struct dpif_offload_class;
struct dpif_offload;

/* Structure used by the dpif_offload_dump_* functions. */
struct dpif_offload_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};

/* Definition of the DPIF offload implementation type.
 *
 * The 'DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED' implementation has a single view,
 * the offload provider is responsible for synchronizing flows and statistics
 * through the dpif flow operations.  An example of this is DPDK's rte_flow.
 *
 * The 'DPIF_OFFLOAD_IMPL_FLOWS_PROVIDER_ONLY' implementation tries to install
 * the offloaded flow first.  If successful, no dpif-layer software flow will
 * be installed.  Offload-specific callbacks are then used to manage the flow
 * and query statistics.  An example of this is kernel TC.
 */
enum dpif_offload_impl_type {
    DPIF_OFFLOAD_IMPL_NONE,
    DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED,
    DPIF_OFFLOAD_IMPL_FLOWS_PROVIDER_ONLY,
};


/* Global functions. */
void dpif_offload_set_global_cfg(const struct ovsrec_open_vswitch *);
bool dpif_offload_enabled(void);
bool dpif_offload_rebalance_policy_enabled(void);


/* Per dpif specific functions. */
void dpif_offload_init(struct dpif_offload *,
                       const struct dpif_offload_class *, struct dpif *);
int dpif_attach_offload_providers(struct dpif *);
void dpif_detach_offload_providers(struct dpif *);
const char *dpif_offload_name(const struct dpif_offload *);
const char *dpif_offload_type(const struct dpif_offload *);
bool dpif_offload_get_debug(const struct dpif_offload *, struct ds *,
                            struct json *);
void dpif_offload_flow_flush(struct dpif *);
void dpif_offload_dump_start(struct dpif_offload_dump *, const struct dpif *);
bool dpif_offload_dump_next(struct dpif_offload_dump *,
                            struct dpif_offload **);
int dpif_offload_dump_done(struct dpif_offload_dump *);
uint64_t dpif_offload_flow_count(const struct dpif *);
uint64_t dpif_offload_flow_count_by_impl(const struct dpif *,
                                         enum dpif_offload_impl_type);
void dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_config *);
void dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_stats *);
void dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_stats *);
struct netdev *dpif_offload_get_netdev_by_port_id(struct dpif *,
                                                  struct dpif_offload **,
                                                  odp_port_t);
struct dpif_offload *dpif_offload_port_offloaded_by(const struct dpif *,
                                                    odp_port_t);
bool dpif_offload_netdevs_out_of_resources(struct dpif *);
enum dpif_offload_impl_type dpif_offload_get_impl_type(
    const struct dpif_offload *);
enum dpif_offload_impl_type dpif_offload_get_impl_type_by_class(
    const char *type);

/* Iterates through each DPIF_OFFLOAD in DPIF, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using dpif_offload_dump_done(). */
#define DPIF_OFFLOAD_FOR_EACH(DPIF_OFFLOAD, DUMP, DPIF)  \
    for (dpif_offload_dump_start(DUMP, DPIF);            \
         (dpif_offload_dump_next(DUMP, &DPIF_OFFLOAD)    \
          ? true                                         \
          : (dpif_offload_dump_done(DUMP), false));      \
        )

struct dpif_offload_port {
    struct netdev *netdev;
    odp_port_t port_no;
};

struct dpif_offload_port_dump {
    const struct dpif *dpif;
    const struct dpif_offload *offload;
    int error;
    void *state;
};

void dpif_offload_port_dump_start(struct dpif_offload_port_dump *,
                                  const struct dpif *);
bool dpif_offload_port_dump_next(struct dpif_offload_port_dump *,
                                 struct dpif_offload_port *);
int dpif_offload_port_dump_done(struct dpif_offload_port_dump *);

/* Iterates through each DPIF_OFFLOAD_PORT in DPIF, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using dpif_offload_port_dump_done(). */
#define DPIF_OFFLOAD_PORT_FOR_EACH(DPIF_OFFLOAD_PORT, DUMP, DPIF)  \
    for (dpif_offload_port_dump_start(DUMP, DPIF);                 \
         (dpif_offload_port_dump_next(DUMP, DPIF_OFFLOAD_PORT)     \
          ? true                                                   \
          : (dpif_offload_port_dump_done(DUMP), false));           \
        )

/* Queries the datapath for hardware offload stats.
 *
 * On success, '*stats' will point to a heap-allocated array of
 * 'netdev_custom_stats' structures, and '*n_stats' will be set to the
 * number of statistics returned.
 *
 * The caller is responsible for freeing the memory using
 * 'netdev_free_custom_stats_counters()' on each 'stats' object, and
 * call free() on 'stats'. */
int dpif_offload_stats_get(struct dpif *, struct netdev_custom_stats **stats,
                           size_t *n_stats);


/* Netdev specific function, which can be used in the fast path. */
bool dpif_offload_netdev_same_offload(const struct netdev *,
                                      const struct netdev *);
int dpif_offload_netdev_flush_flows(struct netdev *);
int dpif_offload_netdev_hw_post_process(struct netdev *, struct dp_packet *);


/* Callback invoked when a hardware flow offload operation (put/del) completes.
 * This callback is used for asynchronous flow offload operations.  When the
 * offload provider cannot complete an operation synchronously (returns
 * EINPROGRESS), it will invoke this callback later to notify the caller of
 * completion. */
typedef void dpif_offload_flow_op_cb(void *aux_dp, void *aux_flow,
                                     struct dpif_flow_stats *stats,
                                     uint32_t flow_mark, int error);

/* Supporting structures for flow modification functions. */
struct dpif_offload_flow_cb_data {
    dpif_offload_flow_op_cb *callback;
    void *callback_aux_dp;
    void *callback_aux_flow;
};

struct dpif_offload_flow_put {
    bool modify;
    odp_port_t in_port;
    odp_port_t orig_in_port;  /* Originating in_port for tunneled packets. */
    const ovs_u128 *ufid;
    struct match *match;
    const struct nlattr *actions;
    size_t actions_len;
    struct dpif_flow_stats *stats;
    struct dpif_offload_flow_cb_data cb_data;
};

struct dpif_offload_flow_del {
    odp_port_t in_port;
    const ovs_u128 *ufid;
    struct dpif_flow_stats *stats;
    struct dpif_offload_flow_cb_data cb_data;
};

/* Flow modification functions, which can be used in the fast path. */
int dpif_offload_datapath_flow_put(const char *dpif_name,
                                   struct dpif_offload_flow_put *,
                                   uint32_t *flow_mark);
int dpif_offload_datapath_flow_del(const char *dpif_name,
                                   struct dpif_offload_flow_del *,
                                   uint32_t *flow_mark);
bool dpif_offload_datapath_flow_stats(const char *dpif_name,
                                      odp_port_t in_port, const ovs_u128 *ufid,
                                      struct dpif_flow_stats *,
                                      struct dpif_flow_attrs *);

static inline void
dpif_offload_datapath_flow_op_continue(struct dpif_offload_flow_cb_data *cb,
                                       struct dpif_flow_stats *stats,
                                       uint32_t flow_mark, int error)
{
    if (cb && cb->callback) {
        cb->callback(cb->callback_aux_dp, cb->callback_aux_flow,
                     stats, flow_mark, error);
    }
}

#endif /* DPIF_OFFLOAD_H */
