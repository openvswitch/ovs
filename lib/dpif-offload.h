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
void dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_config *);
void dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_stats *);
void dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                            struct ofputil_meter_stats *);

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


/* Netdev specific function, which can be used in the fast path. */
int dpif_offload_netdev_flush_flows(struct netdev *);
int dpif_offload_netdev_hw_post_process(struct netdev *, struct dp_packet *);

#endif /* DPIF_OFFLOAD_H */
