/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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

#ifndef OFPROTO_NETFLOW_H
#define OFPROTO_NETFLOW_H 1

#include <stdint.h>
#include "flow.h"
#include "sset.h"

/* Default active timeout interval, in seconds.
 *
 * (The active timeout interval is the interval at which NetFlow records are
 * sent for flows that do not expire, so that such flows are still
 * accounted.) */
#define NF_ACTIVE_TIMEOUT_DEFAULT 600

struct netflow_options {
    struct sset collectors;
    uint8_t engine_type;
    uint8_t engine_id;
    int active_timeout;
    bool add_id_to_iface;
};

#define NF_OUT_FLOOD OFP_PORT_C(UINT16_MAX)
#define NF_OUT_MULTI OFP_PORT_C(UINT16_MAX - 1)
#define NF_OUT_DROP  OFP_PORT_C(UINT16_MAX - 2)

struct netflow *netflow_create(void);
struct netflow *netflow_ref(const struct netflow *);
void netflow_unref(struct netflow *);
bool netflow_exists(void);

int netflow_set_options(struct netflow *, const struct netflow_options *);

void netflow_run(struct netflow *);
void netflow_wait(struct netflow *);

void netflow_mask_wc(struct flow *, struct flow_wildcards *);

void netflow_flow_clear(struct netflow *netflow, struct flow *flow);

void netflow_flow_update(struct netflow *nf, const struct flow *flow,
                         ofp_port_t output_iface,
                         const struct dpif_flow_stats *);

#endif /* netflow.h */
