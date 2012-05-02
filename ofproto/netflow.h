/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

struct ofexpired;

struct netflow_options {
    struct sset collectors;
    uint8_t engine_type;
    uint8_t engine_id;
    int active_timeout;
    bool add_id_to_iface;
};

enum netflow_output_ports {
    NF_OUT_FLOOD = UINT16_MAX,
    NF_OUT_MULTI = UINT16_MAX - 1,
    NF_OUT_DROP = UINT16_MAX - 2
};

struct netflow_flow {
    long long int last_expired;   /* Time this flow last timed out. */
    long long int created;        /* Time flow was created since time out. */

    uint64_t packet_count_off;    /* Packet count at last time out. */
    uint64_t byte_count_off;      /* Byte count at last time out. */

    uint16_t output_iface;        /* Output interface index. */
    uint8_t tcp_flags;            /* Bitwise-OR of all TCP flags seen. */
};

struct netflow *netflow_create(void);
void netflow_destroy(struct netflow *);
int netflow_set_options(struct netflow *, const struct netflow_options *);
void netflow_expire(struct netflow *, struct netflow_flow *,
                    struct ofexpired *);

bool netflow_run(struct netflow *);
void netflow_wait(struct netflow *);

void netflow_flow_init(struct netflow_flow *);
void netflow_flow_clear(struct netflow_flow *);
void netflow_flow_update_time(struct netflow *, struct netflow_flow *,
                              long long int used);
void netflow_flow_update_flags(struct netflow_flow *, uint8_t tcp_flags);
bool netflow_active_timeout_expired(struct netflow *, struct netflow_flow *);

#endif /* netflow.h */
