/*
 * Copyright (c) 2009, 2010 InMon Corp.
 * Copyright (c) 2009, 2012 Nicira, Inc.
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

#ifndef OFPROTO_DPIF_SFLOW_H
#define OFPROTO_DPIF_SFLOW_H 1

#include <stdint.h>
#include "svec.h"
#include "lib/odp-util.h"

struct dpif;
struct dpif_upcall;
struct flow;
struct ofproto_sflow_options;
struct ofport;

struct dpif_sflow *dpif_sflow_create(struct dpif *);
uint32_t dpif_sflow_get_probability(const struct dpif_sflow *);

void dpif_sflow_destroy(struct dpif_sflow *);
void dpif_sflow_set_options(struct dpif_sflow *,
                            const struct ofproto_sflow_options *);
void dpif_sflow_clear(struct dpif_sflow *);
bool dpif_sflow_is_enabled(const struct dpif_sflow *);

void dpif_sflow_add_port(struct dpif_sflow *ds, struct ofport *ofport);
void dpif_sflow_del_port(struct dpif_sflow *, uint16_t ovs_port);

void dpif_sflow_run(struct dpif_sflow *);
void dpif_sflow_wait(struct dpif_sflow *);

void dpif_sflow_received(struct dpif_sflow *,
                         struct ofpbuf *,
                         const struct flow *,
                         const union user_action_cookie *);

int dpif_sflow_odp_port_to_ifindex(const struct dpif_sflow *, uint16_t);

#endif /* ofproto/ofproto-dpif-sflow.h */
