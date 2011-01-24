/*
 * Copyright (c) 2009, 2010 InMon Corp.
 * Copyright (c) 2009 Nicira Networks.
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

#ifndef OFPROTO_SFLOW_H
#define OFPROTO_SFLOW_H 1

#include <stdint.h>
#include "svec.h"

struct dpif;
struct dpif_upcall;
struct flow;
struct ofproto_sflow_options;

struct ofproto_sflow *ofproto_sflow_create(struct dpif *);
void ofproto_sflow_destroy(struct ofproto_sflow *);
void ofproto_sflow_set_options(struct ofproto_sflow *,
                               const struct ofproto_sflow_options *);
void ofproto_sflow_clear(struct ofproto_sflow *);
bool ofproto_sflow_is_enabled(const struct ofproto_sflow *);

void ofproto_sflow_add_port(struct ofproto_sflow *, uint16_t odp_port,
                            const char *netdev_name);
void ofproto_sflow_del_port(struct ofproto_sflow *, uint16_t odp_port);

void ofproto_sflow_run(struct ofproto_sflow *);
void ofproto_sflow_wait(struct ofproto_sflow *);

void ofproto_sflow_received(struct ofproto_sflow *,
                            const struct dpif_upcall *, const struct flow *);

#endif /* ofproto/ofproto-sflow.h */
