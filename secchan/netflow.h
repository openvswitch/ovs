/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef NETFLOW_H
#define NETFLOW_H 1

#include "flow.h"

struct ofexpired;
struct svec;

enum netflow_output_ports {
    NF_OUT_FLOOD = UINT16_MAX,
    NF_OUT_MULTI = UINT16_MAX - 1,
    NF_OUT_DROP = UINT16_MAX - 2
};

struct netflow *netflow_create(void);
void netflow_destroy(struct netflow *);
int netflow_set_collectors(struct netflow *, const struct svec *collectors);
void netflow_set_engine(struct netflow *nf, uint8_t engine_type, 
        uint8_t engine_id, bool add_id_to_iface);
void netflow_expire(struct netflow *, const struct ofexpired *);
void netflow_run(struct netflow *);

#endif /* netflow.h */
