/* Copyright (c) 2011 Nicira Networks.
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

#ifndef BUNDLE_H
#define BUNDLE_H 1

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

struct ds;
struct flow;
struct ofpbuf;

/* NXAST_BUNDLE helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_BUNDLE specification. */

uint16_t bundle_execute(const struct nx_action_bundle *, const struct flow *,
                        bool (*slave_enabled)(uint16_t ofp_port, void *aux),
                        void *aux);
void bundle_execute_load(const struct nx_action_bundle *, struct flow *,
                         bool (*slave_enabled)(uint16_t ofp_port, void *aux),
                         void *aux);
int bundle_check(const struct nx_action_bundle *, int max_ports,
                 const struct flow *);
void bundle_parse(struct ofpbuf *, const char *);
void bundle_parse_load(struct ofpbuf *b, const char *);
void bundle_format(const struct nx_action_bundle *, struct ds *);

/* Returns the 'i'th slave in 'nab'. */
static inline uint16_t
bundle_get_slave(const struct nx_action_bundle *nab, size_t i)
{
    return ntohs(((ovs_be16 *)(nab + 1))[i]);
}

#endif /* bundle.h */
