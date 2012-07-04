/* Copyright (c) 2011, 2012 Nicira, Inc.
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

#include "ofp-errors.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

struct ds;
struct flow;
struct ofpact_bundle;
struct ofpbuf;

/* NXAST_BUNDLE helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_BUNDLE specification. */

uint16_t bundle_execute(const struct ofpact_bundle *, const struct flow *,
                        bool (*slave_enabled)(uint16_t ofp_port, void *aux),
                        void *aux);
enum ofperr bundle_from_openflow(const struct nx_action_bundle *,
                                 struct ofpbuf *ofpact);
enum ofperr bundle_check(const struct ofpact_bundle *, int max_ports,
                         const struct flow *);
void bundle_to_nxast(const struct ofpact_bundle *, struct ofpbuf *of10);
void bundle_parse(const char *, struct ofpbuf *ofpacts);
void bundle_parse_load(const char *, struct ofpbuf *ofpacts);
void bundle_format(const struct ofpact_bundle *, struct ds *);

#endif /* bundle.h */
