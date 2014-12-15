/* Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include "compiler.h"
#include "ofp-errors.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

struct ds;
struct flow;
struct flow_wildcards;
struct ofpact_bundle;
struct ofpbuf;

/* NXAST_BUNDLE helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_BUNDLE specification. */

#define BUNDLE_MAX_SLAVES 2048

ofp_port_t bundle_execute(const struct ofpact_bundle *, const struct flow *,
                        struct flow_wildcards *wc,
                        bool (*slave_enabled)(ofp_port_t ofp_port, void *aux),
                        void *aux);
enum ofperr bundle_check(const struct ofpact_bundle *, ofp_port_t max_ports,
                         const struct flow *);
char *bundle_parse(const char *, struct ofpbuf *ofpacts) OVS_WARN_UNUSED_RESULT;
char *bundle_parse_load(const char *, struct ofpbuf *ofpacts)
    OVS_WARN_UNUSED_RESULT;
void bundle_format(const struct ofpact_bundle *, struct ds *);

#endif /* bundle.h */
