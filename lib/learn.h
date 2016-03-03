/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef LEARN_H
#define LEARN_H 1

#include "compiler.h"
#include "openvswitch/ofp-errors.h"

struct ds;
struct flow;
struct flow_wildcards;
struct ofpbuf;
struct ofpact_learn;
struct ofputil_flow_mod;
struct nx_action_learn;

/* NXAST_LEARN helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_LEARN specification.
 */

enum ofperr learn_check(const struct ofpact_learn *, const struct flow *);
void learn_execute(const struct ofpact_learn *, const struct flow *,
                   struct ofputil_flow_mod *, struct ofpbuf *ofpacts);
void learn_mask(const struct ofpact_learn *, struct flow_wildcards *);

char *learn_parse(char *, struct ofpbuf *ofpacts) OVS_WARN_UNUSED_RESULT;
void learn_format(const struct ofpact_learn *, struct ds *);

#endif /* learn.h */
