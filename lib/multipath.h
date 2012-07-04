/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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

#ifndef MULTIPATH_H
#define MULTIPATH_H 1

#include <stdint.h>
#include "ofp-errors.h"

struct ds;
struct flow;
struct nx_action_multipath;
struct ofpact_multipath;
struct ofpbuf;

/* NXAST_MULTIPATH helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_MULTIPATH specification.
 */

enum ofperr multipath_from_openflow(const struct nx_action_multipath *,
                                    struct ofpact_multipath *);
enum ofperr multipath_check(const struct ofpact_multipath *,
                            const struct flow *);
void multipath_to_nxast(const struct ofpact_multipath *,
                        struct ofpbuf *openflow);

void multipath_execute(const struct ofpact_multipath *, struct flow *);

void multipath_parse(struct ofpact_multipath *, const char *);
void multipath_format(const struct ofpact_multipath *, struct ds *);

#endif /* multipath.h */
