/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

#ifndef AUTOPATH_H
#define AUTOPATH_H 1

#include <stdint.h>
#include "ofp-errors.h"

struct flow;
struct nx_action_autopath;
struct ofpact_autopath;
struct ofpbuf;

/* NXAST_AUTOPATH  helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_AUTOPATH specification. */

void autopath_parse(struct ofpact_autopath *, const char *);

enum ofperr autopath_from_openflow(const struct nx_action_autopath *,
                                   struct ofpact_autopath *);
enum ofperr autopath_check(const struct ofpact_autopath *,
                           const struct flow *);
void autopath_to_nxast(const struct ofpact_autopath *,
                       struct ofpbuf *openflow);

#endif /* autopath.h */
