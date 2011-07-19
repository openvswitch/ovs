/*
 * Copyright (c) 2011 Nicira Networks.
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

struct flow;
struct nx_action_autopath;

/* NXAST_AUTOPATH  helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_AUTOPATH specification. */

void autopath_execute(const struct nx_action_autopath *, struct flow *,
                      uint16_t ofp_port);
void autopath_parse(struct nx_action_autopath *, const char *);
int autopath_check(const struct nx_action_autopath *, const struct flow *);

#endif /* autopath.h */
