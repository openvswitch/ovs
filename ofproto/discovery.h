/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#ifndef DISCOVERY_H
#define DISCOVERY_H 1

#include <stdbool.h>

struct dpif;
struct discovery;
struct settings;
struct switch_status;

int discovery_create(const char *accept_controller_re, bool update_resolv_conf,
                     struct dpif *, struct switch_status *,
                     struct discovery **);
void discovery_destroy(struct discovery *);
bool discovery_get_update_resolv_conf(const struct discovery *);
void discovery_set_update_resolv_conf(struct discovery *,
                                      bool update_resolv_conf);
const char *discovery_get_accept_controller_re(const struct discovery *);
int discovery_set_accept_controller_re(struct discovery *, const char *re);
void discovery_question_connectivity(struct discovery *);
bool discovery_run(struct discovery *, char **controller_name);
void discovery_wait(struct discovery *);

#endif /* discovery.h */
