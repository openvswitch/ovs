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

#ifndef IN_BAND_H
#define IN_BAND_H 1

#include "flow.h"

struct dpif;
struct in_band;
struct odp_actions;
struct ofproto;
struct rconn;
struct settings;
struct switch_status;

int in_band_create(struct ofproto *, struct dpif *, struct switch_status *,
                   struct in_band **);
void in_band_destroy(struct in_band *);

void in_band_set_remotes(struct in_band *,
                         const struct sockaddr_in *, size_t n);

void in_band_run(struct in_band *);
void in_band_wait(struct in_band *);

bool in_band_msg_in_hook(struct in_band *, const flow_t *,
                         const struct ofpbuf *packet);
bool in_band_rule_check(struct in_band *, const flow_t *,
                        const struct odp_actions *);
void in_band_flushed(struct in_band *);

#endif /* in-band.h */
