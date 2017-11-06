/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2015 Nicira, Inc.
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

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "flow.h"

struct flow;
struct in_band;
struct nlattr;
struct ofpbuf;
struct ofproto;

int in_band_create(struct ofproto *, const char *local_name,
                   struct in_band **);
void in_band_destroy(struct in_band *);

void in_band_set_queue(struct in_band *, int queue_id);
void in_band_set_remotes(struct in_band *,
                         const struct sockaddr_in *, size_t n);

bool in_band_run(struct in_band *);
void in_band_wait(struct in_band *);

bool in_band_must_output_to_local_port(const struct flow *);

int in_band_count_rules(const struct in_band *);

#endif /* in-band.h */
