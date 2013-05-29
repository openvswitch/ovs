/*
 * Copyright (c) 2013 Nicira, Inc.
 * Copyright (c) 2013 Simon Horman
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

#ifndef EXECUTE_ACTIONS_H
#define EXECUTE_ACTIONS_H 1

#include <stddef.h>
#include <stdint.h>

struct flow;
struct nlattr;
struct ofpbuf;

void
odp_execute_actions(void *dp, struct ofpbuf *packet, struct flow *key,
                    const struct nlattr *actions, size_t actions_len,
                    void (*output)(void *dp, struct ofpbuf *packet,
                                   uint32_t out_port),
                    void (*userspace)(void *dp, struct ofpbuf *packet,
                                      const struct flow *key,
                                      const struct nlattr *a));
#endif
