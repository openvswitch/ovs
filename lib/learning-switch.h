/*
 * Copyright (c) 2008, 2010 Nicira Networks.
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

#ifndef LEARNING_SWITCH_H
#define LEARNING_SWITCH_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct ofpbuf;
struct rconn;

struct lswitch *lswitch_create(struct rconn *, bool learn_macs,
                               bool exact_flows, int max_idle,
                               bool action_normal, FILE *default_flows);
void lswitch_set_queue(struct lswitch *sw, uint32_t queue);
void lswitch_run(struct lswitch *);
void lswitch_wait(struct lswitch *);
void lswitch_destroy(struct lswitch *);
void lswitch_process_packet(struct lswitch *, struct rconn *,
                            const struct ofpbuf *);


#endif /* learning-switch.h */
