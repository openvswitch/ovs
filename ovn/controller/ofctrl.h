/* Copyright (c) 2015 Nicira, Inc.
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


#ifndef OFCTRL_H
#define OFCTRL_H 1

#include <stdint.h>

#include "meta-flow.h"

struct controller_ctx;
struct hmap;
struct match;
struct ofpbuf;
struct ovsrec_bridge;

/* Interface for OVN main loop. */
void ofctrl_init(void);
enum mf_field_id ofctrl_run(const struct ovsrec_bridge *br_int);
void ofctrl_put(struct hmap *flows);
void ofctrl_wait(void);
void ofctrl_destroy(void);

/* Flow table interface to the rest of ovn-controller. */
void ofctrl_add_flow(struct hmap *flows, uint8_t table_id, uint16_t priority,
                     const struct match *, const struct ofpbuf *ofpacts);

#endif /* ovn/ofctrl.h */
