
/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef PINCTRL_H
#define PINCTRL_H 1

#include <stdint.h>

#include "lib/sset.h"
#include "openvswitch/meta-flow.h"

struct chassis_index;
struct controller_ctx;
struct hmap;
struct lport_index;
struct ovsrec_bridge;
struct sbrec_chassis;

void pinctrl_init(void);
void pinctrl_run(struct controller_ctx *,
                 const struct ovsrec_bridge *, const struct sbrec_chassis *,
                 const struct chassis_index *, struct hmap *local_datapaths,
                 struct sset *active_tunnels);
void pinctrl_wait(struct controller_ctx *);
void pinctrl_destroy(void);

#endif /* ovn/pinctrl.h */
