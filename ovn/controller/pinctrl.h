
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

#ifndef DHCP_H
#define DHCP_H 1

#include <stdint.h>

#include "meta-flow.h"

struct ovsrec_bridge;
struct controller_ctx;

/* Interface for OVN main loop. */
void pinctrl_init(void);
void pinctrl_run(struct controller_ctx *ctx,
                 const struct ovsrec_bridge *br_int);
void pinctrl_wait(void);
void pinctrl_destroy(void);

#endif /* ovn/dhcp.h */
