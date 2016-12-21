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

#ifndef OVN_CHASSIS_H
#define OVN_CHASSIS_H 1

#include <stdbool.h>

struct controller_ctx;
struct ovsdb_idl;
struct ovsrec_bridge;
struct sbrec_chassis;

void chassis_register_ovs_idl(struct ovsdb_idl *);
const struct sbrec_chassis *chassis_run(struct controller_ctx *,
                                        const char *chassis_id,
                                        const struct ovsrec_bridge *br_int);
bool chassis_cleanup(struct controller_ctx *, const struct sbrec_chassis *);

#endif /* ovn/chassis.h */
