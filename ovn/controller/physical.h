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

#ifndef OVN_PHYSICAL_H
#define OVN_PHYSICAL_H 1

/* Logical/Physical Translation
 * ============================
 *
 * This module implements physical-to-logical and logical-to-physical
 * translation as separate OpenFlow tables that run before and after,
 * respectively, the logical pipeline OpenFlow tables.
 */

struct controller_ctx;

void physical_init(struct controller_ctx *);
void physical_run(struct controller_ctx *);

#endif /* ovn/physical.h */
