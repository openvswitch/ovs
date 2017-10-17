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

#ifndef OVN_PATCH_H
#define OVN_PATCH_H 1

/* Patch Ports
 * ===========
 *
 * This module adds and removes patch ports between the integration bridge and
 * physical bridges, as directed by other-config:ovn-bridge-mappings. */

struct controller_ctx;
struct hmap;
struct ovsrec_bridge;
struct sbrec_chassis;

void patch_run(struct controller_ctx *, const struct ovsrec_bridge *br_int,
               const struct sbrec_chassis *);

#endif /* ovn/patch.h */
