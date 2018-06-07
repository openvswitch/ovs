/* Copyright (c) 2017 Red Hat, Inc.
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

#ifndef OVN_BFD_H
#define OVN_BFD_H 1

struct chassis_index;
struct controller_ctx;
struct hmap;
struct ovsdb_idl;
struct ovsrec_bridge;
struct ovsrec_interface_table;
struct sbrec_chassis;
struct sset;

void bfd_register_ovs_idl(struct ovsdb_idl *);
void bfd_run(struct controller_ctx *ctx,
             const struct ovsrec_interface_table *interface_table,
             const struct ovsrec_bridge *br_int,
             const struct sbrec_chassis *chassis_rec,
             const struct hmap *local_datapaths, const struct chassis_index *);
void  bfd_calculate_active_tunnels(const struct ovsrec_bridge *br_int,
                                   struct sset *active_tunnels);

#endif
