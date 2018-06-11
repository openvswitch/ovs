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

#ifndef OVN_PHYSICAL_H
#define OVN_PHYSICAL_H 1

/* Logical/Physical Translation
 * ============================
 *
 * This module implements physical-to-logical and logical-to-physical
 * translation as separate OpenFlow tables that run before the ingress pipeline
 * and after the egress pipeline, respectively, as well as to connect the
 * two pipelines.
 */

#include "openvswitch/meta-flow.h"

struct hmap;
struct ovsdb_idl_index;
struct ovsrec_bridge;
struct simap;
struct sbrec_multicast_group_table;
struct sbrec_port_binding_table;
struct sset;

/* OVN Geneve option information.
 *
 * Keep these in sync with the documentation in ovn-architecture(7). */
#define OVN_GENEVE_CLASS 0x0102  /* Assigned Geneve class for OVN. */
#define OVN_GENEVE_TYPE 0x80     /* Critical option. */
#define OVN_GENEVE_LEN 4

void physical_register_ovs_idl(struct ovsdb_idl *);
void physical_run(struct ovsdb_idl_index *sbrec_chassis_by_name,
                  struct ovsdb_idl_index *sbrec_port_binding_by_name,
                  const struct sbrec_multicast_group_table *,
                  const struct sbrec_port_binding_table *,
                  enum mf_field_id mff_ovn_geneve,
                  const struct ovsrec_bridge *br_int,
                  const struct sbrec_chassis *chassis,
                  const struct simap *ct_zones,
                  const struct hmap *local_datapaths,
                  const struct sset *local_lports,
                  const struct sset *active_tunnels,
                  struct hmap *flow_table);

#endif /* ovn/physical.h */
