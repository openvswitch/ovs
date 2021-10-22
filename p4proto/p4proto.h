/*
* Copyright (c) 2021 Intel Corporation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef P4PROTO_H
#define P4PROTO_H 1

#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "netdev.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Needed for the lock annotations. */
extern struct ovs_mutex p4proto_mutex;

struct p4proto;

/* FIXME: Use right prototypes after stratum integration */
void p4proto_init(void);

void p4proto_deinit(void);

void p4proto_run(void);

void p4proto_create(uint64_t device_id);

void p4proto_destroy(uint64_t device_id);

int p4proto_delete(void);

void p4proto_exit(void);

struct p4proto* p4device_lookup(uint64_t device_id);

void p4proto_add_del_devices(struct shash *new_p4_devices);

void p4proto_update_config_file(uint64_t device_id, const char *file_path);

void p4proto_update_bridge(uint64_t device_id, struct hmap_node *br_node,
                           const char *br_name);

void p4proto_delete_bridges(struct hmap *bridges,
                            struct hmap *new_p4device_bridges,
                            uint64_t device_id);

void p4proto_remove_bridge(struct hmap_node *br_node, const char *br_name);

struct hmap_node * get_bridge_node(const char *br_name);

void p4proto_dump_bridge_names(struct ds *ds, struct hmap *bridges);

void* p4_server_start(void *data);

void p4_server_cleanup(void);

uint64_t get_device_id_from_bridge_name(char *br_name);

#ifdef  __cplusplus
}
#endif

#endif /* p4proto.h */
