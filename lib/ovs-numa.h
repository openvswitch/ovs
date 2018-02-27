/*
 * Copyright (c) 2014 Nicira, Inc.
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

#ifndef OVS_NUMA_H
#define OVS_NUMA_H 1

#include <limits.h>
#include <stdbool.h>

#include "compiler.h"
#include "openvswitch/hmap.h"

#define OVS_CORE_UNSPEC INT_MAX
#define OVS_NUMA_UNSPEC INT_MAX

/* Dump of a list of 'struct ovs_numa_info'. */
struct ovs_numa_dump {
    struct hmap cores;
    struct hmap numas;
};

/* A numa_id - core_id pair. */
struct ovs_numa_info_core {
    struct hmap_node hmap_node;
    int numa_id;
    unsigned core_id;
};

/* A numa node. */
struct ovs_numa_info_numa {
    struct hmap_node hmap_node;
    int numa_id;
    size_t n_cores;
};

void ovs_numa_init(void);
void ovs_numa_set_dummy(const char *config);
bool ovs_numa_numa_id_is_valid(int numa_id);
bool ovs_numa_core_id_is_valid(unsigned core_id);
int ovs_numa_get_n_numas(void);
int ovs_numa_get_n_cores(void);
int ovs_numa_get_numa_id(unsigned core_id);
int ovs_numa_get_n_cores_on_numa(int numa_id);
struct ovs_numa_dump *ovs_numa_dump_cores_on_numa(int numa_id);
struct ovs_numa_dump *ovs_numa_dump_cores_with_cmask(const char *cmask);
struct ovs_numa_dump *ovs_numa_dump_n_cores_per_numa(int n);
bool ovs_numa_dump_contains_core(const struct ovs_numa_dump *,
                                 int numa_id, unsigned core_id);
size_t ovs_numa_dump_count(const struct ovs_numa_dump *);
void ovs_numa_dump_destroy(struct ovs_numa_dump *);
int ovs_numa_thread_setaffinity_core(unsigned core_id);

#define FOR_EACH_CORE_ON_DUMP(ITER, DUMP)                    \
    HMAP_FOR_EACH((ITER), hmap_node, &(DUMP)->cores)

#define FOR_EACH_NUMA_ON_DUMP(ITER, DUMP)                    \
    HMAP_FOR_EACH((ITER), hmap_node, &(DUMP)->numas)

#endif /* ovs-numa.h */
