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

/* On non-Linux, these functions are defined inline in ovs-numa.h. */
#ifdef __linux__

#include <config.h>
#include "ovs-numa.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "ovs-thread.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_numa);

#define MAX_NUMA_NODES 128

/* numa node. */
struct numa_node {
    struct hmap_node hmap_node;     /* In the 'all_numa_nodes'. */
    struct list cores;              /* List of cpu cores on the numa node. */
    int numa_id;                    /* numa node id. */
};

/* Cpu core on a numa node. */
struct cpu_core {
    struct hmap_node hmap_node;/* In the 'all_cpu_cores'. */
    struct list list_node;     /* In 'numa_node->cores' list. */
    struct numa_node *numa;    /* numa node containing the core. */
    int core_id;               /* Core id. */
    bool pinned;               /* If a thread has been pinned to the core. */
};

/* Contains all 'struct numa_node's. */
static struct hmap all_numa_nodes = HMAP_INITIALIZER(&all_numa_nodes);
/* Contains all 'struct cpu_core's. */
static struct hmap all_cpu_cores = HMAP_INITIALIZER(&all_cpu_cores);
/* True if numa node and core info are correctly extracted. */
static bool found_numa_and_core;

/* Returns true if 'str' contains all digits.  Returns false otherwise. */
static bool
contain_all_digits(const char *str)
{
    return str[strspn(str, "0123456789")] == '\0';
}

/* Discovers all numa nodes and the corresponding cpu cores.
 * Constructs the 'struct numa_node' and 'struct cpu_core'. */
static void
discover_numa_and_core(void)
{
    int n_cpus = 0;
    int i;

    for (i = 0; i < MAX_NUMA_NODES; i++) {
        DIR *dir;
        char* path;

        /* Constructs the path to node /sys/devices/system/nodeX. */
        path = xasprintf("/sys/devices/system/node/node%d", i);
        dir = opendir(path);

        /* Creates 'struct numa_node' if the 'dir' is non-null. */
        if (dir) {
            struct numa_node *n = xzalloc(sizeof *n);
            struct dirent *subdir;

            hmap_insert(&all_numa_nodes, &n->hmap_node, hash_int(i, 0));
            list_init(&n->cores);
            n->numa_id = i;

            while ((subdir = readdir(dir)) != NULL) {
                if (!strncmp(subdir->d_name, "cpu", 3)
                    && contain_all_digits(subdir->d_name + 3)){
                    struct cpu_core *c = xzalloc(sizeof *c);
                    uint32_t core_id;

                    core_id = strtoul(subdir->d_name + 3, NULL, 10);
                    hmap_insert(&all_cpu_cores, &c->hmap_node,
                                hash_int(core_id, 0));
                    list_insert(&n->cores, &c->list_node);
                    c->core_id = core_id;
                    n_cpus++;
                }
            }
            VLOG_INFO("Discovered %"PRIuSIZE" CPU cores on NUMA node %d",
                      list_size(&n->cores), n->numa_id);
            free(path);
            closedir(dir);
        } else {
            if (errno != ENOENT) {
                VLOG_WARN("opendir(%s) failed (%s)", path,
                          ovs_strerror(errno));
            }
            free(path);
            break;
        }
    }

    VLOG_INFO("Discovered %"PRIuSIZE" NUMA nodes and %d CPU cores",
               hmap_count(&all_numa_nodes), n_cpus);
    if (hmap_count(&all_numa_nodes) && hmap_count(&all_cpu_cores)) {
        found_numa_and_core = true;
    }
}

/* Extracts the numa node and core info from the 'sysfs'. */
void
ovs_numa_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        discover_numa_and_core();
        ovsthread_once_done(&once);
    }
}

bool
ovs_numa_numa_id_is_valid(int numa_id)
{
    return found_numa_and_core && numa_id < ovs_numa_get_n_numas();
}

bool
ovs_numa_core_id_is_valid(int core_id)
{
    return found_numa_and_core && core_id < ovs_numa_get_n_cores();
}

/* Returns the number of numa nodes. */
int
ovs_numa_get_n_numas(void)
{
    return found_numa_and_core ? hmap_count(&all_numa_nodes)
                               : OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores. */
int
ovs_numa_get_n_cores(void)
{
    return found_numa_and_core ? hmap_count(&all_cpu_cores)
                               : OVS_CORE_UNSPEC;
}

/* Returns the number of cpu cores on numa node.  Returns OVS_CORE_UNSPEC
 * if 'numa_id' is invalid. */
int
ovs_numa_get_n_cores_on_numa(int numa_id)
{
    if (ovs_numa_numa_id_is_valid(numa_id)) {
        struct numa_node *numa;

        numa = CONTAINER_OF(hmap_first_with_hash(&all_numa_nodes,
                                                 hash_int(numa_id, 0)),
                            struct numa_node, hmap_node);

        return list_size(&numa->cores);
    }

    return OVS_CORE_UNSPEC;
}

/* Returns the number of unpinned cpu cores on numa node.  Returns
 * OVS_CORE_UNSPEC if 'numa_id' is invalid. */
int
ovs_numa_get_n_unpinned_cores_on_numa(int numa_id)
{
    if (ovs_numa_numa_id_is_valid(numa_id)) {
        struct numa_node *numa;
        struct cpu_core *core;
        int count = 0;

        numa = CONTAINER_OF(hmap_first_with_hash(&all_numa_nodes,
                                                 hash_int(numa_id, 0)),
                            struct numa_node, hmap_node);
        LIST_FOR_EACH(core, list_node, &numa->cores) {
            if (!core->pinned) {
                count++;
            }
        }

        return count;
    }

    return OVS_CORE_UNSPEC;
}

/* Given 'core_id', tries to pin that core.  Returns true, if succeeds.
 * False, if the core has already been pinned or if 'core_id' is invalid. */
bool
ovs_numa_try_pin_core_specific(int core_id)
{
    if (ovs_numa_core_id_is_valid(core_id)) {
        struct cpu_core *core;

        core = CONTAINER_OF(hmap_first_with_hash(&all_cpu_cores,
                                                 hash_int(core_id, 0)),
                            struct cpu_core, hmap_node);
        if (!core->pinned) {
            core->pinned = true;
            return true;
        }
    }

    return false;
}

/* Searches through all cores for an unpinned core.  Returns the core_id
 * if found and set the 'core->pinned' to true.  Otherwise, returns
 * OVS_CORE_UNSPEC. */
int
ovs_numa_get_unpinned_core_any(void)
{
    struct cpu_core *core;

    HMAP_FOR_EACH(core, hmap_node, &all_cpu_cores) {
        if (!core->pinned) {
            core->pinned = true;
            return core->core_id;
        }
    }

    return OVS_CORE_UNSPEC;
}

/* Searches through all cores on numa node with 'numa_id' for an unpinned
 * core.  Returns the core_id if found and sets the 'core->pinned' to true.
 * Otherwise, returns OVS_CORE_UNSPEC. */
int
ovs_numa_get_unpinned_core_on_numa(int numa_id)
{
    if (ovs_numa_numa_id_is_valid(numa_id)) {
        struct numa_node *numa;
        struct cpu_core *core;

        numa = CONTAINER_OF(hmap_first_with_hash(&all_numa_nodes,
                                                 hash_int(numa_id, 0)),
                            struct numa_node, hmap_node);
        LIST_FOR_EACH(core, list_node, &numa->cores) {
            if (!core->pinned) {
                core->pinned = true;
                return core->core_id;
            }
        }
    }

    return OVS_CORE_UNSPEC;
}

/* Resets the 'core->pinned' for the core with 'core_id'. */
void
ovs_numa_unpin_core(int core_id)
{
    if (ovs_numa_core_id_is_valid(core_id)) {
        struct cpu_core *core;

        core = CONTAINER_OF(hmap_first_with_hash(&all_cpu_cores,
                                                 hash_int(core_id, 0)),
                            struct cpu_core, hmap_node);
        core->pinned = false;
    }
}

#endif /* __linux__ */
