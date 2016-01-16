/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <config.h>
#include "ovsdb-pmu.h"
#include "util.h"
#include "hmap.h"
#include "hash.h"

/* PMU: Partial Map Update */
struct pmu {
    struct hmap_node node;
    struct ovsdb_datum *datum;
    enum pmu_operation operation;
};

/* PMUL: Partial Map Update List */
struct pmul {
    struct hmap hmap;
};

struct pmu*
pmu_create(struct ovsdb_datum *datum, enum pmu_operation operation)
{
    struct pmu *pmu = xmalloc(sizeof *pmu);
    pmu->node.hash = 0;
    pmu->node.next = HMAP_NODE_NULL;
    pmu->datum = datum;
    pmu->operation = operation;
    return pmu;
}

void
pmu_destroy(struct pmu *pmu, const struct ovsdb_type *type)
{
    if (pmu->operation == PMU_DELETE){
        struct ovsdb_type type_ = *type;
        type_.value.type = OVSDB_TYPE_VOID;
        ovsdb_datum_destroy(pmu->datum, &type_);
    } else {
        ovsdb_datum_destroy(pmu->datum, type);
    }
    free(pmu);
}

struct ovsdb_datum*
pmu_datum(const struct pmu *pmu)
{
    return pmu->datum;
}

enum pmu_operation
pmu_operation(const struct pmu *pmu)
{
    return pmu->operation;
}

struct pmul*
pmul_create()
{
    struct pmul *list = xmalloc(sizeof *list);
    hmap_init(&list->hmap);
    return list;
}

void
pmul_destroy(struct pmul *list, const struct ovsdb_type *type)
{
    struct pmu *pmu, *next;
    HMAP_FOR_EACH_SAFE (pmu, next, node, &list->hmap) {
        pmu_destroy(pmu, type);
    }
    hmap_destroy(&list->hmap);
    free(list);
}

/* Inserts a new PMU into 'list'. */
void
pmul_add_pmu(struct pmul *list, struct pmu *pmu)
{
    size_t hash = hash_string(pmu->datum->keys[0].string, 0);
    /* TODO: Check if there is another update with same key */
    hmap_insert(&list->hmap, &pmu->node, hash);
}

struct pmu*
pmul_first(struct pmul *list)
{
    struct hmap_node *node = hmap_first(&list->hmap);
    if (node == NULL) {
        return NULL;
    }
    struct pmu *pmu = CONTAINER_OF(node, struct pmu, node);
    return pmu;
}

struct pmu* pmul_next(struct pmul *list, struct pmu *pmu){
    struct hmap_node *node = hmap_next(&list->hmap, &pmu->node);
    if (node == NULL) {
        return NULL;
    }
    struct pmu *next = CONTAINER_OF(node, struct pmu, node);
    return next;
}
