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

#ifndef OVSDB_PMU_H
#define OVSDB_PMU_H 1

#include "ovsdb-data.h"

enum pmu_operation {
    PMU_UPDATE,
    PMU_INSERT,
    PMU_DELETE
};

struct pmu; /* PMU: Partial Map Update */
struct pmul; /* PMUL: Partial Map Update List */

/* PMU: Partial Map Update functions */
struct pmu* pmu_create(struct ovsdb_datum *, enum pmu_operation);
void pmu_destroy(struct pmu *, const struct ovsdb_type *);
struct ovsdb_datum* pmu_datum(const struct pmu*);
enum pmu_operation pmu_operation(const struct pmu*);

/* PMUL: Partial Map Update List functions */
struct pmul* pmul_create(void);
void pmul_destroy(struct pmul *, const struct ovsdb_type *);
void pmul_add_pmu(struct pmul *list, struct pmu *pmu);
struct pmu* pmul_first(struct pmul *);
struct pmu* pmul_next(struct pmul *, struct pmu *);

#endif /* ovsdb-pmu.h */
