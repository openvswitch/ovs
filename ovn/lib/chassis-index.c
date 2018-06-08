/* Copyright (c) 2016, 2017 Red Hat, Inc.
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

#include <config.h>
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/ovn-sb-idl.h"

struct ovsdb_idl_index *
chassis_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_chassis_col_name);
}

/* Finds and returns the chassis with the given 'name', or NULL if no such
 * chassis exists. */
const struct sbrec_chassis *
chassis_lookup_by_name(struct ovsdb_idl_index *sbrec_chassis_by_name,
                       const char *name)
{
    struct sbrec_chassis *target = sbrec_chassis_index_init_row(
        sbrec_chassis_by_name);
    sbrec_chassis_set_name(target, name);

    struct sbrec_chassis *retval = sbrec_chassis_index_find(
        sbrec_chassis_by_name, target);

    sbrec_chassis_index_destroy_row(target);

    return retval;
}
