/* Copyright (c) 2017, Red Hat, Inc.
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

#ifndef OVN_CHASSIS_INDEX_H
#define OVN_CHASSIS_INDEX_H 1

struct ovsdb_idl;

struct ovsdb_idl_index *chassis_index_create(struct ovsdb_idl *);

const struct sbrec_chassis *chassis_lookup_by_name(
    struct ovsdb_idl_index *sbrec_chassis_by_name, const char *name);

#endif /* ovn/lib/chassis-index.h */
