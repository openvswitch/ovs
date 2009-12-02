/* Copyright (c) 2009 Nicira Networks.
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

#ifndef OVSDB_IDL_H
#define OVSDB_IDL_H 1

struct ovsdb_idl_class;

struct ovsdb_idl *ovsdb_idl_create(const char *remote,
                                   const struct ovsdb_idl_class *);
void ovsdb_idl_destroy(struct ovsdb_idl *);

void ovsdb_idl_run(struct ovsdb_idl *);
void ovsdb_idl_wait(struct ovsdb_idl *);

unsigned int ovsdb_idl_get_seqno(const struct ovsdb_idl *);
void ovsdb_idl_force_reconnect(struct ovsdb_idl *);

#endif /* ovsdb-idl.h */
