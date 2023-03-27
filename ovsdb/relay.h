/*
 * Copyright (c) 2021, Red Hat, Inc.
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

#ifndef OVSDB_RELAY_H
#define OVSDB_RELAY_H 1

#include <stdbool.h>

struct json;
struct ovsdb;
struct ovsdb_schema;

typedef struct ovsdb_error *(*schema_change_callback)(
                                       struct ovsdb *,
                                       const struct ovsdb_schema *,
                                       bool conversion_with_no_data,
                                       void *aux);

void ovsdb_relay_add_db(struct ovsdb *, const char *remote,
                        schema_change_callback schema_change_cb,
                        void *schema_change_aux);
void ovsdb_relay_del_db(struct ovsdb *);
void ovsdb_relay_run(void);
void ovsdb_relay_wait(void);

bool ovsdb_relay_is_connected(struct ovsdb *);

#endif /* OVSDB_RELAY_H */
