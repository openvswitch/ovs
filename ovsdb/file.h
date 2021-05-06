/* Copyright (c) 2009, 2010, 2011, 2016, 2017 Nicira, Inc.
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

#ifndef OVSDB_FILE_H
#define OVSDB_FILE_H 1

#include <stdbool.h>
#include "compiler.h"

struct ovsdb;
struct ovsdb_schema;
struct ovsdb_txn;

void ovsdb_file_column_diff_disable(void);

struct json *ovsdb_to_txn_json(const struct ovsdb *, const char *comment);
struct json *ovsdb_file_txn_to_json(const struct ovsdb_txn *);
struct json *ovsdb_file_txn_annotate(struct json *, const char *comment);
struct ovsdb_error *ovsdb_file_txn_from_json(struct ovsdb *,
                                             const struct json *,
                                             bool converting,
                                             struct ovsdb_txn **)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb *ovsdb_file_read(const char *filename, bool rw);
struct ovsdb *ovsdb_file_read_as_schema(const char *filename,
                                        struct ovsdb_schema *);

struct ovsdb_error *ovsdb_convert(const struct ovsdb *src,
                                  const struct ovsdb_schema *new_schema,
                                  struct ovsdb **dstp)
    OVS_WARN_UNUSED_RESULT;

#endif /* ovsdb/file.h */
