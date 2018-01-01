/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef OVSDB_UTIL_H
#define OVSDB_UTIL_H 1

/* Database access utility functions. */
void ovsdb_util_clear_column(struct ovsdb_row *, const char *column_name);
struct ovsdb_datum *ovsdb_util_get_datum(struct ovsdb_row *row,
                                         const char *column_name,
                                         const enum ovsdb_atomic_type keytype,
                                         const enum ovsdb_atomic_type valtype,
                                         const size_t n_max);
const char *ovsdb_util_read_map_string_column(const struct ovsdb_row *row,
                                              const char *column_name,
                                              const char *key);
const struct ovsdb_row *ovsdb_util_read_map_string_uuid_column(
                                                    const struct ovsdb_row *r,
                                                    const char *column_name,
                                                    const char *key);
const union ovsdb_atom *ovsdb_util_read_column(const struct ovsdb_row *row,
                                               const char *column_name,
                                               enum ovsdb_atomic_type type);
bool ovsdb_util_read_integer_column(const struct ovsdb_row *row,
                                    const char *column_name,
                                    long long int *integerp);
void ovsdb_util_write_integer_column(struct ovsdb_row *row,
                                     const char *column_name,
                                     long long int integer);
bool ovsdb_util_read_string_column(const struct ovsdb_row *row,
                                   const char *column_name,
                                   const char **stringp);
void ovsdb_util_write_string_column(struct ovsdb_row *row,
                                    const char *column_name,
                                    const char *string);
void ovsdb_util_write_string_string_column(struct ovsdb_row *row,
                                           const char *column_name,
                                           char **keys, char **values,
                                           size_t n);
bool ovsdb_util_read_bool_column(const struct ovsdb_row *row,
                                 const char *column_name,
                                 bool *boolp);
void ovsdb_util_write_bool_column(struct ovsdb_row *row,
                                  const char *column_name,
                                  bool value);
bool ovsdb_util_read_uuid_column(const struct ovsdb_row *row,
                                 const char *column_name,
                                 struct uuid *);
void ovsdb_util_write_uuid_column(struct ovsdb_row *row,
                                  const char *column_name,
                                  const struct uuid *);

#endif /* ovsdb/util.h */
