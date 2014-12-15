/* Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#ifndef OVSDB_ERROR_H
#define OVSDB_ERROR_H 1

#include "compiler.h"

struct json;

struct ovsdb_error *ovsdb_error(const char *tag, const char *details, ...)
    OVS_PRINTF_FORMAT(2, 3)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_io_error(int error, const char *details, ...)
    OVS_PRINTF_FORMAT(2, 3)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_syntax_error(const struct json *, const char *tag,
                                       const char *details, ...)
    OVS_PRINTF_FORMAT(3, 4)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_error *ovsdb_wrap_error(struct ovsdb_error *error,
                                     const char *details, ...)
    OVS_PRINTF_FORMAT(2, 3);

struct ovsdb_error *ovsdb_internal_error(struct ovsdb_error *error,
                                         const char *file, int line,
                                         const char *details, ...)
    OVS_PRINTF_FORMAT(4, 5)
    OVS_WARN_UNUSED_RESULT;

/* Returns a pointer to an ovsdb_error that represents an internal error for
 * the current file name and line number with MSG as the associated message.
 * The caller is responsible for freeing the internal error. */
#define OVSDB_BUG(MSG)                                      \
    ovsdb_internal_error(NULL, __FILE__, __LINE__, "%s", MSG)

/* Returns a pointer to an ovsdb_error that represents an internal error for
 * the current file name and line number, with MSG as the associated message.
 * If ERROR is nonnull then the internal error is wrapped around ERROR.  Takes
 * ownership of ERROR.  The caller is responsible for freeing the returned
 * error. */
#define OVSDB_WRAP_BUG(MSG, ERROR)                          \
    ovsdb_internal_error(ERROR, __FILE__, __LINE__, "%s", MSG)

void ovsdb_error_destroy(struct ovsdb_error *);
struct ovsdb_error *ovsdb_error_clone(const struct ovsdb_error *)
    OVS_WARN_UNUSED_RESULT;

char *ovsdb_error_to_string(const struct ovsdb_error *);
struct json *ovsdb_error_to_json(const struct ovsdb_error *);

const char *ovsdb_error_get_tag(const struct ovsdb_error *);

void ovsdb_error_assert(struct ovsdb_error *);

#endif /* ovsdb-error.h */
