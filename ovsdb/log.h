/* Copyright (c) 2009 Nicira Networks
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

#ifndef OVSDB_LOG_H
#define OVSDB_LOG_H 1

#include <sys/types.h>
#include "compiler.h"

struct json;
struct ovsdb_log;

struct ovsdb_error *ovsdb_log_open(const char *name, int flags,
                                   struct ovsdb_log **) WARN_UNUSED_RESULT;
void ovsdb_log_close(struct ovsdb_log *);

struct ovsdb_error *ovsdb_log_read(struct ovsdb_log *, struct json **)
    WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_write(struct ovsdb_log *, struct json *)
    WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_commit(struct ovsdb_log *)
    WARN_UNUSED_RESULT;

#endif /* ovsdb/log.h */
