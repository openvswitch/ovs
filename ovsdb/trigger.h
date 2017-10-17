/* Copyright (c) 2009, 2011, 2012 Nicira, Inc.
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

#ifndef OVSDB_TRIGGER_H
#define OVSDB_TRIGGER_H 1

#include "openvswitch/list.h"

struct ovsdb;

struct ovsdb_trigger {
    struct ovsdb_session *session; /* Session that owns this trigger. */
    struct ovsdb *db;           /* Database on which trigger acts. */
    struct ovs_list node;       /* !result: in db->triggers;
                                 * result: in session->completions. */
    struct json *request;       /* Database request. */
    struct json *result;        /* Result (null if none yet). */
    long long int created;      /* Time created. */
    long long int timeout_msec; /* Max wait duration. */
    bool read_only;             /* Database is in read only mode. */
    char *role;                 /* Role, for role-based access controls. */
    char *id;                   /* ID, for role-based access controls. */
};

void ovsdb_trigger_init(struct ovsdb_session *, struct ovsdb *,
                        struct ovsdb_trigger *,
                        struct json *request, long long int now,
                        bool read_only, const char *role,
                        const char *id);
void ovsdb_trigger_destroy(struct ovsdb_trigger *);

bool ovsdb_trigger_is_complete(const struct ovsdb_trigger *);
struct json *ovsdb_trigger_steal_result(struct ovsdb_trigger *);

void ovsdb_trigger_run(struct ovsdb *, long long int now);
void ovsdb_trigger_wait(struct ovsdb *, long long int now);

#endif /* ovsdb/trigger.h */
