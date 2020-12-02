/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#ifndef OVSDB_CS_H
#define OVSDB_CS_H 1

#include "openvswitch/compiler.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/shash.h"
#include "openvswitch/uuid.h"

/* Open vSwitch Database client synchronization layer. */

/* Helper for partially parsing the <table-updates> or <table-updates2> that
 * appear in struct ovsdb_cs_update_event.  The helper leaves the data in JSON
 * format, so it doesn't need to know column types. */

/* The kind of change to a row. */
enum ovsdb_cs_row_update_type {
    OVSDB_CS_ROW_DELETE,        /* Row deletion. */
    OVSDB_CS_ROW_INSERT,        /* Row insertion. */
    OVSDB_CS_ROW_UPDATE,        /* Replacement of data within a row. */
    OVSDB_CS_ROW_XOR            /* <table-updates2> diff application. */
};

/* Partially parsed <row-update> or <row-update2>. */
struct ovsdb_cs_row_update {
    struct uuid row_uuid;       /* Row's _uuid. */
    enum ovsdb_cs_row_update_type type; /* Type of change. */
    const struct shash *columns; /* Map from column name to json data. */
};

/* Partially parsed <table-update> or <table-update2>. */
struct ovsdb_cs_table_update {
    const char *table_name;
    struct ovsdb_cs_row_update *row_updates;
    size_t n;
};

struct ovsdb_cs_db_update {
    struct ovsdb_cs_table_update *table_updates;
    size_t n;
};

struct ovsdb_error *ovsdb_cs_parse_db_update(
    const struct json *table_updates, int version,
    struct ovsdb_cs_db_update **db_updatep)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_cs_db_update_destroy(struct ovsdb_cs_db_update *);

/* Simple parsing of OVSDB schemas for use by ovsdb_cs clients.  */

struct shash *ovsdb_cs_parse_schema(const struct json *schema_json);
void ovsdb_cs_free_schema(struct shash *schema);

#endif /* ovsdb-cs.h */
