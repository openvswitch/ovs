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
 * WITHOUT WARRANTIES OR CONDITION OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovsdb-cs.h"

#include <errno.h>

#include "hash.h"
#include "jsonrpc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-session.h"
#include "ovsdb-types.h"
#include "sset.h"
#include "svec.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_cs);

static void
log_error(struct ovsdb_error *error)
{
    char *s = ovsdb_error_to_string_free(error);
    VLOG_WARN("error parsing database schema: %s", s);
    free(s);
}

/* Parses 'schema_json', an OVSDB schema in JSON format as described in RFC
 * 7047, to obtain the names of its rows and columns.  If successful, returns
 * an shash whose keys are table names and whose values are ssets, where each
 * sset contains the names of its table's columns.  On failure (due to a parse
 * error), returns NULL.
 *
 * It would also be possible to use the general-purpose OVSDB schema parser in
 * ovsdb-server, but that's overkill, possibly too strict for the current use
 * case, and would require restructuring ovsdb-server to separate the schema
 * code from the rest. */
struct shash *
ovsdb_cs_parse_schema(const struct json *schema_json)
{
    struct ovsdb_parser parser;
    const struct json *tables_json;
    struct ovsdb_error *error;
    struct shash_node *node;
    struct shash *schema;

    ovsdb_parser_init(&parser, schema_json, "database schema");
    tables_json = ovsdb_parser_member(&parser, "tables", OP_OBJECT);
    error = ovsdb_parser_destroy(&parser);
    if (error) {
        log_error(error);
        return NULL;
    }

    schema = xmalloc(sizeof *schema);
    shash_init(schema);
    SHASH_FOR_EACH (node, json_object(tables_json)) {
        const char *table_name = node->name;
        const struct json *json = node->data;
        const struct json *columns_json;

        ovsdb_parser_init(&parser, json, "table schema for table %s",
                          table_name);
        columns_json = ovsdb_parser_member(&parser, "columns", OP_OBJECT);
        error = ovsdb_parser_destroy(&parser);
        if (error) {
            log_error(error);
            ovsdb_cs_free_schema(schema);
            return NULL;
        }

        struct sset *columns = xmalloc(sizeof *columns);
        sset_init(columns);

        struct shash_node *node2;
        SHASH_FOR_EACH (node2, json_object(columns_json)) {
            const char *column_name = node2->name;
            sset_add(columns, column_name);
        }
        shash_add(schema, table_name, columns);
    }
    return schema;
}

/* Frees 'schema', which is in the format returned by
 * ovsdb_cs_parse_schema(). */
void
ovsdb_cs_free_schema(struct shash *schema)
{
    if (schema) {
        struct shash_node *node, *next;

        SHASH_FOR_EACH_SAFE (node, next, schema) {
            struct sset *sset = node->data;
            sset_destroy(sset);
            free(sset);
            shash_delete(schema, node);
        }
        shash_destroy(schema);
        free(schema);
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update1(const struct json *in,
                           struct ovsdb_cs_row_update *out)
{
    const struct json *old_json, *new_json;

    old_json = shash_find_data(json_object(in), "old");
    new_json = shash_find_data(json_object(in), "new");
    if (old_json && old_json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(old_json, NULL,
                                  "\"old\" <row> is not object");
    } else if (new_json && new_json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(new_json, NULL,
                                  "\"new\" <row> is not object");
    } else if ((old_json != NULL) + (new_json != NULL)
               != shash_count(json_object(in))) {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update> contains "
                                  "unexpected member");
    } else if (!old_json && !new_json) {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update> missing \"old\" "
                                  "and \"new\" members");
    }

    if (!new_json) {
        out->type = OVSDB_CS_ROW_DELETE;
        out->columns = json_object(old_json);
    } else if (!old_json) {
        out->type = OVSDB_CS_ROW_INSERT;
        out->columns = json_object(new_json);
    } else {
        out->type = OVSDB_CS_ROW_UPDATE;
        out->columns = json_object(new_json);
    }
    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update2(const struct json *in,
                           struct ovsdb_cs_row_update *out)
{
    const struct shash *object = json_object(in);
    if (shash_count(object) != 1) {
        return ovsdb_syntax_error(
            in, NULL, "<row-update2> has %"PRIuSIZE" members "
            "instead of expected 1", shash_count(object));
    }

    struct shash_node *node = shash_first(object);
    const struct json *columns = node->data;
    if (!strcmp(node->name, "insert") || !strcmp(node->name, "initial")) {
        out->type = OVSDB_CS_ROW_INSERT;
    } else if (!strcmp(node->name, "modify")) {
        out->type = OVSDB_CS_ROW_XOR;
    } else if (!strcmp(node->name, "delete")) {
        out->type = OVSDB_CS_ROW_DELETE;
        if (columns->type != JSON_NULL) {
            return ovsdb_syntax_error(
                in, NULL,
                "<row-update2> delete operation has unexpected value");
        }
        return NULL;
    } else {
        return ovsdb_syntax_error(in, NULL,
                                  "<row-update2> has unknown member \"%s\"",
                                  node->name);
    }

    if (columns->type != JSON_OBJECT) {
        return ovsdb_syntax_error(
            in, NULL,
            "<row-update2> \"%s\" operation has unexpected value",
            node->name);
    }
    out->columns = json_object(columns);

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_row_update(const char *table_name,
                          const struct json *in, int version,
                          struct ovsdb_cs_row_update *out)
{
    if (in->type != JSON_OBJECT) {
        const char *suffix = version > 1 ? "2" : "";
        return ovsdb_syntax_error(
            in, NULL,
            "<table-update%s> for table \"%s\" contains <row-update%s> "
            "that is not an object",
            suffix, table_name, suffix);
    }

    return (version == 1
            ? ovsdb_cs_parse_row_update1(in, out)
            : ovsdb_cs_parse_row_update2(in, out));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_table_update(const char *table_name,
                            const struct json *in, int version,
                            struct ovsdb_cs_table_update *out)
{
    const char *suffix = version > 1 ? "2" : "";

    if (in->type != JSON_OBJECT) {
        return ovsdb_syntax_error(
            in, NULL, "<table-update%s> for table \"%s\" is not an object",
            suffix, table_name);
    }
    struct shash *in_rows = json_object(in);

    out->row_updates = xmalloc(shash_count(in_rows) * sizeof *out->row_updates);

    const struct shash_node *node;
    SHASH_FOR_EACH (node, in_rows) {
        const char *row_uuid_string = node->name;
        struct uuid row_uuid;
        if (!uuid_from_string(&row_uuid, row_uuid_string)) {
            return ovsdb_syntax_error(
                in, NULL,
                "<table-update%s> for table \"%s\" contains "
                "bad UUID \"%s\" as member name",
                suffix, table_name, row_uuid_string);
        }

        const struct json *in_ru = node->data;
        struct ovsdb_cs_row_update *out_ru = &out->row_updates[out->n++];
        *out_ru = (struct ovsdb_cs_row_update) { .row_uuid = row_uuid };

        struct ovsdb_error *error = ovsdb_cs_parse_row_update(
            table_name, in_ru, version, out_ru);
        if (error) {
            return error;
        }
    }

    return NULL;
}

/* Parses OVSDB <table-updates> or <table-updates2> object 'in' into '*outp'.
 * If successful, sets '*outp' to the new object and returns NULL.  On failure,
 * returns the error and sets '*outp' to NULL.
 *
 * On success, the caller must eventually free '*outp', with
 * ovsdb_cs_db_update_destroy().
 *
 * 'version' should be 1 if 'in' is a <table-updates>, 2 or 3 if it is a
 * <table-updates2>. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_cs_parse_db_update(const struct json *in, int version,
                         struct ovsdb_cs_db_update **outp)
{
    const char *suffix = version > 1 ? "2" : "";

    *outp = NULL;
    if (in->type != JSON_OBJECT) {
        return ovsdb_syntax_error(in, NULL,
                                  "<table-updates%s> is not an object", suffix);
    }

    struct ovsdb_cs_db_update *out = xzalloc(sizeof *out);
    out->table_updates = xmalloc(shash_count(json_object(in))
                                 * sizeof *out->table_updates);
    const struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(in)) {
        const char *table_name = node->name;
        const struct json *in_tu = node->data;

        struct ovsdb_cs_table_update *out_tu = &out->table_updates[out->n++];
        *out_tu = (struct ovsdb_cs_table_update) { .table_name = table_name };

        struct ovsdb_error *error = ovsdb_cs_parse_table_update(
            table_name, in_tu, version, out_tu);
        if (error) {
            ovsdb_cs_db_update_destroy(out);
            return error;
        }
    }

    *outp = out;
    return NULL;
}

/* Frees 'du', which was presumably allocated by ovsdb_cs_parse_db_update(). */
void
ovsdb_cs_db_update_destroy(struct ovsdb_cs_db_update *du)
{
    if (!du) {
        return;
    }

    for (size_t i = 0; i < du->n; i++) {
        struct ovsdb_cs_table_update *tu = &du->table_updates[i];
        free(tu->row_updates);
    }
    free(du->table_updates);
    free(du);
}
