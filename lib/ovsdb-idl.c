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

#include <config.h>

#include "ovsdb-idl.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "bitmap.h"
#include "json.h"
#include "jsonrpc.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-idl-provider.h"
#include "shash.h"
#include "util.h"

#define THIS_MODULE VLM_ovsdb_idl
#include "vlog.h"

/* An arc from one idl_row to another.  When row A contains a UUID that
 * references row B, this is represented by an arc from A (the source) to B
 * (the destination).
 *
 * Arcs from a row to itself are omitted, that is, src and dst are always
 * different.
 *
 * Arcs are never duplicated, that is, even if there are multiple references
 * from A to B, there is only a single arc from A to B.
 *
 * Arcs are directed: an arc from A to B is the converse of an an arc from B to
 * A.  Both an arc and its converse may both be present, if each row refers
 * to the other circularly.
 *
 * The source and destination row may be in the same table or in different
 * tables.
 */
struct ovsdb_idl_arc {
    struct list src_node;       /* In src->src_arcs list. */
    struct list dst_node;       /* In dst->dst_arcs list. */
    struct ovsdb_idl_row *src;  /* Source row. */
    struct ovsdb_idl_row *dst;  /* Destination row. */
};

struct ovsdb_idl {
    const struct ovsdb_idl_class *class;
    struct jsonrpc_session *session;
    struct shash table_by_name;
    struct ovsdb_idl_table *tables;
    struct json *monitor_request_id;
    unsigned int last_monitor_request_seqno;
    unsigned int change_seqno;

    /* Transaction support. */
    struct ovsdb_idl_txn *txn;
    struct hmap outstanding_txns;
};

struct ovsdb_idl_txn {
    struct hmap_node hmap_node;
    struct json *request_id;
    struct ovsdb_idl *idl;
    struct hmap txn_rows;
    enum ovsdb_idl_txn_status status;
};

static struct vlog_rate_limit syntax_rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct vlog_rate_limit semantic_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void ovsdb_idl_clear(struct ovsdb_idl *);
static void ovsdb_idl_send_monitor_request(struct ovsdb_idl *);
static void ovsdb_idl_parse_update(struct ovsdb_idl *, const struct json *);
static struct ovsdb_error *ovsdb_idl_parse_update__(struct ovsdb_idl *,
                                                    const struct json *);
static void ovsdb_idl_process_update(struct ovsdb_idl_table *,
                                     const struct uuid *,
                                     const struct json *old,
                                     const struct json *new);
static void ovsdb_idl_insert_row(struct ovsdb_idl_row *, const struct json *);
static void ovsdb_idl_delete_row(struct ovsdb_idl_row *);
static void ovsdb_idl_modify_row(struct ovsdb_idl_row *, const struct json *);

static bool ovsdb_idl_row_is_orphan(const struct ovsdb_idl_row *);
static struct ovsdb_idl_row *ovsdb_idl_row_create__(
    const struct ovsdb_idl_table_class *);
static struct ovsdb_idl_row *ovsdb_idl_row_create(struct ovsdb_idl_table *,
                                                  const struct uuid *);
static void ovsdb_idl_row_destroy(struct ovsdb_idl_row *);

static void ovsdb_idl_row_clear_old(struct ovsdb_idl_row *);
static void ovsdb_idl_row_clear_new(struct ovsdb_idl_row *);

static void ovsdb_idl_txn_abort_all(struct ovsdb_idl *);
static bool ovsdb_idl_txn_process_reply(struct ovsdb_idl *,
                                        const struct jsonrpc_msg *msg);

struct ovsdb_idl *
ovsdb_idl_create(const char *remote, const struct ovsdb_idl_class *class)
{
    struct ovsdb_idl *idl;
    size_t i;

    idl = xzalloc(sizeof *idl);
    idl->class = class;
    idl->session = jsonrpc_session_open(remote);
    shash_init(&idl->table_by_name);
    idl->tables = xmalloc(class->n_tables * sizeof *idl->tables);
    for (i = 0; i < class->n_tables; i++) {
        const struct ovsdb_idl_table_class *tc = &class->tables[i];
        struct ovsdb_idl_table *table = &idl->tables[i];
        size_t j;

        assert(!shash_find(&idl->table_by_name, tc->name));
        shash_add(&idl->table_by_name, tc->name, table);
        table->class = tc;
        shash_init(&table->columns);
        for (j = 0; j < tc->n_columns; j++) {
            const struct ovsdb_idl_column *column = &tc->columns[j];

            assert(!shash_find(&table->columns, column->name));
            shash_add(&table->columns, column->name, column);
        }
        hmap_init(&table->rows);
        table->idl = idl;
    }
    idl->last_monitor_request_seqno = UINT_MAX;
    hmap_init(&idl->outstanding_txns);

    return idl;
}

void
ovsdb_idl_destroy(struct ovsdb_idl *idl)
{
    if (idl) {
        size_t i;

        assert(!idl->txn);
        ovsdb_idl_clear(idl);
        jsonrpc_session_close(idl->session);

        for (i = 0; i < idl->class->n_tables; i++) {
            struct ovsdb_idl_table *table = &idl->tables[i];
            shash_destroy(&table->columns);
            hmap_destroy(&table->rows);
        }
        shash_destroy(&idl->table_by_name);
        free(idl->tables);
        json_destroy(idl->monitor_request_id);
        free(idl);
    }
}

static void
ovsdb_idl_clear(struct ovsdb_idl *idl)
{
    bool changed = false;
    size_t i;

    for (i = 0; i < idl->class->n_tables; i++) {
        struct ovsdb_idl_table *table = &idl->tables[i];
        struct ovsdb_idl_row *row, *next_row;

        if (hmap_is_empty(&table->rows)) {
            continue;
        }

        changed = true;
        HMAP_FOR_EACH_SAFE (row, next_row, struct ovsdb_idl_row, hmap_node,
                            &table->rows) {
            struct ovsdb_idl_arc *arc, *next_arc;

            if (!ovsdb_idl_row_is_orphan(row)) {
                (row->table->class->unparse)(row);
                ovsdb_idl_row_clear_old(row);
            }
            hmap_remove(&table->rows, &row->hmap_node);
            LIST_FOR_EACH_SAFE (arc, next_arc, struct ovsdb_idl_arc, src_node,
                                &row->src_arcs) {
                free(arc);
            }
            /* No need to do anything with dst_arcs: some node has those arcs
             * as forward arcs and will destroy them itself. */

            free(row);
        }
    }

    if (changed) {
        idl->change_seqno++;
    }
}

void
ovsdb_idl_run(struct ovsdb_idl *idl)
{
    int i;

    assert(!idl->txn);
    jsonrpc_session_run(idl->session);
    for (i = 0; jsonrpc_session_is_connected(idl->session) && i < 50; i++) {
        struct jsonrpc_msg *msg, *reply;
        unsigned int seqno;

        seqno = jsonrpc_session_get_seqno(idl->session);
        if (idl->last_monitor_request_seqno != seqno) {
            idl->last_monitor_request_seqno = seqno;
            ovsdb_idl_txn_abort_all(idl);
            ovsdb_idl_send_monitor_request(idl);
            break;
        }

        msg = jsonrpc_session_recv(idl->session);
        if (!msg) {
            break;
        }

        reply = NULL;
        if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
            reply = jsonrpc_create_reply(json_clone(msg->params), msg->id);
        } else if (msg->type == JSONRPC_NOTIFY
                   && !strcmp(msg->method, "update")
                   && msg->params->type == JSON_ARRAY
                   && msg->params->u.array.n == 2
                   && msg->params->u.array.elems[0]->type == JSON_NULL) {
            ovsdb_idl_parse_update(idl, msg->params->u.array.elems[1]);
        } else if (msg->type == JSONRPC_REPLY
                   && idl->monitor_request_id
                   && json_equal(idl->monitor_request_id, msg->id)) {
            json_destroy(idl->monitor_request_id);
            idl->monitor_request_id = NULL;
            ovsdb_idl_clear(idl);
            ovsdb_idl_parse_update(idl, msg->result);
        } else if (msg->type == JSONRPC_REPLY
                   && msg->id && msg->id->type == JSON_STRING
                   && !strcmp(msg->id->u.string, "echo")) {
            /* It's a reply to our echo request.  Ignore it. */
        } else if ((msg->type == JSONRPC_ERROR
                    || msg->type == JSONRPC_REPLY)
                   && ovsdb_idl_txn_process_reply(idl, msg)) {
            /* ovsdb_idl_txn_process_reply() did everything needful. */
        } else {
            VLOG_WARN("%s: received unexpected %s message",
                      jsonrpc_session_get_name(idl->session),
                      jsonrpc_msg_type_to_string(msg->type));
            jsonrpc_session_force_reconnect(idl->session);
        }
        if (reply) {
            jsonrpc_session_send(idl->session, reply);
        }
        jsonrpc_msg_destroy(msg);
    }
}

void
ovsdb_idl_wait(struct ovsdb_idl *idl)
{
    jsonrpc_session_wait(idl->session);
    jsonrpc_session_recv_wait(idl->session);
}

unsigned int
ovsdb_idl_get_seqno(const struct ovsdb_idl *idl)
{
    return idl->change_seqno;
}

void
ovsdb_idl_force_reconnect(struct ovsdb_idl *idl)
{
    jsonrpc_session_force_reconnect(idl->session);
}

static void
ovsdb_idl_send_monitor_request(struct ovsdb_idl *idl)
{
    struct json *monitor_requests;
    struct jsonrpc_msg *msg;
    size_t i;

    monitor_requests = json_object_create();
    for (i = 0; i < idl->class->n_tables; i++) {
        const struct ovsdb_idl_table *table = &idl->tables[i];
        const struct ovsdb_idl_table_class *tc = table->class;
        struct json *monitor_request, *columns;
        size_t i;

        monitor_request = json_object_create();
        columns = json_array_create_empty();
        for (i = 0; i < tc->n_columns; i++) {
            const struct ovsdb_idl_column *column = &tc->columns[i];
            json_array_add(columns, json_string_create(column->name));
        }
        json_object_put(monitor_request, "columns", columns);
        json_object_put(monitor_requests, tc->name, monitor_request);
    }

    json_destroy(idl->monitor_request_id);
    msg = jsonrpc_create_request(
        "monitor", json_array_create_2(json_null_create(), monitor_requests),
        &idl->monitor_request_id);
    jsonrpc_session_send(idl->session, msg);
}

static void
ovsdb_idl_parse_update(struct ovsdb_idl *idl, const struct json *table_updates)
{
    struct ovsdb_error *error;

    idl->change_seqno++;

    error = ovsdb_idl_parse_update__(idl, table_updates);
    if (error) {
        if (!VLOG_DROP_WARN(&syntax_rl)) {
            char *s = ovsdb_error_to_string(error);
            VLOG_WARN_RL(&syntax_rl, "%s", s);
            free(s);
        }
        ovsdb_error_destroy(error);
    }
}

static struct ovsdb_error *
ovsdb_idl_parse_update__(struct ovsdb_idl *idl,
                         const struct json *table_updates)
{
    const struct shash_node *tables_node;

    if (table_updates->type != JSON_OBJECT) {
        return ovsdb_syntax_error(table_updates, NULL,
                                  "<table-updates> is not an object");
    }
    SHASH_FOR_EACH (tables_node, json_object(table_updates)) {
        const struct json *table_update = tables_node->data;
        const struct shash_node *table_node;
        struct ovsdb_idl_table *table;

        table = shash_find_data(&idl->table_by_name, tables_node->name);
        if (!table) {
            return ovsdb_syntax_error(
                table_updates, NULL,
                "<table-updates> includes unknown table \"%s\"",
                tables_node->name);
        }

        if (table_update->type != JSON_OBJECT) {
            return ovsdb_syntax_error(table_update, NULL,
                                      "<table-update> for table \"%s\" is "
                                      "not an object", table->class->name);
        }
        SHASH_FOR_EACH (table_node, json_object(table_update)) {
            const struct json *row_update = table_node->data;
            const struct json *old_json, *new_json;
            struct uuid uuid;

            if (!uuid_from_string(&uuid, table_node->name)) {
                return ovsdb_syntax_error(table_update, NULL,
                                          "<table-update> for table \"%s\" "
                                          "contains bad UUID "
                                          "\"%s\" as member name",
                                          table->class->name,
                                          table_node->name);
            }
            if (row_update->type != JSON_OBJECT) {
                return ovsdb_syntax_error(row_update, NULL,
                                          "<table-update> for table \"%s\" "
                                          "contains <row-update> for %s that "
                                          "is not an object",
                                          table->class->name,
                                          table_node->name);
            }

            old_json = shash_find_data(json_object(row_update), "old");
            new_json = shash_find_data(json_object(row_update), "new");
            if (old_json && old_json->type != JSON_OBJECT) {
                return ovsdb_syntax_error(old_json, NULL,
                                          "\"old\" <row> is not object");
            } else if (new_json && new_json->type != JSON_OBJECT) {
                return ovsdb_syntax_error(new_json, NULL,
                                          "\"new\" <row> is not object");
            } else if ((old_json != NULL) + (new_json != NULL)
                       != shash_count(json_object(row_update))) {
                return ovsdb_syntax_error(row_update, NULL,
                                          "<row-update> contains unexpected "
                                          "member");
            } else if (!old_json && !new_json) {
                return ovsdb_syntax_error(row_update, NULL,
                                          "<row-update> missing \"old\" "
                                          "and \"new\" members");
            }

            ovsdb_idl_process_update(table, &uuid, old_json, new_json);
        }
    }

    return NULL;
}

static struct ovsdb_idl_row *
ovsdb_idl_get_row(struct ovsdb_idl_table *table, const struct uuid *uuid)
{
    struct ovsdb_idl_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, struct ovsdb_idl_row, hmap_node,
                             uuid_hash(uuid), &table->rows) {
        if (uuid_equals(&row->uuid, uuid)) {
            return row;
        }
    }
    return NULL;
}

static void
ovsdb_idl_process_update(struct ovsdb_idl_table *table,
                         const struct uuid *uuid, const struct json *old,
                         const struct json *new)
{
    struct ovsdb_idl_row *row;

    row = ovsdb_idl_get_row(table, uuid);
    if (!new) {
        /* Delete row. */
        if (row && !ovsdb_idl_row_is_orphan(row)) {
            /* XXX perhaps we should check the 'old' values? */
            ovsdb_idl_delete_row(row);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot delete missing row "UUID_FMT" "
                         "from table %s",
                         UUID_ARGS(uuid), table->class->name);
        }
    } else if (!old) {
        /* Insert row. */
        if (!row) {
            ovsdb_idl_insert_row(ovsdb_idl_row_create(table, uuid), new);
        } else if (ovsdb_idl_row_is_orphan(row)) {
            ovsdb_idl_insert_row(row, new);
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot add existing row "UUID_FMT" to "
                         "table %s", UUID_ARGS(uuid), table->class->name);
            ovsdb_idl_modify_row(row, new);
        }
    } else {
        /* Modify row. */
        if (row) {
            /* XXX perhaps we should check the 'old' values? */
            if (!ovsdb_idl_row_is_orphan(row)) {
                ovsdb_idl_modify_row(row, new);
            } else {
                VLOG_WARN_RL(&semantic_rl, "cannot modify missing but "
                             "referenced row "UUID_FMT" in table %s",
                             UUID_ARGS(uuid), table->class->name);
                ovsdb_idl_insert_row(row, new);
            }
        } else {
            VLOG_WARN_RL(&semantic_rl, "cannot modify missing row "UUID_FMT" "
                         "in table %s", UUID_ARGS(uuid), table->class->name);
            ovsdb_idl_insert_row(ovsdb_idl_row_create(table, uuid), new);
        }
    }
}

static void
ovsdb_idl_row_update(struct ovsdb_idl_row *row, const struct json *row_json)
{
    struct ovsdb_idl_table *table = row->table;
    struct shash_node *node;

    SHASH_FOR_EACH (node, json_object(row_json)) {
        const char *column_name = node->name;
        const struct ovsdb_idl_column *column;
        struct ovsdb_datum datum;
        struct ovsdb_error *error;

        column = shash_find_data(&table->columns, column_name);
        if (!column) {
            VLOG_WARN_RL(&syntax_rl, "unknown column %s updating row "UUID_FMT,
                         column_name, UUID_ARGS(&row->uuid));
            continue;
        }

        error = ovsdb_datum_from_json(&datum, &column->type, node->data, NULL);
        if (!error) {
            ovsdb_datum_swap(&row->old[column - table->class->columns],
                             &datum);
            ovsdb_datum_destroy(&datum, &column->type);
        } else {
            char *s = ovsdb_error_to_string(error);
            VLOG_WARN_RL(&syntax_rl, "error parsing column %s in row "UUID_FMT
                         " in table %s: %s", column_name,
                         UUID_ARGS(&row->uuid), table->class->name, s);
            free(s);
            ovsdb_error_destroy(error);
        }
    }
}

static bool
ovsdb_idl_row_is_orphan(const struct ovsdb_idl_row *row)
{
    return !row->old;
}

static void
ovsdb_idl_row_clear_old(struct ovsdb_idl_row *row)
{
    assert(row->old == row->new);
    if (!ovsdb_idl_row_is_orphan(row)) {
        const struct ovsdb_idl_table_class *class = row->table->class;
        size_t i;

        for (i = 0; i < class->n_columns; i++) {
            ovsdb_datum_destroy(&row->old[i], &class->columns[i].type);
        }
        free(row->old);
        row->old = row->new = NULL;
    }
}

static void
ovsdb_idl_row_clear_new(struct ovsdb_idl_row *row)
{
    if (row->old != row->new) {
        if (row->new) {
            const struct ovsdb_idl_table_class *class = row->table->class;
            size_t i;

            BITMAP_FOR_EACH_1 (i, class->n_columns, row->written) {
                ovsdb_datum_destroy(&row->new[i], &class->columns[i].type);
            }
            free(row->new);
            free(row->written);
            row->written = NULL;
        }
        row->new = row->old;
    }
}

static void
ovsdb_idl_row_clear_arcs(struct ovsdb_idl_row *row, bool destroy_dsts)
{
    struct ovsdb_idl_arc *arc, *next;

    /* Delete all forward arcs.  If 'destroy_dsts', destroy any orphaned rows
     * that this causes to be unreferenced. */
    LIST_FOR_EACH_SAFE (arc, next, struct ovsdb_idl_arc, src_node,
                        &row->src_arcs) {
        list_remove(&arc->dst_node);
        if (destroy_dsts
            && ovsdb_idl_row_is_orphan(arc->dst)
            && list_is_empty(&arc->dst->dst_arcs)) {
            ovsdb_idl_row_destroy(arc->dst);
        }
        free(arc);
    }
    list_init(&row->src_arcs);
}

/* Force nodes that reference 'row' to reparse. */
static void
ovsdb_idl_row_reparse_backrefs(struct ovsdb_idl_row *row, bool destroy_dsts)
{
    struct ovsdb_idl_arc *arc, *next;

    /* This is trickier than it looks.  ovsdb_idl_row_clear_arcs() will destroy
     * 'arc', so we need to use the "safe" variant of list traversal.  However,
     * calling ref->table->class->parse will add an arc equivalent to 'arc' to
     * row->arcs.  That could be a problem for traversal, but it adds it at the
     * beginning of the list to prevent us from stumbling upon it again.
     *
     * (If duplicate arcs were possible then we would need to make sure that
     * 'next' didn't also point into 'arc''s destination, but we forbid
     * duplicate arcs.) */
    LIST_FOR_EACH_SAFE (arc, next, struct ovsdb_idl_arc, dst_node,
                        &row->dst_arcs) {
        struct ovsdb_idl_row *ref = arc->src;

        (ref->table->class->unparse)(ref);
        ovsdb_idl_row_clear_arcs(ref, destroy_dsts);
        (ref->table->class->parse)(ref);
    }
}

static struct ovsdb_idl_row *
ovsdb_idl_row_create__(const struct ovsdb_idl_table_class *class)
{
    struct ovsdb_idl_row *row = xmalloc(class->allocation_size);
    memset(row, 0, sizeof *row);
    list_init(&row->src_arcs);
    list_init(&row->dst_arcs);
    hmap_node_nullify(&row->txn_node);
    return row;
}

static struct ovsdb_idl_row *
ovsdb_idl_row_create(struct ovsdb_idl_table *table, const struct uuid *uuid)
{
    struct ovsdb_idl_row *row = ovsdb_idl_row_create__(table->class);
    hmap_insert(&table->rows, &row->hmap_node, uuid_hash(uuid));
    row->uuid = *uuid;
    row->table = table;
    return row;
}

static void
ovsdb_idl_row_destroy(struct ovsdb_idl_row *row)
{
    if (row) {
        ovsdb_idl_row_clear_old(row);
        hmap_remove(&row->table->rows, &row->hmap_node);
        free(row);
    }
}

static void
ovsdb_idl_insert_row(struct ovsdb_idl_row *row, const struct json *row_json)
{
    const struct ovsdb_idl_table_class *class = row->table->class;
    size_t i;

    assert(!row->old && !row->new);
    row->old = row->new = xmalloc(class->n_columns * sizeof *row->old);
    for (i = 0; i < class->n_columns; i++) {
        ovsdb_datum_init_default(&row->old[i], &class->columns[i].type);
    }
    ovsdb_idl_row_update(row, row_json);
    (class->parse)(row);

    ovsdb_idl_row_reparse_backrefs(row, false);
}

static void
ovsdb_idl_delete_row(struct ovsdb_idl_row *row)
{
    (row->table->class->unparse)(row);
    ovsdb_idl_row_clear_arcs(row, true);
    ovsdb_idl_row_clear_old(row);
    if (list_is_empty(&row->dst_arcs)) {
        ovsdb_idl_row_destroy(row);
    } else {
        ovsdb_idl_row_reparse_backrefs(row, true);
    }
}

static void
ovsdb_idl_modify_row(struct ovsdb_idl_row *row, const struct json *row_json)
{
    (row->table->class->unparse)(row);
    ovsdb_idl_row_clear_arcs(row, true);
    ovsdb_idl_row_update(row, row_json);
    (row->table->class->parse)(row);
}

static bool
may_add_arc(const struct ovsdb_idl_row *src, const struct ovsdb_idl_row *dst)
{
    const struct ovsdb_idl_arc *arc;

    /* No self-arcs. */
    if (src == dst) {
        return false;
    }

    /* No duplicate arcs.
     *
     * We only need to test whether the first arc in dst->dst_arcs originates
     * at 'src', since we add all of the arcs from a given source in a clump
     * (in a single call to a row's ->parse function) and new arcs are always
     * added at the front of the dst_arcs list. */
    if (list_is_empty(&dst->dst_arcs)) {
        return true;
    }
    arc = CONTAINER_OF(dst->dst_arcs.next, struct ovsdb_idl_arc, dst_node);
    return arc->src != src;
}

static struct ovsdb_idl_table *
ovsdb_idl_table_from_class(const struct ovsdb_idl *idl,
                           const struct ovsdb_idl_table_class *table_class)
{
    return &idl->tables[table_class - idl->class->tables];
}

struct ovsdb_idl_row *
ovsdb_idl_get_row_arc(struct ovsdb_idl_row *src,
                      struct ovsdb_idl_table_class *dst_table_class,
                      const struct uuid *dst_uuid)
{
    struct ovsdb_idl *idl = src->table->idl;
    struct ovsdb_idl_table *dst_table;
    struct ovsdb_idl_arc *arc;
    struct ovsdb_idl_row *dst;

    dst_table = ovsdb_idl_table_from_class(idl, dst_table_class);
    dst = ovsdb_idl_get_row(dst_table, dst_uuid);
    if (!dst) {
        dst = ovsdb_idl_row_create(dst_table, dst_uuid);
    }

    /* Add a new arc, if it wouldn't be a self-arc or a duplicate arc. */
    if (may_add_arc(src, dst)) {
        /* The arc *must* be added at the front of the dst_arcs list.  See
         * ovsdb_idl_row_reparse_backrefs() for details. */
        arc = xmalloc(sizeof *arc);
        list_push_front(&src->src_arcs, &arc->src_node);
        list_push_front(&dst->dst_arcs, &arc->dst_node);
        arc->src = src;
        arc->dst = dst;
    }

    return !ovsdb_idl_row_is_orphan(dst) ? dst : NULL;
}

static struct ovsdb_idl_row *
next_real_row(struct ovsdb_idl_table *table, struct hmap_node *node)
{
    for (; node; node = hmap_next(&table->rows, node)) {
        struct ovsdb_idl_row *row;

        row = CONTAINER_OF(node, struct ovsdb_idl_row, hmap_node);
        if (!ovsdb_idl_row_is_orphan(row)) {
            return row;
        }
    }
    return NULL;
}

struct ovsdb_idl_row *
ovsdb_idl_first_row(const struct ovsdb_idl *idl,
                    const struct ovsdb_idl_table_class *table_class)
{
    struct ovsdb_idl_table *table
        = ovsdb_idl_table_from_class(idl, table_class);
    return next_real_row(table, hmap_first(&table->rows));
}

struct ovsdb_idl_row *
ovsdb_idl_next_row(const struct ovsdb_idl_row *row)
{
    struct ovsdb_idl_table *table = row->table;

    return next_real_row(table, hmap_next(&table->rows, &row->hmap_node));
}

/* Transactions. */

static void ovsdb_idl_txn_complete(struct ovsdb_idl_txn *txn,
                                   enum ovsdb_idl_txn_status);

const char *
ovsdb_idl_txn_status_to_string(enum ovsdb_idl_txn_status status)
{
    switch (status) {
    case TXN_INCOMPLETE:
        return "incomplete";
    case TXN_ABORTED:
        return "aborted";
    case TXN_SUCCESS:
        return "success";
    case TXN_TRY_AGAIN:
        return "try again";
    case TXN_ERROR:
        return "error";
    }
    return "<unknown>";
}

struct ovsdb_idl_txn *
ovsdb_idl_txn_create(struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;

    assert(!idl->txn);
    idl->txn = txn = xmalloc(sizeof *txn);
    txn->idl = idl;
    txn->status = TXN_INCOMPLETE;
    hmap_init(&txn->txn_rows);
    return txn;
}

void
ovsdb_idl_txn_destroy(struct ovsdb_idl_txn *txn)
{
    ovsdb_idl_txn_abort(txn);
    free(txn);
}

static struct json *
where_uuid_equals(const struct uuid *uuid)
{
    return
        json_array_create_1(
            json_array_create_3(
                json_string_create("_uuid"),
                json_string_create("=="),
                json_array_create_2(
                    json_string_create("uuid"),
                    json_string_create_nocopy(
                        xasprintf(UUID_FMT, UUID_ARGS(uuid))))));
}

static char *
uuid_name_from_uuid(const struct uuid *uuid)
{
    char *name;
    char *p;

    name = xasprintf("row"UUID_FMT, UUID_ARGS(uuid));
    for (p = name; *p != '\0'; p++) {
        if (*p == '-') {
            *p = '_';
        }
    }

    return name;
}

static const struct ovsdb_idl_row *
ovsdb_idl_txn_get_row(const struct ovsdb_idl_txn *txn, const struct uuid *uuid)
{
    const struct ovsdb_idl_row *row;

    HMAP_FOR_EACH_WITH_HASH (row, struct ovsdb_idl_row, txn_node,
                             uuid_hash(uuid), &txn->txn_rows) {
        if (uuid_equals(&row->uuid, uuid)) {
            return row;
        }
    }
    return NULL;
}

/* XXX there must be a cleaner way to do this */
static struct json *
substitute_uuids(struct json *json, const struct ovsdb_idl_txn *txn)
{
    if (json->type == JSON_ARRAY) {
        struct uuid uuid;
        size_t i;

        if (json->u.array.n == 2
            && json->u.array.elems[0]->type == JSON_STRING
            && json->u.array.elems[1]->type == JSON_STRING
            && !strcmp(json->u.array.elems[0]->u.string, "uuid")
            && uuid_from_string(&uuid, json->u.array.elems[1]->u.string)) {
            const struct ovsdb_idl_row *row;

            row = ovsdb_idl_txn_get_row(txn, &uuid);
            if (row && !row->old && row->new) {
                json_destroy(json);

                return json_array_create_2(
                    json_string_create("named-uuid"),
                    json_string_create_nocopy(uuid_name_from_uuid(&uuid)));
            }
        }

        for (i = 0; i < json->u.array.n; i++) {
            json->u.array.elems[i] = substitute_uuids(json->u.array.elems[i],
                                                      txn);
        }
    } else if (json->type == JSON_OBJECT) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, json_object(json)) {
            node->data = substitute_uuids(node->data, txn);
        }
    }
    return json;
}

static void
ovsdb_idl_txn_disassemble(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl_row *row, *next;

    HMAP_FOR_EACH_SAFE (row, next, struct ovsdb_idl_row, txn_node,
                        &txn->txn_rows) {
        if (row->old && row->written) {
            (row->table->class->unparse)(row);
            ovsdb_idl_row_clear_arcs(row, false);
            (row->table->class->parse)(row);
        }
        ovsdb_idl_row_clear_new(row);

        free(row->prereqs);
        row->prereqs = NULL;

        free(row->written);
        row->written = NULL;

        hmap_remove(&txn->txn_rows, &row->txn_node);
        hmap_node_nullify(&row->txn_node);
    }
    hmap_destroy(&txn->txn_rows);
    hmap_init(&txn->txn_rows);
}

enum ovsdb_idl_txn_status
ovsdb_idl_txn_commit(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl_row *row;
    struct json *operations;
    bool any_updates;
    enum ovsdb_idl_txn_status status;

    if (txn != txn->idl->txn) {
        return txn->status;
    }

    operations = json_array_create_empty();

    /* Add prerequisites and declarations of new rows. */
    HMAP_FOR_EACH (row, struct ovsdb_idl_row, txn_node, &txn->txn_rows) {
        /* XXX check that deleted rows exist even if no prereqs? */
        if (row->prereqs) {
            const struct ovsdb_idl_table_class *class = row->table->class;
            size_t n_columns = class->n_columns;
            struct json *op, *columns, *row_json;
            size_t idx;

            op = json_object_create();
            json_array_add(operations, op);
            json_object_put_string(op, "op", "wait");
            json_object_put_string(op, "table", class->name);
            json_object_put(op, "timeout", json_integer_create(0));
            json_object_put(op, "where", where_uuid_equals(&row->uuid));
            json_object_put_string(op, "until", "==");
            columns = json_array_create_empty();
            json_object_put(op, "columns", columns);
            row_json = json_object_create();
            json_object_put(op, "rows", json_array_create_1(row_json));

            BITMAP_FOR_EACH_1 (idx, n_columns, row->prereqs) {
                const struct ovsdb_idl_column *column = &class->columns[idx];
                json_array_add(columns, json_string_create(column->name));
                json_object_put(row_json, column->name,
                                ovsdb_datum_to_json(&row->old[idx],
                                                    &column->type));
            }
        }
        if (row->new && !row->old) {
            struct json *op;

            op = json_object_create();
            json_array_add(operations, op);
            json_object_put_string(op, "op", "declare");
            json_object_put(op, "uuid-name",
                            json_string_create_nocopy(
                                uuid_name_from_uuid(&row->uuid)));
        }
    }

    /* Add updates. */
    any_updates = false;
    HMAP_FOR_EACH (row, struct ovsdb_idl_row, txn_node, &txn->txn_rows) {
        const struct ovsdb_idl_table_class *class = row->table->class;
        size_t n_columns = class->n_columns;
        struct json *row_json;
        size_t idx;

        if (row->old == row->new) {
            continue;
        } else if (!row->new) {
            struct json *op = json_object_create();
            json_object_put_string(op, "op", "delete");
            json_object_put_string(op, "table", class->name);
            json_object_put(op, "where", where_uuid_equals(&row->uuid));
            json_array_add(operations, op);
        } else {
            row_json = NULL;
            BITMAP_FOR_EACH_1 (idx, n_columns, row->written) {
                const struct ovsdb_idl_column *column = &class->columns[idx];

                if (row->old
                    && ovsdb_datum_equals(&row->old[idx], &row->new[idx],
                                          &column->type)) {
                    continue;
                }
                if (!row_json) {
                    struct json *op = json_object_create();
                    json_array_add(operations, op);
                    json_object_put_string(op, "op",
                                           row->old ? "update" : "insert");
                    json_object_put_string(op, "table", class->name);
                    if (row->old) {
                        json_object_put(op, "where",
                                        where_uuid_equals(&row->uuid));
                    } else {
                        json_object_put(op, "uuid-name",
                                        json_string_create_nocopy(
                                            uuid_name_from_uuid(&row->uuid)));
                    }
                    row_json = json_object_create();
                    json_object_put(op, "row", row_json);
                    any_updates = true;
                }
                json_object_put(row_json, column->name,
                                substitute_uuids(
                                    ovsdb_datum_to_json(&row->new[idx],
                                                        &column->type),
                                    txn));
            }
        }
    }

    status = (!any_updates ? TXN_SUCCESS
              : jsonrpc_session_send(
                  txn->idl->session,
                  jsonrpc_create_request(
                      "transact", operations, &txn->request_id))
              ? TXN_TRY_AGAIN
              : TXN_INCOMPLETE);

    hmap_insert(&txn->idl->outstanding_txns, &txn->hmap_node,
                json_hash(txn->request_id, 0));
    txn->idl->txn = NULL;

    ovsdb_idl_txn_disassemble(txn);
    if (status != TXN_INCOMPLETE) {
        ovsdb_idl_txn_complete(txn, status);
    }
    return txn->status;
}

void
ovsdb_idl_txn_abort(struct ovsdb_idl_txn *txn)
{
    ovsdb_idl_txn_disassemble(txn);
    if (txn->status == TXN_INCOMPLETE) {
        txn->status = TXN_ABORTED;
    }
}

static void
ovsdb_idl_txn_complete(struct ovsdb_idl_txn *txn,
                       enum ovsdb_idl_txn_status status)
{
    txn->status = status;
    hmap_remove(&txn->idl->outstanding_txns, &txn->hmap_node);
}

void
ovsdb_idl_txn_write(struct ovsdb_idl_row *row,
                    const struct ovsdb_idl_column *column,
                    struct ovsdb_datum *datum)
{
    const struct ovsdb_idl_table_class *class = row->table->class;
    size_t column_idx = column - class->columns;

    assert(row->new);
    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->idl->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    if (row->old == row->new) {
        row->new = xmalloc(class->n_columns * sizeof *row->new);
    }
    if (!row->written) {
        row->written = bitmap_allocate(class->n_columns);
    }
    if (bitmap_is_set(row->written, column_idx)) {
        ovsdb_datum_destroy(&row->new[column_idx], &column->type);
    } else {
        bitmap_set1(row->written, column_idx);
    }
    row->new[column_idx] = *datum;
}

void
ovsdb_idl_txn_verify(const struct ovsdb_idl_row *row_,
                     const struct ovsdb_idl_column *column)
{
    struct ovsdb_idl_row *row = (struct ovsdb_idl_row *) row_;
    const struct ovsdb_idl_table_class *class = row->table->class;
    size_t column_idx = column - class->columns;

    assert(row->new);
    if (!row->old
        || (row->written && bitmap_is_set(row->written, column_idx))) {
        return;
    }

    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->idl->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    if (!row->prereqs) {
        row->prereqs = bitmap_allocate(class->n_columns);
    }
    bitmap_set1(row->prereqs, column_idx);
}

void
ovsdb_idl_txn_delete(struct ovsdb_idl_row *row)
{
    assert(row->new);
    if (!row->old) {
        ovsdb_idl_row_clear_new(row);
        assert(!row->prereqs);
        hmap_remove(&row->table->idl->txn->txn_rows, &row->txn_node);
        free(row);
    }
    if (hmap_node_is_null(&row->txn_node)) {
        hmap_insert(&row->table->idl->txn->txn_rows, &row->txn_node,
                    uuid_hash(&row->uuid));
    }
    if (row->new == row->old) {
        row->new = NULL;
    } else {
        ovsdb_idl_row_clear_new(row);
    }
}

struct ovsdb_idl_row *
ovsdb_idl_txn_insert(struct ovsdb_idl_txn *txn,
                     const struct ovsdb_idl_table_class *class)
{
    struct ovsdb_idl_row *row = ovsdb_idl_row_create__(class);
    uuid_generate(&row->uuid);
    row->table = ovsdb_idl_table_from_class(txn->idl, class);
    row->new = xmalloc(class->n_columns * sizeof *row->new);
    row->written = bitmap_allocate(class->n_columns);
    hmap_insert(&txn->txn_rows, &row->txn_node, uuid_hash(&row->uuid));
    return row;
}

static void
ovsdb_idl_txn_abort_all(struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;

    HMAP_FOR_EACH (txn, struct ovsdb_idl_txn, hmap_node,
                   &idl->outstanding_txns) {
        ovsdb_idl_txn_complete(txn, TXN_TRY_AGAIN);
    }
}

static struct ovsdb_idl_txn *
ovsdb_idl_txn_find(struct ovsdb_idl *idl, const struct json *id)
{
    struct ovsdb_idl_txn *txn;

    HMAP_FOR_EACH_WITH_HASH (txn, struct ovsdb_idl_txn, hmap_node,
                             json_hash(id, 0), &idl->outstanding_txns) {
        if (json_equal(id, txn->request_id)) {
            return txn;
        }
    }
    return NULL;
}

static bool
ovsdb_idl_txn_process_reply(struct ovsdb_idl *idl,
                            const struct jsonrpc_msg *msg)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;

    txn = ovsdb_idl_txn_find(idl, msg->id);
    if (!txn) {
        return false;
    }

    if (msg->type == JSONRPC_ERROR) {
        status = TXN_ERROR;
    } else if (msg->result->type != JSON_ARRAY) {
        VLOG_WARN_RL(&syntax_rl, "reply to \"transact\" is not JSON array");
        status = TXN_ERROR;
    } else {
        int hard_errors = 0;
        int soft_errors = 0;
        size_t i;

        for (i = 0; i < msg->result->u.array.n; i++) {
            struct json *json = msg->result->u.array.elems[i];

            if (json->type == JSON_NULL) {
                /* This isn't an error in itself but indicates that some prior
                 * operation failed, so make sure that we know about it. */
                soft_errors++;
            } else if (json->type == JSON_OBJECT) {
                struct json *error;

                error = shash_find_data(json_object(json), "error");
                if (error) {
                    if (error->type == JSON_STRING) {
                        if (!strcmp(error->u.string, "timed out")) {
                            soft_errors++;
                        } else {
                            hard_errors++;
                        }
                    } else {
                        hard_errors++;
                        VLOG_WARN_RL(&syntax_rl,
                                     "\"error\" in reply is not JSON string");
                    }
                }
            } else {
                hard_errors++;
                VLOG_WARN_RL(&syntax_rl,
                             "operation reply is not JSON null or object");
            }
        }

        status = (hard_errors ? TXN_ERROR
                  : soft_errors ? TXN_TRY_AGAIN
                  : TXN_SUCCESS);
    }

    ovsdb_idl_txn_complete(txn, status);
    return true;
}
