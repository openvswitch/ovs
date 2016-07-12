/* Copyright (c) 2015 Nicira, Inc.
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
#include "binding.h"

#include "openvswitch/shash.h"
#include "lib/smap.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn-controller-vtep.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"

VLOG_DEFINE_THIS_MODULE(binding);

/*
 * This module scans through the Port_Binding table in ovnsb.  If there is a
 * logical port binding entry for logical switch in vtep gateway chassis's
 * 'vtep_logical_switches' column, sets the binding's chassis column to the
 * corresponding vtep gateway chassis.
 *
 */


/* Returns true if the 'vtep_lswitch' specified in 'port_binding_rec'
 * has already been bound to another port binding entry, and resets
 * 'port_binding_rec''s chassis column.  Otherwise, updates 'ls_to_pb'
 * and returns false. */
static bool
check_pb_conflict(struct shash *ls_to_pb,
                  const struct sbrec_port_binding *port_binding_rec,
                  const char *chassis_name,
                  const char *vtep_lswitch)
{
    const struct sbrec_port_binding *pb_conflict =
        shash_find_data(ls_to_pb, vtep_lswitch);

    if (pb_conflict) {
        VLOG_WARN("logical switch (%s), on vtep gateway chassis "
                  "(%s) has already been associated with logical "
                  "port (%s), ignore logical port (%s)",
                  vtep_lswitch, chassis_name,
                  pb_conflict->logical_port,
                  port_binding_rec->logical_port);
        sbrec_port_binding_set_chassis(port_binding_rec, NULL);

        return true;
    }

    shash_add(ls_to_pb, vtep_lswitch, port_binding_rec);
    return false;
}

/* Returns true if the 'vtep_lswitch' specified in 'port_binding_rec'
 * has already been bound to a different datapath, and resets
 * 'port_binding_rec''s chassis column.  Otherwise, updates 'ls_to_db' and
 * returns false. */
static bool
check_db_conflict(struct shash *ls_to_db,
                  const struct sbrec_port_binding *port_binding_rec,
                  const char *chassis_name,
                  const char *vtep_lswitch)
{
    const struct sbrec_datapath_binding *db_conflict =
        shash_find_data(ls_to_db, vtep_lswitch);

    if (db_conflict && db_conflict != port_binding_rec->datapath) {
        VLOG_WARN("logical switch (%s), on vtep gateway chassis "
                  "(%s) has already been associated with logical "
                  "datapath (with tunnel key %"PRId64"), ignore "
                  "logical port (%s) which belongs to logical "
                  "datapath (with tunnel key %"PRId64")",
                  vtep_lswitch, chassis_name,
                  db_conflict->tunnel_key,
                  port_binding_rec->logical_port,
                  port_binding_rec->datapath->tunnel_key);
        sbrec_port_binding_set_chassis(port_binding_rec, NULL);

        return true;
    }

    shash_replace(ls_to_db, vtep_lswitch, port_binding_rec->datapath);
    return false;
}

/* Updates the 'port_binding_rec''s chassis column to 'chassis_rec'. */
static void
update_pb_chassis(const struct sbrec_port_binding *port_binding_rec,
                  const struct sbrec_chassis *chassis_rec)
{
    if (port_binding_rec->chassis != chassis_rec) {
        if (chassis_rec && port_binding_rec->chassis) {
            VLOG_DBG("Changing chassis association of logical "
                     "port (%s) from (%s) to (%s)",
                     port_binding_rec->logical_port,
                     port_binding_rec->chassis->name,
                     chassis_rec->name);
        }
        sbrec_port_binding_set_chassis(port_binding_rec, chassis_rec);
    }
}


/* Checks and updates logical port to vtep logical switch bindings for each
 * physical switch in VTEP. */
void
binding_run(struct controller_vtep_ctx *ctx)
{
    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    /* 'ls_to_db'
     *
     * Maps vtep logical switch name to the datapath binding entry.  This is
     * used to guarantee that each vtep logical switch is only included
     * in only one ovn datapath (ovn logical switch).  See check_db_conflict()
     * for details.
     *
     * 'ls_to_pb'
     *
     * Maps vtep logical switch name to the port binding entry.  This is used
     * to guarantee that each vtep logical switch on a vtep physical switch
     * is only bound to one logical port.  See check_pb_conflict() for
     * details.
     *
     */
    struct shash ls_to_db = SHASH_INITIALIZER(&ls_to_db);

    /* Stores the 'chassis' and the 'ls_to_pb' map related to
     * a vtep physcial switch. */
    struct ps {
        const struct sbrec_chassis *chassis_rec;
        struct shash ls_to_pb;
    };
    struct shash ps_map = SHASH_INITIALIZER(&ps_map);
    const struct vteprec_physical_switch *pswitch;
    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec
            = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);
        struct ps *ps = xmalloc(sizeof *ps);
        size_t i;

        /* 'chassis_rec' must exist. */
        ovs_assert(chassis_rec);
        ps->chassis_rec = chassis_rec;
        shash_init(&ps->ls_to_pb);
        for (i = 0; i < chassis_rec->n_vtep_logical_switches; i++) {
            shash_add(&ps->ls_to_pb, chassis_rec->vtep_logical_switches[i],
                      NULL);
        }
        shash_add(&ps_map, chassis_rec->name, ps);
    }

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                              "ovn-controller-vtep: updating bindings");

    const struct sbrec_port_binding *port_binding_rec;
    /* Port binding for vtep gateway chassis must have type "vtep",
     * and matched physical switch name and logical switch name. */
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->ovnsb_idl) {
        const char *type = port_binding_rec->type;
        const char *vtep_pswitch = smap_get(&port_binding_rec->options,
                                            "vtep-physical-switch");
        const char *vtep_lswitch = smap_get(&port_binding_rec->options,
                                            "vtep-logical-switch");
        struct ps *ps
            = vtep_pswitch ? shash_find_data(&ps_map, vtep_pswitch) : NULL;
        bool found_ls
            = ps && vtep_lswitch && shash_find(&ps->ls_to_pb, vtep_lswitch);

        if (!strcmp(type, "vtep") && found_ls) {
            bool pb_conflict, db_conflict;

            pb_conflict = check_pb_conflict(&ps->ls_to_pb, port_binding_rec,
                                            ps->chassis_rec->name,
                                            vtep_lswitch);
            db_conflict = check_db_conflict(&ls_to_db, port_binding_rec,
                                            ps->chassis_rec->name,
                                            vtep_lswitch);
            /* Updates port binding's chassis column when there
             * is no conflict. */
            if (!pb_conflict && !db_conflict) {
                update_pb_chassis(port_binding_rec, ps->chassis_rec);
            }
        } else if (port_binding_rec->chassis
                   && shash_find(&ps_map, port_binding_rec->chassis->name)) {
            /* Resets 'port_binding_rec' since it is no longer bound to
             * any vtep logical switch. */
            update_pb_chassis(port_binding_rec, NULL);
        }
    }

    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &ps_map) {
        struct ps *ps = iter->data;
        struct shash_node *node;

        SHASH_FOR_EACH (node, &ps->ls_to_pb) {
            if (!node->data) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_DBG_RL(&rl, "No port binding entry for logical switch (%s)"
                            "on vtep gateway chassis (%s)", node->name,
                            ps->chassis_rec->name);
            }
        }
        shash_delete(&ps_map, iter);
        shash_destroy(&ps->ls_to_pb);
        free(ps);
    }
    shash_destroy(&ls_to_db);
    shash_destroy(&ps_map);
}

/* Removes all port binding association with vtep gateway chassis.
 * Returns true when done (i.e. there is no change made to 'ctx->ovnsb_idl'),
 * otherwise returns false. */
bool
binding_cleanup(struct controller_vtep_ctx *ctx)
{
    if (!ctx->ovnsb_idl_txn) {
        return false;
    }

    struct shash ch_to_pb = SHASH_INITIALIZER(&ch_to_pb);
    const struct sbrec_port_binding *port_binding_rec;
    bool all_done = true;
    /* Hashs all port binding entries using the associated chassis name. */
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->ovnsb_idl) {
        if (port_binding_rec->chassis) {
            shash_add(&ch_to_pb, port_binding_rec->chassis->name,
                      port_binding_rec);
        }
    }

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                              "ovn-controller-vtep: removing bindings");

    const struct vteprec_physical_switch *pswitch;
    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        const struct sbrec_chassis *chassis_rec
            = get_chassis_by_name(ctx->ovnsb_idl, pswitch->name);

        if (!chassis_rec) {
            continue;
        }

        for (;;) {
            port_binding_rec = shash_find_and_delete(&ch_to_pb,
                                                     chassis_rec->name);
            if (!port_binding_rec) {
                break;
            }
            all_done = false;
            update_pb_chassis(port_binding_rec, NULL);
        }
    }
    shash_destroy(&ch_to_pb);

    return all_done;
}
