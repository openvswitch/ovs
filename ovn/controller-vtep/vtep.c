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

#include "vtep.h"

#include "lib/hash.h"
#include "lib/hmap.h"
#include "lib/smap.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "ovn-controller-vtep.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"

VLOG_DEFINE_THIS_MODULE(vtep);

/*
 * Scans through the Binding table in ovnsb and updates the vtep logical
 * switch tunnel keys.
 *
 */

/* Updates the vtep Logical_Switch table entries' tunnel keys based
 * on the port bindings. */
static void
vtep_lswitch_run(struct controller_vtep_ctx *ctx)
{
    struct shash vtep_lswitches = SHASH_INITIALIZER(&vtep_lswitches);
    struct sset vtep_pswitches = SSET_INITIALIZER(&vtep_pswitches);
    struct sset used_ls = SSET_INITIALIZER(&used_ls);
    const struct vteprec_physical_switch *pswitch;
    const struct sbrec_port_binding *port_binding_rec;
    const struct vteprec_logical_switch *vtep_ls;

    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (pswitch, ctx->vtep_idl) {
        sset_add(&vtep_pswitches, pswitch->name);
    }
    VTEPREC_LOGICAL_SWITCH_FOR_EACH (vtep_ls, ctx->vtep_idl) {
        shash_add(&vtep_lswitches, vtep_ls->name, vtep_ls);
    }

    ovsdb_idl_txn_add_comment(ctx->vtep_idl_txn,
                              "ovn-controller-vtep: update logical switch "
                              "tunnel keys");
    /* Collects the logical switch bindings from port binding entries.
     * Since the binding module has already guaranteed that each vtep
     * logical switch is bound only to one ovn-sb logical datapath,
     * we can just iterate and assign tunnel key to vtep logical switch. */
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->ovnsb_idl) {
        if (strcmp(port_binding_rec->type, "vtep")
            || !port_binding_rec->chassis) {
            continue;
        }
        const char *pswitch_name = smap_get(&port_binding_rec->options,
                                            "vtep-physical-switch");
        const char *lswitch_name = smap_get(&port_binding_rec->options,
                                            "vtep-logical-switch");

        /* If 'port_binding_rec->chassis' exists then 'pswitch_name'
         * and 'lswitch_name' must also exist. */
        if (!pswitch_name || !lswitch_name) {
            /* This could only happen when someone directly modifies the
             * database.  (e.g. using ovn-sbctl) */
            VLOG_ERR("logical port (%s) with no 'options:vtep-physical-"
                     "switch' or 'options:vtep-logical-switch' specified "
                     "is bound to chassis (%s).",
                     port_binding_rec->logical_port,
                     port_binding_rec->chassis->name);
            continue;
        }
        vtep_ls = shash_find_data(&vtep_lswitches, lswitch_name);
        /* Also checks 'pswitch_name' since the same 'lswitch_name' could
         * exist in multiple vtep database instances and be bound to different
         * ovn logical networks. */
        if (vtep_ls && sset_find(&vtep_pswitches, pswitch_name)) {
            int64_t tnl_key;

            if (sset_find(&used_ls, lswitch_name)) {
                continue;
            }

            tnl_key = port_binding_rec->datapath->tunnel_key;
            if (vtep_ls->n_tunnel_key
                && vtep_ls->tunnel_key[0] != tnl_key) {
                VLOG_DBG("set vtep logical switch (%s) tunnel key from "
                         "(%"PRId64") to (%"PRId64")", vtep_ls->name,
                         vtep_ls->tunnel_key[0], tnl_key);
            }
            vteprec_logical_switch_set_tunnel_key(vtep_ls, &tnl_key, 1);
            sset_add(&used_ls, lswitch_name);
        }
    }
    struct shash_node *node;
    /* Resets the tunnel keys for the rest of vtep logical switches. */
    SHASH_FOR_EACH (node, &vtep_lswitches) {
        if (!sset_find(&used_ls, node->name)) {
            int64_t tnl_key = 0;

            vteprec_logical_switch_set_tunnel_key(node->data, &tnl_key, 1);
        }
    }

    shash_destroy(&vtep_lswitches);
    sset_destroy(&vtep_pswitches);
    sset_destroy(&used_ls);
}

/* Resets all logical switches' 'tunnel_key' to NULL */
static bool
vtep_lswitch_cleanup(struct ovsdb_idl *vtep_idl)
{
   const struct vteprec_logical_switch *vtep_ls;
    bool done = true;

    VTEPREC_LOGICAL_SWITCH_FOR_EACH (vtep_ls, vtep_idl) {
        if (vtep_ls->n_tunnel_key) {
            vteprec_logical_switch_set_tunnel_key(vtep_ls, NULL, 0);
            done = false;
        }
    }

    return done;
}


/* Updates vtep logical switch tunnel keys. */
void
vtep_run(struct controller_vtep_ctx *ctx)
{
    if (!ctx->vtep_idl_txn) {
        return;
    }
    vtep_lswitch_run(ctx);
}

/* Cleans up all related entries in vtep.  Returns true when done (i.e.
 * there is no change made to 'ctx->vtep_idl'), otherwise returns false. */
bool
vtep_cleanup(struct controller_vtep_ctx *ctx)
{
    if (!ctx->vtep_idl_txn) {
        return false;
    }

    ovsdb_idl_txn_add_comment(ctx->vtep_idl_txn,
                              "ovn-controller-vtep: cleaning up vtep "
                              "configuration");
    return vtep_lswitch_cleanup(ctx->vtep_idl);
}
