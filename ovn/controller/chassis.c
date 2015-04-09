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
#include "chassis.h"

#include "lib/poll-loop.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(chassis);

void
chassis_init(struct controller_ctx *ctx)
{
    ovsdb_idl_add_table(ctx->ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ctx->ovs_idl, &ovsrec_open_vswitch_col_external_ids);
}

static void
register_chassis(struct controller_ctx *ctx,
                 const struct sbrec_chassis *chassis_rec,
                 const char *encap_type, const char *encap_ip)
{
    struct sbrec_encap *encap_rec;
    int retval = TXN_TRY_AGAIN;
    struct ovsdb_idl_txn *txn;

    txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
    ovsdb_idl_txn_add_comment(txn,
                              "ovn-controller: registering chassis '%s'",
                              ctx->chassis_name);

    if (!chassis_rec) {
        chassis_rec = sbrec_chassis_insert(txn);
        sbrec_chassis_set_name(chassis_rec, ctx->chassis_name);
    }

    encap_rec = sbrec_encap_insert(txn);

    sbrec_encap_set_type(encap_rec, encap_type);
    sbrec_encap_set_ip(encap_rec, encap_ip);

    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    retval = ovsdb_idl_txn_commit_block(txn);
    if (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        VLOG_INFO("Problem registering chassis: %s",
                  ovsdb_idl_txn_status_to_string(retval));
        poll_immediate_wake();
    }
    ovsdb_idl_txn_destroy(txn);
}

void
chassis_run(struct controller_ctx *ctx)
{
    const struct sbrec_chassis *chassis_rec;
    const struct ovsrec_open_vswitch *cfg;
    const char *encap_type, *encap_ip;
    static bool inited = false;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
        if (!strcmp(chassis_rec->name, ctx->chassis_name)) {
            break;
        }
    }

    /* xxx Need to support more than one encap.  Also need to support
     * xxx encap options. */
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return;
    }

    encap_type = smap_get(&cfg->external_ids, "ovn-encap-type");
    encap_ip = smap_get(&cfg->external_ids, "ovn-encap-ip");
    if (!encap_type || !encap_ip) {
        VLOG_INFO("Need to specify an encap type and ip");
        return;
    }

    if (chassis_rec) {
        int i;

        for (i = 0; i < chassis_rec->n_encaps; i++) {
            if (!strcmp(chassis_rec->encaps[i]->type, encap_type)
                && !strcmp(chassis_rec->encaps[i]->ip, encap_ip)) {
                /* Nothing changed. */
                inited = true;
                return;
            } else if (!inited) {
                VLOG_WARN("Chassis config changing on startup, make sure "
                          "multiple chassis are not configured : %s/%s->%s/%s",
                          chassis_rec->encaps[i]->type,
                          chassis_rec->encaps[i]->ip,
                          encap_type, encap_ip);
            }

        }
    }

    register_chassis(ctx, chassis_rec, encap_type, encap_ip);
    inited = true;
}

void
chassis_destroy(struct controller_ctx *ctx)
{
    int retval = TXN_TRY_AGAIN;

    ovs_assert(ctx->ovnsb_idl);

    while (retval != TXN_SUCCESS && retval != TXN_UNCHANGED) {
        const struct sbrec_chassis *chassis_rec;
        struct ovsdb_idl_txn *txn;

        SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->ovnsb_idl) {
            if (!strcmp(chassis_rec->name, ctx->chassis_name)) {
                break;
            }
        }

        if (!chassis_rec) {
            return;
        }

        txn = ovsdb_idl_txn_create(ctx->ovnsb_idl);
        ovsdb_idl_txn_add_comment(txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  ctx->chassis_name);
        sbrec_chassis_delete(chassis_rec);

        retval = ovsdb_idl_txn_commit_block(txn);
        if (retval == TXN_ERROR) {
            VLOG_INFO("Problem unregistering chassis: %s",
                      ovsdb_idl_txn_status_to_string(retval));
        }
        ovsdb_idl_txn_destroy(txn);
    }
}
