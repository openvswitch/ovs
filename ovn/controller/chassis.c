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

#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(chassis);

void
chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
}

void
chassis_run(struct controller_ctx *ctx, const char *chassis_id)
{
    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    const struct sbrec_chassis *chassis_rec;
    const struct ovsrec_open_vswitch *cfg;
    const char *encap_type, *encap_ip;
    struct sbrec_encap *encap_rec;
    static bool inited = false;

    chassis_rec = get_chassis_by_name(ctx->ovnsb_idl, chassis_id);

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

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                              "ovn-controller: registering chassis '%s'",
                              chassis_id);

    if (!chassis_rec) {
        chassis_rec = sbrec_chassis_insert(ctx->ovnsb_idl_txn);
        sbrec_chassis_set_name(chassis_rec, chassis_id);
    }

    encap_rec = sbrec_encap_insert(ctx->ovnsb_idl_txn);

    sbrec_encap_set_type(encap_rec, encap_type);
    sbrec_encap_set_ip(encap_rec, encap_ip);

    sbrec_chassis_set_encaps(chassis_rec, &encap_rec, 1);

    inited = true;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
chassis_cleanup(struct controller_ctx *ctx, const char *chassis_id)
{
    if (!chassis_id) {
        return true;
    }

    /* Delete Chassis row. */
    const struct sbrec_chassis *chassis_rec
        = get_chassis_by_name(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return true;
    }
    if (ctx->ovnsb_idl_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  chassis_id);
        sbrec_chassis_delete(chassis_rec);
    }
    return false;
}
