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

#include "lib/dynamic-string.h"
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

static const char *
pop_tunnel_name(uint32_t *type)
{
    if (*type & GENEVE) {
        *type &= ~GENEVE;
        return "geneve";
    } else if (*type & STT) {
        *type &= ~STT;
        return "stt";
    } else if (*type & VXLAN) {
        *type &= ~VXLAN;
        return "vxlan";
    }

    OVS_NOT_REACHED();
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
    static bool inited = false;

    chassis_rec = get_chassis(ctx->ovnsb_idl, chassis_id);

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

    char *tokstr = xstrdup(encap_type);
    char *save_ptr = NULL;
    char *token;
    uint32_t req_tunnels = 0;
    for (token = strtok_r(tokstr, ",", &save_ptr); token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        uint32_t type = get_tunnel_type(token);
        if (!type) {
            VLOG_INFO("Unknown tunnel type: %s", token);
        }
        req_tunnels |= type;
    }
    free(tokstr);

    if (chassis_rec) {
        /* Compare desired tunnels against those currently in the database. */
        uint32_t cur_tunnels = 0;
        bool same = true;
        for (int i = 0; i < chassis_rec->n_encaps; i++) {
            cur_tunnels |= get_tunnel_type(chassis_rec->encaps[i]->type);
            same = same && !strcmp(chassis_rec->encaps[i]->ip, encap_ip);
        }
        same = same && req_tunnels == cur_tunnels;

        if (same) {
            /* Nothing changed. */
            inited = true;
            return;
        } else if (!inited) {
            struct ds cur_encaps = DS_EMPTY_INITIALIZER;
            for (int i = 0; i < chassis_rec->n_encaps; i++) {
                ds_put_format(&cur_encaps, "%s,",
                              chassis_rec->encaps[i]->type);
            }
            ds_chomp(&cur_encaps, ',');

            VLOG_WARN("Chassis config changing on startup, make sure "
                      "multiple chassis are not configured : %s/%s->%s/%s",
                      ds_cstr(&cur_encaps),
                      chassis_rec->encaps[0]->ip,
                      encap_type, encap_ip);
            ds_destroy(&cur_encaps);
        }
    }

    ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                              "ovn-controller: registering chassis '%s'",
                              chassis_id);

    if (!chassis_rec) {
        chassis_rec = sbrec_chassis_insert(ctx->ovnsb_idl_txn);
        sbrec_chassis_set_name(chassis_rec, chassis_id);
    }

    int n_encaps = count_1bits(req_tunnels);
    struct sbrec_encap **encaps = xmalloc(n_encaps * sizeof *encaps);
    for (int i = 0; i < n_encaps; i++) {
        const char *type = pop_tunnel_name(&req_tunnels);

        encaps[i] = sbrec_encap_insert(ctx->ovnsb_idl_txn);

        sbrec_encap_set_type(encaps[i], type);
        sbrec_encap_set_ip(encaps[i], encap_ip);
    }

    sbrec_chassis_set_encaps(chassis_rec, encaps, n_encaps);
    free(encaps);

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
        = get_chassis(ctx->ovnsb_idl, chassis_id);
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
