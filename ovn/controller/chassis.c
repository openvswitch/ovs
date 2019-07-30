/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include <unistd.h>

#include "chassis.h"

#include "lib/smap.h"
#include "lib/sset.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofp-parse.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"
#include "lib/util.h"

VLOG_DEFINE_THIS_MODULE(chassis);

#ifndef HOST_NAME_MAX
/* For windows. */
#define HOST_NAME_MAX 255
#endif /* HOST_NAME_MAX */

/*
 * Structure to hold chassis specific state (currently just chassis-id)
 * to avoid database lookups when changes happen while the controller is
 * running.
 */
struct chassis_info {
    /* Last ID we initialized the Chassis SB record with. */
    struct ds id;

    /* True if Chassis SB record is initialized, false otherwise. */
    uint32_t id_inited : 1;
};

static struct chassis_info chassis_state = {
    .id = DS_EMPTY_INITIALIZER,
    .id_inited = false,
};

static void
chassis_info_set_id(struct chassis_info *info, const char *id)
{
    ds_clear(&info->id);
    ds_put_cstr(&info->id, id);
    info->id_inited = true;
}

static bool
chassis_info_id_inited(const struct chassis_info *info)
{
    return info->id_inited;
}

static const char *
chassis_info_id(const struct chassis_info *info)
{
    return ds_cstr_ro(&info->id);
}

/*
 * Structure for storing the chassis config parsed from the ovs table.
 */
struct ovs_chassis_cfg {
    /* Single string fields parsed from external-ids. */
    const char *hostname;
    const char *bridge_mappings;
    const char *datapath_type;
    const char *encap_csum;
    const char *cms_options;
    const char *chassis_macs;

    /* Set of encap types parsed from the 'ovn-encap-type' external-id. */
    struct sset encap_type_set;
    /* Set of encap IPs parsed from the 'ovn-encap-type' external-id. */
    struct sset encap_ip_set;
    /* Interface type list formatted in the OVN-SB Chassis required format. */
    struct ds iface_types;
};

static void
ovs_chassis_cfg_init(struct ovs_chassis_cfg *cfg)
{
    sset_init(&cfg->encap_type_set);
    sset_init(&cfg->encap_ip_set);
    ds_init(&cfg->iface_types);
}

static void
ovs_chassis_cfg_destroy(struct ovs_chassis_cfg *cfg)
{
    sset_destroy(&cfg->encap_type_set);
    sset_destroy(&cfg->encap_ip_set);
    ds_destroy(&cfg->iface_types);
}

void
chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_datapath_type);
}

static const char *
get_hostname(const struct smap *ext_ids)
{
    const char *hostname = smap_get_def(ext_ids, "hostname", "");

    if (strlen(hostname) == 0) {
        static char hostname_[HOST_NAME_MAX + 1];

        if (gethostname(hostname_, sizeof(hostname_))) {
            hostname_[0] = 0;
        }

        return &hostname_[0];
    }

    return hostname;
}

static const char *
get_bridge_mappings(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-bridge-mappings", "");
}

static const char *
get_chassis_mac_mappings(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-chassis-mac-mappings", "");
}

static const char *
get_cms_options(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-cms-options", "");
}

static const char *
get_encap_csum(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-encap-csum", "true");
}

static const char *
get_datapath_type(const struct ovsrec_bridge *br_int)
{
    if (br_int && br_int->datapath_type) {
        return br_int->datapath_type;
    }

    return "";
}

static void
update_chassis_transport_zones(const struct sset *transport_zones,
                               const struct sbrec_chassis *chassis_rec)
{
    struct sset chassis_tzones_set = SSET_INITIALIZER(&chassis_tzones_set);
    for (int i = 0; i < chassis_rec->n_transport_zones; i++) {
        sset_add(&chassis_tzones_set, chassis_rec->transport_zones[i]);
    }

    /* Only update the transport zones if something changed */
    if (!sset_equals(transport_zones, &chassis_tzones_set)) {
        const char **ls_arr = sset_array(transport_zones);
        sbrec_chassis_set_transport_zones(chassis_rec, ls_arr,
                                          sset_count(transport_zones));
        free(ls_arr);
    }

    sset_destroy(&chassis_tzones_set);
}

/*
 * Parse an ovs 'encap_type' string and stores the resulting types in the
 * 'encap_type_set' string set.
 */
static bool
chassis_parse_ovs_encap_type(const char *encap_type,
                             struct sset *encap_type_set)
{
    sset_from_delimited_string(encap_type_set, encap_type, ",");

    const char *type;

    SSET_FOR_EACH (type, encap_type_set) {
        if (!get_tunnel_type(type)) {
            VLOG_INFO("Unknown tunnel type: %s", type);
        }
    }

    return true;
}

/*
 * Parse an ovs 'encap_ip' string and stores the resulting IP representations
 * in the 'encap_ip_set' string set.
 */
static bool
chassis_parse_ovs_encap_ip(const char *encap_ip, struct sset *encap_ip_set)
{
    sset_from_delimited_string(encap_ip_set, encap_ip, ",");
    return true;
}

/*
 * Parse the ovs 'iface_types' and store them in the format required by the
 * Chassis record.
 */
static bool
chassis_parse_ovs_iface_types(char **iface_types, size_t n_iface_types,
                              struct ds *iface_types_str)
{
    for (size_t i = 0; i < n_iface_types; i++) {
        ds_put_format(iface_types_str, "%s,", iface_types[i]);
    }
    ds_chomp(iface_types_str, ',');
    return true;
}

/*
 * Parse the 'ovs_table' entry and populate 'ovs_cfg'.
 */
static bool
chassis_parse_ovs_config(const struct ovsrec_open_vswitch_table *ovs_table,
                         const struct ovsrec_bridge *br_int,
                         struct ovs_chassis_cfg *ovs_cfg)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);

    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return false;
    }

    const char *encap_type = smap_get(&cfg->external_ids, "ovn-encap-type");
    const char *encap_ips = smap_get(&cfg->external_ids, "ovn-encap-ip");
    if (!encap_type || !encap_ips) {
        VLOG_INFO("Need to specify an encap type and ip");
        return false;
    }

    ovs_cfg->hostname = get_hostname(&cfg->external_ids);
    ovs_cfg->bridge_mappings = get_bridge_mappings(&cfg->external_ids);
    ovs_cfg->datapath_type = get_datapath_type(br_int);
    ovs_cfg->encap_csum = get_encap_csum(&cfg->external_ids);
    ovs_cfg->cms_options = get_cms_options(&cfg->external_ids);
    ovs_cfg->chassis_macs = get_chassis_mac_mappings(&cfg->external_ids);

    if (!chassis_parse_ovs_encap_type(encap_type, &ovs_cfg->encap_type_set)) {
        return false;
    }

    if (!chassis_parse_ovs_encap_ip(encap_ips, &ovs_cfg->encap_ip_set)) {
        sset_destroy(&ovs_cfg->encap_type_set);
        return false;
    }

    if (!chassis_parse_ovs_iface_types(cfg->iface_types,
                                       cfg->n_iface_types,
                                       &ovs_cfg->iface_types)) {
        sset_destroy(&ovs_cfg->encap_type_set);
        sset_destroy(&ovs_cfg->encap_ip_set);
    }

    return true;
}

static void
chassis_build_external_ids(struct smap *ext_ids, const char *bridge_mappings,
                           const char *datapath_type, const char *cms_options,
                           const char *chassis_macs, const char *iface_types)
{
    smap_replace(ext_ids, "ovn-bridge-mappings", bridge_mappings);
    smap_replace(ext_ids, "datapath-type", datapath_type);
    smap_replace(ext_ids, "ovn-cms-options", cms_options);
    smap_replace(ext_ids, "iface-types", iface_types);
    smap_replace(ext_ids, "ovn-chassis-mac-mappings", chassis_macs);
}

/*
 * Returns true if any external-id doesn't match the values in 'chassis-rec'.
 */
static bool
chassis_external_ids_changed(const char *bridge_mappings,
                             const char *datapath_type,
                             const char *cms_options,
                             const char *chassis_macs,
                             const struct ds *iface_types,
                             const struct sbrec_chassis *chassis_rec)
{
    const char *chassis_bridge_mappings =
        get_bridge_mappings(&chassis_rec->external_ids);

    if (strcmp(bridge_mappings, chassis_bridge_mappings)) {
        return true;
    }

    const char *chassis_datapath_type =
        smap_get_def(&chassis_rec->external_ids, "datapath-type", "");

    if (strcmp(datapath_type, chassis_datapath_type)) {
        return true;
    }

    const char *chassis_cms_options =
        get_cms_options(&chassis_rec->external_ids);

    if (strcmp(cms_options, chassis_cms_options)) {
        return true;
    }

    const char *chassis_mac_mappings =
        get_chassis_mac_mappings(&chassis_rec->external_ids);
    if (strcmp(chassis_macs, chassis_mac_mappings)) {
        return true;
    }

    const char *chassis_iface_types =
        smap_get_def(&chassis_rec->external_ids, "iface-types", "");

    if (strcmp(ds_cstr_ro(iface_types), chassis_iface_types)) {
        return true;
    }

    return false;
}

/*
 * Returns true if the tunnel config obtained by combining 'encap_type_set'
 * with 'encap_ip_set' and 'encap_csum' doesn't match the values in
 * 'chassis-rec'.
 */
static bool
chassis_tunnels_changed(const struct sset *encap_type_set,
                        const struct sset *encap_ip_set,
                        const char *encap_csum,
                        const struct sbrec_chassis *chassis_rec)
{
    size_t encap_type_count = 0;

    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        if (strcmp(chassis_rec->name, chassis_rec->encaps[i]->chassis_name)) {
            return true;
        }

        if (!sset_contains(encap_type_set, chassis_rec->encaps[i]->type)) {
            return true;
        }
        encap_type_count++;

        if (!sset_contains(encap_ip_set, chassis_rec->encaps[i]->ip)) {
            return true;
        }

        if (strcmp(smap_get_def(&chassis_rec->encaps[i]->options, "csum", ""),
                   encap_csum)) {
            return true;
        }
    }

    size_t tunnel_count =
        sset_count(encap_type_set) * sset_count(encap_ip_set);

    if (tunnel_count != chassis_rec->n_encaps) {
        return true;
    }

    if (sset_count(encap_type_set) != encap_type_count) {
        return true;
    }

    return false;
}

/*
 * Build the new encaps config (full mesh of 'encap_type_set' and
 * 'encap_ip_set'). Allocates and stores the new 'n_encap' Encap records in
 * 'encaps'.
 */
static struct sbrec_encap **
chassis_build_encaps(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sset *encap_type_set,
                     const struct sset *encap_ip_set,
                     const char *chassis_id,
                     const char *encap_csum,
                     size_t *n_encap)
{
    size_t tunnel_count = 0;

    struct sbrec_encap **encaps =
        xmalloc(sset_count(encap_type_set) * sset_count(encap_ip_set) *
                sizeof(*encaps));
    const struct smap options = SMAP_CONST1(&options, "csum", encap_csum);

    const char *encap_ip;
    const char *encap_type;

    SSET_FOR_EACH (encap_ip, encap_ip_set) {
        SSET_FOR_EACH (encap_type, encap_type_set) {
            struct sbrec_encap *encap = sbrec_encap_insert(ovnsb_idl_txn);

            sbrec_encap_set_type(encap, encap_type);
            sbrec_encap_set_ip(encap, encap_ip);
            sbrec_encap_set_options(encap, &options);
            sbrec_encap_set_chassis_name(encap, chassis_id);

            encaps[tunnel_count] = encap;
            tunnel_count++;
        }
    }

    *n_encap = tunnel_count;
    return encaps;
}

/*
 * Returns a pointer to a chassis record from 'chassis_table' that
 * matches at least one tunnel config.
 */
static const struct sbrec_chassis *
chassis_get_stale_record(const struct sbrec_chassis_table *chassis_table,
                         const struct ovs_chassis_cfg *ovs_cfg,
                         const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    SBREC_CHASSIS_TABLE_FOR_EACH (chassis_rec, chassis_table) {
        for (size_t i = 0; i < chassis_rec->n_encaps; i++) {
            if (sset_contains(&ovs_cfg->encap_type_set,
                              chassis_rec->encaps[i]->type) &&
                    sset_contains(&ovs_cfg->encap_ip_set,
                                  chassis_rec->encaps[i]->ip)) {
                return chassis_rec;
            }
            if (strcmp(chassis_rec->name, chassis_id) == 0) {
                return chassis_rec;
            }
        }
    }

    return NULL;
}

/* If this is a chassis config update after we initialized the record once
 * then we should always be able to find it with the ID we saved in
 * chassis_state.
 * Otherwise (i.e., first time we create the record) then we check if there's
 * a stale record from a previous controller run that didn't end gracefully
 * and reuse it. If not then we create a new record.
 */
static const struct sbrec_chassis *
chassis_get_record(struct ovsdb_idl_txn *ovnsb_idl_txn,
                   struct ovsdb_idl_index *sbrec_chassis_by_name,
                   const struct sbrec_chassis_table *chassis_table,
                   const struct ovs_chassis_cfg *ovs_cfg,
                   const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    if (chassis_info_id_inited(&chassis_state)) {
        chassis_rec = chassis_lookup_by_name(sbrec_chassis_by_name,
                                             chassis_info_id(&chassis_state));
        if (!chassis_rec) {
            VLOG_WARN("Could not find Chassis : stored (%s) ovs (%s)",
                      chassis_info_id(&chassis_state), chassis_id);
        }
    } else {
        chassis_rec =
            chassis_get_stale_record(chassis_table, ovs_cfg, chassis_id);

        if (!chassis_rec && ovnsb_idl_txn) {
            chassis_rec = sbrec_chassis_insert(ovnsb_idl_txn);
        }
    }
    return chassis_rec;
}

/* Update a Chassis record based on the config in the ovs config. */
static void
chassis_update(const struct sbrec_chassis *chassis_rec,
               struct ovsdb_idl_txn *ovnsb_idl_txn,
               const struct ovs_chassis_cfg *ovs_cfg,
               const char *chassis_id,
               const struct sset *transport_zones)
{
    if (strcmp(chassis_id, chassis_rec->name)) {
        sbrec_chassis_set_name(chassis_rec, chassis_id);
    }

    if (strcmp(ovs_cfg->hostname, chassis_rec->hostname)) {
        sbrec_chassis_set_hostname(chassis_rec, ovs_cfg->hostname);
    }

    if (chassis_external_ids_changed(ovs_cfg->bridge_mappings,
                                     ovs_cfg->datapath_type,
                                     ovs_cfg->cms_options,
                                     ovs_cfg->chassis_macs,
                                     &ovs_cfg->iface_types,
                                     chassis_rec)) {
        struct smap ext_ids;

        smap_clone(&ext_ids, &chassis_rec->external_ids);
        chassis_build_external_ids(&ext_ids, ovs_cfg->bridge_mappings,
                                   ovs_cfg->datapath_type,
                                   ovs_cfg->cms_options,
                                   ovs_cfg->chassis_macs,
                                   ds_cstr_ro(&ovs_cfg->iface_types));
        sbrec_chassis_verify_external_ids(chassis_rec);
        sbrec_chassis_set_external_ids(chassis_rec, &ext_ids);
        smap_destroy(&ext_ids);
    }

    update_chassis_transport_zones(transport_zones, chassis_rec);

    /* If any of the encaps should change, update them. */
    bool tunnels_changed =
        chassis_tunnels_changed(&ovs_cfg->encap_type_set,
                                &ovs_cfg->encap_ip_set, ovs_cfg->encap_csum,
                                chassis_rec);
    if (!tunnels_changed) {
        return;
    }

    struct sbrec_encap **encaps;
    size_t n_encap;

    encaps =
        chassis_build_encaps(ovnsb_idl_txn, &ovs_cfg->encap_type_set,
                             &ovs_cfg->encap_ip_set, chassis_id,
                             ovs_cfg->encap_csum, &n_encap);
    sbrec_chassis_set_encaps(chassis_rec, encaps, n_encap);
    free(encaps);
}

/* Returns this chassis's Chassis record, if it is available. */
const struct sbrec_chassis *
chassis_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_chassis_by_name,
            const struct ovsrec_open_vswitch_table *ovs_table,
            const struct sbrec_chassis_table *chassis_table,
            const char *chassis_id,
            const struct ovsrec_bridge *br_int,
            const struct sset *transport_zones)
{
    struct ovs_chassis_cfg ovs_cfg;

    /* Get the chassis config from the ovs table. */
    ovs_chassis_cfg_init(&ovs_cfg);
    if (!chassis_parse_ovs_config(ovs_table, br_int, &ovs_cfg)) {
        return NULL;
    }

    const struct sbrec_chassis *chassis_rec =
        chassis_get_record(ovnsb_idl_txn, sbrec_chassis_by_name,
                           chassis_table, &ovs_cfg, chassis_id);

    /* If we found (or created) a record, update it with the correct config
     * and store the current chassis_id for fast lookup in case it gets
     * modified in the ovs table.
     */
    if (chassis_rec && ovnsb_idl_txn) {
        chassis_update(chassis_rec, ovnsb_idl_txn, &ovs_cfg, chassis_id,
                       transport_zones);
        chassis_info_set_id(&chassis_state, chassis_id);
        ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                                  "ovn-controller: registering chassis '%s'",
                                  chassis_id);
    }

    ovs_chassis_cfg_destroy(&ovs_cfg);
    return chassis_rec;
}

bool
chassis_get_mac(const struct sbrec_chassis *chassis_rec,
                const char *bridge_mapping,
                struct eth_addr *chassis_mac)
{
    const char *tokens
        = get_chassis_mac_mappings(&chassis_rec->external_ids);
    if (!tokens[0]) {
       return false;
    }

    char *save_ptr = NULL;
    bool ret = false;
    char *tokstr = xstrdup(tokens);

    /* Format for a chassis mac configuration is:
     * ovn-chassis-mac-mappings="bridge-name1:MAC1,bridge-name2:MAC2"
     */
    for (char *token = strtok_r(tokstr, ",", &save_ptr);
         token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        char *save_ptr2 = NULL;
        char *chassis_mac_bridge = strtok_r(token, ":", &save_ptr2);
        char *chassis_mac_str = strtok_r(NULL, "", &save_ptr2);

        if (!strcmp(chassis_mac_bridge, bridge_mapping)) {
            struct eth_addr temp_mac;

            /* Return the first chassis mac. */
            char *err_str = str_to_mac(chassis_mac_str, &temp_mac);
            if (err_str) {
                free(err_str);
                continue;
            }

            ret = true;
            *chassis_mac = temp_mac;
            break;
        }
    }

    free(tokstr);
    return ret;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
chassis_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct sbrec_chassis *chassis_rec)
{
    if (!chassis_rec) {
        return true;
    }
    if (ovnsb_idl_txn) {
        ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  chassis_rec->name);
        sbrec_chassis_delete(chassis_rec);
    }
    return false;
}

/*
 * Returns the last initialized chassis-id.
 */
const char *
chassis_get_id(void)
{
    if (chassis_info_id_inited(&chassis_state)) {
        return chassis_info_id(&chassis_state);
    }

    return NULL;
}
