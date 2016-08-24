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
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "lib/smap.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "ovn-controller-vtep.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "vtep/vtep-idl.h"

VLOG_DEFINE_THIS_MODULE(vtep);

struct vtep_rec_physical_locator_list_entry {
    struct ovs_list locators_node;
    const struct vteprec_physical_locator *vteprec_ploc;
};

struct mmr_hash_node_data {
    const struct vteprec_mcast_macs_remote *mmr;
    struct shash physical_locators;
};

/*
 * Scans through the Binding table in ovnsb, and updates the vtep logical
 * switch tunnel keys and the 'Ucast_Macs_Remote' table in the VTEP
 * database.
 *
 */

/* Searches the 'chassis_rec->encaps' for the first vtep tunnel
 * configuration, returns the 'ip'.  Unless duplicated, the returned
 * pointer cannot live past current vtep_run() execution. */
static const char *
get_chassis_vtep_ip(const struct sbrec_chassis *chassis_rec)
{
    if (chassis_rec) {
        size_t i;

        for (i = 0; i < chassis_rec->n_encaps; i++) {
            if (!strcmp(chassis_rec->encaps[i]->type, "vxlan")) {
                return chassis_rec->encaps[i]->ip;
            }
        }
    }

    return NULL;
}

/* Creates a new 'Ucast_Macs_Remote'. */
static struct vteprec_ucast_macs_remote *
create_umr(struct ovsdb_idl_txn *vtep_idl_txn, const char *mac,
           const struct vteprec_logical_switch *vtep_ls)
{
    struct vteprec_ucast_macs_remote *new_umr =
        vteprec_ucast_macs_remote_insert(vtep_idl_txn);

    vteprec_ucast_macs_remote_set_MAC(new_umr, mac);
    vteprec_ucast_macs_remote_set_logical_switch(new_umr, vtep_ls);

    return new_umr;
}

/* Creates a new 'Physical_Locator'. */
static struct vteprec_physical_locator *
create_pl(struct ovsdb_idl_txn *vtep_idl_txn, const char *chassis_ip)
{
    struct vteprec_physical_locator *new_pl =
        vteprec_physical_locator_insert(vtep_idl_txn);

    vteprec_physical_locator_set_dst_ip(new_pl, chassis_ip);
    vteprec_physical_locator_set_encapsulation_type(new_pl, VTEP_ENCAP_TYPE);

    return new_pl;
}

/* Creates a new 'Mcast_Macs_Remote'. */
static void
vtep_create_mmr(struct ovsdb_idl_txn *vtep_idl_txn, const char *mac,
                const struct vteprec_logical_switch *vtep_ls,
                const struct vteprec_physical_locator_set *ploc_set)
{
    struct vteprec_mcast_macs_remote *new_mmr =
       vteprec_mcast_macs_remote_insert(vtep_idl_txn);

    vteprec_mcast_macs_remote_set_MAC(new_mmr, mac);
    vteprec_mcast_macs_remote_set_logical_switch(new_mmr, vtep_ls);
    vteprec_mcast_macs_remote_set_locator_set(new_mmr, ploc_set);
}

/* Compares previous and new mmr locator sets and returns true if they
 * differ and false otherwise. This function also preps a new locator
 * set for database write.
 *
 * 'locators_list' is the new set of locators for the associated
 * 'Mcast_Macs_Remote' entry passed in and is queried to generate the
 * new set of locators in vtep database format. */
static bool
vtep_process_pls(const struct ovs_list *locators_list,
                 const struct mmr_hash_node_data *mmr_ext,
                 struct vteprec_physical_locator **locators)
{
    size_t n_locators_prev = 0;
    size_t n_locators_new = ovs_list_size(locators_list);
    bool locator_lists_differ = false;

    if (mmr_ext) {
        n_locators_prev = mmr_ext->mmr->locator_set->n_locators;
    }
    if (n_locators_prev != n_locators_new) {
        locator_lists_differ = true;
    }

    if (n_locators_new) {
        int i = 0;
        struct vtep_rec_physical_locator_list_entry *ploc_entry;
        LIST_FOR_EACH (ploc_entry, locators_node, locators_list) {
            locators[i] = (struct vteprec_physical_locator *)
                           ploc_entry->vteprec_ploc;
            if (mmr_ext && !shash_find_data(&mmr_ext->physical_locators,
                                            locators[i]->dst_ip)) {
                    locator_lists_differ = true;
            }
            i++;
        }
    }

    return locator_lists_differ;
}

/* Creates a new 'Mcast_Macs_Remote' entry if needed and also cleans up
 * out-dated remote mcast mac entries as needed. */
static void
vtep_update_mmr(struct ovsdb_idl_txn *vtep_idl_txn,
                struct ovs_list *locators_list,
                const struct vteprec_logical_switch *vtep_ls,
                const struct mmr_hash_node_data *mmr_ext)
{
    struct vteprec_physical_locator **locators = NULL;
    size_t n_locators_new = ovs_list_size(locators_list);
    bool mmr_changed;

    locators = xmalloc(n_locators_new * sizeof *locators);

    mmr_changed = vtep_process_pls(locators_list, mmr_ext, locators);

    if (mmr_ext && !n_locators_new) {
        vteprec_mcast_macs_remote_delete(mmr_ext->mmr);
    } else if ((mmr_ext && mmr_changed) ||
               (!mmr_ext && n_locators_new)) {

        const struct vteprec_physical_locator_set *ploc_set =
            vteprec_physical_locator_set_insert(vtep_idl_txn);

        vtep_create_mmr(vtep_idl_txn, "unknown-dst", vtep_ls, ploc_set);

        vteprec_physical_locator_set_set_locators(ploc_set, locators,
                                                  n_locators_new);
    }
    free(locators);
}

/* Updates the vtep Logical_Switch table entries' tunnel keys based
 * on the port bindings. */
static void
vtep_lswitch_run(struct shash *vtep_pbs, struct sset *vtep_pswitches,
                 struct shash *vtep_lswitches)
{
    struct sset used_ls = SSET_INITIALIZER(&used_ls);
    struct shash_node *node;

    /* Collects the logical switch bindings from port binding entries.
     * Since the binding module has already guaranteed that each vtep
     * logical switch is bound only to one ovn-sb logical datapath,
     * we can just iterate and assign tunnel key to vtep logical switch. */
    SHASH_FOR_EACH (node, vtep_pbs) {
        const struct sbrec_port_binding *port_binding_rec = node->data;
        const char *pswitch_name = smap_get(&port_binding_rec->options,
                                            "vtep-physical-switch");
        const char *lswitch_name = smap_get(&port_binding_rec->options,
                                            "vtep-logical-switch");
        const struct vteprec_logical_switch *vtep_ls;

        /* If 'port_binding_rec->chassis' exists then 'pswitch_name'
         * and 'lswitch_name' must also exist. */
        if (!pswitch_name || !lswitch_name) {
            /* This could only happen when someone directly modifies the
             * database,  (e.g. using ovn-sbctl). */
            VLOG_ERR("logical port (%s) with no 'options:vtep-physical-"
                     "switch' or 'options:vtep-logical-switch' specified "
                     "is bound to chassis (%s).",
                     port_binding_rec->logical_port,
                     port_binding_rec->chassis->name);
            continue;
        }
        vtep_ls = shash_find_data(vtep_lswitches, lswitch_name);
        /* Also checks 'pswitch_name' since the same 'lswitch_name' could
         * exist in multiple vtep database instances and be bound to different
         * ovn logical networks. */
        if (vtep_ls && sset_find(vtep_pswitches, pswitch_name)) {
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

            /* OVN is expected to always use source node replication mode,
             * hence the replication mode is hard-coded for each logical
             * switch in the context of ovn-controller-vtep. */
            vteprec_logical_switch_set_replication_mode(vtep_ls, "source_node");
            sset_add(&used_ls, lswitch_name);
        }
    }
    /* Resets the tunnel keys for unused vtep logical switches. */
    SHASH_FOR_EACH (node, vtep_lswitches) {
        if (!sset_find(&used_ls, node->name)) {
            int64_t tnl_key = 0;
            vteprec_logical_switch_set_tunnel_key(node->data, &tnl_key, 1);
        }
    }
    sset_destroy(&used_ls);
}

/* Updates the vtep 'Ucast_Macs_Remote' and 'Mcast_Macs_Remote' tables based
 * on non-vtep port bindings. */
static void
vtep_macs_run(struct ovsdb_idl_txn *vtep_idl_txn, struct shash *ucast_macs_rmts,
              struct shash *mcast_macs_rmts, struct shash *physical_locators,
              struct shash *vtep_lswitches, struct shash *non_vtep_pbs)
{
    struct shash_node *node;
    struct hmap ls_map;

    /* Maps from ovn logical datapath tunnel key (which is also the vtep
     * logical switch tunnel key) to the corresponding vtep logical switch
     * instance.  Also, the shash map 'added_macs' is used for checking
     * duplicated MAC addresses in the same ovn logical datapath. 'mmr_ext'
     * is used to track mmr info per LS that needs creation/update and
     * 'locators_list' collects the new physical locators to be bound for
     * an mmr_ext; 'physical_locators' is used to track existing locators and
     * filter duplicates per logical switch. */
    struct ls_hash_node {
        struct hmap_node hmap_node;

        const struct vteprec_logical_switch *vtep_ls;
        struct shash added_macs;

        struct ovs_list locators_list;
        struct shash physical_locators;
        struct mmr_hash_node_data *mmr_ext;
    };

    hmap_init(&ls_map);
    SHASH_FOR_EACH (node, vtep_lswitches) {
        const struct vteprec_logical_switch *vtep_ls = node->data;
        struct ls_hash_node *ls_node;

        if (!vtep_ls->n_tunnel_key) {
            continue;
        }
        ls_node = xmalloc(sizeof *ls_node);
        ls_node->vtep_ls = vtep_ls;
        shash_init(&ls_node->added_macs);
        shash_init(&ls_node->physical_locators);
        ovs_list_init(&ls_node->locators_list);
        ls_node->mmr_ext = NULL;
        hmap_insert(&ls_map, &ls_node->hmap_node,
                    hash_uint64((uint64_t) vtep_ls->tunnel_key[0]));
    }

    SHASH_FOR_EACH (node, non_vtep_pbs) {
        const struct sbrec_port_binding *port_binding_rec = node->data;
        const struct sbrec_chassis *chassis_rec;
        struct ls_hash_node *ls_node;
        const char *chassis_ip;
        int64_t tnl_key;
        size_t i;

        chassis_rec = port_binding_rec->chassis;
        if (!chassis_rec) {
            continue;
        }

        tnl_key = port_binding_rec->datapath->tunnel_key;
        HMAP_FOR_EACH_WITH_HASH (ls_node, hmap_node,
                                 hash_uint64((uint64_t) tnl_key),
                                 &ls_map) {
            if (ls_node->vtep_ls->tunnel_key[0] == tnl_key) {
                break;
            }
        }
        /* If 'ls_node' is NULL, that means no vtep logical switch is
         * attached to the corresponding ovn logical datapath, so pass.
         */
        if (!ls_node) {
            continue;
        }

        chassis_ip = get_chassis_vtep_ip(chassis_rec);
        /* Unreachable chassis, continue. */
        if (!chassis_ip) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_INFO_RL(&rl, "VTEP tunnel encap on chassis (%s) not found",
                         chassis_rec->name);
            continue;
        }

        const struct vteprec_physical_locator *pl =
            shash_find_data(physical_locators, chassis_ip);
        if (!pl) {
            pl = create_pl(vtep_idl_txn, chassis_ip);
            shash_add(physical_locators, chassis_ip, pl);
        }

        const struct vteprec_physical_locator *ls_pl =
            shash_find_data(&ls_node->physical_locators, chassis_ip);
        if (!ls_pl) {
            struct vtep_rec_physical_locator_list_entry *ploc_entry =
                xmalloc(sizeof *ploc_entry);
            ploc_entry->vteprec_ploc = pl;
            ovs_list_push_back(&ls_node->locators_list,
                               &ploc_entry->locators_node);
            shash_add(&ls_node->physical_locators, chassis_ip, pl);
        }

        char *mac_tnlkey = xasprintf("%s_%"PRId64, "unknown-dst", tnl_key);
        ls_node->mmr_ext = shash_find_data(mcast_macs_rmts, mac_tnlkey);

        if (ls_node->mmr_ext &&
            ls_node->mmr_ext->mmr->logical_switch == ls_node->vtep_ls) {

            /* Delete the entry from the hash table so the mmr does not get
             * removed from the DB later on during stale checking. */
            shash_find_and_delete(mcast_macs_rmts, mac_tnlkey);
        }
        free(mac_tnlkey);

        for (i = 0; i < port_binding_rec->n_mac; i++) {
            const struct vteprec_ucast_macs_remote *umr;
            const struct sbrec_port_binding *conflict;
            char *mac = port_binding_rec->mac[i];

            /* Checks for duplicate MAC in the same vtep logical switch. */
            conflict = shash_find_data(&ls_node->added_macs, mac);
            if (conflict) {
                VLOG_WARN("MAC address (%s) has already been known to be "
                          "on logical port (%s) in the same logical "
                          "datapath, so just ignore this logical port (%s)",
                          mac, conflict->logical_port,
                          port_binding_rec->logical_port);
                continue;
            }
            shash_add(&ls_node->added_macs, mac, port_binding_rec);

            char *mac_ip_tnlkey = xasprintf("%s_%s_%"PRId64, mac, chassis_ip,
                                            tnl_key);
            umr = shash_find_data(ucast_macs_rmts, mac_ip_tnlkey);
            /* If finds the 'umr' entry for the mac, ip, and tnl_key, deletes
             * the entry from shash so that it is not gargage collected.
             *
             * If not found, creates a new 'umr' entry. */
            if (umr && umr->logical_switch == ls_node->vtep_ls) {
                shash_find_and_delete(ucast_macs_rmts, mac_ip_tnlkey);
            } else {
                const struct vteprec_ucast_macs_remote *new_umr;
                new_umr = create_umr(vtep_idl_txn, mac, ls_node->vtep_ls);
                vteprec_ucast_macs_remote_set_locator(new_umr, pl);
            }
            free(mac_ip_tnlkey);
        }
    }

    /* Removes all remaining 'umr's, since they do not exist anymore. */
    SHASH_FOR_EACH (node, ucast_macs_rmts) {
        vteprec_ucast_macs_remote_delete(node->data);
    }
    struct ls_hash_node *iter, *next;
    HMAP_FOR_EACH_SAFE (iter, next, hmap_node, &ls_map) {
        struct vtep_rec_physical_locator_list_entry *ploc_entry;
        vtep_update_mmr(vtep_idl_txn, &iter->locators_list,
                        iter->vtep_ls, iter->mmr_ext);
        LIST_FOR_EACH_POP(ploc_entry, locators_node,
                          &iter->locators_list) {
            free(ploc_entry);
        }
        hmap_remove(&ls_map, &iter->hmap_node);
        shash_destroy(&iter->added_macs);
        shash_destroy(&iter->physical_locators);
        free(iter);
    }
    hmap_destroy(&ls_map);

    /* Clean stale 'Mcast_Macs_Remote' */
    struct mmr_hash_node_data *mmr_ext;
    SHASH_FOR_EACH (node, mcast_macs_rmts) {
        mmr_ext = node->data;
        vteprec_mcast_macs_remote_delete(mmr_ext->mmr);
    }
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

/* Removes all entries in the 'Ucast_Macs_Remote' table in the vtep database.
 * Returns true when all done (i.e. no entry to remove). */
static bool
vtep_ucast_macs_cleanup(struct ovsdb_idl *vtep_idl)
{
    const struct vteprec_ucast_macs_remote *umr;

    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (umr, vtep_idl) {
        vteprec_ucast_macs_remote_delete(umr);
        return false;
    }

    return true;
}

/* Removes all entries in the 'Mcast_Macs_Remote' table in vtep database.
 * Returns true when all done (i.e. no entry to remove). */
static bool
vtep_mcast_macs_cleanup(struct ovsdb_idl *vtep_idl)
{
    const struct vteprec_mcast_macs_remote *mmr;

    VTEPREC_MCAST_MACS_REMOTE_FOR_EACH (mmr, vtep_idl) {
        vteprec_mcast_macs_remote_delete(mmr);
        return false;
    }

    return true;
}

/* Updates vtep logical switch tunnel keys. */
void
vtep_run(struct controller_vtep_ctx *ctx)
{
    if (!ctx->vtep_idl_txn) {
        return;
    }

    struct sset vtep_pswitches = SSET_INITIALIZER(&vtep_pswitches);
    struct shash vtep_lswitches = SHASH_INITIALIZER(&vtep_lswitches);
    struct shash ucast_macs_rmts = SHASH_INITIALIZER(&ucast_macs_rmts);
    struct shash mcast_macs_rmts = SHASH_INITIALIZER(&mcast_macs_rmts);
    struct shash physical_locators = SHASH_INITIALIZER(&physical_locators);
    struct shash vtep_pbs = SHASH_INITIALIZER(&vtep_pbs);
    struct shash non_vtep_pbs = SHASH_INITIALIZER(&non_vtep_pbs);
    const struct vteprec_physical_switch *vtep_ps;
    const struct vteprec_logical_switch *vtep_ls;
    const struct vteprec_ucast_macs_remote *umr;
    const struct sbrec_port_binding *port_binding_rec;
    const struct vteprec_mcast_macs_remote *mmr;
    struct shash_node *node;

    /* Collects 'Physical_Switch's. */
    VTEPREC_PHYSICAL_SWITCH_FOR_EACH (vtep_ps, ctx->vtep_idl) {
        sset_add(&vtep_pswitches, vtep_ps->name);
    }

    /* Collects 'Logical_Switch's. */
    VTEPREC_LOGICAL_SWITCH_FOR_EACH (vtep_ls, ctx->vtep_idl) {
        shash_add(&vtep_lswitches, vtep_ls->name, vtep_ls);
    }

    /* Collects 'Ucast_Macs_Remote's. */
    VTEPREC_UCAST_MACS_REMOTE_FOR_EACH (umr, ctx->vtep_idl) {
        char *mac_ip_tnlkey =
            xasprintf("%s_%s_%"PRId64, umr->MAC,
                      umr->locator ? umr->locator->dst_ip : "",
                      umr->logical_switch && umr->logical_switch->n_tunnel_key
                          ? umr->logical_switch->tunnel_key[0] : INT64_MAX);

        shash_add(&ucast_macs_rmts, mac_ip_tnlkey, umr);
        free(mac_ip_tnlkey);
    }

    /* Collects 'Mcast_Macs_Remote's. */
    VTEPREC_MCAST_MACS_REMOTE_FOR_EACH (mmr, ctx->vtep_idl) {
        struct mmr_hash_node_data *mmr_ext = xmalloc(sizeof *mmr_ext);;
        char *mac_tnlkey =
            xasprintf("%s_%"PRId64, mmr->MAC,
                      mmr->logical_switch && mmr->logical_switch->n_tunnel_key
                          ? mmr->logical_switch->tunnel_key[0] : INT64_MAX);

        shash_add(&mcast_macs_rmts, mac_tnlkey, mmr_ext);
        mmr_ext->mmr = mmr;

        shash_init(&mmr_ext->physical_locators);
        for (size_t i = 0; i < mmr->locator_set->n_locators; i++) {
            shash_add(&mmr_ext->physical_locators,
                      mmr->locator_set->locators[i]->dst_ip,
                      mmr->locator_set->locators[i]);
        }

        free(mac_tnlkey);
    }

    /* Collects 'Physical_Locator's. */
    const struct vteprec_physical_locator *pl;
    VTEPREC_PHYSICAL_LOCATOR_FOR_EACH (pl, ctx->vtep_idl) {
        shash_add(&physical_locators, pl->dst_ip, pl);
    }

    /* Collects and classifies 'Port_Binding's. */
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->ovnsb_idl) {
        struct shash *target =
            !strcmp(port_binding_rec->type, "vtep") ? &vtep_pbs : &non_vtep_pbs;

        if (!port_binding_rec->chassis) {
            continue;
        }
        shash_add(target, port_binding_rec->logical_port, port_binding_rec);
    }

    ovsdb_idl_txn_add_comment(ctx->vtep_idl_txn,
                              "ovn-controller-vtep: update logical switch "
                              "tunnel keys and 'ucast_macs_remote's");

    vtep_lswitch_run(&vtep_pbs, &vtep_pswitches, &vtep_lswitches);
    vtep_macs_run(ctx->vtep_idl_txn, &ucast_macs_rmts,
                  &mcast_macs_rmts, &physical_locators,
                  &vtep_lswitches, &non_vtep_pbs);

    sset_destroy(&vtep_pswitches);
    shash_destroy(&vtep_lswitches);
    shash_destroy(&ucast_macs_rmts);
    SHASH_FOR_EACH (node, &mcast_macs_rmts) {
        struct mmr_hash_node_data *mmr_ext = node->data;
        shash_destroy(&mmr_ext->physical_locators);
        free(mmr_ext);
    }
    shash_destroy(&mcast_macs_rmts);
    shash_destroy(&physical_locators);
    shash_destroy(&vtep_pbs);
    shash_destroy(&non_vtep_pbs);
}

/* Cleans up all related entries in vtep.  Returns true when done (i.e. there
 * is no change made to 'ctx->vtep_idl'), otherwise returns false. */
bool
vtep_cleanup(struct controller_vtep_ctx *ctx)
{
    if (!ctx->vtep_idl_txn) {
        return false;
    }

    bool all_done;

    ovsdb_idl_txn_add_comment(ctx->vtep_idl_txn,
                              "ovn-controller-vtep: cleaning up vtep "
                              "configuration");
    all_done = vtep_lswitch_cleanup(ctx->vtep_idl);
    all_done = vtep_ucast_macs_cleanup(ctx->vtep_idl) && all_done;
    all_done = vtep_mcast_macs_cleanup(ctx->vtep_idl) && all_done;

    return all_done;
}
