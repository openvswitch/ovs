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
#include "encaps.h"
#include "binding.h"
#include "lflow.h"
#include "lport.h"

#include "lib/hash.h"
#include "lib/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(encaps);

void
encaps_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_options);
}

/* Enough context to create a new tunnel, using tunnel_add(). */
struct tunnel_ctx {
    /* Reverse mapping from an encap entry to it's parent chassis to
     * allow updating the overall tunnel when any property changes. */
    struct hmap encap_chassis_hmap;

    /* Table of chassis (indexed by chassis ID) to their tunnel ports in OVS. */
    struct hmap chassis_hmap;

    /* Names of all ports in the bridge, to allow checking uniqueness when
     * adding a new tunnel. */
    struct sset port_names;

    struct ovsdb_idl_txn *ovs_txn;
    const struct ovsrec_bridge *br_int;
};

static struct tunnel_ctx tc = {
    .encap_chassis_hmap = HMAP_INITIALIZER(&tc.encap_chassis_hmap),
    .chassis_hmap = HMAP_INITIALIZER(&tc.chassis_hmap),
    .port_names = SSET_INITIALIZER(&tc.port_names),
};

static char *
tunnel_create_name(const char *chassis_id)
{
    int i;

    for (i = 0; i < UINT16_MAX; i++) {
        char *port_name;
        port_name = xasprintf("ovn-%.6s-%x", chassis_id, i);

        if (!sset_contains(&tc.port_names, port_name)) {
            return port_name;
        }

        free(port_name);
    }

    return NULL;
}

struct encap_hash_node {
    struct hmap_node node;
    struct uuid encap_uuid;

    char *chassis_id;
    struct uuid chassis_uuid;
};

static struct encap_hash_node *
lookup_encap_uuid(const struct uuid *uuid)
{
    struct encap_hash_node *hash_node;
    HMAP_FOR_EACH_WITH_HASH (hash_node, node, uuid_hash(uuid),
                             &tc.encap_chassis_hmap) {
        if (uuid_equals(uuid, &hash_node->encap_uuid)) {
            return hash_node;
        }
    }
    return NULL;
}

static void
insert_encap_uuid(const struct uuid *uuid,
                  const struct sbrec_chassis *chassis_rec)
{
    struct encap_hash_node *hash_node = xmalloc(sizeof *hash_node);

    hash_node->encap_uuid = *uuid;
    hash_node->chassis_id = xstrdup(chassis_rec->name);
    hash_node->chassis_uuid = chassis_rec->header_.uuid;
    hmap_insert(&tc.encap_chassis_hmap, &hash_node->node,
                uuid_hash(&hash_node->encap_uuid));
}

static void
delete_encap_uuid(struct encap_hash_node *encap_hash_node)
{
    hmap_remove(&tc.encap_chassis_hmap, &encap_hash_node->node);
    free(encap_hash_node->chassis_id);
    free(encap_hash_node);
}

struct chassis_hash_node {
    struct hmap_node node;
    char *chassis_id;

    char *port_name;
    struct uuid chassis_uuid;
    struct uuid port_uuid;
};

static struct chassis_hash_node *
lookup_chassis_id(const char *chassis_id)
{
    struct chassis_hash_node *hash_node;
    HMAP_FOR_EACH_WITH_HASH (hash_node, node, hash_string(chassis_id, 0),
                             &tc.chassis_hmap) {
        if (!strcmp(chassis_id, hash_node->chassis_id)) {
            return hash_node;
        }
    }
    return NULL;
}

static void
insert_chassis_id(const char *chassis_id, const char *port_name,
                  const struct uuid *chassis_uuid)
{
    struct chassis_hash_node *hash_node = xmalloc(sizeof *hash_node);

    hash_node->chassis_id = xstrdup(chassis_id);
    hash_node->port_name = xstrdup(port_name);
    hash_node->chassis_uuid = *chassis_uuid;
    /* We don't know the port's UUID until it has been inserted into the
     * database, store zeros for now. It will get updated the next time we
     * wake up. */
    uuid_zero(&hash_node->port_uuid);
    hmap_insert(&tc.chassis_hmap, &hash_node->node, hash_string(chassis_id, 0));
}

static void
delete_chassis_id(struct chassis_hash_node *chassis_hash_node)
{
    hmap_remove(&tc.chassis_hmap, &chassis_hash_node->node);
    free(chassis_hash_node->chassis_id);
    free(chassis_hash_node->port_name);
    free(chassis_hash_node);
}

static void
tunnel_add(const struct sbrec_chassis *chassis_rec,
           const struct sbrec_encap *encap)
{
    const char *new_chassis_id = chassis_rec->name;
    struct smap options = SMAP_INITIALIZER(&options);
    struct ovsrec_port *port, **ports;
    struct ovsrec_interface *iface;
    const char *csum = smap_get(&encap->options, "csum");
    char *port_name;
    size_t i;

    port_name = tunnel_create_name(new_chassis_id);
    if (!port_name) {
        VLOG_WARN("Unable to allocate unique name for '%s' tunnel",
                  new_chassis_id);
        return;
    }

    iface = ovsrec_interface_insert(tc.ovs_txn);
    ovsrec_interface_set_name(iface, port_name);
    ovsrec_interface_set_type(iface, encap->type);
    smap_add(&options, "remote_ip", encap->ip);
    smap_add(&options, "key", "flow");
    if (csum && (!strcmp(csum, "true") || !strcmp(csum, "false"))) {
        smap_add(&options, "csum", csum);
    }
    ovsrec_interface_set_options(iface, &options);
    smap_destroy(&options);

    port = ovsrec_port_insert(tc.ovs_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap id = SMAP_CONST1(&id, "ovn-chassis-id", new_chassis_id);
    ovsrec_port_set_external_ids(port, &id);

    ports = xmalloc(sizeof *tc.br_int->ports * (tc.br_int->n_ports + 1));
    for (i = 0; i < tc.br_int->n_ports; i++) {
        ports[i] = tc.br_int->ports[i];
    }
    ports[tc.br_int->n_ports] = port;
    ovsrec_bridge_verify_ports(tc.br_int);
    ovsrec_bridge_set_ports(tc.br_int, ports, tc.br_int->n_ports + 1);

    insert_chassis_id(new_chassis_id, port_name, &chassis_rec->header_.uuid);
    sset_add(&tc.port_names, port_name);
    free(port_name);
    free(ports);
}

static void
bridge_delete_port(const struct ovsrec_bridge *br,
                   const struct ovsrec_port *port,
                   struct chassis_hash_node *chassis_hash_node)
{
    if (chassis_hash_node) {
        sset_find_and_delete(&tc.port_names, chassis_hash_node->port_name);
        delete_chassis_id(chassis_hash_node);
    }

    if (port) {
        struct ovsrec_port **ports;
        size_t i, n;

        ports = xmalloc(sizeof *br->ports * br->n_ports);
        for (i = n = 0; i < br->n_ports; i++) {
            if (br->ports[i] != port) {
                ports[n++] = br->ports[i];
            }
        }
        ovsrec_bridge_verify_ports(br);
        ovsrec_bridge_set_ports(br, ports, n);
        free(ports);
    }
}

static struct sbrec_encap *
preferred_encap(const struct sbrec_chassis *chassis_rec)
{
    struct sbrec_encap *best_encap = NULL;
    uint32_t best_type = 0;

    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
        if (tun_type > best_type) {
            best_type = tun_type;
            best_encap = chassis_rec->encaps[i];
        }
    }

    return best_encap;
}

static bool
check_and_add_tunnel(const struct sbrec_chassis *chassis_rec,
                     const char *local_chassis_id)
{
    if (strcmp(chassis_rec->name, local_chassis_id)) {
        const struct sbrec_encap *encap = preferred_encap(chassis_rec);
        if (!encap) {
            VLOG_INFO("No supported encaps for '%s'", chassis_rec->name);
            return false;
        }
        tunnel_add(chassis_rec, encap);
        return true;
    }
    return false;
}

static void
check_and_update_tunnel(const struct ovsrec_port *port,
                        const struct sbrec_chassis *chassis_rec)
{
    const struct sbrec_encap *encap = preferred_encap(chassis_rec);
    const struct ovsrec_interface *iface = port->interfaces[0];
    const char *csum = smap_get(&encap->options, "csum");
    const char *existing_csum = smap_get(&iface->options, "csum");

    if (strcmp(encap->type, iface->type)) {
        ovsrec_interface_set_type(iface, encap->type);
    }
    const char *ip = smap_get(&iface->options, "remote_ip");
    if (!ip || strcmp(encap->ip, ip) ||
        (!!csum != !!existing_csum || (csum && strcmp(csum, existing_csum)))) {
        struct smap options = SMAP_INITIALIZER(&options);
        smap_add(&options, "remote_ip", encap->ip);
        smap_add(&options, "key", "flow");
        if (csum && (!strcmp(csum, "true") || !strcmp(csum, "false"))) {
            smap_add(&options, "csum", csum);
        }
        ovsrec_interface_set_options(iface, &options);
        smap_destroy(&options);
    }

    const char *chassis = smap_get_def(&port->external_ids,
                                       "ovn-chassis-id", "");
    if (strcmp(chassis_rec->name, chassis)) {
        const struct smap id = SMAP_CONST1(&id, "ovn-chassis-id",
                                           chassis_rec->name);
        ovsrec_port_set_external_ids(port, &id);
    }
}

void
encaps_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
           const char *local_chassis_id)
{
    if (!ctx->ovs_idl_txn || !br_int) {
        return;
    }

    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_encap *encap_rec;

    tc.br_int = br_int;
    tc.ovs_txn = ctx->ovs_idl_txn;
    ovsdb_idl_txn_add_comment(tc.ovs_txn,
                              "ovn-controller: modifying OVS tunnels '%s'",
                              local_chassis_id);

    /* Generally speaking, the changes that we're interested in and commonly
     * occur happen in the Encap table, so we interate over any changed rows
     * there. Tunnels are set up based on entries in the Chassis table though,
     * so it is necessary to maintain a backwards mapping.
     *
     * In addition to OVN Southbound database changes, it's also possible
     * that OVS's database can get out of sync. This could happen if a
     * port is manually modified or one of our previous transactions failed.
     * If we detect changes to the database and after every attempted
     * transaction, we iterate over all of the ports currently in the database
     * as well as the ones we expect to be there and attempt any repairs. We
     * don't bother to try to do this incrementally since changes are less
     * common. It would also require more bookkeeping to match up ports and
     * interfaces. */

    const struct ovsrec_port *port_rec;
    struct chassis_hash_node *chassis_node, *next;

    sset_clear(&tc.port_names);

    /* Find all of the tunnel ports to remote chassis.
     * Delete the tunnel ports from unknown remote chassis. */
    OVSREC_PORT_FOR_EACH (port_rec, ctx->ovs_idl) {
        sset_add(&tc.port_names, port_rec->name);
        for (int i = 0; i < port_rec->n_interfaces; i++) {
            sset_add(&tc.port_names, port_rec->interfaces[i]->name);
        }

        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id) {
            chassis_node = lookup_chassis_id(chassis_id);
            if (chassis_node) {
                /* Populate the port's UUID the first time we see it after
                 * the port was added. */
                if (uuid_is_zero(&chassis_node->port_uuid)) {
                    chassis_node->port_uuid = port_rec->header_.uuid;
                }
            } else {
                for (int i = 0; i < port_rec->n_interfaces; i++) {
                    sset_find_and_delete(&tc.port_names,
                                         port_rec->interfaces[i]->name);
                }
                sset_find_and_delete(&tc.port_names, port_rec->name);
                bridge_delete_port(tc.br_int, port_rec, NULL);
            }
        }
    }

    /* For each chassis that we previously created, check that both the
     * chassis and port still exist and are current. */
    HMAP_FOR_EACH_SAFE (chassis_node, next, node, &tc.chassis_hmap) {
        chassis_rec = sbrec_chassis_get_for_uuid(ctx->ovnsb_idl,
                                               &chassis_node->chassis_uuid);
        port_rec = ovsrec_port_get_for_uuid(ctx->ovs_idl,
                                            &chassis_node->port_uuid);

        if (!chassis_rec) {
            /* Delete tunnel port (if present) for missing chassis. */
            bridge_delete_port(tc.br_int, port_rec, chassis_node);
            continue;
        }

        if (!port_rec) {
            /* Delete our representation of the chassis, then add back. */
            bridge_delete_port(tc.br_int, NULL, chassis_node);
            check_and_add_tunnel(chassis_rec, local_chassis_id);
        } else {
            /* Update tunnel. */
            check_and_update_tunnel(port_rec, chassis_rec);
        }
    }

    /* Maintain a mapping backwards from encap entries to their parent
     * chassis. Most changes happen at the encap row entry but tunnels need
     * to be established on the basis of the overall chassis. */
    SBREC_CHASSIS_FOR_EACH_TRACKED (chassis_rec, ctx->ovnsb_idl) {
        /* Defer deletion of mapping until we have cleaned up associated
         * ports. */
        if (!sbrec_chassis_is_deleted(chassis_rec)) {
            for (int i = 0; i < chassis_rec->n_encaps; i++) {
                encap_rec = chassis_rec->encaps[i];

                struct encap_hash_node *encap_hash_node;
                encap_hash_node = lookup_encap_uuid(&encap_rec->header_.uuid);
                if (encap_hash_node) {
                    /* A change might have invalidated our mapping. Process the
                     * new version and then iterate over everything to see if it
                     * is OK. */
                    delete_encap_uuid(encap_hash_node);
                    poll_immediate_wake();
                }

                insert_encap_uuid(&encap_rec->header_.uuid, chassis_rec);
            }
        }
    }

    /* Update tunnels based on changes to the Encap table. Once we've detected
     * a change to an encap, we map it back to the parent chassis and add or
     * update the required tunnel. That means that a given changed encap row
     * might actually result in the creation of a different type tunnel if
     * that type is preferred. That's OK - when we process the other encap
     * rows, we'll just skip over the new tunnels. */
    SBREC_ENCAP_FOR_EACH_TRACKED (encap_rec, ctx->ovnsb_idl) {
        struct encap_hash_node *encap_hash_node;
        struct chassis_hash_node *chassis_hash_node;
        const struct ovsrec_port *port_rec = NULL;

        encap_hash_node = lookup_encap_uuid(&encap_rec->header_.uuid);
        if (!encap_hash_node) {
            continue;
        }
        chassis_rec = sbrec_chassis_get_for_uuid(ctx->ovnsb_idl,
                                                &encap_hash_node->chassis_uuid);

        chassis_hash_node = lookup_chassis_id(encap_hash_node->chassis_id);
        if (chassis_hash_node) {
            /* If the UUID is zero it means that we just added the chassis on
             * this spin through encaps_run() - perhaps there are two possible
             * encaps. Presumably the information we had then is the same as
             * we have now, so just skip this. */
            if (uuid_is_zero(&chassis_hash_node->port_uuid)) {
                continue;
            }

            port_rec = ovsrec_port_get_for_uuid(ctx->ovs_idl,
                                                &chassis_hash_node->port_uuid);
        }

        /* Create, update and delete the actual tunnel ports as necessary. */
        if (!port_rec) {
            if (chassis_rec) {
                check_and_add_tunnel(chassis_rec, local_chassis_id);
            }
        } else {
            if (chassis_rec) {
                check_and_update_tunnel(port_rec, chassis_rec);
            } else {
                bridge_delete_port(tc.br_int, port_rec, chassis_hash_node);
            }
        }

        if (!chassis_rec) {
            delete_encap_uuid(encap_hash_node);
        }
    }
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
encaps_cleanup(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
{
    if (!br_int) {
        return true;
    }

    /* Delete all the OVS-created tunnels from the integration bridge. */
    struct ovsrec_port **ports
        = xmalloc(sizeof *br_int->ports * br_int->n_ports);
    size_t n = 0;
    for (size_t i = 0; i < br_int->n_ports; i++) {
        if (!smap_get(&br_int->ports[i]->external_ids, "ovn-chassis-id")) {
            ports[n++] = br_int->ports[i];
        }
    }

    bool any_changes = n != br_int->n_ports;
    if (any_changes && ctx->ovs_idl_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
                                  "ovn-controller: destroying tunnels");
        ovsrec_bridge_verify_ports(br_int);
        ovsrec_bridge_set_ports(br_int, ports, n);
    }
    free(ports);

    return !any_changes;
}
