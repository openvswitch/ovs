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

#include "patch.h"

#include "hash.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(patch);

static char *
patch_port_name(const char *src, const char *dst)
{
    return xasprintf("patch-%s-to-%s", src, dst);
}

/* Return true if 'port' is a patch port with the specified 'peer'. */
static bool
match_patch_port(const struct ovsrec_port *port, const char *peer)
{
    for (size_t i = 0; i < port->n_interfaces; i++) {
        struct ovsrec_interface *iface = port->interfaces[i];
        if (strcmp(iface->type, "patch")) {
            continue;
        }
        const char *iface_peer = smap_get(&iface->options, "peer");
        if (peer && !strcmp(iface_peer, peer)) {
            return true;
        }
    }
    return false;
}

/* Creates a patch port in bridge 'src' named 'src_name', whose peer is
 * 'dst_name' in bridge 'dst'.  Initializes the patch port's
 * external-ids:ovn-patch-port to 'network'.
 *
 * If such a patch port already exists, removes it from 'existing_ports'. */
static void
create_patch_port(struct controller_ctx *ctx,
                  const char *network,
                  const struct ovsrec_bridge *src, const char *src_name,
                  const struct ovsrec_bridge *dst, const char *dst_name,
                  struct shash *existing_ports)
{
    for (size_t i = 0; i < src->n_ports; i++) {
        if (match_patch_port(src->ports[i], dst_name)) {
            /* Patch port already exists on 'src'. */
            shash_find_and_delete(existing_ports, src->ports[i]->name);
            return;
        }
    }

    ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
            "ovn-controller: creating patch port '%s' from '%s' to '%s'",
            src_name, src->name, dst->name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ctx->ovs_idl_txn);
    ovsrec_interface_set_name(iface, src_name);
    ovsrec_interface_set_type(iface, "patch");
    const struct smap options = SMAP_CONST1(&options, "peer", dst_name);
    ovsrec_interface_set_options(iface, &options);

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ctx->ovs_idl_txn);
    ovsrec_port_set_name(port, src_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap ids = SMAP_CONST1(&ids, "ovn-patch-port", network);
    ovsrec_port_set_external_ids(port, &ids);

    struct ovsrec_port **ports;
    ports = xmalloc(sizeof *ports * (src->n_ports + 1));
    memcpy(ports, src->ports, sizeof *ports * src->n_ports);
    ports[src->n_ports] = port;
    ovsrec_bridge_verify_ports(src);
    ovsrec_bridge_set_ports(src, ports, src->n_ports + 1);

    free(ports);
}

/* Creates a pair of patch ports that connect bridges 'b1' and 'b2', using a
 * port named 'name1' and 'name2' in each respective bridge.
 * external-ids:ovn-patch-port in each port is initialized to 'network'.
 *
 * If one or both of the ports already exists, leaves it there and removes it
 * from 'existing_ports'. */
static void
create_patch_ports(struct controller_ctx *ctx,
                   const char *network,
                   const struct ovsrec_bridge *b1,
                   const struct ovsrec_bridge *b2,
                   struct shash *existing_ports)
{
    char *name1 = patch_port_name(b1->name, b2->name);
    char *name2 = patch_port_name(b2->name, b1->name);
    create_patch_port(ctx, network, b1, name1, b2, name2, existing_ports);
    create_patch_port(ctx, network, b2, name2, b1, name1, existing_ports);
    free(name2);
    free(name1);
}

static void
remove_port(struct controller_ctx *ctx,
            const struct ovsrec_port *port)
{
    const struct ovsrec_bridge *bridge;

    /* We know the port we want to delete, but we have to find the bridge its
     * on to do so.  Note this only runs on a config change that should be
     * pretty rare. */
    OVSREC_BRIDGE_FOR_EACH (bridge, ctx->ovs_idl) {
        size_t i;
        for (i = 0; i < bridge->n_ports; i++) {
            if (bridge->ports[i] != port) {
                continue;
            }
            struct ovsrec_port **new_ports;
            new_ports = xmemdup(bridge->ports,
                    sizeof *new_ports * (bridge->n_ports - 1));
            if (i != bridge->n_ports - 1) {
                /* Removed port was not last */
                new_ports[i] = bridge->ports[bridge->n_ports - 1];
            }
            ovsrec_bridge_verify_ports(bridge);
            ovsrec_bridge_set_ports(bridge, new_ports, bridge->n_ports - 1);
            free(new_ports);
            ovsrec_port_delete(port);
            return;
        }
    }
}

/* Obtains external-ids:ovn-bridge-mappings from OVSDB and adds patch ports for
 * the local bridge mappings.  Removes any patch ports for bridge mappings that
 * already existed from 'existing_ports'. */
static void
add_bridge_mappings(struct controller_ctx *ctx,
                    const struct ovsrec_bridge *br_int,
                    struct shash *existing_ports)
{
    /* Get ovn-bridge-mappings. */
    const char *mappings_cfg = "";
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (cfg) {
        mappings_cfg = smap_get(&cfg->external_ids, "ovn-bridge-mappings");
        if (!mappings_cfg) {
            mappings_cfg = "";
        }
    }

    /* Create patch ports. */
    char *cur, *next, *start;
    next = start = xstrdup(mappings_cfg);
    while ((cur = strsep(&next, ",")) && *cur) {
        char *network, *bridge = cur;
        const struct ovsrec_bridge *ovs_bridge;

        network = strsep(&bridge, ":");
        if (!bridge || !*network || !*bridge) {
            VLOG_ERR("Invalid ovn-bridge-mappings configuration: '%s'",
                    mappings_cfg);
            break;
        }

        ovs_bridge = get_bridge(ctx->ovs_idl, bridge);
        if (!ovs_bridge) {
            VLOG_WARN("Bridge '%s' not found for network '%s'",
                    bridge, network);
            continue;
        }

        create_patch_ports(ctx, network, br_int, ovs_bridge, existing_ports);
    }
    free(start);
}

void
patch_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
{
    if (!ctx->ovs_idl_txn) {
        return;
    }

    /* Figure out what patch ports already exist. */
    struct shash existing_ports = SHASH_INITIALIZER(&existing_ports);
    const struct ovsrec_port *port;
    OVSREC_PORT_FOR_EACH (port, ctx->ovs_idl) {
        if (smap_get(&port->external_ids, "ovn-patch-port")) {
            shash_add(&existing_ports, port->name, port);
        }
    }

    /* Create in the database any patch ports that should exist.  Remove from
     * 'existing_ports' any patch ports that do exist in the database and
     * should be there. */
    add_bridge_mappings(ctx, br_int, &existing_ports);

    /* Now 'existing_ports' only still contains patch ports that exist in the
     * database but shouldn't.  Delete them from the database. */
    struct shash_node *port_node, *port_next_node;
    SHASH_FOR_EACH_SAFE (port_node, port_next_node, &existing_ports) {
        struct ovsrec_port *port = port_node->data;
        shash_delete(&existing_ports, port_node);
        remove_port(ctx, port);
    }
    shash_destroy(&existing_ports);
}
