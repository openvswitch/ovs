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

#include "lib/sset.h"
#include "lport.h"
#include "hash.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
VLOG_DEFINE_THIS_MODULE(lport);

static struct ovsdb_idl_index_cursor lport_by_name_cursor;
static struct ovsdb_idl_index_cursor lport_by_key_cursor;
static struct ovsdb_idl_index_cursor dpath_by_key_cursor;
static struct ovsdb_idl_index_cursor mc_grp_by_dp_name_cursor;



/* Finds and returns the port binding record with the given 'name',
 * or NULL if no such port binding exists. */
const struct sbrec_port_binding *
lport_lookup_by_name(struct ovsdb_idl *idl, const char *name)
{
    struct sbrec_port_binding *value;
    const struct sbrec_port_binding *pb, *retval =  NULL;

    /* Build key for an indexed lookup. */
    value = sbrec_port_binding_index_init_row(idl, &sbrec_table_port_binding);
    sbrec_port_binding_index_set_logical_port(value, name);

    /* Find an entry with matching logical port name. Since this column is
     * declared to be an index in the OVN_Southbound schema, the first match
     * (if any) will be the only match. */
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, &lport_by_name_cursor, value) {
        retval = pb;
        break;
    }

    sbrec_port_binding_index_destroy_row(value);

    return retval;
}

/* Finds and returns the datapath binding record with tunnel_key equal to the
 * given 'dp_key', or NULL if no such datapath binding exists. */
const struct sbrec_datapath_binding *
datapath_lookup_by_key(struct ovsdb_idl *idl, uint64_t dp_key)
{
    struct sbrec_datapath_binding *dbval;
    const struct sbrec_datapath_binding *db, *retval = NULL;

    /* Build key for an indexed lookup. */
    dbval = sbrec_datapath_binding_index_init_row(idl,
                                                &sbrec_table_datapath_binding);
    sbrec_datapath_binding_index_set_tunnel_key(dbval, dp_key);

    /* Find an entry with matching tunnel_key. Since this column is declared
     * to be an index in the OVN_Southbound schema, the first match (if any)
     * will be the only match. */
    SBREC_DATAPATH_BINDING_FOR_EACH_EQUAL (db, &dpath_by_key_cursor, dbval) {
        retval = db;
        break;
    }
    sbrec_datapath_binding_index_destroy_row(dbval);

    return retval;
}

/* Finds and returns the port binding record with tunnel_key equal to the
 * given 'port_key' and datapath binding matching 'dp_key', or NULL if no
 * such port binding exists. */
const struct sbrec_port_binding *
lport_lookup_by_key(struct ovsdb_idl *idl, uint64_t dp_key, uint64_t port_key)
{
    struct sbrec_port_binding *pbval;
    const struct sbrec_port_binding *pb, *retval = NULL;
    const struct sbrec_datapath_binding *db;

    /* Lookup datapath corresponding to dp_key. */
    db = datapath_lookup_by_key(idl, dp_key);
    if (!db) {
        return NULL;
    }

    /* Build key for an indexed lookup. */
    pbval = sbrec_port_binding_index_init_row(idl, &sbrec_table_port_binding);
    sbrec_port_binding_index_set_datapath(pbval, db);
    sbrec_port_binding_index_set_tunnel_key(pbval, port_key);

    /* Find an entry with matching tunnel_key and datapath UUID. Since this
     * column pair is declared to be an index in the OVN_Southbound schema,
     * the first match (if any) will be the only match. */
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, &lport_by_key_cursor, pbval) {
        retval = pb;
        break;
    }
    sbrec_port_binding_index_destroy_row(pbval);

    return retval;
}

/* Finds and returns the logical multicast group with the given 'name' and
 * datapath binding, or NULL if no such logical multicast group exists. */
const struct sbrec_multicast_group *
mcgroup_lookup_by_dp_name(struct ovsdb_idl *idl,
                           const struct sbrec_datapath_binding *dp,
                           const char *name)
{
    struct sbrec_multicast_group *mcval;
    const struct sbrec_multicast_group *mc, *retval = NULL;

    /* Build key for an indexed lookup. */
    mcval = sbrec_multicast_group_index_init_row(idl,
                                                 &sbrec_table_multicast_group);
    sbrec_multicast_group_index_set_name(mcval, name);
    sbrec_multicast_group_index_set_datapath(mcval, dp);

    /* Find an entry with matching logical multicast group name and datapath.
     * Since this column pair is declared to be an index in the OVN_Southbound
     * schema, the first match (if any) will be the only match. */
    SBREC_MULTICAST_GROUP_FOR_EACH_EQUAL (mc, &mc_grp_by_dp_name_cursor,
                                          mcval) {
        retval = mc;
        break;
    }

    sbrec_multicast_group_index_destroy_row(mcval);

    return retval;
}

void
lport_init(struct ovsdb_idl *idl)
{
    /* Create a cursor for searching multicast group table by datapath
     * and group name. */
    ovsdb_idl_initialize_cursor(idl, &sbrec_table_multicast_group,
                                "multicast-group-by-dp-name",
                                &mc_grp_by_dp_name_cursor);

    /* Create cursor to search port binding table by logical port name. */
    ovsdb_idl_initialize_cursor(idl, &sbrec_table_port_binding,
                                "lport-by-name",
                                &lport_by_name_cursor);

    /* Create cursor to search port binding table by logical port tunnel key
     * and datapath uuid. */
    ovsdb_idl_initialize_cursor(idl, &sbrec_table_port_binding, "lport-by-key",
                                &lport_by_key_cursor);

    /* Create cursor to search datapath binding table by tunnel key. */
    ovsdb_idl_initialize_cursor(idl, &sbrec_table_datapath_binding,
                                "dpath-by-key", &dpath_by_key_cursor);
}
