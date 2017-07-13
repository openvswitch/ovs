/* Copyright (c) 2017 Red Hat, Inc.
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

#ifndef OVN_GCHASSIS_H
#define OVN_GCHASSIS_H 1

#include <stdint.h>
#include "lib/uuid.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

struct chassis_index;
struct ovsdb_idl;
struct sbrec_chassis;
struct sbrec_gateway_chassis;
struct sbrec_port_binding;
struct sset;


/* Gateway_Chassis management
 * ==========================
 *
 * The following structure and methods handle ordering of Gateway_Chassis
 * entries in a chassisredirect port. And parsing redirect-chassis option
 * for backwards compatibility with older (N-1 version of ovn-northd).
 */
struct gateway_chassis {
    struct ovs_list node;
    const struct sbrec_gateway_chassis *db; /* sbrec row for the gwc */
    bool virtual_gwc; /* db entry not from SBDB, but from redirect-chassis */
};

/* Gets, and orders by priority/name the list of Gateway_Chassis */
struct ovs_list *gateway_chassis_get_ordered(
        const struct sbrec_port_binding *binding,
        const struct chassis_index *chassis_index);

/* Checks if an specific chassis is contained in the gateway_chassis
 * list */
bool gateway_chassis_contains(const struct ovs_list *gateway_chassis,
                              const struct sbrec_chassis *chassis);

/* Destroy a gateway_chassis list from memory */
void gateway_chassis_destroy(struct ovs_list *list);

/* Checks if a chassis is referenced in the port_binding gateway_chassis
 * list or redirect-chassis option (backwards compatibility) */
bool gateway_chassis_in_pb_contains(
        const struct sbrec_port_binding *binding,
        const struct sbrec_chassis *chassis);

/* Returns true if the local chassis is the active gateway among a set
 * of gateway_chassis.  Return false if the local chassis is currently a
 * backup in a set of multiple gateway_chassis. */
bool gateway_chassis_is_active(
        const struct ovs_list *gateway_chassis,
        const struct sbrec_chassis *local_chassis,
        const struct sset *active_tunnels);
#endif /* ovn/controller/gchassis.h */
