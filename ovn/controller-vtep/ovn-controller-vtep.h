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


#ifndef OVN_CONTROLLER_VTEP_H
#define OVN_CONTROLLER_VTEP_H 1

#include "ovn/lib/ovn-sb-idl.h"

struct ovsdb_idl;
struct ovsdb_idl_txn;

struct controller_vtep_ctx {
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnsb_idl_txn;

    struct ovsdb_idl *vtep_idl;
    struct ovsdb_idl_txn *vtep_idl_txn;
};

/* VTEP needs what VTEP needs. */
#define OVN_SB_ENCAP_TYPE "vxlan"
#define VTEP_ENCAP_TYPE "vxlan_over_ipv4"

static inline const struct sbrec_chassis *
get_chassis_by_name(struct ovsdb_idl *ovnsb_idl, const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ovnsb_idl) {
        if (!strcmp(chassis_rec->name, chassis_id)) {
            break;
        }
    }

    return chassis_rec;
}

#endif /* ovn/ovn-controller-vtep.h */
