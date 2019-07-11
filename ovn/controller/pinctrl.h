
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

#ifndef PINCTRL_H
#define PINCTRL_H 1

#include <stdint.h>

#include "lib/sset.h"
#include "openvswitch/meta-flow.h"

struct hmap;
struct lport_index;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct sbrec_chassis;
struct sbrec_dns_table;
struct sbrec_controller_event_table;

void pinctrl_init(void);
void pinctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                 struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                 struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                 struct ovsdb_idl_index *sbrec_port_binding_by_key,
                 struct ovsdb_idl_index *sbrec_port_binding_by_name,
                 struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                 const struct sbrec_dns_table *,
                 const struct sbrec_controller_event_table *,
                 const struct ovsrec_bridge *, const struct sbrec_chassis *,
                 const struct hmap *local_datapaths,
                 const struct sset *active_tunnels);
void pinctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn);
void pinctrl_destroy(void);

#endif /* ovn/pinctrl.h */
