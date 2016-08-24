/*
 * Copyright (c) 2015 Nicira, Inc.
 * Copyright (c) 2014 Wind River Systems, Inc.
 * Copyright (c) 2015 Avaya, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OVS_LLDP_H
#define OVS_LLDP_H

#include <stdint.h>
#include "dp-packet.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "lldp/lldpd.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "timer.h"

/* Transmit every LLDPD_TX_INTERVAL seconds. */
#define LLDP_DEFAULT_TRANSMIT_INTERVAL_MS (LLDPD_TX_INTERVAL * 1000)

struct flow;
struct netdev;
struct smap;

/* Structure per LLDP instance (at the moment per port when enabled).
 */
struct lldp {
    struct hmap_node    hmap_node;        /* Node in all_lldps list. */
    struct lldpd        *lldpd;
    char                *name;            /* Name of the port. */
    struct timer        tx_timer;         /* Send LLDP when expired. */
    struct hmap         mappings_by_isid; /* "struct" indexed by ISID */
    struct hmap         mappings_by_aux;  /* "struct" indexed by aux */
    struct ovs_list     active_mapping_queue;
    struct ovs_refcount ref_cnt;
    bool                enabled;          /* LLDP enabled on port */
};

/* Configuration specific to Auto Attach.
 */
struct aa_settings {
    char *system_description;
    char *system_name;
};

/* Configuration of Auto Attach mappings.
 */
struct aa_mapping_settings {
    uint32_t isid;
    uint16_t vlan;
};

enum bridge_aa_vlan_oper {
   BRIDGE_AA_VLAN_OPER_UNDEF,
   BRIDGE_AA_VLAN_OPER_ADD,
   BRIDGE_AA_VLAN_OPER_REMOVE
};

/* Bridge Auto Attach operations.  Mostly for adding/removing VLAN on
 * the trunk port connected to the Auto Attach server.
 */
struct bridge_aa_vlan {
    struct ovs_list list_node;
    char *port_name;
    uint16_t vlan;
    enum bridge_aa_vlan_oper oper;
};

void lldp_init(void);
long long int lldp_wait(struct lldp *lldp);
long long int lldp_wake_time(const struct lldp *lldp);
void lldp_run(struct lldpd *cfg);
bool lldp_should_send_packet(struct lldp *cfg);
bool lldp_should_process_flow(struct lldp *lldp, const struct flow *flow);
bool lldp_configure(struct lldp *lldp, const struct smap *cfg);
void lldp_process_packet(struct lldp *cfg, const struct dp_packet *);
void lldp_put_packet(struct lldp *lldp, struct dp_packet *packet,
                     const struct eth_addr eth_src);
void lldpd_assign_cfg_to_protocols(struct lldpd *cfg);
struct lldp * lldp_create(const struct netdev *netdev, const uint32_t mtu,
                          const struct smap *cfg);
struct lldp * lldp_ref(const struct lldp *lldp_);
void lldp_unref(struct lldp *lldp);

int aa_get_vlan_queued(struct ovs_list *list);
unsigned int aa_get_vlan_queue_size(void);
int aa_configure(const struct aa_settings *s);
int aa_mapping_register(void *aux, const struct aa_mapping_settings *s);
int aa_mapping_unregister(void *aux);

/* Used by unit tests */
struct lldp * lldp_create_dummy(void);
void lldp_destroy_dummy(struct lldp *);

#endif /* OVS_LLDP_H */
