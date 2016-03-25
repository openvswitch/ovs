/* aa-structs.h */
/* contains tlv structures for various auto attach functionality */

/* Copyright (c) 2015 Nicira, Inc.
 * Copyright (c) 2014 Avaya, Inc
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef AA_STRUCTS_H
#define AA_STRUCTS_H

#include <stdint.h>
#include "openvswitch/list.h"

struct lldp_aa_element_system_id {
    struct eth_addr system_mac;
    uint16_t conn_type;
    uint16_t rsvd;
    uint8_t  rsvd2[2];
};

struct lldpd_aa_element_tlv {
    uint16_t                         type;
    uint16_t                         vlan_tagging;
    uint16_t                         auto_prov_mode;
    uint16_t                         mgmt_vlan;
    struct lldp_aa_element_system_id system_id;
};

struct lldpd_aa_isid_vlan_map_data {
    uint16_t status;
    uint16_t vlan;
    uint32_t isid;
};

struct lldpd_aa_isid_vlan_maps_tlv {
    struct ovs_list                     m_entries;
    struct lldpd_aa_isid_vlan_map_data  isid_vlan_data;
};

#endif
