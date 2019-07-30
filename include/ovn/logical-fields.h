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

#ifndef OVN_LOGICAL_FIELDS_H
#define OVN_LOGICAL_FIELDS_H 1

#include "openvswitch/meta-flow.h"

struct shash;

enum ovn_controller_event {
    OVN_EVENT_EMPTY_LB_BACKENDS = 0,
    OVN_EVENT_MAX,
};

/* Logical fields.
 *
 * These values are documented in ovn-architecture(7), please update the
 * documentation if you change any of them. */
#define MFF_LOG_DATAPATH MFF_METADATA /* Logical datapath (64 bits). */
#define MFF_LOG_FLAGS      MFF_REG10  /* One of MLF_* (32 bits). */
#define MFF_LOG_DNAT_ZONE  MFF_REG11  /* conntrack dnat zone for gateway router
                                       * (32 bits). */
#define MFF_LOG_SNAT_ZONE  MFF_REG12  /* conntrack snat zone for gateway router
                                       * (32 bits). */
#define MFF_LOG_CT_ZONE    MFF_REG13  /* Logical conntrack zone for lports
                                       * (32 bits). */
#define MFF_LOG_INPORT     MFF_REG14  /* Logical input port (32 bits). */
#define MFF_LOG_OUTPORT    MFF_REG15  /* Logical output port (32 bits). */

/* Logical registers.
 *
 * Make sure these don't overlap with the logical fields! */
#define MFF_LOG_REG0 MFF_REG0
#define MFF_N_LOG_REGS 10

void ovn_init_symtab(struct shash *symtab);

/* MFF_LOG_FLAGS_REG bit assignments */
enum mff_log_flags_bits {
    MLF_ALLOW_LOOPBACK_BIT = 0,
    MLF_RCV_FROM_VXLAN_BIT = 1,
    MLF_FORCE_SNAT_FOR_DNAT_BIT = 2,
    MLF_FORCE_SNAT_FOR_LB_BIT = 3,
    MLF_LOCAL_ONLY_BIT = 4,
    MLF_NESTED_CONTAINER_BIT = 5,
};

/* MFF_LOG_FLAGS_REG flag assignments */
enum mff_log_flags {
    /* Allow outputting back to inport. */
    MLF_ALLOW_LOOPBACK = (1 << MLF_ALLOW_LOOPBACK_BIT),

    /* Indicate that a packet was received from a VXLAN tunnel to
     * compensate for the lack of egress port information available in
     * VXLAN encapsulation.  Egress port information is available for
     * Geneve and STT tunnel types. */
    MLF_RCV_FROM_VXLAN = (1 << MLF_RCV_FROM_VXLAN_BIT),

    /* Indicate that a packet needs a force SNAT in the gateway router when
     * DNAT has taken place. */
    MLF_FORCE_SNAT_FOR_DNAT = (1 << MLF_FORCE_SNAT_FOR_DNAT_BIT),

    /* Indicate that a packet needs a force SNAT in the gateway router when
     * load-balancing has taken place. */
    MLF_FORCE_SNAT_FOR_LB = (1 << MLF_FORCE_SNAT_FOR_LB_BIT),

    /* Indicate that a packet that should be distributed across multiple
     * hypervisors should instead only be output to local targets
     */
    MLF_LOCAL_ONLY = (1 << MLF_LOCAL_ONLY_BIT),

    /* Indicate that a packet was received from a nested container. */
    MLF_NESTED_CONTAINER = (1 << MLF_NESTED_CONTAINER_BIT),
};

/* OVN logical fields
 * ===================
 * These are the fields which OVN supports modifying which gets translated
 * to OFFlow controller action.
 *
 * OpenvSwitch doesn't support modifying these fields yet. If a field is
 * supported later by OpenvSwitch, it can be deleted from here.
 */

enum ovn_field_id {
    /*
     * Name: "icmp4.frag_mtu" -
     * Type: be16
     * Description: Sets the low-order 16 bits of the ICMP4 header field
     * (that is labelled "unused" in the ICMP specification) of the ICMP4
     * packet as per the RFC 1191.
     */
    OVN_ICMP4_FRAG_MTU,

    OVN_FIELD_N_IDS
};

struct ovn_field {
    enum ovn_field_id id;
    const char *name;
    unsigned int n_bytes;       /* Width of the field in bytes. */
    unsigned int n_bits;        /* Number of significant bits in field. */
};

static inline const struct ovn_field *
ovn_field_from_id(enum ovn_field_id id)
{
    extern const struct ovn_field ovn_fields[OVN_FIELD_N_IDS];
    ovs_assert((unsigned int) id < OVN_FIELD_N_IDS);
    return &ovn_fields[id];
}

const char *event_to_string(enum ovn_controller_event event);
int string_to_event(const char *s);
const struct ovn_field *ovn_field_from_name(const char *name);
void ovn_destroy_ovnfields(void);
#endif /* ovn/lib/logical-fields.h */
