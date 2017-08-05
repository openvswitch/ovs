/*
 * Copyright (c) 2017 Intel, Inc.
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

#ifndef OPENVSWITCH_OFP_ED_PROPS_H
#define OPENVSWITCH_OFP_ED_PROPS_H 1

#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"
#include "openvswitch/ofpbuf.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum ofp_ed_prop_class {
    OFPPPC_BASIC = 0,            /* ONF Basic class. */
    OFPPPC_MPLS  = 1,            /* MPLS property class. */
    OFPPPC_GRE   = 2,            /* GRE property class. */
    OFPPPC_GTP   = 3,            /* GTP property class. */
    OFPPPC_NSH   = 4,            /* NSH property class */

    /* Experimenter property class.
     *
     * First 32 bits of property data
     * is exp id after that is the experimenter property data.
     */
    OFPPPC_EXPERIMENTER=0xffff
};

enum ofp_ed_nsh_prop_type {
    OFPPPT_PROP_NSH_NONE = 0,    /* unused */
    OFPPPT_PROP_NSH_MDTYPE = 1,  /* property MDTYPE in NSH */
    OFPPPT_PROP_NSH_TLV = 2,     /* property TLV in NSH */
};

/*
 * External representation of encap/decap properties.
 * These must be padded to a multiple of 8 bytes.
 */
struct ofp_ed_prop_header {
    ovs_be16 prop_class;
    uint8_t type;
    uint8_t len;
};

struct ofp_ed_prop_nsh_md_type {
    struct ofp_ed_prop_header header;
    uint8_t md_type;         /* NSH MD type .*/
    uint8_t pad[3];          /* Padding to 8 bytes. */
};

struct ofp_ed_prop_nsh_tlv {
    struct ofp_ed_prop_header header;
    ovs_be16 tlv_class;      /* Metadata class. */
    uint8_t tlv_type;        /* Metadata type including C bit. */
    uint8_t tlv_len;         /* Metadata value length (0-127). */

    /* tlv_len octets of metadata value, padded to a multiple of 8 bytes. */
    uint8_t data[0];
};

/*
 * Internal representation of encap/decap properties
 */
struct ofpact_ed_prop {
    uint16_t prop_class;
    uint8_t type;
    uint8_t len;
};

struct ofpact_ed_prop_nsh_md_type {
    struct ofpact_ed_prop header;
    uint8_t md_type;         /* NSH MD type .*/
    uint8_t pad[3];          /* Padding to 8 bytes. */
};

struct ofpact_ed_prop_nsh_tlv {
    struct ofpact_ed_prop header;
    ovs_be16 tlv_class;      /* Metadata class. */
    uint8_t tlv_type;        /* Metadata type including C bit. */
    uint8_t tlv_len;         /* Metadata value length (0-127). */

    /* tlv_len octets of metadata value, padded to a multiple of 8 bytes. */
    uint8_t data[0];
};
enum ofperr decode_ed_prop(const struct ofp_ed_prop_header **ofp_prop,
                           struct ofpbuf *out, size_t *remaining);
enum ofperr encode_ed_prop(const struct ofpact_ed_prop **prop,
                           struct ofpbuf *out);
bool parse_ed_prop_class(const char *str, uint16_t *prop_class);
bool parse_ed_prop_type(uint16_t prop_class, const char *str, uint8_t *type);
char *parse_ed_prop_value(uint16_t prop_class, uint8_t prop_type,
                          const char *str, struct ofpbuf *out);
char *format_ed_prop_class(const struct ofpact_ed_prop *prop);
char *format_ed_prop_type(const struct ofpact_ed_prop *prop);
void format_ed_prop(struct ds *s, const struct ofpact_ed_prop *prop);

#ifdef  __cplusplus
}
#endif

#endif /* ofp-ed-props.h */
