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

#include <config.h>
#include <arpa/inet.h>
#include "openvswitch/ofp-ed-props.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-parse.h"
#include "util.h"
#include "lib/packets.h"


enum ofperr
decode_ed_prop(const struct ofp_ed_prop_header **ofp_prop,
               struct ofpbuf *out OVS_UNUSED,
               size_t *remaining)
{
    uint16_t prop_class = ntohs((*ofp_prop)->prop_class);
    size_t len = (*ofp_prop)->len;
    size_t pad_len = ROUND_UP(len, 8);

    if (pad_len > *remaining) {
        return OFPERR_OFPBAC_BAD_LEN;
    }

    switch (prop_class) {
    default:
        return OFPERR_NXBAC_UNKNOWN_ED_PROP;
    }

    *remaining -= pad_len;
    *ofp_prop = ALIGNED_CAST(const struct ofp_ed_prop_header *,
                             ((char *)(*ofp_prop) + pad_len));
    return 0;
}

enum ofperr
encode_ed_prop(const struct ofpact_ed_prop **prop,
               struct ofpbuf *out OVS_UNUSED)
{
    size_t prop_len;

    switch ((*prop)->prop_class) {
    default:
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    *prop = ALIGNED_CAST(const struct ofpact_ed_prop *,
                         ((char *)(*prop) + prop_len));
    return 0;
}

bool
parse_ed_prop_class(const char *str OVS_UNUSED,
                    uint16_t *prop_class)
{
    if (!strcmp(str,"basic")) {
        *prop_class = OFPPPC_BASIC;
    } else if (!strcmp(str,"ethernet")) {
        *prop_class = OFPPPC_BASIC;
    } else if (!strcmp(str,"mpls")) {
        *prop_class = OFPPPC_MPLS;
    } else if (!strcmp(str,"gre")) {
        *prop_class = OFPPPC_GRE;
    } else if (!strcmp(str,"gtp")) {
        *prop_class = OFPPPC_GTP;
    } else {
        return false;
    }
    return true;
}

bool
parse_ed_prop_type(uint16_t prop_class,
                   const char *str OVS_UNUSED,
                   uint8_t *type OVS_UNUSED)
{
    switch (prop_class) {
    default:
        return false;
    }
}

/* Parse the value of an encap/decap property based on property class
 * and type and append the parsed property in internal format to the
 * ofpbuf out.
 * Returns a malloced string in the event of a parse error. The caller
 * must free the string.
 */

char *
parse_ed_prop_value(uint16_t prop_class, uint8_t prop_type OVS_UNUSED,
                    const char *value, struct ofpbuf *out OVS_UNUSED)
{

    if (value == NULL || *value == '\0') {
        return xstrdup("Value missing for encap property");
    }

    switch (prop_class) {
    default:
        /* Unsupported property classes rejected before. */
        OVS_NOT_REACHED();
    }

    return NULL;
}

char *
format_ed_prop_class(const struct ofpact_ed_prop *prop)
{
    switch (prop->prop_class) {
    case OFPPPC_BASIC:
        return "basic";
    case OFPPPC_MPLS:
        return "mpls";
    case OFPPPC_GRE:
        return "gre";
    case OFPPPC_GTP:
        return "gtp";
    default:
        OVS_NOT_REACHED();
    }
}

char *
format_ed_prop_type(const struct ofpact_ed_prop *prop)
{
    switch (prop->prop_class) {
    default:
        OVS_NOT_REACHED();
    }
}

void
format_ed_prop(struct ds *s OVS_UNUSED,
                     const struct ofpact_ed_prop *prop)
{
    switch (prop->prop_class) {
    default:
        OVS_NOT_REACHED();
    }
}
