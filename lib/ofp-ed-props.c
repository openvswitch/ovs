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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "openvswitch/ofp-ed-props.h"
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
    uint8_t prop_type = (*ofp_prop)->type;
    size_t len = (*ofp_prop)->len;
    size_t pad_len = ROUND_UP(len, 8);

    if (len < sizeof **ofp_prop || pad_len > *remaining) {
        return OFPERR_OFPBAC_BAD_LEN;
    }

    switch (prop_class) {
    case OFPPPC_NSH: {
        switch (prop_type) {
        case OFPPPT_PROP_NSH_MDTYPE: {
            struct ofp_ed_prop_nsh_md_type *opnmt =
                ALIGNED_CAST(struct ofp_ed_prop_nsh_md_type *, *ofp_prop);
            if (len > sizeof(*opnmt) || len > *remaining) {
                return OFPERR_NXBAC_BAD_ED_PROP;
            }
            struct ofpact_ed_prop_nsh_md_type *pnmt =
                    ofpbuf_put_uninit(out, sizeof(*pnmt));
            pnmt->header.prop_class = prop_class;
            pnmt->header.type = prop_type;
            pnmt->header.len = len;
            pnmt->md_type = opnmt->md_type;
            break;
        }
        case OFPPPT_PROP_NSH_TLV: {
            struct ofp_ed_prop_nsh_tlv *opnt =
                ALIGNED_CAST(struct ofp_ed_prop_nsh_tlv *, *ofp_prop);
            size_t tlv_pad_len = ROUND_UP(opnt->tlv_len, 8);
            if (len != sizeof(*opnt) + tlv_pad_len || len > *remaining) {
                return OFPERR_NXBAC_BAD_ED_PROP;
            }
            struct ofpact_ed_prop_nsh_tlv *pnt =
                    ofpbuf_put_uninit(out, sizeof(*pnt));
            pnt->header.prop_class = prop_class;
            pnt->header.type = prop_type;
            pnt->header.len = len;
            pnt->tlv_class = opnt->tlv_class;
            pnt->tlv_type = opnt->tlv_type;
            pnt->tlv_len = opnt->tlv_len;
            ofpbuf_put(out, opnt->data, tlv_pad_len);
            break;
        }
        default:
            return OFPERR_NXBAC_UNKNOWN_ED_PROP;
        }
        break;
    }
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
    case OFPPPC_NSH: {
        switch ((*prop)->type) {
        case OFPPPT_PROP_NSH_MDTYPE: {
            struct ofpact_ed_prop_nsh_md_type *pnmt =
                ALIGNED_CAST(struct ofpact_ed_prop_nsh_md_type *, *prop);
            struct ofp_ed_prop_nsh_md_type *opnmt =
                    ofpbuf_put_uninit(out, sizeof(*opnmt));
            opnmt->header.prop_class = htons((*prop)->prop_class);
            opnmt->header.type = (*prop)->type;
            opnmt->header.len =
                    offsetof(struct ofp_ed_prop_nsh_md_type, pad);
            opnmt->md_type = pnmt->md_type;
            prop_len = sizeof(*pnmt);
            break;
        }
        case OFPPPT_PROP_NSH_TLV: {
            struct ofpact_ed_prop_nsh_tlv *pnt =
                ALIGNED_CAST(struct ofpact_ed_prop_nsh_tlv *, *prop);
            struct ofp_ed_prop_nsh_tlv *opnt;
            size_t tlv_pad_len = ROUND_UP(pnt->tlv_len, 8);
            size_t len = sizeof(*opnt) + tlv_pad_len;
            opnt = ofpbuf_put_uninit(out, len);
            opnt->header.prop_class = htons((*prop)->prop_class);
            opnt->header.type = (*prop)->type;
            opnt->header.len = len;
            opnt->tlv_class = pnt->tlv_class;
            opnt->tlv_type = pnt->tlv_type;
            opnt->tlv_len = pnt->tlv_len;
            memcpy(opnt->data, pnt->data, tlv_pad_len);
            prop_len = sizeof(*pnt) + tlv_pad_len;
            break;
        }
        default:
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        break;
    }
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
    } else if (!strcmp(str,"nsh")) {
        *prop_class = OFPPPC_NSH;
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
    case OFPPPC_NSH:
        if (!strcmp(str, "md_type")) {
            *type = OFPPPT_PROP_NSH_MDTYPE;
            return true;
        } else if (!strcmp(str, "tlv")) {
            *type = OFPPPT_PROP_NSH_TLV;
            return true;
        } else {
            return false;
        }
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
    char *error = NULL;

    if (value == NULL || *value == '\0') {
        return xstrdup("Value missing for encap property");
    }

    switch (prop_class) {
    case OFPPPC_NSH:
        switch (prop_type) {
        case OFPPPT_PROP_NSH_MDTYPE: {
            /* Format: "<md_type>:uint8_t". */
            uint8_t md_type;
            error = str_to_u8(value, "md_type", &md_type);
            if (error != NULL) {
                return error;
            }
            if (md_type < 1 || md_type > 2) {
                return xstrdup("invalid md_type");
            }
            struct ofpact_ed_prop_nsh_md_type *pnmt =
                    ofpbuf_put_uninit(out, sizeof(*pnmt));
            pnmt->header.prop_class = prop_class;
            pnmt->header.type = prop_type;
            pnmt->header.len =
                    offsetof(struct ofp_ed_prop_nsh_md_type, pad);
            pnmt->md_type = md_type;
            break;
        }
        case OFPPPT_PROP_NSH_TLV: {
            /* Format: "<class>:ovs_be16,<type>:uint8_t,<val>:hex_string" */
            struct ofpact_ed_prop_nsh_tlv *pnt;
            uint16_t tlv_class;
            uint8_t tlv_type;
            char buf[256];
            size_t tlv_value_len, padding;
            size_t start_ofs = out->size;

            if (!ovs_scan(value, "0x%"SCNx16",%"SCNu8",0x%251[0-9a-fA-F]",
                          &tlv_class, &tlv_type, buf)) {
                return xasprintf("Invalid NSH TLV header: %s", value);
            }
            ofpbuf_put_uninit(out, sizeof(*pnt));
            ofpbuf_put_hex(out, buf, &tlv_value_len);
            pnt = ALIGNED_CAST(struct ofpact_ed_prop_nsh_tlv *,
                               ((char *)out->data + start_ofs));
            padding = ROUND_UP(tlv_value_len, 8) - tlv_value_len;
            pnt->header.prop_class = prop_class;
            pnt->header.type = prop_type;
            pnt->header.len = sizeof(*pnt) + tlv_value_len + padding;
            pnt->tlv_class = htons(tlv_class);
            pnt->tlv_type = tlv_type;
            pnt->tlv_len = tlv_value_len;
            if (padding > 0) {
                ofpbuf_put_zeros(out, padding);
            }
            break;
        }
        default:
            /* Unsupported property types rejected before. */
            OVS_NOT_REACHED();
        }
        break;
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
    case OFPPPC_NSH:
        return "nsh";
    default:
        OVS_NOT_REACHED();
    }
}

char *
format_ed_prop_type(const struct ofpact_ed_prop *prop)
{
    switch (prop->prop_class) {
    case OFPPPC_NSH:
        switch (prop->type) {
        case OFPPPT_PROP_NSH_MDTYPE:
            return "md_type";
        case OFPPPT_PROP_NSH_TLV:
            return "tlv";
        default:
            OVS_NOT_REACHED();
        }
        break;
    default:
        OVS_NOT_REACHED();
    }
}

void
format_ed_prop(struct ds *s OVS_UNUSED,
                     const struct ofpact_ed_prop *prop)
{
    switch (prop->prop_class) {
    case OFPPPC_NSH:
        switch (prop->type) {
        case OFPPPT_PROP_NSH_MDTYPE: {
            struct ofpact_ed_prop_nsh_md_type *pnmt =
                ALIGNED_CAST(struct ofpact_ed_prop_nsh_md_type *, prop);
            ds_put_format(s, "%s=%d", format_ed_prop_type(prop),
                          pnmt->md_type);
            return;
        }
        case OFPPPT_PROP_NSH_TLV: {
            struct ofpact_ed_prop_nsh_tlv *pnt =
                ALIGNED_CAST(struct ofpact_ed_prop_nsh_tlv *, prop);
            ds_put_format(s, "%s(0x%04x,%d,",
                          format_ed_prop_type(prop),
                          ntohs(pnt->tlv_class), pnt->tlv_type);
            ds_put_hex(s, pnt->data, pnt->tlv_len);
            ds_put_cstr(s,")");
            return;
        }
        default:
            OVS_NOT_REACHED();
        }
    default:
        OVS_NOT_REACHED();
    }
}
