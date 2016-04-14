/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include "byte-order.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/vlog.h"
#include "util.h"
#include "uuid.h"

struct ofp_prop_be16 {
    ovs_be16 type;
    ovs_be16 len;
    ovs_be16 value;
    uint8_t pad[2];
};
BUILD_ASSERT_DECL(sizeof(struct ofp_prop_be16) == 8);

struct ofp_prop_be32 {
    ovs_be16 type;
    ovs_be16 len;
    ovs_be32 value;
};
BUILD_ASSERT_DECL(sizeof(struct ofp_prop_be32) == 8);

static uint32_t
ofpprop_type_to_exp_id(uint64_t type)
{
    return type >> 32;
}

static uint32_t
ofpprop_type_to_exp_type(uint64_t type)
{
    return type & UINT32_MAX;
}

/* Pulls a property, beginning with struct ofp_prop_header, from the beginning
 * of 'msg'.  Stores the type of the property in '*typep' and, if 'property' is
 * nonnull, the entire property, including the header, in '*property'.  Points
 * 'property->header' to the property header (which could be ofp_prop_header or
 * ofp_prop_experimenter) and 'property->msg' to just past it.  Returns 0 if
 * successful, otherwise an OpenFlow error code.
 *
 * This function treats property types 'min_exp' and larger as introducing
 * experimenter properties.  For most kinds of properties, 0xffff is the
 * appropriate value for 'min_exp', because 0xffff is the only property type
 * used for experimenters, but async config properties also use 0xfffe.  Use
 * 0x10000 (or higher) if experimenter properties are not supported.
 *
 * This function pulls the property's stated size padded out to a multiple of
 * 'alignment' bytes.  The common case in OpenFlow is an 'alignment' of 8, so
 * you can use ofpprop_pull() for that case. */
enum ofperr
ofpprop_pull__(struct ofpbuf *msg, struct ofpbuf *property,
               unsigned int alignment, unsigned int min_exp,
               uint64_t *typep)
{
    struct ofp_prop_header *oph;
    unsigned int padded_len;
    unsigned int len;

    if (msg->size < sizeof *oph) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    oph = msg->data;
    len = ntohs(oph->len);
    padded_len = ROUND_UP(len, alignment);
    if (len < sizeof *oph || padded_len > msg->size) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    uint16_t type = ntohs(oph->type);
    if (type < min_exp) {
        *typep = type;
    } else {
        struct ofp_prop_experimenter *ope = msg->data;
        if (len < sizeof *ope) {
            return OFPERR_OFPBPC_BAD_LEN;
        }

        if (!ope->experimenter) {
            /* Reject experimenter 0 because it yields ambiguity with standard
             * property types. */
            return OFPERR_OFPBPC_BAD_EXPERIMENTER;
        }

        *typep = OFPPROP_EXP(ntohl(ope->experimenter), ntohl(ope->exp_type));
    }

    if (property) {
        ofpbuf_use_const(property, msg->data, len);
        property->header = property->data;
        property->msg = ((uint8_t *) property->data
                         + (type < min_exp
                            ? sizeof(struct ofp_prop_header)
                            : sizeof(struct ofp_prop_experimenter)));
    }
    ofpbuf_pull(msg, padded_len);
    return 0;
}

/* Pulls a property, beginning with struct ofp_prop_header, from the beginning
 * of 'msg'.  Stores the type of the property in '*typep' and, if 'property' is
 * nonnull, the entire property, including the header, in '*property'.  Points
 * 'property->header' to the property header (which could be ofp_prop_header or
 * ofp_prop_experimenter) and 'property->msg' to just past it.  Returns 0 if
 * successful, otherwise an error code.
 *
 * This function treats property type 0xffff as introducing an experimenter
 * property.  Use ofpprop_pull__() instead if some other behavior is needed.
 *
 * This function pulls the property's stated size padded out to a multiple of 8
 * bytes, which is the common case for OpenFlow properties.  Use
 * ofpprop_pull__() instead if some other behavior is needed.*/
enum ofperr
ofpprop_pull(struct ofpbuf *msg, struct ofpbuf *property, uint64_t *typep)
{
    return ofpprop_pull__(msg, property, 8, 0xffff, typep);
}

/* Attempts to parse 'property' as a property containing a 16-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_be16(const struct ofpbuf *property, ovs_be16 *value)
{
    /* OpenFlow uses 8-byte properties for 16-bit values, which doesn't really
     * make sense.  Be forgiving by allowing any size payload as long as it's
     * at least big enough.  */
    ovs_be16 *p = property->msg;
    if (ofpbuf_msgsize(property) < sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *value = *p;
    return 0;
}

/* Attempts to parse 'property' as a property containing a 32-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_be32(const struct ofpbuf *property, ovs_be32 *value)
{
    ovs_be32 *p = property->msg;
    if (ofpbuf_msgsize(property) != sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *value = *p;
    return 0;
}

/* Attempts to parse 'property' as a property containing a 64-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_be64(const struct ofpbuf *property, ovs_be64 *value)
{
    ovs_be64 *p;
    size_t be64_offset = ROUND_UP(ofpbuf_headersize(property), 8);
    if (property->size != be64_offset + sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    p = ALIGNED_CAST(ovs_be64 *, (char *) property->data + be64_offset);
    *value = *p;
    return 0;
}

/* Attempts to parse 'property' as a property containing a 8-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_u8(const struct ofpbuf *property, uint8_t *value)
{
    /* OpenFlow 1.5 and earlier don't have any 8-bit properties, but it uses
     * 8-byte properties for 16-bit values, which doesn't really make sense.
     * Be forgiving by allowing any size payload as long as it's at least big
     * enough. */
    uint8_t *p = property->msg;
    if (ofpbuf_msgsize(property) < sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *value = *p;
    return 0;
}

/* Attempts to parse 'property' as a property containing a 16-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_u16(const struct ofpbuf *property, uint16_t *value)
{
    /* OpenFlow uses 8-byte properties for 16-bit values, which doesn't really
     * make sense.  Be forgiving by allowing any size payload as long as it's
     * at least big enough.  */
    ovs_be16 *p = property->msg;
    if (ofpbuf_msgsize(property) < sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *value = ntohs(*p);
    return 0;
}

/* Attempts to parse 'property' as a property containing a 32-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_u32(const struct ofpbuf *property, uint32_t *value)
{
    ovs_be32 *p = property->msg;
    if (ofpbuf_msgsize(property) != sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *value = ntohl(*p);
    return 0;
}

/* Attempts to parse 'property' as a property containing a 64-bit value.  If
 * successful, stores the value into '*value' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_u64(const struct ofpbuf *property, uint64_t *value)
{
    ovs_be64 *p;
    size_t be64_offset = ROUND_UP(ofpbuf_headersize(property), 8);
    if (property->size != be64_offset + sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    p = ALIGNED_CAST(ovs_be64 *, (char *) property->data + be64_offset);
    *value = ntohll(*p);
    return 0;
}

/* Attempts to parse 'property' as a property containing a UUID.  If
 * successful, stores the value into '*uuid' and returns 0; otherwise returns
 * an OpenFlow error. */
enum ofperr
ofpprop_parse_uuid(const struct ofpbuf *property, struct uuid *uuid)
{
    struct uuid *p = property->msg;
    if (ofpbuf_msgsize(property) != sizeof *p) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    *uuid = *p;
    return 0;
}

/* Attempts to parse 'property' as a property that contains nested properties.
 * If successful, stores the nested data into '*nested' and returns 0;
 * otherwise returns an OpenFlow error.
 *
 * The only thing special about nested properties is that the property header
 * is followed by 4 bytes of padding, so that the nested properties begin at an
 * 8-byte aligned offset.  This function can be used in other situations where
 * this is the case. */
enum ofperr
ofpprop_parse_nested(const struct ofpbuf *property, struct ofpbuf *nested)
{
    size_t nested_offset = ROUND_UP(ofpbuf_headersize(property), 8);
    if (property->size < nested_offset) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    ofpbuf_use_const(nested, property->data, property->size);
    ofpbuf_pull(nested, nested_offset);
    return 0;
}

/* Adds a property with the given 'type' and 'len'-byte contents 'value' to
 * 'msg', padding the property out to a multiple of 8 bytes. */
void
ofpprop_put(struct ofpbuf *msg, uint64_t type, const void *value, size_t len)
{
    size_t start_ofs = ofpprop_start(msg, type);
    ofpbuf_put(msg, value, len);
    ofpprop_end(msg, start_ofs);
}

/* Adds a property with the given 'type' to 'msg', consisting of a struct
 * ofp_prop_header or ofp_prop_experimenter followed by enough zero bytes to
 * total 'len' bytes, followed by padding to bring the property up to a
 * multiple of 8 bytes.  Returns the property header. */
void *
ofpprop_put_zeros(struct ofpbuf *msg, uint64_t type, size_t len)
{
    void *header = ofpbuf_put_zeros(msg, ROUND_UP(len, 8));
    if (!ofpprop_is_experimenter(type)) {
        struct ofp_prop_header *oph = header;
        oph->type = htons(type);
        oph->len = htons(len);
    } else {
        struct ofp_prop_experimenter *ope = header;
        ope->type = htons(0xffff);
        ope->len = htons(len);
        ope->experimenter = htonl(ofpprop_type_to_exp_id(type));
        ope->exp_type = htonl(ofpprop_type_to_exp_type(type));
    }
    return header;
}

/* Adds a property with the given 'type' and 16-bit 'value' to 'msg'. */
void
ofpprop_put_be16(struct ofpbuf *msg, uint64_t type, ovs_be16 value)
{
    if (!ofpprop_is_experimenter(type)) {
        /* The OpenFlow specs consistently (at least they're consistent!)  give
         * properties with a 16-bit integer value a length of 8, not 6, so add
         * two bytes of padding.  */
        ovs_be16 padded_value[2] = { value, 0 };
        ofpprop_put(msg, type, padded_value, sizeof padded_value);
    } else {
        /* There's no precedent but let's assume that this is generally done
         * sanely. */
        ofpprop_put(msg, type, &value, sizeof value);
    }
}

/* Adds a property with the given 'type' and 32-bit 'value' to 'msg'. */
void
ofpprop_put_be32(struct ofpbuf *msg, uint64_t type, ovs_be32 value)
{
    ofpprop_put(msg, type, &value, sizeof value);
}

/* Adds a property with the given 'type' and 64-bit 'value' to 'msg'. */
void
ofpprop_put_be64(struct ofpbuf *msg, uint64_t type, ovs_be64 value)
{
    size_t start = ofpprop_start(msg, type);
    ofpbuf_put_zeros(msg, 4);
    ofpbuf_put(msg, &value, sizeof value);
    ofpprop_end(msg, start);
}

/* Adds a property with the given 'type' and 8-bit 'value' to 'msg'. */
void
ofpprop_put_u8(struct ofpbuf *msg, uint64_t type, uint8_t value)
{
    /* There's no precedent for 8-bit properties in OpenFlow 1.5 and earlier
     * but let's assume they're done sanely. */
    ofpprop_put(msg, type, &value, 1);
}

/* Adds a property with the given 'type' and 16-bit 'value' to 'msg'. */
void
ofpprop_put_u16(struct ofpbuf *msg, uint64_t type, uint16_t value)
{
    ofpprop_put_be16(msg, type, htons(value));
}

/* Adds a property with the given 'type' and 32-bit 'value' to 'msg'. */
void
ofpprop_put_u32(struct ofpbuf *msg, uint64_t type, uint32_t value)
{
    ofpprop_put_be32(msg, type, htonl(value));
}

/* Adds a property with the given 'type' and 64-bit 'value' to 'msg'. */
void
ofpprop_put_u64(struct ofpbuf *msg, uint64_t type, uint64_t value)
{
    ofpprop_put_be64(msg, type, htonll(value));
}

/* Appends a property to 'msg' whose type is 'type' and whose contents is a
 * series of property headers, one for each 1-bit in 'bitmap'. */
void
ofpprop_put_bitmap(struct ofpbuf *msg, uint64_t type, uint64_t bitmap)
{
    size_t start_ofs = ofpprop_start(msg, type);

    for (; bitmap; bitmap = zero_rightmost_1bit(bitmap)) {
        ofpprop_start(msg, rightmost_1bit_idx(bitmap));
    }
    ofpprop_end(msg, start_ofs);
}

/* Appends a content-free property with the given 'type' to 'msg'.
 *
 * (The idea is that the presence of the property acts as a flag.) */
void
ofpprop_put_flag(struct ofpbuf *msg, uint64_t type)
{
    size_t start = ofpprop_start(msg, type);
    ofpprop_end(msg, start);
}

/* Appends a property to 'msg' with the given 'type' and 'uuid' as its
 * value. */
void
ofpprop_put_uuid(struct ofpbuf *msg, uint64_t type, const struct uuid *uuid)
{
    ofpprop_put(msg, type, uuid, sizeof *uuid);
}

/* Appends a property of type 'type' to 'msg' whose contents are padding to
 * 8-byte alignment followed by 'nested'.  This is a suitable way to add nested
 * properties to 'msg'. */
void
ofpprop_put_nested(struct ofpbuf *msg, uint64_t type,
                   const struct ofpbuf *nested)
{
    size_t start = ofpprop_start_nested(msg, type);
    ofpbuf_put(msg, nested->data, nested->size);
    ofpprop_end(msg, start);
}

/* Appends a header for a property of type 'type' to 'msg'.  The caller should
 * add the contents of the property to 'msg', then finish it by calling
 * ofpprop_end().  Returns the offset of the beginning of the property (to pass
 * to ofpprop_end() later). */
size_t
ofpprop_start(struct ofpbuf *msg, uint64_t type)
{
    size_t start_ofs = msg->size;
    if (!ofpprop_is_experimenter(type)) {
        struct ofp_prop_header *oph = ofpbuf_put_uninit(msg, sizeof *oph);
        oph->type = htons(type);
        oph->len = htons(4);
    } else {
        struct ofp_prop_experimenter *ope
            = ofpbuf_put_uninit(msg, sizeof *ope);
        ope->type = htons(0xffff);
        ope->len = htons(12);
        ope->experimenter = htonl(ofpprop_type_to_exp_id(type));
        ope->exp_type = htonl(ofpprop_type_to_exp_type(type));
    }
    return start_ofs;
}

/* Finishes serializing a property that was begun with ofpprop_start(), by
 * padding 'msg' to a multiple of 8 bytes and updating the property's length.
 * 'start_ofs' should be the offset of the beginning of the property, as
 * returned by ofpprop_start(). */
void
ofpprop_end(struct ofpbuf *msg, size_t start_ofs)
{
    struct ofp_prop_header *oph;

    oph = ofpbuf_at_assert(msg, start_ofs, sizeof *oph);
    oph->len = htons(msg->size - start_ofs);
    ofpbuf_padto(msg, ROUND_UP(msg->size, 8));
}

/* Appends a header for a property of type 'type' to 'msg', followed by padding
 * suitable for putting nested properties into the property; that is, padding
 * to an 8-byte alignment.
 *
 * This otherwise works like ofpprop_start().
 *
 * There's no need for ofpprop_end_nested(), because ofpprop_end() works fine
 * for this case. */
size_t
ofpprop_start_nested(struct ofpbuf *msg, uint64_t type)
{
    size_t start_ofs = ofpprop_start(msg, type);
    ofpbuf_padto(msg, ROUND_UP(msg->size, 8));
    return start_ofs;
}

enum ofperr
ofpprop_unknown(struct vlog_module *module, bool loose, const char *msg,
                uint64_t type)
{
    bool is_experimenter = ofpprop_is_experimenter(type);

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    enum vlog_level level = loose ? VLL_DBG : VLL_WARN;
    if (!is_experimenter) {
        vlog_rate_limit(module, level, &rl, "unknown %s property type %"PRId64,
                        msg, type);
    } else {
        vlog_rate_limit(module, level, &rl,
                        "unknown %s property type for exp_id 0x%"PRIx32", "
                        "exp_type %"PRId32, msg,
                        ofpprop_type_to_exp_id(type),
                        ofpprop_type_to_exp_type(type));
    }

    /* There's an error OFPBPC_BAD_EXPERIMENTER that we could use for
     * experimenter IDs that we don't know at all, but that seems like a
     * difficult distinction and OFPERR_OFPBPC_BAD_EXP_TYPE communicates the
     * problem quite well. */
    return (loose ? 0
            : is_experimenter ? OFPERR_OFPBPC_BAD_EXP_TYPE
            : OFPERR_OFPBPC_BAD_TYPE);
}

