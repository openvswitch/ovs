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

#ifndef OPENVSWITCH_OFP_PROP_H
#define OPENVSWITCH_OFP_PROP_H 1

/* OpenFlow 1.3+ property support
 * ==============================
 *
 * Several OpenFlow 1.3+ messages use type-length-value (TLV) properties that
 * take the common form shown by "struct ofp_prop_header".  This module
 * provides support for serializing and deserializing properties in this
 * format.
 *
 *
 * Property types
 * --------------
 *
 * This module uses uint64_t values to identify property types
 *
 *     - OpenFlow assigns 16-bit type values to its own standardized
 *       properties.  ofpprop uses these values directly in uint64_t.
 *
 *       The 16-bit value 0xffff (and for some kinds of properties  0xfffe) is
 *       reserved as a kind of escape to introduce an "experimenter" property
 *       (see below).
 *
 *     - Vendor-specific "experimenter" properties have a 32-bit "experimenter
 *       ID" (generally an Ethernet OUI) and a 32-bit experimenter-defined
 *       "exp_type".  ofpprop encodes these with the experimenter ID in the
 *       high 32 bits and exp_type in the low 32 bits.  (All existing
 *       experimenter IDs are nonzero, so this is unambiguous.)  Use
 *       OFPPROP_EXP to encode these property types.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofpbuf;
struct uuid;
struct vlog_module;

/* Given an OpenFlow experimenter ID (e.g. NX_VENDOR_ID) 'exp_id' and type
 * 'exp_type', yields the code that ofpprop_pull() would use to identify the
 * given experimenter property. */
#define OFPPROP_EXP(EXP_ID, EXP_TYPE) \
    (((uint64_t) (EXP_ID) << 32) | (EXP_TYPE))

/* Returns true if 'type' represents an experimenter property type,
 * false if it represents a standard property type.*/
static inline bool
ofpprop_is_experimenter(uint64_t type)
{
    return type > UINT16_MAX;
}

/* Deserializing properties.  */
enum ofperr ofpprop_pull__(struct ofpbuf *msg, struct ofpbuf *property,
                           unsigned int alignment, unsigned int min_exp,
                           uint64_t *typep);
enum ofperr ofpprop_pull(struct ofpbuf *msg, struct ofpbuf *property,
                         uint64_t *typep);

enum ofperr ofpprop_parse_be16(const struct ofpbuf *, ovs_be16 *value);
enum ofperr ofpprop_parse_be32(const struct ofpbuf *, ovs_be32 *value);
enum ofperr ofpprop_parse_be64(const struct ofpbuf *, ovs_be64 *value);
enum ofperr ofpprop_parse_u8(const struct ofpbuf *, uint8_t *value);
enum ofperr ofpprop_parse_u16(const struct ofpbuf *, uint16_t *value);
enum ofperr ofpprop_parse_u32(const struct ofpbuf *, uint32_t *value);
enum ofperr ofpprop_parse_u64(const struct ofpbuf *, uint64_t *value);
enum ofperr ofpprop_parse_uuid(const struct ofpbuf *, struct uuid *);
enum ofperr ofpprop_parse_nested(const struct ofpbuf *, struct ofpbuf *);

/* Serializing properties. */
void ofpprop_put(struct ofpbuf *, uint64_t type,
                 const void *value, size_t len);
void *ofpprop_put_zeros(struct ofpbuf *, uint64_t type, size_t len);
void ofpprop_put_be16(struct ofpbuf *, uint64_t type, ovs_be16 value);
void ofpprop_put_be32(struct ofpbuf *, uint64_t type, ovs_be32 value);
void ofpprop_put_be64(struct ofpbuf *, uint64_t type, ovs_be64 value);
void ofpprop_put_u8(struct ofpbuf *, uint64_t type, uint8_t value);
void ofpprop_put_u16(struct ofpbuf *, uint64_t type, uint16_t value);
void ofpprop_put_u32(struct ofpbuf *, uint64_t type, uint32_t value);
void ofpprop_put_u64(struct ofpbuf *, uint64_t type, uint64_t value);
void ofpprop_put_bitmap(struct ofpbuf *, uint64_t type, uint64_t bitmap);
void ofpprop_put_flag(struct ofpbuf *, uint64_t type);
void ofpprop_put_uuid(struct ofpbuf *, uint64_t type, const struct uuid *);
void ofpprop_put_nested(struct ofpbuf *, uint64_t type, const struct ofpbuf *);

size_t ofpprop_start(struct ofpbuf *, uint64_t type);
void ofpprop_end(struct ofpbuf *, size_t start_ofs);

size_t ofpprop_start_nested(struct ofpbuf *, uint64_t type);

/* Logging errors while deserializing properties.
 *
 * The attitude that a piece of code should take when it deserializes an
 * unknown property type depends on the code in question:
 *
 *    - In a "loose" context (with LOOSE set to true), that is, where the code
 *      is parsing the property to find out about the state or the capabilities
 *      of some piece of the system, generally an unknown property type is not
 *      a big deal, because it only means that there is additional information
 *      that the receiver does not understand.
 *
 *    - In a "strict" context (with LOOSE set to false), that is, where the
 *      code is parsing the property to change the state or configuration of a
 *      part of the system, generally an unknown property type is an error,
 *      because it means that the receiver is being asked to configure the
 *      system in some way it doesn't understand.
 *
 * Given LOOSE, this macro automatically logs chooses an appropriate log
 * level. */
#define OFPPROP_LOG(RL, LOOSE, ...)                         \
    VLOG_RL(RL, (LOOSE) ? VLL_DBG : VLL_WARN, __VA_ARGS__)

enum ofperr ofpprop_unknown(struct vlog_module *, bool loose, const char *msg,
                            uint64_t type);
#define OFPPROP_UNKNOWN(LOOSE, MSG, TYPE) \
    ofpprop_unknown(&this_module, LOOSE, MSG, TYPE)

#ifdef __cplusplus
}
#endif

#endif /* ofp-prop.h */
