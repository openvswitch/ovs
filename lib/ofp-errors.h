/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#ifndef OFP_ERRORS_H
#define OFP_ERRORS_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ds;
struct ofp_header;

/* Error codes.
 *
 * We embed system errno values and OpenFlow standard and vendor extension
 * error codes into the positive range of "int":
 *
 *   - Errno values are assumed to use the range 1 through 2**30 - 1.
 *
 *     (C and POSIX say that errno values are positive.  We assume that they
 *     are less than 2**29.  They are actually less than 65536 on at least
 *     Linux, FreeBSD, OpenBSD, and Windows.)
 *
 *   - OpenFlow standard and vendor extension error codes use the range
 *     starting at 2**30 (OFPERR_OFS).
 *
 * Zero and negative values are not used.
 */

#define OFPERR_OFS (1 << 30)

enum ofperr {
/* ## ------------------ ## */
/* ## OFPET_HELLO_FAILED ## */
/* ## ------------------ ## */

    /* OF(0).  Hello protocol failed. */
    OFPERR_OFPET_HELLO_FAILED = OFPERR_OFS,

    /* OF(0,0).  No compatible version. */
    OFPERR_OFPHFC_INCOMPATIBLE,

    /* OF(0,1).  Permissions error. */
    OFPERR_OFPHFC_EPERM,

/* ## ----------------- ## */
/* ## OFPET_BAD_REQUEST ## */
/* ## ----------------- ## */

    /* OF(1).  Request was not understood. */
    OFPERR_OFPET_BAD_REQUEST,

    /* OF(1,0).  ofp_header.version not supported. */
    OFPERR_OFPBRC_BAD_VERSION,

    /* OF(1,1).  ofp_header.type not supported. */
    OFPERR_OFPBRC_BAD_TYPE,

    /* OF(1,2).  ofp_stats_msg.type not supported. */
    OFPERR_OFPBRC_BAD_STAT,

    /* OF(1,3).  Vendor not supported (in ofp_vendor_header or
     * ofp_stats_msg). */
    OFPERR_OFPBRC_BAD_VENDOR,

    /* OF(1,4).  Vendor subtype not supported. */
    OFPERR_OFPBRC_BAD_SUBTYPE,

    /* OF(1,5).  Permissions error. */
    OFPERR_OFPBRC_EPERM,

    /* OF(1,6).  Wrong request length for type. */
    OFPERR_OFPBRC_BAD_LEN,

    /* OF(1,7).  Specified buffer has already been used. */
    OFPERR_OFPBRC_BUFFER_EMPTY,

    /* OF(1,8).  Specified buffer does not exist. */
    OFPERR_OFPBRC_BUFFER_UNKNOWN,

    /* OF1.1(1,9).  Specified table-id invalid or does not exist. */
    OFPERR_OFPBRC_BAD_TABLE_ID,

    /* NX(1,256).  Invalid NXM flow match. */
    OFPERR_NXBRC_NXM_INVALID,

    /* NX(1,257).  The nxm_type, or nxm_type taken in combination with
     * nxm_hasmask or nxm_length or both, is invalid or not implemented. */
    OFPERR_NXBRC_NXM_BAD_TYPE,

    /* NX(1,258).  Invalid nxm_value. */
    OFPERR_NXBRC_NXM_BAD_VALUE,

    /* NX(1,259).  Invalid nxm_mask. */
    OFPERR_NXBRC_NXM_BAD_MASK,

    /* NX(1,260).  A prerequisite was not met. */
    OFPERR_NXBRC_NXM_BAD_PREREQ,

    /* NX(1,261).  A given nxm_type was specified more than once. */
    OFPERR_NXBRC_NXM_DUP_TYPE,

    /* NX(1,512).  A request specified a nonexistent table ID. */
    OFPERR_NXBRC_BAD_TABLE_ID,

    /* NX(1,513).  NXT_ROLE_REQUEST specified an invalid role. */
    OFPERR_NXBRC_BAD_ROLE,

    /* NX(1,514).  The in_port in an ofp_packet_out request is invalid. */
    OFPERR_NXBRC_BAD_IN_PORT,

/* ## ---------------- ## */
/* ## OFPET_BAD_ACTION ## */
/* ## ---------------- ## */

    /* OF(2).  Error in action description. */
    OFPERR_OFPET_BAD_ACTION,

    /* OF(2,0).  Unknown action type. */
    OFPERR_OFPBAC_BAD_TYPE,

    /* OF(2,1).  Length problem in actions. */
    OFPERR_OFPBAC_BAD_LEN,

    /* OF(2,2).  Unknown experimenter id specified. */
    OFPERR_OFPBAC_BAD_VENDOR,

    /* OF(2,3).  Unknown action type for experimenter id. */
    OFPERR_OFPBAC_BAD_VENDOR_TYPE,

    /* OF(2,4).  Problem validating output port. */
    OFPERR_OFPBAC_BAD_OUT_PORT,

    /* OF(2,5).  Bad action argument. */
    OFPERR_OFPBAC_BAD_ARGUMENT,

    /* OF(2,6).  Permissions error. */
    OFPERR_OFPBAC_EPERM,

    /* OF(2,7).  Can't handle this many actions. */
    OFPERR_OFPBAC_TOO_MANY,

    /* OF(2,8).  Problem validating output queue. */
    OFPERR_OFPBAC_BAD_QUEUE,

    /* OF1.1(2,9).  Invalid group id in forward action. */
    OFPERR_OFPBAC_BAD_OUT_GROUP,

    /* OF1.1(2,10).  Action can't apply for this match. */
    OFPERR_OFPBAC_MATCH_INCONSISTENT,

    /* OF1.1(2,11).  Action order is unsupported for the action list in an
     * Apply-Actions instruction */
    OFPERR_OFPBAC_UNSUPPORTED_ORDER,

    /* OF1.1(2,12).  Actions uses an unsupported tag/encap. */
    OFPERR_OFPBAC_BAD_TAG,

/* ## --------------------- ## */
/* ## OFPET_BAD_INSTRUCTION ## */
/* ## --------------------- ## */

    /* OF1.1(3).  Error in instruction list. */
    OFPERR_OFPET_BAD_INSTRUCTION,

    /* OF1.1(3,0).  Unknown instruction. */
    OFPERR_OFPBIC_UNKNOWN_INST,

    /* OF1.1(3,1).  Switch or table does not support the instruction. */
    OFPERR_OFPBIC_UNSUP_INST,

    /* OF1.1(3,2).  Invalid Table-ID specified. */
    OFPERR_OFPBIC_BAD_TABLE_ID,

    /* OF1.1(3,3).  Metadata value unsupported by datapath. */
    OFPERR_OFPBIC_UNSUP_METADATA,

    /* OF1.1(3,4).  Metadata mask value unsupported by datapath. */
    OFPERR_OFPBIC_UNSUP_METADATA_MASK,

    /* OF1.1(3,5).  Specific experimenter instruction unsupported. */
    OFPERR_OFPBIC_UNSUP_EXP_INST,

/* ## --------------- ## */
/* ## OFPET_BAD_MATCH ## */
/* ## --------------- ## */

    /* OF1.1(4).  Error in match. */
    OFPERR_OFPET_BAD_MATCH,

    /* OF1.1(4,0).  Unsupported match type specified by the match */
    OFPERR_OFPBMC_BAD_TYPE,

    /* OF1.1(4,1).  Length problem in match. */
    OFPERR_OFPBMC_BAD_LEN,

    /* OF1.1(4,2).  Match uses an unsupported tag/encap. */
    OFPERR_OFPBMC_BAD_TAG,

    /* OF1.1(4,3).  Unsupported datalink addr mask - switch does not support
     * arbitrary datalink address mask. */
    OFPERR_OFPBMC_BAD_DL_ADDR_MASK,

    /* OF1.1(4,4).  Unsupported network addr mask - switch does not support
     * arbitrary network address mask. */
    OFPERR_OFPBMC_BAD_NW_ADDR_MASK,

    /* OF1.1(4,5).  Unsupported wildcard specified in the match. */
    OFPERR_OFPBMC_BAD_WILDCARDS,

    /* OF1.1(4,6).  Unsupported field in the match. */
    OFPERR_OFPBMC_BAD_FIELD,

    /* OF1.1(4,7).  Unsupported value in a match field. */
    OFPERR_OFPBMC_BAD_VALUE,

/* ## --------------------- ## */
/* ## OFPET_FLOW_MOD_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(3), OF1.1(5).  Problem modifying flow entry. */
    OFPERR_OFPET_FLOW_MOD_FAILED,

    /* OF1.1(5,0).  Unspecified error. */
    OFPERR_OFPFMFC_UNKNOWN,

    /* OF1.0(3,0).  Flow not added because of full tables. */
    OFPERR_OFPFMFC_ALL_TABLES_FULL,

    /* OF1.1(5,1).  Flow not added because table was full. */
    OFPERR_OFPFMFC_TABLE_FULL,

    /* OF1.1(5,2).  Table does not exist */
    OFPERR_OFPFMFC_BAD_TABLE_ID,

    /* OF1.0(3,1), OF1.1(5,3).  Attempted to add overlapping flow with
     * CHECK_OVERLAP flag set. */
    OFPERR_OFPFMFC_OVERLAP,

    /* OF1.0(3,2), OF1.1(5,4).  Permissions error. */
    OFPERR_OFPFMFC_EPERM,

    /* OF1.1(5,5).  Flow not added because of unsupported idle/hard timeout. */
    OFPERR_OFPFMFC_BAD_TIMEOUT,

    /* OF1.0(3,3).  Flow not added because of non-zero idle/hard timeout. */
    OFPERR_OFPFMFC_BAD_EMERG_TIMEOUT,

    /* OF1.0(3,4), OF1.1(5,6).  Unsupported or unknown command. */
    OFPERR_OFPFMFC_BAD_COMMAND,

    /* OF1.0(3,5).  Unsupported action list - cannot process in the order
     * specified. */
    OFPERR_OFPFMFC_UNSUPPORTED,

    /* NX1.0(3,256), NX1.1(5,256).  Generic hardware error. */
    OFPERR_NXFMFC_HARDWARE,

    /* NX1.0(3,257), NX1.1(5,257).  A nonexistent table ID was specified in the
     * "command" field of struct ofp_flow_mod, when the nxt_flow_mod_table_id
     * extension is enabled. */
    OFPERR_NXFMFC_BAD_TABLE_ID,

/* ## ---------------------- ## */
/* ## OFPET_GROUP_MOD_FAILED ## */
/* ## ---------------------- ## */

    /* OF1.1(6).  Problem modifying group entry. */
    OFPERR_OFPET_GROUP_MOD_FAILED,

    /* OF1.1(6,0).  Group not added because a group ADD attempted to replace an
     * already-present group. */
    OFPERR_OFPGMFC_GROUP_EXISTS,

    /* OF1.1(6,1).  Group not added because Group specified is invalid. */
    OFPERR_OFPGMFC_INVALID_GROUP,

    /* OF1.1(6,2).  Switch does not support unequal load sharing with select
     * groups. */
    OFPERR_OFPGMFC_WEIGHT_UNSUPPORTED,

    /* OF1.1(6,3).  The group table is full. */
    OFPERR_OFPGMFC_OUT_OF_GROUPS,

    /* OF1.1(6,4).  The maximum number of action buckets for a group has been
     * exceeded. */
    OFPERR_OFPGMFC_OUT_OF_BUCKETS,

    /* OF1.1(6,5).  Switch does not support groups that forward to groups. */
    OFPERR_OFPGMFC_CHAINING_UNSUPPORTED,

    /* OF1.1(6,6).  This group cannot watch the watch_port or watch_group
     * specified. */
    OFPERR_OFPGMFC_WATCH_UNSUPPORTED,

    /* OF1.1(6,7).  Group entry would cause a loop. */
    OFPERR_OFPGMFC_LOOP,

    /* OF1.1(6,8).  Group not modified because a group MODIFY attempted to
     * modify a non-existent group. */
    OFPERR_OFPGMFC_UNKNOWN_GROUP,

/* ## --------------------- ## */
/* ## OFPET_PORT_MOD_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(4), OF1.1(7).  OFPT_PORT_MOD failed. */
    OFPERR_OFPET_PORT_MOD_FAILED,

    /* OF1.0(4,0), OF1.1(7,0).  Specified port does not exist. */
    OFPERR_OFPPMFC_BAD_PORT,

    /* OF1.0(4,1), OF1.1(7,1).  Specified hardware address does not match the
     * port number. */
    OFPERR_OFPPMFC_BAD_HW_ADDR,

    /* OF1.1(7,2).  Specified config is invalid. */
    OFPERR_OFPPMFC_BAD_CONFIG,

    /* OF1.1(7,3).  Specified advertise is invalid. */
    OFPERR_OFPPMFC_BAD_ADVERTISE,

/* ## ---------------------- ## */
/* ## OFPET_TABLE_MOD_FAILED ## */
/* ## ---------------------- ## */

    /* OF1.1(8).  Table mod request failed. */
    OFPERR_OFPET_TABLE_MOD_FAILED,

    /* OF1.1(8,0).  Specified table does not exist. */
    OFPERR_OFPTMFC_BAD_TABLE,

    /* OF1.1(8,1).  Specified config is invalid. */
    OFPERR_OFPTMFC_BAD_CONFIG,

/* ## --------------------- ## */
/* ## OFPET_QUEUE_OP_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(5), OF1.1(9).  Queue operation failed. */
    OFPERR_OFPET_QUEUE_OP_FAILED,

    /* OF1.0(5,0), OF1.1(9,0).  Invalid port (or port does not exist). */
    OFPERR_OFPQOFC_BAD_PORT,

    /* OF1.0(5,1), OF1.1(9,1).  Queue does not exist. */
    OFPERR_OFPQOFC_BAD_QUEUE,

    /* OF1.0(5,2), OF1.1(9,2).  Permissions error. */
    OFPERR_OFPQOFC_EPERM,

/* ## -------------------------- ## */
/* ## OFPET_SWITCH_CONFIG_FAILED ## */
/* ## -------------------------- ## */

    /* OF1.1(10).  Switch config request failed. */
    OFPERR_OFPET_SWITCH_CONFIG_FAILED,

    /* OF1.1(10,0).  Specified flags is invalid. */
    OFPERR_OFPSCFC_BAD_FLAGS,

    /* OF1.1(10,1).  Specified len is invalid. */
    OFPERR_OFPSCFC_BAD_LEN,
};

extern const struct ofperr_domain ofperr_of10;
extern const struct ofperr_domain ofperr_of11;

const struct ofperr_domain *ofperr_domain_from_version(uint8_t version);

bool ofperr_is_valid(enum ofperr);
bool ofperr_is_category(enum ofperr);
bool ofperr_is_nx_extension(enum ofperr);
bool ofperr_is_encodable(enum ofperr, const struct ofperr_domain *);

enum ofperr ofperr_decode(const struct ofperr_domain *,
                          uint16_t type, uint16_t code);
enum ofperr ofperr_decode_type(const struct ofperr_domain *, uint16_t type);

enum ofperr ofperr_decode_msg(const struct ofp_header *, size_t *payload_ofs);
struct ofpbuf *ofperr_encode_reply(enum ofperr, const struct ofp_header *);
struct ofpbuf *ofperr_encode_hello(enum ofperr, const struct ofperr_domain *,
                                   const char *);

const char *ofperr_get_name(enum ofperr);
const char *ofperr_get_description(enum ofperr);

void ofperr_format(struct ds *, enum ofperr);
const char *ofperr_to_string(enum ofperr);

#endif /* ofp-errors.h */
