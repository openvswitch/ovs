/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "openflow/openflow.h"

struct ds;
struct ofpbuf;

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

/* OpenFlow error codes.
 *
 * The comments below are parsed by the extract-ofp-errors program at build
 * time and used to determine the mapping between "enum ofperr" constants and
 * error type/code values used in the OpenFlow protocol:
 *
 *   - The first part of each comment specifies OpenFlow type/code for each
 *     protocol that supports the error.
 *
 *   - Additional text is a human-readable description of the meaning of each
 *     error, used to explain the error to the user.  Any text enclosed in
 *     square brackets is omitted; this can be used to explain rationale for
 *     choice of error codes in the case where this is desirable. */
enum ofperr {
/* Expected duplications. */

    /* Expected: 3,5 in OF1.1 means both OFPBIC_BAD_EXPERIMENTER and
     * OFPBIC_BAD_EXP_TYPE. */

/* ## ------------------ ## */
/* ## OFPET_HELLO_FAILED ## */
/* ## ------------------ ## */

    /* OF1.0+(0).  Hello protocol failed. */
    OFPERR_OFPET_HELLO_FAILED = OFPERR_OFS,

    /* OF1.0+(0,0).  No compatible version. */
    OFPERR_OFPHFC_INCOMPATIBLE,

    /* OF1.0+(0,1).  Permissions error. */
    OFPERR_OFPHFC_EPERM,

/* ## ----------------- ## */
/* ## OFPET_BAD_REQUEST ## */
/* ## ----------------- ## */

    /* OF1.0+(1).  Request was not understood. */
    OFPERR_OFPET_BAD_REQUEST,

    /* OF1.0+(1,0).  ofp_header.version not supported. */
    OFPERR_OFPBRC_BAD_VERSION,

    /* OF1.0+(1,1).  ofp_header.type not supported. */
    OFPERR_OFPBRC_BAD_TYPE,

    /* OF1.0+(1,2).  ofp_stats_msg.type not supported. */
    OFPERR_OFPBRC_BAD_STAT,

    /* OF1.0+(1,3).  Vendor not supported (in ofp_vendor_header or
     * ofp_stats_msg). */
    OFPERR_OFPBRC_BAD_VENDOR,

    /* OF1.0+(1,4).  Vendor subtype not supported. */
    OFPERR_OFPBRC_BAD_SUBTYPE,

    /* OF1.0+(1,5).  Permissions error. */
    OFPERR_OFPBRC_EPERM,

    /* OF1.0+(1,6).  Wrong request length for type. */
    OFPERR_OFPBRC_BAD_LEN,

    /* OF1.0+(1,7).  Specified buffer has already been used. */
    OFPERR_OFPBRC_BUFFER_EMPTY,

    /* OF1.0+(1,8).  Specified buffer does not exist. */
    OFPERR_OFPBRC_BUFFER_UNKNOWN,

    /* NX1.0(1,512), OF1.1+(1,9).  Specified table-id invalid or does not exist.
     * [ A non-standard error (1,512), formerly OFPERR_NXBRC_BAD_TABLE_ID,
     *   is used for OpenFlow 1.0 as there seems to be no appropriste error
     *   code defined the specification. ] */
    OFPERR_OFPBRC_BAD_TABLE_ID,

    /* OF1.2+(1,10).  Denied because controller is slave. */
    OFPERR_OFPBRC_IS_SLAVE,

    /* NX1.0(1,514), NX1.1(1,514), OF1.2+(1,11).  Invalid port.
     * [ A non-standard error (1,514), formerly
     *   OFPERR_NXBRC_BAD_IN_PORT is used for OpenFlow 1.0 and 1.1 as there
     *   seems to be no appropriste error code defined the specifications. ] */
    OFPERR_OFPBRC_BAD_PORT,

    /* OF1.2+(1,12).  Invalid packet in packet-out. */
    OFPERR_OFPBRC_BAD_PACKET,

    /* NX1.0+(1,256).  Invalid NXM flow match. */
    OFPERR_NXBRC_NXM_INVALID,

    /* NX1.0+(1,257).  The nxm_type, or nxm_type taken in combination with
     * nxm_hasmask or nxm_length or both, is invalid or not implemented. */
    OFPERR_NXBRC_NXM_BAD_TYPE,

    /* NX1.0+(1,515).  Must-be-zero field had nonzero value. */
    OFPERR_NXBRC_MUST_BE_ZERO,

    /* NX1.0+(1,516).  The reason in an ofp_port_status message is not
     * valid. */
    OFPERR_NXBRC_BAD_REASON,

    /* NX1.0+(1,517).  The 'id' in an NXST_FLOW_MONITOR request is the same as
     * an existing monitor id (or two monitors in the same NXST_FLOW_MONITOR
     * request have the same 'id').  */
    OFPERR_NXBRC_FM_DUPLICATE_ID,

    /* NX1.0+(1,518).  The 'flags' in an NXST_FLOW_MONITOR request either does
     * not specify at least one of the NXFMF_ADD, NXFMF_DELETE, or NXFMF_MODIFY
     * flags, or specifies a flag bit that is not defined. */
    OFPERR_NXBRC_FM_BAD_FLAGS,

    /* NX1.0+(1,519).  The 'id' in an NXT_FLOW_MONITOR_CANCEL request is not
     * the id of any existing monitor. */
    OFPERR_NXBRC_FM_BAD_ID,

/* ## ---------------- ## */
/* ## OFPET_BAD_ACTION ## */
/* ## ---------------- ## */

    /* OF1.0+(2).  Error in action description. */
    OFPERR_OFPET_BAD_ACTION,

    /* OF1.0+(2,0).  Unknown action type. */
    OFPERR_OFPBAC_BAD_TYPE,

    /* OF1.0+(2,1).  Length problem in actions. */
    OFPERR_OFPBAC_BAD_LEN,

    /* OF1.0+(2,2).  Unknown experimenter id specified. */
    OFPERR_OFPBAC_BAD_VENDOR,

    /* OF1.0+(2,3).  Unknown action type for experimenter id. */
    OFPERR_OFPBAC_BAD_VENDOR_TYPE,

    /* OF1.0+(2,4).  Problem validating output port. */
    OFPERR_OFPBAC_BAD_OUT_PORT,

    /* OF1.0+(2,5).  Bad action argument. */
    OFPERR_OFPBAC_BAD_ARGUMENT,

    /* OF1.0+(2,6).  Permissions error. */
    OFPERR_OFPBAC_EPERM,

    /* OF1.0+(2,7).  Can't handle this many actions. */
    OFPERR_OFPBAC_TOO_MANY,

    /* OF1.0+(2,8).  Problem validating output queue. */
    OFPERR_OFPBAC_BAD_QUEUE,

    /* OF1.1+(2,9).  Invalid group id in forward action. */
    OFPERR_OFPBAC_BAD_OUT_GROUP,

    /* OF1.1+(2,10).  Action can't apply for this match. */
    OFPERR_OFPBAC_MATCH_INCONSISTENT,

    /* OF1.1+(2,11).  Action order is unsupported for the action list in an
     * Apply-Actions instruction */
    OFPERR_OFPBAC_UNSUPPORTED_ORDER,

    /* OF1.1+(2,12).  Actions uses an unsupported tag/encap. */
    OFPERR_OFPBAC_BAD_TAG,

    /* OF1.2+(2,13).  Unsupported type in SET_FIELD action. */
    OFPERR_OFPBAC_SET_TYPE,

    /* OF1.2+(2,14).  Length problem in SET_FIELD action. */
    OFPERR_OFPBAC_SET_LEN,

    /* OF1.2+(2,15).  Bad argument in SET_FIELD action. */
    OFPERR_OFPBAC_ARGUMENT,

    /* NX1.0+(2,256).  Must-be-zero action argument had nonzero value. */
    OFPERR_NXBAC_MUST_BE_ZERO,

/* ## --------------------- ## */
/* ## OFPET_BAD_INSTRUCTION ## */
/* ## --------------------- ## */

    /* OF1.1+(3).  Error in instruction list. */
    OFPERR_OFPIT_BAD_INSTRUCTION,

    /* OF1.1+(3,0).  Unknown instruction. */
    OFPERR_OFPBIC_UNKNOWN_INST,

    /* OF1.1+(3,1).  Switch or table does not support the instruction. */
    OFPERR_OFPBIC_UNSUP_INST,

    /* OF1.1+(3,2).  Invalid Table-ID specified. */
    OFPERR_OFPBIC_BAD_TABLE_ID,

    /* OF1.1+(3,3).  Metadata value unsupported by datapath. */
    OFPERR_OFPBIC_UNSUP_METADATA,

    /* OF1.1+(3,4).  Metadata mask value unsupported by datapath. */
    OFPERR_OFPBIC_UNSUP_METADATA_MASK,

    /* OF1.1+(3,5).  Unknown experimenter id specified. */
    OFPERR_OFPBIC_BAD_EXPERIMENTER,

    /* OF1.1(3,5), OF1.2+(3,6).  Unknown instruction for experimenter id. */
    OFPERR_OFPBIC_BAD_EXP_TYPE,

    /* OF1.2+(3,7).  Length problem in instructions. */
    OFPERR_OFPBIC_BAD_LEN,

    /* OF1.2+(3,8).  Permissions error. */
    OFPERR_OFPBIC_EPERM,

/* ## --------------- ## */
/* ## OFPET_BAD_MATCH ## */
/* ## --------------- ## */

    /* OF1.1+(4).  Error in match. */
    OFPERR_OFPET_BAD_MATCH,

    /* OF1.1+(4,0).  Unsupported match type specified by the match */
    OFPERR_OFPBMC_BAD_TYPE,

    /* OF1.1+(4,1).  Length problem in match. */
    OFPERR_OFPBMC_BAD_LEN,

    /* OF1.1+(4,2).  Match uses an unsupported tag/encap. */
    OFPERR_OFPBMC_BAD_TAG,

    /* OF1.1+(4,3).  Unsupported datalink addr mask - switch does not support
     * arbitrary datalink address mask. */
    OFPERR_OFPBMC_BAD_DL_ADDR_MASK,

    /* OF1.1+(4,4).  Unsupported network addr mask - switch does not support
     * arbitrary network address mask. */
    OFPERR_OFPBMC_BAD_NW_ADDR_MASK,

    /* OF1.1+(4,5).  Unsupported wildcard specified in the match. */
    OFPERR_OFPBMC_BAD_WILDCARDS,

    /* OF1.1+(4,6).  Unsupported field in the match. */
    OFPERR_OFPBMC_BAD_FIELD,

    /* NX1.0(1,258), OF1.1+(4,7).  Unsupported value in a match
     * field. */
    OFPERR_OFPBMC_BAD_VALUE,

    /* NX1.0(1,259), NX1.1(1,259), OF1.2+(4,8).  Unsupported mask specified in
     * the match, field is not dl-address or nw-address. */
    OFPERR_OFPBMC_BAD_MASK,

    /* NX1.0(1,260), NX1.1(1,260), OF1.2+(4,9).  A prerequisite was not met. */
    OFPERR_OFPBMC_BAD_PREREQ,

    /* NX1.0(1,261), NX1.1(1,261), OF1.2+(4,10).  A field type was
     * duplicated. */
    OFPERR_OFPBMC_DUP_FIELD,

    /* OF1.2+(4,11).  Permissions error. */
    OFPERR_OFPBMC_EPERM,

/* ## --------------------- ## */
/* ## OFPET_FLOW_MOD_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(3), OF1.1+(5).  Problem modifying flow entry. */
    OFPERR_OFPET_FLOW_MOD_FAILED,

    /* OF1.1+(5,0).  Unspecified error. */
    OFPERR_OFPFMFC_UNKNOWN,

    /* OF1.0(3,0), OF1.1+(5,1).  Flow not added because of full table(s). */
    OFPERR_OFPFMFC_TABLE_FULL,

    /* OF1.1+(5,2).  Table does not exist */
    OFPERR_OFPFMFC_BAD_TABLE_ID,

    /* OF1.0(3,1), OF1.1+(5,3).  Attempted to add overlapping flow with
     * CHECK_OVERLAP flag set. */
    OFPERR_OFPFMFC_OVERLAP,

    /* OF1.0(3,2), OF1.1+(5,4).  Permissions error. */
    OFPERR_OFPFMFC_EPERM,

    /* OF1.1+(5,5).  Flow not added because of unsupported idle/hard
     * timeout. */
    OFPERR_OFPFMFC_BAD_TIMEOUT,

    /* OF1.0(3,3).  Flow not added because of non-zero idle/hard timeout. */
    OFPERR_OFPFMFC_BAD_EMERG_TIMEOUT,

    /* OF1.0(3,4), OF1.1+(5,6).  Unsupported or unknown command. */
    OFPERR_OFPFMFC_BAD_COMMAND,

    /* OF1.2+(5,7).  Unsupported or unknown flags. */
    OFPERR_OFPFMFC_BAD_FLAGS,

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

    /* OF1.1+(6).  Problem modifying group entry. */
    OFPERR_OFPET_GROUP_MOD_FAILED,

    /* OF1.1+(6,0).  Group not added because a group ADD attempted to replace
     * an already-present group. */
    OFPERR_OFPGMFC_GROUP_EXISTS,

    /* OF1.1+(6,1).  Group not added because Group specified is invalid. */
    OFPERR_OFPGMFC_INVALID_GROUP,

    /* OF1.1+(6,2).  Switch does not support unequal load sharing with select
     * groups. */
    OFPERR_OFPGMFC_WEIGHT_UNSUPPORTED,

    /* OF1.1+(6,3).  The group table is full. */
    OFPERR_OFPGMFC_OUT_OF_GROUPS,

    /* OF1.1+(6,4).  The maximum number of action buckets for a group has been
     * exceeded. */
    OFPERR_OFPGMFC_OUT_OF_BUCKETS,

    /* OF1.1+(6,5).  Switch does not support groups that forward to groups. */
    OFPERR_OFPGMFC_CHAINING_UNSUPPORTED,

    /* OF1.1+(6,6).  This group cannot watch the watch_port or watch_group
     * specified. */
    OFPERR_OFPGMFC_WATCH_UNSUPPORTED,

    /* OF1.1+(6,7).  Group entry would cause a loop. */
    OFPERR_OFPGMFC_LOOP,

    /* OF1.1+(6,8).  Group not modified because a group MODIFY attempted to
     * modify a non-existent group. */
    OFPERR_OFPGMFC_UNKNOWN_GROUP,

    /* OF1.2+(6,9).  Group not deleted because another
                    group is forwarding to it. */
    OFPERR_OFPGMFC_CHAINED_GROUP,

    /* OF1.2+(6,10).  Unsupported or unknown group type. */
    OFPERR_OFPGMFC_BAD_TYPE,

    /* OF1.2+(6,11).  Unsupported or unknown command. */
    OFPERR_OFPGMFC_BAD_COMMAND,

    /* OF1.2+(6,12).  Error in bucket. */
    OFPERR_OFPGMFC_OFPGMFC_BAD_BUCKET,

    /* OF1.2+(6,13).  Error in watch port/group. */
    OFPERR_OFPGMFC_OFPGMFC_BAD_WATCH,

    /* OF1.2+(6,14).  Permissions error. */
    OFPERR_OFPGMFC_OFPGMFC_EPERM,

/* ## --------------------- ## */
/* ## OFPET_PORT_MOD_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(4), OF1.1+(7).  OFPT_PORT_MOD failed. */
    OFPERR_OFPET_PORT_MOD_FAILED,

    /* OF1.0(4,0), OF1.1+(7,0).  Specified port does not exist. */
    OFPERR_OFPPMFC_BAD_PORT,

    /* OF1.0(4,1), OF1.1+(7,1).  Specified hardware address does not match the
     * port number. */
    OFPERR_OFPPMFC_BAD_HW_ADDR,

    /* OF1.1+(7,2).  Specified config is invalid. */
    OFPERR_OFPPMFC_BAD_CONFIG,

    /* OF1.1+(7,3).  Specified advertise is invalid. */
    OFPERR_OFPPMFC_BAD_ADVERTISE,

    /* OF1.2+(7,4).  Permissions error. */
    OFPERR_OFPPMFC_EPERM,

/* ## ---------------------- ## */
/* ## OFPET_TABLE_MOD_FAILED ## */
/* ## ---------------------- ## */

    /* OF1.1+(8).  Table mod request failed. */
    OFPERR_OFPET_TABLE_MOD_FAILED,

    /* OF1.1+(8,0).  Specified table does not exist. */
    OFPERR_OFPTMFC_BAD_TABLE,

    /* OF1.1+(8,1).  Specified config is invalid. */
    OFPERR_OFPTMFC_BAD_CONFIG,

    /* OF1.2+(8,2).  Permissions error. */
    OFPERR_OFPTMFC_EPERM,

/* ## --------------------- ## */
/* ## OFPET_QUEUE_OP_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(5), OF1.1+(9).  Queue operation failed. */
    OFPERR_OFPET_QUEUE_OP_FAILED,

    /* OF1.0(5,0), OF1.1+(9,0).  Invalid port (or port does not exist). */
    OFPERR_OFPQOFC_BAD_PORT,

    /* OF1.0(5,1), OF1.1+(9,1).  Queue does not exist. */
    OFPERR_OFPQOFC_BAD_QUEUE,

    /* OF1.0(5,2), OF1.1+(9,2).  Permissions error. */
    OFPERR_OFPQOFC_EPERM,

/* ## -------------------------- ## */
/* ## OFPET_SWITCH_CONFIG_FAILED ## */
/* ## -------------------------- ## */

    /* OF1.1+(10).  Switch config request failed. */
    OFPERR_OFPET_SWITCH_CONFIG_FAILED,

    /* OF1.1+(10,0).  Specified flags is invalid. */
    OFPERR_OFPSCFC_BAD_FLAGS,

    /* OF1.1+(10,1).  Specified len is invalid. */
    OFPERR_OFPSCFC_BAD_LEN,

    /* OF1.2+(10,2).  Permissions error. */
    OFPERR_OFPSCFC_EPERM,

/* ## ------------------------- ## */
/* ## OFPET_ROLE_REQUEST_FAILED ## */
/* ## ------------------------- ## */

    /* OF1.2+(11).  Controller Role request failed. */
    OFPERR_OFPET_ROLE_REQUEST_FAILED,

    /* OF1.2+(11,0).  Stale Message: old generation_id. */
    OFPERR_OFPRRFC_STALE,

    /* OF1.2+(11,1).  Controller role change unsupported. */
    OFPERR_OFPRRFC_UNSUP,

    /* NX1.0(1,513), NX1.1(1,513), OF1.2+(11,2).  Invalid role. */
    OFPERR_OFPRRFC_BAD_ROLE,

/* ## ------------------ ## */
/* ## OFPET_EXPERIMENTER ## */
/* ## ------------------ ## */

    /* OF1.2+(0xffff).  Experimenter error messages. */
    OFPERR_OFPET_EXPERIMENTER,
};

const char *ofperr_domain_get_name(enum ofp_version);

bool ofperr_is_valid(enum ofperr);
bool ofperr_is_category(enum ofperr);
bool ofperr_is_nx_extension(enum ofperr);
bool ofperr_is_encodable(enum ofperr, enum ofp_version);

enum ofperr ofperr_decode(enum ofp_version, uint16_t type, uint16_t code);
enum ofperr ofperr_decode_type(enum ofp_version, uint16_t type);
enum ofperr ofperr_from_name(const char *);

enum ofperr ofperr_decode_msg(const struct ofp_header *,
                              struct ofpbuf *payload);
struct ofpbuf *ofperr_encode_reply(enum ofperr, const struct ofp_header *);
struct ofpbuf *ofperr_encode_hello(enum ofperr, enum ofp_version ofp_version,
                                   const char *);
int ofperr_get_type(enum ofperr, enum ofp_version);
int ofperr_get_code(enum ofperr, enum ofp_version);

const char *ofperr_get_name(enum ofperr);
const char *ofperr_get_description(enum ofperr);

void ofperr_format(struct ds *, enum ofperr);
const char *ofperr_to_string(enum ofperr);

#endif /* ofp-errors.h */
