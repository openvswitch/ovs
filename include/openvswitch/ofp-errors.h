/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_OFP_ERRORS_H
#define OPENVSWITCH_OFP_ERRORS_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/* OpenFlow error codes
 * --------------------
 *
 * The comments below are parsed by the extract-ofp-errors program at build
 * time and used to determine the mapping between "enum ofperr" constants and
 * error type/code values used in the OpenFlow protocol:
 *
 *   - The first part of each comment specifies the vendor, OpenFlow versions,
 *     type, and sometimes a code for each protocol that supports the error:
 *
 *         # The vendor is OF for standard OpenFlow error codes.  Otherwise it
 *           is one of the *_VENDOR_ID codes defined in openflow-common.h.  (To
 *           add support for a new vendor, add a VENDOR_ID code to that
 *           header.)
 *
 *         # The version can specify a specific OpenFlow version, a version
 *           range delimited by "-", or an open-ended range with "+".
 *
 *         # Standard OpenFlow errors have both a type and a code.  Extension
 *           errors generally have only a type, no code.  There is one
 *           exception: Nicira extension (NX) errors for OpenFlow 1.0 and 1.1
 *           have both a type and a code.  (This means that the version
 *           specification for NX errors may not include version 1.0 or 1.1 (or
 *           both) along with version 1.2 or later, because the requirements
 *           for those versions are different.)
 *
 *   - Additional text is a human-readable description of the meaning of each
 *     error, used to explain the error to the user.  Any text enclosed in
 *     square brackets is omitted; this can be used to explain rationale for
 *     choice of error codes in the case where this is desirable.
 *
 *
 * Expected duplications
 * ---------------------
 *
 * Occasionally, in one version of OpenFlow a single named error can indicate
 * two or more distinct errors, then a later version of OpenFlow splits those
 * meanings into different error codes.  When that happens, both errors are
 * assigned the same value in the earlier version.  That is ordinarily a
 * mistake, so the build system reports an error.  When that happens, add the
 * error message to the list of "Expected duplications" below to suppress the
 * error.  In such a case, the named error defined earlier is how OVS
 * interprets the earlier, merged form of the error.
 *
 * For example, OpenFlow 1.1 defined (3,5) as OFPBIC_UNSUP_EXP_INST, then
 * OpenFlow 1.2 broke this error into OFPBIC_BAD_EXPERIMENTER as (3,5) and
 * OFPBIC_BAD_EXT_TYPE as (3,6).  To allow the OVS code to report just a single
 * error code, instead of protocol version dependent errors, this list of
 * errors only lists the latter two errors, giving both of them the same code
 * (3,5) for OpenFlow 1.1.  Then, when OVS serializes either error into
 * OpenFlow 1.1, it uses the same code (3,5).  In the other direction, when OVS
 * deserializes (3,5) from OpenFlow 1.1, it translates it into
 * OFPBIC_BAD_EXPERIMENTER (because its definition precedes that of
 * OFPBIC_BAD_EXT_TYPE below).  See the "encoding OFPBIC_* experimenter errors"
 * and "decoding OFPBIC_* experimenter errors" tests in tests/ofp-errors.at for
 * full details.
 */
enum ofperr {
/* Expected duplications. */

    /* Expected: 0x0,3,5 in OF1.1 means both OFPBIC_BAD_EXPERIMENTER and
     * OFPBIC_BAD_EXP_TYPE. */

    /* Expected: 0x0,1,5 in OF1.0 means both OFPBRC_EPERM and
     * OFPBRC_IS_SLAVE. */

    /* Expected: 0x0,1,5 in OF1.1 means both OFPBRC_EPERM and
     * OFPBRC_IS_SLAVE. */

/* ## ------------------ ## */
/* ## OFPET_HELLO_FAILED ## */
/* ## ------------------ ## */

    /* OF1.0+(0,0).  No compatible version. */
    OFPERR_OFPHFC_INCOMPATIBLE = OFPERR_OFS,

    /* OF1.0+(0,1).  Permissions error. */
    OFPERR_OFPHFC_EPERM,

/* ## ----------------- ## */
/* ## OFPET_BAD_REQUEST ## */
/* ## ----------------- ## */

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
     *   is used for OpenFlow 1.0 as there seems to be no appropriate error
     *   code defined the specification. ] */
    OFPERR_OFPBRC_BAD_TABLE_ID,

    /* OF1.0-1.1(1,5), OF1.2+(1,10).  Denied because controller is slave. */
    OFPERR_OFPBRC_IS_SLAVE,

    /* NX1.0-1.1(1,514), OF1.2+(1,11).  Invalid port.  [ A non-standard error
     * (1,514), formerly OFPERR_NXBRC_BAD_IN_PORT is used for OpenFlow 1.0 and
     * 1.1 as there seems to be no appropriate error code defined the
     * specifications. ] */
    OFPERR_OFPBRC_BAD_PORT,

    /* OF1.2+(1,12).  Invalid packet in packet-out. */
    OFPERR_OFPBRC_BAD_PACKET,

    /* OF1.3+(1,13).  Multipart request overflowed the assigned buffer. */
    OFPERR_OFPBRC_MULTIPART_BUFFER_OVERFLOW,

    /* OF1.5+(1,17).  Match fields must include only pipeline fields. */
    OFPERR_OFPBRC_PIPELINE_FIELDS_ONLY,

    /* NX1.0-1.1(1,256), NX1.2+(2).  Invalid NXM flow match. */
    OFPERR_NXBRC_NXM_INVALID,

    /* NX1.0-1.1(1,257), NX1.2+(3).  The nxm_type, or nxm_type taken in
     * combination with nxm_hasmask or nxm_length or both, is invalid or not
     * implemented. */
    OFPERR_NXBRC_NXM_BAD_TYPE,

    /* NX1.0-1.1(1,515), NX1.2+(4).  Must-be-zero field had nonzero value. */
    OFPERR_NXBRC_MUST_BE_ZERO,

    /* NX1.0-1.1(1,516), NX1.2+(5).  The reason in an ofp_port_status message
     * is not valid. */
    OFPERR_NXBRC_BAD_REASON,

    /* NX1.0-1.1(1,520), NX1.2+(9).  The 'event' in an NXST_FLOW_MONITOR reply
     * does not specify one of the NXFME_ABBREV, NXFME_ADD, NXFME_DELETE, or
     * NXFME_MODIFY. */
    OFPERR_NXBRC_FM_BAD_EVENT,

    /* NX1.0-1.1(1,521), NX1.2+(10).  The error that occurred cannot be
     * represented in this OpenFlow version. */
    OFPERR_NXBRC_UNENCODABLE_ERROR,

/* ## ---------------- ## */
/* ## OFPET_BAD_ACTION ## */
/* ## ---------------- ## */

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

    /* NX1.0(1,522), OF1.1+(2,10).  Action can't apply for this match or a
     * prerequisite for use of this field is unmet. */
    OFPERR_OFPBAC_MATCH_INCONSISTENT,

    /* OF1.1+(2,11).  Action order is unsupported for the action list in an
     * Apply-Actions instruction */
    OFPERR_OFPBAC_UNSUPPORTED_ORDER,

    /* OF1.1+(2,12).  Actions uses an unsupported tag/encap. */
    OFPERR_OFPBAC_BAD_TAG,

    /* NX1.0-1.1(1,523), OF1.2+(2,13).  Action uses unknown or unsupported OXM
     * or NXM field. */
    OFPERR_OFPBAC_BAD_SET_TYPE,

    /* NX1.0-1.1(1,524), OF1.2+(2,14).  Action references past the end of an
     * OXM or NXM field, or uses a length of zero. */
    OFPERR_OFPBAC_BAD_SET_LEN,

    /* NX1.0-1.1(1,525), OF1.2+(2,15).  Action sets a field to an invalid or
     * unsupported value, or modifies a read-only field. */
    OFPERR_OFPBAC_BAD_SET_ARGUMENT,

    /* ONF1.3-1.4(4250), OF1.5+(2,16).  Field in Set-Field action has Has-Mask
     * bit set to 1. */
    OFPERR_OFPBAC_BAD_SET_MASK,

    /* NX1.0-1.1(2,256), NX1.2+(11).  Must-be-zero action argument had nonzero
     * value. */
    OFPERR_NXBAC_MUST_BE_ZERO,

    /* NX1.0-1.1(2,526), NX1.2+(15).  Conjunction action must be only action
     * present.  conjunction(id, k/n) must satisfy 1 <= k <= n and 2 <= n <=
     * 64. */
    OFPERR_NXBAC_BAD_CONJUNCTION,

    /* NX1.3+(39).  Unsupported packet type in encap or decap. */
    OFPERR_NXBAC_BAD_HEADER_TYPE,

    /* NX1.3+(40).  Unrecognized encap or decap property. */
    OFPERR_NXBAC_UNKNOWN_ED_PROP,

    /* NX1.3+(41).  Error in encap or decap property. */
    OFPERR_NXBAC_BAD_ED_PROP,

    /* NX1.0-1.1(1,265), NX1.2+(42).  Action requires connection tracking or a
     * particular connection-tracking based feature that the datapath in use
     * does not support.  If a kernel-based datapath is in use, the kernel
     * module may need to be upgraded. */
    OFPERR_NXBAC_CT_DATAPATH_SUPPORT,

/* ## --------------------- ## */
/* ## OFPET_BAD_INSTRUCTION ## */
/* ## --------------------- ## */

    /* OF1.1+(3,0).  Unknown instruction. */
    OFPERR_OFPBIC_UNKNOWN_INST,

    /* NX1.0(2,257), OF1.1+(3,1).  Switch or table does not support the
     * instruction. */
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

    /* NX1.1(3,256), ONF1.2-1.3(2600), OF1.4+(3,9).  Duplicate instruction. */
    OFPERR_OFPBIC_DUP_INST,

/* ## --------------- ## */
/* ## OFPET_BAD_MATCH ## */
/* ## --------------- ## */

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

    /* NX1.0(1,262), OF1.1+(4,5).  Unsupported wildcard specified in the
     * match. */
    OFPERR_OFPBMC_BAD_WILDCARDS,

    /* NX1.0(0,263), OF1.1+(4,6).  Unsupported field in the match. */
    OFPERR_OFPBMC_BAD_FIELD,

    /* NX1.0(1,258), OF1.1+(4,7).  Unsupported value in a match
     * field. */
    OFPERR_OFPBMC_BAD_VALUE,

    /* NX1.0-1.1(1,259), OF1.2+(4,8).  Unsupported mask specified in the match,
     * field is not dl-address or nw-address. */
    OFPERR_OFPBMC_BAD_MASK,

    /* NX1.0-1.1(1,260), OF1.2+(4,9).  A prerequisite was not met. */
    OFPERR_OFPBMC_BAD_PREREQ,

    /* NX1.0-1.1(1,261), OF1.2+(4,10).  A field type was duplicated. */
    OFPERR_OFPBMC_DUP_FIELD,

    /* OF1.2+(4,11).  Permissions error. */
    OFPERR_OFPBMC_EPERM,

    /* NX1.0-1.1(1,264), NX1.2+(43).  Flow match requires connection tracking
     * or a particular connection-tracking based feature that the datapath in
     * use does not support.  If a kernel-based datapath is in use, the kernel
     * module may need to be upgraded. */
    OFPERR_NXBMC_CT_DATAPATH_SUPPORT,

/* ## --------------------- ## */
/* ## OFPET_FLOW_MOD_FAILED ## */
/* ## --------------------- ## */

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

    /* NX1.0(3,258), NX1.1(5,258), OF1.2+(5,7).  Unsupported or unknown
     * flags. */
    OFPERR_OFPFMFC_BAD_FLAGS,

    /* OF1.0(3,5).  Unsupported action list - cannot process in the order
     * specified. */
    OFPERR_OFPFMFC_UNSUPPORTED,

    /* NX1.0-1.1(5,256), NX1.2+(12).  Generic hardware error. */
    OFPERR_NXFMFC_HARDWARE,

    /* NX1.0-1.1(5,257), NX1.2+(13).  A nonexistent table ID was specified in
     * the "command" field of struct ofp_flow_mod, when the
     * nxt_flow_mod_table_id extension is enabled. */
    OFPERR_NXFMFC_BAD_TABLE_ID,

    /* NX1.0-1.1(1,536), NX1.2+(37).  Attempted to add a flow with an invalid
     * variable length meta-flow field. */
    OFPERR_NXFMFC_INVALID_TLV_FIELD,

/* ## ---------------------- ## */
/* ## OFPET_GROUP_MOD_FAILED ## */
/* ## ---------------------- ## */

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
    OFPERR_OFPGMFC_BAD_BUCKET,

    /* OF1.2+(6,13).  Error in watch port/group. */
    OFPERR_OFPGMFC_BAD_WATCH,

    /* OF1.2+(6,14).  Permissions error. */
    OFPERR_OFPGMFC_EPERM,

    /* OF1.5+(6,15).  Invalid bucket identifier used in
     * INSERT BUCKET or REMOVE BUCKET command. */
    OFPERR_OFPGMFC_UNKNOWN_BUCKET,

    /* OF1.5+(6,16).  Can't insert bucket because a bucket
     * already exist with that bucket-id. */
    OFPERR_OFPGMFC_BUCKET_EXISTS,

/* ## --------------------- ## */
/* ## OFPET_PORT_MOD_FAILED ## */
/* ## --------------------- ## */

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

    /* OF1.1+(8,0).  Specified table does not exist. */
    OFPERR_OFPTMFC_BAD_TABLE,

    /* OF1.1+(8,1).  Specified config is invalid. */
    OFPERR_OFPTMFC_BAD_CONFIG,

    /* OF1.2+(8,2).  Permissions error. */
    OFPERR_OFPTMFC_EPERM,

/* ## --------------------- ## */
/* ## OFPET_QUEUE_OP_FAILED ## */
/* ## --------------------- ## */

    /* OF1.0(5,0), OF1.1+(9,0).  Invalid port (or port does not exist). */
    OFPERR_OFPQOFC_BAD_PORT,

    /* OF1.0(5,1), OF1.1+(9,1).  Queue does not exist. */
    OFPERR_OFPQOFC_BAD_QUEUE,

    /* OF1.0(5,2), OF1.1+(9,2).  Permissions error. */
    OFPERR_OFPQOFC_EPERM,

    /* NX1.4+(23).  System error retrieving queue details. */
    OFPERR_NXQOFC_QUEUE_ERROR,

/* ## -------------------------- ## */
/* ## OFPET_SWITCH_CONFIG_FAILED ## */
/* ## -------------------------- ## */

    /* OF1.1+(10,0).  Specified flags is invalid. */
    OFPERR_OFPSCFC_BAD_FLAGS,

    /* OF1.1+(10,1).  Specified len is invalid. */
    OFPERR_OFPSCFC_BAD_LEN,

    /* OF1.2+(10,2).  Permissions error. */
    OFPERR_OFPSCFC_EPERM,

/* ## ------------------------- ## */
/* ## OFPET_ROLE_REQUEST_FAILED ## */
/* ## ------------------------- ## */

    /* OF1.2+(11,0).  Stale Message: old generation_id. */
    OFPERR_OFPRRFC_STALE,

    /* OF1.2+(11,1).  Controller role change unsupported. */
    OFPERR_OFPRRFC_UNSUP,

    /* NX1.0-1.1(1,513), OF1.2+(11,2).  Invalid role. */
    OFPERR_OFPRRFC_BAD_ROLE,

/* ## ---------------------- ## */
/* ## OFPET_METER_MOD_FAILED ## */
/* ## ---------------------- ## */

    /* OF1.3+(12,0).  Unspecified error. */
    OFPERR_OFPMMFC_UNKNOWN,

    /* OF1.3+(12,1).  Meter not added because a Meter ADD attempted to
     * replace an existing Meter. */
    OFPERR_OFPMMFC_METER_EXISTS,

    /* OF1.3+(12,2).  Meter not added because Meter specified is invalid. */
    OFPERR_OFPMMFC_INVALID_METER,

    /* OF1.3+(12,3).  Meter not modified because a Meter MODIFY attempted
     * to modify a non-existent Meter. */
    OFPERR_OFPMMFC_UNKNOWN_METER,

    /* OF1.3+(12,4).  Unsupported or unknown command. */
    OFPERR_OFPMMFC_BAD_COMMAND,

    /* OF1.3+(12,5).  Flag configuration unsupported. */
    OFPERR_OFPMMFC_BAD_FLAGS,

    /* OF1.3+(12,6).  Rate unsupported. */
    OFPERR_OFPMMFC_BAD_RATE,

    /* OF1.3+(12,7).  Burst size unsupported. */
    OFPERR_OFPMMFC_BAD_BURST,

    /* OF1.3+(12,8).  Band unsupported. */
    OFPERR_OFPMMFC_BAD_BAND,

    /* OF1.3+(12,9).  Band value unsupported. */
    OFPERR_OFPMMFC_BAD_BAND_VALUE,

    /* OF1.3+(12,10).  No more meters available. */
    OFPERR_OFPMMFC_OUT_OF_METERS,

    /* OF1.3+(12,11).  The maximum number of properties for a meter has
     * been exceeded. */
    OFPERR_OFPMMFC_OUT_OF_BANDS,

/* ## --------------------------- ## */
/* ## OFPET_TABLE_FEATURES_FAILED ## */
/* ## --------------------------- ## */

    /* OF1.3+(13,0).  Specified table does not exist. */
    OFPERR_OFPTFFC_BAD_TABLE,

    /* OF1.3+(13,1).  Invalid metadata mask. */
    OFPERR_OFPTFFC_BAD_METADATA,

    /* OF1.3+(13,5).  Permissions error. */
    OFPERR_OFPTFFC_EPERM,

/* ## ------------------ ## */
/* ## OFPET_BAD_PROPERTY ## */
/* ## ------------------ ## */

    /* NX1.0-1.1(13,2), NX1.2(25), OF1.3(13,2), OF1.4+(14,0).  Unknown property
     * type.
     *
     * [Known as OFPTFFC_BAD_TYPE in OF1.3.] */
    OFPERR_OFPBPC_BAD_TYPE,

    /* NX1.0-1.1(13,3), NX1.2(26), OF1.3(13,3), OF1.4+(14,1).  Length problem
     * in property.
     *
     * [Known as OFPTFFC_BAD_LEN in OF1.3.] */
    OFPERR_OFPBPC_BAD_LEN,

    /* NX1.0-1.1(13,4), NX1.2(27), OF1.3(13,4), OF1.4+(14,2).  Unsupported
     * property value.
     *
     * [Known as OFPTFFC_BAD_ARGUMENT in OF1.3.] */
    OFPERR_OFPBPC_BAD_VALUE,

    /* NX1.0-1.1(14,3), NX1.2(28), ONF1.3(4443), OF1.4+(14,3).  Can't handle
     * this many properties. */
    OFPERR_OFPBPC_TOO_MANY,

    /* NX1.0-1.1(14,4), NX1.2(29), ONF1.3(4444), OF1.4+(14,4).  A property type
     * was duplicated. */
    OFPERR_OFPBPC_DUP_TYPE,

    /* NX1.0-1.1(14,5), NX1.2(30), ONF1.3(4445), OF1.4+(14,5).  Unknown
     * experimenter id specified. */
    OFPERR_OFPBPC_BAD_EXPERIMENTER,

    /* NX1.0-1.1(14,6), NX1.2(31), ONF1.3(4446), OF1.4+(14,6).  Unknown
     * exp_type for experimenter id. */
    OFPERR_OFPBPC_BAD_EXP_TYPE,

    /* NX1.0-1.1(14,7), NX1.2(32), ONF1.3(4447), OF1.4+(14,7).  Unknown value
     * for experimenter id. */
    OFPERR_OFPBPC_BAD_EXP_VALUE,

    /* NX1.0-1.1(14,8), NX1.2(33), ONF1.3(4448), OF1.4+(14,8).  Permissions
     * error. */
    OFPERR_OFPBPC_EPERM,

/* ## -------------------------- ## */
/* ## OFPET_ASYNC_CONFIG_FAILED  ## */
/* ## -------------------------- ## */

    /* OF1.4+(15,0).  One mask is invalid. */
    OFPERR_OFPACFC_INVALID,

    /* OF1.4+(15,1).  Requested configuration not supported. */
    OFPERR_OFPACFC_UNSUPPORTED,

    /* OF1.4+(15,2).  Permissions error. */
    OFPERR_OFPACFC_EPERM,

/* ## -------------------- ## */
/* ## OFPET_BUNDLE_FAILED  ## */
/* ## -------------------- ## */

    /* ONF1.3(2300), OF1.4+(17,0).  Unspecified error. */
    OFPERR_OFPBFC_UNKNOWN,

    /* ONF1.3(2301), OF1.4+(17,1).  Permissions error. */
    OFPERR_OFPBFC_EPERM,

    /* ONF1.3(2302), OF1.4+(17,2).  Bundle ID doesn't exist. */
    OFPERR_OFPBFC_BAD_ID,

    /* ONF1.3(2303), OF1.4+(17,3).  Bundle ID already exists. */
    OFPERR_OFPBFC_BUNDLE_EXIST,

    /* ONF1.3(2304), OF1.4+(17,4).  Bundle ID is closed. */
    OFPERR_OFPBFC_BUNDLE_CLOSED,

    /* ONF1.3(2305), OF1.4+(17,5).  Too many bundle IDs. */
    OFPERR_OFPBFC_OUT_OF_BUNDLES,

    /* ONF1.3(2306), OF1.4+(17,6).  Unsupported of unknown message control
     * type. */
    OFPERR_OFPBFC_BAD_TYPE,

    /* ONF1.3(2307), OF1.4+(17,7).  Unsupported, unknown, or inconsistent
     * flags. */
    OFPERR_OFPBFC_BAD_FLAGS,

    /* ONF1.3(2308), OF1.4+(17,8).  Length problem in included message. */
    OFPERR_OFPBFC_MSG_BAD_LEN,

    /* ONF1.3(2309), OF1.4+(17,9).  Inconsistent or duplicate XID. */
    OFPERR_OFPBFC_MSG_BAD_XID,

    /* ONF1.3(2310), OF1.4+(17,10).  Unsupported message in this bundle. */
    OFPERR_OFPBFC_MSG_UNSUP,

    /* ONF1.3(2311), OF1.4+(17,11).  Unsupported message combination in this
     * bundle. */
    OFPERR_OFPBFC_MSG_CONFLICT,

    /* ONF1.3(2312), OF1.4+(17,12).  Cant handle this many messages in
     * bundle. */
    OFPERR_OFPBFC_MSG_TOO_MANY,

    /* ONF1.3(2313), OF1.4+(17,13).  One message in bundle failed. */
    OFPERR_OFPBFC_MSG_FAILED,

    /* ONF1.3(2314), OF1.4+(17,14).  Bundle is taking too long. */
    OFPERR_OFPBFC_TIMEOUT,

    /* ONF1.3(2315), OF1.4+(17,15).  Bundle is locking the resource. */
    OFPERR_OFPBFC_BUNDLE_IN_PROGRESS,

    /* NX1.4-1.5(22), OF1.6+(17,19).  In an OFPT_BUNDLE_ADD_MESSAGE, the
     * OpenFlow version in the inner and outer messages differ. */
    OFPERR_OFPBFC_BAD_VERSION,

/* ## ------------------------- ## */
/* ## OFPET_FLOW_MONITOR_FAILED ## */
/* ## ------------------------- ## */

    /* OF1.4+(16,0).  Unspecified error. */
    OFPERR_OFPMOFC_UNKNOWN,

    /* NX1.0-1.1(1,517), NX1.2-1.3(6), OF1.4+(16,1).  Monitor not added
     * because a Monitor ADD attempted to replace an existing Monitor. */
    OFPERR_OFPMOFC_MONITOR_EXISTS,

    /* OF1.4+(16,2).  Monitor not added because
     * Monitor specified is invalid. */
    OFPERR_OFPMOFC_INVALID_MONITOR,

    /* NX1.0-1.1(1,519), NX1.2-1.3(8), OF1.4+(16,3).  Monitor not modified
     * because a Monitor MODIFY attempted to modify a non-existent Monitor. */
    OFPERR_OFPMOFC_UNKNOWN_MONITOR,

    /* OF1.4+(16,4).  Unsupported or unknown command. */
    OFPERR_OFPMOFC_BAD_COMMAND,

    /* NX1.0-1.1(1,518), NX1.2-1.3(7), OF1.4+(16,5).  Flag configuration
     * unsupported. */
    OFPERR_OFPMOFC_BAD_FLAGS,

    /* OF1.4+(16,6).  Specified table does not exist. */
    OFPERR_OFPMOFC_BAD_TABLE_ID,

    /* OF1.4+(16,7).  Error in output port/group. */
    OFPERR_OFPMOFC_BAD_OUT,

/* ## ----------------------------- ## */
/* ## OFPET_TLV_TABLE_MOD_FAILED ## */
/* ## ----------------------------- ## */

    /* NX1.0-1.1(1,527), NX1.2+(16).  The TLV table mod command is not
     * recognized as a valid operation. */
    OFPERR_NXTTMFC_BAD_COMMAND,

    /* NX1.0-1.1(1,528), NX1.2+(17).  The option length is not a valid
     * option size for TLVs. */
    OFPERR_NXTTMFC_BAD_OPT_LEN,

    /* NX1.0-1.1(1,529), NX1.2+(18).  The field index is out of range for
     * the supported NX_TUN_METADATA<n> match. */
    OFPERR_NXTTMFC_BAD_FIELD_IDX,

    /* NX1.0-1.1(1,530), NX1.2+(19).  The total set of configured options
     * exceeds the maximum supported by the switch. */
    OFPERR_NXTTMFC_TABLE_FULL,

    /* NX1.0-1.1(1,531), NX1.2+(20).  The controller issued an NXTTMC_ADD
     * command for a field index that is already mapped. */
    OFPERR_NXTTMFC_ALREADY_MAPPED,

    /* NX1.0-1.1(1,532), NX1.2+(21).  The option TLV that is attempting
     * to be mapped is the same as one assigned to a different field. */
    OFPERR_NXTTMFC_DUP_ENTRY,

    /* NX1.0-1.1(1,537), NX1.2+(38).  Attempted to delete a TLV mapping that
     * is used by any active flow. */
    OFPERR_NXTTMFC_INVALID_TLV_DEL,

/* ## ---------- ## */
/* ## NXT_RESUME ## */
/* ## ---------- ## */

    /* NX1.0-1.1(1,533), NX1.2+(34).  This datapath doesn't support
     * NXT_RESUME. */
    OFPERR_NXR_NOT_SUPPORTED,

    /* NX1.0-1.1(1,534), NX1.2+(35).  Continuation is stale: Open vSwitch
     * process has been restarted or bridge has been destroyed since
     * continuation was generated, or continuation was not generated by this
     * Open vSwitch instance. */
    OFPERR_NXR_STALE,

/* ## ---------- ## */
/* ## NXT_STATS  ## */
/* ## ---------- ## */

    /* NX1.0-1.1(1,535), NX1.2+(36).  Protocol is not configured on this
     * Open vSwitch instance. */
    OFPERR_NXST_NOT_CONFIGURED,
};

const char *ofperr_domain_get_name(enum ofp_version);

bool ofperr_is_valid(enum ofperr);

enum ofperr ofperr_from_name(const char *);

enum ofperr ofperr_decode_msg(const struct ofp_header *,
                              struct ofpbuf *payload);
struct ofpbuf *ofperr_encode_reply(enum ofperr, const struct ofp_header *);
struct ofpbuf *ofperr_encode_hello(enum ofperr, enum ofp_version ofp_version,
                                   const char *);
int ofperr_get_vendor(enum ofperr, enum ofp_version);
int ofperr_get_type(enum ofperr, enum ofp_version);
int ofperr_get_code(enum ofperr, enum ofp_version);

const char *ofperr_get_name(enum ofperr);
const char *ofperr_get_description(enum ofperr);

void ofperr_format(struct ds *, enum ofperr);
const char *ofperr_to_string(enum ofperr);

#ifdef __cplusplus
}
#endif

#endif /* ofp-errors.h */
