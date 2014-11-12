/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef OPENFLOW_NICIRA_EXT_H
#define OPENFLOW_NICIRA_EXT_H 1

#include <openflow/openflow.h>
#include <openvswitch/types.h>

/* The following vendor extensions, proposed by Nicira, are not yet
 * standardized, so they are not included in openflow.h.  Some of them may be
 * suitable for standardization; others we never expect to standardize. */


/* Nicira vendor-specific error messages extension.
 *
 * OpenFlow 1.0 has a set of predefined error types (OFPET_*) and codes (which
 * are specific to each type).  It does not have any provision for
 * vendor-specific error codes, and it does not even provide "generic" error
 * codes that can apply to problems not anticipated by the OpenFlow
 * specification authors.
 *
 * This extension attempts to address the problem by adding a generic "error
 * vendor extension".  The extension works as follows: use NXET_VENDOR as type
 * and NXVC_VENDOR_ERROR as code, followed by struct nx_vendor_error with
 * vendor-specific details, followed by at least 64 bytes of the failed
 * request.
 *
 * It would be better to have a type-specific vendor extension, e.g. so that
 * OFPET_BAD_ACTION could be used with vendor-specific code values.  But
 * OFPET_BAD_ACTION and most other standardized types already specify that
 * their 'data' values are (the start of) the OpenFlow message being replied
 * to, so there is no room to insert a vendor ID.
 *
 * Currently this extension is only implemented by Open vSwitch, but it seems
 * like a reasonable candidate for future standardization.
 */

/* This is a random number to avoid accidental collision with any other
 * vendor's extension. */
#define NXET_VENDOR 0xb0c2

/* ofp_error msg 'code' values for NXET_VENDOR. */
enum nx_vendor_code {
    NXVC_VENDOR_ERROR           /* 'data' contains struct nx_vendor_error. */
};

/* 'data' for 'type' == NXET_VENDOR, 'code' == NXVC_VENDOR_ERROR. */
struct nx_vendor_error {
    ovs_be32 vendor;            /* Vendor ID as in struct ofp_vendor_header. */
    ovs_be16 type;              /* Vendor-defined type. */
    ovs_be16 code;              /* Vendor-defined subtype. */
    /* Followed by at least the first 64 bytes of the failed request. */
};

/* Nicira vendor requests and replies. */

/* Header for Nicira vendor requests and replies. */
struct nicira_header {
    struct ofp_header header;
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be32 subtype;           /* See the NXT numbers in ofp-msgs.h. */
};
OFP_ASSERT(sizeof(struct nicira_header) == 16);

/* Header for Nicira vendor stats request and reply messages in OpenFlow
 * 1.0. */
struct nicira10_stats_msg {
    struct ofp10_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;           /* One of NXST_* below. */
    uint8_t pad[4];             /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct nicira10_stats_msg) == 24);

/* Header for Nicira vendor stats request and reply messages in OpenFlow
 * 1.1. */
struct nicira11_stats_msg {
    struct ofp11_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;           /* One of NXST_* below. */
};
OFP_ASSERT(sizeof(struct nicira11_stats_msg) == 24);

/* Fields to use when hashing flows. */
enum nx_hash_fields {
    /* Ethernet source address (NXM_OF_ETH_SRC) only. */
    NX_HASH_FIELDS_ETH_SRC,

    /* L2 through L4, symmetric across src/dst.  Specifically, each of the
     * following fields, if present, is hashed (slashes separate symmetric
     * pairs):
     *
     *  - NXM_OF_ETH_DST / NXM_OF_ETH_SRC
     *  - NXM_OF_ETH_TYPE
     *  - The VID bits from NXM_OF_VLAN_TCI, ignoring PCP and CFI.
     *  - NXM_OF_IP_PROTO
     *  - NXM_OF_IP_SRC / NXM_OF_IP_DST
     *  - NXM_OF_TCP_SRC / NXM_OF_TCP_DST
     */
    NX_HASH_FIELDS_SYMMETRIC_L4
};

/* This command enables or disables an Open vSwitch extension that allows a
 * controller to specify the OpenFlow table to which a flow should be added,
 * instead of having the switch decide which table is most appropriate as
 * required by OpenFlow 1.0.  Because NXM was designed as an extension to
 * OpenFlow 1.0, the extension applies equally to ofp10_flow_mod and
 * nx_flow_mod.  By default, the extension is disabled.
 *
 * When this feature is enabled, Open vSwitch treats struct ofp10_flow_mod's
 * and struct nx_flow_mod's 16-bit 'command' member as two separate fields.
 * The upper 8 bits are used as the table ID, the lower 8 bits specify the
 * command as usual.  A table ID of 0xff is treated like a wildcarded table ID.
 *
 * The specific treatment of the table ID depends on the type of flow mod:
 *
 *    - OFPFC_ADD: Given a specific table ID, the flow is always placed in that
 *      table.  If an identical flow already exists in that table only, then it
 *      is replaced.  If the flow cannot be placed in the specified table,
 *      either because the table is full or because the table cannot support
 *      flows of the given type, the switch replies with an OFPFMFC_TABLE_FULL
 *      error.  (A controller can distinguish these cases by comparing the
 *      current and maximum number of entries reported in ofp_table_stats.)
 *
 *      If the table ID is wildcarded, the switch picks an appropriate table
 *      itself.  If an identical flow already exist in the selected flow table,
 *      then it is replaced.  The choice of table might depend on the flows
 *      that are already in the switch; for example, if one table fills up then
 *      the switch might fall back to another one.
 *
 *    - OFPFC_MODIFY, OFPFC_DELETE: Given a specific table ID, only flows
 *      within that table are matched and modified or deleted.  If the table ID
 *      is wildcarded, flows within any table may be matched and modified or
 *      deleted.
 *
 *    - OFPFC_MODIFY_STRICT, OFPFC_DELETE_STRICT: Given a specific table ID,
 *      only a flow within that table may be matched and modified or deleted.
 *      If the table ID is wildcarded and exactly one flow within any table
 *      matches, then it is modified or deleted; if flows in more than one
 *      table match, then none is modified or deleted.
 */
struct nx_flow_mod_table_id {
    uint8_t set;                /* Nonzero to enable, zero to disable. */
    uint8_t pad[7];
};
OFP_ASSERT(sizeof(struct nx_flow_mod_table_id) == 8);

enum nx_packet_in_format {
    NXPIF_OPENFLOW10 = 0,       /* Standard OpenFlow 1.0 compatible. */
    NXPIF_NXM = 1               /* Nicira Extended. */
};

/* NXT_SET_PACKET_IN_FORMAT request. */
struct nx_set_packet_in_format {
    ovs_be32 format;            /* One of NXPIF_*. */
};
OFP_ASSERT(sizeof(struct nx_set_packet_in_format) == 4);

/* NXT_PACKET_IN (analogous to OFPT_PACKET_IN).
 *
 * NXT_PACKET_IN is similar to the OpenFlow 1.2 OFPT_PACKET_IN.  The
 * differences are:
 *
 *     - NXT_PACKET_IN includes the cookie of the rule that triggered the
 *       message.  (OpenFlow 1.3 OFPT_PACKET_IN also includes the cookie.)
 *
 *     - The metadata fields use NXM (instead of OXM) field numbers.
 *
 * Open vSwitch 1.9.0 and later omits metadata fields that are zero (as allowed
 * by OpenFlow 1.2).  Earlier versions included all implemented metadata
 * fields.
 *
 * Open vSwitch does not include non-metadata in the nx_match, because by
 * definition that information can be found in the packet itself.  The format
 * and the standards allow this, however, so controllers should be prepared to
 * tolerate future changes.
 *
 * The NXM format is convenient for reporting metadata values, but it is
 * important not to interpret the format as matching against a flow, because it
 * does not.  Nothing is being matched; arbitrary metadata masks would not be
 * meaningful.
 *
 * Whereas in most cases a controller can expect to only get back NXM fields
 * that it set up itself (e.g. flow dumps will ordinarily report only NXM
 * fields from flows that the controller added), NXT_PACKET_IN messages might
 * contain fields that the controller does not understand, because the switch
 * might support fields (new registers, new protocols, etc.) that the
 * controller does not.  The controller must prepared to tolerate these.
 *
 * The 'cookie' field has no meaning when 'reason' is OFPR_NO_MATCH.  In this
 * case it should be UINT64_MAX. */
struct nx_packet_in {
    ovs_be32 buffer_id;       /* ID assigned by datapath. */
    ovs_be16 total_len;       /* Full length of frame. */
    uint8_t reason;           /* Reason packet is sent (one of OFPR_*). */
    uint8_t table_id;         /* ID of the table that was looked up. */
    ovs_be64 cookie;          /* Cookie of the rule that was looked up. */
    ovs_be16 match_len;       /* Size of nx_match. */
    uint8_t pad[6];           /* Align to 64-bits. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, then
     *   - Exactly 2 all-zero padding bytes, then
     *   - An Ethernet frame whose length is inferred from nxh.header.length.
     *
     * The padding bytes preceding the Ethernet frame ensure that the IP
     * header (if any) following the Ethernet header is 32-bit aligned. */

    /* uint8_t nxm_fields[...]; */ /* NXM headers. */
    /* uint8_t pad[2]; */          /* Align to 64 bit + 16 bit. */
    /* uint8_t data[0]; */         /* Ethernet frame. */
};
OFP_ASSERT(sizeof(struct nx_packet_in) == 24);

/* Configures the "role" of the sending controller.  The default role is:
 *
 *    - Other (NX_ROLE_OTHER), which allows the controller access to all
 *      OpenFlow features.
 *
 * The other possible roles are a related pair:
 *
 *    - Master (NX_ROLE_MASTER) is equivalent to Other, except that there may
 *      be at most one Master controller at a time: when a controller
 *      configures itself as Master, any existing Master is demoted to the
 *      Slave role.
 *
 *    - Slave (NX_ROLE_SLAVE) allows the controller read-only access to
 *      OpenFlow features.  In particular attempts to modify the flow table
 *      will be rejected with an OFPBRC_EPERM error.
 *
 *      Slave controllers do not receive OFPT_PACKET_IN or OFPT_FLOW_REMOVED
 *      messages, but they do receive OFPT_PORT_STATUS messages.
 */
struct nx_role_request {
    ovs_be32 role;              /* One of NX_ROLE_*. */
};
OFP_ASSERT(sizeof(struct nx_role_request) == 4);

enum nx_role {
    NX_ROLE_OTHER,              /* Default role, full access. */
    NX_ROLE_MASTER,             /* Full access, at most one. */
    NX_ROLE_SLAVE               /* Read-only access. */
};

/* NXT_SET_ASYNC_CONFIG.
 *
 * Sent by a controller, this message configures the asynchronous messages that
 * the controller wants to receive.  Element 0 in each array specifies messages
 * of interest when the controller has an "other" or "master" role; element 1,
 * when the controller has a "slave" role.
 *
 * Each array element is a bitmask in which a 0-bit disables receiving a
 * particular message and a 1-bit enables receiving it.  Each bit controls the
 * message whose 'reason' corresponds to the bit index.  For example, the bit
 * with value 1<<2 == 4 in port_status_mask[1] determines whether the
 * controller will receive OFPT_PORT_STATUS messages with reason OFPPR_MODIFY
 * (value 2) when the controller has a "slave" role.
 *
 * As a side effect, for service controllers, this message changes the
 * miss_send_len from default of zero to OFP_DEFAULT_MISS_SEND_LEN (128).
 */
struct nx_async_config {
    ovs_be32 packet_in_mask[2];    /* Bitmasks of OFPR_* values. */
    ovs_be32 port_status_mask[2];  /* Bitmasks of OFPRR_* values. */
    ovs_be32 flow_removed_mask[2]; /* Bitmasks of OFPPR_* values. */
};
OFP_ASSERT(sizeof(struct nx_async_config) == 24);

/* Flexible flow specifications (aka NXM = Nicira Extended Match).
 *
 * OpenFlow 1.0 has "struct ofp10_match" for specifying flow matches.  This
 * structure is fixed-length and hence difficult to extend.  This section
 * describes a more flexible, variable-length flow match, called "nx_match" for
 * short, that is also supported by Open vSwitch.  This section also defines a
 * replacement for each OpenFlow message that includes struct ofp10_match.
 *
 * OpenFlow 1.2+ introduced OpenFlow Extensible Match (OXM), adapting
 * the design of NXM.  The format of NXM and OXM are compatible.
 *
 *
 * Format
 * ======
 *
 * An nx_match is a sequence of zero or more "nxm_entry"s, which are
 * type-length-value (TLV) entries, each 5 to 259 (inclusive) bytes long.
 * "nxm_entry"s are not aligned on or padded to any multibyte boundary.  The
 * first 4 bytes of an nxm_entry are its "header", followed by the entry's
 * "body".
 *
 * An nxm_entry's header is interpreted as a 32-bit word in network byte order:
 *
 * |<-------------------- nxm_type ------------------>|
 * |                                                  |
 * |31                              16 15            9| 8 7                0
 * +----------------------------------+---------------+--+------------------+
 * |            nxm_vendor            |   nxm_field   |hm|    nxm_length    |
 * +----------------------------------+---------------+--+------------------+
 *
 * The most-significant 23 bits of the header are collectively "nxm_type".
 * Bits 16...31 are "nxm_vendor", one of OFPXMC12_* values.  In case of
 * NXM, it's either OFPXMC12_NXM_0 or OFPXMC12_NXM_1.
 * Bits 9...15 are "nxm_field", which is a vendor-specific value.  nxm_type
 * normally designates a protocol header, such as the Ethernet type, but it
 * can also refer to packet metadata, such as the switch port on which a packet
 * arrived.
 *
 * Bit 8 is "nxm_hasmask" (labeled "hm" above for space reasons).  The meaning
 * of this bit is explained later.
 *
 * The least-significant 8 bits are "nxm_length", a positive integer.  The
 * length of the nxm_entry, including the header, is exactly 4 + nxm_length
 * bytes.
 *
 * For a given nxm_vendor, nxm_field, and nxm_hasmask value, nxm_length is a
 * constant.  It is included only to allow software to minimally parse
 * "nxm_entry"s of unknown types.  (Similarly, for a given nxm_vendor,
 * nxm_field, and nxm_length, nxm_hasmask is a constant.)
 *
 *
 * Semantics
 * =========
 *
 * A zero-length nx_match (one with no "nxm_entry"s) matches every packet.
 *
 * An nxm_entry places a constraint on the packets matched by the nx_match:
 *
 *   - If nxm_hasmask is 0, the nxm_entry's body contains a value for the
 *     field, called "nxm_value".  The nx_match matches only packets in which
 *     the field equals nxm_value.
 *
 *   - If nxm_hasmask is 1, then the nxm_entry's body contains a value for the
 *     field (nxm_value), followed by a bitmask of the same length as the
 *     value, called "nxm_mask".  For each 1-bit in position J in nxm_mask, the
 *     nx_match matches only packets for which bit J in the given field's value
 *     matches bit J in nxm_value.  A 0-bit in nxm_mask causes the
 *     corresponding bit in nxm_value is ignored (it should be 0; Open vSwitch
 *     may enforce this someday), as is the corresponding bit in the field's
 *     value.  (The sense of the nxm_mask bits is the opposite of that used by
 *     the "wildcards" member of struct ofp10_match.)
 *
 *     When nxm_hasmask is 1, nxm_length is always even.
 *
 *     An all-zero-bits nxm_mask is equivalent to omitting the nxm_entry
 *     entirely.  An all-one-bits nxm_mask is equivalent to specifying 0 for
 *     nxm_hasmask.
 *
 * When there are multiple "nxm_entry"s, all of the constraints must be met.
 *
 *
 * Mask Restrictions
 * =================
 *
 * Masks may be restricted:
 *
 *   - Some nxm_types may not support masked wildcards, that is, nxm_hasmask
 *     must always be 0 when these fields are specified.  For example, the
 *     field that identifies the port on which a packet was received may not be
 *     masked.
 *
 *   - Some nxm_types that do support masked wildcards may only support certain
 *     nxm_mask patterns.  For example, fields that have IPv4 address values
 *     may be restricted to CIDR masks.
 *
 * These restrictions should be noted in specifications for individual fields.
 * A switch may accept an nxm_hasmask or nxm_mask value that the specification
 * disallows, if the switch correctly implements support for that nxm_hasmask
 * or nxm_mask value.  A switch must reject an attempt to set up a flow that
 * contains a nxm_hasmask or nxm_mask value that it does not support.
 *
 *
 * Prerequisite Restrictions
 * =========================
 *
 * The presence of an nxm_entry with a given nxm_type may be restricted based
 * on the presence of or values of other "nxm_entry"s.  For example:
 *
 *   - An nxm_entry for nxm_type=NXM_OF_IP_TOS is allowed only if it is
 *     preceded by another entry with nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0,
 *     and nxm_value=0x0800.  That is, matching on the IP source address is
 *     allowed only if the Ethernet type is explicitly set to IP.
 *
 *   - An nxm_entry for nxm_type=NXM_OF_TCP_SRC is allowed only if it is
 *     preceded by an entry with nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0, and
 *     nxm_value either 0x0800 or 0x86dd, and another with
 *     nxm_type=NXM_OF_IP_PROTO, nxm_hasmask=0, nxm_value=6, in that order.
 *     That is, matching on the TCP source port is allowed only if the Ethernet
 *     type is IP or IPv6 and the IP protocol is TCP.
 *
 * These restrictions should be noted in specifications for individual fields.
 * A switch may implement relaxed versions of these restrictions.  A switch
 * must reject an attempt to set up a flow that violates its restrictions.
 *
 *
 * Ordering Restrictions
 * =====================
 *
 * An nxm_entry that has prerequisite restrictions must appear after the
 * "nxm_entry"s for its prerequisites.  Ordering of "nxm_entry"s within an
 * nx_match is not otherwise constrained.
 *
 * Any given nxm_type may appear in an nx_match at most once.
 *
 *
 * nxm_entry Examples
 * ==================
 *
 * These examples show the format of a single nxm_entry with particular
 * nxm_hasmask and nxm_length values.  The diagrams are labeled with field
 * numbers and byte indexes.
 *
 *
 * 8-bit nxm_value, nxm_hasmask=1, nxm_length=2:
 *
 *  0          3  4   5
 * +------------+---+---+
 * |   header   | v | m |
 * +------------+---+---+
 *
 *
 * 16-bit nxm_value, nxm_hasmask=0, nxm_length=2:
 *
 *  0          3 4    5
 * +------------+------+
 * |   header   | value|
 * +------------+------+
 *
 *
 * 32-bit nxm_value, nxm_hasmask=0, nxm_length=4:
 *
 *  0          3 4           7
 * +------------+-------------+
 * |   header   |  nxm_value  |
 * +------------+-------------+
 *
 *
 * 48-bit nxm_value, nxm_hasmask=0, nxm_length=6:
 *
 *  0          3 4                9
 * +------------+------------------+
 * |   header   |     nxm_value    |
 * +------------+------------------+
 *
 *
 * 48-bit nxm_value, nxm_hasmask=1, nxm_length=12:
 *
 *  0          3 4                9 10              15
 * +------------+------------------+------------------+
 * |   header   |     nxm_value    |      nxm_mask    |
 * +------------+------------------+------------------+
 *
 *
 * Error Reporting
 * ===============
 *
 * A switch should report an error in an nx_match using error type
 * OFPET_BAD_REQUEST and one of the NXBRC_NXM_* codes.  Ideally the switch
 * should report a specific error code, if one is assigned for the particular
 * problem, but NXBRC_NXM_INVALID is also available to report a generic
 * nx_match error.
 */

/* Number of registers allocated NXM field IDs. */
#define NXM_NX_MAX_REGS 16

/* Bits in the value of NXM_NX_IP_FRAG. */
#define NX_IP_FRAG_ANY   (1 << 0) /* Is this a fragment? */
#define NX_IP_FRAG_LATER (1 << 1) /* Is this a fragment with nonzero offset? */

/* ## --------------------- ## */
/* ## Requests and replies. ## */
/* ## --------------------- ## */

enum nx_flow_format {
    NXFF_OPENFLOW10 = 0,         /* Standard OpenFlow 1.0 compatible. */
    NXFF_NXM = 2                 /* Nicira extended match. */
};

/* NXT_SET_FLOW_FORMAT request. */
struct nx_set_flow_format {
    ovs_be32 format;            /* One of NXFF_*. */
};
OFP_ASSERT(sizeof(struct nx_set_flow_format) == 4);

/* NXT_FLOW_MOD (analogous to OFPT_FLOW_MOD).
 *
 * It is possible to limit flow deletions and modifications to certain
 * cookies by using the NXM_NX_COOKIE(_W) matches.  The "cookie" field
 * is used only to add or modify flow cookies.
 */
struct nx_flow_mod {
    ovs_be64 cookie;              /* Opaque controller-issued identifier. */
    ovs_be16 command;             /* OFPFC_* + possibly a table ID (see comment
                                   * on struct nx_flow_mod_table_id). */
    ovs_be16 idle_timeout;        /* Idle time before discarding (seconds). */
    ovs_be16 hard_timeout;        /* Max time before discarding (seconds). */
    ovs_be16 priority;            /* Priority level of flow entry. */
    ovs_be32 buffer_id;           /* Buffered packet to apply to (or -1).
                                     Not meaningful for OFPFC_DELETE*. */
    ovs_be16 out_port;            /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_NONE
                                     indicates no restriction. */
    ovs_be16 flags;               /* One of OFPFF_*. */
    ovs_be16 match_len;           /* Size of nx_match. */
    uint8_t pad[6];               /* Align to 64-bits. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, then
     *   - Actions to fill out the remainder of the message length (always a
     *     multiple of 8).
     */
};
OFP_ASSERT(sizeof(struct nx_flow_mod) == 32);

/* NXT_FLOW_REMOVED (analogous to OFPT_FLOW_REMOVED).
 *
 * 'table_id' is present only in Open vSwitch 1.11 and later.  In earlier
 * versions of Open vSwitch, this is a padding byte that is always zeroed.
 * Therefore, a 'table_id' value of 0 indicates that the table ID is not known,
 * and other values may be interpreted as one more than the flow's former table
 * ID. */
struct nx_flow_removed {
    ovs_be64 cookie;          /* Opaque controller-issued identifier. */
    ovs_be16 priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t table_id;         /* Flow's former table ID, plus one. */
    ovs_be32 duration_sec;    /* Time flow was alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow was alive in nanoseconds beyond
                                 duration_sec. */
    ovs_be16 idle_timeout;    /* Idle timeout from original flow mod. */
    ovs_be16 match_len;       /* Size of nx_match. */
    ovs_be64 packet_count;
    ovs_be64 byte_count;
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes. */
};
OFP_ASSERT(sizeof(struct nx_flow_removed) == 40);

/* Nicira vendor stats request of type NXST_FLOW (analogous to OFPST_FLOW
 * request).
 *
 * It is possible to limit matches to certain cookies by using the
 * NXM_NX_COOKIE and NXM_NX_COOKIE_W matches.
 */
struct nx_flow_stats_request {
    ovs_be16 out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
    ovs_be16 match_len;       /* Length of nx_match. */
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 or 0xff for all tables. */
    uint8_t pad[3];           /* Align to 64 bits. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, which must also exactly fill out the length of the
     *     message.
     */
};
OFP_ASSERT(sizeof(struct nx_flow_stats_request) == 8);

/* Body for Nicira vendor stats reply of type NXST_FLOW (analogous to
 * OFPST_FLOW reply).
 *
 * The values of 'idle_age' and 'hard_age' are only meaningful when talking to
 * a switch that implements the NXT_FLOW_AGE extension.  Zero means that the
 * true value is unknown, perhaps because hardware does not track the value.
 * (Zero is also the value that one should ordinarily expect to see talking to
 * a switch that does not implement NXT_FLOW_AGE, since those switches zero the
 * padding bytes that these fields replaced.)  A nonzero value X represents X-1
 * seconds.  A value of 65535 represents 65534 or more seconds.
 *
 * 'idle_age' is the number of seconds that the flow has been idle, that is,
 * the number of seconds since a packet passed through the flow.  'hard_age' is
 * the number of seconds since the flow was last modified (e.g. OFPFC_MODIFY or
 * OFPFC_MODIFY_STRICT).  (The 'duration_*' fields are the elapsed time since
 * the flow was added, regardless of subsequent modifications.)
 *
 * For a flow with an idle or hard timeout, 'idle_age' or 'hard_age',
 * respectively, will ordinarily be smaller than the timeout, but flow
 * expiration times are only approximate and so one must be prepared to
 * tolerate expirations that occur somewhat early or late.
 */
struct nx_flow_stats {
    ovs_be16 length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    ovs_be32 duration_sec;    /* Time flow has been alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow has been alive in nanoseconds
                                 beyond duration_sec. */
    ovs_be16 priority;        /* Priority of the entry. */
    ovs_be16 idle_timeout;    /* Number of seconds idle before expiration. */
    ovs_be16 hard_timeout;    /* Number of seconds before expiration. */
    ovs_be16 match_len;       /* Length of nx_match. */
    ovs_be16 idle_age;        /* Seconds since last packet, plus one. */
    ovs_be16 hard_age;        /* Seconds since last modification, plus one. */
    ovs_be64 cookie;          /* Opaque controller-issued identifier. */
    ovs_be64 packet_count;    /* Number of packets, UINT64_MAX if unknown. */
    ovs_be64 byte_count;      /* Number of bytes, UINT64_MAX if unknown. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, then
     *   - Actions to fill out the remainder 'length' bytes (always a multiple
     *     of 8).
     */
};
OFP_ASSERT(sizeof(struct nx_flow_stats) == 48);

/* Nicira vendor stats request of type NXST_AGGREGATE (analogous to
 * OFPST_AGGREGATE request).
 *
 * The reply format is identical to the reply format for OFPST_AGGREGATE,
 * except for the header. */
struct nx_aggregate_stats_request {
    ovs_be16 out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
    ovs_be16 match_len;       /* Length of nx_match. */
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 or 0xff for all tables. */
    uint8_t pad[3];           /* Align to 64 bits. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, which must also exactly fill out the length of the
     *     message.
     */
};
OFP_ASSERT(sizeof(struct nx_aggregate_stats_request) == 8);

/* NXT_SET_CONTROLLER_ID.
 *
 * Each OpenFlow controller connection has a 16-bit identifier that is
 * initially 0.  This message changes the connection's ID to 'id'.
 *
 * Controller connection IDs need not be unique.
 *
 * The NXAST_CONTROLLER action is the only current user of controller
 * connection IDs. */
struct nx_controller_id {
    uint8_t zero[6];            /* Must be zero. */
    ovs_be16 controller_id;     /* New controller connection ID. */
};
OFP_ASSERT(sizeof(struct nx_controller_id) == 8);

/* Flow Table Monitoring
 * =====================
 *
 * NXST_FLOW_MONITOR allows a controller to keep track of changes to OpenFlow
 * flow table(s) or subsets of them, with the following workflow:
 *
 * 1. The controller sends an NXST_FLOW_MONITOR request to begin monitoring
 *    flows.  The 'id' in the request must be unique among all monitors that
 *    the controller has started and not yet canceled on this OpenFlow
 *    connection.
 *
 * 2. The switch responds with an NXST_FLOW_MONITOR reply.  If the request's
 *    'flags' included NXFMF_INITIAL, the reply includes all the flows that
 *    matched the request at the time of the request (with event NXFME_ADDED).
 *    If 'flags' did not include NXFMF_INITIAL, the reply is empty.
 *
 *    The reply uses the xid of the request (as do all replies to OpenFlow
 *    requests).
 *
 * 3. Whenever a change to a flow table entry matches some outstanding monitor
 *    request's criteria and flags, the switch sends a notification to the
 *    controller as an additional NXST_FLOW_MONITOR reply with xid 0.
 *
 *    When multiple outstanding monitors match a single change, only a single
 *    notification is sent.  This merged notification includes the information
 *    requested in any of the individual monitors.  That is, if any of the
 *    matching monitors requests actions (NXFMF_ACTIONS), the notification
 *    includes actions, and if any of the monitors request full changes for the
 *    controller's own changes (NXFMF_OWN), the controller's own changes will
 *    be included in full.
 *
 * 4. The controller may cancel a monitor with NXT_FLOW_MONITOR_CANCEL.  No
 *    further notifications will be sent on the basis of the canceled monitor
 *    afterward.
 *
 *
 * Buffer Management
 * =================
 *
 * OpenFlow messages for flow monitor notifications can overflow the buffer
 * space available to the switch, either temporarily (e.g. due to network
 * conditions slowing OpenFlow traffic) or more permanently (e.g. the sustained
 * rate of flow table change exceeds the network bandwidth between switch and
 * controller).
 *
 * When Open vSwitch's notification buffer space reaches a limiting threshold,
 * OVS reacts as follows:
 *
 * 1. OVS sends an NXT_FLOW_MONITOR_PAUSED message to the controller, following
 *    all the already queued notifications.  After it receives this message,
 *    the controller knows that its view of the flow table, as represented by
 *    flow monitor notifications, is incomplete.
 *
 * 2. As long as the notification buffer is not empty:
 *
 *        - NXMFE_ADD and NXFME_MODIFIED notifications will not be sent.
 *
 *        - NXFME_DELETED notifications will still be sent, but only for flows
 *          that existed before OVS sent NXT_FLOW_MONITOR_PAUSED.
 *
 *        - NXFME_ABBREV notifications will not be sent.  They are treated as
 *          the expanded version (and therefore only the NXFME_DELETED
 *          components, if any, are sent).
 *
 * 3. When the notification buffer empties, OVS sends NXFME_ADD notifications
 *    for flows added since the buffer reached its limit and NXFME_MODIFIED
 *    notifications for flows that existed before the limit was reached and
 *    changed after the limit was reached.
 *
 * 4. OVS sends an NXT_FLOW_MONITOR_RESUMED message to the controller.  After
 *    it receives this message, the controller knows that its view of the flow
 *    table, as represented by flow monitor notifications, is again complete.
 *
 * This allows the maximum buffer space requirement for notifications to be
 * bounded by the limit plus the maximum number of supported flows.
 *
 *
 * "Flow Removed" messages
 * =======================
 *
 * The flow monitor mechanism is independent of OFPT_FLOW_REMOVED and
 * NXT_FLOW_REMOVED.  Flow monitor updates for deletion are sent if
 * NXFMF_DELETE is set on a monitor, regardless of whether the
 * OFPFF_SEND_FLOW_REM flag was set when the flow was added. */

/* NXST_FLOW_MONITOR request.
 *
 * The NXST_FLOW_MONITOR request's body consists of an array of zero or more
 * instances of this structure.  The request arranges to monitor the flows
 * that match the specified criteria, which are interpreted in the same way as
 * for NXST_FLOW.
 *
 * 'id' identifies a particular monitor for the purpose of allowing it to be
 * canceled later with NXT_FLOW_MONITOR_CANCEL.  'id' must be unique among
 * existing monitors that have not already been canceled.
 *
 * The reply includes the initial flow matches for monitors that have the
 * NXFMF_INITIAL flag set.  No single flow will be included in the reply more
 * than once, even if more than one requested monitor matches that flow.  The
 * reply will be empty if none of the monitors has NXFMF_INITIAL set or if none
 * of the monitors initially matches any flows.
 *
 * For NXFMF_ADD, an event will be reported if 'out_port' matches against the
 * actions of the flow being added or, for a flow that is replacing an existing
 * flow, if 'out_port' matches against the actions of the flow being replaced.
 * For NXFMF_DELETE, 'out_port' matches against the actions of a flow being
 * deleted.  For NXFMF_MODIFY, an event will be reported if 'out_port' matches
 * either the old or the new actions. */
struct nx_flow_monitor_request {
    ovs_be32 id;                /* Controller-assigned ID for this monitor. */
    ovs_be16 flags;             /* NXFMF_*. */
    ovs_be16 out_port;          /* Required output port, if not OFPP_NONE. */
    ovs_be16 match_len;         /* Length of nx_match. */
    uint8_t table_id;           /* One table's ID or 0xff for all tables. */
    uint8_t zeros[5];           /* Align to 64 bits (must be zero). */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes. */
};
OFP_ASSERT(sizeof(struct nx_flow_monitor_request) == 16);

/* 'flags' bits in struct nx_flow_monitor_request. */
enum nx_flow_monitor_flags {
    /* When to send updates. */
    NXFMF_INITIAL = 1 << 0,     /* Initially matching flows. */
    NXFMF_ADD = 1 << 1,         /* New matching flows as they are added. */
    NXFMF_DELETE = 1 << 2,      /* Old matching flows as they are removed. */
    NXFMF_MODIFY = 1 << 3,      /* Matching flows as they are changed. */

    /* What to include in updates. */
    NXFMF_ACTIONS = 1 << 4,     /* If set, actions are included. */
    NXFMF_OWN = 1 << 5,         /* If set, include own changes in full. */
};

/* NXST_FLOW_MONITOR reply header.
 *
 * The body of an NXST_FLOW_MONITOR reply is an array of variable-length
 * structures, each of which begins with this header.  The 'length' member may
 * be used to traverse the array, and the 'event' member may be used to
 * determine the particular structure.
 *
 * Every instance is a multiple of 8 bytes long. */
struct nx_flow_update_header {
    ovs_be16 length;            /* Length of this entry. */
    ovs_be16 event;             /* One of NXFME_*. */
    /* ...other data depending on 'event'... */
};
OFP_ASSERT(sizeof(struct nx_flow_update_header) == 4);

/* 'event' values in struct nx_flow_update_header. */
enum nx_flow_update_event {
    /* struct nx_flow_update_full. */
    NXFME_ADDED = 0,            /* Flow was added. */
    NXFME_DELETED = 1,          /* Flow was deleted. */
    NXFME_MODIFIED = 2,         /* Flow (generally its actions) was changed. */

    /* struct nx_flow_update_abbrev. */
    NXFME_ABBREV = 3,           /* Abbreviated reply. */
};

/* NXST_FLOW_MONITOR reply for NXFME_ADDED, NXFME_DELETED, and
 * NXFME_MODIFIED. */
struct nx_flow_update_full {
    ovs_be16 length;            /* Length is 24. */
    ovs_be16 event;             /* One of NXFME_*. */
    ovs_be16 reason;            /* OFPRR_* for NXFME_DELETED, else zero. */
    ovs_be16 priority;          /* Priority of the entry. */
    ovs_be16 idle_timeout;      /* Number of seconds idle before expiration. */
    ovs_be16 hard_timeout;      /* Number of seconds before expiration. */
    ovs_be16 match_len;         /* Length of nx_match. */
    uint8_t table_id;           /* ID of flow's table. */
    uint8_t pad;                /* Reserved, currently zeroed. */
    ovs_be64 cookie;            /* Opaque controller-issued identifier. */
    /* Followed by:
     *   - Exactly match_len (possibly 0) bytes containing the nx_match, then
     *   - Exactly (match_len + 7)/8*8 - match_len (between 0 and 7) bytes of
     *     all-zero bytes, then
     *   - Actions to fill out the remainder 'length' bytes (always a multiple
     *     of 8).  If NXFMF_ACTIONS was not specified, or 'event' is
     *     NXFME_DELETED, no actions are included.
     */
};
OFP_ASSERT(sizeof(struct nx_flow_update_full) == 24);

/* NXST_FLOW_MONITOR reply for NXFME_ABBREV.
 *
 * When the controller does not specify NXFMF_OWN in a monitor request, any
 * flow tables changes due to the controller's own requests (on the same
 * OpenFlow channel) will be abbreviated, when possible, to this form, which
 * simply specifies the 'xid' of the OpenFlow request (e.g. an OFPT_FLOW_MOD or
 * NXT_FLOW_MOD) that caused the change.
 *
 * Some changes cannot be abbreviated and will be sent in full:
 *
 *   - Changes that only partially succeed.  This can happen if, for example,
 *     a flow_mod with type OFPFC_MODIFY affects multiple flows, but only some
 *     of those modifications succeed (e.g. due to hardware limitations).
 *
 *     This cannot occur with the Open vSwitch software datapath.  This also
 *     cannot occur in Open vSwitch 2.4 and later, because these versions only
 *     execute any flow modifications if all of them will succeed.
 *
 *   - Changes that race with conflicting changes made by other controllers or
 *     other flow_mods (not separated by barriers) by the same controller.
 *
 *     This cannot occur with the current Open vSwitch implementation
 *     (regardless of datapath) because Open vSwitch internally serializes
 *     potentially conflicting changes.
 *
 *   - Changes that occur when flow notification is paused (see "Buffer
 *     Management" above).
 *
 * A flow_mod that does not change the flow table will not trigger any
 * notification, even an abbreviated one.  For example, a "modify" or "delete"
 * flow_mod that does not match any flows will not trigger a notification.
 * Whether an "add" or "modify" that specifies all the same parameters that a
 * flow already has triggers a notification is unspecified and subject to
 * change in future versions of Open vSwitch.
 *
 * OVS will always send the notifications for a given flow table change before
 * the reply to a OFPT_BARRIER_REQUEST request that follows the flow table
 * change.  Thus, if the controller does not receive an abbreviated (or
 * unabbreviated) notification for a flow_mod before the next
 * OFPT_BARRIER_REPLY, it will never receive one. */
struct nx_flow_update_abbrev {
    ovs_be16 length;            /* Length is 8. */
    ovs_be16 event;             /* NXFME_ABBREV. */
    ovs_be32 xid;               /* Controller-specified xid from flow_mod. */
};
OFP_ASSERT(sizeof(struct nx_flow_update_abbrev) == 8);

/* NXT_FLOW_MONITOR_CANCEL.
 *
 * Used by a controller to cancel an outstanding monitor. */
struct nx_flow_monitor_cancel {
    ovs_be32 id;                /* 'id' from nx_flow_monitor_request. */
};
OFP_ASSERT(sizeof(struct nx_flow_monitor_cancel) == 4);

#endif /* openflow/nicira-ext.h */
