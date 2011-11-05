/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks
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

#include "openflow/openflow.h"
#include "openvswitch/types.h"

/* The following vendor extensions, proposed by Nicira Networks, are not yet
 * standardized, so they are not included in openflow.h.  Some of them may be
 * suitable for standardization; others we never expect to standardize. */

#define NX_VENDOR_ID 0x00002320

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

/* Specific Nicira extension error numbers.
 *
 * These are the "code" values used in nx_vendor_error.  So far, the "type"
 * values in nx_vendor_error are the same as those in ofp_error_msg.  That is,
 * at Nicira so far we've only needed additional vendor-specific 'code' values,
 * so we're using the existing 'type' values to avoid having to invent new ones
 * that duplicate the current ones' meanings. */

/* Additional "code" values for OFPET_BAD_REQUEST. */
enum nx_bad_request_code {
/* Nicira Extended Match (NXM) errors. */

    /* Generic error code used when there is an error in an NXM sent to the
     * switch.  The switch may use one of the more specific error codes below,
     * if there is an appropriate one, to simplify debugging, but it is not
     * required to do so. */
    NXBRC_NXM_INVALID = 0x100,

    /* The nxm_type, or nxm_type taken in combination with nxm_hasmask or
     * nxm_length or both, is invalid or not implemented. */
    NXBRC_NXM_BAD_TYPE = 0x101,

    /* Invalid nxm_value. */
    NXBRC_NXM_BAD_VALUE = 0x102,

    /* Invalid nxm_mask. */
    NXBRC_NXM_BAD_MASK = 0x103,

    /* A prerequisite was not met. */
    NXBRC_NXM_BAD_PREREQ = 0x104,

    /* A given nxm_type was specified more than once. */
    NXBRC_NXM_DUP_TYPE = 0x105,

/* Other errors. */

    /* A request specified a nonexistent table ID.  (But NXFMFC_BAD_TABLE_ID is
     * used instead, when it is appropriate, because that is such a special
     * case.) */
    NXBRC_BAD_TABLE_ID = 0x200,

    /* NXT_ROLE_REQUEST specified an invalid role. */
    NXBRC_BAD_ROLE = 0x201,

    /* The in_port in an ofp_packet_out request is invalid. */
    NXBRC_BAD_IN_PORT = 0x202
};

/* Additional "code" values for OFPET_FLOW_MOD_FAILED. */
enum nx_flow_mod_failed_code {
    /* Generic hardware error. */
    NXFMFC_HARDWARE = 0x100,

    /* A nonexistent table ID was specified in the "command" field of struct
     * ofp_flow_mod, when the nxt_flow_mod_table_id extension is enabled. */
    NXFMFC_BAD_TABLE_ID = 0x101
};

/* Nicira vendor requests and replies. */

/* Header for Nicira vendor requests and replies. */
struct nicira_header {
    struct ofp_header header;
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be32 subtype;           /* One of NXT_* below. */
};
OFP_ASSERT(sizeof(struct nicira_header) == 16);

/* Values for the 'subtype' member of struct nicira_header. */
enum nicira_type {
    /* No longer used. */
    NXT_STATUS_REQUEST__OBSOLETE = 0,
    NXT_STATUS_REPLY__OBSOLETE = 1,
    NXT_ACT_SET_CONFIG__OBSOLETE = 2,
    NXT_ACT_GET_CONFIG__OBSOLETE = 3,
    NXT_COMMAND_REQUEST__OBSOLETE = 4,
    NXT_COMMAND_REPLY__OBSOLETE = 5,
    NXT_FLOW_END_CONFIG__OBSOLETE = 6,
    NXT_FLOW_END__OBSOLETE = 7,
    NXT_MGMT__OBSOLETE = 8,
    NXT_TUN_ID_FROM_COOKIE__OBSOLETE = 9,

    /* Controller role support.  The request body is struct nx_role_request.
     * The reply echos the request. */
    NXT_ROLE_REQUEST = 10,
    NXT_ROLE_REPLY = 11,

    /* Flexible flow specification (aka NXM = Nicira Extended Match). */
    NXT_SET_FLOW_FORMAT = 12,   /* Set flow format. */
    NXT_FLOW_MOD = 13,          /* Analogous to OFPT_FLOW_MOD. */
    NXT_FLOW_REMOVED = 14,      /* Analogous to OFPT_FLOW_REMOVED. */

    /* Use the upper 8 bits of the 'command' member in struct ofp_flow_mod to
     * designate the table to which a flow is to be added?  See the big comment
     * on struct nxt_flow_mod_table_id for more information. */
    NXT_FLOW_MOD_TABLE_ID = 15
};

/* Header for Nicira vendor stats request and reply messages. */
struct nicira_stats_msg {
    struct ofp_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;           /* One of NXST_* below. */
    uint8_t pad[4];             /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct nicira_stats_msg) == 24);

/* Values for the 'subtype' member of struct nicira_stats_msg. */
enum nicira_stats_type {
    /* Flexible flow specification (aka NXM = Nicira Extended Match). */
    NXST_FLOW,                  /* Analogous to OFPST_FLOW. */
    NXST_AGGREGATE              /* Analogous to OFPST_AGGREGATE. */
};

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
 * required by OpenFlow 1.0.  By default, the extension is disabled.
 *
 * When this feature is enabled, Open vSwitch treats struct ofp_flow_mod's
 * 16-bit 'command' member as two separate fields.  The upper 8 bits are used
 * as the table ID, the lower 8 bits specify the command as usual.  A table ID
 * of 0xff is treated like a wildcarded table ID.
 *
 * The specific treatment of the table ID depends on the type of flow mod:
 *
 *    - OFPFC_ADD: Given a specific table ID, the flow is always placed in that
 *      table.  If an identical flow already exists in that table only, then it
 *      is replaced.  If the flow cannot be placed in the specified table,
 *      either because the table is full or because the table cannot support
 *      flows of the given type, the switch replies with an
 *      OFPFMFC_ALL_TABLES_FULL error.  (A controller can distinguish these
 *      cases by comparing the current and maximum number of entries reported
 *      in ofp_table_stats.)
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
struct nxt_flow_mod_table_id {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* NXT_FLOW_MOD_TABLE_ID. */
    uint8_t set;                /* Nonzero to enable, zero to disable. */
    uint8_t pad[7];
};
OFP_ASSERT(sizeof(struct nxt_flow_mod_table_id) == 24);

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
    struct nicira_header nxh;
    ovs_be32 role;              /* One of NX_ROLE_*. */
};

enum nx_role {
    NX_ROLE_OTHER,              /* Default role, full access. */
    NX_ROLE_MASTER,             /* Full access, at most one. */
    NX_ROLE_SLAVE               /* Read-only access. */
};

/* Nicira vendor flow actions. */

enum nx_action_subtype {
    NXAST_SNAT__OBSOLETE,       /* No longer used. */
    NXAST_RESUBMIT,             /* struct nx_action_resubmit */
    NXAST_SET_TUNNEL,           /* struct nx_action_set_tunnel */
    NXAST_DROP_SPOOFED_ARP__OBSOLETE,
    NXAST_SET_QUEUE,            /* struct nx_action_set_queue */
    NXAST_POP_QUEUE,            /* struct nx_action_pop_queue */
    NXAST_REG_MOVE,             /* struct nx_action_reg_move */
    NXAST_REG_LOAD,             /* struct nx_action_reg_load */
    NXAST_NOTE,                 /* struct nx_action_note */
    NXAST_SET_TUNNEL64,         /* struct nx_action_set_tunnel64 */
    NXAST_MULTIPATH,            /* struct nx_action_multipath */
    NXAST_AUTOPATH,             /* struct nx_action_autopath */
    NXAST_BUNDLE,               /* struct nx_action_bundle */
    NXAST_BUNDLE_LOAD,          /* struct nx_action_bundle */
    NXAST_RESUBMIT_TABLE,       /* struct nx_action_resubmit */
    NXAST_OUTPUT_REG,           /* struct nx_action_output_reg */
    NXAST_LEARN,                /* struct nx_action_learn */
    NXAST_EXIT                  /* struct nx_action_header */
};

/* Header for Nicira-defined actions. */
struct nx_action_header {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_*. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct nx_action_header) == 16);

/* Action structures for NXAST_RESUBMIT and NXAST_RESUBMIT_TABLE.
 *
 * These actions search one of the switch's flow tables:
 *
 *    - For NXAST_RESUBMIT_TABLE only, if the 'table' member is not 255, then
 *      it specifies the table to search.
 *
 *    - Otherwise (for NXAST_RESUBMIT_TABLE with a 'table' of 255, or for
 *      NXAST_RESUBMIT regardless of 'table'), it searches the current flow
 *      table, that is, the OpenFlow flow table that contains the flow from
 *      which this action was obtained.  If this action did not come from a
 *      flow table (e.g. it came from an OFPT_PACKET_OUT message), then table 0
 *      is the current table.
 *
 * The flow table lookup uses a flow that may be slightly modified from the
 * original lookup:
 *
 *    - For NXAST_RESUBMIT, the 'in_port' member of struct nx_action_resubmit
 *      is used as the flow's in_port.
 *
 *    - For NXAST_RESUBMIT_TABLE, if the 'in_port' member is not OFPP_IN_PORT,
 *      then its value is used as the flow's in_port.  Otherwise, the original
 *      in_port is used.
 *
 *    - If actions that modify the flow (e.g. OFPAT_SET_VLAN_VID) precede the
 *      resubmit action, then the flow is updated with the new values.
 *
 * Following the lookup, the original in_port is restored.
 *
 * If the modified flow matched in the flow table, then the corresponding
 * actions are executed.  Afterward, actions following the resubmit in the
 * original set of actions, if any, are executed; any changes made to the
 * packet (e.g. changes to VLAN) by secondary actions persist when those
 * actions are executed, although the original in_port is restored.
 *
 * Resubmit actions may be used any number of times within a set of actions.
 *
 * Resubmit actions may nest to an implementation-defined depth.  Beyond this
 * implementation-defined depth, further resubmit actions are simply ignored.
 *
 * NXAST_RESUBMIT ignores 'table' and 'pad'.  NXAST_RESUBMIT_TABLE requires
 * 'pad' to be all-bits-zero.
 *
 * Open vSwitch 1.0.1 and earlier did not support recursion.  Open vSwitch
 * before 1.2.90 did not support NXAST_RESUBMIT_TABLE.
 */
struct nx_action_resubmit {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_RESUBMIT. */
    ovs_be16 in_port;               /* New in_port for checking flow table. */
    uint8_t table;                  /* NXAST_RESUBMIT_TABLE: table to use. */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct nx_action_resubmit) == 16);

/* Action structure for NXAST_SET_TUNNEL.
 *
 * Sets the encapsulating tunnel ID to a 32-bit value.  The most-significant 32
 * bits of the tunnel ID are set to 0. */
struct nx_action_set_tunnel {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_TUNNEL. */
    uint8_t pad[2];
    ovs_be32 tun_id;                /* Tunnel ID. */
};
OFP_ASSERT(sizeof(struct nx_action_set_tunnel) == 16);

/* Action structure for NXAST_SET_TUNNEL64.
 *
 * Sets the encapsulating tunnel ID to a 64-bit value. */
struct nx_action_set_tunnel64 {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_TUNNEL64. */
    uint8_t pad[6];
    ovs_be64 tun_id;                /* Tunnel ID. */
};
OFP_ASSERT(sizeof(struct nx_action_set_tunnel64) == 24);

/* Action structure for NXAST_SET_QUEUE.
 *
 * Set the queue that should be used when packets are output.  This is similar
 * to the OpenFlow OFPAT_ENQUEUE action, but does not take the output port as
 * an argument.  This allows the queue to be defined before the port is
 * known. */
struct nx_action_set_queue {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_QUEUE. */
    uint8_t pad[2];
    ovs_be32 queue_id;              /* Where to enqueue packets. */
};
OFP_ASSERT(sizeof(struct nx_action_set_queue) == 16);

/* Action structure for NXAST_POP_QUEUE.
 *
 * Restores the queue to the value it was before any NXAST_SET_QUEUE actions
 * were used.  Only the original queue can be restored this way; no stack is
 * maintained. */
struct nx_action_pop_queue {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_POP_QUEUE. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct nx_action_pop_queue) == 16);

/* Action structure for NXAST_REG_MOVE.
 *
 * Copies src[src_ofs:src_ofs+n_bits] to dst[dst_ofs:dst_ofs+n_bits], where
 * a[b:c] denotes the bits within 'a' numbered 'b' through 'c' (not including
 * bit 'c').  Bit numbering starts at 0 for the least-significant bit, 1 for
 * the next most significant bit, and so on.
 *
 * 'src' and 'dst' are nxm_header values with nxm_hasmask=0.  (It doesn't make
 * sense to use nxm_hasmask=1 because the action does not do any kind of
 * matching; it uses the actual value of a field.)
 *
 * The following nxm_header values are potentially acceptable as 'src':
 *
 *   - NXM_OF_IN_PORT
 *   - NXM_OF_ETH_DST
 *   - NXM_OF_ETH_SRC
 *   - NXM_OF_ETH_TYPE
 *   - NXM_OF_VLAN_TCI
 *   - NXM_OF_IP_TOS
 *   - NXM_OF_IP_PROTO
 *   - NXM_OF_IP_SRC
 *   - NXM_OF_IP_DST
 *   - NXM_OF_TCP_SRC
 *   - NXM_OF_TCP_DST
 *   - NXM_OF_UDP_SRC
 *   - NXM_OF_UDP_DST
 *   - NXM_OF_ICMP_TYPE
 *   - NXM_OF_ICMP_CODE
 *   - NXM_OF_ARP_OP
 *   - NXM_OF_ARP_SPA
 *   - NXM_OF_ARP_TPA
 *   - NXM_NX_TUN_ID
 *   - NXM_NX_ARP_SHA
 *   - NXM_NX_ARP_THA
 *   - NXM_NX_ICMPV6_TYPE
 *   - NXM_NX_ICMPV6_CODE
 *   - NXM_NX_ND_SLL
 *   - NXM_NX_ND_TLL
 *   - NXM_NX_REG(idx) for idx in the switch's accepted range.
 *
 * The following nxm_header values are potentially acceptable as 'dst':
 *
 *   - NXM_OF_ETH_DST
 *   - NXM_OF_ETH_SRC
 *   - NXM_OF_IP_TOS
 *   - NXM_OF_IP_SRC
 *   - NXM_OF_IP_DST
 *   - NXM_OF_TCP_SRC
 *   - NXM_OF_TCP_DST
 *   - NXM_OF_UDP_SRC
 *   - NXM_OF_UDP_DST
 *     Modifying any of the above fields changes the corresponding packet
 *     header.
 *
 *   - NXM_NX_REG(idx) for idx in the switch's accepted range.
 *
 *   - NXM_OF_VLAN_TCI.  Modifying this field's value has side effects on the
 *     packet's 802.1Q header.  Setting a value with CFI=0 removes the 802.1Q
 *     header (if any), ignoring the other bits.  Setting a value with CFI=1
 *     adds or modifies the 802.1Q header appropriately, setting the TCI field
 *     to the field's new value (with the CFI bit masked out).
 *
 *   - NXM_NX_TUN_ID.  Modifying this value modifies the tunnel ID used for the
 *     packet's next tunnel encapsulation.
 *
 * A given nxm_header value may be used as 'src' or 'dst' only on a flow whose
 * nx_match satisfies its prerequisites.  For example, NXM_OF_IP_TOS may be
 * used only if the flow's nx_match includes an nxm_entry that specifies
 * nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0, and nxm_value=0x0800.
 *
 * The switch will reject actions for which src_ofs+n_bits is greater than the
 * width of 'src' or dst_ofs+n_bits is greater than the width of 'dst' with
 * error type OFPET_BAD_ACTION, code OFPBAC_BAD_ARGUMENT.
 */
struct nx_action_reg_move {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_REG_MOVE. */
    ovs_be16 n_bits;                /* Number of bits. */
    ovs_be16 src_ofs;               /* Starting bit offset in source. */
    ovs_be16 dst_ofs;               /* Starting bit offset in destination. */
    ovs_be32 src;                   /* Source register. */
    ovs_be32 dst;                   /* Destination register. */
};
OFP_ASSERT(sizeof(struct nx_action_reg_move) == 24);

/* Action structure for NXAST_REG_LOAD.
 *
 * Copies value[0:n_bits] to dst[ofs:ofs+n_bits], where a[b:c] denotes the bits
 * within 'a' numbered 'b' through 'c' (not including bit 'c').  Bit numbering
 * starts at 0 for the least-significant bit, 1 for the next most significant
 * bit, and so on.
 *
 * 'dst' is an nxm_header with nxm_hasmask=0.  See the documentation for
 * NXAST_REG_MOVE, above, for the permitted fields and for the side effects of
 * loading them.
 *
 * The 'ofs' and 'n_bits' fields are combined into a single 'ofs_nbits' field
 * to avoid enlarging the structure by another 8 bytes.  To allow 'n_bits' to
 * take a value between 1 and 64 (inclusive) while taking up only 6 bits, it is
 * also stored as one less than its true value:
 *
 *  15                           6 5                0
 * +------------------------------+------------------+
 * |              ofs             |    n_bits - 1    |
 * +------------------------------+------------------+
 *
 * The switch will reject actions for which ofs+n_bits is greater than the
 * width of 'dst', or in which any bits in 'value' with value 2**n_bits or
 * greater are set to 1, with error type OFPET_BAD_ACTION, code
 * OFPBAC_BAD_ARGUMENT.
 */
struct nx_action_reg_load {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_REG_LOAD. */
    ovs_be16 ofs_nbits;             /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 dst;                   /* Destination register. */
    ovs_be64 value;                 /* Immediate value. */
};
OFP_ASSERT(sizeof(struct nx_action_reg_load) == 24);

/* Action structure for NXAST_NOTE.
 *
 * This action has no effect.  It is variable length.  The switch does not
 * attempt to interpret the user-defined 'note' data in any way.  A controller
 * can use this action to attach arbitrary metadata to a flow.
 *
 * This action might go away in the future.
 */
struct nx_action_note {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* A multiple of 8, but at least 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_NOTE. */
    uint8_t note[6];                /* Start of user-defined data. */
    /* Possibly followed by additional user-defined data. */
};
OFP_ASSERT(sizeof(struct nx_action_note) == 16);

/* Action structure for NXAST_MULTIPATH.
 *
 * This action performs the following steps in sequence:
 *
 *    1. Hashes the fields designated by 'fields', one of NX_HASH_FIELDS_*.
 *       Refer to the definition of "enum nx_mp_fields" for details.
 *
 *       The 'basis' value is used as a universal hash parameter, that is,
 *       different values of 'basis' yield different hash functions.  The
 *       particular universal hash function used is implementation-defined.
 *
 *       The hashed fields' values are drawn from the current state of the
 *       flow, including all modifications that have been made by actions up to
 *       this point.
 *
 *    2. Applies the multipath link choice algorithm specified by 'algorithm',
 *       one of NX_MP_ALG_*.  Refer to the definition of "enum nx_mp_algorithm"
 *       for details.
 *
 *       The output of the algorithm is 'link', an unsigned integer less than
 *       or equal to 'max_link'.
 *
 *       Some algorithms use 'arg' as an additional argument.
 *
 *    3. Stores 'link' in dst[ofs:ofs+n_bits].  The format and semantics of
 *       'dst' and 'ofs_nbits' are similar to those for the NXAST_REG_LOAD
 *       action.
 *
 * The switch will reject actions that have an unknown 'fields', or an unknown
 * 'algorithm', or in which ofs+n_bits is greater than the width of 'dst', or
 * in which 'max_link' is greater than or equal to 2**n_bits, with error type
 * OFPET_BAD_ACTION, code OFPBAC_BAD_ARGUMENT.
 */
struct nx_action_multipath {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* Length is 32. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_MULTIPATH. */

    /* What fields to hash and how. */
    ovs_be16 fields;            /* One of NX_HASH_FIELDS_*. */
    ovs_be16 basis;             /* Universal hash parameter. */
    ovs_be16 pad0;

    /* Multipath link choice algorithm to apply to hash value. */
    ovs_be16 algorithm;         /* One of NX_MP_ALG_*. */
    ovs_be16 max_link;          /* Number of output links, minus 1. */
    ovs_be32 arg;               /* Algorithm-specific argument. */
    ovs_be16 pad1;

    /* Where to store the result. */
    ovs_be16 ofs_nbits;         /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 dst;               /* Destination. */
};
OFP_ASSERT(sizeof(struct nx_action_multipath) == 32);

/* NXAST_MULTIPATH: Multipath link choice algorithm to apply.
 *
 * In the descriptions below, 'n_links' is max_link + 1. */
enum nx_mp_algorithm {
    /* link = hash(flow) % n_links.
     *
     * Redistributes all traffic when n_links changes.  O(1) performance.  See
     * RFC 2992.
     *
     * Use UINT16_MAX for max_link to get a raw hash value. */
    NX_MP_ALG_MODULO_N,

    /* link = hash(flow) / (MAX_HASH / n_links).
     *
     * Redistributes between one-quarter and one-half of traffic when n_links
     * changes.  O(1) performance.  See RFC 2992.
     */
    NX_MP_ALG_HASH_THRESHOLD,

    /* for i in [0,n_links):
     *   weights[i] = hash(flow, i)
     * link = { i such that weights[i] >= weights[j] for all j != i }
     *
     * Redistributes 1/n_links of traffic when n_links changes.  O(n_links)
     * performance.  If n_links is greater than a threshold (currently 64, but
     * subject to change), Open vSwitch will substitute another algorithm
     * automatically.  See RFC 2992. */
    NX_MP_ALG_HRW,              /* Highest Random Weight. */

    /* i = 0
     * repeat:
     *     i = i + 1
     *     link = hash(flow, i) % arg
     * while link > max_link
     *
     * Redistributes 1/n_links of traffic when n_links changes.  O(1)
     * performance when arg/max_link is bounded by a constant.
     *
     * Redistributes all traffic when arg changes.
     *
     * arg must be greater than max_link and for best performance should be no
     * more than approximately max_link * 2.  If arg is outside the acceptable
     * range, Open vSwitch will automatically substitute the least power of 2
     * greater than max_link.
     *
     * This algorithm is specific to Open vSwitch.
     */
    NX_MP_ALG_ITER_HASH         /* Iterative Hash. */
};

/* Action structure for NXAST_LEARN.
 *
 * This action adds or modifies a flow in an OpenFlow table, similar to
 * OFPT_FLOW_MOD with OFPFC_MODIFY_STRICT as 'command'.  The new flow has the
 * specified idle timeout, hard timeout, priority, cookie, and flags.  The new
 * flow's match criteria and actions are built by applying each of the series
 * of flow_mod_spec elements included as part of the action.
 *
 * A flow_mod_spec starts with a 16-bit header.  A header that is all-bits-0 is
 * a no-op used for padding the action as a whole to a multiple of 8 bytes in
 * length.  Otherwise, the flow_mod_spec can be thought of as copying 'n_bits'
 * bits from a source to a destination.  In this case, the header contains
 * multiple fields:
 *
 *  15  14  13 12  11 10                              0
 * +------+---+------+---------------------------------+
 * |   0  |src|  dst |             n_bits              |
 * +------+---+------+---------------------------------+
 *
 * The meaning and format of a flow_mod_spec depends on 'src' and 'dst'.  The
 * following table summarizes the meaning of each possible combination.
 * Details follow the table:
 *
 *   src dst  meaning
 *   --- ---  ----------------------------------------------------------
 *    0   0   Add match criteria based on value in a field.
 *    1   0   Add match criteria based on an immediate value.
 *    0   1   Add NXAST_REG_LOAD action to copy field into a different field.
 *    1   1   Add NXAST_REG_LOAD action to load immediate value into a field.
 *    0   2   Add OFPAT_OUTPUT action to output to port from specified field.
 *   All other combinations are undefined and not allowed.
 *
 * The flow_mod_spec header is followed by a source specification and a
 * destination specification.  The format and meaning of the source
 * specification depends on 'src':
 *
 *   - If 'src' is 0, the source bits are taken from a field in the flow to
 *     which this action is attached.  (This should be a wildcarded field.  If
 *     its value is fully specified then the source bits being copied have
 *     constant values.)
 *
 *     The source specification is an ovs_be32 'field' and an ovs_be16 'ofs'.
 *     'field' is an nxm_header with nxm_hasmask=0, and 'ofs' the starting bit
 *     offset within that field.  The source bits are field[ofs:ofs+n_bits-1].
 *     'field' and 'ofs' are subject to the same restrictions as the source
 *     field in NXAST_REG_MOVE.
 *
 *   - If 'src' is 1, the source bits are a constant value.  The source
 *     specification is (n_bits+15)/16*2 bytes long.  Taking those bytes as a
 *     number in network order, the source bits are the 'n_bits'
 *     least-significant bits.  The switch will report an error if other bits
 *     in the constant are nonzero.
 *
 * The flow_mod_spec destination specification, for 'dst' of 0 or 1, is an
 * ovs_be32 'field' and an ovs_be16 'ofs'.  'field' is an nxm_header with
 * nxm_hasmask=0 and 'ofs' is a starting bit offset within that field.  The
 * meaning of the flow_mod_spec depends on 'dst':
 *
 *   - If 'dst' is 0, the flow_mod_spec specifies match criteria for the new
 *     flow.  The new flow matches only if bits field[ofs:ofs+n_bits-1] in a
 *     packet equal the source bits.  'field' may be any nxm_header with
 *     nxm_hasmask=0 that is allowed in NXT_FLOW_MOD.
 *
 *     Order is significant.  Earlier flow_mod_specs must satisfy any
 *     prerequisites for matching fields specified later, by copying constant
 *     values into prerequisite fields.
 *
 *     The switch will reject flow_mod_specs that do not satisfy NXM masking
 *     restrictions.
 *
 *   - If 'dst' is 1, the flow_mod_spec specifies an NXAST_REG_LOAD action for
 *     the new flow.  The new flow copies the source bits into
 *     field[ofs:ofs+n_bits-1].  Actions are executed in the same order as the
 *     flow_mod_specs.
 *
 * The flow_mod_spec destination spec for 'dst' of 2 (when 'src' is 0) is
 * empty.  It has the following meaning:
 *
 *   - The flow_mod_spec specifies an OFPAT_OUTPUT action for the new flow.
 *     The new flow outputs to the OpenFlow port specified by the source field.
 *     Of the special output ports with value OFPP_MAX or larger, OFPP_IN_PORT,
 *     OFPP_FLOOD, OFPP_LOCAL, and OFPP_ALL are supported.  Other special ports
 *     may not be used.
 *
 * Resource Management
 * -------------------
 *
 * A switch has a finite amount of flow table space available for learning.
 * When this space is exhausted, no new learning table entries will be learned
 * until some existing flow table entries expire.  The controller should be
 * prepared to handle this by flooding (which can be implemented as a
 * low-priority flow).
 *
 * Examples
 * --------
 *
 * The following examples give a prose description of the flow_mod_specs along
 * with informal notation for how those would be represented and a hex dump of
 * the bytes that would be required.
 *
 * These examples could work with various nx_action_learn parameters.  Typical
 * values would be idle_timeout=OFP_FLOW_PERMANENT, hard_timeout=60,
 * priority=OFP_DEFAULT_PRIORITY, flags=0, table_id=10.
 *
 * 1. Learn input port based on the source MAC, with lookup into
 *    NXM_NX_REG1[16:31] by resubmit to in_port=99:
 *
 *    Match on in_port=99:
 *       ovs_be16(src=1, dst=0, n_bits=16),               20 10
 *       ovs_be16(99),                                    00 63
 *       ovs_be32(NXM_OF_IN_PORT), ovs_be16(0)            00 00 00 02 00 00
 *
 *    Match Ethernet destination on Ethernet source from packet:
 *       ovs_be16(src=0, dst=0, n_bits=48),               00 30
 *       ovs_be32(NXM_OF_ETH_SRC), ovs_be16(0)            00 00 04 06 00 00
 *       ovs_be32(NXM_OF_ETH_DST), ovs_be16(0)            00 00 02 06 00 00
 *
 *    Set NXM_NX_REG1[16:31] to the packet's input port:
 *       ovs_be16(src=0, dst=1, n_bits=16),               08 10
 *       ovs_be32(NXM_OF_IN_PORT), ovs_be16(0)            00 00 00 02 00 00
 *       ovs_be32(NXM_NX_REG1), ovs_be16(16)              00 01 02 04 00 10
 *
 *    Given a packet that arrived on port A with Ethernet source address B,
 *    this would set up the flow "in_port=99, dl_dst=B,
 *    actions=load:A->NXM_NX_REG1[16..31]".
 *
 *    In syntax accepted by ovs-ofctl, this action is: learn(in_port=99,
 *    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],
 *    load:NXM_OF_IN_PORT[]->NXM_NX_REG1[16..31])
 *
 * 2. Output to input port based on the source MAC and VLAN VID, with lookup
 *    into NXM_NX_REG1[16:31]:
 *
 *    Match on same VLAN ID as packet:
 *       ovs_be16(src=0, dst=0, n_bits=12),               00 0c
 *       ovs_be32(NXM_OF_VLAN_TCI), ovs_be16(0)           00 00 08 02 00 00
 *       ovs_be32(NXM_OF_VLAN_TCI), ovs_be16(0)           00 00 08 02 00 00
 *
 *    Match Ethernet destination on Ethernet source from packet:
 *       ovs_be16(src=0, dst=0, n_bits=48),               00 30
 *       ovs_be32(NXM_OF_ETH_SRC), ovs_be16(0)            00 00 04 06 00 00
 *       ovs_be32(NXM_OF_ETH_DST), ovs_be16(0)            00 00 02 06 00 00
 *
 *    Output to the packet's input port:
 *       ovs_be16(src=0, dst=2, n_bits=16),               10 10
 *       ovs_be32(NXM_OF_IN_PORT), ovs_be16(0)            00 00 00 02 00 00
 *
 *    Given a packet that arrived on port A with Ethernet source address B in
 *    VLAN C, this would set up the flow "dl_dst=B, vlan_vid=C,
 *    actions=output:A".
 *
 *    In syntax accepted by ovs-ofctl, this action is:
 *    learn(NXM_OF_VLAN_TCI[0..11], NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],
 *    output:NXM_OF_IN_PORT[])
 *
 * 3. Here's a recipe for a very simple-minded MAC learning switch.  It uses a
 *    10-second MAC expiration time to make it easier to see what's going on
 *
 *      ovs-vsctl del-controller br0
 *      ovs-ofctl del-flows br0
 *      ovs-ofctl add-flow br0 "table=0 actions=learn(table=1, \
          hard_timeout=10, NXM_OF_VLAN_TCI[0..11],             \
          NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],                   \
          output:NXM_OF_IN_PORT[]), resubmit(,1)"
 *      ovs-ofctl add-flow br0 "table=1 priority=0 actions=flood"
 *
 *    You can then dump the MAC learning table with:
 *
 *      ovs-ofctl dump-flows br0 table=1
 *
 * Usage Advice
 * ------------
 *
 * For best performance, segregate learned flows into a table that is not used
 * for any other flows except possibly for a lowest-priority "catch-all" flow
 * (a flow with no match criteria).  If different learning actions specify
 * different match criteria, use different tables for the learned flows.
 *
 * The meaning of 'hard_timeout' and 'idle_timeout' can be counterintuitive.
 * These timeouts apply to the flow that is added, which means that a flow with
 * an idle timeout will expire when no traffic has been sent *to* the learned
 * address.  This is not usually the intent in MAC learning; instead, we want
 * the MAC learn entry to expire when no traffic has been sent *from* the
 * learned address.  Use a hard timeout for that.
 */
struct nx_action_learn {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* At least 24. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_LEARN. */
    ovs_be16 idle_timeout;      /* Idle time before discarding (seconds). */
    ovs_be16 hard_timeout;      /* Max time before discarding (seconds). */
    ovs_be16 priority;          /* Priority level of flow entry. */
    ovs_be64 cookie;            /* Cookie for new flow. */
    ovs_be16 flags;             /* Either 0 or OFPFF_SEND_FLOW_REM. */
    uint8_t table_id;           /* Table to insert flow entry. */
    uint8_t pad[5];             /* Must be zero. */
    /* Followed by a sequence of flow_mod_spec elements, as described above,
     * until the end of the action is reached. */
};
OFP_ASSERT(sizeof(struct nx_action_learn) == 32);

#define NX_LEARN_N_BITS_MASK    0x3ff

#define NX_LEARN_SRC_FIELD     (0 << 13) /* Copy from field. */
#define NX_LEARN_SRC_IMMEDIATE (1 << 13) /* Copy from immediate value. */
#define NX_LEARN_SRC_MASK      (1 << 13)

#define NX_LEARN_DST_MATCH     (0 << 11) /* Add match criterion. */
#define NX_LEARN_DST_LOAD      (1 << 11) /* Add NXAST_REG_LOAD action. */
#define NX_LEARN_DST_OUTPUT    (2 << 11) /* Add OFPAT_OUTPUT action. */
#define NX_LEARN_DST_RESERVED  (3 << 11) /* Not yet defined. */
#define NX_LEARN_DST_MASK      (3 << 11)

/* Action structure for NXAST_AUTOPATH.
 *
 * This action performs the following steps in sequence:
 *
 *    1. Hashes the flow using an implementation-defined hash function.
 *
 *       The hashed fields' values are drawn from the current state of the
 *       flow, including all modifications that have been made by actions up to
 *       this point.
 *
 *    2. Selects an OpenFlow 'port'.
 *
 *       'port' is selected in an implementation-defined manner, taking into
 *       account 'id' and the hash value calculated in step 1.
 *
 *       Generally a switch will have been configured with a set of ports that
 *       may be chosen given 'id'.  The switch may take into account any number
 *       of factors when choosing 'port' from its configured set.  Factors may
 *       include carrier, load, and the results of configuration protocols such
 *       as LACP.
 *
 *    3. Stores 'port' in dst[ofs:ofs+n_bits].
 *
 *       The format and semantics of 'dst' and 'ofs_nbits' are similar to those
 *       for the NXAST_REG_LOAD action.
 *
 * The switch will reject actions in which ofs+n_bits is greater than the width
 * of 'dst', with error type OFPET_BAD_ACTION, code OFPBAC_BAD_ARGUMENT.
 */
struct nx_action_autopath {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* Length is 20. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_AUTOPATH. */

    /* Where to store the result. */
    ovs_be16 ofs_nbits;         /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 dst;               /* Destination. */

    ovs_be32 id;                /* Autopath ID. */
    ovs_be32 pad;
};
OFP_ASSERT(sizeof(struct nx_action_autopath) == 24);

/* Action structure for NXAST_BUNDLE and NXAST_BUNDLE_LOAD.
 *
 * The bundle actions choose a slave from a supplied list of options.
 * NXAST_BUNDLE outputs to its selection.  NXAST_BUNDLE_LOAD writes its
 * selection to a register.
 *
 * The list of possible slaves follows the nx_action_bundle structure. The size
 * of each slave is governed by its type as indicated by the 'slave_type'
 * parameter. The list of slaves should be padded at its end with zeros to make
 * the total length of the action a multiple of 8.
 *
 * Switches infer from the 'slave_type' parameter the size of each slave.  All
 * implementations must support the NXM_OF_IN_PORT 'slave_type' which indicates
 * that the slaves are OpenFlow port numbers with NXM_LENGTH(NXM_OF_IN_PORT) ==
 * 2 byte width.  Switches should reject actions which indicate unknown or
 * unsupported slave types.
 *
 * Switches use a strategy dictated by the 'algorithm' parameter to choose a
 * slave.  If the switch does not support the specified 'algorithm' parameter,
 * it should reject the action.
 *
 * Several algorithms take into account liveness when selecting slaves.  The
 * liveness of a slave is implementation defined (with one exception), but will
 * generally take into account things like its carrier status and the results
 * of any link monitoring protocols which happen to be running on it.  In order
 * to give controllers a place-holder value, the OFPP_NONE port is always
 * considered live.
 *
 * Some slave selection strategies require the use of a hash function, in which
 * case the 'fields' and 'basis' parameters should be populated.  The 'fields'
 * parameter (one of NX_HASH_FIELDS_*) designates which parts of the flow to
 * hash.  Refer to the definition of "enum nx_hash_fields" for details.  The
 * 'basis' parameter is used as a universal hash parameter.  Different values
 * of 'basis' yield different hash results.
 *
 * The 'zero' parameter at the end of the action structure is reserved for
 * future use.  Switches are required to reject actions which have nonzero
 * bytes in the 'zero' field.
 *
 * NXAST_BUNDLE actions should have 'ofs_nbits' and 'dst' zeroed.  Switches
 * should reject actions which have nonzero bytes in either of these fields.
 *
 * NXAST_BUNDLE_LOAD stores the OpenFlow port number of the selected slave in
 * dst[ofs:ofs+n_bits].  The format and semantics of 'dst' and 'ofs_nbits' are
 * similar to those for the NXAST_REG_LOAD action. */
struct nx_action_bundle {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* Length including slaves. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_BUNDLE. */

    /* Slave choice algorithm to apply to hash value. */
    ovs_be16 algorithm;         /* One of NX_BD_ALG_*. */

    /* What fields to hash and how. */
    ovs_be16 fields;            /* One of NX_HASH_FIELDS_*. */
    ovs_be16 basis;             /* Universal hash parameter. */

    ovs_be32 slave_type;        /* NXM_OF_IN_PORT. */
    ovs_be16 n_slaves;          /* Number of slaves. */

    ovs_be16 ofs_nbits;         /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 dst;               /* Destination. */

    uint8_t zero[4];            /* Reserved. Must be zero. */
};
OFP_ASSERT(sizeof(struct nx_action_bundle) == 32);

/* NXAST_BUNDLE: Bundle slave choice algorithm to apply.
 *
 * In the descriptions below, 'slaves' is the list of possible slaves in the
 * order they appear in the OpenFlow action. */
enum nx_bd_algorithm {
    /* Chooses the first live slave listed in the bundle.
     *
     * O(n_slaves) performance. */
    NX_BD_ALG_ACTIVE_BACKUP,

    /* for i in [0,n_slaves):
     *   weights[i] = hash(flow, i)
     * slave = { slaves[i] such that weights[i] >= weights[j] for all j != i }
     *
     * Redistributes 1/n_slaves of traffic when a slave's liveness changes.
     * O(n_slaves) performance.
     *
     * Uses the 'fields' and 'basis' parameters. */
    NX_BD_ALG_HRW /* Highest Random Weight. */
};

/* Action structure for NXAST_OUTPUT_REG.
 *
 * Outputs to the OpenFlow port number written to src[ofs:ofs+nbits].
 *
 * The format and semantics of 'src' and 'ofs_nbits' are similar to those for
 * the NXAST_REG_LOAD action.
 *
 * The acceptable nxm_header values for 'src' are the same as the acceptable
 * nxm_header values for the 'src' field of NXAST_REG_MOVE.
 *
 * The 'max_len' field indicates the number of bytes to send when the chosen
 * port is OFPP_CONTROLLER.  Its semantics are equivalent to the 'max_len'
 * field of OFPAT_OUTPUT.
 *
 * The 'zero' field is required to be zeroed for forward compatibility. */
struct nx_action_output_reg {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* 24. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_OUTPUT_REG. */

    ovs_be16 ofs_nbits;         /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 src;               /* Source. */

    ovs_be16 max_len;           /* Max length to send to controller. */

    uint8_t zero[6];            /* Reserved, must be zero. */
};
OFP_ASSERT(sizeof(struct nx_action_output_reg) == 24);

/* NXAST_EXIT
 *
 * Discontinues action processing.
 *
 * The NXAST_EXIT action causes the switch to immediately halt processing
 * actions for the flow.  Any actions which have already been processed are
 * executed by the switch.  However, any further actions, including those which
 * may be in different tables, or different levels of the NXAST_RESUBMIT
 * hierarchy, will be ignored.
 *
 * Uses the nx_action_header structure. */

/* Flexible flow specifications (aka NXM = Nicira Extended Match).
 *
 * OpenFlow 1.0 has "struct ofp_match" for specifying flow matches.  This
 * structure is fixed-length and hence difficult to extend.  This section
 * describes a more flexible, variable-length flow match, called "nx_match" for
 * short, that is also supported by Open vSwitch.  This section also defines a
 * replacement for each OpenFlow message that includes struct ofp_match.
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
 * Bits 16...31 are "nxm_vendor", one of the NXM_VENDOR_* values below.  Bits
 * 9...15 are "nxm_field", which is a vendor-specific value.  nxm_type normally
 * designates a protocol header, such as the Ethernet type, but it can also
 * refer to packet metadata, such as the switch port on which a packet arrived.
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
 *     corresponding bits in nxm_value and the field's value to be ignored.
 *     (The sense of the nxm_mask bits is the opposite of that used by the
 *     "wildcards" member of struct ofp_match.)
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

#define NXM_HEADER__(VENDOR, FIELD, HASMASK, LENGTH) \
    (((VENDOR) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
#define NXM_HEADER(VENDOR, FIELD, LENGTH) \
    NXM_HEADER__(VENDOR, FIELD, 0, LENGTH)
#define NXM_HEADER_W(VENDOR, FIELD, LENGTH) \
    NXM_HEADER__(VENDOR, FIELD, 1, (LENGTH) * 2)
#define NXM_VENDOR(HEADER) ((HEADER) >> 16)
#define NXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define NXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define NXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define NXM_LENGTH(HEADER) ((HEADER) & 0xff)

#define NXM_MAKE_WILD_HEADER(HEADER) \
        NXM_HEADER_W(NXM_VENDOR(HEADER), NXM_FIELD(HEADER), NXM_LENGTH(HEADER))

/* ## ------------------------------- ## */
/* ## OpenFlow 1.0-compatible fields. ## */
/* ## ------------------------------- ## */

/* Physical or virtual port on which the packet was received.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_IN_PORT    NXM_HEADER  (0x0000,  0, 2)

/* Source or destination address in Ethernet header.
 *
 * Prereqs: None.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: The nxm_mask patterns 01:00:00:00:00:00 and FE:FF:FF:FF:FF:FF must
 *   be supported for NXM_OF_ETH_DST_W (as well as the trivial patterns that
 *   are all-0-bits or all-1-bits).  Support for other patterns and for masking
 *   of NXM_OF_ETH_SRC is optional. */
#define NXM_OF_ETH_DST    NXM_HEADER  (0x0000,  1, 6)
#define NXM_OF_ETH_DST_W  NXM_HEADER_W(0x0000,  1, 6)
#define NXM_OF_ETH_SRC    NXM_HEADER  (0x0000,  2, 6)

/* Packet's Ethernet type.
 *
 * For an Ethernet II packet this is taken from the Ethernet header.  For an
 * 802.2 LLC+SNAP header with OUI 00-00-00 this is taken from the SNAP header.
 * A packet that has neither format has value 0x05ff
 * (OFP_DL_TYPE_NOT_ETH_TYPE).
 *
 * For a packet with an 802.1Q header, this is the type of the encapsulated
 * frame.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_ETH_TYPE   NXM_HEADER  (0x0000,  3, 2)

/* 802.1Q TCI.
 *
 * For a packet with an 802.1Q header, this is the Tag Control Information
 * (TCI) field, with the CFI bit forced to 1.  For a packet with no 802.1Q
 * header, this has value 0.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Arbitrary masks.
 *
 * This field can be used in various ways:
 *
 *   - If it is not constrained at all, the nx_match matches packets without
 *     an 802.1Q header or with an 802.1Q header that has any TCI value.
 *
 *   - Testing for an exact match with 0 matches only packets without an
 *     802.1Q header.
 *
 *   - Testing for an exact match with a TCI value with CFI=1 matches packets
 *     that have an 802.1Q header with a specified VID and PCP.
 *
 *   - Testing for an exact match with a nonzero TCI value with CFI=0 does
 *     not make sense.  The switch may reject this combination.
 *
 *   - Testing with a specific VID and CFI=1, with nxm_mask=0x1fff, matches
 *     packets that have an 802.1Q header with that VID (and any PCP).
 *
 *   - Testing with a specific PCP and CFI=1, with nxm_mask=0xf000, matches
 *     packets that have an 802.1Q header with that PCP (and any VID).
 *
 *   - Testing with nxm_value=0, nxm_mask=0x0fff matches packets with no 802.1Q
 *     header or with an 802.1Q header with a VID of 0.
 *
 *   - Testing with nxm_value=0, nxm_mask=0xe000 matches packets with no 802.1Q
 *     header or with an 802.1Q header with a PCP of 0.
 *
 *   - Testing with nxm_value=0, nxm_mask=0xefff matches packets with no 802.1Q
 *     header or with an 802.1Q header with both VID and PCP of 0.
 */
#define NXM_OF_VLAN_TCI   NXM_HEADER  (0x0000,  4, 2)
#define NXM_OF_VLAN_TCI_W NXM_HEADER_W(0x0000,  4, 2)

/* The "type of service" byte of the IP header, with the ECN bits forced to 0.
 *
 * Prereqs: NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer with 2 least-significant bits forced to 0.
 *
 * Masking: Not maskable. */
#define NXM_OF_IP_TOS     NXM_HEADER  (0x0000,  5, 1)

/* The "protocol" byte in the IP header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define NXM_OF_IP_PROTO   NXM_HEADER  (0x0000,  6, 1)

/* The source or destination address in the IP header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x0800 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Only CIDR masks are allowed, that is, masks that consist of N
 *   high-order bits set to 1 and the other 32-N bits set to 0. */
#define NXM_OF_IP_SRC     NXM_HEADER  (0x0000,  7, 4)
#define NXM_OF_IP_SRC_W   NXM_HEADER_W(0x0000,  7, 4)
#define NXM_OF_IP_DST     NXM_HEADER  (0x0000,  8, 4)
#define NXM_OF_IP_DST_W   NXM_HEADER_W(0x0000,  8, 4)

/* The source or destination port in the TCP header.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *   NXM_OF_IP_PROTO must match 6 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_TCP_SRC    NXM_HEADER  (0x0000,  9, 2)
#define NXM_OF_TCP_DST    NXM_HEADER  (0x0000, 10, 2)

/* The source or destination port in the UDP header.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 *   NXM_OF_IP_PROTO must match 17 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_UDP_SRC    NXM_HEADER  (0x0000, 11, 2)
#define NXM_OF_UDP_DST    NXM_HEADER  (0x0000, 12, 2)

/* The type or code in the ICMP header.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match 0x0800 exactly.
 *   NXM_OF_IP_PROTO must match 1 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define NXM_OF_ICMP_TYPE  NXM_HEADER  (0x0000, 13, 1)
#define NXM_OF_ICMP_CODE  NXM_HEADER  (0x0000, 14, 1)

/* ARP opcode.
 *
 * For an Ethernet+IP ARP packet, the opcode in the ARP header.  Always 0
 * otherwise.  Only ARP opcodes between 1 and 255 should be specified for
 * matching.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_ARP_OP     NXM_HEADER  (0x0000, 15, 2)

/* For an Ethernet+IP ARP packet, the source or target protocol address
 * in the ARP header.  Always 0 otherwise.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Only CIDR masks are allowed, that is, masks that consist of N
 *   high-order bits set to 1 and the other 32-N bits set to 0. */
#define NXM_OF_ARP_SPA    NXM_HEADER  (0x0000, 16, 4)
#define NXM_OF_ARP_SPA_W  NXM_HEADER_W(0x0000, 16, 4)
#define NXM_OF_ARP_TPA    NXM_HEADER  (0x0000, 17, 4)
#define NXM_OF_ARP_TPA_W  NXM_HEADER_W(0x0000, 17, 4)

/* ## ------------------------ ## */
/* ## Nicira match extensions. ## */
/* ## ------------------------ ## */

/* Metadata registers.
 *
 * Registers initially have value 0.  Actions allow register values to be
 * manipulated.
 *
 * Prereqs: None.
 *
 * Format: Array of 32-bit integer registers.  Space is reserved for up to
 *   NXM_NX_MAX_REGS registers, but switches may implement fewer.
 *
 * Masking: Arbitrary masks. */
#define NXM_NX_MAX_REGS 16
#define NXM_NX_REG(IDX)   NXM_HEADER  (0x0001, IDX, 4)
#define NXM_NX_REG_W(IDX) NXM_HEADER_W(0x0001, IDX, 4)
#define NXM_NX_REG_IDX(HEADER) NXM_FIELD(HEADER)
#define NXM_IS_NX_REG(HEADER) (!((((HEADER) ^ NXM_NX_REG0)) & 0xffffe1ff))
#define NXM_IS_NX_REG_W(HEADER) (!((((HEADER) ^ NXM_NX_REG0_W)) & 0xffffe1ff))
#define NXM_NX_REG0       NXM_HEADER  (0x0001, 0, 4)
#define NXM_NX_REG0_W     NXM_HEADER_W(0x0001, 0, 4)
#define NXM_NX_REG1       NXM_HEADER  (0x0001, 1, 4)
#define NXM_NX_REG1_W     NXM_HEADER_W(0x0001, 1, 4)
#define NXM_NX_REG2       NXM_HEADER  (0x0001, 2, 4)
#define NXM_NX_REG2_W     NXM_HEADER_W(0x0001, 2, 4)
#define NXM_NX_REG3       NXM_HEADER  (0x0001, 3, 4)
#define NXM_NX_REG3_W     NXM_HEADER_W(0x0001, 3, 4)
#define NXM_NX_REG4       NXM_HEADER  (0x0001, 4, 4)
#define NXM_NX_REG4_W     NXM_HEADER_W(0x0001, 4, 4)

/* Tunnel ID.
 *
 * For a packet received via GRE tunnel including a (32-bit) key, the key is
 * stored in the low 32-bits and the high bits are zeroed.  For other packets,
 * the value is 0.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define NXM_NX_TUN_ID     NXM_HEADER  (0x0001, 16, 8)
#define NXM_NX_TUN_ID_W   NXM_HEADER_W(0x0001, 16, 8)

/* For an Ethernet+IP ARP packet, the source or target hardware address
 * in the ARP header.  Always 0 otherwise.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define NXM_NX_ARP_SHA    NXM_HEADER  (0x0001, 17, 6)
#define NXM_NX_ARP_THA    NXM_HEADER  (0x0001, 18, 6)

/* The source or destination address in the IPv6 header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Only CIDR masks are allowed, that is, masks that consist of N
 *   high-order bits set to 1 and the other 128-N bits set to 0. */
#define NXM_NX_IPV6_SRC    NXM_HEADER  (0x0001, 19, 16)
#define NXM_NX_IPV6_SRC_W  NXM_HEADER_W(0x0001, 19, 16)
#define NXM_NX_IPV6_DST    NXM_HEADER  (0x0001, 20, 16)
#define NXM_NX_IPV6_DST_W  NXM_HEADER_W(0x0001, 20, 16)

/* The type or code in the ICMPv6 header.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   NXM_OF_IP_PROTO must match 58 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define NXM_NX_ICMPV6_TYPE NXM_HEADER  (0x0001, 21, 1)
#define NXM_NX_ICMPV6_CODE NXM_HEADER  (0x0001, 22, 1)

/* The target address in an IPv6 Neighbor Discovery message.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   NXM_OF_IP_PROTO must match 58 exactly.
 *   NXM_OF_ICMPV6_TYPE must be either 135 or 136.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Not maskable. */
#define NXM_NX_ND_TARGET   NXM_HEADER  (0x0001, 23, 16)

/* The source link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   NXM_OF_IP_PROTO must match 58 exactly.
 *   NXM_OF_ICMPV6_TYPE must be exactly 135.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define NXM_NX_ND_SLL      NXM_HEADER  (0x0001, 24, 6)

/* The target link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   NXM_OF_IP_PROTO must match 58 exactly.
 *   NXM_OF_ICMPV6_TYPE must be exactly 136.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define NXM_NX_ND_TLL      NXM_HEADER  (0x0001, 25, 6)

/* IP fragment information.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit value with one of the values 0, 1, or 3, as described below.
 *
 * Masking: Fully maskable.
 *
 * This field has three possible values:
 *
 *   - A packet that is not an IP fragment has value 0.
 *
 *   - A packet that is an IP fragment with offset 0 (the first fragment) has
 *     bit 0 set and thus value 1.
 *
 *   - A packet that is an IP fragment with nonzero offset has bits 0 and 1 set
 *     and thus value 3.
 *
 * NX_IP_FRAG_ANY and NX_IP_FRAG_LATER are declared to symbolically represent
 * the meanings of bits 0 and 1.
 *
 * The switch may reject matches against values that can never appear.
 *
 * It is important to understand how this field interacts with the OpenFlow IP
 * fragment handling mode:
 *
 *   - In OFPC_FRAG_DROP mode, the OpenFlow switch drops all IP fragments
 *     before they reach the flow table, so every packet that is available for
 *     matching will have value 0 in this field.
 *
 *   - Open vSwitch does not implement OFPC_FRAG_REASM mode, but if it did then
 *     IP fragments would be reassembled before they reached the flow table and
 *     again every packet available for matching would always have value 0.
 *
 *   - In OFPC_FRAG_NORMAL mode, all three values are possible, but OpenFlow
 *     1.0 says that fragments' transport ports are always 0, even for the
 *     first fragment, so this does not provide much extra information.
 *
 *   - In OFPC_FRAG_NX_MATCH mode, all three values are possible.  For
 *     fragments with offset 0, Open vSwitch makes L4 header information
 *     available.
 */
#define NXM_NX_IP_FRAG     NXM_HEADER  (0x0001, 26, 1)
#define NXM_NX_IP_FRAG_W   NXM_HEADER_W(0x0001, 26, 1)

/* Bits in the value of NXM_NX_IP_FRAG. */
#define NX_IP_FRAG_ANY   (1 << 0) /* Is this a fragment? */
#define NX_IP_FRAG_LATER (1 << 1) /* Is this a fragment with nonzero offset? */

/* The flow label in the IPv6 header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match 0x86dd exactly.
 *
 * Format: 20-bit IPv6 flow label in least-significant bits.
 *
 * Masking: Not maskable. */
#define NXM_NX_IPV6_LABEL  NXM_HEADER  (0x0001, 27, 4)

/* The ECN of the IP header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: ECN in the low-order 2 bits.
 *
 * Masking: Not maskable. */
#define NXM_NX_IP_ECN      NXM_HEADER  (0x0001, 28, 1)

/* The time-to-live/hop limit of the IP header.
 *
 * Prereqs: NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define NXM_NX_IP_TTL      NXM_HEADER  (0x0001, 29, 1)

/* ## --------------------- ## */
/* ## Requests and replies. ## */
/* ## --------------------- ## */

enum nx_flow_format {
    NXFF_OPENFLOW10 = 0,         /* Standard OpenFlow 1.0 compatible. */
    NXFF_NXM = 2                 /* Nicira extended match. */
};

/* NXT_SET_FLOW_FORMAT request. */
struct nxt_set_flow_format {
    struct ofp_header header;
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be32 subtype;           /* NXT_SET_FLOW_FORMAT. */
    ovs_be32 format;            /* One of NXFF_*. */
};
OFP_ASSERT(sizeof(struct nxt_set_flow_format) == 20);

/* NXT_FLOW_MOD (analogous to OFPT_FLOW_MOD). */
struct nx_flow_mod {
    struct nicira_header nxh;
    ovs_be64 cookie;              /* Opaque controller-issued identifier. */
    ovs_be16 command;             /* One of OFPFC_*. */
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
OFP_ASSERT(sizeof(struct nx_flow_mod) == 48);

/* NXT_FLOW_REMOVED (analogous to OFPT_FLOW_REMOVED). */
struct nx_flow_removed {
    struct nicira_header nxh;
    ovs_be64 cookie;          /* Opaque controller-issued identifier. */
    ovs_be16 priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t pad[1];           /* Align to 32-bits. */
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
OFP_ASSERT(sizeof(struct nx_flow_removed) == 56);

/* Nicira vendor stats request of type NXST_FLOW (analogous to OFPST_FLOW
 * request). */
struct nx_flow_stats_request {
    struct nicira_stats_msg nsm;
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
OFP_ASSERT(sizeof(struct nx_flow_stats_request) == 32);

/* Body for Nicira vendor stats reply of type NXST_FLOW (analogous to
 * OFPST_FLOW reply). */
struct nx_flow_stats {
    ovs_be16 length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    ovs_be32 duration_sec;    /* Time flow has been alive in seconds. */
    ovs_be32 duration_nsec;   /* Time flow has been alive in nanoseconds
                                 beyond duration_sec. */
    ovs_be16 priority;        /* Priority of the entry. Only meaningful
                                 when this is not an exact-match entry. */
    ovs_be16 idle_timeout;    /* Number of seconds idle before expiration. */
    ovs_be16 hard_timeout;    /* Number of seconds before expiration. */
    ovs_be16 match_len;       /* Length of nx_match. */
    uint8_t pad2[4];          /* Align to 64 bits. */
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
 * OFPST_AGGREGATE request). */
struct nx_aggregate_stats_request {
    struct nicira_stats_msg nsm;
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
OFP_ASSERT(sizeof(struct nx_aggregate_stats_request) == 32);

/* Body for nicira_stats_msg reply of type NXST_AGGREGATE (analogous to
 * OFPST_AGGREGATE reply). */
struct nx_aggregate_stats_reply {
    struct nicira_stats_msg nsm;
    ovs_be64 packet_count;     /* Number of packets, UINT64_MAX if unknown. */
    ovs_be64 byte_count;       /* Number of bytes, UINT64_MAX if unknown. */
    ovs_be32 flow_count;       /* Number of flows. */
    uint8_t pad[4];            /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct nx_aggregate_stats_reply) == 48);

#endif /* openflow/nicira-ext.h */
