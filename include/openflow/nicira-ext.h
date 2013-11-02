/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
    NXAST_AUTOPATH__OBSOLETE,   /* No longer used. */
    NXAST_BUNDLE,               /* struct nx_action_bundle */
    NXAST_BUNDLE_LOAD,          /* struct nx_action_bundle */
    NXAST_RESUBMIT_TABLE,       /* struct nx_action_resubmit */
    NXAST_OUTPUT_REG,           /* struct nx_action_output_reg */
    NXAST_LEARN,                /* struct nx_action_learn */
    NXAST_EXIT,                 /* struct nx_action_header */
    NXAST_DEC_TTL,              /* struct nx_action_header */
    NXAST_FIN_TIMEOUT,          /* struct nx_action_fin_timeout */
    NXAST_CONTROLLER,           /* struct nx_action_controller */
    NXAST_DEC_TTL_CNT_IDS,      /* struct nx_action_cnt_ids */
    NXAST_WRITE_METADATA,       /* struct nx_action_write_metadata */
    NXAST_PUSH_MPLS,            /* struct nx_action_push_mpls */
    NXAST_POP_MPLS,             /* struct nx_action_pop_mpls */
    NXAST_SET_MPLS_TTL,         /* struct nx_action_ttl */
    NXAST_DEC_MPLS_TTL,         /* struct nx_action_header */
    NXAST_STACK_PUSH,           /* struct nx_action_stack */
    NXAST_STACK_POP,            /* struct nx_action_stack */
    NXAST_SAMPLE,               /* struct nx_action_sample */
    NXAST_SET_MPLS_LABEL,       /* struct nx_action_ttl */
    NXAST_SET_MPLS_TC,          /* struct nx_action_ttl */
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
    ovs_be16 len;                   /* Length is 24. */
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
 *   - NXM_NX_PKT_MARK
 *   - NXM_NX_TUN_IPV4_SRC
 *   - NXM_NX_TUN_IPV4_DST
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
 *   - NXM_NX_ARP_SHA
 *   - NXM_NX_ARP_THA
 *   - NXM_OF_ARP_OP
 *   - NXM_OF_ARP_SPA
 *   - NXM_OF_ARP_TPA
 *     Modifying any of the above fields changes the corresponding packet
 *     header.
 *
 *   - NXM_OF_IN_PORT
 *
 *   - NXM_NX_REG(idx) for idx in the switch's accepted range.
 *
 *   - NXM_NX_PKT_MARK
 *
 *   - NXM_OF_VLAN_TCI.  Modifying this field's value has side effects on the
 *     packet's 802.1Q header.  Setting a value with CFI=0 removes the 802.1Q
 *     header (if any), ignoring the other bits.  Setting a value with CFI=1
 *     adds or modifies the 802.1Q header appropriately, setting the TCI field
 *     to the field's new value (with the CFI bit masked out).
 *
 *   - NXM_NX_TUN_ID, NXM_NX_TUN_IPV4_SRC, NXM_NX_TUN_IPV4_DST.  Modifying
 *     any of these values modifies the corresponding tunnel header field used
 *     for the packet's next tunnel encapsulation, if allowed by the
 *     configuration of the output tunnel port.
 *
 * A given nxm_header value may be used as 'src' or 'dst' only on a flow whose
 * nx_match satisfies its prerequisites.  For example, NXM_OF_IP_TOS may be
 * used only if the flow's nx_match includes an nxm_entry that specifies
 * nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0, and nxm_value=0x0800.
 *
 * The switch will reject actions for which src_ofs+n_bits is greater than the
 * width of 'src' or dst_ofs+n_bits is greater than the width of 'dst' with
 * error type OFPET_BAD_ACTION, code OFPBAC_BAD_ARGUMENT.
 *
 * This action behaves properly when 'src' overlaps with 'dst', that is, it
 * behaves as if 'src' were copied out to a temporary buffer, then the
 * temporary buffer copied to 'dst'.
 */
struct nx_action_reg_move {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 24. */
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
    ovs_be16 len;                   /* Length is 24. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_REG_LOAD. */
    ovs_be16 ofs_nbits;             /* (ofs << 6) | (n_bits - 1). */
    ovs_be32 dst;                   /* Destination register. */
    ovs_be64 value;                 /* Immediate value. */
};
OFP_ASSERT(sizeof(struct nx_action_reg_load) == 24);

/* Action structure for NXAST_STACK_PUSH and NXAST_STACK_POP.
 *
 * Pushes (or pops) field[offset: offset + n_bits] to (or from)
 * top of the stack.
 */
struct nx_action_stack {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_STACK_PUSH or NXAST_STACK_POP. */
    ovs_be16 offset;                /* Bit offset into the field. */
    ovs_be32 field;                 /* The field used for push or pop. */
    ovs_be16 n_bits;                /* (n_bits + 1) bits of the field. */
    uint8_t zero[6];                /* Reserved, must be zero. */
};
OFP_ASSERT(sizeof(struct nx_action_stack) == 24);

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
 *     A single NXAST_REG_LOAD action writes no more than 64 bits, so n_bits
 *     greater than 64 yields multiple NXAST_REG_LOAD actions.
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
 * If a learned flow matches a single TCP stream with a relatively long
 * timeout, one may make the best of resource constraints by setting
 * 'fin_idle_timeout' or 'fin_hard_timeout' (both measured in seconds), or
 * both, to shorter timeouts.  When either of these is specified as a nonzero
 * value, OVS adds a NXAST_FIN_TIMEOUT action, with the specified timeouts, to
 * the learned flow.
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
    uint8_t pad;                /* Must be zero. */
    ovs_be16 fin_idle_timeout;  /* Idle timeout after FIN, if nonzero. */
    ovs_be16 fin_hard_timeout;  /* Hard timeout after FIN, if nonzero. */
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

/* Action structure for NXAST_FIN_TIMEOUT.
 *
 * This action changes the idle timeout or hard timeout, or both, of this
 * OpenFlow rule when the rule matches a TCP packet with the FIN or RST flag.
 * When such a packet is observed, the action reduces the rule's idle timeout
 * to 'fin_idle_timeout' and its hard timeout to 'fin_hard_timeout'.  This
 * action has no effect on an existing timeout that is already shorter than the
 * one that the action specifies.  A 'fin_idle_timeout' or 'fin_hard_timeout'
 * of zero has no effect on the respective timeout.
 *
 * 'fin_idle_timeout' and 'fin_hard_timeout' are measured in seconds.
 * 'fin_hard_timeout' specifies time since the flow's creation, not since the
 * receipt of the FIN or RST.
 *
 * This is useful for quickly discarding learned TCP flows that otherwise will
 * take a long time to expire.
 *
 * This action is intended for use with an OpenFlow rule that matches only a
 * single TCP flow.  If the rule matches multiple TCP flows (e.g. it wildcards
 * all TCP traffic, or all TCP traffic to a particular port), then any FIN or
 * RST in any of those flows will cause the entire OpenFlow rule to expire
 * early, which is not normally desirable.
 */
struct nx_action_fin_timeout {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* 16. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_FIN_TIMEOUT. */
    ovs_be16 fin_idle_timeout;  /* New idle timeout, if nonzero. */
    ovs_be16 fin_hard_timeout;  /* New hard timeout, if nonzero. */
    ovs_be16 pad;               /* Must be zero. */
};
OFP_ASSERT(sizeof(struct nx_action_fin_timeout) == 16);

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
    ovs_be16 subtype;           /* NXAST_BUNDLE or NXAST_BUNDLE_LOAD. */

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


/* Action structure for NXAST_DEC_TTL_CNT_IDS.
 *
 * If the packet is not IPv4 or IPv6, does nothing.  For IPv4 or IPv6, if the
 * TTL or hop limit is at least 2, decrements it by 1.  Otherwise, if TTL or
 * hop limit is 0 or 1, sends a packet-in to the controllers with each of the
 * 'n_controllers' controller IDs specified in 'cnt_ids'.
 *
 * (This differs from NXAST_DEC_TTL in that for NXAST_DEC_TTL the packet-in is
 * sent only to controllers with id 0.)
 */
struct nx_action_cnt_ids {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* Length including slaves. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_DEC_TTL_CNT_IDS. */

    ovs_be16 n_controllers;     /* Number of controllers. */
    uint8_t zeros[4];           /* Must be zero. */

    /* Followed by 1 or more controller ids.
     *
     * uint16_t cnt_ids[];        // Controller ids.
     * uint8_t pad[];           // Must be 0 to 8-byte align cnt_ids[].
     */
};
OFP_ASSERT(sizeof(struct nx_action_cnt_ids) == 16);


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
 * OpenFlow 1.0 has "struct ofp10_match" for specifying flow matches.  This
 * structure is fixed-length and hence difficult to extend.  This section
 * describes a more flexible, variable-length flow match, called "nx_match" for
 * short, that is also supported by Open vSwitch.  This section also defines a
 * replacement for each OpenFlow message that includes struct ofp10_match.
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
 * Masking: Fully maskable, in versions 1.8 and later. Earlier versions only
 *   supported the following masks for NXM_OF_ETH_DST_W: 00:00:00:00:00:00,
 *   fe:ff:ff:ff:ff:ff, 01:00:00:00:00:00, ff:ff:ff:ff:ff:ff. */
#define NXM_OF_ETH_DST    NXM_HEADER  (0x0000,  1, 6)
#define NXM_OF_ETH_DST_W  NXM_HEADER_W(0x0000,  1, 6)
#define NXM_OF_ETH_SRC    NXM_HEADER  (0x0000,  2, 6)
#define NXM_OF_ETH_SRC_W  NXM_HEADER_W(0x0000,  2, 6)

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
 * Masking: Fully maskable, in Open vSwitch 1.8 and later.  In earlier
 *   versions, only CIDR masks are allowed, that is, masks that consist of N
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
 * Masking: Fully maskable, in Open vSwitch 1.6 and later.  Not maskable, in
 *   earlier versions. */
#define NXM_OF_TCP_SRC    NXM_HEADER  (0x0000,  9, 2)
#define NXM_OF_TCP_SRC_W  NXM_HEADER_W(0x0000,  9, 2)
#define NXM_OF_TCP_DST    NXM_HEADER  (0x0000, 10, 2)
#define NXM_OF_TCP_DST_W  NXM_HEADER_W(0x0000, 10, 2)

/* The source or destination port in the UDP header.
 *
 * Prereqs:
 *   NXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 *   NXM_OF_IP_PROTO must match 17 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Fully maskable, in Open vSwitch 1.6 and later.  Not maskable, in
 *   earlier versions. */
#define NXM_OF_UDP_SRC    NXM_HEADER  (0x0000, 11, 2)
#define NXM_OF_UDP_SRC_W  NXM_HEADER_W(0x0000, 11, 2)
#define NXM_OF_UDP_DST    NXM_HEADER  (0x0000, 12, 2)
#define NXM_OF_UDP_DST_W  NXM_HEADER_W(0x0000, 12, 2)

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
 * Prereqs: NXM_OF_ETH_TYPE must match either 0x0806 or 0x8035.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define NXM_OF_ARP_OP     NXM_HEADER  (0x0000, 15, 2)

/* For an Ethernet+IP ARP packet, the source or target protocol address
 * in the ARP header.  Always 0 otherwise.
 *
 * Prereqs: NXM_OF_ETH_TYPE must match either 0x0806 or 0x8035.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Fully maskable, in Open vSwitch 1.8 and later.  In earlier
 *   versions, only CIDR masks are allowed, that is, masks that consist of N
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
#define NXM_NX_REG5       NXM_HEADER  (0x0001, 5, 4)
#define NXM_NX_REG5_W     NXM_HEADER_W(0x0001, 5, 4)
#define NXM_NX_REG6       NXM_HEADER  (0x0001, 6, 4)
#define NXM_NX_REG6_W     NXM_HEADER_W(0x0001, 6, 4)
#define NXM_NX_REG7       NXM_HEADER  (0x0001, 7, 4)
#define NXM_NX_REG7_W     NXM_HEADER_W(0x0001, 7, 4)

/* Tunnel ID.
 *
 * For a packet received via a GRE, VXLAN or LISP tunnel including a (32-bit)
 * key, the key is stored in the low 32-bits and the high bits are zeroed.  For
 * other packets, the value is 0.
 *
 * All zero bits, for packets not received via a keyed tunnel.
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
 * Prereqs: NXM_OF_ETH_TYPE must match either 0x0806 or 0x8035.
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
 * Masking: Fully maskable, in Open vSwitch 1.8 and later.  In previous
 *   versions, only CIDR masks are allowed, that is, masks that consist of N
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
 * Masking: Fully maskable, in Open vSwitch 1.8 and later.  In previous
 *   versions, only CIDR masks are allowed, that is, masks that consist of N
 *   high-order bits set to 1 and the other 128-N bits set to 0. */
#define NXM_NX_ND_TARGET     NXM_HEADER    (0x0001, 23, 16)
#define NXM_NX_ND_TARGET_W   NXM_HEADER_W  (0x0001, 23, 16)

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
 * Masking: Fully maskable. */
#define NXM_NX_IPV6_LABEL   NXM_HEADER  (0x0001, 27, 4)
#define NXM_NX_IPV6_LABEL_W NXM_HEADER_W(0x0001, 27, 4)

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

/* Flow cookie.
 *
 * This may be used to gain the OpenFlow 1.1-like ability to restrict
 * certain NXM-based Flow Mod and Flow Stats Request messages to flows
 * with specific cookies.  See the "nx_flow_mod" and "nx_flow_stats_request"
 * structure definitions for more details.  This match is otherwise not
 * allowed.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define NXM_NX_COOKIE     NXM_HEADER  (0x0001, 30, 8)
#define NXM_NX_COOKIE_W   NXM_HEADER_W(0x0001, 30, 8)

/* The source or destination address in the outer IP header of a tunneled
 * packet.
 *
 * For non-tunneled packets, the value is 0.
 *
 * Prereqs: None.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Fully maskable. */
#define NXM_NX_TUN_IPV4_SRC   NXM_HEADER  (0x0001, 31, 4)
#define NXM_NX_TUN_IPV4_SRC_W NXM_HEADER_W(0x0001, 31, 4)
#define NXM_NX_TUN_IPV4_DST   NXM_HEADER  (0x0001, 32, 4)
#define NXM_NX_TUN_IPV4_DST_W NXM_HEADER_W(0x0001, 32, 4)

/* Metadata marked onto the packet in a system-dependent manner.
 *
 * The packet mark may be used to carry contextual information
 * to other parts of the system outside of Open vSwitch. As a
 * result, the semantics depend on system in use.
 *
 * Prereqs: None.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Fully maskable. */
#define NXM_NX_PKT_MARK   NXM_HEADER  (0x0001, 33, 4)
#define NXM_NX_PKT_MARK_W NXM_HEADER_W(0x0001, 33, 4)

/* The flags in the TCP header.
*
* Prereqs:
*   NXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
*   NXM_OF_IP_PROTO must match 6 exactly.
*
* Format: 16-bit integer with 4 most-significant bits forced to 0.
*
* Masking: Bits 0-11 fully maskable. */
#define NXM_NX_TCP_FLAGS   NXM_HEADER  (0x0001, 34, 2)
#define NXM_NX_TCP_FLAGS_W NXM_HEADER_W(0x0001, 34, 2)

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

/* Action structure for NXAST_CONTROLLER.
 *
 * This generalizes using OFPAT_OUTPUT to send a packet to OFPP_CONTROLLER.  In
 * addition to the 'max_len' that OFPAT_OUTPUT supports, it also allows
 * specifying:
 *
 *    - 'reason': The reason code to use in the ofp_packet_in or nx_packet_in.
 *
 *    - 'controller_id': The ID of the controller connection to which the
 *      ofp_packet_in should be sent.  The ofp_packet_in or nx_packet_in is
 *      sent only to controllers that have the specified controller connection
 *      ID.  See "struct nx_controller_id" for more information. */
struct nx_action_controller {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_CONTROLLER. */
    ovs_be16 max_len;               /* Maximum length to send to controller. */
    ovs_be16 controller_id;         /* Controller ID to send packet-in. */
    uint8_t reason;                 /* enum ofp_packet_in_reason (OFPR_*). */
    uint8_t zero;                   /* Must be zero. */
};
OFP_ASSERT(sizeof(struct nx_action_controller) == 16);

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
 *     This cannot occur with the current implementation of the Open vSwitch
 *     software datapath.  It could happen with other datapath implementations.
 *
 *   - Changes that race with conflicting changes made by other controllers or
 *     other flow_mods (not separated by barriers) by the same controller.
 *
 *     This cannot occur with the current Open vSwitch implementation
 *     (regardless of datapath) because Open vSwitch internally serializes
 *     potentially conflicting changes.
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

/* Action structure for NXAST_WRITE_METADATA.
 *
 * Modifies the 'mask' bits of the metadata value. */
struct nx_action_write_metadata {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 32. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_WRITE_METADATA. */
    uint8_t zeros[6];               /* Must be zero. */
    ovs_be64 metadata;              /* Metadata register. */
    ovs_be64 mask;                  /* Metadata mask. */
};
OFP_ASSERT(sizeof(struct nx_action_write_metadata) == 32);

/* Action structure for NXAST_PUSH_MPLS. */
struct nx_action_push_mpls {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_PUSH_MPLS. */
    ovs_be16 ethertype;             /* Ethertype */
    uint8_t  pad[4];
};
OFP_ASSERT(sizeof(struct nx_action_push_mpls) == 16);

/* Action structure for NXAST_POP_MPLS. */
struct nx_action_pop_mpls {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_POP_MPLS. */
    ovs_be16 ethertype;             /* Ethertype */
    uint8_t  pad[4];
};
OFP_ASSERT(sizeof(struct nx_action_pop_mpls) == 16);

/* Action structure for NXAST_SET_MPLS_LABEL. */
struct nx_action_mpls_label {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_MPLS_LABEL. */
    uint8_t  zeros[2];               /* Must be zero. */
    ovs_be32 label;                 /* LABEL */
};
OFP_ASSERT(sizeof(struct nx_action_mpls_label) == 16);

/* Action structure for NXAST_SET_MPLS_TC. */
struct nx_action_mpls_tc {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_MPLS_TC. */
    uint8_t  tc;                    /* TC */
    uint8_t  pad[5];
};
OFP_ASSERT(sizeof(struct nx_action_mpls_tc) == 16);

/* Action structure for NXAST_SET_MPLS_TTL. */
struct nx_action_mpls_ttl {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SET_MPLS_TTL. */
    uint8_t  ttl;                   /* TTL */
    uint8_t  pad[5];
};
OFP_ASSERT(sizeof(struct nx_action_mpls_ttl) == 16);

/* Action structure for NXAST_SAMPLE.
 *
 * Samples matching packets with the given probability and sends them
 * each to the set of collectors identified with the given ID.  The
 * probability is expressed as a number of packets to be sampled out
 * of USHRT_MAX packets, and must be >0.
 *
 * When sending packet samples to IPFIX collectors, the IPFIX flow
 * record sent for each sampled packet is associated with the given
 * observation domain ID and observation point ID.  Each IPFIX flow
 * record contain the sampled packet's headers when executing this
 * rule.  If a sampled packet's headers are modified by previous
 * actions in the flow, those modified headers are sent. */
struct nx_action_sample {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 24. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SAMPLE. */
    ovs_be16 probability;           /* Fraction of packets to sample. */
    ovs_be32 collector_set_id;      /* ID of collector set in OVSDB. */
    ovs_be32 obs_domain_id;         /* ID of sampling observation domain. */
    ovs_be32 obs_point_id;          /* ID of sampling observation point. */
};
OFP_ASSERT(sizeof(struct nx_action_sample) == 24);

#endif /* openflow/nicira-ext.h */
