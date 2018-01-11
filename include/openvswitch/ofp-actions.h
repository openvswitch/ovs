/*
 * Copyright (c) 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_OFP_ACTIONS_H
#define OPENVSWITCH_OFP_ACTIONS_H 1

#include <stddef.h>
#include <stdint.h>
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"
#include "openvswitch/ofp-ed-props.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vl_mff_map;

/* List of OVS abstracted actions.
 *
 * This macro is used directly only internally by this header, but the list is
 * still of interest to developers.
 *
 * Each OFPACT invocation has the following parameters:
 *
 * 1. <ENUM>, used below in the enum definition of OFPACT_<ENUM>, and
 *    elsewhere.
 *
 * 2. <STRUCT> corresponding to a structure "struct <STRUCT>", that must be
 *    defined below.  This structure must be an abstract definition of the
 *    action.  Its first member must have type "struct ofpact" and name
 *    "ofpact".  It may be fixed length or end with a flexible array member
 *    (e.g. "int member[];").
 *
 * 3. <MEMBER>, which has one of two possible values:
 *
 *        - If "struct <STRUCT>" is fixed-length, it must be "ofpact".
 *
 *        - If "struct <STRUCT>" is variable-length, it must be the name of the
 *          flexible array member.
 *
 * 4. <NAME>, a quoted string that gives the name of the action, for use in
 *    parsing actions from text.
 */
#define OFPACTS                                                         \
    /* Output. */                                                       \
    OFPACT(OUTPUT,          ofpact_output,      ofpact, "output")       \
    OFPACT(GROUP,           ofpact_group,       ofpact, "group")        \
    OFPACT(CONTROLLER,      ofpact_controller,  userdata, "controller") \
    OFPACT(ENQUEUE,         ofpact_enqueue,     ofpact, "enqueue")      \
    OFPACT(OUTPUT_REG,      ofpact_output_reg,  ofpact, "output_reg")   \
    OFPACT(BUNDLE,          ofpact_bundle,      slaves, "bundle")       \
                                                                        \
    /* Header changes. */                                               \
    OFPACT(SET_FIELD,       ofpact_set_field,   ofpact, "set_field")    \
    OFPACT(SET_VLAN_VID,    ofpact_vlan_vid,    ofpact, "set_vlan_vid") \
    OFPACT(SET_VLAN_PCP,    ofpact_vlan_pcp,    ofpact, "set_vlan_pcp") \
    OFPACT(STRIP_VLAN,      ofpact_null,        ofpact, "strip_vlan")   \
    OFPACT(PUSH_VLAN,       ofpact_push_vlan,   ofpact, "push_vlan")    \
    OFPACT(SET_ETH_SRC,     ofpact_mac,         ofpact, "mod_dl_src")   \
    OFPACT(SET_ETH_DST,     ofpact_mac,         ofpact, "mod_dl_dst")   \
    OFPACT(SET_IPV4_SRC,    ofpact_ipv4,        ofpact, "mod_nw_src")   \
    OFPACT(SET_IPV4_DST,    ofpact_ipv4,        ofpact, "mod_nw_dst")   \
    OFPACT(SET_IP_DSCP,     ofpact_dscp,        ofpact, "mod_nw_tos")   \
    OFPACT(SET_IP_ECN,      ofpact_ecn,         ofpact, "mod_nw_ecn")   \
    OFPACT(SET_IP_TTL,      ofpact_ip_ttl,      ofpact, "mod_nw_ttl")   \
    OFPACT(SET_L4_SRC_PORT, ofpact_l4_port,     ofpact, "mod_tp_src")   \
    OFPACT(SET_L4_DST_PORT, ofpact_l4_port,     ofpact, "mod_tp_dst")   \
    OFPACT(REG_MOVE,        ofpact_reg_move,    ofpact, "move")         \
    OFPACT(STACK_PUSH,      ofpact_stack,       ofpact, "push")         \
    OFPACT(STACK_POP,       ofpact_stack,       ofpact, "pop")          \
    OFPACT(DEC_TTL,         ofpact_cnt_ids,     cnt_ids, "dec_ttl")     \
    OFPACT(SET_MPLS_LABEL,  ofpact_mpls_label,  ofpact, "set_mpls_label") \
    OFPACT(SET_MPLS_TC,     ofpact_mpls_tc,     ofpact, "set_mpls_tc")  \
    OFPACT(SET_MPLS_TTL,    ofpact_mpls_ttl,    ofpact, "set_mpls_ttl") \
    OFPACT(DEC_MPLS_TTL,    ofpact_null,        ofpact, "dec_mpls_ttl") \
    OFPACT(PUSH_MPLS,       ofpact_push_mpls,   ofpact, "push_mpls")    \
    OFPACT(POP_MPLS,        ofpact_pop_mpls,    ofpact, "pop_mpls")     \
    OFPACT(DEC_NSH_TTL,     ofpact_null,        ofpact, "dec_nsh_ttl")  \
                                                                        \
    /* Generic encap & decap */                                         \
    OFPACT(ENCAP,           ofpact_encap,       props, "encap")         \
    OFPACT(DECAP,           ofpact_decap,       ofpact, "decap")        \
                                                                        \
    /* Metadata. */                                                     \
    OFPACT(SET_TUNNEL,      ofpact_tunnel,      ofpact, "set_tunnel")   \
    OFPACT(SET_QUEUE,       ofpact_queue,       ofpact, "set_queue")    \
    OFPACT(POP_QUEUE,       ofpact_null,        ofpact, "pop_queue")    \
    OFPACT(FIN_TIMEOUT,     ofpact_fin_timeout, ofpact, "fin_timeout")  \
                                                                        \
    /* Flow table interaction. */                                       \
    OFPACT(RESUBMIT,        ofpact_resubmit,    ofpact, "resubmit")     \
    OFPACT(LEARN,           ofpact_learn,       specs, "learn")         \
    OFPACT(CONJUNCTION,     ofpact_conjunction, ofpact, "conjunction")  \
                                                                        \
    /* Arithmetic. */                                                   \
    OFPACT(MULTIPATH,       ofpact_multipath,   ofpact, "multipath")    \
                                                                        \
    /* Other. */                                                        \
    OFPACT(NOTE,            ofpact_note,        data, "note")           \
    OFPACT(EXIT,            ofpact_null,        ofpact, "exit")         \
    OFPACT(SAMPLE,          ofpact_sample,      ofpact, "sample")       \
    OFPACT(UNROLL_XLATE,    ofpact_unroll_xlate, ofpact, "unroll_xlate") \
    OFPACT(CT,              ofpact_conntrack,   ofpact, "ct")           \
    OFPACT(CT_CLEAR,        ofpact_null,        ofpact, "ct_clear")     \
    OFPACT(NAT,             ofpact_nat,         ofpact, "nat")          \
    OFPACT(OUTPUT_TRUNC,    ofpact_output_trunc,ofpact, "output_trunc") \
    OFPACT(CLONE,           ofpact_nest,        actions, "clone")       \
                                                                        \
    /* Debugging actions.                                               \
     *                                                                  \
     * These are intentionally undocumented, subject to change, and     \
     * only accepted if ovs-vswitchd is started with --enable-dummy. */ \
    OFPACT(DEBUG_RECIRC, ofpact_null,           ofpact, "debug_recirc") \
    OFPACT(DEBUG_SLOW,   ofpact_null,           ofpact, "debug_slow")   \
                                                                        \
    /* Instructions. */                                                 \
    OFPACT(METER,           ofpact_meter,       ofpact, "meter")        \
    OFPACT(CLEAR_ACTIONS,   ofpact_null,        ofpact, "clear_actions") \
    OFPACT(WRITE_ACTIONS,   ofpact_nest,        actions, "write_actions") \
    OFPACT(WRITE_METADATA,  ofpact_metadata,    ofpact, "write_metadata") \
    OFPACT(GOTO_TABLE,      ofpact_goto_table,  ofpact, "goto_table")

/* enum ofpact_type, with a member OFPACT_<ENUM> for each action. */
enum OVS_PACKED_ENUM ofpact_type {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME) OFPACT_##ENUM,
    OFPACTS
#undef OFPACT
};

/* Define N_OFPACTS to the number of types of ofpacts. */
enum {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME) + 1
    N_OFPACTS = OFPACTS
#undef OFPACT
};

/* Header for an action.
 *
 * Each action is a structure "struct ofpact_*" that begins with "struct
 * ofpact", usually followed by other data that describes the action.  Actions
 * are padded out to a multiple of OFPACT_ALIGNTO bytes in length.
 *
 * The 'raw' member is special:
 *
 *     - Most "struct ofpact"s correspond to one particular kind of OpenFlow
 *       action, at least in a given OpenFlow version.  For example,
 *       OFPACT_SET_VLAN_VID corresponds to OFPAT10_SET_VLAN_VID in OpenFlow
 *       1.0.
 *
 *       For such actions, the 'raw' member is not meaningful and generally
 *       should be zero.
 *
 *     - A few "struct ofpact"s correspond to multiple OpenFlow actions.  For
 *       example, OFPACT_SET_TUNNEL can be NXAST_SET_TUNNEL or
 *       NXAST_SET_TUNNEL64.  In these cases, if the "struct ofpact" originated
 *       from OpenFlow, then we want to make sure that, if it gets translated
 *       back to OpenFlow later, it is translated back to the same action type.
 *       (Otherwise, we'd violate the promise made in the topics/design doc, in
 *       the "Action Reproduction" section.)
 *
 *       For such actions, the 'raw' member should be the "enum ofp_raw_action"
 *       originally extracted from the OpenFlow action.  (If the action didn't
 *       originate from OpenFlow, then setting 'raw' to zero should be fine:
 *       code to translate the ofpact to OpenFlow must tolerate this case.)
 */
struct ofpact {
    /* We want the space advantage of an 8-bit type here on every
     * implementation, without giving up the advantage of having a useful type
     * on implementations that support packed enums. */
#ifdef HAVE_PACKED_ENUM
    enum ofpact_type type;      /* OFPACT_*. */
#else
    uint8_t type;               /* OFPACT_* */
#endif

    uint8_t raw;                /* Original type when added, if any. */
    uint16_t len;               /* Length of the action, in bytes, including
                                 * struct ofpact, excluding padding. */
};
BUILD_ASSERT_DECL(sizeof(struct ofpact) == 4);

/* Alignment. */
#define OFPACT_ALIGNTO 8
#define OFPACT_ALIGN(SIZE) ROUND_UP(SIZE, OFPACT_ALIGNTO)
#define OFPACT_PADDED_MEMBERS(MEMBERS) PADDED_MEMBERS(OFPACT_ALIGNTO, MEMBERS)

/* Returns the ofpact following 'ofpact'. */
static inline struct ofpact *
ofpact_next(const struct ofpact *ofpact)
{
    return ALIGNED_CAST(struct ofpact *,
                        (uint8_t *) ofpact + OFPACT_ALIGN(ofpact->len));
}

struct ofpact *ofpact_next_flattened(const struct ofpact *);

static inline struct ofpact *
ofpact_end(const struct ofpact *ofpacts, size_t ofpacts_len)
{
    return ALIGNED_CAST(struct ofpact *, (uint8_t *) ofpacts + ofpacts_len);
}

static inline bool
ofpact_last(const struct ofpact *a, const struct ofpact *ofpacts,
            size_t ofpact_len)
{
    return ofpact_next(a) == ofpact_end(ofpacts, ofpact_len);
}

static inline const struct ofpact *
ofpact_find_type_flattened(const struct ofpact *a, enum ofpact_type type,
                           const struct ofpact * const end)
{
    while (a < end) {
        if (a->type == type) {
            return a;
        }
        a = ofpact_next_flattened(a);
    }
    return NULL;
}

#define OFPACT_FIND_TYPE_FLATTENED(A, TYPE, END) \
    ofpact_get_##TYPE##_nullable(                       \
        ofpact_find_type_flattened(A, OFPACT_##TYPE, END))

/* Assigns POS to each ofpact, in turn, in the OFPACTS_LEN bytes of ofpacts
 * starting at OFPACTS. */
#define OFPACT_FOR_EACH(POS, OFPACTS, OFPACTS_LEN)                      \
    for ((POS) = (OFPACTS); (POS) < ofpact_end(OFPACTS, OFPACTS_LEN);  \
         (POS) = ofpact_next(POS))

/* Assigns POS to each ofpact, in turn, in the OFPACTS_LEN bytes of ofpacts
 * starting at OFPACTS.
 *
 * For ofpacts that contain nested ofpacts, this visits each of the inner
 * ofpacts as well. */
#define OFPACT_FOR_EACH_FLATTENED(POS, OFPACTS, OFPACTS_LEN)           \
    for ((POS) = (OFPACTS); (POS) < ofpact_end(OFPACTS, OFPACTS_LEN);  \
         (POS) = ofpact_next_flattened(POS))

#define OFPACT_FOR_EACH_TYPE_FLATTENED(POS, TYPE, OFPACTS, OFPACTS_LEN) \
    for ((POS) = OFPACT_FIND_TYPE_FLATTENED(OFPACTS, TYPE,              \
                                  ofpact_end(OFPACTS, OFPACTS_LEN));    \
         (POS);                                                         \
         (POS) = OFPACT_FIND_TYPE_FLATTENED(                            \
             ofpact_next_flattened(&(POS)->ofpact), TYPE,               \
             ofpact_end(OFPACTS, OFPACTS_LEN)))

/* Action structure for each OFPACT_*. */

/* OFPACT_STRIP_VLAN, OFPACT_POP_QUEUE, OFPACT_EXIT, OFPACT_CLEAR_ACTIONS.
 *
 * Used for OFPAT10_STRIP_VLAN, NXAST_POP_QUEUE, NXAST_EXIT,
 * OFPAT11_POP_VLAN, OFPIT11_CLEAR_ACTIONS.
 *
 * Action structure for actions that do not have any extra data beyond the
 * action type. */
struct ofpact_null {
    struct ofpact ofpact;
};

/* OFPACT_OUTPUT.
 *
 * Used for OFPAT10_OUTPUT. */
struct ofpact_output {
    struct ofpact ofpact;
    ofp_port_t port;            /* Output port. */
    uint16_t max_len;           /* Max send len, for port OFPP_CONTROLLER. */
};

/* OFPACT_CONTROLLER.
 *
 * Used for NXAST_CONTROLLER. */
struct ofpact_controller {
    OFPACT_PADDED_MEMBERS(
        struct ofpact ofpact;
        uint16_t max_len;   /* Max length to send to controller. */
        uint16_t controller_id; /* Controller ID to send packet-in. */
        enum ofp_packet_in_reason reason; /* Reason to put in packet-in. */

        /* If true, this action freezes packet traversal of the OpenFlow
         * tables and adds a continuation to the packet-in message, that
         * a controller can use to resume that traversal. */
        bool pause;

        /* Arbitrary data to include in the packet-in message (currently,
         * only in NXT_PACKET_IN2). */
        uint16_t userdata_len;
    );
    uint8_t userdata[0];
};

/* OFPACT_ENQUEUE.
 *
 * Used for OFPAT10_ENQUEUE. */
struct ofpact_enqueue {
    struct ofpact ofpact;
    ofp_port_t port;
    uint32_t queue;
};

/* OFPACT_OUTPUT_REG.
 *
 * Used for NXAST_OUTPUT_REG. */
struct ofpact_output_reg {
    struct ofpact ofpact;
    uint16_t max_len;
    struct mf_subfield src;
};

/* OFPACT_OUTPUT_TRUNC.
 *
 * Used for NXAST_OUTPUT_TRUNC. */
struct ofpact_output_trunc {
    struct ofpact ofpact;
    ofp_port_t port;            /* Output port. */
    uint32_t max_len;           /* Max send len. */
};

/* Bundle slave choice algorithm to apply.
 *
 * In the descriptions below, 'slaves' is the list of possible slaves in the
 * order they appear in the OpenFlow action. */
enum nx_bd_algorithm {
    /* Chooses the first live slave listed in the bundle.
     *
     * O(n_slaves) performance. */
    NX_BD_ALG_ACTIVE_BACKUP = 0,

    /* Highest Random Weight.
     *
     * for i in [0,n_slaves):
     *   weights[i] = hash(flow, i)
     * slave = { slaves[i] such that weights[i] >= weights[j] for all j != i }
     *
     * Redistributes 1/n_slaves of traffic when a slave's liveness changes.
     * O(n_slaves) performance.
     *
     * Uses the 'fields' and 'basis' parameters. */
    NX_BD_ALG_HRW = 1
};

/* OFPACT_BUNDLE.
 *
 * Used for NXAST_BUNDLE. */
struct ofpact_bundle {
    struct ofpact ofpact;

    /* Slave choice algorithm to apply to hash value. */
    enum nx_bd_algorithm algorithm;

    /* What fields to hash and how. */
    enum nx_hash_fields fields;
    uint16_t basis;             /* Universal hash parameter. */

    struct mf_subfield dst;

    /* Slaves for output. */
    unsigned int n_slaves;
    ofp_port_t slaves[];
};

/* OFPACT_SET_VLAN_VID.
 *
 * We keep track if vlan was present at action validation time to avoid a
 * PUSH_VLAN when translating to OpenFlow 1.1+.
 *
 * We also keep the originating OFPUTIL action code in ofpact.compat.
 *
 * Used for OFPAT10_SET_VLAN_VID and OFPAT11_SET_VLAN_VID. */
struct ofpact_vlan_vid {
    struct ofpact ofpact;
    uint16_t vlan_vid;          /* VLAN VID in low 12 bits, 0 in other bits. */
    bool push_vlan_if_needed;   /* OF 1.0 semantics if true. */
    bool flow_has_vlan;         /* VLAN present at action validation time? */
};

/* OFPACT_SET_VLAN_PCP.
 *
 * We keep track if vlan was present at action validation time to avoid a
 * PUSH_VLAN when translating to OpenFlow 1.1+.
 *
 * We also keep the originating OFPUTIL action code in ofpact.compat.
 *
 * Used for OFPAT10_SET_VLAN_PCP and OFPAT11_SET_VLAN_PCP. */
struct ofpact_vlan_pcp {
    struct ofpact ofpact;
    uint8_t vlan_pcp;           /* VLAN PCP in low 3 bits, 0 in other bits. */
    bool push_vlan_if_needed;   /* OF 1.0 semantics if true. */
    bool flow_has_vlan;         /* VLAN present at action validation time? */
};

/* OFPACT_PUSH_VLAN.
 *
 * Used for OFPAT11_PUSH_VLAN. */
struct ofpact_push_vlan {
    struct ofpact ofpact;
    ovs_be16 ethertype;
};

/* OFPACT_SET_ETH_SRC, OFPACT_SET_ETH_DST.
 *
 * Used for OFPAT10_SET_DL_SRC, OFPAT10_SET_DL_DST. */
struct ofpact_mac {
    struct ofpact ofpact;
    struct eth_addr mac;
};

/* OFPACT_SET_IPV4_SRC, OFPACT_SET_IPV4_DST.
 *
 * Used for OFPAT10_SET_NW_SRC, OFPAT10_SET_NW_DST. */
struct ofpact_ipv4 {
    struct ofpact ofpact;
    ovs_be32 ipv4;
};

/* OFPACT_SET_IP_DSCP.
 *
 * Used for OFPAT10_SET_NW_TOS. */
struct ofpact_dscp {
    struct ofpact ofpact;
    uint8_t dscp;               /* DSCP in high 6 bits, rest ignored. */
};

/* OFPACT_SET_IP_ECN.
 *
 * Used for OFPAT11_SET_NW_ECN. */
struct ofpact_ecn {
    struct ofpact ofpact;
    uint8_t ecn;               /* ECN in low 2 bits, rest ignored. */
};

/* OFPACT_SET_IP_TTL.
 *
 * Used for OFPAT11_SET_NW_TTL. */
struct ofpact_ip_ttl {
    struct ofpact ofpact;
    uint8_t ttl;
};

/* OFPACT_SET_L4_SRC_PORT, OFPACT_SET_L4_DST_PORT.
 *
 * Used for OFPAT10_SET_TP_SRC, OFPAT10_SET_TP_DST. */
struct ofpact_l4_port {
    struct ofpact ofpact;
    uint16_t port;              /* TCP, UDP or SCTP port number. */
    uint8_t  flow_ip_proto;     /* IP proto from corresponding match, or 0 */
};

/* OFPACT_REG_MOVE.
 *
 * Used for NXAST_REG_MOVE. */
struct ofpact_reg_move {
    struct ofpact ofpact;
    struct mf_subfield src;
    struct mf_subfield dst;
};

/* OFPACT_STACK_PUSH, OFPACT_STACK_POP.
 *
 * Used for NXAST_STACK_PUSH and NXAST_STACK_POP. */
struct ofpact_stack {
    struct ofpact ofpact;
    struct mf_subfield subfield;
};

/* OFPACT_SET_FIELD.
 *
 * Used for NXAST_REG_LOAD and OFPAT12_SET_FIELD. */
struct ofpact_set_field {
    OFPACT_PADDED_MEMBERS(
        struct ofpact ofpact;
        bool flow_has_vlan;   /* VLAN present at action validation time. */
        const struct mf_field *field;
    );
    union mf_value value[];  /* Significant value bytes followed by
                              * significant mask bytes. */
};
BUILD_ASSERT_DECL(offsetof(struct ofpact_set_field, value)
                  % OFPACT_ALIGNTO == 0);
BUILD_ASSERT_DECL(offsetof(struct ofpact_set_field, value)
                  == sizeof(struct ofpact_set_field));

/* Use macro to not have to deal with constness. */
#define ofpact_set_field_mask(SF)                               \
    ALIGNED_CAST(union mf_value *,                              \
                 (uint8_t *)(SF)->value + (SF)->field->n_bytes)

/* OFPACT_PUSH_VLAN/MPLS/PBB
 *
 * Used for NXAST_PUSH_MPLS, OFPAT11_PUSH_MPLS. */
struct ofpact_push_mpls {
    struct ofpact ofpact;
    ovs_be16 ethertype;
};

/* OFPACT_POP_MPLS
 *
 * Used for NXAST_POP_MPLS, OFPAT11_POP_MPLS.. */
struct ofpact_pop_mpls {
    struct ofpact ofpact;
    ovs_be16 ethertype;
};

/* OFPACT_SET_TUNNEL.
 *
 * Used for NXAST_SET_TUNNEL, NXAST_SET_TUNNEL64. */
struct ofpact_tunnel {
    struct ofpact ofpact;
    uint64_t tun_id;
};

/* OFPACT_SET_QUEUE.
 *
 * Used for NXAST_SET_QUEUE. */
struct ofpact_queue {
    struct ofpact ofpact;
    uint32_t queue_id;
};

/* OFPACT_FIN_TIMEOUT.
 *
 * Used for NXAST_FIN_TIMEOUT. */
struct ofpact_fin_timeout {
    struct ofpact ofpact;
    uint16_t fin_idle_timeout;
    uint16_t fin_hard_timeout;
};

/* OFPACT_WRITE_METADATA.
 *
 * Used for NXAST_WRITE_METADATA. */
struct ofpact_metadata {
    struct ofpact ofpact;
    ovs_be64 metadata;
    ovs_be64 mask;
};

/* OFPACT_METER.
 *
 * Used for OFPIT13_METER. */
struct ofpact_meter {
    struct ofpact ofpact;
    uint32_t meter_id;
    uint32_t provider_meter_id;
};

/* OFPACT_WRITE_ACTIONS, OFPACT_CLONE.
 *
 * Used for OFPIT11_WRITE_ACTIONS, NXAST_CLONE. */
struct ofpact_nest {
    OFPACT_PADDED_MEMBERS(struct ofpact ofpact;);
    struct ofpact actions[];
};
BUILD_ASSERT_DECL(offsetof(struct ofpact_nest, actions) % OFPACT_ALIGNTO == 0);
BUILD_ASSERT_DECL(offsetof(struct ofpact_nest, actions)
                  == sizeof(struct ofpact_nest));

static inline size_t
ofpact_nest_get_action_len(const struct ofpact_nest *on)
{
    return on->ofpact.len - offsetof(struct ofpact_nest, actions);
}

/* Bits for 'flags' in struct nx_action_conntrack.
 *
 * If NX_CT_F_COMMIT is set, then the connection entry is moved from the
 * unconfirmed to confirmed list in the tracker.
 * If NX_CT_F_FORCE is set, in addition to NX_CT_F_COMMIT, then the conntrack
 * entry is replaced with a new one in case the original direction of the
 * existing entry is opposite of the current packet direction.
 */
enum nx_conntrack_flags {
    NX_CT_F_COMMIT = 1 << 0,
    NX_CT_F_FORCE  = 1 << 1,
};

/* Magic value for struct nx_action_conntrack 'recirc_table' field, to specify
 * that the packet should not be recirculated. */
#define NX_CT_RECIRC_NONE OFPTT_ALL

#if !defined(IPPORT_FTP)
#define IPPORT_FTP  21
#endif

#if !defined(IPPORT_TFTP)
#define IPPORT_TFTP  69
#endif

/* OFPACT_CT.
 *
 * Used for NXAST_CT. */
struct ofpact_conntrack {
    OFPACT_PADDED_MEMBERS(
        struct ofpact ofpact;
        uint16_t flags;
        uint16_t zone_imm;
        struct mf_subfield zone_src;
        uint16_t alg;
        uint8_t recirc_table;
    );
    struct ofpact actions[0];
};
BUILD_ASSERT_DECL(offsetof(struct ofpact_conntrack, actions)
                  % OFPACT_ALIGNTO == 0);
BUILD_ASSERT_DECL(offsetof(struct ofpact_conntrack, actions)
                  == sizeof(struct ofpact_conntrack));

static inline size_t
ofpact_ct_get_action_len(const struct ofpact_conntrack *oc)
{
    return oc->ofpact.len - offsetof(struct ofpact_conntrack, actions);
}

void ofpacts_execute_action_set(struct ofpbuf *action_list,
                                const struct ofpbuf *action_set);

/* Bits for 'flags' in struct nx_action_nat.
 */
enum nx_nat_flags {
    NX_NAT_F_SRC          = 1 << 0, /* Mutually exclusive with NX_NAT_F_DST. */
    NX_NAT_F_DST          = 1 << 1,
    NX_NAT_F_PERSISTENT   = 1 << 2,
    NX_NAT_F_PROTO_HASH   = 1 << 3, /* Mutually exclusive with PROTO_RANDOM. */
    NX_NAT_F_PROTO_RANDOM = 1 << 4,
    NX_NAT_F_MASK = (NX_NAT_F_SRC | NX_NAT_F_DST | NX_NAT_F_PERSISTENT | NX_NAT_F_PROTO_HASH | NX_NAT_F_PROTO_RANDOM)
};

/* OFPACT_NAT.
 *
 * Used for NXAST_NAT. */
struct ofpact_nat {
    struct ofpact ofpact;
    uint8_t range_af; /* AF_UNSPEC, AF_INET, or AF_INET6 */
    uint16_t flags;  /* NX_NAT_F_* */
    struct {
        struct {
            uint16_t min;
            uint16_t max;
        } proto;
        union {
            struct {
                ovs_be32 min;
                ovs_be32 max;
            } ipv4;
            struct {
                struct in6_addr min;
                struct in6_addr max;
            } ipv6;
        } addr;
    } range;
};


/* OFPACT_RESUBMIT.
 *
 * Used for NXAST_RESUBMIT, NXAST_RESUBMIT_TABLE, NXAST_RESUBMIT_TABLE_CT. */
struct ofpact_resubmit {
    struct ofpact ofpact;
    ofp_port_t in_port;
    uint8_t table_id;
    bool with_ct_orig;   /* Resubmit with Conntrack original direction tuple
                          * fields in place of IP header fields. */
};

/* Bits for 'flags' in struct nx_action_learn.
 *
 * If NX_LEARN_F_SEND_FLOW_REM is set, then the learned flows will have their
 * OFPFF_SEND_FLOW_REM flag set.
 *
 * If NX_LEARN_F_WRITE_RESULT is set, then the actions will write whether the
 * learn operation succeded on a bit.  If the learn is successful the bit will
 * be set, otherwise (e.g. if the limit is hit) the bit will be unset.
 *
 * If NX_LEARN_F_DELETE_LEARNED is set, then removing this action will delete
 * all the flows from the learn action's 'table_id' that have the learn
 * action's 'cookie'.  Important points:
 *
 *     - The deleted flows include those created by this action, those created
 *       by other learn actions with the same 'table_id' and 'cookie', those
 *       created by flow_mod requests by a controller in the specified table
 *       with the specified cookie, and those created through any other
 *       means.
 *
 *     - If multiple flows specify "learn" actions with
 *       NX_LEARN_F_DELETE_LEARNED with the same 'table_id' and 'cookie', then
 *       no deletion occurs until all of those "learn" actions are deleted.
 *
 *     - Deleting a flow that contains a learn action is the most obvious way
 *       to delete a learn action.  Modifying a flow's actions, or replacing it
 *       by a new flow, can also delete a learn action.  Finally, replacing a
 *       learn action with NX_LEARN_F_DELETE_LEARNED with a learn action
 *       without that flag also effectively deletes the learn action and can
 *       trigger flow deletion.
 *
 * NX_LEARN_F_DELETE_LEARNED was added in Open vSwitch 2.4. */
enum nx_learn_flags {
    NX_LEARN_F_SEND_FLOW_REM = 1 << 0,
    NX_LEARN_F_DELETE_LEARNED = 1 << 1,
    NX_LEARN_F_WRITE_RESULT = 1 << 2,
};

#define NX_LEARN_N_BITS_MASK    0x3ff

#define NX_LEARN_SRC_FIELD     (0 << 13) /* Copy from field. */
#define NX_LEARN_SRC_IMMEDIATE (1 << 13) /* Copy from immediate value. */
#define NX_LEARN_SRC_MASK      (1 << 13)

#define NX_LEARN_DST_MATCH     (0 << 11) /* Add match criterion. */
#define NX_LEARN_DST_LOAD      (1 << 11) /* Add NXAST_REG_LOAD action. */
#define NX_LEARN_DST_OUTPUT    (2 << 11) /* Add OFPAT_OUTPUT action. */
#define NX_LEARN_DST_RESERVED  (3 << 11) /* Not yet defined. */
#define NX_LEARN_DST_MASK      (3 << 11)

/* Part of struct ofpact_learn, below. */
struct ofpact_learn_spec {
    OFPACT_PADDED_MEMBERS(
        struct mf_subfield src;    /* NX_LEARN_SRC_FIELD only. */
        struct mf_subfield dst;    /* NX_LEARN_DST_MATCH,
                                    * NX_LEARN_DST_LOAD only. */
        uint16_t src_type;         /* One of NX_LEARN_SRC_*. */
        uint16_t dst_type;         /* One of NX_LEARN_DST_*. */
        uint8_t n_bits;            /* Number of bits in source and dest. */
    );
    /* Followed by 'DIV_ROUND_UP(n_bits, 8)' bytes of immediate data for
     * match 'dst_type's NX_LEARN_DST_MATCH and NX_LEARN_DST_LOAD when
     * NX_LEARN_SRC_IMMEDIATE is set in 'src_type', followed by zeroes to align
     * to OFPACT_ALIGNTO. */
};
BUILD_ASSERT_DECL(sizeof(struct ofpact_learn_spec) % OFPACT_ALIGNTO == 0);

static inline const void *
ofpact_learn_spec_imm(const struct ofpact_learn_spec *spec)
{
    return spec + 1;
}

static inline const struct ofpact_learn_spec *
ofpact_learn_spec_next(const struct ofpact_learn_spec *spec)
{
    if (spec->src_type == NX_LEARN_SRC_IMMEDIATE) {
        unsigned int n_bytes = OFPACT_ALIGN(DIV_ROUND_UP(spec->n_bits, 8));
        return ALIGNED_CAST(const struct ofpact_learn_spec *,
                            (const uint8_t *)(spec + 1) + n_bytes);
    }
    return spec + 1;
}

/* OFPACT_LEARN.
 *
 * Used for NXAST_LEARN. */
struct ofpact_learn {
    OFPACT_PADDED_MEMBERS(
        struct ofpact ofpact;

        uint16_t idle_timeout;     /* Idle time before discarding (seconds). */
        uint16_t hard_timeout;     /* Max time before discarding (seconds). */
        uint16_t priority;         /* Priority level of flow entry. */
        uint8_t table_id;          /* Table to insert flow entry. */
        enum nx_learn_flags flags; /* NX_LEARN_F_*. */
        ovs_be64 cookie;           /* Cookie for new flow. */
        uint16_t fin_idle_timeout; /* Idle timeout after FIN, if nonzero. */
        uint16_t fin_hard_timeout; /* Hard timeout after FIN, if nonzero. */
        /* If the number of flows on 'table_id' with 'cookie' exceeds this,
         * the action will not add a new flow. 0 indicates unlimited. */
        uint32_t limit;
        /* Used only if 'flags' has NX_LEARN_F_WRITE_RESULT.  If the execution
         * failed to install a new flow because 'limit' is exceeded,
         * result_dst will be set to 0, otherwise to 1. */
        struct mf_subfield result_dst;
    );

    struct ofpact_learn_spec specs[];
};

static inline const struct ofpact_learn_spec *
ofpact_learn_spec_end(const struct ofpact_learn *learn)
{
    return ALIGNED_CAST(const struct ofpact_learn_spec *,
                        ofpact_next(&learn->ofpact));
}

#define OFPACT_LEARN_SPEC_FOR_EACH(SPEC, LEARN) \
    for ((SPEC) = (LEARN)->specs;               \
         (SPEC) < ofpact_learn_spec_end(LEARN); \
         (SPEC) = ofpact_learn_spec_next(SPEC))

/* Multipath link choice algorithm to apply.
 *
 * In the descriptions below, 'n_links' is max_link + 1. */
enum nx_mp_algorithm {
    /* link = hash(flow) % n_links.
     *
     * Redistributes all traffic when n_links changes.  O(1) performance.  See
     * RFC 2992.
     *
     * Use UINT16_MAX for max_link to get a raw hash value. */
    NX_MP_ALG_MODULO_N = 0,

    /* link = hash(flow) / (MAX_HASH / n_links).
     *
     * Redistributes between one-quarter and one-half of traffic when n_links
     * changes.  O(1) performance.  See RFC 2992.
     */
    NX_MP_ALG_HASH_THRESHOLD = 1,

    /* Highest Random Weight.
     *
     * for i in [0,n_links):
     *   weights[i] = hash(flow, i)
     * link = { i such that weights[i] >= weights[j] for all j != i }
     *
     * Redistributes 1/n_links of traffic when n_links changes.  O(n_links)
     * performance.  If n_links is greater than a threshold (currently 64, but
     * subject to change), Open vSwitch will substitute another algorithm
     * automatically.  See RFC 2992. */
    NX_MP_ALG_HRW = 2,

    /* Iterative Hash.
     *
     * i = 0
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
    NX_MP_ALG_ITER_HASH = 3,
};

/* OFPACT_CONJUNCTION.
 *
 * Used for NXAST_CONJUNCTION. */
struct ofpact_conjunction {
    struct ofpact ofpact;
    uint8_t clause;
    uint8_t n_clauses;
    uint32_t id;
};

/* OFPACT_MULTIPATH.
 *
 * Used for NXAST_MULTIPATH. */
struct ofpact_multipath {
    struct ofpact ofpact;

    /* What fields to hash and how. */
    enum nx_hash_fields fields;
    uint16_t basis;             /* Universal hash parameter. */

    /* Multipath link choice algorithm to apply to hash value. */
    enum nx_mp_algorithm algorithm;
    uint16_t max_link;          /* Number of output links, minus 1. */
    uint32_t arg;               /* Algorithm-specific argument. */

    /* Where to store the result. */
    struct mf_subfield dst;
};

/* OFPACT_NOTE.
 *
 * Used for NXAST_NOTE. */
struct ofpact_note {
    struct ofpact ofpact;
    size_t length;
    uint8_t data[];
};

/* Direction of sampled packets. */
enum nx_action_sample_direction {
    /* OVS will attempt to infer the sample's direction based on whether
     * 'sampling_port' is the packet's output port.  This is generally
     * effective except when sampling happens as part of an output to a patch
     * port, which doesn't involve a datapath output action. */
    NX_ACTION_SAMPLE_DEFAULT,

    /* Explicit direction.  This is useful for sampling packets coming in from
     * or going out of a patch port, where the direction cannot be inferred. */
    NX_ACTION_SAMPLE_INGRESS,
    NX_ACTION_SAMPLE_EGRESS
};

/* OFPACT_SAMPLE.
 *
 * Used for NXAST_SAMPLE, NXAST_SAMPLE2, and NXAST_SAMPLE3. */
struct ofpact_sample {
    struct ofpact ofpact;
    uint16_t probability;  /* Always positive. */
    uint32_t collector_set_id;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
    ofp_port_t sampling_port;
    enum nx_action_sample_direction direction;
};

/* OFPACT_DEC_TTL.
 *
 * Used for OFPAT11_DEC_NW_TTL, NXAST_DEC_TTL and NXAST_DEC_TTL_CNT_IDS. */
struct ofpact_cnt_ids {
    struct ofpact ofpact;

    /* Controller ids. */
    unsigned int n_controllers;
    uint16_t cnt_ids[];
};

/* OFPACT_SET_MPLS_LABEL.
 *
 * Used for OFPAT11_SET_MPLS_LABEL and NXAST_SET_MPLS_LABEL */
struct ofpact_mpls_label {
    struct ofpact ofpact;

    ovs_be32 label;
};

/* OFPACT_SET_MPLS_TC.
 *
 * Used for OFPAT11_SET_MPLS_TC and NXAST_SET_MPLS_TC */
struct ofpact_mpls_tc {
    struct ofpact ofpact;

    uint8_t tc;
};

/* OFPACT_SET_MPLS_TTL.
 *
 * Used for OFPAT11_SET_MPLS_TTL and NXAST_SET_MPLS_TTL */
struct ofpact_mpls_ttl {
    struct ofpact ofpact;

    uint8_t ttl;
};

/* OFPACT_GOTO_TABLE
 *
 * Used for OFPIT11_GOTO_TABLE */
struct ofpact_goto_table {
    struct ofpact ofpact;
    uint8_t table_id;
};

/* OFPACT_GROUP.
 *
 * Used for OFPAT11_GROUP. */
struct ofpact_group {
    struct ofpact ofpact;
    uint32_t group_id;
};

/* OFPACT_UNROLL_XLATE.
 *
 * Used only internally. */
struct ofpact_unroll_xlate {
    struct ofpact ofpact;

    /* Metadata in xlate context, visible to controller via PACKET_INs. */
    uint8_t  rule_table_id;       /* 0xFF if none. */
    ovs_be64 rule_cookie;         /* OVS_BE64_MAX if none. */
};

/* OFPACT_ENCAP.
 *
 * Used for NXAST_ENCAP. */

struct ofpact_encap {
    struct ofpact ofpact;
    ovs_be32 new_pkt_type;        /* Packet type of the header to add. */
    uint16_t hdr_size;            /* New header size in bytes. */
    uint16_t n_props;             /* Number of encap properties. */
    struct ofpact_ed_prop props[]; /* Properties in internal format. */
};

/* OFPACT_DECAP.
 *
 * Used for NXAST_DECAP. */
struct ofpact_decap {
    struct ofpact ofpact;

    /* New packet type.
     *
     * The special value (0,0xFFFE) "Use next proto" is used to request OVS to
     * automatically set the new packet type based on the decap'ed header's
     * next protocol.
     */
    ovs_be32 new_pkt_type;
};

/* Converting OpenFlow to ofpacts. */
enum ofperr ofpacts_pull_openflow_actions(struct ofpbuf *openflow,
                                          unsigned int actions_len,
                                          enum ofp_version version,
                                          const struct vl_mff_map *,
                                          uint64_t *ofpacts_tlv_bitmap,
                                          struct ofpbuf *ofpacts);
enum ofperr
ofpacts_pull_openflow_instructions(struct ofpbuf *openflow,
                                   unsigned int instructions_len,
                                   enum ofp_version version,
                                   const struct vl_mff_map *vl_mff_map,
                                   uint64_t *ofpacts_tlv_bitmap,
                                   struct ofpbuf *ofpacts);
enum ofperr ofpacts_check(struct ofpact[], size_t ofpacts_len,
                          struct match *, ofp_port_t max_ports,
                          uint8_t table_id, uint8_t n_tables,
                          enum ofputil_protocol *usable_protocols);
enum ofperr ofpacts_check_consistency(struct ofpact[], size_t ofpacts_len,
                                      struct match *, ofp_port_t max_ports,
                                      uint8_t table_id, uint8_t n_tables,
                                      enum ofputil_protocol usable_protocols);
enum ofperr ofpact_check_output_port(ofp_port_t port, ofp_port_t max_ports);

/* Converting ofpacts to OpenFlow. */
size_t ofpacts_put_openflow_actions(const struct ofpact[], size_t ofpacts_len,
                                    struct ofpbuf *openflow, enum ofp_version);
void ofpacts_put_openflow_instructions(const struct ofpact[],
                                       size_t ofpacts_len,
                                       struct ofpbuf *openflow,
                                       enum ofp_version ofp_version);

/* Sets of supported actions. */
ovs_be32 ofpact_bitmap_to_openflow(uint64_t ofpacts_bitmap, enum ofp_version);
uint64_t ofpact_bitmap_from_openflow(ovs_be32 ofpat_bitmap, enum ofp_version);
void ofpact_bitmap_format(uint64_t ofpacts_bitmap, struct ds *);

/* Working with ofpacts. */
bool ofpacts_output_to_port(const struct ofpact[], size_t ofpacts_len,
                            ofp_port_t port);
bool ofpacts_output_to_group(const struct ofpact[], size_t ofpacts_len,
                             uint32_t group_id);
bool ofpacts_equal(const struct ofpact a[], size_t a_len,
                   const struct ofpact b[], size_t b_len);
bool ofpacts_equal_stringwise(const struct ofpact a[], size_t a_len,
                              const struct ofpact b[], size_t b_len);
const struct mf_field *ofpact_get_mf_dst(const struct ofpact *ofpact);
uint32_t ofpacts_get_meter(const struct ofpact[], size_t ofpacts_len);

/* Formatting and parsing ofpacts. */
void ofpacts_format(const struct ofpact[], size_t ofpacts_len,
                    const struct ofputil_port_map *, struct ds *);
char *ofpacts_parse_actions(const char *, const struct ofputil_port_map *,
                            struct ofpbuf *ofpacts,
                            enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;
char *ofpacts_parse_instructions(const char *, const struct ofputil_port_map *,
                                 struct ofpbuf *ofpacts,
                                 enum ofputil_protocol *usable_protocols)
    OVS_WARN_UNUSED_RESULT;
const char *ofpact_name(enum ofpact_type);

/* Internal use by the helpers below. */
void ofpact_init(struct ofpact *, enum ofpact_type, size_t len);
void *ofpact_put(struct ofpbuf *, enum ofpact_type, size_t len);
void *ofpact_finish(struct ofpbuf *, struct ofpact *);

/* For each OFPACT_<ENUM> with a corresponding struct <STRUCT>, this defines
 * the following commonly useful functions:
 *
 *   struct <STRUCT> *ofpact_put_<ENUM>(struct ofpbuf *ofpacts);
 *
 *     Appends a new 'ofpact', of length OFPACT_<ENUM>_SIZE, to 'ofpacts',
 *     initializes it with ofpact_init_<ENUM>(), and returns it.  Also sets
 *     'ofpacts->header' to the returned action.
 *
 *     After using this function to add a variable-length action, add the
 *     elements of the flexible array (e.g. with ofpbuf_put()), then use
 *     ofpact_finish() to pad the action to a multiple of OFPACT_ALIGNTO bytes
 *     and update its embedded length field.  (Keep in mind the need to refresh
 *     the structure from 'ofpacts->header' after adding data to 'ofpacts'.)
 *
 *   struct <STRUCT> *ofpact_get_<ENUM>(const struct ofpact *ofpact);
 *
 *     Returns 'ofpact' cast to "struct <STRUCT> *".  'ofpact->type' must be
 *     OFPACT_<ENUM>.
 *
 *   void ofpact_finish_<ENUM>(struct ofpbuf *ofpacts, struct <STRUCT> **ap);
 *
 *     Finishes composing variable-length action '*ap' (begun using
 *     ofpact_put_<NAME>() on 'ofpacts'), by padding the action to a multiple
 *     of OFPACT_ALIGNTO bytes and updating its embedded length field.
 *
 *     May reallocate 'ofpacts', and so as a convenience automatically updates
 *     '*ap' to point to the new location.  If the caller has other pointers
 *     within 'ap' or 'ofpacts', it needs to update them manually.
 *
 * as well as the following more rarely useful definitions:
 *
 *   void ofpact_init_<ENUM>(struct <STRUCT> *ofpact);
 *
 *     Initializes the parts of 'ofpact' that identify it as having type
 *     OFPACT_<ENUM> and length OFPACT_<ENUM>_SIZE and zeros the rest.
 *
 *   <ENUM>_SIZE
 *
 *     The size of the action structure.  For a fixed-length action, this is
 *     sizeof(struct <STRUCT>) rounded up to a multiple of OFPACT_ALIGNTO.  For
 *     a variable-length action, this is the offset to the variable-length
 *     part.
 */
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                              \
    BUILD_ASSERT_DECL(offsetof(struct STRUCT, ofpact) == 0);            \
                                                                        \
    enum { OFPACT_##ENUM##_SIZE                                         \
           = (offsetof(struct STRUCT, MEMBER) != 0                      \
              ? offsetof(struct STRUCT, MEMBER)                         \
              : OFPACT_ALIGN(sizeof(struct STRUCT))) };                 \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_get_##ENUM(const struct ofpact *ofpact)                      \
    {                                                                   \
        ovs_assert(ofpact->type == OFPACT_##ENUM);                      \
        return ALIGNED_CAST(struct STRUCT *, ofpact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_get_##ENUM##_nullable(const struct ofpact *ofpact)           \
    {                                                                   \
        ovs_assert(!ofpact || ofpact->type == OFPACT_##ENUM);           \
        return ALIGNED_CAST(struct STRUCT *, ofpact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_put_##ENUM(struct ofpbuf *ofpacts)                           \
    {                                                                   \
        return (struct STRUCT *) ofpact_put(ofpacts, OFPACT_##ENUM,     \
                                            OFPACT_##ENUM##_SIZE);      \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ofpact_init_##ENUM(struct STRUCT *ofpact)                           \
    {                                                                   \
        ofpact_init(&ofpact->ofpact, OFPACT_##ENUM,                     \
                    OFPACT_##ENUM##_SIZE);                              \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ofpact_finish_##ENUM(struct ofpbuf *ofpbuf, struct STRUCT **ofpactp) \
    {                                                                   \
        struct ofpact *ofpact = &(*ofpactp)->ofpact;                    \
        ovs_assert(ofpact->type == OFPACT_##ENUM);                      \
        *ofpactp = (struct STRUCT *) ofpact_finish(ofpbuf, ofpact);     \
    }
OFPACTS
#undef OFPACT

/* Additional functions for composing ofpacts. */
struct ofpact_set_field *ofpact_put_set_field(struct ofpbuf *ofpacts,
                                              const struct mf_field *,
                                              const void *value,
                                              const void *mask);
struct ofpact_set_field *ofpact_put_reg_load(struct ofpbuf *ofpacts,
                                             const struct mf_field *,
                                             const void *value,
                                             const void *mask);
struct ofpact_set_field *ofpact_put_reg_load2(struct ofpbuf *ofpacts,
                                              const struct mf_field *,
                                              const void *value,
                                              const void *mask);

/* OpenFlow 1.1 instructions.
 * The order is sorted in execution order. Not in the value of OFPIT11_xxx.
 * It is enforced on parser from text string.
 */
#define OVS_INSTRUCTIONS                                    \
    DEFINE_INST(OFPIT13_METER,                              \
                ofp13_instruction_meter,          false,    \
                "meter")                                    \
                                                            \
    DEFINE_INST(OFPIT11_APPLY_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "apply_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_CLEAR_ACTIONS,                      \
                ofp11_instruction,                false,    \
                "clear_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "write_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_METADATA,                     \
                ofp11_instruction_write_metadata, false,    \
                "write_metadata")                           \
                                                            \
    DEFINE_INST(OFPIT11_GOTO_TABLE,                         \
                ofp11_instruction_goto_table,     false,    \
                "goto_table")

enum ovs_instruction_type {
#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME) OVSINST_##ENUM,
    OVS_INSTRUCTIONS
#undef DEFINE_INST
};

enum {
#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME) + 1
    N_OVS_INSTRUCTIONS = OVS_INSTRUCTIONS
#undef DEFINE_INST
};

const char *ovs_instruction_name_from_type(enum ovs_instruction_type type);
int ovs_instruction_type_from_name(const char *name);
enum ovs_instruction_type ovs_instruction_type_from_ofpact_type(
    enum ofpact_type);
enum ofperr ovs_instruction_type_from_inst_type(
    enum ovs_instruction_type *instruction_type, const uint16_t inst_type);

ovs_be32 ovsinst_bitmap_to_openflow(uint32_t ovsinst_bitmap, enum ofp_version);
uint32_t ovsinst_bitmap_from_openflow(ovs_be32 ofpit_bitmap,
                                      enum ofp_version);

#ifdef __cplusplus
}
#endif

#endif /* ofp-actions.h */
