/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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

#ifndef OFP_ACTIONS_H
#define OFP_ACTIONS_H 1

#include <stddef.h>
#include <stdint.h>
#include "meta-flow.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

/* List of OVS abstracted actions.
 *
 * This macro is used directly only internally by this header, but the list is
 * still of interest to developers.
 *
 * Each DEFINE_OFPACT invocation has the following parameters:
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
 */
#define OFPACTS                                                     \
    /* Output. */                                                   \
    DEFINE_OFPACT(OUTPUT,          ofpact_output,        ofpact)    \
    DEFINE_OFPACT(GROUP,           ofpact_group,         ofpact)    \
    DEFINE_OFPACT(CONTROLLER,      ofpact_controller,    ofpact)    \
    DEFINE_OFPACT(ENQUEUE,         ofpact_enqueue,       ofpact)    \
    DEFINE_OFPACT(OUTPUT_REG,      ofpact_output_reg,    ofpact)    \
    DEFINE_OFPACT(BUNDLE,          ofpact_bundle,        slaves)    \
                                                                    \
    /* Header changes. */                                           \
    DEFINE_OFPACT(SET_FIELD,       ofpact_set_field,     ofpact)    \
    DEFINE_OFPACT(SET_VLAN_VID,    ofpact_vlan_vid,      ofpact)    \
    DEFINE_OFPACT(SET_VLAN_PCP,    ofpact_vlan_pcp,      ofpact)    \
    DEFINE_OFPACT(STRIP_VLAN,      ofpact_null,          ofpact)    \
    DEFINE_OFPACT(PUSH_VLAN,       ofpact_null,          ofpact)    \
    DEFINE_OFPACT(SET_ETH_SRC,     ofpact_mac,           ofpact)    \
    DEFINE_OFPACT(SET_ETH_DST,     ofpact_mac,           ofpact)    \
    DEFINE_OFPACT(SET_IPV4_SRC,    ofpact_ipv4,          ofpact)    \
    DEFINE_OFPACT(SET_IPV4_DST,    ofpact_ipv4,          ofpact)    \
    DEFINE_OFPACT(SET_IP_DSCP,     ofpact_dscp,          ofpact)    \
    DEFINE_OFPACT(SET_IP_ECN,      ofpact_ecn,           ofpact)    \
    DEFINE_OFPACT(SET_IP_TTL,      ofpact_ip_ttl,        ofpact)    \
    DEFINE_OFPACT(SET_L4_SRC_PORT, ofpact_l4_port,       ofpact)    \
    DEFINE_OFPACT(SET_L4_DST_PORT, ofpact_l4_port,       ofpact)    \
    DEFINE_OFPACT(REG_MOVE,        ofpact_reg_move,      ofpact)    \
    DEFINE_OFPACT(REG_LOAD,        ofpact_reg_load,      ofpact)    \
    DEFINE_OFPACT(STACK_PUSH,      ofpact_stack,         ofpact)    \
    DEFINE_OFPACT(STACK_POP,       ofpact_stack,         ofpact)    \
    DEFINE_OFPACT(DEC_TTL,         ofpact_cnt_ids,       cnt_ids)   \
    DEFINE_OFPACT(SET_MPLS_LABEL,  ofpact_mpls_label,    ofpact)    \
    DEFINE_OFPACT(SET_MPLS_TC,     ofpact_mpls_tc,       ofpact)    \
    DEFINE_OFPACT(SET_MPLS_TTL,    ofpact_mpls_ttl,      ofpact)    \
    DEFINE_OFPACT(DEC_MPLS_TTL,    ofpact_null,          ofpact)    \
    DEFINE_OFPACT(PUSH_MPLS,       ofpact_push_mpls,     ofpact)    \
    DEFINE_OFPACT(POP_MPLS,        ofpact_pop_mpls,      ofpact)    \
                                                                    \
    /* Metadata. */                                                 \
    DEFINE_OFPACT(SET_TUNNEL,      ofpact_tunnel,        ofpact)    \
    DEFINE_OFPACT(SET_QUEUE,       ofpact_queue,         ofpact)    \
    DEFINE_OFPACT(POP_QUEUE,       ofpact_null,          ofpact)    \
    DEFINE_OFPACT(FIN_TIMEOUT,     ofpact_fin_timeout,   ofpact)    \
                                                                    \
    /* Flow table interaction. */                                   \
    DEFINE_OFPACT(RESUBMIT,        ofpact_resubmit,      ofpact)    \
    DEFINE_OFPACT(LEARN,           ofpact_learn,         specs)     \
                                                                    \
    /* Arithmetic. */                                               \
    DEFINE_OFPACT(MULTIPATH,       ofpact_multipath,     ofpact)    \
                                                                    \
    /* Other. */                                                    \
    DEFINE_OFPACT(NOTE,            ofpact_note,          data)      \
    DEFINE_OFPACT(EXIT,            ofpact_null,          ofpact)    \
    DEFINE_OFPACT(SAMPLE,          ofpact_sample,        ofpact)    \
                                                                    \
    /* Instructions */                                              \
    DEFINE_OFPACT(METER,           ofpact_meter,         ofpact)    \
    DEFINE_OFPACT(CLEAR_ACTIONS,   ofpact_null,          ofpact)    \
    DEFINE_OFPACT(WRITE_ACTIONS,   ofpact_nest,          ofpact)    \
    DEFINE_OFPACT(WRITE_METADATA,  ofpact_metadata,      ofpact)    \
    DEFINE_OFPACT(GOTO_TABLE,      ofpact_goto_table,    ofpact)

/* enum ofpact_type, with a member OFPACT_<ENUM> for each action. */
enum OVS_PACKED_ENUM ofpact_type {
#define DEFINE_OFPACT(ENUM, STRUCT, MEMBER) OFPACT_##ENUM,
    OFPACTS
#undef DEFINE_OFPACT
};

/* N_OFPACTS, the number of values of "enum ofpact_type". */
enum {
    N_OFPACTS =
#define DEFINE_OFPACT(ENUM, STRUCT, MEMBER) + 1
    OFPACTS
#undef DEFINE_OFPACT
};

/* Header for an action.
 *
 * Each action is a structure "struct ofpact_*" that begins with "struct
 * ofpact", usually followed by other data that describes the action.  Actions
 * are padded out to a multiple of OFPACT_ALIGNTO bytes in length.
 *
 * The 'compat' member is special:
 *
 *     - Most "struct ofpact"s correspond to one particular kind of OpenFlow
 *       action, at least in a given OpenFlow version.  For example,
 *       OFPACT_SET_VLAN_VID corresponds to OFPAT10_SET_VLAN_VID in OpenFlow
 *       1.0.
 *
 *       For such actions, the 'compat' member is not meaningful and generally
 *       should be zero.
 *
 *     - A few "struct ofpact"s correspond to multiple OpenFlow actions.  For
 *       example, OFPACT_SET_TUNNEL can be NXAST_SET_TUNNEL or
 *       NXAST_SET_TUNNEL64.  In these cases, if the "struct ofpact" originated
 *       from OpenFlow, then we want to make sure that, if it gets translated
 *       back to OpenFlow later, it is translated back to the same action type.
 *       (Otherwise, we'd violate the promise made in DESIGN, in the "Action
 *       Reproduction" section.)
 *
 *       For such actions, the 'compat' member should be the original action
 *       type.  (If the action didn't originate from OpenFlow, then setting
 *       'compat' to zero should be fine: code to translate the ofpact to
 *       OpenFlow must tolerate this case.)
 */
struct ofpact {
    enum ofpact_type type;      /* OFPACT_*. */
    enum ofputil_action_code compat; /* Original type when added, if any. */
    uint16_t len;               /* Length of the action, in bytes, including
                                 * struct ofpact, excluding padding. */
};

#ifdef __GNUC__
/* Make sure that OVS_PACKED_ENUM really worked. */
BUILD_ASSERT_DECL(sizeof(struct ofpact) == 4);
#endif

/* Alignment. */
#define OFPACT_ALIGNTO 8
#define OFPACT_ALIGN(SIZE) ROUND_UP(SIZE, OFPACT_ALIGNTO)

static inline struct ofpact *
ofpact_next(const struct ofpact *ofpact)
{
    return (void *) ((uint8_t *) ofpact + OFPACT_ALIGN(ofpact->len));
}

static inline struct ofpact *
ofpact_end(const struct ofpact *ofpacts, size_t ofpacts_len)
{
    return (void *) ((uint8_t *) ofpacts + ofpacts_len);
}

/* Assigns POS to each ofpact, in turn, in the OFPACTS_LEN bytes of ofpacts
 * starting at OFPACTS. */
#define OFPACT_FOR_EACH(POS, OFPACTS, OFPACTS_LEN)                      \
    for ((POS) = (OFPACTS); (POS) < ofpact_end(OFPACTS, OFPACTS_LEN);  \
         (POS) = ofpact_next(POS))

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
    struct ofpact ofpact;
    uint16_t max_len;           /* Maximum length to send to controller. */
    uint16_t controller_id;     /* Controller ID to send packet-in. */
    enum ofp_packet_in_reason reason; /* Reason to put in packet-in. */
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
    struct mf_subfield src;
    uint16_t max_len;
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

/* OFPACT_SET_ETH_SRC, OFPACT_SET_ETH_DST.
 *
 * Used for OFPAT10_SET_DL_SRC, OFPAT10_SET_DL_DST. */
struct ofpact_mac {
    struct ofpact ofpact;
    uint8_t mac[ETH_ADDR_LEN];
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

/* OFPACT_STACK_PUSH.
 *
 * Used for NXAST_STACK_PUSH and NXAST_STACK_POP. */
struct ofpact_stack {
    struct ofpact ofpact;
    struct mf_subfield subfield;
};

/* OFPACT_REG_LOAD.
 *
 * Used for NXAST_REG_LOAD. */
struct ofpact_reg_load {
    struct ofpact ofpact;
    struct mf_subfield dst;
    union mf_subvalue subvalue; /* Least-significant bits are used. */
};

/* The position in the packet at which to insert an MPLS header.
 *
 * Used NXAST_PUSH_MPLS, OFPAT11_PUSH_MPLS. */
enum ofpact_mpls_position {
    /* Add the MPLS LSE after the Ethernet header but before any VLAN tags.
     * OpenFlow 1.3+ requires this behavior. */
   OFPACT_MPLS_BEFORE_VLAN,

   /* Add the MPLS LSE after the Ethernet header and any VLAN tags.
    * OpenFlow 1.1 and 1.2 require this behavior. */
   OFPACT_MPLS_AFTER_VLAN
};

/* OFPACT_SET_FIELD.
 *
 * Used for OFPAT12_SET_FIELD. */
struct ofpact_set_field {
    struct ofpact ofpact;
    const struct mf_field *field;
    bool flow_has_vlan;   /* VLAN present at action validation time. */
    union mf_value value;
};

/* OFPACT_PUSH_VLAN/MPLS/PBB
 *
 * Used for NXAST_PUSH_MPLS, OFPAT11_PUSH_MPLS. */
struct ofpact_push_mpls {
    struct ofpact ofpact;
    ovs_be16 ethertype;
    enum ofpact_mpls_position position;
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
};

/* OFPACT_WRITE_ACTIONS.
 *
 * Used for OFPIT11_WRITE_ACTIONS. */
struct ofpact_nest {
    struct ofpact ofpact;
    uint8_t pad[OFPACT_ALIGN(sizeof(struct ofpact)) - sizeof(struct ofpact)];
    struct ofpact actions[];
};
BUILD_ASSERT_DECL(offsetof(struct ofpact_nest, actions) == OFPACT_ALIGNTO);

static inline size_t
ofpact_nest_get_action_len(const struct ofpact_nest *on)
{
    return on->ofpact.len - offsetof(struct ofpact_nest, actions);
}

void ofpacts_execute_action_set(struct ofpbuf *action_list,
                                const struct ofpbuf *action_set);

/* OFPACT_RESUBMIT.
 *
 * Used for NXAST_RESUBMIT, NXAST_RESUBMIT_TABLE. */
struct ofpact_resubmit {
    struct ofpact ofpact;
    ofp_port_t in_port;
    uint8_t table_id;
};

/* Part of struct ofpact_learn, below. */
struct ofpact_learn_spec {
    int n_bits;                 /* Number of bits in source and dest. */

    int src_type;               /* One of NX_LEARN_SRC_*. */
    struct mf_subfield src;     /* NX_LEARN_SRC_FIELD only. */
    union mf_subvalue src_imm;  /* NX_LEARN_SRC_IMMEDIATE only. */

    int dst_type;             /* One of NX_LEARN_DST_*. */
    struct mf_subfield dst;   /* NX_LEARN_DST_MATCH, NX_LEARN_DST_LOAD only. */
};

/* OFPACT_LEARN.
 *
 * Used for NXAST_LEARN. */
struct ofpact_learn {
    struct ofpact ofpact;

    uint16_t idle_timeout;      /* Idle time before discarding (seconds). */
    uint16_t hard_timeout;      /* Max time before discarding (seconds). */
    uint16_t priority;          /* Priority level of flow entry. */
    uint8_t table_id;           /* Table to insert flow entry. */
    uint64_t cookie;            /* Cookie for new flow. */
    enum ofputil_flow_mod_flags flags;
    uint16_t fin_idle_timeout;  /* Idle timeout after FIN, if nonzero. */
    uint16_t fin_hard_timeout;  /* Hard timeout after FIN, if nonzero. */

    unsigned int n_specs;
    struct ofpact_learn_spec specs[];
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

/* OFPACT_SAMPLE.
 *
 * Used for NXAST_SAMPLE. */
struct ofpact_sample {
    struct ofpact ofpact;
    uint16_t probability;  // Always >0.
    uint32_t collector_set_id;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
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

/* Converting OpenFlow to ofpacts. */
enum ofperr ofpacts_pull_openflow_actions(struct ofpbuf *openflow,
                                          unsigned int actions_len,
                                          enum ofp_version version,
                                          struct ofpbuf *ofpacts);
enum ofperr ofpacts_pull_openflow_instructions(struct ofpbuf *openflow,
                                               unsigned int instructions_len,
                                               enum ofp_version version,
                                               struct ofpbuf *ofpacts);
enum ofperr ofpacts_check(struct ofpact[], size_t ofpacts_len,
                          struct flow *, ofp_port_t max_ports,
                          uint8_t table_id, uint8_t n_tables,
                          enum ofputil_protocol *usable_protocols);
enum ofperr ofpacts_check_consistency(struct ofpact[], size_t ofpacts_len,
                                      struct flow *, ofp_port_t max_ports,
                                      uint8_t table_id, uint8_t n_tables,
                                      enum ofputil_protocol usable_protocols);
enum ofperr ofpacts_verify(const struct ofpact ofpacts[], size_t ofpacts_len);
enum ofperr ofpact_check_output_port(ofp_port_t port, ofp_port_t max_ports);

/* Converting ofpacts to OpenFlow. */
size_t ofpacts_put_openflow_actions(const struct ofpact[], size_t ofpacts_len,
                                    struct ofpbuf *openflow, enum ofp_version);
void ofpacts_put_openflow_instructions(const struct ofpact[],
                                       size_t ofpacts_len,
                                       struct ofpbuf *openflow,
                                       enum ofp_version ofp_version);

/* Working with ofpacts. */
bool ofpacts_output_to_port(const struct ofpact[], size_t ofpacts_len,
                            ofp_port_t port);
bool ofpacts_output_to_group(const struct ofpact[], size_t ofpacts_len,
                             uint32_t group_id);
bool ofpacts_equal(const struct ofpact a[], size_t a_len,
                   const struct ofpact b[], size_t b_len);
uint32_t ofpacts_get_meter(const struct ofpact[], size_t ofpacts_len);

/* Formatting ofpacts.
 *
 * (For parsing ofpacts, see ofp-parse.h.) */
void ofpacts_format(const struct ofpact[], size_t ofpacts_len, struct ds *);

/* Internal use by the helpers below. */
void ofpact_init(struct ofpact *, enum ofpact_type, size_t len);
void *ofpact_put(struct ofpbuf *, enum ofpact_type, size_t len);

/* For each OFPACT_<ENUM> with a corresponding struct <STRUCT>, this defines
 * the following commonly useful functions:
 *
 *   struct <STRUCT> *ofpact_put_<ENUM>(struct ofpbuf *ofpacts);
 *
 *     Appends a new 'ofpact', of length OFPACT_<ENUM>_RAW_SIZE, to 'ofpacts',
 *     initializes it with ofpact_init_<ENUM>(), and returns it.  Also sets
 *     'ofpacts->l2' to the returned action.
 *
 *     After using this function to add a variable-length action, add the
 *     elements of the flexible array (e.g. with ofpbuf_put()), then use
 *     ofpact_update_len() to update the length embedded into the action.
 *     (Keep in mind the need to refresh the structure from 'ofpacts->l2' after
 *     adding data to 'ofpacts'.)
 *
 *   struct <STRUCT> *ofpact_get_<ENUM>(const struct ofpact *ofpact);
 *
 *     Returns 'ofpact' cast to "struct <STRUCT> *".  'ofpact->type' must be
 *     OFPACT_<ENUM>.
 *
 * as well as the following more rarely useful definitions:
 *
 *   void ofpact_init_<ENUM>(struct <STRUCT> *ofpact);
 *
 *     Initializes the parts of 'ofpact' that identify it as having type
 *     OFPACT_<ENUM> and length OFPACT_<ENUM>_RAW_SIZE and zeros the rest.
 *
 *   <ENUM>_RAW_SIZE
 *
 *     The size of the action structure.  For a fixed-length action, this is
 *     sizeof(struct <STRUCT>).  For a variable-length action, this is the
 *     offset to the variable-length part.
 *
 *   <ENUM>_SIZE
 *
 *     An integer constant, the value of OFPACT_<ENUM>_RAW_SIZE rounded up to a
 *     multiple of OFPACT_ALIGNTO.
 */
#define DEFINE_OFPACT(ENUM, STRUCT, MEMBER)                             \
    BUILD_ASSERT_DECL(offsetof(struct STRUCT, ofpact) == 0);            \
                                                                        \
    enum { OFPACT_##ENUM##_RAW_SIZE                                     \
           = (offsetof(struct STRUCT, MEMBER)                           \
              ? offsetof(struct STRUCT, MEMBER)                         \
              : sizeof(struct STRUCT)) };                               \
                                                                        \
    enum { OFPACT_##ENUM##_SIZE                                         \
           = ROUND_UP(OFPACT_##ENUM##_RAW_SIZE, OFPACT_ALIGNTO) };      \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_get_##ENUM(const struct ofpact *ofpact)                      \
    {                                                                   \
        ovs_assert(ofpact->type == OFPACT_##ENUM);                      \
        return ALIGNED_CAST(struct STRUCT *, ofpact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ofpact_put_##ENUM(struct ofpbuf *ofpacts)                           \
    {                                                                   \
        return ofpact_put(ofpacts, OFPACT_##ENUM,                       \
                          OFPACT_##ENUM##_RAW_SIZE);                    \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ofpact_init_##ENUM(struct STRUCT *ofpact)                           \
    {                                                                   \
        ofpact_init(&ofpact->ofpact, OFPACT_##ENUM,                     \
                    OFPACT_##ENUM##_RAW_SIZE);                          \
    }
OFPACTS
#undef DEFINE_OFPACT

/* Functions to use after adding ofpacts to a buffer. */
void ofpact_update_len(struct ofpbuf *, struct ofpact *);
void ofpact_pad(struct ofpbuf *);

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
#endif /* ofp-actions.h */
