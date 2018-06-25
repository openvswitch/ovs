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

#include <config.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "bundle.h"
#include "byte-order.h"
#include "colors.h"
#include "compiler.h"
#include "dummy.h"
#include "openvswitch/hmap.h"
#include "learn.h"
#include "multipath.h"
#include "nx-match.h"
#include "odp-netlink.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofp-table.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "unaligned.h"
#include "util.h"
#include "vl-mff-map.h"

VLOG_DEFINE_THIS_MODULE(ofp_actions);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

struct ofp_action_header;

/* Header for Open vSwitch and ONF vendor extension actions.
 *
 * This is the entire header for a few Open vSwitch vendor extension actions,
 * the ones that either have no arguments or for which variable-length
 * arguments follow the header.
 *
 * This cannot be used as an entirely generic vendor extension action header,
 * because OpenFlow does not specify the location or size of the action
 * subtype; it just happens that ONF extensions and Nicira extensions share
 * this format. */
struct ext_action_header {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* At least 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID or ONF_VENDOR_ID. */
    ovs_be16 subtype;               /* See enum ofp_raw_action_type. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ext_action_header) == 16);

/* Raw identifiers for OpenFlow actions.
 *
 * Decoding and encoding OpenFlow actions across multiple versions is difficult
 * to do in a clean, consistent way.  This enumeration lays out all of the
 * forms of actions that Open vSwitch supports.
 *
 * The comments here must follow a stylized form because the
 * "extract-ofp-actions" program parses them at build time to generate data
 * tables.
 *
 *   - The first part of each comment specifies the vendor, OpenFlow versions,
 *     and type for each protocol that supports the action:
 *
 *         # The vendor is OF for standard OpenFlow actions, NX for Nicira
 *           extension actions.  (Support for other vendors can be added, but
 *           it can't be done just based on a vendor ID definition alone
 *           because OpenFlow doesn't define a standard way to specify a
 *           subtype for vendor actions, so other vendors might do it different
 *           from Nicira.)
 *
 *         # The version can specify a specific OpenFlow version, a version
 *           range delimited by "-", or an open-ended range with "+".
 *
 *         # The type, in parentheses, is the action type number (for standard
 *           OpenFlow actions) or subtype (for vendor extension actions).
 *
 *         # Optionally one may add "is deprecated" followed by a
 *           human-readable reason in parentheses (which will be used in log
 *           messages), if a particular action should no longer be used.
 *
 *     Multiple such specifications may be separated by commas.
 *
 *   - The second part describes the action's wire format.  It may be:
 *
 *         # "struct <name>": The struct fully specifies the wire format.  The
 *           action is exactly the size of the struct.  (Thus, the struct must
 *           be an exact multiple of 8 bytes in size.)
 *
 *         # "struct <name>, ...": The struct specifies the beginning of the
 *           wire format.  An instance of the action is either the struct's
 *           exact size, or a multiple of 8 bytes longer.
 *
 *         # "uint<N>_t" or "ovs_be<N>": The action consists of a (standard or
 *           vendor extension) header, followed by 0 or more pad bytes to align
 *           to a multiple of <N> bits, followed by an argument of the given
 *           type, followed by 0 or more pad bytes to bring the total action up
 *           to a multiple of 8 bytes.
 *
 *         # "void": The action is just a (standard or vendor extension)
 *           header.
 *
 *         # Optionally, one may add "VLMFF" in the end of the second part if
 *           the Openflow action may use a variable length meta-flow field
 *           (i.e. tun_metadata). Adding "VLMFF" will pass the per-switch based
 *           variable length meta-flow field mapping map (struct vl_mff_map) to
 *           the corresponding action decoding function.
 *
 *   - Optional additional text enclosed in square brackets is commentary for
 *     the human reader.
 */
enum ofp_raw_action_type {
/* ## ----------------- ## */
/* ## Standard actions. ## */
/* ## ----------------- ## */

    /* OF1.0(0): struct ofp10_action_output. */
    OFPAT_RAW10_OUTPUT,
    /* OF1.1+(0): struct ofp11_action_output. */
    OFPAT_RAW11_OUTPUT,

    /* OF1.0(1): uint16_t. */
    OFPAT_RAW10_SET_VLAN_VID,
    /* OF1.0(2): uint8_t. */
    OFPAT_RAW10_SET_VLAN_PCP,

    /* OF1.1(1), OF1.2+(1) is deprecated (use Set-Field): uint16_t.
     *
     * [Semantics differ slightly between the 1.0 and 1.1 versions of the VLAN
     * modification actions: the 1.0 versions push a VLAN header if none is
     * present, but the 1.1 versions do not.  That is the only reason that we
     * distinguish their raw action types.] */
    OFPAT_RAW11_SET_VLAN_VID,
    /* OF1.1(2), OF1.2+(2) is deprecated (use Set-Field): uint8_t. */
    OFPAT_RAW11_SET_VLAN_PCP,

    /* OF1.1+(17): ovs_be16.
     *
     * [The argument is the Ethertype, e.g. ETH_TYPE_VLAN_8021Q, not the VID or
     * TCI.] */
    OFPAT_RAW11_PUSH_VLAN,

    /* OF1.0(3): void. */
    OFPAT_RAW10_STRIP_VLAN,
    /* OF1.1+(18): void. */
    OFPAT_RAW11_POP_VLAN,

    /* OF1.0(4), OF1.1(3), OF1.2+(3) is deprecated (use Set-Field): struct
     * ofp_action_dl_addr. */
    OFPAT_RAW_SET_DL_SRC,

    /* OF1.0(5), OF1.1(4), OF1.2+(4) is deprecated (use Set-Field): struct
     * ofp_action_dl_addr. */
    OFPAT_RAW_SET_DL_DST,

    /* OF1.0(6), OF1.1(5), OF1.2+(5) is deprecated (use Set-Field):
     * ovs_be32. */
    OFPAT_RAW_SET_NW_SRC,

    /* OF1.0(7), OF1.1(6), OF1.2+(6) is deprecated (use Set-Field):
     * ovs_be32. */
    OFPAT_RAW_SET_NW_DST,

    /* OF1.0(8), OF1.1(7), OF1.2+(7) is deprecated (use Set-Field): uint8_t. */
    OFPAT_RAW_SET_NW_TOS,

    /* OF1.1(8), OF1.2+(8) is deprecated (use Set-Field): uint8_t. */
    OFPAT_RAW11_SET_NW_ECN,

    /* OF1.0(9), OF1.1(9), OF1.2+(9) is deprecated (use Set-Field):
     * ovs_be16. */
    OFPAT_RAW_SET_TP_SRC,

    /* OF1.0(10), OF1.1(10), OF1.2+(10) is deprecated (use Set-Field):
     * ovs_be16. */
    OFPAT_RAW_SET_TP_DST,

    /* OF1.0(11): struct ofp10_action_enqueue. */
    OFPAT_RAW10_ENQUEUE,

    /* NX1.0(30), OF1.1(13), OF1.2+(13) is deprecated (use Set-Field):
     * ovs_be32. */
    OFPAT_RAW_SET_MPLS_LABEL,

    /* NX1.0(31), OF1.1(14), OF1.2+(14) is deprecated (use Set-Field):
     * uint8_t. */
    OFPAT_RAW_SET_MPLS_TC,

    /* NX1.0(25), OF1.1(15), OF1.2+(15) is deprecated (use Set-Field):
     * uint8_t. */
    OFPAT_RAW_SET_MPLS_TTL,

    /* NX1.0(26), OF1.1+(16): void. */
    OFPAT_RAW_DEC_MPLS_TTL,

    /* NX1.0(23), OF1.1+(19): ovs_be16.
     *
     * [The argument is the Ethertype, e.g. ETH_TYPE_MPLS, not the label.] */
    OFPAT_RAW_PUSH_MPLS,

    /* NX1.0(24), OF1.1+(20): ovs_be16.
     *
     * [The argument is the Ethertype, e.g. ETH_TYPE_IPV4 if at BoS or
     * ETH_TYPE_MPLS otherwise, not the label.] */
    OFPAT_RAW_POP_MPLS,

    /* NX1.0(4), OF1.1+(21): uint32_t. */
    OFPAT_RAW_SET_QUEUE,

    /* NX1.0(40), OF1.1+(22): uint32_t. */
    OFPAT_RAW_GROUP,

    /* OF1.1+(23): uint8_t. */
    OFPAT_RAW11_SET_NW_TTL,

    /* NX1.0(18), OF1.1+(24): void. */
    OFPAT_RAW_DEC_NW_TTL,
    /* NX1.0+(21): struct nx_action_cnt_ids, ... */
    NXAST_RAW_DEC_TTL_CNT_IDS,

    /* OF1.2-1.4(25): struct ofp12_action_set_field, ... VLMFF */
    OFPAT_RAW12_SET_FIELD,
    /* OF1.5+(25): struct ofp12_action_set_field, ... VLMFF */
    OFPAT_RAW15_SET_FIELD,
    /* NX1.0-1.4(7): struct nx_action_reg_load. VLMFF
     *
     * [In OpenFlow 1.5, set_field is a superset of reg_load functionality, so
     * we drop reg_load.] */
    NXAST_RAW_REG_LOAD,
    /* NX1.0-1.4(33): struct ext_action_header, ... VLMFF
     *
     * [In OpenFlow 1.5, set_field is a superset of reg_load2 functionality, so
     * we drop reg_load2.] */
    NXAST_RAW_REG_LOAD2,

    /* OF1.5+(28): struct ofp15_action_copy_field, ... VLMFF */
    OFPAT_RAW15_COPY_FIELD,
    /* ONF1.3-1.4(3200): struct onf_action_copy_field, ... VLMFF */
    ONFACT_RAW13_COPY_FIELD,
    /* NX1.0-1.4(6): struct nx_action_reg_move, ... VLMFF */
    NXAST_RAW_REG_MOVE,

/* ## ------------------------- ## */
/* ## Nicira extension actions. ## */
/* ## ------------------------- ## */

/* Actions similar to standard actions are listed with the standard actions. */

    /* NX1.0+(1): uint16_t. */
    NXAST_RAW_RESUBMIT,
    /* NX1.0+(14): struct nx_action_resubmit. */
    NXAST_RAW_RESUBMIT_TABLE,
    /* NX1.0+(44): struct nx_action_resubmit. */
    NXAST_RAW_RESUBMIT_TABLE_CT,

    /* NX1.0+(2): uint32_t. */
    NXAST_RAW_SET_TUNNEL,
    /* NX1.0+(9): uint64_t. */
    NXAST_RAW_SET_TUNNEL64,

    /* NX1.0+(5): void. */
    NXAST_RAW_POP_QUEUE,

    /* NX1.0+(8): struct nx_action_note, ... */
    NXAST_RAW_NOTE,

    /* NX1.0+(10): struct nx_action_multipath. VLMFF */
    NXAST_RAW_MULTIPATH,

    /* NX1.0+(12): struct nx_action_bundle, ... */
    NXAST_RAW_BUNDLE,
    /* NX1.0+(13): struct nx_action_bundle, ... VLMFF */
    NXAST_RAW_BUNDLE_LOAD,

    /* NX1.0+(15): struct nx_action_output_reg. VLMFF */
    NXAST_RAW_OUTPUT_REG,
    /* NX1.0+(32): struct nx_action_output_reg2. VLMFF */
    NXAST_RAW_OUTPUT_REG2,

    /* NX1.0+(16): struct nx_action_learn, ... VLMFF */
    NXAST_RAW_LEARN,
    /* NX1.0+(45): struct nx_action_learn2, ... VLMFF */
    NXAST_RAW_LEARN2,

    /* NX1.0+(17): void. */
    NXAST_RAW_EXIT,

    /* NX1.0+(19): struct nx_action_fin_timeout. */
    NXAST_RAW_FIN_TIMEOUT,

    /* NX1.0+(20): struct nx_action_controller. */
    NXAST_RAW_CONTROLLER,
    /* NX1.0+(37): struct ext_action_header, ... */
    NXAST_RAW_CONTROLLER2,

    /* NX1.0+(22): struct nx_action_write_metadata. */
    NXAST_RAW_WRITE_METADATA,

    /* NX1.0+(27): struct nx_action_stack. VLMFF */
    NXAST_RAW_STACK_PUSH,

    /* NX1.0+(28): struct nx_action_stack. VLMFF */
    NXAST_RAW_STACK_POP,

    /* NX1.0+(29): struct nx_action_sample. */
    NXAST_RAW_SAMPLE,
    /* NX1.0+(38): struct nx_action_sample2. */
    NXAST_RAW_SAMPLE2,
    /* NX1.0+(41): struct nx_action_sample2. */
    NXAST_RAW_SAMPLE3,

    /* NX1.0+(34): struct nx_action_conjunction. */
    NXAST_RAW_CONJUNCTION,

    /* NX1.0+(35): struct nx_action_conntrack, ... VLMFF */
    NXAST_RAW_CT,

    /* NX1.0+(36): struct nx_action_nat, ... */
    NXAST_RAW_NAT,

    /* NX1.0+(39): struct nx_action_output_trunc. */
    NXAST_RAW_OUTPUT_TRUNC,

    /* NX1.0+(42): struct ext_action_header, ... VLMFF */
    NXAST_RAW_CLONE,

    /* NX1.0+(43): void. */
    NXAST_RAW_CT_CLEAR,

    /* NX1.3+(46): struct nx_action_encap, ... */
    NXAST_RAW_ENCAP,

    /* NX1.3+(47): struct nx_action_decap, ... */
    NXAST_RAW_DECAP,

    /* NX1.3+(48): void. */
    NXAST_RAW_DEC_NSH_TTL,

/* ## ------------------ ## */
/* ## Debugging actions. ## */
/* ## ------------------ ## */

/* These are intentionally undocumented, subject to change, and ovs-vswitchd */
/* accepts them only if started with --enable-dummy. */

    /* NX1.0+(254): void. */
    NXAST_RAW_DEBUG_SLOW,

    /* NX1.0+(255): void. */
    NXAST_RAW_DEBUG_RECIRC,
};

/* OpenFlow actions are always a multiple of 8 bytes in length. */
#define OFP_ACTION_ALIGN 8

/* Define a few functions for working with instructions. */
#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME)             \
    static inline const struct STRUCT * OVS_UNUSED              \
    instruction_get_##ENUM(const struct ofp11_instruction *inst)\
    {                                                           \
        ovs_assert(inst->type == htons(ENUM));                  \
        return ALIGNED_CAST(struct STRUCT *, inst);             \
    }                                                           \
                                                                \
    static inline void OVS_UNUSED                               \
    instruction_init_##ENUM(struct STRUCT *s)                   \
    {                                                           \
        memset(s, 0, sizeof *s);                                \
        s->type = htons(ENUM);                                  \
        s->len = htons(sizeof *s);                              \
    }                                                           \
                                                                \
    static inline struct STRUCT * OVS_UNUSED                    \
    instruction_put_##ENUM(struct ofpbuf *buf)                  \
    {                                                           \
        struct STRUCT *s = ofpbuf_put_uninit(buf, sizeof *s);   \
        instruction_init_##ENUM(s);                             \
        return s;                                               \
    }
OVS_INSTRUCTIONS
#undef DEFINE_INST

static void ofpacts_update_instruction_actions(struct ofpbuf *openflow,
                                               size_t ofs);
static void pad_ofpat(struct ofpbuf *openflow, size_t start_ofs);

static enum ofperr ofpacts_verify(const struct ofpact[], size_t ofpacts_len,
                                  uint32_t allowed_ovsinsts,
                                  enum ofpact_type outer_action);

static void put_set_field(struct ofpbuf *openflow, enum ofp_version,
                          enum mf_field_id, uint64_t value);

static void put_reg_load(struct ofpbuf *openflow,
                         const struct mf_subfield *, uint64_t value);

static enum ofperr ofpact_pull_raw(struct ofpbuf *, enum ofp_version,
                                   enum ofp_raw_action_type *, uint64_t *arg);
static void *ofpact_put_raw(struct ofpbuf *, enum ofp_version,
                            enum ofp_raw_action_type, uint64_t arg);

static char *OVS_WARN_UNUSED_RESULT ofpacts_parse(
    char *str, const struct ofpact_parse_params *pp,
    bool allow_instructions, enum ofpact_type outer_action);
static enum ofperr ofpacts_pull_openflow_actions__(
    struct ofpbuf *openflow, unsigned int actions_len,
    enum ofp_version version, uint32_t allowed_ovsinsts,
    struct ofpbuf *ofpacts, enum ofpact_type outer_action,
    const struct vl_mff_map *vl_mff_map, uint64_t *ofpacts_tlv_bitmap);
static char * OVS_WARN_UNUSED_RESULT ofpacts_parse_copy(
    const char *s_, const struct ofpact_parse_params *pp,
    bool allow_instructions, enum ofpact_type outer_action);

/* Returns the ofpact following 'ofpact', except that if 'ofpact' contains
 * nested ofpacts it returns the first one. */
struct ofpact *
ofpact_next_flattened(const struct ofpact *ofpact)
{
    switch (ofpact->type) {
    case OFPACT_OUTPUT:
    case OFPACT_GROUP:
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_OUTPUT_TRUNC:
    case OFPACT_BUNDLE:
    case OFPACT_SET_FIELD:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_PUSH_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_STACK_PUSH:
    case OFPACT_STACK_POP:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_CONJUNCTION:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SAMPLE:
    case OFPACT_UNROLL_XLATE:
    case OFPACT_CT_CLEAR:
    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
    case OFPACT_METER:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_METADATA:
    case OFPACT_GOTO_TABLE:
    case OFPACT_NAT:
    case OFPACT_ENCAP:
    case OFPACT_DECAP:
    case OFPACT_DEC_NSH_TTL:
        return ofpact_next(ofpact);

    case OFPACT_CLONE:
        return ofpact_get_CLONE(ofpact)->actions;

    case OFPACT_CT:
        return ofpact_get_CT(ofpact)->actions;

    case OFPACT_WRITE_ACTIONS:
        return ofpact_get_WRITE_ACTIONS(ofpact)->actions;
    }

    OVS_NOT_REACHED();
}

/* Pull off existing actions or instructions. Used by nesting actions to keep
 * ofpacts_parse() oblivious of actions nesting.
 *
 * Push the actions back on after nested parsing, e.g.:
 *
 *     size_t ofs = ofpacts_pull(ofpacts);
 *     ...nested parsing...
 *     ofpbuf_push_uninit(ofpacts, ofs);
 */
static size_t
ofpacts_pull(struct ofpbuf *ofpacts)
{
    size_t ofs;

    ofs = ofpacts->size;
    ofpbuf_pull(ofpacts, ofs);

    return ofs;
}

#include "ofp-actions.inc1"

/* Output actions. */

/* Action structure for OFPAT10_OUTPUT, which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
 * number of bytes to send.  A 'max_len' of zero means no bytes of the
 * packet should be sent. */
struct ofp10_action_output {
    ovs_be16 type;                  /* OFPAT10_OUTPUT. */
    ovs_be16 len;                   /* Length is 8. */
    ovs_be16 port;                  /* Output port. */
    ovs_be16 max_len;               /* Max length to send to controller. */
};
OFP_ASSERT(sizeof(struct ofp10_action_output) == 8);

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
   * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
   * number of bytes to send. A 'max_len' of zero means no bytes of the
   * packet should be sent.*/
struct ofp11_action_output {
    ovs_be16 type;                    /* OFPAT11_OUTPUT. */
    ovs_be16 len;                     /* Length is 16. */
    ovs_be32 port;                    /* Output port. */
    ovs_be16 max_len;                 /* Max length to send to controller. */
    uint8_t pad[6];                   /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp11_action_output) == 16);

static enum ofperr
decode_OFPAT_RAW10_OUTPUT(const struct ofp10_action_output *oao,
                          enum ofp_version ofp_version OVS_UNUSED,
                          struct ofpbuf *out)
{
    struct ofpact_output *output;

    output = ofpact_put_OUTPUT(out);
    output->port = u16_to_ofp(ntohs(oao->port));
    output->max_len = ntohs(oao->max_len);

    return ofpact_check_output_port(output->port, OFPP_MAX);
}

static enum ofperr
decode_OFPAT_RAW11_OUTPUT(const struct ofp11_action_output *oao,
                          enum ofp_version ofp_version OVS_UNUSED,
                          struct ofpbuf *out)
{
    struct ofpact_output *output;
    enum ofperr error;

    output = ofpact_put_OUTPUT(out);
    output->max_len = ntohs(oao->max_len);

    error = ofputil_port_from_ofp11(oao->port, &output->port);
    if (error) {
        return error;
    }

    return ofpact_check_output_port(output->port, OFPP_MAX);
}

static void
encode_OUTPUT(const struct ofpact_output *output,
              enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        struct ofp10_action_output *oao;

        oao = put_OFPAT10_OUTPUT(out);
        oao->port = htons(ofp_to_u16(output->port));
        oao->max_len = htons(output->max_len);
    } else {
        struct ofp11_action_output *oao;

        oao = put_OFPAT11_OUTPUT(out);
        oao->port = ofputil_port_to_ofp11(output->port);
        oao->max_len = htons(output->max_len);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_truncate_subfield(const char *arg_,
                        const struct ofpact_parse_params *pp,
                        struct ofpact_output_trunc *output_trunc)
{
    char *key, *value;
    char *arg = CONST_CAST(char *, arg_);

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        if (!strcmp(key, "port")) {
            if (!ofputil_port_from_string(value, pp->port_map,
                                          &output_trunc->port)) {
                return xasprintf("output to unknown truncate port: %s",
                                  value);
            }
            if (ofp_to_u16(output_trunc->port) > ofp_to_u16(OFPP_MAX)) {
                if (output_trunc->port != OFPP_LOCAL &&
                    output_trunc->port != OFPP_IN_PORT)
                return xasprintf("output to unsupported truncate port: %s",
                                 value);
            }
        } else if (!strcmp(key, "max_len")) {
            char *err;

            err = str_to_u32(value, &output_trunc->max_len);
            if (err) {
                return err;
            }
        } else {
            return xasprintf("invalid key '%s' in output_trunc argument",
                                key);
        }
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_OUTPUT(const char *arg, const struct ofpact_parse_params *pp)
{
    if (strstr(arg, "port") && strstr(arg, "max_len")) {
        struct ofpact_output_trunc *output_trunc;

        output_trunc = ofpact_put_OUTPUT_TRUNC(pp->ofpacts);
        return parse_truncate_subfield(arg, pp, output_trunc);
    }

    ofp_port_t port;
    if (ofputil_port_from_string(arg, pp->port_map, &port)) {
        struct ofpact_output *output = ofpact_put_OUTPUT(pp->ofpacts);
        output->port = port;
        output->max_len = output->port == OFPP_CONTROLLER ? UINT16_MAX : 0;
        return NULL;
    }

    struct mf_subfield src;
    char *error = mf_parse_subfield(&src, arg);
    if (!error) {
        struct ofpact_output_reg *output_reg;

        output_reg = ofpact_put_OUTPUT_REG(pp->ofpacts);
        output_reg->max_len = UINT16_MAX;
        output_reg->src = src;
        return NULL;
    }
    free(error);

    return xasprintf("%s: output to unknown port", arg);
}

static void
format_OUTPUT(const struct ofpact_output *a,
              const struct ofpact_format_params *fp)
{
    if (ofp_to_u16(a->port) < ofp_to_u16(OFPP_MAX)) {
        ds_put_format(fp->s, "%soutput:%s", colors.special, colors.end);
    }
    ofputil_format_port(a->port, fp->port_map, fp->s);
    if (a->port == OFPP_CONTROLLER) {
        ds_put_format(fp->s, ":%"PRIu16, a->max_len);
    }
}

/* Group actions. */

static enum ofperr
decode_OFPAT_RAW_GROUP(uint32_t group_id,
                         enum ofp_version ofp_version OVS_UNUSED,
                         struct ofpbuf *out)
{
    ofpact_put_GROUP(out)->group_id = group_id;
    return 0;
}

static void
encode_GROUP(const struct ofpact_group *group,
             enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_GROUP(out, ofp_version, group->group_id);
}

static char * OVS_WARN_UNUSED_RESULT
parse_GROUP(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_u32(arg, &ofpact_put_GROUP(pp->ofpacts)->group_id);
}

static void
format_GROUP(const struct ofpact_group *a,
             const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sgroup:%s%"PRIu32,
                  colors.special, colors.end, a->group_id);
}

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

/* Properties for NXAST_CONTROLLER2.
 *
 * For more information on the effect of NXAC2PT_PAUSE, see the large comment
 * on NXT_PACKET_IN2 in nicira-ext.h */
enum nx_action_controller2_prop_type {
    NXAC2PT_MAX_LEN,            /* ovs_be16 max bytes to send (default all). */
    NXAC2PT_CONTROLLER_ID,      /* ovs_be16 dest controller ID (default 0). */
    NXAC2PT_REASON,             /* uint8_t reason (OFPR_*), default 0. */
    NXAC2PT_USERDATA,           /* Data to copy into NXPINT_USERDATA. */
    NXAC2PT_PAUSE,              /* Flag to pause pipeline to resume later. */
};

/* The action structure for NXAST_CONTROLLER2 is "struct ext_action_header",
 * followed by NXAC2PT_* properties. */

static enum ofperr
decode_NXAST_RAW_CONTROLLER(const struct nx_action_controller *nac,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    struct ofpact_controller *oc;

    oc = ofpact_put_CONTROLLER(out);
    oc->ofpact.raw = NXAST_RAW_CONTROLLER;
    oc->max_len = ntohs(nac->max_len);
    oc->controller_id = ntohs(nac->controller_id);
    oc->reason = nac->reason;
    ofpact_finish_CONTROLLER(out, &oc);

    return 0;
}

static enum ofperr
decode_NXAST_RAW_CONTROLLER2(const struct ext_action_header *eah,
                             enum ofp_version ofp_version OVS_UNUSED,
                             struct ofpbuf *out)
{
    if (!is_all_zeros(eah->pad, sizeof eah->pad)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    size_t start_ofs = out->size;
    struct ofpact_controller *oc = ofpact_put_CONTROLLER(out);
    oc->ofpact.raw = NXAST_RAW_CONTROLLER2;
    oc->max_len = UINT16_MAX;
    oc->reason = OFPR_ACTION;

    struct ofpbuf properties;
    ofpbuf_use_const(&properties, eah, ntohs(eah->len));
    ofpbuf_pull(&properties, sizeof *eah);

    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        enum ofperr error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case NXAC2PT_MAX_LEN:
            error = ofpprop_parse_u16(&payload, &oc->max_len);
            break;

        case NXAC2PT_CONTROLLER_ID:
            error = ofpprop_parse_u16(&payload, &oc->controller_id);
            break;

        case NXAC2PT_REASON: {
            uint8_t u8;
            error = ofpprop_parse_u8(&payload, &u8);
            oc->reason = u8;
            break;
        }

        case NXAC2PT_USERDATA:
            out->size = start_ofs + OFPACT_CONTROLLER_SIZE;
            ofpbuf_put(out, payload.msg, ofpbuf_msgsize(&payload));
            oc = ofpbuf_at_assert(out, start_ofs, sizeof *oc);
            oc->userdata_len = ofpbuf_msgsize(&payload);
            break;

        case NXAC2PT_PAUSE:
            oc->pause = true;
            break;

        default:
            error = OFPPROP_UNKNOWN(false, "NXAST_RAW_CONTROLLER2", type);
            break;
        }
        if (error) {
            return error;
        }
    }

    ofpact_finish_CONTROLLER(out, &oc);

    return 0;
}

static void
encode_CONTROLLER(const struct ofpact_controller *controller,
                  enum ofp_version ofp_version OVS_UNUSED,
                  struct ofpbuf *out)
{
    if (controller->userdata_len
        || controller->pause
        || controller->ofpact.raw == NXAST_RAW_CONTROLLER2) {
        size_t start_ofs = out->size;
        put_NXAST_CONTROLLER2(out);
        if (controller->max_len != UINT16_MAX) {
            ofpprop_put_u16(out, NXAC2PT_MAX_LEN, controller->max_len);
        }
        if (controller->controller_id != 0) {
            ofpprop_put_u16(out, NXAC2PT_CONTROLLER_ID,
                            controller->controller_id);
        }
        if (controller->reason != OFPR_ACTION) {
            ofpprop_put_u8(out, NXAC2PT_REASON, controller->reason);
        }
        if (controller->userdata_len != 0) {
            ofpprop_put(out, NXAC2PT_USERDATA, controller->userdata,
                        controller->userdata_len);
        }
        if (controller->pause) {
            ofpprop_put_flag(out, NXAC2PT_PAUSE);
        }
        pad_ofpat(out, start_ofs);
    } else {
        struct nx_action_controller *nac;

        nac = put_NXAST_CONTROLLER(out);
        nac->max_len = htons(controller->max_len);
        nac->controller_id = htons(controller->controller_id);
        nac->reason = controller->reason;
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_CONTROLLER(char *arg, const struct ofpact_parse_params *pp)
{
    enum ofp_packet_in_reason reason = OFPR_ACTION;
    uint16_t controller_id = 0;
    uint16_t max_len = UINT16_MAX;
    const char *userdata = NULL;
    bool pause = false;

    if (!arg[0]) {
        /* Use defaults. */
    } else if (strspn(arg, "0123456789") == strlen(arg)) {
        char *error = str_to_u16(arg, "max_len", &max_len);
        if (error) {
            return error;
        }
    } else {
        char *name, *value;

        while (ofputil_parse_key_value(&arg, &name, &value)) {
            if (!strcmp(name, "reason")) {
                if (!ofputil_packet_in_reason_from_string(value, &reason)) {
                    return xasprintf("unknown reason \"%s\"", value);
                }
            } else if (!strcmp(name, "max_len")) {
                char *error = str_to_u16(value, "max_len", &max_len);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "id")) {
                char *error = str_to_u16(value, "id", &controller_id);
                if (error) {
                    return error;
                }
            } else if (!strcmp(name, "userdata")) {
                userdata = value;
            } else if (!strcmp(name, "pause")) {
                pause = true;
            } else {
                return xasprintf("unknown key \"%s\" parsing controller "
                                 "action", name);
            }
        }
    }

    if (reason == OFPR_ACTION && controller_id == 0 && !userdata && !pause) {
        struct ofpact_output *output;

        output = ofpact_put_OUTPUT(pp->ofpacts);
        output->port = OFPP_CONTROLLER;
        output->max_len = max_len;
    } else {
        struct ofpact_controller *controller;

        controller = ofpact_put_CONTROLLER(pp->ofpacts);
        controller->max_len = max_len;
        controller->reason = reason;
        controller->controller_id = controller_id;
        controller->pause = pause;

        if (userdata) {
            size_t start_ofs = pp->ofpacts->size;
            const char *end = ofpbuf_put_hex(pp->ofpacts, userdata, NULL);
            if (*end) {
                return xstrdup("bad hex digit in `controller' "
                               "action `userdata'");
            }
            size_t userdata_len = pp->ofpacts->size - start_ofs;
            controller = pp->ofpacts->header;
            controller->userdata_len = userdata_len;
        }
        ofpact_finish_CONTROLLER(pp->ofpacts, &controller);
    }

    return NULL;
}

static void
format_hex_arg(struct ds *s, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (i) {
            ds_put_char(s, '.');
        }
        ds_put_format(s, "%02"PRIx8, data[i]);
    }
}

static void
format_CONTROLLER(const struct ofpact_controller *a,
                  const struct ofpact_format_params *fp)
{
    if (a->reason == OFPR_ACTION && !a->controller_id && !a->userdata_len
        && !a->pause) {
        ds_put_format(fp->s, "%sCONTROLLER:%s%"PRIu16,
                      colors.special, colors.end, a->max_len);
    } else {
        enum ofp_packet_in_reason reason = a->reason;

        ds_put_format(fp->s, "%scontroller(%s", colors.paren, colors.end);
        if (reason != OFPR_ACTION) {
            char reasonbuf[OFPUTIL_PACKET_IN_REASON_BUFSIZE];

            ds_put_format(fp->s, "%sreason=%s%s,", colors.param, colors.end,
                          ofputil_packet_in_reason_to_string(
                              reason, reasonbuf, sizeof reasonbuf));
        }
        if (a->max_len != UINT16_MAX) {
            ds_put_format(fp->s, "%smax_len=%s%"PRIu16",",
                          colors.param, colors.end, a->max_len);
        }
        if (a->controller_id != 0) {
            ds_put_format(fp->s, "%sid=%s%"PRIu16",",
                          colors.param, colors.end, a->controller_id);
        }
        if (a->userdata_len) {
            ds_put_format(fp->s, "%suserdata=%s", colors.param, colors.end);
            format_hex_arg(fp->s, a->userdata, a->userdata_len);
            ds_put_char(fp->s, ',');
        }
        if (a->pause) {
            ds_put_format(fp->s, "%spause%s,", colors.value, colors.end);
        }
        ds_chomp(fp->s, ',');
        ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
    }
}

/* Enqueue action. */
struct ofp10_action_enqueue {
    ovs_be16 type;            /* OFPAT10_ENQUEUE. */
    ovs_be16 len;             /* Len is 16. */
    ovs_be16 port;            /* Port that queue belongs. Should
                                 refer to a valid physical port
                                 (i.e. < OFPP_MAX) or OFPP_IN_PORT. */
    uint8_t pad[6];           /* Pad for 64-bit alignment. */
    ovs_be32 queue_id;        /* Where to enqueue the packets. */
};
OFP_ASSERT(sizeof(struct ofp10_action_enqueue) == 16);

static enum ofperr
decode_OFPAT_RAW10_ENQUEUE(const struct ofp10_action_enqueue *oae,
                           enum ofp_version ofp_version OVS_UNUSED,
                           struct ofpbuf *out)
{
    struct ofpact_enqueue *enqueue;

    enqueue = ofpact_put_ENQUEUE(out);
    enqueue->port = u16_to_ofp(ntohs(oae->port));
    enqueue->queue = ntohl(oae->queue_id);
    if (ofp_to_u16(enqueue->port) >= ofp_to_u16(OFPP_MAX)
        && enqueue->port != OFPP_IN_PORT
        && enqueue->port != OFPP_LOCAL) {
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
    return 0;
}

static void
encode_ENQUEUE(const struct ofpact_enqueue *enqueue,
               enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        struct ofp10_action_enqueue *oae;

        oae = put_OFPAT10_ENQUEUE(out);
        oae->port = htons(ofp_to_u16(enqueue->port));
        oae->queue_id = htonl(enqueue->queue);
    } else {
        put_OFPAT_SET_QUEUE(out, ofp_version, enqueue->queue);

        struct ofp11_action_output *oao = put_OFPAT11_OUTPUT(out);
        oao->port = ofputil_port_to_ofp11(enqueue->port);
        oao->max_len = OVS_BE16_MAX;

        put_NXAST_POP_QUEUE(out);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_ENQUEUE(char *arg, const struct ofpact_parse_params *pp)
{
    char *sp = NULL;
    char *port = strtok_r(arg, ":q,", &sp);
    char *queue = strtok_r(NULL, "", &sp);
    struct ofpact_enqueue *enqueue;

    if (port == NULL || queue == NULL) {
        return xstrdup("\"enqueue\" syntax is \"enqueue:PORT:QUEUE\" or "
                       "\"enqueue(PORT,QUEUE)\"");
    }

    enqueue = ofpact_put_ENQUEUE(pp->ofpacts);
    if (!ofputil_port_from_string(port, pp->port_map, &enqueue->port)) {
        return xasprintf("%s: enqueue to unknown port", port);
    }
    return str_to_u32(queue, &enqueue->queue);
}

static void
format_ENQUEUE(const struct ofpact_enqueue *a,
               const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%senqueue:%s", colors.param, colors.end);
    ofputil_format_port(a->port, fp->port_map, fp->s);
    ds_put_format(fp->s, ":%"PRIu32, a->queue);
}

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

/* Action structure for NXAST_OUTPUT_REG2.
 *
 * Like the NXAST_OUTPUT_REG but organized so that there is room for a 64-bit
 * experimenter OXM as 'src'.
 */
struct nx_action_output_reg2 {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* 24. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_OUTPUT_REG2. */

    ovs_be16 ofs_nbits;         /* (ofs << 6) | (n_bits - 1). */
    ovs_be16 max_len;           /* Max length to send to controller. */

    /* Followed by:
     * - 'src', as an OXM/NXM header (either 4 or 8 bytes).
     * - Enough 0-bytes to pad the action out to 24 bytes. */
    uint8_t pad[10];
};
OFP_ASSERT(sizeof(struct nx_action_output_reg2) == 24);

static enum ofperr
decode_NXAST_RAW_OUTPUT_REG(const struct nx_action_output_reg *naor,
                            enum ofp_version ofp_version OVS_UNUSED,
                            const struct vl_mff_map *vl_mff_map,
                            uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    struct ofpact_output_reg *output_reg;
    enum ofperr error;

    if (!is_all_zeros(naor->zero, sizeof naor->zero)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    output_reg = ofpact_put_OUTPUT_REG(out);
    output_reg->ofpact.raw = NXAST_RAW_OUTPUT_REG;
    output_reg->src.ofs = nxm_decode_ofs(naor->ofs_nbits);
    output_reg->src.n_bits = nxm_decode_n_bits(naor->ofs_nbits);
    output_reg->max_len = ntohs(naor->max_len);
    error = mf_vl_mff_mf_from_nxm_header(ntohl(naor->src), vl_mff_map,
                                         &output_reg->src.field, tlv_bitmap);
    if (error) {
        return error;
    }

    return mf_check_src(&output_reg->src, NULL);
}

static enum ofperr
decode_NXAST_RAW_OUTPUT_REG2(const struct nx_action_output_reg2 *naor,
                             enum ofp_version ofp_version OVS_UNUSED,
                             const struct vl_mff_map *vl_mff_map,
                             uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    struct ofpact_output_reg *output_reg;
    enum ofperr error;

    output_reg = ofpact_put_OUTPUT_REG(out);
    output_reg->ofpact.raw = NXAST_RAW_OUTPUT_REG2;
    output_reg->src.ofs = nxm_decode_ofs(naor->ofs_nbits);
    output_reg->src.n_bits = nxm_decode_n_bits(naor->ofs_nbits);
    output_reg->max_len = ntohs(naor->max_len);

    struct ofpbuf b = ofpbuf_const_initializer(naor, ntohs(naor->len));
    ofpbuf_pull(&b, OBJECT_OFFSETOF(naor, pad));

    error = mf_vl_mff_nx_pull_header(&b, vl_mff_map, &output_reg->src.field,
                                     NULL, tlv_bitmap);
    if (error) {
        return error;
    }

    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    return mf_check_src(&output_reg->src, NULL);
}

static void
encode_OUTPUT_REG(const struct ofpact_output_reg *output_reg,
                  enum ofp_version ofp_version OVS_UNUSED,
                  struct ofpbuf *out)
{
    /* If 'output_reg' came in as an NXAST_RAW_OUTPUT_REG2 action, or if it
     * cannot be encoded in the older form, encode it as
     * NXAST_RAW_OUTPUT_REG2. */
    if (output_reg->ofpact.raw == NXAST_RAW_OUTPUT_REG2
        || !mf_nxm_header(output_reg->src.field->id)) {
        struct nx_action_output_reg2 *naor = put_NXAST_OUTPUT_REG2(out);
        size_t size = out->size;

        naor->ofs_nbits = nxm_encode_ofs_nbits(output_reg->src.ofs,
                                               output_reg->src.n_bits);
        naor->max_len = htons(output_reg->max_len);

        out->size = size - sizeof naor->pad;
        nx_put_mff_header(out, output_reg->src.field, 0, false);
        out->size = size;
    } else {
        struct nx_action_output_reg *naor = put_NXAST_OUTPUT_REG(out);

        naor->ofs_nbits = nxm_encode_ofs_nbits(output_reg->src.ofs,
                                               output_reg->src.n_bits);
        naor->src = htonl(nxm_header_from_mff(output_reg->src.field));
        naor->max_len = htons(output_reg->max_len);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_OUTPUT_REG(const char *arg, const struct ofpact_parse_params *pp)
{
    return parse_OUTPUT(arg, pp);
}

static void
format_OUTPUT_REG(const struct ofpact_output_reg *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%soutput:%s", colors.special, colors.end);
    mf_format_subfield(&a->src, fp->s);
}

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
 * considered live, that is, NXAST_BUNDLE_LOAD stores OFPP_NONE in the output
 * register if no slave is live.
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

static enum ofperr
decode_bundle(bool load, const struct nx_action_bundle *nab,
              const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap,
              struct ofpbuf *ofpacts)
{
    static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
    struct ofpact_bundle *bundle;
    uint32_t slave_type;
    size_t slaves_size, i;
    enum ofperr error;

    bundle = ofpact_put_BUNDLE(ofpacts);

    bundle->n_slaves = ntohs(nab->n_slaves);
    bundle->basis = ntohs(nab->basis);
    bundle->fields = ntohs(nab->fields);
    bundle->algorithm = ntohs(nab->algorithm);
    slave_type = ntohl(nab->slave_type);
    slaves_size = ntohs(nab->len) - sizeof *nab;

    error = OFPERR_OFPBAC_BAD_ARGUMENT;
    if (!flow_hash_fields_valid(bundle->fields)) {
        VLOG_WARN_RL(&rll, "unsupported fields %d", (int) bundle->fields);
    } else if (bundle->n_slaves > BUNDLE_MAX_SLAVES) {
        VLOG_WARN_RL(&rll, "too many slaves");
    } else if (bundle->algorithm != NX_BD_ALG_HRW
               && bundle->algorithm != NX_BD_ALG_ACTIVE_BACKUP) {
        VLOG_WARN_RL(&rll, "unsupported algorithm %d", (int) bundle->algorithm);
    } else if (slave_type != mf_nxm_header(MFF_IN_PORT)) {
        VLOG_WARN_RL(&rll, "unsupported slave type %"PRIu32, slave_type);
    } else {
        error = 0;
    }

    if (!is_all_zeros(nab->zero, sizeof nab->zero)) {
        VLOG_WARN_RL(&rll, "reserved field is nonzero");
        error = OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    if (load) {
        bundle->dst.ofs = nxm_decode_ofs(nab->ofs_nbits);
        bundle->dst.n_bits = nxm_decode_n_bits(nab->ofs_nbits);
        error = mf_vl_mff_mf_from_nxm_header(ntohl(nab->dst), vl_mff_map,
                                             &bundle->dst.field, tlv_bitmap);
        if (error) {
            return error;
        }

        if (bundle->dst.n_bits < 16) {
            VLOG_WARN_RL(&rll, "bundle_load action requires at least 16 bit "
                         "destination.");
            error = OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    } else {
        if (nab->ofs_nbits || nab->dst) {
            VLOG_WARN_RL(&rll, "bundle action has nonzero reserved fields");
            error = OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    }

    if (slaves_size < bundle->n_slaves * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rll, "Nicira action %s only has %"PRIuSIZE" bytes "
                     "allocated for slaves.  %"PRIuSIZE" bytes are required "
                     "for %u slaves.",
                     load ? "bundle_load" : "bundle", slaves_size,
                     bundle->n_slaves * sizeof(ovs_be16), bundle->n_slaves);
        error = OFPERR_OFPBAC_BAD_LEN;
    } else {
        for (i = 0; i < bundle->n_slaves; i++) {
            ofp_port_t ofp_port
                = u16_to_ofp(ntohs(((ovs_be16 *)(nab + 1))[i]));
            ofpbuf_put(ofpacts, &ofp_port, sizeof ofp_port);
            bundle = ofpacts->header;
        }
    }

    ofpact_finish_BUNDLE(ofpacts, &bundle);
    if (!error) {
        error = bundle_check(bundle, OFPP_MAX, NULL);
    }
    return error;
}

static enum ofperr
decode_NXAST_RAW_BUNDLE(const struct nx_action_bundle *nab,
                        enum ofp_version ofp_version OVS_UNUSED,
                        struct ofpbuf *out)
{
    return decode_bundle(false, nab, NULL, NULL, out);
}

static enum ofperr
decode_NXAST_RAW_BUNDLE_LOAD(const struct nx_action_bundle *nab,
                             enum ofp_version ofp_version OVS_UNUSED,
                             const struct vl_mff_map *vl_mff_map,
                             uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    return decode_bundle(true, nab, vl_mff_map, tlv_bitmap, out);
}

static void
encode_BUNDLE(const struct ofpact_bundle *bundle,
              enum ofp_version ofp_version OVS_UNUSED,
              struct ofpbuf *out)
{
    int slaves_len = ROUND_UP(2 * bundle->n_slaves, OFP_ACTION_ALIGN);
    struct nx_action_bundle *nab;
    ovs_be16 *slaves;
    size_t i;

    nab = (bundle->dst.field
           ? put_NXAST_BUNDLE_LOAD(out)
           : put_NXAST_BUNDLE(out));
    nab->len = htons(ntohs(nab->len) + slaves_len);
    nab->algorithm = htons(bundle->algorithm);
    nab->fields = htons(bundle->fields);
    nab->basis = htons(bundle->basis);
    nab->slave_type = htonl(mf_nxm_header(MFF_IN_PORT));
    nab->n_slaves = htons(bundle->n_slaves);
    if (bundle->dst.field) {
        nab->ofs_nbits = nxm_encode_ofs_nbits(bundle->dst.ofs,
                                              bundle->dst.n_bits);
        nab->dst = htonl(nxm_header_from_mff(bundle->dst.field));
    }

    slaves = ofpbuf_put_zeros(out, slaves_len);
    for (i = 0; i < bundle->n_slaves; i++) {
        slaves[i] = htons(ofp_to_u16(bundle->slaves[i]));
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_BUNDLE(const char *arg, const struct ofpact_parse_params *pp)
{
    return bundle_parse(arg, pp->port_map, pp->ofpacts);
}

static char * OVS_WARN_UNUSED_RESULT
parse_bundle_load(const char *arg, const struct ofpact_parse_params *pp)
{
    return bundle_parse_load(arg, pp->port_map, pp->ofpacts);
}

static void
format_BUNDLE(const struct ofpact_bundle *a,
              const struct ofpact_format_params *fp)
{
    bundle_format(a, fp->port_map, fp->s);
}

/* Set VLAN actions. */

static enum ofperr
decode_set_vlan_vid(uint16_t vid, bool push_vlan_if_needed, struct ofpbuf *out)
{
    if (vid & ~0xfff) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else {
        struct ofpact_vlan_vid *vlan_vid = ofpact_put_SET_VLAN_VID(out);
        vlan_vid->vlan_vid = vid;
        vlan_vid->push_vlan_if_needed = push_vlan_if_needed;
        return 0;
    }
}

static enum ofperr
decode_OFPAT_RAW10_SET_VLAN_VID(uint16_t vid,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    return decode_set_vlan_vid(vid, true, out);
}

static enum ofperr
decode_OFPAT_RAW11_SET_VLAN_VID(uint16_t vid,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    return decode_set_vlan_vid(vid, false, out);
}

static void
encode_SET_VLAN_VID(const struct ofpact_vlan_vid *vlan_vid,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    uint16_t vid = vlan_vid->vlan_vid;

    /* Push a VLAN tag, if none is present and this form of the action calls
     * for such a feature. */
    if (ofp_version > OFP10_VERSION
        && vlan_vid->push_vlan_if_needed
        && !vlan_vid->flow_has_vlan) {
        put_OFPAT11_PUSH_VLAN(out, htons(ETH_TYPE_VLAN_8021Q));
    }

    if (ofp_version == OFP10_VERSION) {
        put_OFPAT10_SET_VLAN_VID(out, vid);
    } else if (ofp_version == OFP11_VERSION) {
        put_OFPAT11_SET_VLAN_VID(out, vid);
    } else {
        put_set_field(out, ofp_version, MFF_VLAN_VID, vid | OFPVID12_PRESENT);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_set_vlan_vid(char *arg, bool push_vlan_if_needed,
                   const struct ofpact_parse_params *pp)
{
    struct ofpact_vlan_vid *vlan_vid;
    uint16_t vid;
    char *error;

    error = str_to_u16(arg, "VLAN VID", &vid);
    if (error) {
        return error;
    }

    if (vid & ~VLAN_VID_MASK) {
        return xasprintf("%s: not a valid VLAN VID", arg);
    }
    vlan_vid = ofpact_put_SET_VLAN_VID(pp->ofpacts);
    vlan_vid->vlan_vid = vid;
    vlan_vid->push_vlan_if_needed = push_vlan_if_needed;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_VLAN_VID(char *arg, const struct ofpact_parse_params *pp)
{
    return parse_set_vlan_vid(arg, false, pp);
}

static void
format_SET_VLAN_VID(const struct ofpact_vlan_vid *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%s%s:%s%"PRIu16, colors.param,
                  a->push_vlan_if_needed ? "mod_vlan_vid" : "set_vlan_vid",
                  colors.end, a->vlan_vid);
}

/* Set PCP actions. */

static enum ofperr
decode_set_vlan_pcp(uint8_t pcp, bool push_vlan_if_needed, struct ofpbuf *out)
{
    if (pcp & ~7) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else {
        struct ofpact_vlan_pcp *vlan_pcp = ofpact_put_SET_VLAN_PCP(out);
        vlan_pcp->vlan_pcp = pcp;
        vlan_pcp->push_vlan_if_needed = push_vlan_if_needed;
        return 0;
    }
}

static enum ofperr
decode_OFPAT_RAW10_SET_VLAN_PCP(uint8_t pcp,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    return decode_set_vlan_pcp(pcp, true, out);
}

static enum ofperr
decode_OFPAT_RAW11_SET_VLAN_PCP(uint8_t pcp,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    return decode_set_vlan_pcp(pcp, false, out);
}

static void
encode_SET_VLAN_PCP(const struct ofpact_vlan_pcp *vlan_pcp,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    uint8_t pcp = vlan_pcp->vlan_pcp;

    /* Push a VLAN tag, if none is present and this form of the action calls
     * for such a feature. */
    if (ofp_version > OFP10_VERSION
        && vlan_pcp->push_vlan_if_needed
        && !vlan_pcp->flow_has_vlan) {
        put_OFPAT11_PUSH_VLAN(out, htons(ETH_TYPE_VLAN_8021Q));
    }

    if (ofp_version == OFP10_VERSION) {
        put_OFPAT10_SET_VLAN_PCP(out, pcp);
    } else if (ofp_version == OFP11_VERSION) {
        put_OFPAT11_SET_VLAN_PCP(out, pcp);
    } else {
        put_set_field(out, ofp_version, MFF_VLAN_PCP, pcp);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_set_vlan_pcp(char *arg, bool push_vlan_if_needed,
                   const struct ofpact_parse_params *pp)
{
    struct ofpact_vlan_pcp *vlan_pcp;
    uint8_t pcp;
    char *error;

    error = str_to_u8(arg, "VLAN PCP", &pcp);
    if (error) {
        return error;
    }

    if (pcp & ~7) {
        return xasprintf("%s: not a valid VLAN PCP", arg);
    }
    vlan_pcp = ofpact_put_SET_VLAN_PCP(pp->ofpacts);
    vlan_pcp->vlan_pcp = pcp;
    vlan_pcp->push_vlan_if_needed = push_vlan_if_needed;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_VLAN_PCP(char *arg, const struct ofpact_parse_params *pp)
{
    return parse_set_vlan_pcp(arg, false, pp);
}

static void
format_SET_VLAN_PCP(const struct ofpact_vlan_pcp *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%s%s:%s%"PRIu8, colors.param,
                  a->push_vlan_if_needed ? "mod_vlan_pcp" : "set_vlan_pcp",
                  colors.end, a->vlan_pcp);
}

/* Strip VLAN actions. */

static enum ofperr
decode_OFPAT_RAW10_STRIP_VLAN(struct ofpbuf *out)
{
    ofpact_put_STRIP_VLAN(out)->ofpact.raw = OFPAT_RAW10_STRIP_VLAN;
    return 0;
}

static enum ofperr
decode_OFPAT_RAW11_POP_VLAN(struct ofpbuf *out)
{
    ofpact_put_STRIP_VLAN(out)->ofpact.raw = OFPAT_RAW11_POP_VLAN;
    return 0;
}

static void
encode_STRIP_VLAN(const struct ofpact_null *null OVS_UNUSED,
                  enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        put_OFPAT10_STRIP_VLAN(out);
    } else {
        put_OFPAT11_POP_VLAN(out);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_STRIP_VLAN(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_STRIP_VLAN(pp->ofpacts)->ofpact.raw = OFPAT_RAW10_STRIP_VLAN;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_pop_vlan(const struct ofpact_parse_params *pp)
{
    ofpact_put_STRIP_VLAN(pp->ofpacts)->ofpact.raw = OFPAT_RAW11_POP_VLAN;
    return NULL;
}

static void
format_STRIP_VLAN(const struct ofpact_null *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, (a->ofpact.raw == OFPAT_RAW11_POP_VLAN
                    ? "%spop_vlan%s"
                    : "%sstrip_vlan%s"),
                  colors.value, colors.end);
}

/* Push VLAN action. */

static enum ofperr
decode_OFPAT_RAW11_PUSH_VLAN(ovs_be16 eth_type,
                             enum ofp_version ofp_version OVS_UNUSED,
                             struct ofpbuf *out)
{
    struct ofpact_push_vlan *push_vlan;
    if (!eth_type_vlan(eth_type)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    push_vlan = ofpact_put_PUSH_VLAN(out);
    push_vlan->ethertype = eth_type;
    return 0;
}

static void
encode_PUSH_VLAN(const struct ofpact_push_vlan *push_vlan,
                 enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        /* PUSH is a side effect of a SET_VLAN_VID/PCP, which should
         * follow this action. */
    } else {
        put_OFPAT11_PUSH_VLAN(out, push_vlan->ethertype);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_PUSH_VLAN(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_push_vlan *push_vlan;
    uint16_t ethertype;
    char *error;

    *pp->usable_protocols &= OFPUTIL_P_OF11_UP;
    error = str_to_u16(arg, "ethertype", &ethertype);
    if (error) {
        return error;
    }

    if (!eth_type_vlan(htons(ethertype))) {
        return xasprintf("%s: not a valid VLAN ethertype", arg);
    }
    push_vlan = ofpact_put_PUSH_VLAN(pp->ofpacts);
    push_vlan->ethertype = htons(ethertype);
    return NULL;
}

static void
format_PUSH_VLAN(const struct ofpact_push_vlan *push_vlan,
                 const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%spush_vlan:%s%#"PRIx16,
                  colors.param, colors.end, ntohs(push_vlan->ethertype));
}

/* Action structure for OFPAT10_SET_DL_SRC/DST and OFPAT11_SET_DL_SRC/DST. */
struct ofp_action_dl_addr {
    ovs_be16 type;                  /* Type. */
    ovs_be16 len;                   /* Length is 16. */
    struct eth_addr dl_addr;        /* Ethernet address. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct ofp_action_dl_addr) == 16);

static enum ofperr
decode_OFPAT_RAW_SET_DL_SRC(const struct ofp_action_dl_addr *a,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_ETH_SRC(out)->mac = a->dl_addr;
    return 0;
}

static enum ofperr
decode_OFPAT_RAW_SET_DL_DST(const struct ofp_action_dl_addr *a,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_ETH_DST(out)->mac = a->dl_addr;
    return 0;
}

static void
encode_SET_ETH_addr(const struct ofpact_mac *mac, enum ofp_version ofp_version,
                    enum ofp_raw_action_type raw, enum mf_field_id field,
                    struct ofpbuf *out)
{
    if (ofp_version < OFP12_VERSION) {
        struct ofp_action_dl_addr *oada;

        oada = ofpact_put_raw(out, ofp_version, raw, 0);
        oada->dl_addr = mac->mac;
    } else {
        put_set_field(out, ofp_version, field, eth_addr_to_uint64(mac->mac));
    }
}

static void
encode_SET_ETH_SRC(const struct ofpact_mac *mac, enum ofp_version ofp_version,
                   struct ofpbuf *out)
{
    encode_SET_ETH_addr(mac, ofp_version, OFPAT_RAW_SET_DL_SRC, MFF_ETH_SRC,
                        out);

}

static void
encode_SET_ETH_DST(const struct ofpact_mac *mac,
                               enum ofp_version ofp_version,
                               struct ofpbuf *out)
{
    encode_SET_ETH_addr(mac, ofp_version, OFPAT_RAW_SET_DL_DST, MFF_ETH_DST,
                        out);

}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_ETH_SRC(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_mac(arg, &ofpact_put_SET_ETH_SRC(pp->ofpacts)->mac);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_ETH_DST(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_mac(arg, &ofpact_put_SET_ETH_DST(pp->ofpacts)->mac);
}

static void
format_SET_ETH_SRC(const struct ofpact_mac *a,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_dl_src:%s"ETH_ADDR_FMT,
                  colors.param, colors.end, ETH_ADDR_ARGS(a->mac));
}

static void
format_SET_ETH_DST(const struct ofpact_mac *a,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_dl_dst:%s"ETH_ADDR_FMT,
                  colors.param, colors.end, ETH_ADDR_ARGS(a->mac));
}

/* Set IPv4 address actions. */

static enum ofperr
decode_OFPAT_RAW_SET_NW_SRC(ovs_be32 ipv4,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_IPV4_SRC(out)->ipv4 = ipv4;
    return 0;
}

static enum ofperr
decode_OFPAT_RAW_SET_NW_DST(ovs_be32 ipv4,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_IPV4_DST(out)->ipv4 = ipv4;
    return 0;
}

static void
encode_SET_IPV4_addr(const struct ofpact_ipv4 *ipv4,
                     enum ofp_version ofp_version,
                     enum ofp_raw_action_type raw, enum mf_field_id field,
                     struct ofpbuf *out)
{
    ovs_be32 addr = ipv4->ipv4;
    if (ofp_version < OFP12_VERSION) {
        ofpact_put_raw(out, ofp_version, raw, ntohl(addr));
    } else {
        put_set_field(out, ofp_version, field, ntohl(addr));
    }
}

static void
encode_SET_IPV4_SRC(const struct ofpact_ipv4 *ipv4,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    encode_SET_IPV4_addr(ipv4, ofp_version, OFPAT_RAW_SET_NW_SRC, MFF_IPV4_SRC,
                         out);
}

static void
encode_SET_IPV4_DST(const struct ofpact_ipv4 *ipv4,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    encode_SET_IPV4_addr(ipv4, ofp_version, OFPAT_RAW_SET_NW_DST, MFF_IPV4_DST,
                         out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_IPV4_SRC(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_ip(arg, &ofpact_put_SET_IPV4_SRC(pp->ofpacts)->ipv4);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_IPV4_DST(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_ip(arg, &ofpact_put_SET_IPV4_DST(pp->ofpacts)->ipv4);
}

static void
format_SET_IPV4_SRC(const struct ofpact_ipv4 *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_nw_src:%s"IP_FMT,
                  colors.param, colors.end, IP_ARGS(a->ipv4));
}

static void
format_SET_IPV4_DST(const struct ofpact_ipv4 *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_nw_dst:%s"IP_FMT,
                  colors.param, colors.end, IP_ARGS(a->ipv4));
}

/* Set IPv4/v6 TOS actions. */

static enum ofperr
decode_OFPAT_RAW_SET_NW_TOS(uint8_t dscp,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    if (dscp & ~IP_DSCP_MASK) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else {
        ofpact_put_SET_IP_DSCP(out)->dscp = dscp;
        return 0;
    }
}

static void
encode_SET_IP_DSCP(const struct ofpact_dscp *dscp,
                   enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version < OFP12_VERSION) {
        put_OFPAT_SET_NW_TOS(out, ofp_version, dscp->dscp);
    } else {
        put_set_field(out, ofp_version, MFF_IP_DSCP_SHIFTED, dscp->dscp >> 2);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_IP_DSCP(char *arg, const struct ofpact_parse_params *pp)

{
    uint8_t tos;
    char *error;

    error = str_to_u8(arg, "TOS", &tos);
    if (error) {
        return error;
    }

    if (tos & ~IP_DSCP_MASK) {
        return xasprintf("%s: not a valid TOS", arg);
    }
    ofpact_put_SET_IP_DSCP(pp->ofpacts)->dscp = tos;
    return NULL;
}

static void
format_SET_IP_DSCP(const struct ofpact_dscp *a,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_nw_tos:%s%d",
                  colors.param, colors.end, a->dscp);
}

/* Set IPv4/v6 ECN actions. */

static enum ofperr
decode_OFPAT_RAW11_SET_NW_ECN(uint8_t ecn,
                              enum ofp_version ofp_version OVS_UNUSED,
                              struct ofpbuf *out)
{
    if (ecn & ~IP_ECN_MASK) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else {
        ofpact_put_SET_IP_ECN(out)->ecn = ecn;
        return 0;
    }
}

static void
encode_SET_IP_ECN(const struct ofpact_ecn *ip_ecn,
                  enum ofp_version ofp_version, struct ofpbuf *out)
{
    uint8_t ecn = ip_ecn->ecn;
    if (ofp_version == OFP10_VERSION) {
        struct mf_subfield dst = { .field = mf_from_id(MFF_IP_ECN),
                                   .ofs = 0, .n_bits = 2 };
        put_reg_load(out, &dst, ecn);
    } else if (ofp_version == OFP11_VERSION) {
        put_OFPAT11_SET_NW_ECN(out, ecn);
    } else {
        put_set_field(out, ofp_version, MFF_IP_ECN, ecn);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_IP_ECN(char *arg, const struct ofpact_parse_params *pp)
{
    uint8_t ecn;
    char *error;

    error = str_to_u8(arg, "ECN", &ecn);
    if (error) {
        return error;
    }

    if (ecn & ~IP_ECN_MASK) {
        return xasprintf("%s: not a valid ECN", arg);
    }
    ofpact_put_SET_IP_ECN(pp->ofpacts)->ecn = ecn;
    return NULL;
}

static void
format_SET_IP_ECN(const struct ofpact_ecn *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_nw_ecn:%s%d",
                  colors.param, colors.end, a->ecn);
}

/* Set IPv4/v6 TTL actions. */

static enum ofperr
decode_OFPAT_RAW11_SET_NW_TTL(uint8_t ttl,
                              enum ofp_version ofp_version OVS_UNUSED,
                              struct ofpbuf *out)
{
    ofpact_put_SET_IP_TTL(out)->ttl = ttl;
    return 0;
}

static void
encode_SET_IP_TTL(const struct ofpact_ip_ttl *ttl,
                  enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version >= OFP11_VERSION) {
        put_OFPAT11_SET_NW_TTL(out, ttl->ttl);
    } else {
        struct mf_subfield dst = { .field = mf_from_id(MFF_IP_TTL),
                                   .ofs = 0, .n_bits = 8 };
        put_reg_load(out, &dst, ttl->ttl);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_IP_TTL(char *arg, const struct ofpact_parse_params *pp)

{
    uint8_t ttl;
    char *error;

    error = str_to_u8(arg, "TTL", &ttl);
    if (error) {
        return error;
    }

    ofpact_put_SET_IP_TTL(pp->ofpacts)->ttl = ttl;
    return NULL;
}

static void
format_SET_IP_TTL(const struct ofpact_ip_ttl *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_nw_ttl:%s%d",
                  colors.param, colors.end, a->ttl);
}

/* Set TCP/UDP/SCTP port actions. */

static enum ofperr
decode_OFPAT_RAW_SET_TP_SRC(ovs_be16 port,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_L4_SRC_PORT(out)->port = ntohs(port);
    return 0;
}

static enum ofperr
decode_OFPAT_RAW_SET_TP_DST(ovs_be16 port,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    ofpact_put_SET_L4_DST_PORT(out)->port = ntohs(port);
    return 0;
}

static void
encode_SET_L4_port(const struct ofpact_l4_port *l4_port,
                   enum ofp_version ofp_version, enum ofp_raw_action_type raw,
                   enum mf_field_id field, struct ofpbuf *out)
{
    uint16_t port = l4_port->port;

    if (ofp_version >= OFP12_VERSION && field != MFF_N_IDS) {
        put_set_field(out, ofp_version, field, port);
    } else {
        ofpact_put_raw(out, ofp_version, raw, port);
    }
}

static void
encode_SET_L4_SRC_PORT(const struct ofpact_l4_port *l4_port,
                       enum ofp_version ofp_version, struct ofpbuf *out)
{
    uint8_t proto = l4_port->flow_ip_proto;
    enum mf_field_id field = (proto == IPPROTO_TCP ? MFF_TCP_SRC
                              : proto == IPPROTO_UDP ? MFF_UDP_SRC
                              : proto == IPPROTO_SCTP ? MFF_SCTP_SRC
                              : MFF_N_IDS);

    encode_SET_L4_port(l4_port, ofp_version, OFPAT_RAW_SET_TP_SRC, field, out);
}

static void
encode_SET_L4_DST_PORT(const struct ofpact_l4_port *l4_port,
                       enum ofp_version ofp_version,
                       struct ofpbuf *out)
{
    uint8_t proto = l4_port->flow_ip_proto;
    enum mf_field_id field = (proto == IPPROTO_TCP ? MFF_TCP_DST
                              : proto == IPPROTO_UDP ? MFF_UDP_DST
                              : proto == IPPROTO_SCTP ? MFF_SCTP_DST
                              : MFF_N_IDS);

    encode_SET_L4_port(l4_port, ofp_version, OFPAT_RAW_SET_TP_DST, field, out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_L4_SRC_PORT(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_u16(arg, "source port",
                      &ofpact_put_SET_L4_SRC_PORT(pp->ofpacts)->port);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_L4_DST_PORT(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_u16(arg, "destination port",
                      &ofpact_put_SET_L4_DST_PORT(pp->ofpacts)->port);
}

static void
format_SET_L4_SRC_PORT(const struct ofpact_l4_port *a,
                       const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_tp_src:%s%d",
                  colors.param, colors.end, a->port);
}

static void
format_SET_L4_DST_PORT(const struct ofpact_l4_port *a,
                       const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smod_tp_dst:%s%d",
                  colors.param, colors.end, a->port);
}

/* Action structure for OFPAT_COPY_FIELD. */
struct ofp15_action_copy_field {
    ovs_be16 type;              /* OFPAT_COPY_FIELD. */
    ovs_be16 len;               /* Length is padded to 64 bits. */
    ovs_be16 n_bits;            /* Number of bits to copy. */
    ovs_be16 src_offset;        /* Starting bit offset in source. */
    ovs_be16 dst_offset;        /* Starting bit offset in destination. */
    uint8_t pad[2];
    /* Followed by:
     * - OXM header for source field.
     * - OXM header for destination field.
     * - Padding with 0-bytes to a multiple of 8 bytes.
     * The "pad2" member is the beginning of the above. */
    uint8_t pad2[4];
};
OFP_ASSERT(sizeof(struct ofp15_action_copy_field) == 16);

/* Action structure for OpenFlow 1.3 extension copy-field action.. */
struct onf_action_copy_field {
    ovs_be16 type;              /* OFPAT_EXPERIMENTER. */
    ovs_be16 len;               /* Length is padded to 64 bits. */
    ovs_be32 experimenter;      /* ONF_VENDOR_ID. */
    ovs_be16 exp_type;          /* 3200. */
    uint8_t pad[2];             /* Not used. */
    ovs_be16 n_bits;            /* Number of bits to copy. */
    ovs_be16 src_offset;        /* Starting bit offset in source. */
    ovs_be16 dst_offset;        /* Starting bit offset in destination. */
    uint8_t pad2[2];            /* Not used. */
    /* Followed by:
     * - OXM header for source field.
     * - OXM header for destination field.
     * - Padding with 0-bytes (either 0 or 4 of them) to a multiple of 8 bytes.
     * The "pad3" member is the beginning of the above. */
    uint8_t pad3[4];            /* Not used. */
};
OFP_ASSERT(sizeof(struct onf_action_copy_field) == 24);

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
 *   - NXM_OF_ICMP_TYPE
 *   - NXM_OF_ICMP_CODE
 *   - NXM_NX_ICMPV6_TYPE
 *   - NXM_NX_ICMPV6_CODE
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
    /* Followed by:
     * - OXM/NXM header for source field (4 or 8 bytes).
     * - OXM/NXM header for destination field (4 or 8 bytes).
     * - Padding with 0-bytes to a multiple of 8 bytes, if necessary. */
};
OFP_ASSERT(sizeof(struct nx_action_reg_move) == 16);

static enum ofperr
decode_copy_field__(ovs_be16 src_offset, ovs_be16 dst_offset, ovs_be16 n_bits,
                    const void *action, ovs_be16 action_len, size_t oxm_offset,
                    const struct vl_mff_map *vl_mff_map,
                    uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
    enum ofperr error;

    move->ofpact.raw = ONFACT_RAW13_COPY_FIELD;
    move->src.ofs = ntohs(src_offset);
    move->src.n_bits = ntohs(n_bits);
    move->dst.ofs = ntohs(dst_offset);
    move->dst.n_bits = ntohs(n_bits);

    struct ofpbuf b = ofpbuf_const_initializer(action, ntohs(action_len));
    ofpbuf_pull(&b, oxm_offset);

    error = mf_vl_mff_nx_pull_header(&b, vl_mff_map, &move->src.field, NULL,
                                     tlv_bitmap);
    if (error) {
        return error;
    }
    error = mf_vl_mff_nx_pull_header(&b, vl_mff_map, &move->dst.field, NULL,
                                     tlv_bitmap);
    if (error) {
        return error;
    }

    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    return nxm_reg_move_check(move, NULL);
}

static enum ofperr
decode_OFPAT_RAW15_COPY_FIELD(const struct ofp15_action_copy_field *oacf,
                              enum ofp_version ofp_version OVS_UNUSED,
                              const struct vl_mff_map *vl_mff_map,
                              uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    return decode_copy_field__(oacf->src_offset, oacf->dst_offset,
                               oacf->n_bits, oacf, oacf->len,
                               OBJECT_OFFSETOF(oacf, pad2), vl_mff_map,
                               tlv_bitmap, ofpacts);
}

static enum ofperr
decode_ONFACT_RAW13_COPY_FIELD(const struct onf_action_copy_field *oacf,
                               enum ofp_version ofp_version OVS_UNUSED,
                               const struct vl_mff_map *vl_mff_map,
                               uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    return decode_copy_field__(oacf->src_offset, oacf->dst_offset,
                               oacf->n_bits, oacf, oacf->len,
                               OBJECT_OFFSETOF(oacf, pad3), vl_mff_map,
                               tlv_bitmap, ofpacts);
}

static enum ofperr
decode_NXAST_RAW_REG_MOVE(const struct nx_action_reg_move *narm,
                          enum ofp_version ofp_version OVS_UNUSED,
                          const struct vl_mff_map *vl_mff_map,
                          uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
    enum ofperr error;

    move->ofpact.raw = NXAST_RAW_REG_MOVE;
    move->src.ofs = ntohs(narm->src_ofs);
    move->src.n_bits = ntohs(narm->n_bits);
    move->dst.ofs = ntohs(narm->dst_ofs);
    move->dst.n_bits = ntohs(narm->n_bits);

    struct ofpbuf b = ofpbuf_const_initializer(narm, ntohs(narm->len));
    ofpbuf_pull(&b, sizeof *narm);

    error = mf_vl_mff_nx_pull_header(&b, vl_mff_map, &move->src.field, NULL,
                                     tlv_bitmap);
    if (error) {
        return error;
    }

    error = mf_vl_mff_nx_pull_header(&b, vl_mff_map, &move->dst.field, NULL,
                                     tlv_bitmap);
    if (error) {
        return error;
    }

    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    return nxm_reg_move_check(move, NULL);
}

static void
encode_REG_MOVE(const struct ofpact_reg_move *move,
                enum ofp_version ofp_version, struct ofpbuf *out)
{
    /* For OpenFlow 1.3, the choice of ONFACT_RAW13_COPY_FIELD versus
     * NXAST_RAW_REG_MOVE is somewhat difficult.  Neither one is guaranteed to
     * be supported by every OpenFlow 1.3 implementation.  It would be ideal to
     * probe for support.  Until we have that ability, we currently prefer
     * NXAST_RAW_REG_MOVE for backward compatibility with older Open vSwitch
     * versions.  */
    size_t start_ofs = out->size;
    if (ofp_version >= OFP15_VERSION) {
        struct ofp15_action_copy_field *copy = put_OFPAT15_COPY_FIELD(out);
        copy->n_bits = htons(move->dst.n_bits);
        copy->src_offset = htons(move->src.ofs);
        copy->dst_offset = htons(move->dst.ofs);
        out->size = out->size - sizeof copy->pad2;
        nx_put_mff_header(out, move->src.field, ofp_version, false);
        nx_put_mff_header(out, move->dst.field, ofp_version, false);
    } else if (ofp_version == OFP13_VERSION
               && move->ofpact.raw == ONFACT_RAW13_COPY_FIELD) {
        struct onf_action_copy_field *copy = put_ONFACT13_COPY_FIELD(out);
        copy->n_bits = htons(move->dst.n_bits);
        copy->src_offset = htons(move->src.ofs);
        copy->dst_offset = htons(move->dst.ofs);
        out->size = out->size - sizeof copy->pad3;
        nx_put_mff_header(out, move->src.field, ofp_version, false);
        nx_put_mff_header(out, move->dst.field, ofp_version, false);
    } else {
        struct nx_action_reg_move *narm = put_NXAST_REG_MOVE(out);
        narm->n_bits = htons(move->dst.n_bits);
        narm->src_ofs = htons(move->src.ofs);
        narm->dst_ofs = htons(move->dst.ofs);
        nx_put_mff_header(out, move->src.field, 0, false);
        nx_put_mff_header(out, move->dst.field, 0, false);
    }
    pad_ofpat(out, start_ofs);
}

static char * OVS_WARN_UNUSED_RESULT
parse_REG_MOVE(const char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(pp->ofpacts);
    return nxm_parse_reg_move(move, arg);
}

static void
format_REG_MOVE(const struct ofpact_reg_move *a,
                const struct ofpact_format_params *fp)
{
    nxm_format_reg_move(a, fp->s);
}

/* Action structure for OFPAT12_SET_FIELD. */
struct ofp12_action_set_field {
    ovs_be16 type;                  /* OFPAT12_SET_FIELD. */
    ovs_be16 len;                   /* Length is padded to 64 bits. */

    /* Followed by:
     * - An OXM header, value, and (in OpenFlow 1.5+) optionally a mask.
     * - Enough 0-bytes to pad out to a multiple of 64 bits.
     *
     * The "pad" member is the beginning of the above. */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp12_action_set_field) == 8);

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

/* The NXAST_REG_LOAD2 action structure is "struct ext_action_header",
 * followed by:
 *
 * - An NXM/OXM header, value, and optionally a mask.
 * - Enough 0-bytes to pad out to a multiple of 64 bits.
 *
 * The "pad" member is the beginning of the above. */

static enum ofperr
decode_ofpat_set_field(const struct ofp12_action_set_field *oasf,
                       bool may_mask, const struct vl_mff_map *vl_mff_map,
                       uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpbuf b = ofpbuf_const_initializer(oasf, ntohs(oasf->len));
    ofpbuf_pull(&b, OBJECT_OFFSETOF(oasf, pad));

    union mf_value value, mask;
    const struct mf_field *field;
    enum ofperr error;
    error  = mf_vl_mff_nx_pull_entry(&b, vl_mff_map, &field, &value,
                                     may_mask ? &mask : NULL, tlv_bitmap);
    if (error) {
        return (error == OFPERR_OFPBMC_BAD_MASK
                ? OFPERR_OFPBAC_BAD_SET_MASK
                : error);
    }

    if (!may_mask) {
        memset(&mask, 0xff, field->n_bytes);
    }

    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    /* OpenFlow says specifically that one may not set OXM_OF_IN_PORT via
     * Set-Field. */
    if (field->id == MFF_IN_PORT_OXM) {
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    /* oxm_length is now validated to be compatible with mf_value. */
    if (!field->writable) {
        VLOG_WARN_RL(&rl, "destination field %s is not writable",
                     field->name);
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    /* The value must be valid for match.  OpenFlow 1.5 also says,
     * "In an OXM_OF_VLAN_VID set-field action, the OFPVID_PRESENT bit must be
     * a 1-bit in oxm_value and in oxm_mask." */
    if (!mf_is_value_valid(field, &value)
        || (field->id == MFF_VLAN_VID
            && (!(mask.be16 & htons(OFPVID12_PRESENT))
                || !(value.be16 & htons(OFPVID12_PRESENT))))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        mf_format(field, &value, NULL, NULL, &ds);
        VLOG_WARN_RL(&rl, "Invalid value for set field %s: %s",
                     field->name, ds_cstr(&ds));
        ds_destroy(&ds);

        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    ofpact_put_set_field(ofpacts, field, &value, &mask);
    return 0;
}

static enum ofperr
decode_OFPAT_RAW12_SET_FIELD(const struct ofp12_action_set_field *oasf,
                             enum ofp_version ofp_version OVS_UNUSED,
                             const struct vl_mff_map *vl_mff_map,
                             uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    return decode_ofpat_set_field(oasf, false, vl_mff_map, tlv_bitmap,
                                  ofpacts);
}

static enum ofperr
decode_OFPAT_RAW15_SET_FIELD(const struct ofp12_action_set_field *oasf,
                             enum ofp_version ofp_version OVS_UNUSED,
                             const struct vl_mff_map *vl_mff_map,
                             uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    return decode_ofpat_set_field(oasf, true, vl_mff_map, tlv_bitmap, ofpacts);
}

static enum ofperr
decode_NXAST_RAW_REG_LOAD(const struct nx_action_reg_load *narl,
                          enum ofp_version ofp_version OVS_UNUSED,
                          const struct vl_mff_map *vl_mff_map,
                          uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    struct mf_subfield dst;
    enum ofperr error;

    dst.ofs = nxm_decode_ofs(narl->ofs_nbits);
    dst.n_bits = nxm_decode_n_bits(narl->ofs_nbits);
    error = mf_vl_mff_mf_from_nxm_header(ntohl(narl->dst), vl_mff_map,
                                         &dst.field, tlv_bitmap);
    if (error) {
        return error;
    }

    error = mf_check_dst(&dst, NULL);
    if (error) {
        return error;
    }

    /* Reject 'narl' if a bit numbered 'n_bits' or higher is set to 1 in
     * narl->value. */
    if (dst.n_bits < 64 && ntohll(narl->value) >> dst.n_bits) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    struct ofpact_set_field *sf = ofpact_put_reg_load(out, dst.field, NULL,
                                                      NULL);
    bitwise_put(ntohll(narl->value),
                sf->value, dst.field->n_bytes, dst.ofs,
                dst.n_bits);
    bitwise_put(UINT64_MAX,
                ofpact_set_field_mask(sf), dst.field->n_bytes, dst.ofs,
                dst.n_bits);
    return 0;
}

static enum ofperr
decode_NXAST_RAW_REG_LOAD2(const struct ext_action_header *eah,
                           enum ofp_version ofp_version OVS_UNUSED,
                           const struct vl_mff_map *vl_mff_map,
                           uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    struct ofpbuf b = ofpbuf_const_initializer(eah, ntohs(eah->len));
    ofpbuf_pull(&b, OBJECT_OFFSETOF(eah, pad));

    union mf_value value, mask;
    const struct mf_field *field;
    enum ofperr error;
    error = mf_vl_mff_nx_pull_entry(&b, vl_mff_map, &field, &value, &mask,
                                    tlv_bitmap);
    if (error) {
        return error;
    }

    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    if (!field->writable) {
        VLOG_WARN_RL(&rl, "destination field %s is not writable", field->name);
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    /* Put value and mask. */
    ofpact_put_reg_load2(out, field, &value, &mask);
    return 0;
}

static void
put_set_field(struct ofpbuf *openflow, enum ofp_version ofp_version,
              enum mf_field_id field, uint64_t value_)
{
    struct ofp12_action_set_field *oasf OVS_UNUSED;
    int n_bytes = mf_from_id(field)->n_bytes;
    size_t start_ofs = openflow->size;
    union mf_value value;

    value.be64 = htonll(value_ << (8 * (8 - n_bytes)));

    oasf = put_OFPAT12_SET_FIELD(openflow);
    openflow->size = openflow->size - sizeof oasf->pad;
    nx_put_entry(openflow, mf_from_id(field), ofp_version, &value, NULL);
    pad_ofpat(openflow, start_ofs);
}

static void
put_reg_load(struct ofpbuf *openflow,
             const struct mf_subfield *dst, uint64_t value)
{
    ovs_assert(dst->n_bits <= 64);

    struct nx_action_reg_load *narl = put_NXAST_REG_LOAD(openflow);
    narl->ofs_nbits = nxm_encode_ofs_nbits(dst->ofs, dst->n_bits);
    narl->dst = htonl(nxm_header_from_mff(dst->field));
    narl->value = htonll(value);
}

static bool
next_load_segment(const struct ofpact_set_field *sf,
                  struct mf_subfield *dst, uint64_t *value)
{
    int n_bits = sf->field->n_bits;
    int n_bytes = sf->field->n_bytes;
    int start = dst->ofs + dst->n_bits;

    if (start < n_bits) {
        dst->field = sf->field;
        dst->ofs = bitwise_scan(ofpact_set_field_mask(sf), n_bytes, 1, start,
                                n_bits);
        if (dst->ofs < n_bits) {
            dst->n_bits = bitwise_scan(ofpact_set_field_mask(sf), n_bytes, 0,
                                       dst->ofs + 1,
                                       MIN(dst->ofs + 64, n_bits)) - dst->ofs;
            *value = bitwise_get(sf->value, n_bytes, dst->ofs, dst->n_bits);
            return true;
        }
    }
    return false;
}

/* Convert 'sf' to a series of REG_LOADs. */
static void
set_field_to_nxast(const struct ofpact_set_field *sf, struct ofpbuf *openflow)
{
    /* If 'sf' cannot be encoded as NXAST_REG_LOAD because it requires an
     * experimenter OXM or is variable length (or if it came in as
     * NXAST_REG_LOAD2), encode as NXAST_REG_LOAD2.  Otherwise use
     * NXAST_REG_LOAD, which is backward compatible. */
    if (sf->ofpact.raw == NXAST_RAW_REG_LOAD2
        || !mf_nxm_header(sf->field->id) || sf->field->variable_len) {
        struct ext_action_header *eah OVS_UNUSED;
        size_t start_ofs = openflow->size;

        eah = put_NXAST_REG_LOAD2(openflow);
        openflow->size = openflow->size - sizeof eah->pad;
        nx_put_entry(openflow, sf->field, 0, sf->value,
                     ofpact_set_field_mask(sf));
        pad_ofpat(openflow, start_ofs);
    } else {
        struct mf_subfield dst;
        uint64_t value;

        dst.ofs = dst.n_bits = 0;
        while (next_load_segment(sf, &dst, &value)) {
            put_reg_load(openflow, &dst, value);
        }
    }
}

/* Convert 'sf', which must set an entire field, to standard OpenFlow 1.0/1.1
 * actions, if we can, falling back to Nicira extensions if we must.
 *
 * We check only meta-flow types that can appear within set field actions and
 * that have a mapping to compatible action types.  These struct mf_field
 * definitions have a defined OXM or NXM header value and specify the field as
 * writable. */
static void
set_field_to_legacy_openflow(const struct ofpact_set_field *sf,
                             enum ofp_version ofp_version,
                             struct ofpbuf *out)
{
    switch ((int) sf->field->id) {
    case MFF_VLAN_TCI: {
        ovs_be16 tci = sf->value->be16;
        bool cfi = (tci & htons(VLAN_CFI)) != 0;
        uint16_t vid = vlan_tci_to_vid(tci);
        uint8_t pcp = vlan_tci_to_pcp(tci);

        if (ofp_version < OFP11_VERSION) {
            /* NXM_OF_VLAN_TCI to OpenFlow 1.0 mapping:
             *
             * If CFI=1, Add or modify VLAN VID & PCP.
             * If CFI=0, strip VLAN header, if any.
             */
            if (cfi) {
                put_OFPAT10_SET_VLAN_VID(out, vid);
                put_OFPAT10_SET_VLAN_PCP(out, pcp);
            } else {
                put_OFPAT10_STRIP_VLAN(out);
            }
        } else {
            /* NXM_OF_VLAN_TCI to OpenFlow 1.1 mapping:
             *
             * If CFI=1, Add or modify VLAN VID & PCP.
             *    OpenFlow 1.1 set actions only apply if the packet
             *    already has VLAN tags.  To be sure that is the case
             *    we have to push a VLAN header.  As we do not support
             *    multiple layers of VLANs, this is a no-op, if a VLAN
             *    header already exists.  This may backfire, however,
             *    when we start supporting multiple layers of VLANs.
             * If CFI=0, strip VLAN header, if any.
             */
            if (cfi) {
                /* Push a VLAN tag, if one was not seen at action validation
                 * time. */
                if (!sf->flow_has_vlan) {
                    put_OFPAT11_PUSH_VLAN(out, htons(ETH_TYPE_VLAN_8021Q));
                }
                put_OFPAT11_SET_VLAN_VID(out, vid);
                put_OFPAT11_SET_VLAN_PCP(out, pcp);
            } else {
                /* If the flow did not match on vlan, we have no way of
                 * knowing if the vlan tag exists, so we must POP just to be
                 * sure. */
                put_OFPAT11_POP_VLAN(out);
            }
        }
        break;
    }

    case MFF_VLAN_VID: {
        uint16_t vid = ntohs(sf->value->be16) & VLAN_VID_MASK;
        if (ofp_version == OFP10_VERSION) {
            put_OFPAT10_SET_VLAN_VID(out, vid);
        } else {
            put_OFPAT11_SET_VLAN_VID(out, vid);
        }
        break;
    }

    case MFF_VLAN_PCP:
        if (ofp_version == OFP10_VERSION) {
            put_OFPAT10_SET_VLAN_PCP(out, sf->value->u8);
        } else {
            put_OFPAT11_SET_VLAN_PCP(out, sf->value->u8);
        }
        break;

    case MFF_ETH_SRC:
        put_OFPAT_SET_DL_SRC(out, ofp_version)->dl_addr = sf->value->mac;
        break;

    case MFF_ETH_DST:
        put_OFPAT_SET_DL_DST(out, ofp_version)->dl_addr = sf->value->mac;
        break;

    case MFF_IPV4_SRC:
        put_OFPAT_SET_NW_SRC(out, ofp_version, sf->value->be32);
        break;

    case MFF_IPV4_DST:
        put_OFPAT_SET_NW_DST(out, ofp_version, sf->value->be32);
        break;

    case MFF_IP_DSCP:
        put_OFPAT_SET_NW_TOS(out, ofp_version, sf->value->u8);
        break;

    case MFF_IP_DSCP_SHIFTED:
        put_OFPAT_SET_NW_TOS(out, ofp_version, sf->value->u8 << 2);
        break;

    case MFF_IP_ECN: {
        struct ofpact_ecn ip_ecn = { .ecn = sf->value->u8 };
        encode_SET_IP_ECN(&ip_ecn, ofp_version, out);
        break;
    }

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        put_OFPAT_SET_TP_SRC(out, sf->value->be16);
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        put_OFPAT_SET_TP_DST(out, sf->value->be16);
        break;

    default:
        set_field_to_nxast(sf, out);
        break;
    }
}

static void
set_field_to_set_field(const struct ofpact_set_field *sf,
                       enum ofp_version ofp_version, struct ofpbuf *out)
{
    struct ofp12_action_set_field *oasf OVS_UNUSED;
    size_t start_ofs = out->size;

    oasf = put_OFPAT12_SET_FIELD(out);
    out->size = out->size - sizeof oasf->pad;
    nx_put_entry(out, sf->field, ofp_version, sf->value,
                 ofpact_set_field_mask(sf));
    pad_ofpat(out, start_ofs);
}

static void
encode_SET_FIELD(const struct ofpact_set_field *sf,
                 enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version >= OFP15_VERSION) {
        /* OF1.5+ only has Set-Field (reg_load is redundant so we drop it
         * entirely). */
        set_field_to_set_field(sf, ofp_version, out);
    } else if (sf->ofpact.raw == NXAST_RAW_REG_LOAD ||
               sf->ofpact.raw == NXAST_RAW_REG_LOAD2) {
        /* It came in as reg_load, send it out the same way. */
        set_field_to_nxast(sf, out);
    } else if (ofp_version < OFP12_VERSION) {
        /* OpenFlow 1.0 and 1.1 don't have Set-Field. */
        set_field_to_legacy_openflow(sf, ofp_version, out);
    } else if (is_all_ones(ofpact_set_field_mask(sf), sf->field->n_bytes)) {
        /* We're encoding to OpenFlow 1.2, 1.3, or 1.4.  The action sets an
         * entire field, so encode it as OFPAT_SET_FIELD. */
        set_field_to_set_field(sf, ofp_version, out);
    } else {
        /* We're encoding to OpenFlow 1.2, 1.3, or 1.4.  The action cannot be
         * encoded as OFPAT_SET_FIELD because it does not set an entire field,
         * so encode it as reg_load. */
        set_field_to_nxast(sf, out);
    }
}

/* Parses the input argument 'arg' into the key, value, and delimiter
 * components that are common across the reg_load and set_field action format.
 *
 * With an argument like "1->metadata", sets the following pointers to
 * point within 'arg':
 * key: "metadata"
 * value: "1"
 * delim: "->"
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
set_field_split_str(char *arg, char **key, char **value, char **delim)
{
    char *value_end;

    *value = arg;
    value_end = strstr(arg, "->");
    *key = value_end + strlen("->");
    if (delim) {
        *delim = value_end;
    }

    if (!value_end) {
        return xasprintf("%s: missing `->'", arg);
    }
    if (strlen(value_end) <= strlen("->")) {
        return xasprintf("%s: missing field name following `->'", arg);
    }

    return NULL;
}

/* Parses a "set_field" action with argument 'arg', appending the parsed
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
set_field_parse__(char *arg, const struct ofpact_parse_params *pp)
{
    char *value;
    char *delim;
    char *key;
    const struct mf_field *mf;
    union mf_value sf_value, sf_mask;
    char *error;

    error = set_field_split_str(arg, &key, &value, &delim);
    if (error) {
        return error;
    }

    mf = mf_from_name(key);
    if (!mf) {
        return xasprintf("%s is not a valid OXM field name", key);
    }
    if (!mf->writable) {
        return xasprintf("%s is read-only", key);
    }

    delim[0] = '\0';
    error = mf_parse(mf, value, pp->port_map, &sf_value, &sf_mask);
    if (error) {
        return error;
    }

    if (!mf_is_value_valid(mf, &sf_value)) {
        return xasprintf("%s is not a valid value for field %s", value, key);
    }

    *pp->usable_protocols &= mf->usable_protocols_exact;

    ofpact_put_set_field(pp->ofpacts, mf, &sf_value, &sf_mask);
    return NULL;
}

/* Parses 'arg' as the argument to a "set_field" action, and appends such an
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_SET_FIELD(const char *arg, const struct ofpact_parse_params *pp)
{
    char *copy = xstrdup(arg);
    char *error = set_field_parse__(copy, pp);
    free(copy);
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
parse_reg_load(char *arg, const struct ofpact_parse_params *pp)
{
    struct mf_subfield dst;
    char *key, *value_str;
    union mf_value value;
    char *error;

    error = set_field_split_str(arg, &key, &value_str, NULL);
    if (error) {
        return error;
    }

    error = mf_parse_subfield(&dst, key);
    if (error) {
        return error;
    }

    if (parse_int_string(value_str, (uint8_t *)&value, dst.field->n_bytes,
                         &key)) {
        return xasprintf("%s: cannot parse integer value", arg);
    }

    if (!bitwise_is_all_zeros(&value, dst.field->n_bytes, dst.n_bits,
                              dst.field->n_bytes * 8 - dst.n_bits)) {
        struct ds ds;

        ds_init(&ds);
        mf_format(dst.field, &value, NULL, NULL, &ds);
        error = xasprintf("%s: value %s does not fit into %d bits",
                          arg, ds_cstr(&ds), dst.n_bits);
        ds_destroy(&ds);
        return error;
    }

    struct ofpact_set_field *sf = ofpact_put_reg_load(pp->ofpacts, dst.field,
                                                      NULL, NULL);

    bitwise_copy(&value, dst.field->n_bytes, 0, sf->value,
                 dst.field->n_bytes, dst.ofs, dst.n_bits);
    bitwise_one(ofpact_set_field_mask(sf), dst.field->n_bytes, dst.ofs,
                dst.n_bits);
    return NULL;
}

static void
format_SET_FIELD(const struct ofpact_set_field *a,
                 const struct ofpact_format_params *fp)
{
    if (a->ofpact.raw == NXAST_RAW_REG_LOAD) {
        struct mf_subfield dst;
        uint64_t value;

        dst.ofs = dst.n_bits = 0;
        while (next_load_segment(a, &dst, &value)) {
            ds_put_format(fp->s, "%sload:%s%#"PRIx64"%s->%s",
                          colors.special, colors.end, value,
                          colors.special, colors.end);
            mf_format_subfield(&dst, fp->s);
            ds_put_char(fp->s, ',');
        }
        ds_chomp(fp->s, ',');
    } else {
        ds_put_format(fp->s, "%sset_field:%s", colors.special, colors.end);
        mf_format(a->field, a->value, ofpact_set_field_mask(a),
                  fp->port_map, fp->s);
        ds_put_format(fp->s, "%s->%s%s",
                      colors.special, colors.end, a->field->name);
    }
}

/* Appends an OFPACT_SET_FIELD ofpact with enough space for the value and mask
 * for the 'field' to 'ofpacts' and returns it.  Fills in the value from
 * 'value', if non-NULL, and mask from 'mask' if non-NULL.  If 'value' is
 * non-NULL and 'mask' is NULL, an all-ones mask will be filled in. */
struct ofpact_set_field *
ofpact_put_set_field(struct ofpbuf *ofpacts, const struct mf_field *field,
                     const void *value, const void *mask)
{
    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = field;

    /* Fill in the value and mask if given, otherwise put zeroes so that the
     * caller may fill in the value and mask itself. */
    if (value) {
        ofpbuf_put_uninit(ofpacts, 2 * field->n_bytes);
        sf = ofpacts->header;
        memcpy(sf->value, value, field->n_bytes);
        if (mask) {
            memcpy(ofpact_set_field_mask(sf), mask, field->n_bytes);
        } else {
            memset(ofpact_set_field_mask(sf), 0xff, field->n_bytes);
        }
    } else {
        ofpbuf_put_zeros(ofpacts, 2 * field->n_bytes);
        sf = ofpacts->header;
    }
    /* Update length. */
    ofpact_finish_SET_FIELD(ofpacts, &sf);

    return sf;
}

/* Appends an OFPACT_SET_FIELD ofpact to 'ofpacts' and returns it.  The ofpact
 * is marked such that, if possible, it will be translated to OpenFlow as
 * NXAST_REG_LOAD extension actions rather than OFPAT_SET_FIELD, either because
 * that was the way that the action was expressed when it came into OVS or for
 * backward compatibility. */
struct ofpact_set_field *
ofpact_put_reg_load(struct ofpbuf *ofpacts, const struct mf_field *field,
                    const void *value, const void *mask)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts, field, value,
                                                       mask);
    sf->ofpact.raw = NXAST_RAW_REG_LOAD;

    return sf;
}

struct ofpact_set_field *
ofpact_put_reg_load2(struct ofpbuf *ofpacts, const struct mf_field *field,
                     const void *value, const void *mask)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts, field, value,
                                                       mask);
    sf->ofpact.raw = NXAST_RAW_REG_LOAD2;

    return sf;
}


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
    /* Followed by:
     * - OXM/NXM header for field to push or pop (4 or 8 bytes).
     * - ovs_be16 'n_bits', the number of bits to extract from the field.
     * - Enough 0-bytes to pad out the action to 24 bytes. */
    uint8_t pad[12];                /* See above. */
};
OFP_ASSERT(sizeof(struct nx_action_stack) == 24);

static enum ofperr
decode_stack_action(const struct nx_action_stack *nasp,
                    const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap,
                    struct ofpact_stack *stack_action)
{
    enum ofperr error;
    stack_action->subfield.ofs = ntohs(nasp->offset);

    struct ofpbuf b = ofpbuf_const_initializer(nasp, sizeof *nasp);
    ofpbuf_pull(&b, OBJECT_OFFSETOF(nasp, pad));
    error  = mf_vl_mff_nx_pull_header(&b, vl_mff_map,
                                      &stack_action->subfield.field, NULL,
                                      tlv_bitmap);
    if (error) {
        return error;
    }

    stack_action->subfield.n_bits = ntohs(*(const ovs_be16 *) b.data);
    ofpbuf_pull(&b, 2);
    if (!is_all_zeros(b.data, b.size)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    return 0;
}

static enum ofperr
decode_NXAST_RAW_STACK_PUSH(const struct nx_action_stack *nasp,
                            enum ofp_version ofp_version OVS_UNUSED,
                            const struct vl_mff_map *vl_mff_map,
                            uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpact_stack *push = ofpact_put_STACK_PUSH(ofpacts);
    enum ofperr error = decode_stack_action(nasp, vl_mff_map, tlv_bitmap,
                                            push);
    return error ? error : nxm_stack_push_check(push, NULL);
}

static enum ofperr
decode_NXAST_RAW_STACK_POP(const struct nx_action_stack *nasp,
                           enum ofp_version ofp_version OVS_UNUSED,
                           const struct vl_mff_map *vl_mff_map,
                           uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpact_stack *pop = ofpact_put_STACK_POP(ofpacts);
    enum ofperr error = decode_stack_action(nasp, vl_mff_map, tlv_bitmap,
                                            pop);
    return error ? error : nxm_stack_pop_check(pop, NULL);
}

static void
encode_STACK_op(const struct ofpact_stack *stack_action,
                struct nx_action_stack *nasp)
{
    struct ofpbuf b;
    ovs_be16 n_bits;

    nasp->offset = htons(stack_action->subfield.ofs);

    ofpbuf_use_stack(&b, nasp, ntohs(nasp->len));
    ofpbuf_put_uninit(&b, OBJECT_OFFSETOF(nasp, pad));
    nx_put_mff_header(&b, stack_action->subfield.field, 0, false);
    n_bits = htons(stack_action->subfield.n_bits);
    ofpbuf_put(&b, &n_bits, sizeof n_bits);
}

static void
encode_STACK_PUSH(const struct ofpact_stack *stack,
                  enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    encode_STACK_op(stack, put_NXAST_STACK_PUSH(out));
}

static void
encode_STACK_POP(const struct ofpact_stack *stack,
                 enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    encode_STACK_op(stack, put_NXAST_STACK_POP(out));
}

static char * OVS_WARN_UNUSED_RESULT
parse_STACK_PUSH(char *arg, const struct ofpact_parse_params *pp)
{
    return nxm_parse_stack_action(ofpact_put_STACK_PUSH(pp->ofpacts), arg);
}

static char * OVS_WARN_UNUSED_RESULT
parse_STACK_POP(char *arg, const struct ofpact_parse_params *pp)
{
    return nxm_parse_stack_action(ofpact_put_STACK_POP(pp->ofpacts), arg);
}

static void
format_STACK_PUSH(const struct ofpact_stack *a,
                  const struct ofpact_format_params *fp)
{
    nxm_format_stack_push(a, fp->s);
}

static void
format_STACK_POP(const struct ofpact_stack *a,
                 const struct ofpact_format_params *fp)
{
    nxm_format_stack_pop(a, fp->s);
}

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

static enum ofperr
decode_OFPAT_RAW_DEC_NW_TTL(struct ofpbuf *out)
{
    uint16_t id = 0;
    struct ofpact_cnt_ids *ids;
    enum ofperr error = 0;

    ids = ofpact_put_DEC_TTL(out);
    ids->n_controllers = 1;
    ofpbuf_put(out, &id, sizeof id);
    ids = out->header;
    ofpact_finish_DEC_TTL(out, &ids);
    return error;
}

static enum ofperr
decode_NXAST_RAW_DEC_TTL_CNT_IDS(const struct nx_action_cnt_ids *nac_ids,
                                 enum ofp_version ofp_version OVS_UNUSED,
                                 struct ofpbuf *out)
{
    struct ofpact_cnt_ids *ids;
    size_t ids_size;
    int i;

    ids = ofpact_put_DEC_TTL(out);
    ids->ofpact.raw = NXAST_RAW_DEC_TTL_CNT_IDS;
    ids->n_controllers = ntohs(nac_ids->n_controllers);
    ids_size = ntohs(nac_ids->len) - sizeof *nac_ids;

    if (!is_all_zeros(nac_ids->zeros, sizeof nac_ids->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    if (ids_size < ids->n_controllers * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rl, "Nicira action dec_ttl_cnt_ids only has %"PRIuSIZE" "
                     "bytes allocated for controller ids.  %"PRIuSIZE" bytes "
                     "are required for %u controllers.",
                     ids_size, ids->n_controllers * sizeof(ovs_be16),
                     ids->n_controllers);
        return OFPERR_OFPBAC_BAD_LEN;
    }

    for (i = 0; i < ids->n_controllers; i++) {
        uint16_t id = ntohs(((ovs_be16 *)(nac_ids + 1))[i]);
        ofpbuf_put(out, &id, sizeof id);
        ids = out->header;
    }

    ofpact_finish_DEC_TTL(out, &ids);

    return 0;
}

static void
encode_DEC_TTL(const struct ofpact_cnt_ids *dec_ttl,
               enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (dec_ttl->ofpact.raw == NXAST_RAW_DEC_TTL_CNT_IDS
        || dec_ttl->n_controllers != 1
        || dec_ttl->cnt_ids[0] != 0) {
        struct nx_action_cnt_ids *nac_ids = put_NXAST_DEC_TTL_CNT_IDS(out);
        int ids_len = ROUND_UP(2 * dec_ttl->n_controllers, OFP_ACTION_ALIGN);
        ovs_be16 *ids;
        size_t i;

        nac_ids->len = htons(ntohs(nac_ids->len) + ids_len);
        nac_ids->n_controllers = htons(dec_ttl->n_controllers);

        ids = ofpbuf_put_zeros(out, ids_len);
        for (i = 0; i < dec_ttl->n_controllers; i++) {
            ids[i] = htons(dec_ttl->cnt_ids[i]);
        }
    } else {
        put_OFPAT_DEC_NW_TTL(out, ofp_version);
    }
}

static void
parse_noargs_dec_ttl(const struct ofpact_parse_params *pp)
{
    struct ofpact_cnt_ids *ids;
    uint16_t id = 0;

    ofpact_put_DEC_TTL(pp->ofpacts);
    ofpbuf_put(pp->ofpacts, &id, sizeof id);
    ids = pp->ofpacts->header;
    ids->n_controllers++;
    ofpact_finish_DEC_TTL(pp->ofpacts, &ids);
}

static char * OVS_WARN_UNUSED_RESULT
parse_DEC_TTL(char *arg, const struct ofpact_parse_params *pp)
{
    if (*arg == '\0') {
        parse_noargs_dec_ttl(pp);
    } else {
        struct ofpact_cnt_ids *ids;
        char *cntr;

        ids = ofpact_put_DEC_TTL(pp->ofpacts);
        ids->ofpact.raw = NXAST_RAW_DEC_TTL_CNT_IDS;
        for (cntr = strtok_r(arg, ", ", &arg); cntr != NULL;
             cntr = strtok_r(NULL, ", ", &arg)) {
            uint16_t id = atoi(cntr);

            ofpbuf_put(pp->ofpacts, &id, sizeof id);
            ids = pp->ofpacts->header;
            ids->n_controllers++;
        }
        if (!ids->n_controllers) {
            return xstrdup("dec_ttl_cnt_ids: expected at least one controller "
                           "id.");
        }
        ofpact_finish_DEC_TTL(pp->ofpacts, &ids);
    }
    return NULL;
}

static void
format_DEC_TTL(const struct ofpact_cnt_ids *a,
               const struct ofpact_format_params *fp)
{
    size_t i;

    ds_put_format(fp->s, "%sdec_ttl%s", colors.paren, colors.end);
    if (a->ofpact.raw == NXAST_RAW_DEC_TTL_CNT_IDS) {
        ds_put_format(fp->s, "%s(%s", colors.paren, colors.end);
        for (i = 0; i < a->n_controllers; i++) {
            if (i) {
                ds_put_cstr(fp->s, ",");
            }
            ds_put_format(fp->s, "%"PRIu16, a->cnt_ids[i]);
        }
        ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
    }
}

/* Set MPLS label actions. */

static enum ofperr
decode_OFPAT_RAW_SET_MPLS_LABEL(ovs_be32 label,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    ofpact_put_SET_MPLS_LABEL(out)->label = label;
    return 0;
}

static void
encode_SET_MPLS_LABEL(const struct ofpact_mpls_label *label,
                      enum ofp_version ofp_version,
                                  struct ofpbuf *out)
{
    if (ofp_version < OFP12_VERSION) {
        put_OFPAT_SET_MPLS_LABEL(out, ofp_version, label->label);
    } else {
        put_set_field(out, ofp_version, MFF_MPLS_LABEL, ntohl(label->label));
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_MPLS_LABEL(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_mpls_label *mpls_label
        = ofpact_put_SET_MPLS_LABEL(pp->ofpacts);
    if (*arg == '\0') {
        return xstrdup("set_mpls_label: expected label.");
    }

    mpls_label->label = htonl(atoi(arg));
    return NULL;
}

static void
format_SET_MPLS_LABEL(const struct ofpact_mpls_label *a,
                      const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sset_mpls_label(%s%"PRIu32"%s)%s",
                  colors.paren, colors.end, ntohl(a->label),
                  colors.paren, colors.end);
}

/* Set MPLS TC actions. */

static enum ofperr
decode_OFPAT_RAW_SET_MPLS_TC(uint8_t tc,
                             enum ofp_version ofp_version OVS_UNUSED,
                             struct ofpbuf *out)
{
    ofpact_put_SET_MPLS_TC(out)->tc = tc;
    return 0;
}

static void
encode_SET_MPLS_TC(const struct ofpact_mpls_tc *tc,
                   enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version < OFP12_VERSION) {
        put_OFPAT_SET_MPLS_TC(out, ofp_version, tc->tc);
    } else {
        put_set_field(out, ofp_version, MFF_MPLS_TC, tc->tc);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_MPLS_TC(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_mpls_tc *mpls_tc = ofpact_put_SET_MPLS_TC(pp->ofpacts);

    if (*arg == '\0') {
        return xstrdup("set_mpls_tc: expected tc.");
    }

    mpls_tc->tc = atoi(arg);
    return NULL;
}

static void
format_SET_MPLS_TC(const struct ofpact_mpls_tc *a,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sset_mpls_ttl(%s%"PRIu8"%s)%s",
                  colors.paren, colors.end, a->tc,
                  colors.paren, colors.end);
}

/* Set MPLS TTL actions. */

static enum ofperr
decode_OFPAT_RAW_SET_MPLS_TTL(uint8_t ttl,
                              enum ofp_version ofp_version OVS_UNUSED,
                              struct ofpbuf *out)
{
    ofpact_put_SET_MPLS_TTL(out)->ttl = ttl;
    return 0;
}

static void
encode_SET_MPLS_TTL(const struct ofpact_mpls_ttl *ttl,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_SET_MPLS_TTL(out, ofp_version, ttl->ttl);
}

/* Parses 'arg' as the argument to a "set_mpls_ttl" action, and appends such an
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_SET_MPLS_TTL(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_mpls_ttl *mpls_ttl = ofpact_put_SET_MPLS_TTL(pp->ofpacts);

    if (*arg == '\0') {
        return xstrdup("set_mpls_ttl: expected ttl.");
    }

    mpls_ttl->ttl = atoi(arg);
    return NULL;
}

static void
format_SET_MPLS_TTL(const struct ofpact_mpls_ttl *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sset_mpls_ttl(%s%"PRIu8"%s)%s",
                  colors.paren, colors.end, a->ttl,
                  colors.paren, colors.end);
}

/* Decrement MPLS TTL actions. */

static enum ofperr
decode_OFPAT_RAW_DEC_MPLS_TTL(struct ofpbuf *out)
{
    ofpact_put_DEC_MPLS_TTL(out);
    return 0;
}

static void
encode_DEC_MPLS_TTL(const struct ofpact_null *null OVS_UNUSED,
                    enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_DEC_MPLS_TTL(out, ofp_version);
}

static char * OVS_WARN_UNUSED_RESULT
parse_DEC_MPLS_TTL(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_DEC_MPLS_TTL(pp->ofpacts);
    return NULL;
}

static void
format_DEC_MPLS_TTL(const struct ofpact_null *a OVS_UNUSED,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sdec_mpls_ttl%s", colors.value, colors.end);
}

/* Push MPLS label action. */

static enum ofperr
decode_OFPAT_RAW_PUSH_MPLS(ovs_be16 ethertype,
                           enum ofp_version ofp_version OVS_UNUSED,
                           struct ofpbuf *out)
{
    struct ofpact_push_mpls *oam;

    if (!eth_type_mpls(ethertype)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    oam = ofpact_put_PUSH_MPLS(out);
    oam->ethertype = ethertype;

    return 0;
}

static void
encode_PUSH_MPLS(const struct ofpact_push_mpls *push_mpls,
                 enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_PUSH_MPLS(out, ofp_version, push_mpls->ethertype);
}

static char * OVS_WARN_UNUSED_RESULT
parse_PUSH_MPLS(char *arg, const struct ofpact_parse_params *pp)
{
    uint16_t ethertype;
    char *error;

    error = str_to_u16(arg, "push_mpls", &ethertype);
    if (!error) {
        ofpact_put_PUSH_MPLS(pp->ofpacts)->ethertype = htons(ethertype);
    }
    return error;
}

static void
format_PUSH_MPLS(const struct ofpact_push_mpls *a,
                 const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%spush_mpls:%s0x%04"PRIx16,
                  colors.param, colors.end, ntohs(a->ethertype));
}

/* Pop MPLS label action. */

static enum ofperr
decode_OFPAT_RAW_POP_MPLS(ovs_be16 ethertype,
                          enum ofp_version ofp_version OVS_UNUSED,
                          struct ofpbuf *out)
{
    ofpact_put_POP_MPLS(out)->ethertype = ethertype;
    return 0;
}

static void
encode_POP_MPLS(const struct ofpact_pop_mpls *pop_mpls,
                enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_POP_MPLS(out, ofp_version, pop_mpls->ethertype);
}

static char * OVS_WARN_UNUSED_RESULT
parse_POP_MPLS(char *arg, const struct ofpact_parse_params *pp)
{
    uint16_t ethertype;
    char *error;

    error = str_to_u16(arg, "pop_mpls", &ethertype);
    if (!error) {
        ofpact_put_POP_MPLS(pp->ofpacts)->ethertype = htons(ethertype);
    }
    return error;
}

static void
format_POP_MPLS(const struct ofpact_pop_mpls *a,
                const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%spop_mpls:%s0x%04"PRIx16,
                  colors.param, colors.end, ntohs(a->ethertype));
}

/* Set tunnel ID actions. */

static enum ofperr
decode_NXAST_RAW_SET_TUNNEL(uint32_t tun_id,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    struct ofpact_tunnel *tunnel = ofpact_put_SET_TUNNEL(out);
    tunnel->ofpact.raw = NXAST_RAW_SET_TUNNEL;
    tunnel->tun_id = tun_id;
    return 0;
}

static enum ofperr
decode_NXAST_RAW_SET_TUNNEL64(uint64_t tun_id,
                              enum ofp_version ofp_version OVS_UNUSED,
                              struct ofpbuf *out)
{
    struct ofpact_tunnel *tunnel = ofpact_put_SET_TUNNEL(out);
    tunnel->ofpact.raw = NXAST_RAW_SET_TUNNEL64;
    tunnel->tun_id = tun_id;
    return 0;
}

static void
encode_SET_TUNNEL(const struct ofpact_tunnel *tunnel,
                  enum ofp_version ofp_version, struct ofpbuf *out)
{
    uint64_t tun_id = tunnel->tun_id;

    if (ofp_version < OFP12_VERSION) {
        if (tun_id <= UINT32_MAX
            && tunnel->ofpact.raw != NXAST_RAW_SET_TUNNEL64) {
            put_NXAST_SET_TUNNEL(out, tun_id);
        } else {
            put_NXAST_SET_TUNNEL64(out, tun_id);
        }
    } else {
        put_set_field(out, ofp_version, MFF_TUN_ID, tun_id);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_set_tunnel(char *arg, enum ofp_raw_action_type raw,
                 const struct ofpact_parse_params *pp)
{
    struct ofpact_tunnel *tunnel;

    tunnel = ofpact_put_SET_TUNNEL(pp->ofpacts);
    tunnel->ofpact.raw = raw;
    return str_to_u64(arg, &tunnel->tun_id);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_TUNNEL(char *arg, const struct ofpact_parse_params *pp)
{
    return parse_set_tunnel(arg, NXAST_RAW_SET_TUNNEL, pp);
}

static void
format_SET_TUNNEL(const struct ofpact_tunnel *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sset_tunnel%s:%s%#"PRIx64, colors.param,
                  (a->tun_id > UINT32_MAX
                   || a->ofpact.raw == NXAST_RAW_SET_TUNNEL64 ? "64" : ""),
                  colors.end, a->tun_id);
}

/* Set queue action. */

static enum ofperr
decode_OFPAT_RAW_SET_QUEUE(uint32_t queue_id,
                           enum ofp_version ofp_version OVS_UNUSED,
                           struct ofpbuf *out)
{
    ofpact_put_SET_QUEUE(out)->queue_id = queue_id;
    return 0;
}

static void
encode_SET_QUEUE(const struct ofpact_queue *queue,
                 enum ofp_version ofp_version, struct ofpbuf *out)
{
    put_OFPAT_SET_QUEUE(out, ofp_version, queue->queue_id);
}

static char * OVS_WARN_UNUSED_RESULT
parse_SET_QUEUE(char *arg, const struct ofpact_parse_params *pp)
{
    return str_to_u32(arg, &ofpact_put_SET_QUEUE(pp->ofpacts)->queue_id);
}

static void
format_SET_QUEUE(const struct ofpact_queue *a,
                 const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sset_queue:%s%"PRIu32,
                  colors.param, colors.end, a->queue_id);
}

/* Pop queue action. */

static enum ofperr
decode_NXAST_RAW_POP_QUEUE(struct ofpbuf *out)
{
    ofpact_put_POP_QUEUE(out);
    return 0;
}

static void
encode_POP_QUEUE(const struct ofpact_null *null OVS_UNUSED,
                 enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    put_NXAST_POP_QUEUE(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_POP_QUEUE(const char *arg OVS_UNUSED,
                const struct ofpact_parse_params *pp)
{
    ofpact_put_POP_QUEUE(pp->ofpacts);
    return NULL;
}

static void
format_POP_QUEUE(const struct ofpact_null *a OVS_UNUSED,
                 const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%spop_queue%s", colors.value, colors.end);
}

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

static enum ofperr
decode_NXAST_RAW_FIN_TIMEOUT(const struct nx_action_fin_timeout *naft,
                             enum ofp_version ofp_version OVS_UNUSED,
                             struct ofpbuf *out)
{
    struct ofpact_fin_timeout *oft;

    oft = ofpact_put_FIN_TIMEOUT(out);
    oft->fin_idle_timeout = ntohs(naft->fin_idle_timeout);
    oft->fin_hard_timeout = ntohs(naft->fin_hard_timeout);
    return 0;
}

static void
encode_FIN_TIMEOUT(const struct ofpact_fin_timeout *fin_timeout,
                   enum ofp_version ofp_version OVS_UNUSED,
                   struct ofpbuf *out)
{
    struct nx_action_fin_timeout *naft = put_NXAST_FIN_TIMEOUT(out);
    naft->fin_idle_timeout = htons(fin_timeout->fin_idle_timeout);
    naft->fin_hard_timeout = htons(fin_timeout->fin_hard_timeout);
}

static char * OVS_WARN_UNUSED_RESULT
parse_FIN_TIMEOUT(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_fin_timeout *oft = ofpact_put_FIN_TIMEOUT(pp->ofpacts);
    char *key, *value;

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        char *error;

        if (!strcmp(key, "idle_timeout")) {
            error =  str_to_u16(value, key, &oft->fin_idle_timeout);
        } else if (!strcmp(key, "hard_timeout")) {
            error = str_to_u16(value, key, &oft->fin_hard_timeout);
        } else {
            error = xasprintf("invalid key '%s' in 'fin_timeout' argument",
                              key);
        }

        if (error) {
            return error;
        }
    }
    return NULL;
}

static void
format_FIN_TIMEOUT(const struct ofpact_fin_timeout *a,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sfin_timeout(%s", colors.paren, colors.end);
    if (a->fin_idle_timeout) {
        ds_put_format(fp->s, "%sidle_timeout=%s%"PRIu16",",
                      colors.param, colors.end, a->fin_idle_timeout);
    }
    if (a->fin_hard_timeout) {
        ds_put_format(fp->s, "%shard_timeout=%s%"PRIu16",",
                      colors.param, colors.end, a->fin_hard_timeout);
    }
    ds_chomp(fp->s, ',');
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

/* Action structure for NXAST_ENCAP */
struct nx_action_encap {
    ovs_be16 type;         /* OFPAT_VENDOR. */
    ovs_be16 len;          /* Total size including any property TLVs. */
    ovs_be32 vendor;       /* NX_VENDOR_ID. */
    ovs_be16 subtype;      /* NXAST_ENCAP. */
    ovs_be16 hdr_size;     /* Header size in bytes, 0 = 'not specified'.*/
    ovs_be32 new_pkt_type; /* Header type to add and PACKET_TYPE of result. */
    struct ofp_ed_prop_header props[];  /* Encap TLV properties. */
};
OFP_ASSERT(sizeof(struct nx_action_encap) == 16);

static enum ofperr
decode_NXAST_RAW_ENCAP(const struct nx_action_encap *nae,
                       enum ofp_version ofp_version OVS_UNUSED,
                       struct ofpbuf *out)
{
    struct ofpact_encap *encap;
    const struct ofp_ed_prop_header *ofp_prop;
    size_t props_len;
    uint16_t n_props = 0;
    int err;

    encap = ofpact_put_ENCAP(out);
    encap->ofpact.raw = NXAST_RAW_ENCAP;
    switch (ntohl(nae->new_pkt_type)) {
    case PT_ETH:
    case PT_NSH:
        /* Add supported encap header types here. */
        break;
    default:
        return OFPERR_NXBAC_BAD_HEADER_TYPE;
    }
    encap->new_pkt_type = nae->new_pkt_type;
    encap->hdr_size = ntohs(nae->hdr_size);

    ofp_prop = nae->props;
    props_len = ntohs(nae->len) - offsetof(struct nx_action_encap, props);
    n_props = 0;
    while (props_len > 0) {
        err = decode_ed_prop(&ofp_prop, out, &props_len);
        if (err) {
            return err;
        }
        n_props++;
    }
    encap->n_props = n_props;
    out->header = &encap->ofpact;
    ofpact_finish_ENCAP(out, &encap);

    return 0;
}

static void
encode_ENCAP(const struct ofpact_encap *encap,
             enum ofp_version ofp_version OVS_UNUSED,
             struct ofpbuf *out)
{
    size_t start_ofs = out->size;
    struct nx_action_encap *nae = put_NXAST_ENCAP(out);
    int i;

    nae->new_pkt_type = encap->new_pkt_type;
    nae->hdr_size = htons(encap->hdr_size);
    const struct ofpact_ed_prop *prop = encap->props;
    for (i = 0; i < encap->n_props; i++) {
        encode_ed_prop(&prop, out);
    }
    pad_ofpat(out, start_ofs);
}

static bool
parse_encap_header(const char *hdr, ovs_be32 *packet_type)
{
    if (strcmp(hdr, "ethernet") == 0) {
        *packet_type = htonl(PT_ETH);
    } else if (strcmp(hdr, "nsh") == 0) {
        *packet_type = htonl(PT_NSH);
    } else {
        return false;
    }
    return true;
}

static char *
parse_ed_props(const uint16_t prop_class, char **arg, int *n_props, struct ofpbuf *out)
{
    char *key, *value, *err;
    uint8_t prop_type;

    while (ofputil_parse_key_value(arg, &key, &value)) {
        if (!parse_ed_prop_type(prop_class, key, &prop_type)) {
            return xasprintf("Invalid property: %s", key);
        }
        if (value == NULL) {
            return xasprintf("Missing the value for property: %s", key);
        }
        err = parse_ed_prop_value(prop_class, prop_type, value, out);
        if (err != NULL) {
            return err;
        }
        (*n_props)++;
    }
    return NULL;
}

/* The string representation of the encap action is
 * encap(header_type(prop=<value>,tlv(<class>,<type>,<value>),...))
 */

static char * OVS_WARN_UNUSED_RESULT
parse_ENCAP(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_encap *encap;
    char *key, *value, *str;
    char *error = NULL;
    uint16_t prop_class;
    int n_props = 0;

    encap = ofpact_put_ENCAP(pp->ofpacts);
    encap->hdr_size = 0;
    /* Parse encap header type. */
    str = arg;
    if (!ofputil_parse_key_value(&arg, &key, &value)) {
        return xasprintf("Missing encap hdr: %s", str);
    }
    if (!parse_encap_header(key, &encap->new_pkt_type)) {
        return xasprintf("Encap hdr not supported: %s", value);
    }
    if (!parse_ed_prop_class(key, &prop_class)) {
        return xasprintf("Invalid encap prop class: %s", key);
    }
    /* Parse encap properties. */
    error = parse_ed_props(prop_class, &value, &n_props, pp->ofpacts);
    if (error != NULL) {
        return error;
    }
    /* ofpbuf may have been re-allocated. */
    encap = pp->ofpacts->header;
    encap->n_props = n_props;
    ofpact_finish_ENCAP(pp->ofpacts, &encap);
    return NULL;
}

static char *
format_encap_pkt_type(const ovs_be32 pkt_type)
{
    switch (ntohl(pkt_type)) {
    case PT_ETH:
        return "ethernet";
    case PT_NSH:
        return "nsh";
    default:
        return "UNKNOWN";
    }
}

static void
format_ed_props(struct ds *s, uint16_t n_props,
                const struct ofpact_ed_prop *prop)
{
    const uint8_t *p = (uint8_t *) prop;
    int i;

    if (n_props == 0) {
        return;
    }
    for (i = 0; i < n_props; i++) {
        format_ed_prop(s, prop);
        ds_put_char(s, ',');
        p += ROUND_UP(prop->len, 8);
        prop = ALIGNED_CAST(const struct ofpact_ed_prop *, p);
    }
    if (n_props > 0) {
        ds_chomp(s, ',');
    }
}

static void
format_ENCAP(const struct ofpact_encap *a,
             const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sencap(%s", colors.paren, colors.end);
    ds_put_format(fp->s, "%s", format_encap_pkt_type(a->new_pkt_type));
    if (a->n_props > 0) {
        ds_put_format(fp->s, "%s(%s", colors.paren, colors.end);
        format_ed_props(fp->s, a->n_props, a->props);
        ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
    }
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

/* Action structure for NXAST_DECAP */
struct nx_action_decap {
    ovs_be16 type;         /* OFPAT_VENDOR. */
    ovs_be16 len;          /* Total size including any property TLVs. */
    ovs_be32 vendor;       /* NX_VENDOR_ID. */
    ovs_be16 subtype;      /* NXAST_DECAP. */
    uint8_t pad[2];        /* 2 bytes padding */

    /* Packet type or result.
     *
     * The special value (0,0xFFFE) "Use next proto"
     * is used to request OVS to automatically set the new packet type based
     * on the decap'ed header's next protocol.
     */
    ovs_be32 new_pkt_type;
};
OFP_ASSERT(sizeof(struct nx_action_decap) == 16);

static enum ofperr
decode_NXAST_RAW_DECAP(const struct nx_action_decap *nad,
                       enum ofp_version ofp_version OVS_UNUSED,
                       struct ofpbuf *ofpacts)
{
    struct ofpact_decap * decap;

    if (ntohs(nad->len) > sizeof *nad) {
        /* No properties supported yet. */
        return OFPERR_NXBAC_UNKNOWN_ED_PROP;
    }

    decap = ofpact_put_DECAP(ofpacts);
    decap->ofpact.raw = NXAST_RAW_DECAP;
    decap->new_pkt_type = nad->new_pkt_type;
    return 0;
}

static void
encode_DECAP(const struct ofpact_decap *decap,
                enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    struct nx_action_decap *nad = put_NXAST_DECAP(out);

    nad->len = htons(sizeof(struct nx_action_decap));
    nad->new_pkt_type = decap->new_pkt_type;
}

static char * OVS_WARN_UNUSED_RESULT
parse_DECAP(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_decap *decap;
    char *key, *value, *pos;
    char *error = NULL;
    uint16_t ns, type;

    decap = ofpact_put_DECAP(pp->ofpacts);
    /* Default next packet_type is PT_USE_NEXT_PROTO. */
    decap->new_pkt_type = htonl(PT_USE_NEXT_PROTO);

    /* Parse decap packet_type if given. */
    if (ofputil_parse_key_value(&arg, &key, &value)) {
        if (strcmp(key, "packet_type") == 0) {
            pos = value;
            if (!ofputil_parse_key_value(&pos, &key, &value)
                || strcmp(key, "ns") != 0) {
                return xstrdup("Missing packet_type attribute ns");
            }
            error = str_to_u16(value, "ns", &ns);
            if (error) {
                return error;
            }
            if (ns >= OFPHTN_N_TYPES) {
                return xasprintf("Unsupported ns value: %"PRIu16, ns);
            }
            if (!ofputil_parse_key_value(&pos, &key, &value)
                || strcmp(key, "type") != 0) {
                return xstrdup("Missing packet_type attribute type");
            }
            error = str_to_u16(value, "type", &type);
            if (error) {
                return error;
            }
            decap->new_pkt_type = htonl(PACKET_TYPE(ns, type));
        } else {
            return xasprintf("Invalid decap argument: %s", key);
        }
    }
    return NULL;
}

static void
format_DECAP(const struct ofpact_decap *a,
             const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sdecap(%s", colors.paren, colors.end);
    if (a->new_pkt_type != htonl(PT_USE_NEXT_PROTO)) {
        ds_put_format(fp->s, "packet_type(ns=%"PRIu16",id=%#"PRIx16")",
                      pt_ns(a->new_pkt_type),
                      pt_ns_type(a->new_pkt_type));
    }
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

/* Action dec_nsh_ttl */

static enum ofperr
decode_NXAST_RAW_DEC_NSH_TTL(struct ofpbuf *out)
{
    ofpact_put_DEC_NSH_TTL(out);
    return 0;
}

static void
encode_DEC_NSH_TTL(const struct ofpact_null *null OVS_UNUSED,
            enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    put_NXAST_DEC_NSH_TTL(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_DEC_NSH_TTL(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_DEC_NSH_TTL(pp->ofpacts);
    return NULL;
}

static void
format_DEC_NSH_TTL(const struct ofpact_null *a OVS_UNUSED,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sdec_nsh_ttl%s", colors.special, colors.end);
}


/* Action structures for NXAST_RESUBMIT, NXAST_RESUBMIT_TABLE, and
 * NXAST_RESUBMIT_TABLE_CT.
 *
 * These actions search one of the switch's flow tables:
 *
 *    - For NXAST_RESUBMIT_TABLE and NXAST_RESUBMIT_TABLE_CT, if the
 *      'table' member is not 255, then it specifies the table to search.
 *
 *    - Otherwise (for NXAST_RESUBMIT_TABLE or NXAST_RESUBMIT_TABLE_CT with a
 *      'table' of 255, or for NXAST_RESUBMIT regardless of 'table'), it
 *      searches the current flow table, that is, the OpenFlow flow table that
 *      contains the flow from which this action was obtained.  If this action
 *      did not come from a flow table (e.g. it came from an OFPT_PACKET_OUT
 *      message), then table 0 is the current table.
 *
 * The flow table lookup uses a flow that may be slightly modified from the
 * original lookup:
 *
 *    - For NXAST_RESUBMIT, the 'in_port' member of struct nx_action_resubmit
 *      is used as the flow's in_port.
 *
 *    - For NXAST_RESUBMIT_TABLE and NXAST_RESUBMIT_TABLE_CT, if the 'in_port'
 *      member is not OFPP_IN_PORT, then its value is used as the flow's
 *      in_port.  Otherwise, the original in_port is used.
 *
 *    - For NXAST_RESUBMIT_TABLE_CT the Conntrack 5-tuple fields are used as
 *      the packets IP header fields during the lookup.
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
 * Resubmit actions may nest.  To prevent infinite loops and excessive resource
 * use, the implementation may limit nesting depth and the total number of
 * resubmits:
 *
 *    - Open vSwitch 1.0.1 and earlier did not support recursion.
 *
 *    - Open vSwitch 1.0.2 and 1.0.3 limited recursion to 8 levels.
 *
 *    - Open vSwitch 1.1 and 1.2 limited recursion to 16 levels.
 *
 *    - Open vSwitch 1.2 through 1.8 limited recursion to 32 levels.
 *
 *    - Open vSwitch 1.9 through 2.0 limited recursion to 64 levels.
 *
 *    - Open vSwitch 2.1 through 2.5 limited recursion to 64 levels and impose
 *      a total limit of 4,096 resubmits per flow translation (earlier versions
 *      did not impose any total limit).
 *
 * NXAST_RESUBMIT ignores 'table' and 'pad'.  NXAST_RESUBMIT_TABLE and
 * NXAST_RESUBMIT_TABLE_CT require 'pad' to be all-bits-zero.
 *
 * Open vSwitch 1.0.1 and earlier did not support recursion.  Open vSwitch
 * before 1.2.90 did not support NXAST_RESUBMIT_TABLE.  Open vSwitch before
 * 2.8.0 did not support NXAST_RESUBMIT_TABLE_CT.
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

static enum ofperr
decode_NXAST_RAW_RESUBMIT(uint16_t port,
                          enum ofp_version ofp_version OVS_UNUSED,
                          struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.raw = NXAST_RAW_RESUBMIT;
    resubmit->in_port = u16_to_ofp(port);
    resubmit->table_id = 0xff;
    return 0;
}

static enum ofperr
decode_NXAST_RAW_RESUBMIT_TABLE(const struct nx_action_resubmit *nar,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    if (nar->pad[0] || nar->pad[1] || nar->pad[2]) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.raw = NXAST_RAW_RESUBMIT_TABLE;
    resubmit->in_port = u16_to_ofp(ntohs(nar->in_port));
    resubmit->table_id = nar->table;
    return 0;
}

static enum ofperr
decode_NXAST_RAW_RESUBMIT_TABLE_CT(const struct nx_action_resubmit *nar,
                                   enum ofp_version ofp_version OVS_UNUSED,
                                   struct ofpbuf *out)
{
    enum ofperr error = decode_NXAST_RAW_RESUBMIT_TABLE(nar, ofp_version, out);
    if (error) {
        return error;
    }
    struct ofpact_resubmit *resubmit = out->header;
    resubmit->ofpact.raw = NXAST_RAW_RESUBMIT_TABLE_CT;
    resubmit->with_ct_orig = true;
    return 0;
}

static void
encode_RESUBMIT(const struct ofpact_resubmit *resubmit,
                enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    uint16_t in_port = ofp_to_u16(resubmit->in_port);

    if (resubmit->table_id == 0xff
        && resubmit->ofpact.raw == NXAST_RAW_RESUBMIT) {
        put_NXAST_RESUBMIT(out, in_port);
    } else {
        struct nx_action_resubmit *nar;
        nar = resubmit->with_ct_orig
            ? put_NXAST_RESUBMIT_TABLE_CT(out) : put_NXAST_RESUBMIT_TABLE(out);
        nar->table = resubmit->table_id;
        nar->in_port = htons(in_port);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_RESUBMIT(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_resubmit *resubmit;
    char *in_port_s, *table_s, *ct_s;

    resubmit = ofpact_put_RESUBMIT(pp->ofpacts);

    in_port_s = strsep(&arg, ",");
    if (in_port_s && in_port_s[0]) {
        if (!ofputil_port_from_string(in_port_s, pp->port_map,
                                      &resubmit->in_port)) {
            return xasprintf("%s: resubmit to unknown port", in_port_s);
        }
    } else {
        resubmit->in_port = OFPP_IN_PORT;
    }

    table_s = strsep(&arg, ",");
    if (table_s && table_s[0]) {
        if (!ofputil_table_from_string(table_s, pp->table_map,
                                       &resubmit->table_id)) {
            return xasprintf("%s: resubmit to unknown table", table_s);
        }
    } else {
        resubmit->table_id = 255;
    }

    ct_s = strsep(&arg, ",");
    if (ct_s && ct_s[0]) {
        if (strcmp(ct_s, "ct")) {
            return xasprintf("%s: unknown parameter", ct_s);
        }
        resubmit->with_ct_orig = true;
    } else {
        resubmit->with_ct_orig = false;
    }

    if (resubmit->in_port == OFPP_IN_PORT && resubmit->table_id == 255) {
        return xstrdup("at least one \"in_port\" or \"table\" must be "
                       "specified  on resubmit");
    }
    return NULL;
}

static void
format_RESUBMIT(const struct ofpact_resubmit *a,
                const struct ofpact_format_params *fp)
{
    if (a->in_port != OFPP_IN_PORT && a->table_id == 255) {
        ds_put_format(fp->s, "%sresubmit:%s", colors.special, colors.end);
        ofputil_format_port(a->in_port, fp->port_map, fp->s);
    } else {
        ds_put_format(fp->s, "%sresubmit(%s", colors.paren, colors.end);
        if (a->in_port != OFPP_IN_PORT) {
            ofputil_format_port(a->in_port, fp->port_map, fp->s);
        }
        ds_put_char(fp->s, ',');
        if (a->table_id != 255) {
            ofputil_format_table(a->table_id, fp->table_map, fp->s);
        }
        if (a->with_ct_orig) {
            ds_put_cstr(fp->s, ",ct");
        }
        ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
    }
}

/* Action structure for NXAST_LEARN and NXAST_LEARN2.
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
 *
 *
 * Visibility of Changes
 * ---------------------
 *
 * Prior to Open vSwitch 2.4, any changes made by a "learn" action in a given
 * flow translation are visible to flow table lookups made later in the flow
 * translation.  This means that, in the example above, a MAC learned by the
 * learn action in table 0 would be found in table 1 (if the packet being
 * processed had the same source and destination MAC address).
 *
 * In Open vSwitch 2.4 and later, changes to a flow table (whether to add or
 * modify a flow) by a "learn" action are visible only for later flow
 * translations, not for later lookups within the same flow translation.  In
 * the MAC learning example, a MAC learned by the learn action in table 0 would
 * not be found in table 1 if the flow translation would resubmit to table 1
 * after the processing of the learn action, meaning that if this MAC had not
 * been learned before then the packet would be flooded. */
struct nx_action_learn {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* At least 24. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_LEARN. */
    ovs_be16 idle_timeout;      /* Idle time before discarding (seconds). */
    ovs_be16 hard_timeout;      /* Max time before discarding (seconds). */
    ovs_be16 priority;          /* Priority level of flow entry. */
    ovs_be64 cookie;            /* Cookie for new flow. */
    ovs_be16 flags;             /* NX_LEARN_F_*. */
    uint8_t table_id;           /* Table to insert flow entry. */
    uint8_t pad;                /* Must be zero. */
    ovs_be16 fin_idle_timeout;  /* Idle timeout after FIN, if nonzero. */
    ovs_be16 fin_hard_timeout;  /* Hard timeout after FIN, if nonzero. */
    /* Followed by a sequence of flow_mod_spec elements, as described above,
     * until the end of the action is reached. */
};
OFP_ASSERT(sizeof(struct nx_action_learn) == 32);

struct nx_action_learn2 {
    struct nx_action_learn up;  /* The wire format includes nx_action_learn. */
    ovs_be32 limit;             /* Maximum number of learned flows.
                                 * 0 indicates unlimited. */

    /* Where to store the result. */
    ovs_be16 result_dst_ofs;    /* Starting bit offset in destination. */

    ovs_be16 pad2;              /* Must be zero. */
    /* Followed by:
     * - OXM/NXM header for destination field (4 or 8 bytes),
     *   if NX_LEARN_F_WRITE_RESULT is set in 'flags'
     * - a sequence of flow_mod_spec elements, as described above,
     *   until the end of the action is reached. */
};
OFP_ASSERT(sizeof(struct nx_action_learn2) == 40);

static ovs_be16
get_be16(const void **pp)
{
    const ovs_be16 *p = *pp;
    ovs_be16 value = *p;
    *pp = p + 1;
    return value;
}

static ovs_be32
get_be32(const void **pp)
{
    const ovs_be32 *p = *pp;
    ovs_be32 value = get_unaligned_be32(p);
    *pp = p + 1;
    return value;
}

static enum ofperr
get_subfield(int n_bits, const void **p, struct mf_subfield *sf,
             const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap)
{
    enum ofperr error;

    error = mf_vl_mff_mf_from_nxm_header(ntohl(get_be32(p)), vl_mff_map,
                                         &sf->field, tlv_bitmap);
    sf->ofs = ntohs(get_be16(p));
    sf->n_bits = n_bits;
    return error;
}

static unsigned int
learn_min_len(uint16_t header)
{
    int n_bits = header & NX_LEARN_N_BITS_MASK;
    int src_type = header & NX_LEARN_SRC_MASK;
    int dst_type = header & NX_LEARN_DST_MASK;
    unsigned int min_len;

    min_len = 0;
    if (src_type == NX_LEARN_SRC_FIELD) {
        min_len += sizeof(ovs_be32); /* src_field */
        min_len += sizeof(ovs_be16); /* src_ofs */
    } else {
        min_len += 2 * DIV_ROUND_UP(n_bits, 16);
    }
    if (dst_type == NX_LEARN_DST_MATCH ||
        dst_type == NX_LEARN_DST_LOAD) {
        min_len += sizeof(ovs_be32); /* dst_field */
        min_len += sizeof(ovs_be16); /* dst_ofs */
    }
    return min_len;
}

static enum ofperr
decode_LEARN_common(const struct nx_action_learn *nal,
                    enum ofp_raw_action_type raw,
                    struct ofpact_learn *learn)
{
    if (nal->pad) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    learn->ofpact.raw = raw;
    learn->idle_timeout = ntohs(nal->idle_timeout);
    learn->hard_timeout = ntohs(nal->hard_timeout);
    learn->priority = ntohs(nal->priority);
    learn->cookie = nal->cookie;
    learn->table_id = nal->table_id;
    learn->fin_idle_timeout = ntohs(nal->fin_idle_timeout);
    learn->fin_hard_timeout = ntohs(nal->fin_hard_timeout);
    learn->flags = ntohs(nal->flags);

    if (learn->table_id == 0xff) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

static enum ofperr
decode_LEARN_specs(const void *p, const void *end,
                   const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap,
                   struct ofpbuf *ofpacts)
{
    struct ofpact_learn *learn = ofpacts->header;

    while (p != end) {
        struct ofpact_learn_spec *spec;
        uint16_t header = ntohs(get_be16(&p));

        if (!header) {
            break;
        }

        spec = ofpbuf_put_zeros(ofpacts, sizeof *spec);
        learn = ofpacts->header;

        spec->src_type = header & NX_LEARN_SRC_MASK;
        spec->dst_type = header & NX_LEARN_DST_MASK;
        spec->n_bits = header & NX_LEARN_N_BITS_MASK;

        /* Check for valid src and dst type combination. */
        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD ||
            (spec->dst_type == NX_LEARN_DST_OUTPUT &&
             spec->src_type == NX_LEARN_SRC_FIELD)) {
            /* OK. */
        } else {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }

        /* Check that the arguments don't overrun the end of the action. */
        if ((char *) end - (char *) p < learn_min_len(header)) {
            return OFPERR_OFPBAC_BAD_LEN;
        }

        /* Get the source. */
        const uint8_t *imm = NULL;
        unsigned int imm_bytes = 0;
        enum ofperr error;
        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            error = get_subfield(spec->n_bits, &p, &spec->src, vl_mff_map,
                                 tlv_bitmap);
            if (error) {
                return error;
            }
        } else {
            int p_bytes = 2 * DIV_ROUND_UP(spec->n_bits, 16);
            p = (const uint8_t *) p + p_bytes;

            imm_bytes = DIV_ROUND_UP(spec->n_bits, 8);
            imm = (const uint8_t *) p - imm_bytes;
        }

        /* Get the destination. */
        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD) {
            error = get_subfield(spec->n_bits, &p, &spec->dst, vl_mff_map,
                                 tlv_bitmap);
            if (error) {
                return error;
            }
        }

        if (imm) {
            uint8_t *src_imm = ofpbuf_put_zeros(ofpacts,
                                                OFPACT_ALIGN(imm_bytes));
            memcpy(src_imm, imm, imm_bytes);

            learn = ofpacts->header;
        }
    }
    ofpact_finish_LEARN(ofpacts, &learn);

    if (!is_all_zeros(p, (char *) end - (char *) p)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

/* Converts 'nal' into a "struct ofpact_learn" and appends that struct to
 * 'ofpacts'.  Returns 0 if successful, otherwise an OFPERR_*. */
static enum ofperr
decode_NXAST_RAW_LEARN(const struct nx_action_learn *nal,
                       enum ofp_version ofp_version OVS_UNUSED,
                       const struct vl_mff_map *vl_mff_map,
                       uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpact_learn *learn;
    enum ofperr error;

    learn = ofpact_put_LEARN(ofpacts);

    error = decode_LEARN_common(nal, NXAST_RAW_LEARN, learn);
    if (error) {
        return error;
    }

    if (learn->flags & ~(NX_LEARN_F_SEND_FLOW_REM |
                         NX_LEARN_F_DELETE_LEARNED)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return decode_LEARN_specs(nal + 1, (char *) nal + ntohs(nal->len),
                              vl_mff_map, tlv_bitmap, ofpacts);
}

/* Converts 'nal' into a "struct ofpact_learn" and appends that struct to
 * 'ofpacts'.  Returns 0 if successful, otherwise an OFPERR_*. */
static enum ofperr
decode_NXAST_RAW_LEARN2(const struct nx_action_learn2 *nal,
                        enum ofp_version ofp_version OVS_UNUSED,
                        const struct vl_mff_map *vl_mff_map,
                        uint64_t *tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpbuf b = ofpbuf_const_initializer(nal, ntohs(nal->up.len));
    struct ofpact_learn *learn;
    enum ofperr error;

    if (nal->pad2) {
        return OFPERR_NXBAC_MUST_BE_ZERO;
    }

    learn = ofpact_put_LEARN(ofpacts);
    error = decode_LEARN_common(&nal->up, NXAST_RAW_LEARN2, learn);
    if (error) {
        return error;
    }

    learn->limit = ntohl(nal->limit);

    if (learn->flags & ~(NX_LEARN_F_SEND_FLOW_REM |
                         NX_LEARN_F_DELETE_LEARNED |
                         NX_LEARN_F_WRITE_RESULT)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    ofpbuf_pull(&b, sizeof *nal);

    if (learn->flags & NX_LEARN_F_WRITE_RESULT) {
        error = nx_pull_header(&b, vl_mff_map, &learn->result_dst.field, NULL);
        if (error) {
            return error;
        }
        if (!learn->result_dst.field->writable) {
            return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
        }
        learn->result_dst.ofs = ntohs(nal->result_dst_ofs);
        learn->result_dst.n_bits = 1;
    } else if (nal->result_dst_ofs) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return decode_LEARN_specs(b.data, (char *) nal + ntohs(nal->up.len),
                              vl_mff_map, tlv_bitmap, ofpacts);
}

static void
put_be16(struct ofpbuf *b, ovs_be16 x)
{
    ofpbuf_put(b, &x, sizeof x);
}

static void
put_be32(struct ofpbuf *b, ovs_be32 x)
{
    ofpbuf_put(b, &x, sizeof x);
}

static void
put_u16(struct ofpbuf *b, uint16_t x)
{
    put_be16(b, htons(x));
}

static void
put_u32(struct ofpbuf *b, uint32_t x)
{
    put_be32(b, htonl(x));
}

static void
encode_LEARN(const struct ofpact_learn *learn,
             enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    const struct ofpact_learn_spec *spec;
    struct nx_action_learn *nal;
    size_t start_ofs;

    start_ofs = out->size;

    if (learn->ofpact.raw == NXAST_RAW_LEARN2
        || learn->limit != 0
        || learn->flags & NX_LEARN_F_WRITE_RESULT) {
        struct nx_action_learn2 *nal2;

        nal2 = put_NXAST_LEARN2(out);
        nal2->limit = htonl(learn->limit);
        nal2->result_dst_ofs = htons(learn->result_dst.ofs);
        nal = &nal2->up;
    } else {
        nal = put_NXAST_LEARN(out);
    }
    nal->idle_timeout = htons(learn->idle_timeout);
    nal->hard_timeout = htons(learn->hard_timeout);
    nal->fin_idle_timeout = htons(learn->fin_idle_timeout);
    nal->fin_hard_timeout = htons(learn->fin_hard_timeout);
    nal->priority = htons(learn->priority);
    nal->cookie = learn->cookie;
    nal->flags = htons(learn->flags);
    nal->table_id = learn->table_id;

    if (learn->flags & NX_LEARN_F_WRITE_RESULT) {
        nx_put_header(out, learn->result_dst.field->id, 0, false);
    }

    OFPACT_LEARN_SPEC_FOR_EACH (spec, learn) {
        put_u16(out, spec->n_bits | spec->dst_type | spec->src_type);

        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            put_u32(out, nxm_header_from_mff(spec->src.field));
            put_u16(out, spec->src.ofs);
        } else {
            size_t n_dst_bytes = 2 * DIV_ROUND_UP(spec->n_bits, 16);
            uint8_t *bits = ofpbuf_put_zeros(out, n_dst_bytes);
            unsigned int n_bytes = DIV_ROUND_UP(spec->n_bits, 8);

            memcpy(bits + n_dst_bytes - n_bytes, ofpact_learn_spec_imm(spec),
                   n_bytes);
        }

        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD) {
            put_u32(out, nxm_header_from_mff(spec->dst.field));
            put_u16(out, spec->dst.ofs);
        }
    }

    pad_ofpat(out, start_ofs);
}

static char * OVS_WARN_UNUSED_RESULT
parse_LEARN(char *arg, const struct ofpact_parse_params *pp)
{
    return learn_parse(arg, pp->port_map, pp->table_map, pp->ofpacts);
}

static void
format_LEARN(const struct ofpact_learn *a,
             const struct ofpact_format_params *fp)
{
    learn_format(a, fp->port_map, fp->table_map, fp->s);
}

/* Action structure for NXAST_CONJUNCTION. */
struct nx_action_conjunction {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* At least 16. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* See enum ofp_raw_action_type. */
    uint8_t clause;
    uint8_t n_clauses;
    ovs_be32 id;
};
OFP_ASSERT(sizeof(struct nx_action_conjunction) == 16);

static void
add_conjunction(struct ofpbuf *out,
                uint32_t id, uint8_t clause, uint8_t n_clauses)
{
    struct ofpact_conjunction *oc;

    oc = ofpact_put_CONJUNCTION(out);
    oc->id = id;
    oc->clause = clause;
    oc->n_clauses = n_clauses;
}

static enum ofperr
decode_NXAST_RAW_CONJUNCTION(const struct nx_action_conjunction *nac,
                             enum ofp_version ofp_version OVS_UNUSED,
                             struct ofpbuf *out)
{
    if (nac->n_clauses < 2 || nac->n_clauses > 64
        || nac->clause >= nac->n_clauses) {
        return OFPERR_NXBAC_BAD_CONJUNCTION;
    } else {
        add_conjunction(out, ntohl(nac->id), nac->clause, nac->n_clauses);
        return 0;
    }
}

static void
encode_CONJUNCTION(const struct ofpact_conjunction *oc,
                   enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    struct nx_action_conjunction *nac = put_NXAST_CONJUNCTION(out);
    nac->clause = oc->clause;
    nac->n_clauses = oc->n_clauses;
    nac->id = htonl(oc->id);
}

static void
format_CONJUNCTION(const struct ofpact_conjunction *oc,
                   const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sconjunction(%s%"PRIu32",%d/%"PRIu8"%s)%s",
                  colors.paren, colors.end,
                  oc->id, oc->clause + 1, oc->n_clauses,
                  colors.paren, colors.end);
}

static char * OVS_WARN_UNUSED_RESULT
parse_CONJUNCTION(const char *arg, const struct ofpact_parse_params *pp)
{
    uint8_t n_clauses;
    uint8_t clause;
    uint32_t id;
    int n;

    if (!ovs_scan(arg, "%"SCNi32" , %"SCNu8" / %"SCNu8" %n",
                  &id, &clause, &n_clauses, &n) || n != strlen(arg)) {
        return xstrdup("\"conjunction\" syntax is \"conjunction(id,i/n)\"");
    }

    if (n_clauses < 2) {
        return xstrdup("conjunction must have at least 2 clauses");
    } else if (n_clauses > 64) {
        return xstrdup("conjunction must have at most 64 clauses");
    } else if (clause < 1) {
        return xstrdup("clause index must be positive");
    } else if (clause > n_clauses) {
        return xstrdup("clause index must be less than or equal to "
                       "number of clauses");
    }

    add_conjunction(pp->ofpacts, id, clause - 1, n_clauses);
    return NULL;
}

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

static enum ofperr
decode_NXAST_RAW_MULTIPATH(const struct nx_action_multipath *nam,
                           enum ofp_version ofp_version OVS_UNUSED,
                           const struct vl_mff_map *vl_mff_map,
                           uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    uint32_t n_links = ntohs(nam->max_link) + 1;
    size_t min_n_bits = log_2_ceil(n_links);
    struct ofpact_multipath *mp;
    enum ofperr error;

    mp = ofpact_put_MULTIPATH(out);
    mp->fields = ntohs(nam->fields);
    mp->basis = ntohs(nam->basis);
    mp->algorithm = ntohs(nam->algorithm);
    mp->max_link = ntohs(nam->max_link);
    mp->arg = ntohl(nam->arg);
    mp->dst.ofs = nxm_decode_ofs(nam->ofs_nbits);
    mp->dst.n_bits = nxm_decode_n_bits(nam->ofs_nbits);
    error = mf_vl_mff_mf_from_nxm_header(ntohl(nam->dst), vl_mff_map,
                                         &mp->dst.field, tlv_bitmap);
    if (error) {
        return error;
    }

    if (!flow_hash_fields_valid(mp->fields)) {
        VLOG_WARN_RL(&rl, "unsupported fields %d", (int) mp->fields);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else if (mp->algorithm != NX_MP_ALG_MODULO_N
               && mp->algorithm != NX_MP_ALG_HASH_THRESHOLD
               && mp->algorithm != NX_MP_ALG_HRW
               && mp->algorithm != NX_MP_ALG_ITER_HASH) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %d", (int) mp->algorithm);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else if (mp->dst.n_bits < min_n_bits) {
        VLOG_WARN_RL(&rl, "multipath action requires at least %"PRIuSIZE" bits for "
                     "%"PRIu32" links", min_n_bits, n_links);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return multipath_check(mp, NULL);
}

static void
encode_MULTIPATH(const struct ofpact_multipath *mp,
                 enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    struct nx_action_multipath *nam = put_NXAST_MULTIPATH(out);

    nam->fields = htons(mp->fields);
    nam->basis = htons(mp->basis);
    nam->algorithm = htons(mp->algorithm);
    nam->max_link = htons(mp->max_link);
    nam->arg = htonl(mp->arg);
    nam->ofs_nbits = nxm_encode_ofs_nbits(mp->dst.ofs, mp->dst.n_bits);
    nam->dst = htonl(nxm_header_from_mff(mp->dst.field));
}

static char * OVS_WARN_UNUSED_RESULT
parse_MULTIPATH(const char *arg, const struct ofpact_parse_params *pp)
{
    return multipath_parse(ofpact_put_MULTIPATH(pp->ofpacts), arg);
}

static void
format_MULTIPATH(const struct ofpact_multipath *a,
                 const struct ofpact_format_params *fp)
{
    multipath_format(a, fp->s);
}

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

static enum ofperr
decode_NXAST_RAW_NOTE(const struct nx_action_note *nan,
                      enum ofp_version ofp_version OVS_UNUSED,
                      struct ofpbuf *out)
{
    struct ofpact_note *note;
    unsigned int length;

    length = ntohs(nan->len) - offsetof(struct nx_action_note, note);
    note = ofpact_put_NOTE(out);
    note->length = length;
    ofpbuf_put(out, nan->note, length);
    note = out->header;
    ofpact_finish_NOTE(out, &note);

    return 0;
}

static void
encode_NOTE(const struct ofpact_note *note,
            enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    size_t start_ofs = out->size;
    struct nx_action_note *nan;

    put_NXAST_NOTE(out);
    out->size = out->size - sizeof nan->note;

    ofpbuf_put(out, note->data, note->length);
    pad_ofpat(out, start_ofs);
}

static char * OVS_WARN_UNUSED_RESULT
parse_NOTE(const char *arg, const struct ofpact_parse_params *pp)
{
    size_t start_ofs = pp->ofpacts->size;
    ofpact_put_NOTE(pp->ofpacts);
    arg = ofpbuf_put_hex(pp->ofpacts, arg, NULL);
    if (arg[0]) {
        return xstrdup("bad hex digit in `note' argument");
    }
    struct ofpact_note *note = ofpbuf_at_assert(pp->ofpacts, start_ofs,
                                                sizeof *note);
    note->length = pp->ofpacts->size - (start_ofs + sizeof *note);
    ofpact_finish_NOTE(pp->ofpacts, &note);
    return NULL;
}

static void
format_NOTE(const struct ofpact_note *a,
            const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%snote:%s", colors.param, colors.end);
    format_hex_arg(fp->s, a->data, a->length);
}

/* Exit action. */

static enum ofperr
decode_NXAST_RAW_EXIT(struct ofpbuf *out)
{
    ofpact_put_EXIT(out);
    return 0;
}

static void
encode_EXIT(const struct ofpact_null *null OVS_UNUSED,
            enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    put_NXAST_EXIT(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_EXIT(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_EXIT(pp->ofpacts);
    return NULL;
}

static void
format_EXIT(const struct ofpact_null *a OVS_UNUSED,
            const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sexit%s", colors.special, colors.end);
}

/* Unroll xlate action. */

static void
encode_UNROLL_XLATE(const struct ofpact_unroll_xlate *unroll OVS_UNUSED,
                    enum ofp_version ofp_version OVS_UNUSED,
                    struct ofpbuf *out OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

static char * OVS_WARN_UNUSED_RESULT
parse_UNROLL_XLATE(char *arg OVS_UNUSED,
                   const struct ofpact_parse_params *pp OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

static void
format_UNROLL_XLATE(const struct ofpact_unroll_xlate *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sunroll_xlate(%s%stable=%s",
                  colors.paren,   colors.end,
                  colors.special, colors.end);
    ofputil_format_table(a->rule_table_id, fp->table_map, fp->s);
    ds_put_format(fp->s, ", %scookie=%s%"PRIu64"%s)%s",
                  colors.param,   colors.end, ntohll(a->rule_cookie),
                  colors.paren,   colors.end);
}

/* The NXAST_CLONE action is "struct ext_action_header", followed by zero or
 * more embedded OpenFlow actions. */

static enum ofperr
decode_NXAST_RAW_CLONE(const struct ext_action_header *eah,
                       enum ofp_version ofp_version,
                       const struct vl_mff_map *vl_mff_map,
                       uint64_t *tlv_bitmap, struct ofpbuf *out)
{
    int error;
    struct ofpbuf openflow;
    const size_t clone_offset = ofpacts_pull(out);
    struct ofpact_nest *clone = ofpact_put_CLONE(out);

    /* decode action list */
    ofpbuf_pull(out, sizeof(*clone));
    openflow = ofpbuf_const_initializer(
                    eah + 1, ntohs(eah->len) - sizeof *eah);
    error = ofpacts_pull_openflow_actions__(&openflow, openflow.size,
                                            ofp_version,
                                            1u << OVSINST_OFPIT11_APPLY_ACTIONS,
                                            out, 0, vl_mff_map, tlv_bitmap);
    clone = ofpbuf_push_uninit(out, sizeof *clone);
    out->header = &clone->ofpact;
    ofpact_finish_CLONE(out, &clone);
    ofpbuf_push_uninit(out, clone_offset);
    return error;
}

static void
encode_CLONE(const struct ofpact_nest *clone,
              enum ofp_version ofp_version, struct ofpbuf *out)
{
    size_t len;
    const size_t ofs = out->size;
    struct ext_action_header *eah;

    put_NXAST_CLONE(out);
    len = ofpacts_put_openflow_actions(clone->actions,
                                       ofpact_nest_get_action_len(clone),
                                       out, ofp_version);
    len += sizeof *eah;
    eah = ofpbuf_at(out, ofs, sizeof *eah);
    eah->len = htons(len);
}

static char * OVS_WARN_UNUSED_RESULT
parse_CLONE(char *arg, const struct ofpact_parse_params *pp)
{
    const size_t clone_offset = ofpacts_pull(pp->ofpacts);
    struct ofpact_nest *clone = ofpact_put_CLONE(pp->ofpacts);
    char *error;

    ofpbuf_pull(pp->ofpacts, sizeof *clone);
    error = ofpacts_parse_copy(arg, pp, false, 0);
    /* header points to the action list */
    pp->ofpacts->header = ofpbuf_push_uninit(pp->ofpacts, sizeof *clone);
    clone = pp->ofpacts->header;

    ofpact_finish_CLONE(pp->ofpacts, &clone);
    ofpbuf_push_uninit(pp->ofpacts, clone_offset);
    return error;
}

static void
format_CLONE(const struct ofpact_nest *a,
             const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sclone(%s", colors.paren, colors.end);
    ofpacts_format(a->actions, ofpact_nest_get_action_len(a), fp);
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

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

/* Action structure for NXAST_SAMPLE2 and NXAST_SAMPLE3.
 *
 * NXAST_SAMPLE2 was added in Open vSwitch 2.5.90.  Compared to NXAST_SAMPLE,
 * it adds support for exporting egress tunnel information.
 *
 * NXAST_SAMPLE3 was added in Open vSwitch 2.6.90.  Compared to NXAST_SAMPLE2,
 * it adds support for the 'direction' field. */
struct nx_action_sample2 {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 32. */
    ovs_be32 vendor;                /* NX_VENDOR_ID. */
    ovs_be16 subtype;               /* NXAST_SAMPLE. */
    ovs_be16 probability;           /* Fraction of packets to sample. */
    ovs_be32 collector_set_id;      /* ID of collector set in OVSDB. */
    ovs_be32 obs_domain_id;         /* ID of sampling observation domain. */
    ovs_be32 obs_point_id;          /* ID of sampling observation point. */
    ovs_be16 sampling_port;         /* Sampling port. */
    uint8_t  direction;             /* NXAST_SAMPLE3 only. */
    uint8_t  zeros[5];              /* Pad to a multiple of 8 bytes */
 };
 OFP_ASSERT(sizeof(struct nx_action_sample2) == 32);

static enum ofperr
decode_NXAST_RAW_SAMPLE(const struct nx_action_sample *nas,
                        enum ofp_version ofp_version OVS_UNUSED,
                        struct ofpbuf *out)
{
    struct ofpact_sample *sample;

    sample = ofpact_put_SAMPLE(out);
    sample->ofpact.raw = NXAST_RAW_SAMPLE;
    sample->probability = ntohs(nas->probability);
    sample->collector_set_id = ntohl(nas->collector_set_id);
    sample->obs_domain_id = ntohl(nas->obs_domain_id);
    sample->obs_point_id = ntohl(nas->obs_point_id);
    sample->sampling_port = OFPP_NONE;
    sample->direction = NX_ACTION_SAMPLE_DEFAULT;

    if (sample->probability == 0) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

static enum ofperr
decode_SAMPLE2(const struct nx_action_sample2 *nas,
               enum ofp_raw_action_type raw,
               enum nx_action_sample_direction direction,
               struct ofpact_sample *sample)
{
    sample->ofpact.raw = raw;
    sample->probability = ntohs(nas->probability);
    sample->collector_set_id = ntohl(nas->collector_set_id);
    sample->obs_domain_id = ntohl(nas->obs_domain_id);
    sample->obs_point_id = ntohl(nas->obs_point_id);
    sample->sampling_port = u16_to_ofp(ntohs(nas->sampling_port));
    sample->direction = direction;

    if (sample->probability == 0) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

static enum ofperr
decode_NXAST_RAW_SAMPLE2(const struct nx_action_sample2 *nas,
                         enum ofp_version ofp_version OVS_UNUSED,
                         struct ofpbuf *out)
{
    return decode_SAMPLE2(nas, NXAST_RAW_SAMPLE2, NX_ACTION_SAMPLE_DEFAULT,
                          ofpact_put_SAMPLE(out));
}

static enum ofperr
decode_NXAST_RAW_SAMPLE3(const struct nx_action_sample2 *nas,
                         enum ofp_version ofp_version OVS_UNUSED,
                         struct ofpbuf *out)
{
    struct ofpact_sample *sample = ofpact_put_SAMPLE(out);
    if (!is_all_zeros(nas->zeros, sizeof nas->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }
    if (nas->direction != NX_ACTION_SAMPLE_DEFAULT &&
        nas->direction != NX_ACTION_SAMPLE_INGRESS &&
        nas->direction != NX_ACTION_SAMPLE_EGRESS) {
        VLOG_WARN_RL(&rl, "invalid sample direction %"PRIu8, nas->direction);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    return decode_SAMPLE2(nas, NXAST_RAW_SAMPLE3, nas->direction, sample);
}

static void
encode_SAMPLE2(const struct ofpact_sample *sample,
               struct nx_action_sample2 *nas)
{
    nas->probability = htons(sample->probability);
    nas->collector_set_id = htonl(sample->collector_set_id);
    nas->obs_domain_id = htonl(sample->obs_domain_id);
    nas->obs_point_id = htonl(sample->obs_point_id);
    nas->sampling_port = htons(ofp_to_u16(sample->sampling_port));
    nas->direction = sample->direction;
}

static void
encode_SAMPLE(const struct ofpact_sample *sample,
              enum ofp_version ofp_version OVS_UNUSED, struct ofpbuf *out)
{
    if (sample->ofpact.raw == NXAST_RAW_SAMPLE3
        || sample->direction != NX_ACTION_SAMPLE_DEFAULT) {
        encode_SAMPLE2(sample, put_NXAST_SAMPLE3(out));
    } else if (sample->ofpact.raw == NXAST_RAW_SAMPLE2
               || sample->sampling_port != OFPP_NONE) {
        encode_SAMPLE2(sample, put_NXAST_SAMPLE2(out));
    } else {
        struct nx_action_sample *nas = put_NXAST_SAMPLE(out);
        nas->probability = htons(sample->probability);
        nas->collector_set_id = htonl(sample->collector_set_id);
        nas->obs_domain_id = htonl(sample->obs_domain_id);
        nas->obs_point_id = htonl(sample->obs_point_id);
    }
}

/* Parses 'arg' as the argument to a "sample" action, and appends such an
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_SAMPLE(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_sample *os = ofpact_put_SAMPLE(pp->ofpacts);
    os->sampling_port = OFPP_NONE;
    os->direction = NX_ACTION_SAMPLE_DEFAULT;

    char *key, *value;
    while (ofputil_parse_key_value(&arg, &key, &value)) {
        char *error = NULL;

        if (!strcmp(key, "probability")) {
            error = str_to_u16(value, "probability", &os->probability);
            if (!error && os->probability == 0) {
                error = xasprintf("invalid probability value \"%s\"", value);
            }
        } else if (!strcmp(key, "collector_set_id")) {
            error = str_to_u32(value, &os->collector_set_id);
        } else if (!strcmp(key, "obs_domain_id")) {
            error = str_to_u32(value, &os->obs_domain_id);
        } else if (!strcmp(key, "obs_point_id")) {
            error = str_to_u32(value, &os->obs_point_id);
        } else if (!strcmp(key, "sampling_port")) {
            if (!ofputil_port_from_string(value, pp->port_map,
                                          &os->sampling_port)) {
                error = xasprintf("%s: unknown port", value);
            }
        } else if (!strcmp(key, "ingress")) {
            os->direction = NX_ACTION_SAMPLE_INGRESS;
        } else if (!strcmp(key, "egress")) {
            os->direction = NX_ACTION_SAMPLE_EGRESS;
        } else {
            error = xasprintf("invalid key \"%s\" in \"sample\" argument",
                              key);
        }
        if (error) {
            return error;
        }
    }
    if (os->probability == 0) {
        return xstrdup("non-zero \"probability\" must be specified on sample");
    }

    return NULL;
}

static void
format_SAMPLE(const struct ofpact_sample *a,
              const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%ssample(%s%sprobability=%s%"PRIu16
                  ",%scollector_set_id=%s%"PRIu32
                  ",%sobs_domain_id=%s%"PRIu32
                  ",%sobs_point_id=%s%"PRIu32,
                  colors.paren, colors.end,
                  colors.param, colors.end, a->probability,
                  colors.param, colors.end, a->collector_set_id,
                  colors.param, colors.end, a->obs_domain_id,
                  colors.param, colors.end, a->obs_point_id);
    if (a->sampling_port != OFPP_NONE) {
        ds_put_format(fp->s, ",%ssampling_port=%s", colors.param, colors.end);
        ofputil_format_port(a->sampling_port, fp->port_map, fp->s);
    }
    if (a->direction == NX_ACTION_SAMPLE_INGRESS) {
        ds_put_format(fp->s, ",%singress%s", colors.param, colors.end);
    } else if (a->direction == NX_ACTION_SAMPLE_EGRESS) {
        ds_put_format(fp->s, ",%segress%s", colors.param, colors.end);
    }
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

/* debug instructions. */

static bool enable_debug;

void
ofpact_dummy_enable(void)
{
    enable_debug = true;
}

static enum ofperr
decode_NXAST_RAW_DEBUG_RECIRC(struct ofpbuf *out)
{
    if (!enable_debug) {
        return OFPERR_OFPBAC_BAD_VENDOR_TYPE;
    }

    ofpact_put_DEBUG_RECIRC(out);
    return 0;
}

static void
encode_DEBUG_RECIRC(const struct ofpact_null *n OVS_UNUSED,
                    enum ofp_version ofp_version OVS_UNUSED,
                    struct ofpbuf *out)
{
    put_NXAST_DEBUG_RECIRC(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_DEBUG_RECIRC(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_DEBUG_RECIRC(pp->ofpacts);
    return NULL;
}

static void
format_DEBUG_RECIRC(const struct ofpact_null *a OVS_UNUSED,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sdebug_recirc%s", colors.value, colors.end);
}

static enum ofperr
decode_NXAST_RAW_DEBUG_SLOW(struct ofpbuf *out)
{
    if (!enable_debug) {
        return OFPERR_OFPBAC_BAD_VENDOR_TYPE;
    }

    ofpact_put_DEBUG_SLOW(out);
    return 0;
}

static void
encode_DEBUG_SLOW(const struct ofpact_null *n OVS_UNUSED,
                  enum ofp_version ofp_version OVS_UNUSED,
                  struct ofpbuf *out)
{
    put_NXAST_DEBUG_SLOW(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_DEBUG_SLOW(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_DEBUG_SLOW(pp->ofpacts);
    return NULL;
}

static void
format_DEBUG_SLOW(const struct ofpact_null *a OVS_UNUSED,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sdebug_slow%s", colors.value, colors.end);
}

/* Action structure for NXAST_CT.
 *
 * Pass traffic to the connection tracker.
 *
 * There are two important concepts to understanding the connection tracking
 * interface: Packet state and Connection state. Packets may be "Untracked" or
 * "Tracked". Connections may be "Uncommitted" or "Committed".
 *
 *   - Packet State:
 *
 *      Untracked packets have an unknown connection state.  In most
 *      cases, packets entering the OpenFlow pipeline will initially be
 *      in the untracked state. Untracked packets may become tracked by
 *      executing NXAST_CT with a "recirc_table" specified. This makes
 *      various aspects about the connection available, in particular
 *      the connection state.
 *
 *      An NXAST_CT action always puts the packet into an untracked
 *      state for the current processing path.  If "recirc_table" is
 *      set, execution is forked and the packet passes through the
 *      connection tracker.  The specified table's processing path is
 *      able to match on Connection state until the end of the OpenFlow
 *      pipeline or NXAST_CT is called again.
 *
 *   - Connection State:
 *
 *      Multiple packets may be associated with a single connection. Initially,
 *      all connections are uncommitted. The connection state corresponding to
 *      a packet is available in the NXM_NX_CT_STATE field for tracked packets.
 *
 *      Uncommitted connections have no state stored about them. Uncommitted
 *      connections may transition into the committed state by executing
 *      NXAST_CT with the NX_CT_F_COMMIT flag.
 *
 *      Once a connection becomes committed, information may be gathered about
 *      the connection by passing subsequent packets through the connection
 *      tracker, and the state of the connection will be stored beyond the
 *      lifetime of packet processing.
 *
 *      A committed connection always has the directionality of the packet that
 *      caused the connection to be committed in the first place.  This is the
 *      "original direction" of the connection, and the opposite direction is
 *      the "reply direction".  If a connection is already committed, but it is
 *      then decided that the original direction should be the opposite of the
 *      existing connection, NX_CT_F_FORCE flag may be used in addition to
 *      NX_CT_F_COMMIT flag to in effect terminate the existing connection and
 *      start a new one in the current direction.
 *
 *      Connections may transition back into the uncommitted state due to
 *      external timers, or due to the contents of packets that are sent to the
 *      connection tracker. This behaviour is outside of the scope of the
 *      OpenFlow interface.
 *
 * The "zone" specifies a context within which the tracking is done:
 *
 *      The connection tracking zone is a 16-bit number. Each zone is an
 *      independent connection tracking context. The connection state for each
 *      connection is completely separate for each zone, so if a connection
 *      is committed to zone A, then it will remain uncommitted in zone B.
 *      If NXAST_CT is executed with the same zone multiple times, later
 *      executions have no effect.
 *
 *      If 'zone_src' is nonzero, this specifies that the zone should be
 *      sourced from a field zone_src[ofs:ofs+nbits]. The format and semantics
 *      of 'zone_src' and 'zone_ofs_nbits' are similar to those for the
 *      NXAST_REG_LOAD action. The acceptable nxm_header values for 'zone_src'
 *      are the same as the acceptable nxm_header values for the 'src' field of
 *      NXAST_REG_MOVE.
 *
 *      If 'zone_src' is zero, then the value of 'zone_imm' will be used as the
 *      connection tracking zone.
 *
 * The "recirc_table" allows NXM_NX_CT_* fields to become available:
 *
 *      If "recirc_table" has a value other than NX_CT_RECIRC_NONE, then the
 *      packet will be logically cloned prior to executing this action. One
 *      copy will be sent to the connection tracker, then will be re-injected
 *      into the OpenFlow pipeline beginning at the OpenFlow table specified in
 *      this field. When the packet re-enters the pipeline, the NXM_NX_CT_*
 *      fields will be populated. The original instance of the packet will
 *      continue the current actions list. This can be thought of as similar to
 *      the effect of the "output" action: One copy is sent out (in this case,
 *      to the connection tracker), but the current copy continues processing.
 *
 *      It is strongly recommended that this table is later than the current
 *      table, to prevent loops.
 *
 * The "alg" attaches protocol-specific behaviour to this action:
 *
 *      The ALG is a 16-bit number which specifies that additional
 *      processing should be applied to this traffic.
 *
 *      Protocol | Value | Meaning
 *      --------------------------------------------------------------------
 *      None     |     0 | No protocol-specific behaviour.
 *      FTP      |    21 | Parse FTP control connections and observe the
 *               |       | negotiation of related data connections.
 *      Other    | Other | Unsupported protocols.
 *
 *      By way of example, if FTP control connections have this action applied
 *      with the ALG set to FTP (21), then the connection tracker will observe
 *      the negotiation of data connections. This allows the connection
 *      tracker to identify subsequent data connections as "related" to this
 *      existing connection. The "related" flag will be populated in the
 *      NXM_NX_CT_STATE field for such connections if the 'recirc_table' is
 *      specified.
 *
 * Zero or more actions may immediately follow this action. These actions will
 * be executed within the context of the connection tracker, and they require
 * NX_CT_F_COMMIT flag be set.
 */
struct nx_action_conntrack {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* At least 24. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_CT. */
    ovs_be16 flags;             /* Zero or more NX_CT_F_* flags.
                                 * Unspecified flag bits must be zero. */
    ovs_be32 zone_src;          /* Connection tracking context. */
    union {
        ovs_be16 zone_ofs_nbits;/* Range to use from source field. */
        ovs_be16 zone_imm;      /* Immediate value for zone. */
    };
    uint8_t recirc_table;       /* Recirculate to a specific table, or
                                   NX_CT_RECIRC_NONE for no recirculation. */
    uint8_t pad[3];             /* Zeroes */
    ovs_be16 alg;               /* Well-known port number for the protocol.
                                 * 0 indicates no ALG is required. */
    /* Followed by a sequence of zero or more OpenFlow actions. The length of
     * these is included in 'len'. */
};
OFP_ASSERT(sizeof(struct nx_action_conntrack) == 24);

static enum ofperr
decode_ct_zone(const struct nx_action_conntrack *nac,
               struct ofpact_conntrack *out,
               const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap)
{
    if (nac->zone_src) {
        enum ofperr error;

        out->zone_src.ofs = nxm_decode_ofs(nac->zone_ofs_nbits);
        out->zone_src.n_bits = nxm_decode_n_bits(nac->zone_ofs_nbits);
        error = mf_vl_mff_mf_from_nxm_header(ntohl(nac->zone_src),
                                             vl_mff_map, &out->zone_src.field,
                                             tlv_bitmap);
        if (error) {
            return error;
        }

        error = mf_check_src(&out->zone_src, NULL);
        if (error) {
            return error;
        }

        if (out->zone_src.n_bits != 16) {
            VLOG_WARN_RL(&rl, "zone n_bits %d not within valid range [16..16]",
                         out->zone_src.n_bits);
            return OFPERR_OFPBAC_BAD_SET_LEN;
        }
    } else {
        out->zone_src.field = NULL;
        out->zone_imm = ntohs(nac->zone_imm);
    }

    return 0;
}

static enum ofperr
decode_NXAST_RAW_CT(const struct nx_action_conntrack *nac,
                    enum ofp_version ofp_version,
                    const struct vl_mff_map *vl_mff_map, uint64_t *tlv_bitmap,
                    struct ofpbuf *out)
{
    const size_t ct_offset = ofpacts_pull(out);
    struct ofpact_conntrack *conntrack = ofpact_put_CT(out);
    int error;

    conntrack->flags = ntohs(nac->flags);
    if (conntrack->flags & NX_CT_F_FORCE &&
        !(conntrack->flags & NX_CT_F_COMMIT)) {
        error = OFPERR_OFPBAC_BAD_ARGUMENT;
        goto out;
    }

    error = decode_ct_zone(nac, conntrack, vl_mff_map, tlv_bitmap);
    if (error) {
        goto out;
    }
    conntrack->recirc_table = nac->recirc_table;
    conntrack->alg = ntohs(nac->alg);

    ofpbuf_pull(out, sizeof(*conntrack));

    struct ofpbuf openflow = ofpbuf_const_initializer(
        nac + 1, ntohs(nac->len) - sizeof(*nac));
    error = ofpacts_pull_openflow_actions__(&openflow, openflow.size,
                                            ofp_version,
                                            1u << OVSINST_OFPIT11_APPLY_ACTIONS,
                                            out, OFPACT_CT, vl_mff_map,
                                            tlv_bitmap);
    if (error) {
        goto out;
    }

    conntrack = ofpbuf_push_uninit(out, sizeof(*conntrack));
    out->header = &conntrack->ofpact;
    ofpact_finish_CT(out, &conntrack);

    if (conntrack->ofpact.len > sizeof(*conntrack)
        && !(conntrack->flags & NX_CT_F_COMMIT)) {
        const struct ofpact *a;
        size_t ofpacts_len = conntrack->ofpact.len - sizeof(*conntrack);

        OFPACT_FOR_EACH (a, conntrack->actions, ofpacts_len) {
            if (a->type != OFPACT_NAT || ofpact_get_NAT(a)->flags
                || ofpact_get_NAT(a)->range_af != AF_UNSPEC) {
                VLOG_WARN_RL(&rl, "CT action requires commit flag if actions "
                             "other than NAT without arguments are specified.");
                error = OFPERR_OFPBAC_BAD_ARGUMENT;
                goto out;
            }
        }
    }

out:
    ofpbuf_push_uninit(out, ct_offset);
    return error;
}

static void
encode_CT(const struct ofpact_conntrack *conntrack,
          enum ofp_version ofp_version, struct ofpbuf *out)
{
    struct nx_action_conntrack *nac;
    const size_t ofs = out->size;
    size_t len;

    nac = put_NXAST_CT(out);
    nac->flags = htons(conntrack->flags);
    if (conntrack->zone_src.field) {
        nac->zone_src = htonl(nxm_header_from_mff(conntrack->zone_src.field));
        nac->zone_ofs_nbits = nxm_encode_ofs_nbits(conntrack->zone_src.ofs,
                                                   conntrack->zone_src.n_bits);
    } else {
        nac->zone_src = htonl(0);
        nac->zone_imm = htons(conntrack->zone_imm);
    }
    nac->recirc_table = conntrack->recirc_table;
    nac->alg = htons(conntrack->alg);

    len = ofpacts_put_openflow_actions(conntrack->actions,
                                       ofpact_ct_get_action_len(conntrack),
                                       out, ofp_version);
    len += sizeof(*nac);
    nac = ofpbuf_at(out, ofs, sizeof(*nac));
    nac->len = htons(len);
}

static char *OVS_WARN_UNUSED_RESULT
parse_NAT(char *arg, const struct ofpact_parse_params *pp);

/* Parses 'arg' as the argument to a "ct" action, and appends such an
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_CT(char *arg, const struct ofpact_parse_params *pp)
{
    const size_t ct_offset = ofpacts_pull(pp->ofpacts);
    struct ofpact_conntrack *oc;
    char *error = NULL;
    char *key, *value;

    oc = ofpact_put_CT(pp->ofpacts);
    oc->flags = 0;
    oc->recirc_table = NX_CT_RECIRC_NONE;
    while (ofputil_parse_key_value(&arg, &key, &value)) {
        if (!strcmp(key, "commit")) {
            oc->flags |= NX_CT_F_COMMIT;
        } else if (!strcmp(key, "force")) {
            oc->flags |= NX_CT_F_FORCE;
        } else if (!strcmp(key, "table")) {
            if (!ofputil_table_from_string(value, pp->table_map,
                                           &oc->recirc_table)) {
                error = xasprintf("unknown table %s", value);
            } else if (oc->recirc_table == NX_CT_RECIRC_NONE) {
                error = xasprintf("invalid table %#"PRIx8, oc->recirc_table);
            }
        } else if (!strcmp(key, "zone")) {
            error = str_to_u16(value, "zone", &oc->zone_imm);

            if (error) {
                free(error);
                error = mf_parse_subfield(&oc->zone_src, value);
                if (error) {
                    return error;
                }
            }
        } else if (!strcmp(key, "alg")) {
            error = str_to_connhelper(value, &oc->alg);
        } else if (!strcmp(key, "nat")) {
            const size_t nat_offset = ofpacts_pull(pp->ofpacts);

            error = parse_NAT(value, pp);
            /* Update CT action pointer and length. */
            pp->ofpacts->header = ofpbuf_push_uninit(pp->ofpacts, nat_offset);
            oc = pp->ofpacts->header;
        } else if (!strcmp(key, "exec")) {
            /* Hide existing actions from ofpacts_parse_copy(), so the
             * nesting can be handled transparently. */
            enum ofputil_protocol usable_protocols2;
            const size_t exec_offset = ofpacts_pull(pp->ofpacts);

            /* Initializes 'usable_protocol2', fold it back to
             * '*usable_protocols' afterwards, so that we do not lose
             * restrictions already in there. */
            struct ofpact_parse_params pp2 = *pp;
            pp2.usable_protocols = &usable_protocols2;
            error = ofpacts_parse_copy(value, &pp2, false, OFPACT_CT);
            *pp->usable_protocols &= usable_protocols2;
            pp->ofpacts->header = ofpbuf_push_uninit(pp->ofpacts, exec_offset);
            oc = pp->ofpacts->header;
        } else {
            error = xasprintf("invalid argument to \"ct\" action: `%s'", key);
        }
        if (error) {
            break;
        }
    }
    if (!error && oc->flags & NX_CT_F_FORCE && !(oc->flags & NX_CT_F_COMMIT)) {
        error = xasprintf("\"force\" flag requires \"commit\" flag.");
    }
    ofpact_finish_CT(pp->ofpacts, &oc);
    ofpbuf_push_uninit(pp->ofpacts, ct_offset);
    return error;
}

static void
format_alg(int port, struct ds *s)
{
    switch(port) {
    case IPPORT_FTP:
        ds_put_format(s, "%salg=%sftp,", colors.param, colors.end);
        break;
    case IPPORT_TFTP:
        ds_put_format(s, "%salg=%stftp,", colors.param, colors.end);
        break;
    case 0:
        /* Don't print. */
        break;
    default:
        ds_put_format(s, "%salg=%s%d,", colors.param, colors.end, port);
        break;
    }
}

static void format_NAT(const struct ofpact_nat *,
                       const struct ofpact_format_params *fp);

static void
format_CT(const struct ofpact_conntrack *a,
          const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sct(%s", colors.paren, colors.end);
    if (a->flags & NX_CT_F_COMMIT) {
        ds_put_format(fp->s, "%scommit%s,", colors.value, colors.end);
    }
    if (a->flags & NX_CT_F_FORCE) {
        ds_put_format(fp->s, "%sforce%s,", colors.value, colors.end);
    }
    if (a->recirc_table != NX_CT_RECIRC_NONE) {
        ds_put_format(fp->s, "%stable=%s", colors.special, colors.end);
        ofputil_format_table(a->recirc_table, fp->table_map, fp->s);
        ds_put_char(fp->s, ',');
    }
    if (a->zone_src.field) {
        ds_put_format(fp->s, "%szone=%s", colors.param, colors.end);
        mf_format_subfield(&a->zone_src, fp->s);
        ds_put_char(fp->s, ',');
    } else if (a->zone_imm) {
        ds_put_format(fp->s, "%szone=%s%"PRIu16",",
                      colors.param, colors.end, a->zone_imm);
    }
    /* If the first action is a NAT action, format it outside of the 'exec'
     * envelope. */
    const struct ofpact *action = a->actions;
    size_t actions_len = ofpact_ct_get_action_len(a);
    if (actions_len && action->type == OFPACT_NAT) {
        format_NAT(ofpact_get_NAT(action), fp);
        ds_put_char(fp->s, ',');
        actions_len -= OFPACT_ALIGN(action->len);
        action = ofpact_next(action);
    }
    if (actions_len) {
        ds_put_format(fp->s, "%sexec(%s", colors.paren, colors.end);
        ofpacts_format(action, actions_len, fp);
        ds_put_format(fp->s, "%s),%s", colors.paren, colors.end);
    }
    format_alg(a->alg, fp->s);
    ds_chomp(fp->s, ',');
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

/* ct_clear action. */

static enum ofperr
decode_NXAST_RAW_CT_CLEAR(struct ofpbuf *out)
{
    ofpact_put_CT_CLEAR(out);
    return 0;
}

static void
encode_CT_CLEAR(const struct ofpact_null *null OVS_UNUSED,
                enum ofp_version ofp_version OVS_UNUSED,
                struct ofpbuf *out)
{
    put_NXAST_CT_CLEAR(out);
}

static char * OVS_WARN_UNUSED_RESULT
parse_CT_CLEAR(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_CT_CLEAR(pp->ofpacts);
    return NULL;
}

static void
format_CT_CLEAR(const struct ofpact_null *a OVS_UNUSED,
                const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sct_clear%s", colors.value, colors.end);
}

/* NAT action. */

/* Which optional fields are present? */
enum nx_nat_range {
    NX_NAT_RANGE_IPV4_MIN  = 1 << 0, /* ovs_be32 */
    NX_NAT_RANGE_IPV4_MAX  = 1 << 1, /* ovs_be32 */
    NX_NAT_RANGE_IPV6_MIN  = 1 << 2, /* struct in6_addr */
    NX_NAT_RANGE_IPV6_MAX  = 1 << 3, /* struct in6_addr */
    NX_NAT_RANGE_PROTO_MIN = 1 << 4, /* ovs_be16 */
    NX_NAT_RANGE_PROTO_MAX = 1 << 5, /* ovs_be16 */
};

/* Action structure for NXAST_NAT. */
struct nx_action_nat {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* At least 16. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_NAT. */
    uint8_t  pad[2];            /* Must be zero. */
    ovs_be16 flags;             /* Zero or more NX_NAT_F_* flags.
                                 * Unspecified flag bits must be zero. */
    ovs_be16 range_present;     /* NX_NAT_RANGE_* */
    /* Followed by optional parameters as specified by 'range_present' */
};
OFP_ASSERT(sizeof(struct nx_action_nat) == 16);

static void
encode_NAT(const struct ofpact_nat *nat,
           enum ofp_version ofp_version OVS_UNUSED,
           struct ofpbuf *out)
{
    struct nx_action_nat *nan;
    const size_t ofs = out->size;
    uint16_t range_present = 0;

    nan = put_NXAST_NAT(out);
    nan->flags = htons(nat->flags);
    if (nat->range_af == AF_INET) {
        if (nat->range.addr.ipv4.min) {
            ovs_be32 *min = ofpbuf_put_uninit(out, sizeof *min);
            *min = nat->range.addr.ipv4.min;
            range_present |= NX_NAT_RANGE_IPV4_MIN;
        }
        if (nat->range.addr.ipv4.max) {
            ovs_be32 *max = ofpbuf_put_uninit(out, sizeof *max);
            *max = nat->range.addr.ipv4.max;
            range_present |= NX_NAT_RANGE_IPV4_MAX;
        }
    } else if (nat->range_af == AF_INET6) {
        if (!ipv6_mask_is_any(&nat->range.addr.ipv6.min)) {
            struct in6_addr *min = ofpbuf_put_uninit(out, sizeof *min);
            *min = nat->range.addr.ipv6.min;
            range_present |= NX_NAT_RANGE_IPV6_MIN;
        }
        if (!ipv6_mask_is_any(&nat->range.addr.ipv6.max)) {
            struct in6_addr *max = ofpbuf_put_uninit(out, sizeof *max);
            *max = nat->range.addr.ipv6.max;
            range_present |= NX_NAT_RANGE_IPV6_MAX;
        }
    }
    if (nat->range_af != AF_UNSPEC) {
        if (nat->range.proto.min) {
            ovs_be16 *min = ofpbuf_put_uninit(out, sizeof *min);
            *min = htons(nat->range.proto.min);
            range_present |= NX_NAT_RANGE_PROTO_MIN;
        }
        if (nat->range.proto.max) {
            ovs_be16 *max = ofpbuf_put_uninit(out, sizeof *max);
            *max = htons(nat->range.proto.max);
            range_present |= NX_NAT_RANGE_PROTO_MAX;
        }
    }
    pad_ofpat(out, ofs);
    nan = ofpbuf_at(out, ofs, sizeof *nan);
    nan->range_present = htons(range_present);
}

static enum ofperr
decode_NXAST_RAW_NAT(const struct nx_action_nat *nan,
                     enum ofp_version ofp_version OVS_UNUSED,
                     struct ofpbuf *out)
{
    struct ofpact_nat *nat;
    uint16_t range_present = ntohs(nan->range_present);
    const char *opts = (char *)(nan + 1);
    uint16_t len = ntohs(nan->len) - sizeof *nan;

    nat = ofpact_put_NAT(out);
    nat->flags = ntohs(nan->flags);

    /* Check for unknown or mutually exclusive flags. */
    if ((nat->flags & ~NX_NAT_F_MASK)
        || (nat->flags & NX_NAT_F_SRC && nat->flags & NX_NAT_F_DST)
        || (nat->flags & NX_NAT_F_PROTO_HASH
            && nat->flags & NX_NAT_F_PROTO_RANDOM)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

#define NX_NAT_GET_OPT(DST, SRC, LEN, TYPE)                     \
    (LEN >= sizeof(TYPE)                                        \
     ? (memcpy(DST, SRC, sizeof(TYPE)), LEN -= sizeof(TYPE),    \
        SRC += sizeof(TYPE))                                    \
     : NULL)

    nat->range_af = AF_UNSPEC;
    if (range_present & NX_NAT_RANGE_IPV4_MIN) {
        if (range_present & (NX_NAT_RANGE_IPV6_MIN | NX_NAT_RANGE_IPV6_MAX)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }

        if (!NX_NAT_GET_OPT(&nat->range.addr.ipv4.min, opts, len, ovs_be32)
            || !nat->range.addr.ipv4.min) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }

        nat->range_af = AF_INET;

        if (range_present & NX_NAT_RANGE_IPV4_MAX) {
            if (!NX_NAT_GET_OPT(&nat->range.addr.ipv4.max, opts, len,
                                ovs_be32)) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
            if (ntohl(nat->range.addr.ipv4.max)
                < ntohl(nat->range.addr.ipv4.min)) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
        }
    } else if (range_present & NX_NAT_RANGE_IPV4_MAX) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else if (range_present & NX_NAT_RANGE_IPV6_MIN) {
        if (!NX_NAT_GET_OPT(&nat->range.addr.ipv6.min, opts, len,
                            struct in6_addr)
            || ipv6_mask_is_any(&nat->range.addr.ipv6.min)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }

        nat->range_af = AF_INET6;

        if (range_present & NX_NAT_RANGE_IPV6_MAX) {
            if (!NX_NAT_GET_OPT(&nat->range.addr.ipv6.max, opts, len,
                                struct in6_addr)) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
            if (memcmp(&nat->range.addr.ipv6.max, &nat->range.addr.ipv6.min,
                       sizeof(struct in6_addr)) < 0) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
        }
    } else if (range_present & NX_NAT_RANGE_IPV6_MAX) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    if (range_present & NX_NAT_RANGE_PROTO_MIN) {
        ovs_be16 proto;

        if (nat->range_af == AF_UNSPEC) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        if (!NX_NAT_GET_OPT(&proto, opts, len, ovs_be16) || proto == 0) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        nat->range.proto.min = ntohs(proto);
        if (range_present & NX_NAT_RANGE_PROTO_MAX) {
            if (!NX_NAT_GET_OPT(&proto, opts, len, ovs_be16)) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
            nat->range.proto.max = ntohs(proto);
            if (nat->range.proto.max < nat->range.proto.min) {
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
        }
    } else if (range_present & NX_NAT_RANGE_PROTO_MAX) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

static void
format_NAT(const struct ofpact_nat *a, const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%snat%s", colors.paren, colors.end);

    if (a->flags & (NX_NAT_F_SRC | NX_NAT_F_DST)) {
        ds_put_format(fp->s, "%s(%s", colors.paren, colors.end);
        ds_put_format(fp->s, a->flags & NX_NAT_F_SRC ? "%ssrc%s" : "%sdst%s",
                      colors.param, colors.end);

        if (a->range_af != AF_UNSPEC) {
            ds_put_format(fp->s, "%s=%s", colors.param, colors.end);

            if (a->range_af == AF_INET) {
                ds_put_format(fp->s, IP_FMT, IP_ARGS(a->range.addr.ipv4.min));

                if (a->range.addr.ipv4.max
                    && a->range.addr.ipv4.max != a->range.addr.ipv4.min) {
                    ds_put_format(fp->s, "-"IP_FMT,
                                  IP_ARGS(a->range.addr.ipv4.max));
                }
            } else if (a->range_af == AF_INET6) {
                ipv6_format_addr_bracket(&a->range.addr.ipv6.min, fp->s,
                                        a->range.proto.min);

                if (!ipv6_mask_is_any(&a->range.addr.ipv6.max)
                    && memcmp(&a->range.addr.ipv6.max, &a->range.addr.ipv6.min,
                              sizeof(struct in6_addr)) != 0) {
                    ds_put_char(fp->s, '-');
                    ipv6_format_addr_bracket(&a->range.addr.ipv6.max, fp->s,
                                            a->range.proto.min);
                }
            }
            if (a->range.proto.min) {
                ds_put_char(fp->s, ':');
                ds_put_format(fp->s, "%"PRIu16, a->range.proto.min);

                if (a->range.proto.max
                    && a->range.proto.max != a->range.proto.min) {
                    ds_put_format(fp->s, "-%"PRIu16, a->range.proto.max);
                }
            }
            ds_put_char(fp->s, ',');

            if (a->flags & NX_NAT_F_PERSISTENT) {
                ds_put_format(fp->s, "%spersistent%s,",
                              colors.value, colors.end);
            }
            if (a->flags & NX_NAT_F_PROTO_HASH) {
                ds_put_format(fp->s, "%shash%s,", colors.value, colors.end);
            }
            if (a->flags & NX_NAT_F_PROTO_RANDOM) {
                ds_put_format(fp->s, "%srandom%s,", colors.value, colors.end);
            }
        }
        ds_chomp(fp->s, ',');
        ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
    }
}

static char * OVS_WARN_UNUSED_RESULT
str_to_nat_range(const char *s, struct ofpact_nat *on)
{
    char ipv6_s[IPV6_SCAN_LEN + 1];
    int n = 0;

    on->range_af = AF_UNSPEC;
    if (ovs_scan_len(s, &n, IP_SCAN_FMT,
                     IP_SCAN_ARGS(&on->range.addr.ipv4.min))) {
        on->range_af = AF_INET;

        if (s[n] == '-') {
            n++;
            if (!ovs_scan_len(s, &n, IP_SCAN_FMT,
                              IP_SCAN_ARGS(&on->range.addr.ipv4.max))
                || (ntohl(on->range.addr.ipv4.max)
                    < ntohl(on->range.addr.ipv4.min))) {
                goto error;
            }
        }
    } else if ((ovs_scan_len(s, &n, IPV6_SCAN_FMT, ipv6_s)
                || ovs_scan_len(s, &n, "["IPV6_SCAN_FMT"]", ipv6_s))
               && inet_pton(AF_INET6, ipv6_s, &on->range.addr.ipv6.min) == 1) {
        on->range_af = AF_INET6;

        if (s[n] == '-') {
            n++;
            if (!(ovs_scan_len(s, &n, IPV6_SCAN_FMT, ipv6_s)
                  || ovs_scan_len(s, &n, "["IPV6_SCAN_FMT"]", ipv6_s))
                || inet_pton(AF_INET6, ipv6_s, &on->range.addr.ipv6.max) != 1
                || memcmp(&on->range.addr.ipv6.max, &on->range.addr.ipv6.min,
                          sizeof on->range.addr.ipv6.max) < 0) {
                goto error;
            }
        }
    }
    if (on->range_af != AF_UNSPEC && s[n] == ':') {
        n++;
        if (!ovs_scan_len(s, &n, "%"SCNu16, &on->range.proto.min)) {
            goto error;
        }
        if (s[n] == '-') {
            n++;
            if (!ovs_scan_len(s, &n, "%"SCNu16, &on->range.proto.max)
                || on->range.proto.max < on->range.proto.min) {
                goto error;
            }
        }
    }
    if (strlen(s) != n) {
        return xasprintf("garbage (%s) after nat range \"%s\" (pos: %d)",
                         &s[n], s, n);
    }
    return NULL;
error:
    return xasprintf("invalid nat range \"%s\"", s);
}


/* Parses 'arg' as the argument to a "nat" action, and appends such an
 * action to 'pp->ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
parse_NAT(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_nat *on = ofpact_put_NAT(pp->ofpacts);
    char *key, *value;

    on->flags = 0;
    on->range_af = AF_UNSPEC;

    while (ofputil_parse_key_value(&arg, &key, &value)) {
        char *error = NULL;

        if (!strcmp(key, "src")) {
            on->flags |= NX_NAT_F_SRC;
            error = str_to_nat_range(value, on);
        } else if (!strcmp(key, "dst")) {
            on->flags |= NX_NAT_F_DST;
            error = str_to_nat_range(value, on);
        } else if (!strcmp(key, "persistent")) {
            on->flags |= NX_NAT_F_PERSISTENT;
        } else if (!strcmp(key, "hash")) {
            on->flags |= NX_NAT_F_PROTO_HASH;
        } else if (!strcmp(key, "random")) {
            on->flags |= NX_NAT_F_PROTO_RANDOM;
        } else {
            error = xasprintf("invalid key \"%s\" in \"nat\" argument",
                              key);
        }
        if (error) {
            return error;
        }
    }
    if (on->flags & NX_NAT_F_SRC && on->flags & NX_NAT_F_DST) {
        return xasprintf("May only specify one of \"src\" or \"dst\".");
    }
    if (!(on->flags & NX_NAT_F_SRC || on->flags & NX_NAT_F_DST)) {
        if (on->flags) {
            return xasprintf("Flags allowed only with \"src\" or \"dst\".");
        }
        if (on->range_af != AF_UNSPEC) {
            return xasprintf("Range allowed only with \"src\" or \"dst\".");
        }
    }
    if (on->flags & NX_NAT_F_PROTO_HASH && on->flags & NX_NAT_F_PROTO_RANDOM) {
        return xasprintf("Both \"hash\" and \"random\" are not allowed.");
    }

    return NULL;
}

/* Truncate output action. */
struct nx_action_output_trunc {
    ovs_be16 type;              /* OFPAT_VENDOR. */
    ovs_be16 len;               /* At least 16. */
    ovs_be32 vendor;            /* NX_VENDOR_ID. */
    ovs_be16 subtype;           /* NXAST_OUTPUT_TRUNC. */
    ovs_be16 port;              /* Output port */
    ovs_be32 max_len;           /* Truncate packet to size bytes */
};
OFP_ASSERT(sizeof(struct nx_action_output_trunc) == 16);

static enum ofperr
decode_NXAST_RAW_OUTPUT_TRUNC(const struct nx_action_output_trunc *natrc,
                            enum ofp_version ofp_version OVS_UNUSED,
                            struct ofpbuf *out)
{
    struct ofpact_output_trunc *output_trunc;

    output_trunc = ofpact_put_OUTPUT_TRUNC(out);
    output_trunc->max_len = ntohl(natrc->max_len);
    output_trunc->port = u16_to_ofp(ntohs(natrc->port));

    if (output_trunc->max_len < ETH_HEADER_LEN) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    return 0;
}

static void
encode_OUTPUT_TRUNC(const struct ofpact_output_trunc *output_trunc,
                  enum ofp_version ofp_version OVS_UNUSED,
                  struct ofpbuf *out)
{
    struct nx_action_output_trunc *natrc = put_NXAST_OUTPUT_TRUNC(out);

    natrc->max_len = htonl(output_trunc->max_len);
    natrc->port = htons(ofp_to_u16(output_trunc->port));
}

static char * OVS_WARN_UNUSED_RESULT
parse_OUTPUT_TRUNC(const char *arg,
                   const struct ofpact_parse_params *pp OVS_UNUSED)
{
    /* Disable output_trunc parsing.  Expose as output(port=N,max_len=M) and
     * reuse parse_OUTPUT to parse output_trunc action. */
    return xasprintf("unknown action %s", arg);
}

static void
format_OUTPUT_TRUNC(const struct ofpact_output_trunc *a,
                    const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%soutput%s(port=", colors.special, colors.end);
    ofputil_format_port(a->port, fp->port_map, fp->s);
    ds_put_format(fp->s, ",max_len=%"PRIu32")", a->max_len);
}


/* Meter instruction. */

static void
encode_METER(const struct ofpact_meter *meter,
             enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version >= OFP13_VERSION) {
        instruction_put_OFPIT13_METER(out)->meter_id = htonl(meter->meter_id);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_METER(char *arg, const struct ofpact_parse_params *pp)
{
    *pp->usable_protocols &= OFPUTIL_P_OF13_UP;
    return str_to_u32(arg, &ofpact_put_METER(pp->ofpacts)->meter_id);
}

static void
format_METER(const struct ofpact_meter *a,
             const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%smeter:%s%"PRIu32,
                  colors.param, colors.end, a->meter_id);
}

/* Clear-Actions instruction. */

static void
encode_CLEAR_ACTIONS(const struct ofpact_null *null OVS_UNUSED,
                     enum ofp_version ofp_version OVS_UNUSED,
                     struct ofpbuf *out OVS_UNUSED)
{
    if (ofp_version > OFP10_VERSION) {
        instruction_put_OFPIT11_CLEAR_ACTIONS(out);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_CLEAR_ACTIONS(char *arg OVS_UNUSED, const struct ofpact_parse_params *pp)
{
    ofpact_put_CLEAR_ACTIONS(pp->ofpacts);
    return NULL;
}

static void
format_CLEAR_ACTIONS(const struct ofpact_null *a OVS_UNUSED,
                     const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sclear_actions%s", colors.value, colors.end);
}

/* Write-Actions instruction. */

static void
encode_WRITE_ACTIONS(const struct ofpact_nest *actions,
                     enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version > OFP10_VERSION) {
        const size_t ofs = out->size;

        instruction_put_OFPIT11_WRITE_ACTIONS(out);
        ofpacts_put_openflow_actions(actions->actions,
                                     ofpact_nest_get_action_len(actions),
                                     out, ofp_version);
        ofpacts_update_instruction_actions(out, ofs);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_WRITE_ACTIONS(char *arg, const struct ofpact_parse_params *pp)
{
    size_t ofs = ofpacts_pull(pp->ofpacts);
    struct ofpact_nest *on;
    char *error;

    /* Add a Write-Actions instruction and then pull it off. */
    ofpact_put(pp->ofpacts, OFPACT_WRITE_ACTIONS, sizeof *on);
    ofpbuf_pull(pp->ofpacts, sizeof *on);

    /* Parse nested actions.
     *
     * We pulled off "write-actions" and the previous actions because the
     * OFPACT_WRITE_ACTIONS is only partially constructed: its length is such
     * that it doesn't actually include the nested actions.  That means that
     * ofpacts_parse() would reject them as being part of an Apply-Actions that
     * follows a Write-Actions, which is an invalid order.  */
    error = ofpacts_parse(arg, pp, false, OFPACT_WRITE_ACTIONS);

    /* Put the Write-Actions back on and update its length. */
    on = ofpbuf_push_uninit(pp->ofpacts, sizeof *on);
    on->ofpact.len = pp->ofpacts->size;

    /* Put any previous actions or instructions back on. */
    ofpbuf_push_uninit(pp->ofpacts, ofs);

    return error;
}

static void
format_WRITE_ACTIONS(const struct ofpact_nest *a,
                     const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%swrite_actions(%s", colors.paren, colors.end);
    ofpacts_format(a->actions, ofpact_nest_get_action_len(a), fp);
    ds_put_format(fp->s, "%s)%s", colors.paren, colors.end);
}

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

static enum ofperr
decode_NXAST_RAW_WRITE_METADATA(const struct nx_action_write_metadata *nawm,
                                enum ofp_version ofp_version OVS_UNUSED,
                                struct ofpbuf *out)
{
    struct ofpact_metadata *om;

    if (!is_all_zeros(nawm->zeros, sizeof nawm->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    om = ofpact_put_WRITE_METADATA(out);
    om->metadata = nawm->metadata;
    om->mask = nawm->mask;

    return 0;
}

static void
encode_WRITE_METADATA(const struct ofpact_metadata *metadata,
                      enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        struct nx_action_write_metadata *nawm;

        nawm = put_NXAST_WRITE_METADATA(out);
        nawm->metadata = metadata->metadata;
        nawm->mask = metadata->mask;
    } else {
        struct ofp11_instruction_write_metadata *oiwm;

        oiwm = instruction_put_OFPIT11_WRITE_METADATA(out);
        oiwm->metadata = metadata->metadata;
        oiwm->metadata_mask = metadata->mask;
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_WRITE_METADATA(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_metadata *om;
    char *mask = strchr(arg, '/');

    *pp->usable_protocols &= OFPUTIL_P_NXM_OF11_UP;

    om = ofpact_put_WRITE_METADATA(pp->ofpacts);
    if (mask) {
        char *error;

        *mask = '\0';
        error = str_to_be64(mask + 1, &om->mask);
        if (error) {
            return error;
        }
    } else {
        om->mask = OVS_BE64_MAX;
    }

    return str_to_be64(arg, &om->metadata);
}

static void
format_WRITE_METADATA(const struct ofpact_metadata *a,
                      const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%swrite_metadata:%s%#"PRIx64,
                  colors.param, colors.end, ntohll(a->metadata));
    if (a->mask != OVS_BE64_MAX) {
        ds_put_format(fp->s, "/%#"PRIx64, ntohll(a->mask));
    }
}

/* Goto-Table instruction. */

static void
encode_GOTO_TABLE(const struct ofpact_goto_table *goto_table,
                  enum ofp_version ofp_version, struct ofpbuf *out)
{
    if (ofp_version == OFP10_VERSION) {
        struct nx_action_resubmit *nar;

        nar = put_NXAST_RESUBMIT_TABLE(out);
        nar->table = goto_table->table_id;
        nar->in_port = htons(ofp_to_u16(OFPP_IN_PORT));
    } else {
        struct ofp11_instruction_goto_table *oigt;

        oigt = instruction_put_OFPIT11_GOTO_TABLE(out);
        oigt->table_id = goto_table->table_id;
        memset(oigt->pad, 0, sizeof oigt->pad);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_GOTO_TABLE(char *arg, const struct ofpact_parse_params *pp)
{
    struct ofpact_goto_table *ogt = ofpact_put_GOTO_TABLE(pp->ofpacts);
    if (!ofputil_table_from_string(arg, pp->table_map, &ogt->table_id)) {
        return xasprintf("unknown table \"%s\"", arg);
    }
    return NULL;
}

static void
format_GOTO_TABLE(const struct ofpact_goto_table *a,
                  const struct ofpact_format_params *fp)
{
    ds_put_format(fp->s, "%sgoto_table:%s", colors.param, colors.end);
    ofputil_format_table(a->table_id, fp->table_map, fp->s);
}

static void
log_bad_action(const struct ofp_action_header *actions, size_t actions_len,
               const struct ofp_action_header *bad_action, enum ofperr error)
{
    if (!VLOG_DROP_WARN(&rl)) {
        struct ds s;

        ds_init(&s);
        ds_put_hex_dump(&s, actions, actions_len, 0, false);
        VLOG_WARN("bad action at offset %#"PRIxPTR" (%s):\n%s",
                  (char *)bad_action - (char *)actions,
                  ofperr_get_name(error), ds_cstr(&s));
        ds_destroy(&s);
    }
}

static enum ofperr
ofpacts_decode(const void *actions, size_t actions_len,
               enum ofp_version ofp_version,
               const struct vl_mff_map *vl_mff_map,
               uint64_t *ofpacts_tlv_bitmap, struct ofpbuf *ofpacts)
{
    struct ofpbuf openflow = ofpbuf_const_initializer(actions, actions_len);
    while (openflow.size) {
        const struct ofp_action_header *action = openflow.data;
        enum ofp_raw_action_type raw;
        enum ofperr error;
        uint64_t arg;

        error = ofpact_pull_raw(&openflow, ofp_version, &raw, &arg);
        if (!error) {
            error = ofpact_decode(action, raw, ofp_version, arg, vl_mff_map,
                                  ofpacts_tlv_bitmap, ofpacts);
        }

        if (error) {
            log_bad_action(actions, actions_len, action, error);
            return error;
        }
    }
    return 0;
}

static enum ofperr
ofpacts_pull_openflow_actions__(struct ofpbuf *openflow,
                                unsigned int actions_len,
                                enum ofp_version version,
                                uint32_t allowed_ovsinsts,
                                struct ofpbuf *ofpacts,
                                enum ofpact_type outer_action,
                                const struct vl_mff_map *vl_mff_map,
                                uint64_t *ofpacts_tlv_bitmap)
{
    const struct ofp_action_header *actions;
    size_t orig_size = ofpacts->size;
    enum ofperr error;

    if (actions_len % OFP_ACTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u is not a "
                     "multiple of %d", actions_len, OFP_ACTION_ALIGN);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    actions = ofpbuf_try_pull(openflow, actions_len);
    if (actions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u exceeds "
                     "remaining message length (%"PRIu32")",
                     actions_len, openflow->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    error = ofpacts_decode(actions, actions_len, version, vl_mff_map,
                           ofpacts_tlv_bitmap, ofpacts);
    if (error) {
        ofpacts->size = orig_size;
        return error;
    }

    error = ofpacts_verify(ofpacts->data, ofpacts->size, allowed_ovsinsts,
                           outer_action);
    if (error) {
        ofpacts->size = orig_size;
    }
    return error;
}

/* Attempts to convert 'actions_len' bytes of OpenFlow actions from the front
 * of 'openflow' into ofpacts.  On success, appends the converted actions to
 * 'ofpacts'; on failure, 'ofpacts' is unchanged (but might be reallocated) .
 * Returns 0 if successful, otherwise an OpenFlow error.
 *
 * Actions are processed according to their OpenFlow version which
 * is provided in the 'version' parameter.
 *
 * In most places in OpenFlow, actions appear encapsulated in instructions, so
 * you should call ofpacts_pull_openflow_instructions() instead of this
 * function.
 *
 * 'vl_mff_map' and 'ofpacts_tlv_bitmap' are optional. If 'vl_mff_map' is
 * provided, it is used to get variable length mf_fields with configured
 * length in the actions. If an action uses a variable length mf_field,
 * 'ofpacts_tlv_bitmap' is updated accordingly for ref counting. If
 * 'vl_mff_map' is not provided, the default mf_fields with maximum length
 * will be used.
 *
 * The parsed actions are valid generically, but they may not be valid in a
 * specific context.  For example, port numbers up to OFPP_MAX are valid
 * generically, but specific datapaths may only support port numbers in a
 * smaller range.  Use ofpacts_check() to additional check whether actions are
 * valid in a specific context. */
enum ofperr
ofpacts_pull_openflow_actions(struct ofpbuf *openflow,
                              unsigned int actions_len,
                              enum ofp_version version,
                              const struct vl_mff_map *vl_mff_map,
                              uint64_t *ofpacts_tlv_bitmap,
                              struct ofpbuf *ofpacts)
{
    return ofpacts_pull_openflow_actions__(openflow, actions_len, version,
                                           1u << OVSINST_OFPIT11_APPLY_ACTIONS,
                                           ofpacts, 0, vl_mff_map,
                                           ofpacts_tlv_bitmap);
}

/* OpenFlow 1.1 action sets. */

/* Append ofpact 'a' onto the tail of 'out' */
static void
ofpact_copy(struct ofpbuf *out, const struct ofpact *a)
{
    ofpbuf_put(out, a, OFPACT_ALIGN(a->len));
}

/* The order in which actions in an action set get executed.  This is only for
 * the actions where only the last instance added is used. */
#define ACTION_SET_ORDER                        \
    SLOT(OFPACT_STRIP_VLAN)                     \
    SLOT(OFPACT_POP_MPLS)                       \
    SLOT(OFPACT_DECAP)                          \
    SLOT(OFPACT_ENCAP)                          \
    SLOT(OFPACT_PUSH_MPLS)                      \
    SLOT(OFPACT_PUSH_VLAN)                      \
    SLOT(OFPACT_DEC_TTL)                        \
    SLOT(OFPACT_DEC_MPLS_TTL)                   \
    SLOT(OFPACT_DEC_NSH_TTL)

/* Priority for "final actions" in an action set.  An action set only gets
 * executed at all if at least one of these actions is present.  If more than
 * one is present, then only the one later in this list is executed (and if
 * more than one of a given type, the one later in the action set). */
#define ACTION_SET_FINAL_PRIORITY               \
    FINAL(OFPACT_CT)                            \
    FINAL(OFPACT_CT_CLEAR)                      \
    FINAL(OFPACT_RESUBMIT)                      \
    FINAL(OFPACT_OUTPUT)                        \
    FINAL(OFPACT_GROUP)

enum action_set_class {
    /* Actions that individually can usefully appear only once in an action
     * set.  If they do appear more than once, then only the last instance is
     * honored. */
#define SLOT(OFPACT) ACTION_SLOT_##OFPACT,
    ACTION_SET_ORDER
#undef SLOT

    /* Final actions. */
#define FINAL(OFPACT) ACTION_SLOT_##OFPACT,
    ACTION_SET_FINAL_PRIORITY
#undef FINAL

    /* Actions that can appear in an action set more than once and are executed
     * in order. */
    ACTION_SLOT_SET_OR_MOVE,

    /* Actions that shouldn't appear in the action set at all. */
    ACTION_SLOT_INVALID
};

/* Count the action set slots. */
#define SLOT(OFPACT) +1
enum { N_ACTION_SLOTS = ACTION_SET_ORDER };
#undef SLOT

static enum action_set_class
action_set_classify(const struct ofpact *a)
{
    switch (a->type) {
#define SLOT(OFPACT) case OFPACT: return ACTION_SLOT_##OFPACT;
        ACTION_SET_ORDER
#undef SLOT

#define FINAL(OFPACT) case OFPACT: return ACTION_SLOT_##OFPACT;
        ACTION_SET_FINAL_PRIORITY
#undef FINAL

    case OFPACT_SET_FIELD:
    case OFPACT_REG_MOVE:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_SET_QUEUE:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_SET_VLAN_VID:
        return ACTION_SLOT_SET_OR_MOVE;

    case OFPACT_BUNDLE:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_CLONE:
    case OFPACT_NAT:
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_EXIT:
    case OFPACT_UNROLL_XLATE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_GOTO_TABLE:
    case OFPACT_LEARN:
    case OFPACT_CONJUNCTION:
    case OFPACT_METER:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_OUTPUT_TRUNC:
    case OFPACT_POP_QUEUE:
    case OFPACT_SAMPLE:
    case OFPACT_STACK_POP:
    case OFPACT_STACK_PUSH:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_WRITE_METADATA:
    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
        return ACTION_SLOT_INVALID;

    default:
        OVS_NOT_REACHED();
    }
}

/* True if an action is allowed in the action set.
 * False otherwise. */
static bool
ofpact_is_allowed_in_actions_set(const struct ofpact *a)
{
    return action_set_classify(a) != ACTION_SLOT_INVALID;
}

/* Reads 'action_set', which contains ofpacts accumulated by
 * OFPACT_WRITE_ACTIONS instructions, and writes equivalent actions to be
 * executed directly into 'action_list'.  (These names correspond to the
 * "Action Set" and "Action List" terms used in OpenFlow 1.1+.)
 *
 * In general this involves appending the last instance of each action that is
 * admissible in the action set in the order described in the OpenFlow
 * specification.
 *
 * Exceptions:
 * + output action is only appended if no group action was present in 'in'.
 * + As a simplification all set actions are copied in the order the are
 *   provided in 'in' as many set actions applied to a field has the same
 *   affect as only applying the last action that sets a field and
 *   duplicates are removed by do_xlate_actions().
 *   This has an unwanted side-effect of compsoting multiple
 *   LOAD_REG actions that touch different regions of the same field. */
void
ofpacts_execute_action_set(struct ofpbuf *action_list,
                           const struct ofpbuf *action_set)
{
    const struct ofpact *slots[N_ACTION_SLOTS] = {NULL, };

    struct ofpbuf set_or_move;
    ofpbuf_init(&set_or_move, 0);

    const struct ofpact *final_action = NULL;
    enum action_set_class final_class = 0;

    const struct ofpact *cursor;
    OFPACT_FOR_EACH (cursor, action_set->data, action_set->size) {
        int class = action_set_classify(cursor);
        if (class < N_ACTION_SLOTS) {
            slots[class] = cursor;
        } else if (class < ACTION_SLOT_SET_OR_MOVE) {
            if (class >= final_class) {
                final_action = cursor;
                final_class = class;
            }
        } else if (class == ACTION_SLOT_SET_OR_MOVE) {
            ofpact_copy(&set_or_move, cursor);
        } else {
            ovs_assert(class == ACTION_SLOT_INVALID);
        }
    }

    if (final_action) {
        for (int i = 0; i < N_ACTION_SLOTS; i++) {
            if (slots[i]) {
                ofpact_copy(action_list, slots[i]);
            }
        }
        ofpbuf_put(action_list, set_or_move.data, set_or_move.size);
        ofpact_copy(action_list, final_action);
    }
    ofpbuf_uninit(&set_or_move);
}


static enum ofperr
ofpacts_decode_for_action_set(const struct ofp_action_header *in,
                              size_t n_in, enum ofp_version version,
                              const struct vl_mff_map *vl_mff_map,
                              uint64_t *ofpacts_tlv_bitmap,
                              struct ofpbuf *out)
{
    enum ofperr error;
    struct ofpact *a;
    size_t start = out->size;

    error = ofpacts_decode(in, n_in, version, vl_mff_map, ofpacts_tlv_bitmap,
                           out);

    if (error) {
        return error;
    }

    OFPACT_FOR_EACH (a, ofpact_end(out->data, start), out->size - start) {
        if (!ofpact_is_allowed_in_actions_set(a)) {
            VLOG_WARN_RL(&rl, "disallowed action in action set");
            return OFPERR_OFPBAC_BAD_TYPE;
        }
    }

    return 0;
}

/* OpenFlow 1.1 instructions. */

struct instruction_type_info {
    enum ovs_instruction_type type;
    const char *name;
};

static const struct instruction_type_info inst_info[] = {
#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME)    {OVSINST_##ENUM, NAME},
OVS_INSTRUCTIONS
#undef DEFINE_INST
};

const char *
ovs_instruction_name_from_type(enum ovs_instruction_type type)
{
    return type < ARRAY_SIZE(inst_info) ? inst_info[type].name : NULL;
}

int
ovs_instruction_type_from_name(const char *name)
{
    const struct instruction_type_info *p;
    for (p = inst_info; p < &inst_info[ARRAY_SIZE(inst_info)]; p++) {
        if (!strcasecmp(name, p->name)) {
            return p->type;
        }
    }
    return -1;
}

enum ovs_instruction_type
ovs_instruction_type_from_ofpact_type(enum ofpact_type type)
{
    switch (type) {
    case OFPACT_METER:
        return OVSINST_OFPIT13_METER;
    case OFPACT_CLEAR_ACTIONS:
        return OVSINST_OFPIT11_CLEAR_ACTIONS;
    case OFPACT_WRITE_ACTIONS:
        return OVSINST_OFPIT11_WRITE_ACTIONS;
    case OFPACT_WRITE_METADATA:
        return OVSINST_OFPIT11_WRITE_METADATA;
    case OFPACT_GOTO_TABLE:
        return OVSINST_OFPIT11_GOTO_TABLE;
    case OFPACT_OUTPUT:
    case OFPACT_GROUP:
    case OFPACT_CLONE:
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_OUTPUT_TRUNC:
    case OFPACT_BUNDLE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_PUSH_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_SET_FIELD:
    case OFPACT_STACK_PUSH:
    case OFPACT_STACK_POP:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_CONJUNCTION:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_UNROLL_XLATE:
    case OFPACT_SAMPLE:
    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
    case OFPACT_CT:
    case OFPACT_CT_CLEAR:
    case OFPACT_NAT:
    case OFPACT_ENCAP:
    case OFPACT_DECAP:
    case OFPACT_DEC_NSH_TTL:
    default:
        return OVSINST_OFPIT11_APPLY_ACTIONS;
    }
}

enum ofperr
ovs_instruction_type_from_inst_type(enum ovs_instruction_type *instruction_type,
                                    const uint16_t inst_type)
{
    switch (inst_type) {

#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME) \
    case ENUM:                                      \
        *instruction_type = OVSINST_##ENUM;         \
        return 0;
OVS_INSTRUCTIONS
#undef DEFINE_INST

    default:
        return OFPERR_OFPBIC_UNKNOWN_INST;
    }
}

/* Two-way translation between OVS's internal "OVSINST_*" representation of
 * instructions and the "OFPIT_*" representation used in OpenFlow. */
struct ovsinst_map {
    enum ovs_instruction_type ovsinst; /* Internal name for instruction. */
    int ofpit;                         /* OFPIT_* number from OpenFlow spec. */
};

static const struct ovsinst_map *
get_ovsinst_map(enum ofp_version version)
{
    /* OpenFlow 1.1 and 1.2 instructions. */
    static const struct ovsinst_map of11[] = {
        { OVSINST_OFPIT11_GOTO_TABLE, 1 },
        { OVSINST_OFPIT11_WRITE_METADATA, 2 },
        { OVSINST_OFPIT11_WRITE_ACTIONS, 3 },
        { OVSINST_OFPIT11_APPLY_ACTIONS, 4 },
        { OVSINST_OFPIT11_CLEAR_ACTIONS, 5 },
        { 0, -1 },
    };

    /* OpenFlow 1.3+ instructions. */
    static const struct ovsinst_map of13[] = {
        { OVSINST_OFPIT11_GOTO_TABLE, 1 },
        { OVSINST_OFPIT11_WRITE_METADATA, 2 },
        { OVSINST_OFPIT11_WRITE_ACTIONS, 3 },
        { OVSINST_OFPIT11_APPLY_ACTIONS, 4 },
        { OVSINST_OFPIT11_CLEAR_ACTIONS, 5 },
        { OVSINST_OFPIT13_METER, 6 },
        { 0, -1 },
    };

    return version < OFP13_VERSION ? of11 : of13;
}

/* Converts 'ovsinst_bitmap', a bitmap whose bits correspond to OVSINST_*
 * values, into a bitmap of instructions suitable for OpenFlow 'version'
 * (OFP11_VERSION or later), and returns the result. */
ovs_be32
ovsinst_bitmap_to_openflow(uint32_t ovsinst_bitmap, enum ofp_version version)
{
    uint32_t ofpit_bitmap = 0;
    const struct ovsinst_map *x;

    for (x = get_ovsinst_map(version); x->ofpit >= 0; x++) {
        if (ovsinst_bitmap & (1u << x->ovsinst)) {
            ofpit_bitmap |= 1u << x->ofpit;
        }
    }
    return htonl(ofpit_bitmap);
}

/* Converts 'ofpit_bitmap', a bitmap of instructions from an OpenFlow message
 * with the given 'version' (OFP11_VERSION or later) into a bitmap whose bits
 * correspond to OVSINST_* values, and returns the result. */
uint32_t
ovsinst_bitmap_from_openflow(ovs_be32 ofpit_bitmap, enum ofp_version version)
{
    uint32_t ovsinst_bitmap = 0;
    const struct ovsinst_map *x;

    for (x = get_ovsinst_map(version); x->ofpit >= 0; x++) {
        if (ofpit_bitmap & htonl(1u << x->ofpit)) {
            ovsinst_bitmap |= 1u << x->ovsinst;
        }
    }
    return ovsinst_bitmap;
}

static inline struct ofp11_instruction *
instruction_next(const struct ofp11_instruction *inst)
{
    return ((struct ofp11_instruction *) (void *)
            ((uint8_t *) inst + ntohs(inst->len)));
}

static inline bool
instruction_is_valid(const struct ofp11_instruction *inst,
                     size_t n_instructions)
{
    uint16_t len = ntohs(inst->len);
    return (!(len % OFP11_INSTRUCTION_ALIGN)
            && len >= sizeof *inst
            && len / sizeof *inst <= n_instructions);
}

/* This macro is careful to check for instructions with bad lengths. */
#define INSTRUCTION_FOR_EACH(ITER, LEFT, INSTRUCTIONS, N_INSTRUCTIONS)  \
    for ((ITER) = (INSTRUCTIONS), (LEFT) = (N_INSTRUCTIONS);            \
         (LEFT) > 0 && instruction_is_valid(ITER, LEFT);                \
         ((LEFT) -= (ntohs((ITER)->len)                                 \
                     / sizeof(struct ofp11_instruction)),               \
          (ITER) = instruction_next(ITER)))

static enum ofperr
decode_openflow11_instruction(const struct ofp11_instruction *inst,
                              enum ovs_instruction_type *type)
{
    uint16_t len = ntohs(inst->len);

    switch (inst->type) {
    case CONSTANT_HTONS(OFPIT11_EXPERIMENTER):
        return OFPERR_OFPBIC_BAD_EXPERIMENTER;

#define DEFINE_INST(ENUM, STRUCT, EXTENSIBLE, NAME)     \
        case CONSTANT_HTONS(ENUM):                      \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *type = OVSINST_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBIC_BAD_LEN;           \
            }
OVS_INSTRUCTIONS
#undef DEFINE_INST

    default:
        return OFPERR_OFPBIC_UNKNOWN_INST;
    }
}

static enum ofperr
decode_openflow11_instructions(const struct ofp11_instruction insts[],
                               size_t n_insts,
                               const struct ofp11_instruction *out[])
{
    const struct ofp11_instruction *inst;
    size_t left;

    memset(out, 0, N_OVS_INSTRUCTIONS * sizeof *out);
    INSTRUCTION_FOR_EACH (inst, left, insts, n_insts) {
        enum ovs_instruction_type type;
        enum ofperr error;

        error = decode_openflow11_instruction(inst, &type);
        if (error) {
            return error;
        }

        if (out[type]) {
            return OFPERR_OFPBIC_DUP_INST;
        }
        out[type] = inst;
    }

    if (left) {
        VLOG_WARN_RL(&rl, "bad instruction format at offset %"PRIuSIZE,
                     (n_insts - left) * sizeof *inst);
        return OFPERR_OFPBIC_BAD_LEN;
    }
    return 0;
}

static void
get_actions_from_instruction(const struct ofp11_instruction *inst,
                             const struct ofp_action_header **actions,
                             size_t *actions_len)
{
    *actions = ALIGNED_CAST(const struct ofp_action_header *, inst + 1);
    *actions_len = ntohs(inst->len) - sizeof *inst;
}

enum ofperr
ofpacts_pull_openflow_instructions(struct ofpbuf *openflow,
                                   unsigned int instructions_len,
                                   enum ofp_version version,
                                   const struct vl_mff_map *vl_mff_map,
                                   uint64_t *ofpacts_tlv_bitmap,
                                   struct ofpbuf *ofpacts)
{
    const struct ofp11_instruction *instructions;
    const struct ofp11_instruction *insts[N_OVS_INSTRUCTIONS];
    enum ofperr error;

    ofpbuf_clear(ofpacts);
    if (version == OFP10_VERSION) {
        return ofpacts_pull_openflow_actions__(openflow, instructions_len,
                                               version,
                                               (1u << N_OVS_INSTRUCTIONS) - 1,
                                               ofpacts, 0, vl_mff_map,
                                               ofpacts_tlv_bitmap);
    }

    if (instructions_len % OFP11_INSTRUCTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u is not a "
                     "multiple of %d",
                     instructions_len, OFP11_INSTRUCTION_ALIGN);
        error = OFPERR_OFPBIC_BAD_LEN;
        goto exit;
    }

    instructions = ofpbuf_try_pull(openflow, instructions_len);
    if (instructions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u exceeds "
                     "remaining message length (%"PRIu32")",
                     instructions_len, openflow->size);
        error = OFPERR_OFPBIC_BAD_LEN;
        goto exit;
    }

    error = decode_openflow11_instructions(
        instructions, instructions_len / OFP11_INSTRUCTION_ALIGN,
        insts);
    if (error) {
        goto exit;
    }

    if (insts[OVSINST_OFPIT13_METER]) {
        const struct ofp13_instruction_meter *oim;
        struct ofpact_meter *om;

        oim = ALIGNED_CAST(const struct ofp13_instruction_meter *,
                           insts[OVSINST_OFPIT13_METER]);

        om = ofpact_put_METER(ofpacts);
        om->meter_id = ntohl(oim->meter_id);
        om->provider_meter_id = UINT32_MAX; /* No provider meter ID. */
    }
    if (insts[OVSINST_OFPIT11_APPLY_ACTIONS]) {
        const struct ofp_action_header *actions;
        size_t actions_len;

        get_actions_from_instruction(insts[OVSINST_OFPIT11_APPLY_ACTIONS],
                                     &actions, &actions_len);
        error = ofpacts_decode(actions, actions_len, version, vl_mff_map,
                               ofpacts_tlv_bitmap, ofpacts);
        if (error) {
            goto exit;
        }
    }
    if (insts[OVSINST_OFPIT11_CLEAR_ACTIONS]) {
        instruction_get_OFPIT11_CLEAR_ACTIONS(
            insts[OVSINST_OFPIT11_CLEAR_ACTIONS]);
        ofpact_put_CLEAR_ACTIONS(ofpacts);
    }
    if (insts[OVSINST_OFPIT11_WRITE_ACTIONS]) {
        struct ofpact_nest *on;
        const struct ofp_action_header *actions;
        size_t actions_len;
        size_t start = ofpacts->size;
        ofpact_put(ofpacts, OFPACT_WRITE_ACTIONS,
                   offsetof(struct ofpact_nest, actions));
        get_actions_from_instruction(insts[OVSINST_OFPIT11_WRITE_ACTIONS],
                                     &actions, &actions_len);
        error = ofpacts_decode_for_action_set(actions, actions_len,
                                              version, vl_mff_map,
                                              ofpacts_tlv_bitmap, ofpacts);
        if (error) {
            goto exit;
        }
        on = ofpbuf_at_assert(ofpacts, start, sizeof *on);
        on->ofpact.len = ofpacts->size - start;
    }
    if (insts[OVSINST_OFPIT11_WRITE_METADATA]) {
        const struct ofp11_instruction_write_metadata *oiwm;
        struct ofpact_metadata *om;

        oiwm = ALIGNED_CAST(const struct ofp11_instruction_write_metadata *,
                            insts[OVSINST_OFPIT11_WRITE_METADATA]);

        om = ofpact_put_WRITE_METADATA(ofpacts);
        om->metadata = oiwm->metadata;
        om->mask = oiwm->metadata_mask;
    }
    if (insts[OVSINST_OFPIT11_GOTO_TABLE]) {
        const struct ofp11_instruction_goto_table *oigt;
        struct ofpact_goto_table *ogt;

        oigt = instruction_get_OFPIT11_GOTO_TABLE(
            insts[OVSINST_OFPIT11_GOTO_TABLE]);
        ogt = ofpact_put_GOTO_TABLE(ofpacts);
        ogt->table_id = oigt->table_id;
    }

    error = ofpacts_verify(ofpacts->data, ofpacts->size,
                           (1u << N_OVS_INSTRUCTIONS) - 1, 0);
exit:
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
}

/* Update the length of the instruction that begins at offset 'ofs' within
 * 'openflow' and contains nested actions that extend to the end of 'openflow'.
 * If the instruction contains no nested actions, deletes it entirely. */
static void
ofpacts_update_instruction_actions(struct ofpbuf *openflow, size_t ofs)
{
    struct ofp11_instruction_actions *oia;

    oia = ofpbuf_at_assert(openflow, ofs, sizeof *oia);
    if (openflow->size > ofs + sizeof *oia) {
        oia->len = htons(openflow->size - ofs);
    } else {
        openflow->size = ofs;
    }
}

/* Checks that 'port' is a valid output port for OFPACT_OUTPUT, given that the
 * switch will never have more than 'max_ports' ports.  Returns 0 if 'port' is
 * valid, otherwise an OpenFlow error code. */
enum ofperr
ofpact_check_output_port(ofp_port_t port, ofp_port_t max_ports)
{
    switch (port) {
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_LOCAL:
        return 0;

    case OFPP_NONE:
        return OFPERR_OFPBAC_BAD_OUT_PORT;

    default:
        if (ofp_to_u16(port) < ofp_to_u16(max_ports)) {
            return 0;
        }
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}

/* Removes the protocols that require consistency between match and actions
 * (that's everything but OpenFlow 1.0) from '*usable_protocols'.
 *
 * (An example of an inconsistency between match and actions is a flow that
 * does not match on an MPLS Ethertype but has an action that pops an MPLS
 * label.) */
static void
inconsistent_match(enum ofputil_protocol *usable_protocols)
{
    *usable_protocols &= OFPUTIL_P_OF10_ANY;
}

/* May modify flow->packet_type, flow->dl_type, flow->nw_proto and
 * flow->vlan_tci, caller must restore them.
 *
 * Modifies some actions, filling in fields that could not be properly set
 * without context. */
static enum ofperr
ofpact_check__(enum ofputil_protocol *usable_protocols, struct ofpact *a,
               struct match *match, ofp_port_t max_ports,
               uint8_t table_id, uint8_t n_tables)
{
    struct flow *flow = &match->flow;
    const struct ofpact_enqueue *enqueue;
    const struct mf_field *mf;
    ovs_be16 dl_type = get_dl_type(flow);

    switch (a->type) {
    case OFPACT_OUTPUT:
        return ofpact_check_output_port(ofpact_get_OUTPUT(a)->port,
                                        max_ports);

    case OFPACT_CONTROLLER:
        return 0;

    case OFPACT_ENQUEUE:
        enqueue = ofpact_get_ENQUEUE(a);
        if (ofp_to_u16(enqueue->port) >= ofp_to_u16(max_ports)
            && enqueue->port != OFPP_IN_PORT
            && enqueue->port != OFPP_LOCAL) {
            return OFPERR_OFPBAC_BAD_OUT_PORT;
        }
        return 0;

    case OFPACT_OUTPUT_REG:
        return mf_check_src(&ofpact_get_OUTPUT_REG(a)->src, match);

    case OFPACT_OUTPUT_TRUNC:
        return ofpact_check_output_port(ofpact_get_OUTPUT_TRUNC(a)->port,
                                        max_ports);

    case OFPACT_BUNDLE:
        return bundle_check(ofpact_get_BUNDLE(a), max_ports, match);

    case OFPACT_SET_VLAN_VID:
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1+ if need be. */
        ofpact_get_SET_VLAN_VID(a)->flow_has_vlan =
            (flow->vlans[0].tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (!(flow->vlans[0].tci & htons(VLAN_CFI)) &&
            !ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
            inconsistent_match(usable_protocols);
        }
        /* Temporary mark that we have a vlan tag. */
        flow->vlans[0].tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_SET_VLAN_PCP:
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1+ if need be. */
        ofpact_get_SET_VLAN_PCP(a)->flow_has_vlan =
            (flow->vlans[0].tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (!(flow->vlans[0].tci & htons(VLAN_CFI)) &&
            !ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
            inconsistent_match(usable_protocols);
        }
        /* Temporary mark that we have a vlan tag. */
        flow->vlans[0].tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_STRIP_VLAN:
        if (!(flow->vlans[0].tci & htons(VLAN_CFI))) {
            inconsistent_match(usable_protocols);
        }
        flow_pop_vlan(flow, NULL);
        return 0;

    case OFPACT_PUSH_VLAN:
        if (flow->vlans[FLOW_MAX_VLAN_HEADERS - 1].tci & htons(VLAN_CFI)) {
            /* Support maximum (FLOW_MAX_VLAN_HEADERS) VLAN headers. */
            return OFPERR_OFPBAC_BAD_TAG;
        }
        /* Temporary mark that we have a vlan tag. */
        flow_push_vlan_uninit(flow, NULL);
        flow->vlans[0].tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
        return 0;

    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
        if (dl_type != htons(ETH_TYPE_IP)) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_DEC_TTL:
        if (!is_ip_any(flow)) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
        if (!is_ip_any(flow) || (flow->nw_frag & FLOW_NW_FRAG_LATER) ||
            (flow->nw_proto != IPPROTO_TCP && flow->nw_proto != IPPROTO_UDP
             && flow->nw_proto != IPPROTO_SCTP)) {
            inconsistent_match(usable_protocols);
        }
        /* Note on which transport protocol the port numbers are set.
         * This allows this set action to be converted to an OF1.2 set field
         * action. */
        if (a->type == OFPACT_SET_L4_SRC_PORT) {
            ofpact_get_SET_L4_SRC_PORT(a)->flow_ip_proto = flow->nw_proto;
        } else {
            ofpact_get_SET_L4_DST_PORT(a)->flow_ip_proto = flow->nw_proto;
        }
        return 0;

    case OFPACT_REG_MOVE:
        return nxm_reg_move_check(ofpact_get_REG_MOVE(a), match);

    case OFPACT_SET_FIELD:
        mf = ofpact_get_SET_FIELD(a)->field;
        /* Require OXM_OF_VLAN_VID to have an existing VLAN header. */
        if (!mf_are_prereqs_ok(mf, flow, NULL) ||
            (mf->id == MFF_VLAN_VID &&
             !(flow->vlans[0].tci & htons(VLAN_CFI)))) {
            VLOG_WARN_RL(&rl, "set_field %s lacks correct prerequisites",
                         mf->name);
            return OFPERR_OFPBAC_MATCH_INCONSISTENT;
        }
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1 if need be. */
        ofpact_get_SET_FIELD(a)->flow_has_vlan =
            (flow->vlans[0].tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (mf->id == MFF_VLAN_TCI) {
            /* The set field may add or remove the vlan tag,
             * Mark the status temporarily. */
            flow->vlans[0].tci = ofpact_get_SET_FIELD(a)->value->be16;
        }
        return 0;

    case OFPACT_STACK_PUSH:
        return nxm_stack_push_check(ofpact_get_STACK_PUSH(a), match);

    case OFPACT_STACK_POP:
        return nxm_stack_pop_check(ofpact_get_STACK_POP(a), match);

    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
        if (!eth_type_mpls(dl_type)) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
        return 0;

    case OFPACT_RESUBMIT: {
        struct ofpact_resubmit *resubmit = ofpact_get_RESUBMIT(a);

        if (resubmit->with_ct_orig && !is_ct_valid(flow, &match->wc, NULL)) {
            return OFPERR_OFPBAC_MATCH_INCONSISTENT;
        }
        return 0;
    }
    case OFPACT_FIN_TIMEOUT:
        if (flow->nw_proto != IPPROTO_TCP) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_LEARN:
        return learn_check(ofpact_get_LEARN(a), match);

    case OFPACT_CONJUNCTION:
        return 0;

    case OFPACT_MULTIPATH:
        return multipath_check(ofpact_get_MULTIPATH(a), match);

    case OFPACT_NOTE:
    case OFPACT_EXIT:
        return 0;

    case OFPACT_PUSH_MPLS:
        if (flow->packet_type != htonl(PT_ETH)) {
            inconsistent_match(usable_protocols);
        }
        flow->dl_type = ofpact_get_PUSH_MPLS(a)->ethertype;
        /* The packet is now MPLS and the MPLS payload is opaque.
         * Thus nothing can be assumed about the network protocol.
         * Temporarily mark that we have no nw_proto. */
        flow->nw_proto = 0;
        return 0;

    case OFPACT_POP_MPLS:
        if (flow->packet_type != htonl(PT_ETH)
            || !eth_type_mpls(dl_type)) {
            inconsistent_match(usable_protocols);
        }
        flow->dl_type = ofpact_get_POP_MPLS(a)->ethertype;
        return 0;

    case OFPACT_SAMPLE:
        return 0;

    case OFPACT_CLONE: {
        struct ofpact_nest *on = ofpact_get_CLONE(a);
        return ofpacts_check(on->actions, ofpact_nest_get_action_len(on),
                             match, max_ports, table_id, n_tables,
                             usable_protocols);
    }

    case OFPACT_CT: {
        struct ofpact_conntrack *oc = ofpact_get_CT(a);

        if (!dl_type_is_ip_any(dl_type)
            || (flow->ct_state & CS_INVALID && oc->flags & NX_CT_F_COMMIT)
            || (oc->alg == IPPORT_FTP && flow->nw_proto != IPPROTO_TCP)
            || (oc->alg == IPPORT_TFTP && flow->nw_proto != IPPROTO_UDP)) {
            /* We can't downgrade to OF1.0 and expect inconsistent CT actions
             * be silently discarded.  Instead, datapath flow install fails, so
             * it is better to flag inconsistent CT actions as hard errors. */
            return OFPERR_OFPBAC_MATCH_INCONSISTENT;
        }

        if (oc->zone_src.field) {
            return mf_check_src(&oc->zone_src, match);
        }

        return ofpacts_check(oc->actions, ofpact_ct_get_action_len(oc),
                             match, max_ports, table_id, n_tables,
                             usable_protocols);
    }

    case OFPACT_CT_CLEAR:
        return 0;

    case OFPACT_NAT: {
        struct ofpact_nat *on = ofpact_get_NAT(a);

        if (!dl_type_is_ip_any(dl_type) ||
            (on->range_af == AF_INET && dl_type != htons(ETH_TYPE_IP)) ||
            (on->range_af == AF_INET6
             && dl_type != htons(ETH_TYPE_IPV6))) {
            return OFPERR_OFPBAC_MATCH_INCONSISTENT;
        }
        return 0;
    }

    case OFPACT_CLEAR_ACTIONS:
        return 0;

    case OFPACT_WRITE_ACTIONS: {
        /* Use a temporary copy of 'usable_protocols' because we can't check
         * consistency of an action set. */
        struct ofpact_nest *on = ofpact_get_WRITE_ACTIONS(a);
        enum ofputil_protocol p = *usable_protocols;
        return ofpacts_check(on->actions, ofpact_nest_get_action_len(on),
                             match, max_ports, table_id, n_tables, &p);
    }

    case OFPACT_WRITE_METADATA:
        return 0;

    case OFPACT_METER: {
        uint32_t mid = ofpact_get_METER(a)->meter_id;
        if (mid == 0 || mid > OFPM13_MAX) {
            return OFPERR_OFPMMFC_INVALID_METER;
        }
        return 0;
    }

    case OFPACT_GOTO_TABLE: {
        uint8_t goto_table = ofpact_get_GOTO_TABLE(a)->table_id;
        if ((table_id != 255 && goto_table <= table_id)
            || (n_tables != 255 && goto_table >= n_tables)) {
            return OFPERR_OFPBIC_BAD_TABLE_ID;
        }
        return 0;
    }

    case OFPACT_GROUP:
        return 0;

    case OFPACT_UNROLL_XLATE:
        /* UNROLL is an internal action that should never be seen via
         * OpenFlow. */
        return OFPERR_OFPBAC_BAD_TYPE;

    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
        return 0;

    case OFPACT_ENCAP:
        flow->packet_type = ofpact_get_ENCAP(a)->new_pkt_type;
        if (pt_ns(flow->packet_type) == OFPHTN_ETHERTYPE) {
            flow->dl_type = htons(pt_ns_type(flow->packet_type));
        }
        if (!is_ip_any(flow)) {
            flow->nw_proto = 0;
        }
        return 0;

    case OFPACT_DECAP:
        if (flow->packet_type == htonl(PT_ETH)) {
            /* Adjust the packet_type to allow subsequent actions. */
            flow->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE,
                                               ntohs(flow->dl_type));
        } else {
            /* The actual packet_type is only known after decapsulation.
             * Do not allow subsequent actions that depend on packet headers. */
            flow->packet_type = htonl(PT_UNKNOWN);
            flow->dl_type = OVS_BE16_MAX;
        }
        return 0;

    case OFPACT_DEC_NSH_TTL:
        if ((flow->packet_type != htonl(PT_NSH)) &&
            (flow->dl_type != htons(ETH_TYPE_NSH))) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    default:
        OVS_NOT_REACHED();
    }
}

/* Checks that the 'ofpacts_len' bytes of actions in 'ofpacts' are
 * appropriate for a packet with the prerequisites satisfied by 'flow' in a
 * switch with no more than 'max_ports' ports.
 *
 * If 'ofpacts' and 'flow' are inconsistent with one another, un-sets in
 * '*usable_protocols' the protocols that forbid the inconsistency.  (An
 * example of an inconsistency between match and actions is a flow that does
 * not match on an MPLS Ethertype but has an action that pops an MPLS label.)
 *
 * May annotate ofpacts with information gathered from the 'match'.
 *
 * May temporarily modify 'match', but restores the changes before
 * returning. */
enum ofperr
ofpacts_check(struct ofpact ofpacts[], size_t ofpacts_len,
              struct match *match, ofp_port_t max_ports,
              uint8_t table_id, uint8_t n_tables,
              enum ofputil_protocol *usable_protocols)
{
    struct ofpact *a;
    ovs_be32 packet_type = match->flow.packet_type;
    ovs_be16 dl_type = match->flow.dl_type;
    uint8_t nw_proto = match->flow.nw_proto;
    enum ofperr error = 0;
    union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS];

    memcpy(&vlans, &match->flow.vlans, sizeof(vlans));

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        error = ofpact_check__(usable_protocols, a, match,
                               max_ports, table_id, n_tables);
        if (error) {
            break;
        }
    }
    /* Restore fields that may have been modified. */
    match->flow.packet_type = packet_type;
    match->flow.dl_type = dl_type;
    memcpy(&match->flow.vlans, &vlans, sizeof(vlans));
    match->flow.nw_proto = nw_proto;
    return error;
}

/* Like ofpacts_check(), but reports inconsistencies as
 * OFPERR_OFPBAC_MATCH_INCONSISTENT rather than clearing bits. */
enum ofperr
ofpacts_check_consistency(struct ofpact ofpacts[], size_t ofpacts_len,
                          struct match *match, ofp_port_t max_ports,
                          uint8_t table_id, uint8_t n_tables,
                          enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol p = usable_protocols;
    enum ofperr error;

    error = ofpacts_check(ofpacts, ofpacts_len, match, max_ports,
                          table_id, n_tables, &p);
    return (error ? error
            : p != usable_protocols ? OFPERR_OFPBAC_MATCH_INCONSISTENT
            : 0);
}

/* Returns the destination field that 'ofpact' would write to, or NULL
 * if the action would not write to an mf_field. */
const struct mf_field *
ofpact_get_mf_dst(const struct ofpact *ofpact)
{
    if (ofpact->type == OFPACT_SET_FIELD) {
        const struct ofpact_set_field *orl;

        orl = CONTAINER_OF(ofpact, struct ofpact_set_field, ofpact);
        return orl->field;
    } else if (ofpact->type == OFPACT_REG_MOVE) {
        const struct ofpact_reg_move *orm;

        orm = CONTAINER_OF(ofpact, struct ofpact_reg_move, ofpact);
        return orm->dst.field;
    }

    return NULL;
}

static enum ofperr
unsupported_nesting(enum ofpact_type action, enum ofpact_type outer_action)
{
    VLOG_WARN("%s action doesn't support nested action %s",
              ofpact_name(outer_action), ofpact_name(action));
    return OFPERR_OFPBAC_BAD_ARGUMENT;
}

static bool
field_requires_ct(enum mf_field_id field)
{
    return field == MFF_CT_MARK || field == MFF_CT_LABEL;
}

/* Apply nesting constraints for actions */
static enum ofperr
ofpacts_verify_nested(const struct ofpact *a, enum ofpact_type outer_action)
{
    const struct mf_field *field = ofpact_get_mf_dst(a);

    if (field && field_requires_ct(field->id) && outer_action != OFPACT_CT) {
        VLOG_WARN("cannot set CT fields outside of ct action");
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }
    if (a->type == OFPACT_NAT) {
        if (outer_action != OFPACT_CT) {
            VLOG_WARN("Cannot have NAT action outside of \"ct\" action");
            return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
        }
        return 0;
    }

    if (outer_action) {
        ovs_assert(outer_action == OFPACT_WRITE_ACTIONS
                   || outer_action == OFPACT_CT);

        if (outer_action == OFPACT_CT) {
            if (!field) {
                return unsupported_nesting(a->type, outer_action);
            } else if (!field_requires_ct(field->id)) {
                VLOG_WARN("%s action doesn't support nested modification "
                          "of %s", ofpact_name(outer_action), field->name);
                return OFPERR_OFPBAC_BAD_ARGUMENT;
            }
        }
    }

    return 0;
}

/* Verifies that the 'ofpacts_len' bytes of actions in 'ofpacts' are in the
 * appropriate order as defined by the OpenFlow spec and as required by Open
 * vSwitch.
 *
 * 'allowed_ovsinsts' is a bitmap of OVSINST_* values, in which 1-bits indicate
 * instructions that are allowed within 'ofpacts[]'.
 *
 * If 'outer_action' is not zero, it specifies that the actions are nested
 * within another action of type 'outer_action'. */
static enum ofperr
ofpacts_verify(const struct ofpact ofpacts[], size_t ofpacts_len,
               uint32_t allowed_ovsinsts, enum ofpact_type outer_action)
{
    const struct ofpact *a;
    enum ovs_instruction_type inst;

    inst = OVSINST_OFPIT13_METER;
    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        enum ovs_instruction_type next;
        enum ofperr error;

        if (a->type == OFPACT_CONJUNCTION) {
            OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
                if (a->type != OFPACT_CONJUNCTION && a->type != OFPACT_NOTE) {
                    VLOG_WARN("\"conjunction\" actions may be used along with "
                              "\"note\" but not any other kind of action "
                              "(such as the \"%s\" action used here)",
                              ofpact_name(a->type));
                    return OFPERR_NXBAC_BAD_CONJUNCTION;
                }
            }
            return 0;
        }

        error = ofpacts_verify_nested(a, outer_action);
        if (error) {
            return error;
        }

        next = ovs_instruction_type_from_ofpact_type(a->type);
        if (a > ofpacts
            && (inst == OVSINST_OFPIT11_APPLY_ACTIONS
                ? next < inst
                : next <= inst)) {
            const char *name = ovs_instruction_name_from_type(inst);
            const char *next_name = ovs_instruction_name_from_type(next);

            if (next == inst) {
                VLOG_WARN("duplicate %s instruction not allowed, for OpenFlow "
                          "1.1+ compatibility", name);
            } else {
                VLOG_WARN("invalid instruction ordering: %s must appear "
                          "before %s, for OpenFlow 1.1+ compatibility",
                          next_name, name);
            }
            return OFPERR_OFPBAC_UNSUPPORTED_ORDER;
        }
        if (!((1u << next) & allowed_ovsinsts)) {
            const char *name = ovs_instruction_name_from_type(next);

            VLOG_WARN("%s instruction not allowed here", name);
            return OFPERR_OFPBIC_UNSUP_INST;
        }

        inst = next;
    }

    return 0;
}

/* Converting ofpacts to OpenFlow. */

static void
encode_ofpact(const struct ofpact *a, enum ofp_version ofp_version,
              struct ofpbuf *out)
{
    switch (a->type) {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                              \
        case OFPACT_##ENUM:                                             \
            encode_##ENUM(ofpact_get_##ENUM(a), ofp_version, out);      \
            return;
        OFPACTS
#undef OFPACT
    default:
        OVS_NOT_REACHED();
    }
}

/* Converts the 'ofpacts_len' bytes of ofpacts in 'ofpacts' into OpenFlow
 * actions in 'openflow', appending the actions to any existing data in
 * 'openflow'. */
size_t
ofpacts_put_openflow_actions(const struct ofpact ofpacts[], size_t ofpacts_len,
                             struct ofpbuf *openflow,
                             enum ofp_version ofp_version)
{
    const struct ofpact *a;
    size_t start_size = openflow->size;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        encode_ofpact(a, ofp_version, openflow);
    }
    return openflow->size - start_size;
}

static enum ovs_instruction_type
ofpact_is_apply_actions(const struct ofpact *a)
{
    return (ovs_instruction_type_from_ofpact_type(a->type)
            == OVSINST_OFPIT11_APPLY_ACTIONS);
}

void
ofpacts_put_openflow_instructions(const struct ofpact ofpacts[],
                                  size_t ofpacts_len,
                                  struct ofpbuf *openflow,
                                  enum ofp_version ofp_version)
{
    const struct ofpact *end = ofpact_end(ofpacts, ofpacts_len);
    const struct ofpact *a;

    if (ofp_version == OFP10_VERSION) {
        ofpacts_put_openflow_actions(ofpacts, ofpacts_len, openflow,
                                     ofp_version);
        return;
    }

    a = ofpacts;
    while (a < end) {
        if (ofpact_is_apply_actions(a)) {
            size_t ofs = openflow->size;

            instruction_put_OFPIT11_APPLY_ACTIONS(openflow);
            do {
                encode_ofpact(a, ofp_version, openflow);
                a = ofpact_next(a);
            } while (a < end && ofpact_is_apply_actions(a));
            ofpacts_update_instruction_actions(openflow, ofs);
        } else {
            encode_ofpact(a, ofp_version, openflow);
            a = ofpact_next(a);
        }
    }
}

/* Sets of supported actions. */

/* Two-way translation between OVS's internal "OFPACT_*" representation of
 * actions and the "OFPAT_*" representation used in some OpenFlow version.
 * (OFPAT_* numbering varies from one OpenFlow version to another, so a given
 * instance is specific to one OpenFlow version.) */
struct ofpact_map {
    enum ofpact_type ofpact;    /* Internal name for action type. */
    int ofpat;                  /* OFPAT_* number from OpenFlow spec. */
};

static const struct ofpact_map *
get_ofpact_map(enum ofp_version version)
{
    /* OpenFlow 1.0 actions. */
    static const struct ofpact_map of10[] = {
        { OFPACT_OUTPUT, 0 },
        { OFPACT_SET_VLAN_VID, 1 },
        { OFPACT_SET_VLAN_PCP, 2 },
        { OFPACT_STRIP_VLAN, 3 },
        { OFPACT_SET_ETH_SRC, 4 },
        { OFPACT_SET_ETH_DST, 5 },
        { OFPACT_SET_IPV4_SRC, 6 },
        { OFPACT_SET_IPV4_DST, 7 },
        { OFPACT_SET_IP_DSCP, 8 },
        { OFPACT_SET_L4_SRC_PORT, 9 },
        { OFPACT_SET_L4_DST_PORT, 10 },
        { OFPACT_ENQUEUE, 11 },
        { 0, -1 },
    };

    /* OpenFlow 1.1 actions. */
    static const struct ofpact_map of11[] = {
        { OFPACT_OUTPUT, 0 },
        { OFPACT_SET_VLAN_VID, 1 },
        { OFPACT_SET_VLAN_PCP, 2 },
        { OFPACT_SET_ETH_SRC, 3 },
        { OFPACT_SET_ETH_DST, 4 },
        { OFPACT_SET_IPV4_SRC, 5 },
        { OFPACT_SET_IPV4_DST, 6 },
        { OFPACT_SET_IP_DSCP, 7 },
        { OFPACT_SET_IP_ECN, 8 },
        { OFPACT_SET_L4_SRC_PORT, 9 },
        { OFPACT_SET_L4_DST_PORT, 10 },
        /* OFPAT_COPY_TTL_OUT (11) not supported. */
        /* OFPAT_COPY_TTL_IN (12) not supported. */
        { OFPACT_SET_MPLS_LABEL, 13 },
        { OFPACT_SET_MPLS_TC, 14 },
        { OFPACT_SET_MPLS_TTL, 15 },
        { OFPACT_DEC_MPLS_TTL, 16 },
        { OFPACT_PUSH_VLAN, 17 },
        { OFPACT_STRIP_VLAN, 18 },
        { OFPACT_PUSH_MPLS, 19 },
        { OFPACT_POP_MPLS, 20 },
        { OFPACT_SET_QUEUE, 21 },
        { OFPACT_GROUP, 22 },
        { OFPACT_SET_IP_TTL, 23 },
        { OFPACT_DEC_TTL, 24 },
        { 0, -1 },
    };

    /* OpenFlow 1.2, 1.3, and 1.4 actions. */
    static const struct ofpact_map of12[] = {
        { OFPACT_OUTPUT, 0 },
        /* OFPAT_COPY_TTL_OUT (11) not supported. */
        /* OFPAT_COPY_TTL_IN (12) not supported. */
        { OFPACT_SET_MPLS_TTL, 15 },
        { OFPACT_DEC_MPLS_TTL, 16 },
        { OFPACT_PUSH_VLAN, 17 },
        { OFPACT_STRIP_VLAN, 18 },
        { OFPACT_PUSH_MPLS, 19 },
        { OFPACT_POP_MPLS, 20 },
        { OFPACT_SET_QUEUE, 21 },
        { OFPACT_GROUP, 22 },
        { OFPACT_SET_IP_TTL, 23 },
        { OFPACT_DEC_TTL, 24 },
        { OFPACT_SET_FIELD, 25 },
        /* OF1.3+ OFPAT_PUSH_PBB (26) not supported. */
        /* OF1.3+ OFPAT_POP_PBB (27) not supported. */
        { 0, -1 },
    };

    switch (version) {
    case OFP10_VERSION:
        return of10;

    case OFP11_VERSION:
        return of11;

    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
    default:
        return of12;
    }
}

/* Converts 'ofpacts_bitmap', a bitmap whose bits correspond to OFPACT_*
 * values, into a bitmap of actions suitable for OpenFlow 'version', and
 * returns the result. */
ovs_be32
ofpact_bitmap_to_openflow(uint64_t ofpacts_bitmap, enum ofp_version version)
{
    uint32_t openflow_bitmap = 0;
    const struct ofpact_map *x;

    for (x = get_ofpact_map(version); x->ofpat >= 0; x++) {
        if (ofpacts_bitmap & (UINT64_C(1) << x->ofpact)) {
            openflow_bitmap |= 1u << x->ofpat;
        }
    }
    return htonl(openflow_bitmap);
}

/* Converts 'ofpat_bitmap', a bitmap of actions from an OpenFlow message with
 * the given 'version' into a bitmap whose bits correspond to OFPACT_* values,
 * and returns the result. */
uint64_t
ofpact_bitmap_from_openflow(ovs_be32 ofpat_bitmap, enum ofp_version version)
{
    uint64_t ofpact_bitmap = 0;
    const struct ofpact_map *x;

    for (x = get_ofpact_map(version); x->ofpat >= 0; x++) {
        if (ofpat_bitmap & htonl(1u << x->ofpat)) {
            ofpact_bitmap |= UINT64_C(1) << x->ofpact;
        }
    }
    return ofpact_bitmap;
}

/* Appends to 's' a string representation of the set of OFPACT_* represented
 * by 'ofpacts_bitmap'. */
void
ofpact_bitmap_format(uint64_t ofpacts_bitmap, struct ds *s)
{
    if (!ofpacts_bitmap) {
        ds_put_cstr(s, "<none>");
    } else {
        while (ofpacts_bitmap) {
            ds_put_format(s, "%s ",
                          ofpact_name(rightmost_1bit_idx(ofpacts_bitmap)));
            ofpacts_bitmap = zero_rightmost_1bit(ofpacts_bitmap);
        }
        ds_chomp(s, ' ');
    }
}

/* Returns true if 'action' outputs to 'port', false otherwise. */
static bool
ofpact_outputs_to_port(const struct ofpact *ofpact, ofp_port_t port)
{
    switch (ofpact->type) {
    case OFPACT_OUTPUT:
        return ofpact_get_OUTPUT(ofpact)->port == port;
    case OFPACT_ENQUEUE:
        return ofpact_get_ENQUEUE(ofpact)->port == port;
    case OFPACT_CONTROLLER:
        return port == OFPP_CONTROLLER;

    case OFPACT_OUTPUT_REG:
    case OFPACT_OUTPUT_TRUNC:
    case OFPACT_BUNDLE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_PUSH_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_SET_FIELD:
    case OFPACT_STACK_PUSH:
    case OFPACT_STACK_POP:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_WRITE_METADATA:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_CONJUNCTION:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_UNROLL_XLATE:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_SAMPLE:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_CLONE:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
    case OFPACT_GROUP:
    case OFPACT_DEBUG_RECIRC:
    case OFPACT_DEBUG_SLOW:
    case OFPACT_CT:
    case OFPACT_CT_CLEAR:
    case OFPACT_NAT:
    case OFPACT_ENCAP:
    case OFPACT_DECAP:
    case OFPACT_DEC_NSH_TTL:
    default:
        return false;
    }
}

/* Returns true if any action in the 'ofpacts_len' bytes of 'ofpacts' outputs
 * to 'port', false otherwise. */
bool
ofpacts_output_to_port(const struct ofpact *ofpacts, size_t ofpacts_len,
                       ofp_port_t port)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH_FLATTENED (a, ofpacts, ofpacts_len) {
        if (ofpact_outputs_to_port(a, port)) {
            return true;
        }
    }

    return false;
}

/* Returns true if any action in the 'ofpacts_len' bytes of 'ofpacts' outputs
 * to 'group', false otherwise. */
bool
ofpacts_output_to_group(const struct ofpact *ofpacts, size_t ofpacts_len,
                        uint32_t group_id)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH_FLATTENED (a, ofpacts, ofpacts_len) {
        if (a->type == OFPACT_GROUP
            && ofpact_get_GROUP(a)->group_id == group_id) {
            return true;
        }
    }

    return false;
}

/* Returns true if the 'a_len' bytes of actions in 'a' and the 'b_len' bytes of
 * actions in 'b' are bytewise identical. */
bool
ofpacts_equal(const struct ofpact *a, size_t a_len,
              const struct ofpact *b, size_t b_len)
{
    return a_len == b_len && !memcmp(a, b, a_len);
}

/* Returns true if the 'a_len' bytes of actions in 'a' and the 'b_len' bytes of
 * actions in 'b' are identical when formatted as strings.  (Converting actions
 * to string form suppresses some rarely meaningful differences, such as the
 * 'compat' member of actions.) */
bool
ofpacts_equal_stringwise(const struct ofpact *a, size_t a_len,
                         const struct ofpact *b, size_t b_len)
{
    struct ds a_s = DS_EMPTY_INITIALIZER;
    struct ofpact_format_params a_fp = { .s = &a_s };
    ofpacts_format(a, a_len, &a_fp);

    struct ds b_s = DS_EMPTY_INITIALIZER;
    struct ofpact_format_params b_fp = { .s = &b_s };
    ofpacts_format(b, b_len, &b_fp);

    bool equal = !strcmp(ds_cstr(&a_s), ds_cstr(&b_s));

    ds_destroy(&a_s);
    ds_destroy(&b_s);

    return equal;
}

/* Finds the OFPACT_METER action, if any, in the 'ofpacts_len' bytes of
 * 'ofpacts'.  If found, returns its meter ID; if not, returns 0.
 *
 * This function relies on the order of 'ofpacts' being correct (as checked by
 * ofpacts_verify()). */
uint32_t
ofpacts_get_meter(const struct ofpact ofpacts[], size_t ofpacts_len)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        enum ovs_instruction_type inst;

        inst = ovs_instruction_type_from_ofpact_type(a->type);
        if (a->type == OFPACT_METER) {
            return ofpact_get_METER(a)->meter_id;
        } else if (inst > OVSINST_OFPIT13_METER) {
            break;
        }
    }

    return 0;
}

/* Formatting ofpacts. */

static void
ofpact_format(const struct ofpact *a,
              const struct ofpact_format_params *fp)
{
    switch (a->type) {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                              \
        case OFPACT_##ENUM:                                             \
            format_##ENUM(ALIGNED_CAST(const struct STRUCT *, a), fp);  \
            break;
        OFPACTS
#undef OFPACT
    default:
        OVS_NOT_REACHED();
    }
}

/* Appends a string representing the 'ofpacts_len' bytes of ofpacts in
 * 'ofpacts' to 'fp->s'.  If 'port_map' is nonnull, uses it to translate port
 * numbers to names in output. */
void
ofpacts_format(const struct ofpact *ofpacts, size_t ofpacts_len,
               const struct ofpact_format_params *fp)
{
    if (!ofpacts_len) {
        ds_put_format(fp->s, "%sdrop%s", colors.drop, colors.end);
    } else {
        const struct ofpact *a;

        OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
            if (a != ofpacts) {
                ds_put_char(fp->s, ',');
            }

            ofpact_format(a, fp);
        }
    }
}

/* Internal use by helpers. */

/* Implementation of ofpact_put_<ENUM>(). */
void *
ofpact_put(struct ofpbuf *ofpacts, enum ofpact_type type, size_t len)
{
    struct ofpact *ofpact;

    ofpacts->header = ofpbuf_put_uninit(ofpacts, len);
    ofpact = ofpacts->header;
    ofpact_init(ofpact, type, len);
    return ofpact;
}

/* Implementation of ofpact_init_<ENUM>(). */
void
ofpact_init(struct ofpact *ofpact, enum ofpact_type type, size_t len)
{
    memset(ofpact, 0, len);
    ofpact->type = type;
    ofpact->raw = -1;
    ofpact->len = len;
}

/* Implementation of ofpact_finish_<ENUM>().
 *
 * Finishes composing a variable-length action (begun using
 * ofpact_put_<NAME>()), by padding the action to a multiple of OFPACT_ALIGNTO
 * bytes and updating its embedded length field.  See the large comment near
 * the end of ofp-actions.h for more information.
 *
 * May reallocate 'ofpacts'. Callers should consider updating their 'ofpact'
 * pointer to the return value of this function. */
void *
ofpact_finish(struct ofpbuf *ofpacts, struct ofpact *ofpact)
{
    ptrdiff_t len;

    ovs_assert(ofpact == ofpacts->header);
    len = (char *) ofpbuf_tail(ofpacts) - (char *) ofpact;
    ovs_assert(len > 0 && len <= UINT16_MAX);
    ofpact->len = len;
    ofpbuf_padto(ofpacts, OFPACT_ALIGN(ofpacts->size));

    return ofpacts->header;
}

static char * OVS_WARN_UNUSED_RESULT
ofpact_parse(enum ofpact_type type, char *value,
             const struct ofpact_parse_params *pp)
{
    switch (type) {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                              \
        case OFPACT_##ENUM:                                             \
            return parse_##ENUM(value, pp);
        OFPACTS
#undef OFPACT
    default:
        OVS_NOT_REACHED();
    }
}

static bool
ofpact_type_from_name(const char *name, enum ofpact_type *type)
{
#define OFPACT(ENUM, STRUCT, MEMBER, NAME)                            \
    if (!strcasecmp(name, NAME)) {                                    \
        *type = OFPACT_##ENUM;                                          \
        return true;                                                    \
    }
    OFPACTS
#undef OFPACT

    return false;
}

/* Parses 'str' as a series of instructions, and appends them to 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 *
 * If 'outer_action' is specified, indicates that the actions being parsed
 * are nested within another action of the type specified in 'outer_action'. */
static char * OVS_WARN_UNUSED_RESULT
ofpacts_parse__(char *str, const struct ofpact_parse_params *pp,
                bool allow_instructions, enum ofpact_type outer_action)
{
    int prev_inst = -1;
    enum ofperr retval;
    char *key, *value;
    bool drop = false;
    char *pos;

    pos = str;
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        enum ovs_instruction_type inst = OVSINST_OFPIT11_APPLY_ACTIONS;
        enum ofpact_type type;
        char *error = NULL;
        ofp_port_t port;

        if (ofpact_type_from_name(key, &type)) {
            error = ofpact_parse(type, value, pp);
            inst = ovs_instruction_type_from_ofpact_type(type);
        } else if (!strcasecmp(key, "mod_vlan_vid")) {
            error = parse_set_vlan_vid(value, true, pp);
        } else if (!strcasecmp(key, "mod_vlan_pcp")) {
            error = parse_set_vlan_pcp(value, true, pp);
        } else if (!strcasecmp(key, "set_nw_ttl")) {
            error = parse_SET_IP_TTL(value, pp);
        } else if (!strcasecmp(key, "pop_vlan")) {
            error = parse_pop_vlan(pp);
        } else if (!strcasecmp(key, "set_tunnel64")) {
            error = parse_set_tunnel(value, NXAST_RAW_SET_TUNNEL64, pp);
        } else if (!strcasecmp(key, "load")) {
            error = parse_reg_load(value, pp);
        } else if (!strcasecmp(key, "bundle_load")) {
            error = parse_bundle_load(value, pp);
        } else if (!strcasecmp(key, "drop")) {
            drop = true;
        } else if (!strcasecmp(key, "apply_actions")) {
            return xstrdup("apply_actions is the default instruction");
        } else if (ofputil_port_from_string(key, pp->port_map, &port)) {
            ofpact_put_OUTPUT(pp->ofpacts)->port = port;
        } else {
            return xasprintf("unknown action %s", key);
        }
        if (error) {
            return error;
        }

        if (inst != OVSINST_OFPIT11_APPLY_ACTIONS) {
            if (!allow_instructions) {
                return xasprintf("only actions are allowed here (not "
                                 "instruction %s)",
                                 ovs_instruction_name_from_type(inst));
            }
            if (inst == prev_inst) {
                return xasprintf("instruction %s may be specified only once",
                                 ovs_instruction_name_from_type(inst));
            }
        }
        if (prev_inst != -1 && inst < prev_inst) {
            return xasprintf("instruction %s must be specified before %s",
                             ovs_instruction_name_from_type(inst),
                             ovs_instruction_name_from_type(prev_inst));
        }
        prev_inst = inst;
    }

    if (drop && pp->ofpacts->size) {
        return xstrdup("\"drop\" must not be accompanied by any other action "
                       "or instruction");
    }

    retval = ofpacts_verify(pp->ofpacts->data, pp->ofpacts->size,
                            (allow_instructions
                             ? (1u << N_OVS_INSTRUCTIONS) - 1
                             : 1u << OVSINST_OFPIT11_APPLY_ACTIONS),
                            outer_action);
    if (retval) {
        return xstrdup("Incorrect instruction ordering");
    }

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
ofpacts_parse(char *str, const struct ofpact_parse_params *pp,
              bool allow_instructions, enum ofpact_type outer_action)
{
    uint32_t orig_size = pp->ofpacts->size;
    char *error = ofpacts_parse__(str, pp, allow_instructions, outer_action);
    if (error) {
        pp->ofpacts->size = orig_size;
    }
    return error;
}

static char * OVS_WARN_UNUSED_RESULT
ofpacts_parse_copy(const char *s_, const struct ofpact_parse_params *pp,
                   bool allow_instructions, enum ofpact_type outer_action)
{
    char *error, *s;

    *pp->usable_protocols = OFPUTIL_P_ANY;

    s = xstrdup(s_);
    error = ofpacts_parse(s, pp, allow_instructions, outer_action);
    free(s);

    return error;
}

/* Parses 's' as a set of OpenFlow actions and appends the actions to
 * 'ofpacts'. 'outer_action', if nonzero, specifies that 's' contains actions
 * that are nested within the action of type 'outer_action'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
ofpacts_parse_actions(const char *s, const struct ofpact_parse_params *pp)
{
    return ofpacts_parse_copy(s, pp, false, 0);
}

/* Parses 's' as a set of OpenFlow instructions and appends the instructions to
 * 'ofpacts'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
ofpacts_parse_instructions(const char *s, const struct ofpact_parse_params *pp)
{
    return ofpacts_parse_copy(s, pp, true, 0);
}

const char *
ofpact_name(enum ofpact_type type)
{
    switch (type) {
#define OFPACT(ENUM, STRUCT, MEMBER, NAME) case OFPACT_##ENUM: return NAME;
        OFPACTS
#undef OFPACT
    }
    return "<unknown>";
}

/* Low-level action decoding and encoding functions. */

/* Everything needed to identify a particular OpenFlow action. */
struct ofpact_hdrs {
    uint32_t vendor;              /* 0 if standard, otherwise a vendor code. */
    uint16_t type;                /* Type if standard, otherwise subtype. */
    uint8_t ofp_version;          /* From ofp_header. */
};

/* Information about a particular OpenFlow action. */
struct ofpact_raw_instance {
    /* The action's identity. */
    struct ofpact_hdrs hdrs;
    enum ofp_raw_action_type raw;

    /* Looking up the action. */
    struct hmap_node decode_node; /* Based on 'hdrs'. */
    struct hmap_node encode_node; /* Based on 'raw' + 'hdrs.ofp_version'. */

    /* The action's encoded size.
     *
     * If this action is fixed-length, 'min_length' == 'max_length'.
     * If it is variable length, then 'max_length' is ROUND_DOWN(UINT16_MAX,
     * OFP_ACTION_ALIGN) == 65528. */
    unsigned short int min_length;
    unsigned short int max_length;

    /* For actions with a simple integer numeric argument, 'arg_ofs' is the
     * offset of that argument from the beginning of the action and 'arg_len'
     * its length, both in bytes.
     *
     * For actions that take other forms, these are both zero. */
    unsigned short int arg_ofs;
    unsigned short int arg_len;

    /* The name of the action, e.g. "OFPAT_OUTPUT" or "NXAST_RESUBMIT". */
    const char *name;

    /* If this action is deprecated, a human-readable string with a brief
     * explanation. */
    const char *deprecation;
};

/* Action header. */
struct ofp_action_header {
    /* The meaning of other values of 'type' generally depends on the OpenFlow
     * version (see enum ofp_raw_action_type).
     *
     * Across all OpenFlow versions, OFPAT_VENDOR indicates that 'vendor'
     * designates an OpenFlow vendor ID and that the remainder of the action
     * structure has a vendor-defined meaning.
     */
#define OFPAT_VENDOR 0xffff
    ovs_be16 type;

    /* Always a multiple of 8. */
    ovs_be16 len;

    /* For type == OFPAT_VENDOR only, this is a vendor ID, e.g. NX_VENDOR_ID or
     * ONF_VENDOR_ID.  Other 'type's use this space for some other purpose. */
    ovs_be32 vendor;
};
OFP_ASSERT(sizeof(struct ofp_action_header) == 8);

static bool
ofpact_hdrs_equal(const struct ofpact_hdrs *a,
                  const struct ofpact_hdrs *b)
{
    return (a->vendor == b->vendor
            && a->type == b->type
            && a->ofp_version == b->ofp_version);
}

static uint32_t
ofpact_hdrs_hash(const struct ofpact_hdrs *hdrs)
{
    return hash_2words(hdrs->vendor,
                       ((uint32_t) hdrs->type << 16) | hdrs->ofp_version);
}

#include "ofp-actions.inc2"

static struct hmap *
ofpact_decode_hmap(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static struct hmap hmap;

    if (ovsthread_once_start(&once)) {
        struct ofpact_raw_instance *inst;

        hmap_init(&hmap);
        for (inst = all_raw_instances;
             inst < &all_raw_instances[ARRAY_SIZE(all_raw_instances)];
             inst++) {
            hmap_insert(&hmap, &inst->decode_node,
                        ofpact_hdrs_hash(&inst->hdrs));
        }
        ovsthread_once_done(&once);
    }
    return &hmap;
}

static struct hmap *
ofpact_encode_hmap(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static struct hmap hmap;

    if (ovsthread_once_start(&once)) {
        struct ofpact_raw_instance *inst;

        hmap_init(&hmap);
        for (inst = all_raw_instances;
             inst < &all_raw_instances[ARRAY_SIZE(all_raw_instances)];
             inst++) {
            hmap_insert(&hmap, &inst->encode_node,
                        hash_2words(inst->raw, inst->hdrs.ofp_version));
        }
        ovsthread_once_done(&once);
    }
    return &hmap;
}

static enum ofperr
ofpact_decode_raw(enum ofp_version ofp_version,
                  const struct ofp_action_header *oah, size_t length,
                  const struct ofpact_raw_instance **instp)
{
    const struct ofpact_raw_instance *inst;
    struct ofpact_hdrs hdrs;

    *instp = NULL;
    if (length < sizeof *oah) {
        return OFPERR_OFPBAC_BAD_LEN;
    }

    /* Get base action type. */
    if (oah->type == htons(OFPAT_VENDOR)) {
        /* Get vendor. */
        hdrs.vendor = ntohl(oah->vendor);
        if (hdrs.vendor == NX_VENDOR_ID || hdrs.vendor == ONF_VENDOR_ID) {
            /* Get extension subtype. */
            const struct ext_action_header *nah;

            nah = ALIGNED_CAST(const struct ext_action_header *, oah);
            if (length < sizeof *nah) {
                return OFPERR_OFPBAC_BAD_LEN;
            }
            hdrs.type = ntohs(nah->subtype);
        } else {
            VLOG_WARN_RL(&rl, "OpenFlow action has unknown vendor %#"PRIx32,
                         hdrs.vendor);
            return OFPERR_OFPBAC_BAD_VENDOR;
        }
    } else {
        hdrs.vendor = 0;
        hdrs.type = ntohs(oah->type);
    }

    hdrs.ofp_version = ofp_version;
    HMAP_FOR_EACH_WITH_HASH (inst, decode_node, ofpact_hdrs_hash(&hdrs),
                             ofpact_decode_hmap()) {
        if (ofpact_hdrs_equal(&hdrs, &inst->hdrs)) {
            *instp = inst;
            return 0;
        }
    }

    VLOG_WARN_RL(&rl, "unknown %s action for vendor %#"PRIx32" and "
                 "type %"PRIu16, ofputil_version_to_string(ofp_version),
                 hdrs.vendor, hdrs.type);
    return (hdrs.vendor
            ? OFPERR_OFPBAC_BAD_VENDOR_TYPE
            : OFPERR_OFPBAC_BAD_TYPE);
}

static enum ofperr
ofpact_pull_raw(struct ofpbuf *buf, enum ofp_version ofp_version,
                enum ofp_raw_action_type *raw, uint64_t *arg)
{
    const struct ofp_action_header *oah = buf->data;
    const struct ofpact_raw_instance *action;
    unsigned int length;
    enum ofperr error;

    *raw = *arg = 0;
    error = ofpact_decode_raw(ofp_version, oah, buf->size, &action);
    if (error) {
        return error;
    }

    if (action->deprecation) {
        VLOG_INFO_RL(&rl, "%s is deprecated in %s (%s)",
                     action->name, ofputil_version_to_string(ofp_version),
                     action->deprecation);
    }

    length = ntohs(oah->len);
    if (length > buf->size) {
        VLOG_WARN_RL(&rl, "OpenFlow action %s length %u exceeds action buffer "
                     "length %"PRIu32, action->name, length, buf->size);
        return OFPERR_OFPBAC_BAD_LEN;
    }
    if (length < action->min_length || length > action->max_length) {
        VLOG_WARN_RL(&rl, "OpenFlow action %s length %u not in valid range "
                     "[%hu,%hu]", action->name, length,
                     action->min_length, action->max_length);
        return OFPERR_OFPBAC_BAD_LEN;
    }
    if (length % 8) {
        VLOG_WARN_RL(&rl, "OpenFlow action %s length %u is not a multiple "
                     "of 8", action->name, length);
        return OFPERR_OFPBAC_BAD_LEN;
    }

    *raw = action->raw;
    *arg = 0;
    if (action->arg_len) {
        const uint8_t *p;
        int i;

        p = ofpbuf_at_assert(buf, action->arg_ofs, action->arg_len);
        for (i = 0; i < action->arg_len; i++) {
            *arg = (*arg << 8) | p[i];
        }
    }

    ofpbuf_pull(buf, length);

    return 0;
}

static const struct ofpact_raw_instance *
ofpact_raw_lookup(enum ofp_version ofp_version, enum ofp_raw_action_type raw)
{
    const struct ofpact_raw_instance *inst;

    HMAP_FOR_EACH_WITH_HASH (inst, encode_node, hash_2words(raw, ofp_version),
                             ofpact_encode_hmap()) {
        if (inst->raw == raw && inst->hdrs.ofp_version == ofp_version) {
            return inst;
        }
    }
    OVS_NOT_REACHED();
}

static void *
ofpact_put_raw(struct ofpbuf *buf, enum ofp_version ofp_version,
               enum ofp_raw_action_type raw, uint64_t arg)
{
    const struct ofpact_raw_instance *inst;
    struct ofp_action_header *oah;
    const struct ofpact_hdrs *hdrs;

    inst = ofpact_raw_lookup(ofp_version, raw);
    hdrs = &inst->hdrs;

    oah = ofpbuf_put_zeros(buf, inst->min_length);
    oah->type = htons(hdrs->vendor ? OFPAT_VENDOR : hdrs->type);
    oah->len = htons(inst->min_length);
    oah->vendor = htonl(hdrs->vendor);

    switch (hdrs->vendor) {
    case 0:
        break;

    case NX_VENDOR_ID:
    case ONF_VENDOR_ID: {
        struct ext_action_header *nah = (struct ext_action_header *) oah;
        nah->subtype = htons(hdrs->type);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }

    if (inst->arg_len) {
        uint8_t *p = (uint8_t *) oah + inst->arg_ofs + inst->arg_len;
        int i;

        for (i = 0; i < inst->arg_len; i++) {
            *--p = arg;
            arg >>= 8;
        }
    } else {
        ovs_assert(!arg);
    }

    return oah;
}

static void
pad_ofpat(struct ofpbuf *openflow, size_t start_ofs)
{
    struct ofp_action_header *oah;

    ofpbuf_put_zeros(openflow, PAD_SIZE(openflow->size - start_ofs,
                                        OFP_ACTION_ALIGN));

    oah = ofpbuf_at_assert(openflow, start_ofs, sizeof *oah);
    oah->len = htons(openflow->size - start_ofs);
}

