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

#include <config.h>
#include "ofp-actions.h"
#include "bundle.h"
#include "byte-order.h"
#include "compiler.h"
#include "dynamic-string.h"
#include "learn.h"
#include "meta-flow.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_actions);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Converting OpenFlow 1.0 to ofpacts. */

union ofp_action {
    ovs_be16 type;
    struct ofp_action_header header;
    struct ofp_action_vendor_header vendor;
    struct ofp10_action_output output10;
    struct ofp_action_vlan_vid vlan_vid;
    struct ofp_action_vlan_pcp vlan_pcp;
    struct ofp_action_nw_addr nw_addr;
    struct ofp_action_nw_tos nw_tos;
    struct ofp11_action_nw_ecn nw_ecn;
    struct ofp11_action_nw_ttl nw_ttl;
    struct ofp_action_tp_port tp_port;
    struct ofp_action_dl_addr dl_addr;
    struct ofp10_action_enqueue enqueue;
    struct ofp11_action_output ofp11_output;
    struct ofp11_action_push push;
    struct ofp11_action_pop_mpls ofp11_pop_mpls;
    struct ofp11_action_set_queue ofp11_set_queue;
    struct ofp11_action_mpls_label ofp11_mpls_label;
    struct ofp11_action_mpls_tc ofp11_mpls_tc;
    struct ofp11_action_mpls_ttl ofp11_mpls_ttl;
    struct ofp11_action_group group;
    struct ofp12_action_set_field set_field;
    struct nx_action_header nxa_header;
    struct nx_action_resubmit resubmit;
    struct nx_action_set_tunnel set_tunnel;
    struct nx_action_set_tunnel64 set_tunnel64;
    struct nx_action_write_metadata write_metadata;
    struct nx_action_set_queue set_queue;
    struct nx_action_reg_move reg_move;
    struct nx_action_reg_load reg_load;
    struct nx_action_stack stack;
    struct nx_action_note note;
    struct nx_action_multipath multipath;
    struct nx_action_bundle bundle;
    struct nx_action_output_reg output_reg;
    struct nx_action_cnt_ids cnt_ids;
    struct nx_action_fin_timeout fin_timeout;
    struct nx_action_controller controller;
    struct nx_action_push_mpls push_mpls;
    struct nx_action_mpls_ttl mpls_ttl;
    struct nx_action_pop_mpls pop_mpls;
    struct nx_action_sample sample;
    struct nx_action_learn learn;
    struct nx_action_mpls_label mpls_label;
    struct nx_action_mpls_tc mpls_tc;
};

static enum ofperr
output_from_openflow10(const struct ofp10_action_output *oao,
                       struct ofpbuf *out)
{
    struct ofpact_output *output;

    output = ofpact_put_OUTPUT(out);
    output->port = u16_to_ofp(ntohs(oao->port));
    output->max_len = ntohs(oao->max_len);

    return ofpact_check_output_port(output->port, OFPP_MAX);
}

static enum ofperr
enqueue_from_openflow10(const struct ofp10_action_enqueue *oae,
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
resubmit_from_openflow(const struct nx_action_resubmit *nar,
                       struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.compat = OFPUTIL_NXAST_RESUBMIT;
    resubmit->in_port = u16_to_ofp(ntohs(nar->in_port));
    resubmit->table_id = 0xff;
}

static enum ofperr
resubmit_table_from_openflow(const struct nx_action_resubmit *nar,
                             struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    if (nar->pad[0] || nar->pad[1] || nar->pad[2]) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.compat = OFPUTIL_NXAST_RESUBMIT_TABLE;
    resubmit->in_port = u16_to_ofp(ntohs(nar->in_port));
    resubmit->table_id = nar->table;
    return 0;
}

static enum ofperr
output_reg_from_openflow(const struct nx_action_output_reg *naor,
                         struct ofpbuf *out)
{
    struct ofpact_output_reg *output_reg;

    if (!is_all_zeros(naor->zero, sizeof naor->zero)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    output_reg = ofpact_put_OUTPUT_REG(out);
    output_reg->src.field = mf_from_nxm_header(ntohl(naor->src));
    output_reg->src.ofs = nxm_decode_ofs(naor->ofs_nbits);
    output_reg->src.n_bits = nxm_decode_n_bits(naor->ofs_nbits);
    output_reg->max_len = ntohs(naor->max_len);

    return mf_check_src(&output_reg->src, NULL);
}

static void
fin_timeout_from_openflow(const struct nx_action_fin_timeout *naft,
                          struct ofpbuf *out)
{
    struct ofpact_fin_timeout *oft;

    oft = ofpact_put_FIN_TIMEOUT(out);
    oft->fin_idle_timeout = ntohs(naft->fin_idle_timeout);
    oft->fin_hard_timeout = ntohs(naft->fin_hard_timeout);
}

static void
controller_from_openflow(const struct nx_action_controller *nac,
                         struct ofpbuf *out)
{
    struct ofpact_controller *oc;

    oc = ofpact_put_CONTROLLER(out);
    oc->max_len = ntohs(nac->max_len);
    oc->controller_id = ntohs(nac->controller_id);
    oc->reason = nac->reason;
}

static enum ofperr
metadata_from_nxast(const struct nx_action_write_metadata *nawm,
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
note_from_openflow(const struct nx_action_note *nan, struct ofpbuf *out)
{
    struct ofpact_note *note;
    unsigned int length;

    length = ntohs(nan->len) - offsetof(struct nx_action_note, note);
    note = ofpact_put(out, OFPACT_NOTE,
                      offsetof(struct ofpact_note, data) + length);
    note->length = length;
    memcpy(note->data, nan->note, length);
}

static enum ofperr
dec_ttl_from_openflow(struct ofpbuf *out, enum ofputil_action_code compat)
{
    uint16_t id = 0;
    struct ofpact_cnt_ids *ids;
    enum ofperr error = 0;

    ids = ofpact_put_DEC_TTL(out);
    ids->ofpact.compat = compat;
    ids->n_controllers = 1;
    ofpbuf_put(out, &id, sizeof id);
    ids = out->frame;
    ofpact_update_len(out, &ids->ofpact);
    return error;
}

static enum ofperr
dec_ttl_cnt_ids_from_openflow(const struct nx_action_cnt_ids *nac_ids,
                              struct ofpbuf *out)
{
    struct ofpact_cnt_ids *ids;
    size_t ids_size;
    int i;

    ids = ofpact_put_DEC_TTL(out);
    ids->ofpact.compat = OFPUTIL_NXAST_DEC_TTL_CNT_IDS;
    ids->n_controllers = ntohs(nac_ids->n_controllers);
    ids_size = ntohs(nac_ids->len) - sizeof *nac_ids;

    if (!is_all_zeros(nac_ids->zeros, sizeof nac_ids->zeros)) {
        return OFPERR_NXBRC_MUST_BE_ZERO;
    }

    if (ids_size < ids->n_controllers * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rl, "Nicira action dec_ttl_cnt_ids only has %"PRIuSIZE" bytes "
                     "allocated for controller ids.  %"PRIuSIZE" bytes are required for "
                     "%"PRIu16" controllers.", ids_size,
                     ids->n_controllers * sizeof(ovs_be16), ids->n_controllers);
        return OFPERR_OFPBAC_BAD_LEN;
    }

    for (i = 0; i < ids->n_controllers; i++) {
        uint16_t id = ntohs(((ovs_be16 *)(nac_ids + 1))[i]);
        ofpbuf_put(out, &id, sizeof id);
        ids = out->frame;
    }

    ofpact_update_len(out, &ids->ofpact);

    return 0;
}

static enum ofperr
sample_from_openflow(const struct nx_action_sample *nas,
                     struct ofpbuf *out)
{
    struct ofpact_sample *sample;

    sample = ofpact_put_SAMPLE(out);
    sample->probability = ntohs(nas->probability);
    sample->collector_set_id = ntohl(nas->collector_set_id);
    sample->obs_domain_id = ntohl(nas->obs_domain_id);
    sample->obs_point_id = ntohl(nas->obs_point_id);

    if (sample->probability == 0) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

static enum ofperr
push_mpls_from_openflow(ovs_be16 ethertype, struct ofpbuf *out)
{
    struct ofpact_push_mpls *oam;

    if (!eth_type_mpls(ethertype)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    oam = ofpact_put_PUSH_MPLS(out);
    oam->ethertype = ethertype;

    return 0;
}

static enum ofperr
decode_nxast_action(const union ofp_action *a, enum ofputil_action_code *code)
{
    const struct nx_action_header *nah = &a->nxa_header;
    uint16_t len = ntohs(a->header.len);

    if (len < sizeof(struct nx_action_header)) {
        return OFPERR_OFPBAC_BAD_LEN;
    } else if (a->vendor.vendor != CONSTANT_HTONL(NX_VENDOR_ID)) {
        return OFPERR_OFPBAC_BAD_VENDOR;
    }

    switch (nah->subtype) {
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)    \
        case CONSTANT_HTONS(ENUM):                      \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *code = OFPUTIL_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBAC_BAD_LEN;           \
            }                                           \
            OVS_NOT_REACHED();
#include "ofp-util.def"

    case CONSTANT_HTONS(NXAST_SNAT__OBSOLETE):
    case CONSTANT_HTONS(NXAST_DROP_SPOOFED_ARP__OBSOLETE):
    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

/* Parses 'a' to determine its type.  On success stores the correct type into
 * '*code' and returns 0.  On failure returns an OFPERR_* error code and
 * '*code' is indeterminate.
 *
 * The caller must have already verified that 'a''s length is potentially
 * correct (that is, a->header.len is nonzero and a multiple of
 * OFP_ACTION_ALIGN and no longer than the amount of space allocated to 'a').
 *
 * This function verifies that 'a''s length is correct for the type of action
 * that it represents. */
static enum ofperr
decode_openflow10_action(const union ofp_action *a,
                         enum ofputil_action_code *code)
{
    switch (a->type) {
    case CONSTANT_HTONS(OFPAT10_VENDOR):
        return decode_nxast_action(a, code);

#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                          \
        case CONSTANT_HTONS(ENUM):                                  \
            if (a->header.len == htons(sizeof(struct STRUCT))) {    \
                *code = OFPUTIL_##ENUM;                             \
                return 0;                                           \
            } else {                                                \
                return OFPERR_OFPBAC_BAD_LEN;                       \
            }                                                       \
            break;
#include "ofp-util.def"

    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

static enum ofperr
ofpact_from_nxast(const union ofp_action *a, enum ofputil_action_code code,
                  struct ofpbuf *out)
{
    struct ofpact_tunnel *tunnel;
    enum ofperr error = 0;

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT10_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#define OFPAT13_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        OVS_NOT_REACHED();

    case OFPUTIL_NXAST_RESUBMIT:
        resubmit_from_openflow(&a->resubmit, out);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
        tunnel = ofpact_put_SET_TUNNEL(out);
        tunnel->ofpact.compat = code;
        tunnel->tun_id = ntohl(a->set_tunnel.tun_id);
        break;

    case OFPUTIL_NXAST_WRITE_METADATA:
        error = metadata_from_nxast(&a->write_metadata, out);
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        ofpact_put_SET_QUEUE(out)->queue_id = ntohl(a->set_queue.queue_id);
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ofpact_put_POP_QUEUE(out);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        error = nxm_reg_move_from_openflow(&a->reg_move, out);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        error = nxm_reg_load_from_openflow(&a->reg_load, out);
        break;

    case OFPUTIL_NXAST_STACK_PUSH:
        error = nxm_stack_push_from_openflow(&a->stack, out);
        break;

    case OFPUTIL_NXAST_STACK_POP:
        error = nxm_stack_pop_from_openflow(&a->stack, out);
        break;

    case OFPUTIL_NXAST_NOTE:
        note_from_openflow(&a->note, out);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL64:
        tunnel = ofpact_put_SET_TUNNEL(out);
        tunnel->ofpact.compat = code;
        tunnel->tun_id = ntohll(a->set_tunnel64.tun_id);
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        error = multipath_from_openflow(&a->multipath,
                                        ofpact_put_MULTIPATH(out));
        break;

    case OFPUTIL_NXAST_BUNDLE:
    case OFPUTIL_NXAST_BUNDLE_LOAD:
        error = bundle_from_openflow(&a->bundle, out);
        break;

    case OFPUTIL_NXAST_OUTPUT_REG:
        error = output_reg_from_openflow(&a->output_reg, out);
        break;

    case OFPUTIL_NXAST_RESUBMIT_TABLE:
        error = resubmit_table_from_openflow(&a->resubmit, out);
        break;

    case OFPUTIL_NXAST_LEARN:
        error = learn_from_openflow(&a->learn, out);
        break;

    case OFPUTIL_NXAST_EXIT:
        ofpact_put_EXIT(out);
        break;

    case OFPUTIL_NXAST_DEC_TTL:
        error = dec_ttl_from_openflow(out, code);
        break;

    case OFPUTIL_NXAST_DEC_TTL_CNT_IDS:
        error = dec_ttl_cnt_ids_from_openflow(&a->cnt_ids, out);
        break;

    case OFPUTIL_NXAST_FIN_TIMEOUT:
        fin_timeout_from_openflow(&a->fin_timeout, out);
        break;

    case OFPUTIL_NXAST_CONTROLLER:
        controller_from_openflow(&a->controller, out);
        break;

    case OFPUTIL_NXAST_PUSH_MPLS:
        error = push_mpls_from_openflow(a->push_mpls.ethertype, out);
        break;

    case OFPUTIL_NXAST_SET_MPLS_LABEL:
        ofpact_put_SET_MPLS_LABEL(out)->label = a->mpls_label.label;
        break;

    case OFPUTIL_NXAST_SET_MPLS_TC:
        ofpact_put_SET_MPLS_TC(out)->tc = a->mpls_tc.tc;
        break;

    case OFPUTIL_NXAST_SET_MPLS_TTL:
        ofpact_put_SET_MPLS_TTL(out)->ttl = a->mpls_ttl.ttl;
        break;

    case OFPUTIL_NXAST_DEC_MPLS_TTL:
        ofpact_put_DEC_MPLS_TTL(out);
        break;

    case OFPUTIL_NXAST_POP_MPLS:
        if (eth_type_mpls(a->pop_mpls.ethertype)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_POP_MPLS(out)->ethertype = a->pop_mpls.ethertype;
        break;

    case OFPUTIL_NXAST_SAMPLE:
        error = sample_from_openflow(&a->sample, out);
        break;
    }

    return error;
}

static enum ofperr
ofpact_from_openflow10(const union ofp_action *a,
                       enum ofp_version version OVS_UNUSED,
                       struct ofpbuf *out)
{
    enum ofputil_action_code code;
    enum ofperr error;
    struct ofpact_vlan_vid *vlan_vid;
    struct ofpact_vlan_pcp *vlan_pcp;

    error = decode_openflow10_action(a, &code);
    if (error) {
        return error;
    }

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#define OFPAT13_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        OVS_NOT_REACHED();

    case OFPUTIL_OFPAT10_OUTPUT:
        return output_from_openflow10(&a->output10, out);

    case OFPUTIL_OFPAT10_SET_VLAN_VID:
        if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        vlan_vid = ofpact_put_SET_VLAN_VID(out);
        vlan_vid->vlan_vid = ntohs(a->vlan_vid.vlan_vid);
        vlan_vid->push_vlan_if_needed = true;
        vlan_vid->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_PCP:
        if (a->vlan_pcp.vlan_pcp & ~7) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        vlan_pcp = ofpact_put_SET_VLAN_PCP(out);
        vlan_pcp->vlan_pcp = a->vlan_pcp.vlan_pcp;
        vlan_pcp->push_vlan_if_needed = true;
        vlan_pcp->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT10_STRIP_VLAN:
        ofpact_put_STRIP_VLAN(out)->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT10_SET_DL_SRC:
        memcpy(ofpact_put_SET_ETH_SRC(out)->mac, a->dl_addr.dl_addr,
               ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT10_SET_DL_DST:
        memcpy(ofpact_put_SET_ETH_DST(out)->mac, a->dl_addr.dl_addr,
               ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT10_SET_NW_SRC:
        ofpact_put_SET_IPV4_SRC(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT10_SET_NW_DST:
        ofpact_put_SET_IPV4_DST(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT10_SET_NW_TOS:
        if (a->nw_tos.nw_tos & ~IP_DSCP_MASK) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_IP_DSCP(out)->dscp = a->nw_tos.nw_tos;
        break;

    case OFPUTIL_OFPAT10_SET_TP_SRC:
        ofpact_put_SET_L4_SRC_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT10_SET_TP_DST:
        ofpact_put_SET_L4_DST_PORT(out)->port = ntohs(a->tp_port.tp_port);

        break;

    case OFPUTIL_OFPAT10_ENQUEUE:
        error = enqueue_from_openflow10(&a->enqueue, out);
        break;

#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
	return ofpact_from_nxast(a, code, out);
    }

    return error;
}

static enum ofperr ofpact_from_openflow11(const union ofp_action *,
                                          enum ofp_version,
                                          struct ofpbuf *out);

static inline union ofp_action *
action_next(const union ofp_action *a)
{
    return ((union ofp_action *) (void *)
            ((uint8_t *) a + ntohs(a->header.len)));
}

static inline bool
action_is_valid(const union ofp_action *a, size_t max_actions)
{
    uint16_t len = ntohs(a->header.len);
    return (!(len % OFP_ACTION_ALIGN)
            && len >= OFP_ACTION_ALIGN
            && len / OFP_ACTION_ALIGN <= max_actions);
}

/* This macro is careful to check for actions with bad lengths. */
#define ACTION_FOR_EACH(ITER, LEFT, ACTIONS, MAX_ACTIONS)                 \
    for ((ITER) = (ACTIONS), (LEFT) = (MAX_ACTIONS);                      \
         (LEFT) > 0 && action_is_valid(ITER, LEFT);                     \
         ((LEFT) -= ntohs((ITER)->header.len) / OFP_ACTION_ALIGN, \
          (ITER) = action_next(ITER)))

static void
log_bad_action(const union ofp_action *actions, size_t max_actions,
               const union ofp_action *bad_action, enum ofperr error)
{
    if (!VLOG_DROP_WARN(&rl)) {
        struct ds s;

        ds_init(&s);
        ds_put_hex_dump(&s, actions, max_actions * OFP_ACTION_ALIGN, 0, false);
        VLOG_WARN("bad action at offset %#"PRIxPTR" (%s):\n%s",
                  (char *)bad_action - (char *)actions,
                  ofperr_get_name(error), ds_cstr(&s));
        ds_destroy(&s);
    }
}

static enum ofperr
ofpacts_from_openflow(const union ofp_action *in, size_t n_in,
                      enum ofp_version version, struct ofpbuf *out)
{
    const union ofp_action *a;
    size_t left;

    enum ofperr (*ofpact_from_openflow)(const union ofp_action *a,
                                        enum ofp_version,
                                        struct ofpbuf *out) =
        (version == OFP10_VERSION) ?
        ofpact_from_openflow10 : ofpact_from_openflow11;

    ACTION_FOR_EACH (a, left, in, n_in) {
        enum ofperr error = ofpact_from_openflow(a, version, out);
        if (error) {
            log_bad_action(in, n_in, a, error);
            return error;
        }
    }
    if (left) {
        enum ofperr error = OFPERR_OFPBAC_BAD_LEN;
        log_bad_action(in, n_in, a, error);
        return error;
    }

    ofpact_pad(out);
    return 0;
}

/* Attempts to convert 'actions_len' bytes of OpenFlow actions from the
 * front of 'openflow' into ofpacts.  On success, replaces any existing content
 * in 'ofpacts' by the converted ofpacts; on failure, clears 'ofpacts'.
 * Returns 0 if successful, otherwise an OpenFlow error.
 *
 * Actions are processed according to their OpenFlow version which
 * is provided in the 'version' parameter.
 *
 * In most places in OpenFlow 1.1 and 1.2, actions appear encapsulated in
 * instructions, so you should call ofpacts_pull_openflow_instructions()
 * instead of this function.
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
                              struct ofpbuf *ofpacts) {
    const union ofp_action *actions;
    enum ofperr error;

    ofpbuf_clear(ofpacts);

    if (actions_len % OFP_ACTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u is not a "
                     "multiple of %d", actions_len, OFP_ACTION_ALIGN);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    actions = ofpbuf_try_pull(openflow, actions_len);
    if (actions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u exceeds "
                     "remaining message length (%"PRIu32")",
                     actions_len, ofpbuf_size(openflow));
        return OFPERR_OFPBRC_BAD_LEN;
    }

    error = ofpacts_from_openflow(actions, actions_len / OFP_ACTION_ALIGN,
                                  version, ofpacts);
    if (error) {
        ofpbuf_clear(ofpacts);
        return error;
    }

    error = ofpacts_verify(ofpbuf_data(ofpacts), ofpbuf_size(ofpacts));
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
}


/* OpenFlow 1.1 actions. */

/* Parses 'a' to determine its type.  On success stores the correct type into
 * '*code' and returns 0.  On failure returns an OFPERR_* error code and
 * '*code' is indeterminate.
 *
 * The caller must have already verified that 'a''s length is potentially
 * correct (that is, a->header.len is nonzero and a multiple of
 * OFP_ACTION_ALIGN and no longer than the amount of space allocated to 'a').
 *
 * This function verifies that 'a''s length is correct for the type of action
 * that it represents. */
static enum ofperr
decode_openflow11_action(const union ofp_action *a,
                         enum ofputil_action_code *code)
{
    uint16_t len;

    switch (a->type) {
    case CONSTANT_HTONS(OFPAT11_EXPERIMENTER):
        return decode_nxast_action(a, code);

#define OFPAT11_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)  \
        case CONSTANT_HTONS(ENUM):                      \
            len = ntohs(a->header.len);                 \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *code = OFPUTIL_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBAC_BAD_LEN;           \
            }                                           \
            OVS_NOT_REACHED();
#include "ofp-util.def"

    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

static enum ofperr
set_field_from_openflow(const struct ofp12_action_set_field *oasf,
                        struct ofpbuf *ofpacts)
{
    uint16_t oasf_len = ntohs(oasf->len);
    uint32_t oxm_header = ntohl(oasf->dst);
    uint8_t oxm_length = NXM_LENGTH(oxm_header);
    struct ofpact_set_field *sf;
    const struct mf_field *mf;

    /* ofp12_action_set_field is padded to 64 bits by zero */
    if (oasf_len != ROUND_UP(sizeof *oasf + oxm_length, 8)) {
        return OFPERR_OFPBAC_BAD_SET_LEN;
    }
    if (!is_all_zeros((const uint8_t *)oasf + sizeof *oasf + oxm_length,
                      oasf_len - oxm_length - sizeof *oasf)) {
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }

    if (NXM_HASMASK(oxm_header)) {
        return OFPERR_OFPBAC_BAD_SET_TYPE;
    }
    mf = mf_from_nxm_header(oxm_header);
    if (!mf) {
        return OFPERR_OFPBAC_BAD_SET_TYPE;
    }
    ovs_assert(mf->n_bytes == oxm_length);
    /* oxm_length is now validated to be compatible with mf_value. */
    if (!mf->writable) {
        VLOG_WARN_RL(&rl, "destination field %s is not writable", mf->name);
        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }
    sf = ofpact_put_SET_FIELD(ofpacts);
    sf->field = mf;
    memcpy(&sf->value, oasf + 1, mf->n_bytes);

    /* The value must be valid for match and must have the OFPVID_PRESENT bit
     * on for OXM_OF_VLAN_VID. */
    if (!mf_is_value_valid(mf, &sf->value)
        || (mf->id == MFF_VLAN_VID
            && !(sf->value.be16 & htons(OFPVID12_PRESENT)))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        mf_format(mf, &sf->value, NULL, &ds);
        VLOG_WARN_RL(&rl, "Invalid value for set field %s: %s",
                     mf->name, ds_cstr(&ds));
        ds_destroy(&ds);

        return OFPERR_OFPBAC_BAD_SET_ARGUMENT;
    }
    return 0;
}

static void
set_field_to_openflow12(const struct ofpact_set_field *sf,
                        struct ofpbuf *openflow,
                        enum ofp_version version)
{
    uint16_t padded_value_len = ROUND_UP(sf->field->n_bytes, 8);
    struct ofp12_action_set_field *oasf;
    char *value;

    oasf = ofputil_put_OFPAT12_SET_FIELD(openflow);
    oasf->dst = htonl(mf_oxm_header(sf->field->id, version));
    oasf->len = htons(sizeof *oasf + padded_value_len);

    value = ofpbuf_put_zeros(openflow, padded_value_len);
    memcpy(value, &sf->value, sf->field->n_bytes);
}

/* Convert 'sf' to one or two REG_LOADs. */
static void
set_field_to_nxast(const struct ofpact_set_field *sf, struct ofpbuf *openflow)
{
    const struct mf_field *mf = sf->field;
    struct nx_action_reg_load *narl;

    if (mf->n_bits > 64) {
        ovs_assert(mf->n_bytes == 16); /* IPv6 addr. */
        /* Split into 64bit chunks */
        /* Lower bits first. */
        narl = ofputil_put_NXAST_REG_LOAD(openflow);
        narl->ofs_nbits = nxm_encode_ofs_nbits(0, 64);
        narl->dst = htonl(mf->nxm_header);
        memcpy(&narl->value, &sf->value.ipv6.s6_addr[8], sizeof narl->value);
        /* Higher bits next. */
        narl = ofputil_put_NXAST_REG_LOAD(openflow);
        narl->ofs_nbits = nxm_encode_ofs_nbits(64, mf->n_bits - 64);
        narl->dst = htonl(mf->nxm_header);
        memcpy(&narl->value, &sf->value.ipv6.s6_addr[0], sizeof narl->value);
    } else {
        narl = ofputil_put_NXAST_REG_LOAD(openflow);
        narl->ofs_nbits = nxm_encode_ofs_nbits(0, mf->n_bits);
        narl->dst = htonl(mf->nxm_header);
        memset(&narl->value, 0, 8 - mf->n_bytes);
        memcpy((char*)&narl->value + (8 - mf->n_bytes),
               &sf->value, mf->n_bytes);
    }
}

/* Convert 'sf' to standard OpenFlow 1.1 actions, if we can, falling back
 * to Nicira extensions if we must.
 *
 * We check only meta-flow types that can appear within set field actions and
 * that have a mapping to compatible action types.  These struct mf_field
 * definitions have a defined OXM or NXM header value and specify the field as
 * writable. */
static void
set_field_to_openflow11(const struct ofpact_set_field *sf,
                        struct ofpbuf *openflow)
{
    switch ((int) sf->field->id) {
    case MFF_VLAN_TCI:
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
        if (sf->value.be16 & htons(VLAN_CFI)) {
            /* Push a VLAN tag, if one was not seen at action validation
             * time. */
            if (!sf->flow_has_vlan) {
                ofputil_put_OFPAT11_PUSH_VLAN(openflow)->ethertype
                    = htons(ETH_TYPE_VLAN_8021Q);
            }
            ofputil_put_OFPAT11_SET_VLAN_VID(openflow)->vlan_vid
                = sf->value.be16 & htons(VLAN_VID_MASK);
            ofputil_put_OFPAT11_SET_VLAN_PCP(openflow)->vlan_pcp
                = vlan_tci_to_pcp(sf->value.be16);
        } else {
            /* If the flow did not match on vlan, we have no way of
             * knowing if the vlan tag exists, so we must POP just to be
             * sure. */
            ofputil_put_OFPAT11_POP_VLAN(openflow);
        }
        break;

    case MFF_VLAN_VID:
        /* OXM VLAN_PCP to OpenFlow 1.1.
         * Set field on OXM_OF_VLAN_VID onlyapplies to an existing vlan
         * tag.  Clear the OFPVID_PRESENT bit.
         */
        ofputil_put_OFPAT11_SET_VLAN_VID(openflow)->vlan_vid
            = sf->value.be16 & htons(VLAN_VID_MASK);
        break;

    case MFF_VLAN_PCP:
        /* OXM VLAN_PCP to OpenFlow 1.1.
         * OXM_OF_VLAN_PCP only applies to existing vlan tag. */
        ofputil_put_OFPAT11_SET_VLAN_PCP(openflow)->vlan_pcp = sf->value.u8;
        break;

    case MFF_ETH_SRC:
        memcpy(ofputil_put_OFPAT11_SET_DL_SRC(openflow)->dl_addr,
               sf->value.mac, ETH_ADDR_LEN);
        break;

    case MFF_ETH_DST:
        memcpy(ofputil_put_OFPAT11_SET_DL_DST(openflow)->dl_addr,
               sf->value.mac, ETH_ADDR_LEN);
        break;

    case MFF_MPLS_LABEL:
        ofputil_put_OFPAT11_SET_MPLS_LABEL(openflow)->mpls_label =
            sf->value.be32;
        break;

    case MFF_MPLS_TC:
        ofputil_put_OFPAT11_SET_MPLS_TC(openflow)->mpls_tc = sf->value.u8;
        break;

    case MFF_IPV4_SRC:
        ofputil_put_OFPAT11_SET_NW_SRC(openflow)->nw_addr = sf->value.be32;
        break;

    case MFF_IPV4_DST:
        ofputil_put_OFPAT11_SET_NW_DST(openflow)->nw_addr = sf->value.be32;
        break;

    case MFF_IP_DSCP:
        ofputil_put_OFPAT11_SET_NW_TOS(openflow)->nw_tos = sf->value.u8;
        break;

    case MFF_IP_DSCP_SHIFTED:
        ofputil_put_OFPAT11_SET_NW_TOS(openflow)->nw_tos = sf->value.u8 << 2;
        break;

    case MFF_IP_ECN:
        ofputil_put_OFPAT11_SET_NW_ECN(openflow)->nw_ecn = sf->value.u8;
        break;

    case MFF_IP_TTL:
        ofputil_put_OFPAT11_SET_NW_TTL(openflow)->nw_ttl = sf->value.u8;
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
    case MFF_SCTP_SRC:
        ofputil_put_OFPAT11_SET_TP_SRC(openflow)->tp_port = sf->value.be16;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
    case MFF_SCTP_DST:
        ofputil_put_OFPAT11_SET_TP_DST(openflow)->tp_port = sf->value.be16;
        break;

    default:
        set_field_to_nxast(sf, openflow);
        break;
    }
}

/* Convert 'sf' to standard OpenFlow 1.0 actions, if we can, falling back
 * to Nicira extensions if we must.
 *
 * We check only meta-flow types that can appear within set field actions and
 * that have a mapping to compatible action types.  These struct mf_field
 * definitions have a defined OXM or NXM header value and specify the field as
 * writable. */
static void
set_field_to_openflow10(const struct ofpact_set_field *sf,
                        struct ofpbuf *openflow)
{
    switch ((int) sf->field->id) {
    case MFF_VLAN_TCI:
        /* NXM_OF_VLAN_TCI to OpenFlow 1.0 mapping:
         *
         * If CFI=1, Add or modify VLAN VID & PCP.
         * If CFI=0, strip VLAN header, if any.
         */
        if (sf->value.be16 & htons(VLAN_CFI)) {
            ofputil_put_OFPAT10_SET_VLAN_VID(openflow)->vlan_vid
                = sf->value.be16 & htons(VLAN_VID_MASK);
            ofputil_put_OFPAT10_SET_VLAN_PCP(openflow)->vlan_pcp
                = vlan_tci_to_pcp(sf->value.be16);
        } else {
            ofputil_put_OFPAT10_STRIP_VLAN(openflow);
        }
        break;

    case MFF_VLAN_VID:
        /* OXM VLAN_VID to OpenFlow 1.0.
         * Set field on OXM_OF_VLAN_VID onlyapplies to an existing vlan
         * tag.  Clear the OFPVID_PRESENT bit.
         */
        ofputil_put_OFPAT10_SET_VLAN_VID(openflow)->vlan_vid
            = sf->value.be16 & htons(VLAN_VID_MASK);
        break;

    case MFF_VLAN_PCP:
        /* OXM VLAN_PCP to OpenFlow 1.0.
         * OXM_OF_VLAN_PCP only applies to existing vlan tag. */
        ofputil_put_OFPAT10_SET_VLAN_PCP(openflow)->vlan_pcp = sf->value.u8;
        break;

    case MFF_ETH_SRC:
        memcpy(ofputil_put_OFPAT10_SET_DL_SRC(openflow)->dl_addr,
               sf->value.mac, ETH_ADDR_LEN);
        break;

    case MFF_ETH_DST:
        memcpy(ofputil_put_OFPAT10_SET_DL_DST(openflow)->dl_addr,
               sf->value.mac, ETH_ADDR_LEN);
        break;

    case MFF_IPV4_SRC:
        ofputil_put_OFPAT10_SET_NW_SRC(openflow)->nw_addr = sf->value.be32;
        break;

    case MFF_IPV4_DST:
        ofputil_put_OFPAT10_SET_NW_DST(openflow)->nw_addr = sf->value.be32;
        break;

    case MFF_IP_DSCP:
        ofputil_put_OFPAT10_SET_NW_TOS(openflow)->nw_tos = sf->value.u8;
        break;

    case MFF_IP_DSCP_SHIFTED:
        ofputil_put_OFPAT10_SET_NW_TOS(openflow)->nw_tos = sf->value.u8 << 2;
        break;

    case MFF_TCP_SRC:
    case MFF_UDP_SRC:
        ofputil_put_OFPAT10_SET_TP_SRC(openflow)->tp_port = sf->value.be16;
        break;

    case MFF_TCP_DST:
    case MFF_UDP_DST:
        ofputil_put_OFPAT10_SET_TP_DST(openflow)->tp_port = sf->value.be16;
        break;

    default:
        set_field_to_nxast(sf, openflow);
        break;
    }
}

static void
set_field_to_openflow(const struct ofpact_set_field *sf,
                      struct ofpbuf *openflow)
{
    struct ofp_header *oh = (struct ofp_header *)openflow->frame;

    if (oh->version >= OFP12_VERSION) {
        set_field_to_openflow12(sf, openflow, oh->version);
    } else if (oh->version == OFP11_VERSION) {
        set_field_to_openflow11(sf, openflow);
    } else if (oh->version == OFP10_VERSION) {
        set_field_to_openflow10(sf, openflow);
    } else {
        OVS_NOT_REACHED();
    }
}

static enum ofperr
output_from_openflow11(const struct ofp11_action_output *oao,
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

static enum ofperr
ofpact_from_openflow11(const union ofp_action *a, enum ofp_version version,
                       struct ofpbuf *out)
{
    enum ofputil_action_code code;
    enum ofperr error;
    struct ofpact_vlan_vid *vlan_vid;
    struct ofpact_vlan_pcp *vlan_pcp;

    error = decode_openflow11_action(a, &code);
    if (error) {
        return error;
    }

    if (version >= OFP12_VERSION) {
        switch ((int)code) {
        case OFPUTIL_OFPAT11_SET_VLAN_VID:
        case OFPUTIL_OFPAT11_SET_VLAN_PCP:
        case OFPUTIL_OFPAT11_SET_DL_SRC:
        case OFPUTIL_OFPAT11_SET_DL_DST:
        case OFPUTIL_OFPAT11_SET_NW_SRC:
        case OFPUTIL_OFPAT11_SET_NW_DST:
        case OFPUTIL_OFPAT11_SET_NW_TOS:
        case OFPUTIL_OFPAT11_SET_NW_ECN:
        case OFPUTIL_OFPAT11_SET_TP_SRC:
        case OFPUTIL_OFPAT11_SET_TP_DST:
            VLOG_WARN_RL(&rl, "Deprecated action %s received over %s",
                         ofputil_action_name_from_code(code),
                         ofputil_version_to_string(version));
        }
    }

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT10_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT13_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        OVS_NOT_REACHED();

    case OFPUTIL_OFPAT11_OUTPUT:
        return output_from_openflow11(&a->ofp11_output, out);

    case OFPUTIL_OFPAT11_SET_VLAN_VID:
        if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        vlan_vid = ofpact_put_SET_VLAN_VID(out);
        vlan_vid->vlan_vid = ntohs(a->vlan_vid.vlan_vid);
        vlan_vid->push_vlan_if_needed = false;
        vlan_vid->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT11_SET_VLAN_PCP:
        if (a->vlan_pcp.vlan_pcp & ~7) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        vlan_pcp = ofpact_put_SET_VLAN_PCP(out);
        vlan_pcp->vlan_pcp = a->vlan_pcp.vlan_pcp;
        vlan_pcp->push_vlan_if_needed = false;
        vlan_pcp->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT11_PUSH_VLAN:
        if (a->push.ethertype != htons(ETH_TYPE_VLAN_8021Q)) {
            /* XXX 802.1AD(QinQ) isn't supported at the moment */
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_PUSH_VLAN(out);
        break;

    case OFPUTIL_OFPAT11_POP_VLAN:
        ofpact_put_STRIP_VLAN(out)->ofpact.compat = code;
        break;

    case OFPUTIL_OFPAT11_SET_QUEUE:
        ofpact_put_SET_QUEUE(out)->queue_id =
            ntohl(a->ofp11_set_queue.queue_id);
        break;

    case OFPUTIL_OFPAT11_SET_DL_SRC:
        memcpy(ofpact_put_SET_ETH_SRC(out)->mac, a->dl_addr.dl_addr,
               ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT11_SET_DL_DST:
        memcpy(ofpact_put_SET_ETH_DST(out)->mac, a->dl_addr.dl_addr,
               ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT11_DEC_NW_TTL:
        dec_ttl_from_openflow(out, code);
        break;

    case OFPUTIL_OFPAT11_SET_NW_SRC:
        ofpact_put_SET_IPV4_SRC(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT11_SET_NW_DST:
        ofpact_put_SET_IPV4_DST(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT11_SET_NW_TOS:
        if (a->nw_tos.nw_tos & ~IP_DSCP_MASK) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_IP_DSCP(out)->dscp = a->nw_tos.nw_tos;
        break;

    case OFPUTIL_OFPAT11_SET_NW_ECN:
        if (a->nw_ecn.nw_ecn & ~IP_ECN_MASK) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_IP_ECN(out)->ecn = a->nw_ecn.nw_ecn;
        break;

    case OFPUTIL_OFPAT11_SET_NW_TTL:
        ofpact_put_SET_IP_TTL(out)->ttl = a->nw_ttl.nw_ttl;
        break;

    case OFPUTIL_OFPAT11_SET_TP_SRC:
        ofpact_put_SET_L4_SRC_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT11_SET_TP_DST:
        ofpact_put_SET_L4_DST_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT12_SET_FIELD:
        return set_field_from_openflow(&a->set_field, out);

    case OFPUTIL_OFPAT11_SET_MPLS_LABEL:
        ofpact_put_SET_MPLS_LABEL(out)->label = a->ofp11_mpls_label.mpls_label;
        break;

    case OFPUTIL_OFPAT11_SET_MPLS_TC:
        ofpact_put_SET_MPLS_TC(out)->tc = a->ofp11_mpls_tc.mpls_tc;
        break;

    case OFPUTIL_OFPAT11_SET_MPLS_TTL:
        ofpact_put_SET_MPLS_TTL(out)->ttl = a->ofp11_mpls_ttl.mpls_ttl;
        break;

    case OFPUTIL_OFPAT11_DEC_MPLS_TTL:
        ofpact_put_DEC_MPLS_TTL(out);
        break;

    case OFPUTIL_OFPAT11_PUSH_MPLS:
        error = push_mpls_from_openflow(a->push.ethertype, out);
        break;

    case OFPUTIL_OFPAT11_POP_MPLS:
        if (eth_type_mpls(a->ofp11_pop_mpls.ethertype)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_POP_MPLS(out)->ethertype = a->ofp11_pop_mpls.ethertype;
        break;

    case OFPUTIL_OFPAT11_GROUP:
        ofpact_put_GROUP(out)->group_id = ntohl(a->group.group_id);
        break;

#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        return ofpact_from_nxast(a, code, out);
    }

    return error;
}

/* True if an action sets the value of a field
 * in a way that is compatibile with the action set.
 * False otherwise. */
static bool
ofpact_is_set_action(const struct ofpact *a)
{
    switch (a->type) {
    case OFPACT_SET_FIELD:
    case OFPACT_REG_LOAD:
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
        return true;
    case OFPACT_BUNDLE:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_CONTROLLER:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_DEC_TTL:
    case OFPACT_ENQUEUE:
    case OFPACT_EXIT:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_GOTO_TABLE:
    case OFPACT_GROUP:
    case OFPACT_LEARN:
    case OFPACT_METER:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_OUTPUT:
    case OFPACT_OUTPUT_REG:
    case OFPACT_POP_MPLS:
    case OFPACT_POP_QUEUE:
    case OFPACT_PUSH_MPLS:
    case OFPACT_PUSH_VLAN:
    case OFPACT_REG_MOVE:
    case OFPACT_RESUBMIT:
    case OFPACT_SAMPLE:
    case OFPACT_STACK_POP:
    case OFPACT_STACK_PUSH:
    case OFPACT_STRIP_VLAN:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_WRITE_METADATA:
        return false;
    default:
        OVS_NOT_REACHED();
    }
}

/* True if an action is allowed in the action set.
 * False otherwise. */
static bool
ofpact_is_allowed_in_actions_set(const struct ofpact *a)
{
    switch (a->type) {
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_DEC_TTL:
    case OFPACT_GROUP:
    case OFPACT_OUTPUT:
    case OFPACT_POP_MPLS:
    case OFPACT_PUSH_MPLS:
    case OFPACT_PUSH_VLAN:
    case OFPACT_REG_LOAD:
    case OFPACT_SET_FIELD:
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
    case OFPACT_STRIP_VLAN:
        return true;

    /* In general these actions are excluded because they are not part of
     * the OpenFlow specification nor map to actions that are defined in
     * the specification.  Thus the order in which they should be applied
     * in the action set is undefined. */
    case OFPACT_BUNDLE:
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_EXIT:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_POP_QUEUE:
    case OFPACT_REG_MOVE:
    case OFPACT_RESUBMIT:
    case OFPACT_SAMPLE:
    case OFPACT_STACK_POP:
    case OFPACT_STACK_PUSH:

    /* The action set may only include actions and thus
     * may not include any instructions */
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_WRITE_METADATA:
        return false;
    default:
        OVS_NOT_REACHED();
    }
}

/* Append ofpact 'a' onto the tail of 'out' */
static void
ofpact_copy(struct ofpbuf *out, const struct ofpact *a)
{
    ofpbuf_put(out, a, OFPACT_ALIGN(a->len));
}

/* Copies the last ofpact whose type is 'filter' from 'in' to 'out'. */
static bool
ofpacts_copy_last(struct ofpbuf *out, const struct ofpbuf *in,
                  enum ofpact_type filter)
{
    const struct ofpact *target;
    const struct ofpact *a;

    target = NULL;
    OFPACT_FOR_EACH (a, ofpbuf_data(in), ofpbuf_size(in)) {
        if (a->type == filter) {
            target = a;
        }
    }
    if (target) {
        ofpact_copy(out, target);
    }
    return target != NULL;
}

/* Append all ofpacts, for which 'filter' returns true, from 'in' to 'out'.
 * The order of appended ofpacts is preserved between 'in' and 'out' */
static void
ofpacts_copy_all(struct ofpbuf *out, const struct ofpbuf *in,
                 bool (*filter)(const struct ofpact *))
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpbuf_data(in), ofpbuf_size(in)) {
        if (filter(a)) {
            ofpact_copy(out, a);
        }
    }
}

/* Reads 'action_set', which contains ofpacts accumulated by
 * OFPACT_WRITE_ACTIONS instructions, and writes equivalent actions to be
 * executed directly into 'action_list'.  (These names correspond to the
 * "Action Set" and "Action List" terms used in OpenFlow 1.1+.)
 *
 * In general this involves appending the last instance of each action that is
 * adimissible in the action set in the order described in the OpenFlow
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
    /* The OpenFlow spec "Action Set" section specifies this order. */
    ofpacts_copy_last(action_list, action_set, OFPACT_STRIP_VLAN);
    ofpacts_copy_last(action_list, action_set, OFPACT_POP_MPLS);
    ofpacts_copy_last(action_list, action_set, OFPACT_PUSH_MPLS);
    ofpacts_copy_last(action_list, action_set, OFPACT_PUSH_VLAN);
    ofpacts_copy_last(action_list, action_set, OFPACT_DEC_TTL);
    ofpacts_copy_last(action_list, action_set, OFPACT_DEC_MPLS_TTL);
    ofpacts_copy_all(action_list, action_set, ofpact_is_set_action);
    ofpacts_copy_last(action_list, action_set, OFPACT_SET_QUEUE);

    /* If both OFPACT_GROUP and OFPACT_OUTPUT are present, OpenFlow says that
     * we should execute only OFPACT_GROUP.
     *
     * If neither OFPACT_GROUP nor OFPACT_OUTPUT is present, then we can drop
     * all the actions because there's no point in modifying a packet that will
     * not be sent anywhere. */
    if (!ofpacts_copy_last(action_list, action_set, OFPACT_GROUP) &&
        !ofpacts_copy_last(action_list, action_set, OFPACT_OUTPUT)) {
        ofpbuf_clear(action_list);
    }
}


static enum ofperr
ofpacts_from_openflow11_for_action_set(const union ofp_action *in,
                                       size_t n_in, enum ofp_version version,
                                       struct ofpbuf *out)
{
    enum ofperr error;
    struct ofpact *a;
    size_t start = ofpbuf_size(out);

    error = ofpacts_from_openflow(in, n_in, version, out);

    if (error) {
        return error;
    }

    OFPACT_FOR_EACH (a, ofpact_end(ofpbuf_data(out), start), ofpbuf_size(out) - start) {
        if (!ofpact_is_allowed_in_actions_set(a)) {
            VLOG_WARN_RL(&rl, "disallowed action in action set");
            return OFPERR_OFPBAC_BAD_TYPE;
        }
    }

    return 0;
}


/* OpenFlow 1.1 instructions. */

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
    return inst_info[type].name;
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
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_OUTPUT_REG:
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
    case OFPACT_REG_LOAD:
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
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SAMPLE:
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
            return OFPERR_ONFBIC_DUP_INSTRUCTION;
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
                             const union ofp_action **actions,
                             size_t *max_actions)
{
    *actions = ALIGNED_CAST(const union ofp_action *, inst + 1);
    *max_actions = (ntohs(inst->len) - sizeof *inst) / OFP11_INSTRUCTION_ALIGN;
}

enum ofperr
ofpacts_pull_openflow_instructions(struct ofpbuf *openflow,
                                   unsigned int instructions_len,
                                   enum ofp_version version,
                                   struct ofpbuf *ofpacts)
{
    const struct ofp11_instruction *instructions;
    const struct ofp11_instruction *insts[N_OVS_INSTRUCTIONS];
    enum ofperr error;

    ofpbuf_clear(ofpacts);

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
                     instructions_len, ofpbuf_size(openflow));
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
    }
    if (insts[OVSINST_OFPIT11_APPLY_ACTIONS]) {
        const union ofp_action *actions;
        size_t max_actions;

        get_actions_from_instruction(insts[OVSINST_OFPIT11_APPLY_ACTIONS],
                                     &actions, &max_actions);
        error = ofpacts_from_openflow(actions, max_actions, version, ofpacts);
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
        const union ofp_action *actions;
        size_t max_actions;
        size_t start;

        ofpact_pad(ofpacts);
        start = ofpbuf_size(ofpacts);
        on = ofpact_put(ofpacts, OFPACT_WRITE_ACTIONS,
                        offsetof(struct ofpact_nest, actions));
        get_actions_from_instruction(insts[OVSINST_OFPIT11_WRITE_ACTIONS],
                                     &actions, &max_actions);
        error = ofpacts_from_openflow11_for_action_set(actions, max_actions,
                                                       version, ofpacts);
        if (error) {
            goto exit;
        }
        on = ofpbuf_at_assert(ofpacts, start, sizeof *on);
        on->ofpact.len = ofpbuf_size(ofpacts) - start;
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

    error = ofpacts_verify(ofpbuf_data(ofpacts), ofpbuf_size(ofpacts));
exit:
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
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
    case OFPP_NONE:
    case OFPP_LOCAL:
        return 0;

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

/* May modify flow->dl_type, flow->nw_proto and flow->vlan_tci,
 * caller must restore them.
 *
 * Modifies some actions, filling in fields that could not be properly set
 * without context. */
static enum ofperr
ofpact_check__(enum ofputil_protocol *usable_protocols, struct ofpact *a,
               struct flow *flow, ofp_port_t max_ports,
               uint8_t table_id, uint8_t n_tables)
{
    const struct ofpact_enqueue *enqueue;
    const struct mf_field *mf;

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
        return mf_check_src(&ofpact_get_OUTPUT_REG(a)->src, flow);

    case OFPACT_BUNDLE:
        return bundle_check(ofpact_get_BUNDLE(a), max_ports, flow);

    case OFPACT_SET_VLAN_VID:
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1+ if need be. */
        ofpact_get_SET_VLAN_VID(a)->flow_has_vlan =
            (flow->vlan_tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (!(flow->vlan_tci & htons(VLAN_CFI)) &&
            !ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
            inconsistent_match(usable_protocols);
        }
        /* Temporary mark that we have a vlan tag. */
        flow->vlan_tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_SET_VLAN_PCP:
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1+ if need be. */
        ofpact_get_SET_VLAN_PCP(a)->flow_has_vlan =
            (flow->vlan_tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (!(flow->vlan_tci & htons(VLAN_CFI)) &&
            !ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
            inconsistent_match(usable_protocols);
        }
        /* Temporary mark that we have a vlan tag. */
        flow->vlan_tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_STRIP_VLAN:
        if (!(flow->vlan_tci & htons(VLAN_CFI))) {
            inconsistent_match(usable_protocols);
        }
        /* Temporary mark that we have no vlan tag. */
        flow->vlan_tci = htons(0);
        return 0;

    case OFPACT_PUSH_VLAN:
        if (flow->vlan_tci & htons(VLAN_CFI)) {
            /* Multiple VLAN headers not supported. */
            return OFPERR_OFPBAC_BAD_TAG;
        }
        /* Temporary mark that we have a vlan tag. */
        flow->vlan_tci |= htons(VLAN_CFI);
        return 0;

    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
        return 0;

    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
        if (flow->dl_type != htons(ETH_TYPE_IP)) {
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
        if (!is_ip_any(flow) ||
            (flow->nw_proto != IPPROTO_TCP && flow->nw_proto != IPPROTO_UDP
             && flow->nw_proto != IPPROTO_SCTP)) {
            inconsistent_match(usable_protocols);
        }
        /* Note on which transport protocol the port numbers are set.
         * This allows this set action to be converted to an OF1.2 set field
         * action. */
        ofpact_get_SET_L4_SRC_PORT(a)->flow_ip_proto = flow->nw_proto;
        return 0;

    case OFPACT_SET_L4_DST_PORT:
        if (!is_ip_any(flow) ||
            (flow->nw_proto != IPPROTO_TCP && flow->nw_proto != IPPROTO_UDP
             && flow->nw_proto != IPPROTO_SCTP)) {
            inconsistent_match(usable_protocols);
        }
        /* Note on which transport protocol the port numbers are set.
         * This allows this set action to be converted to an OF1.2 set field
         * action. */
        ofpact_get_SET_L4_DST_PORT(a)->flow_ip_proto = flow->nw_proto;
        return 0;

    case OFPACT_REG_MOVE:
        return nxm_reg_move_check(ofpact_get_REG_MOVE(a), flow);

    case OFPACT_REG_LOAD:
        return nxm_reg_load_check(ofpact_get_REG_LOAD(a), flow);

    case OFPACT_SET_FIELD:
        mf = ofpact_get_SET_FIELD(a)->field;
        /* Require OXM_OF_VLAN_VID to have an existing VLAN header. */
        if (!mf_are_prereqs_ok(mf, flow) ||
            (mf->id == MFF_VLAN_VID && !(flow->vlan_tci & htons(VLAN_CFI)))) {
            VLOG_WARN_RL(&rl, "set_field %s lacks correct prerequisities",
                         mf->name);
            return OFPERR_OFPBAC_MATCH_INCONSISTENT;
        }
        /* Remember if we saw a vlan tag in the flow to aid translating to
         * OpenFlow 1.1 if need be. */
        ofpact_get_SET_FIELD(a)->flow_has_vlan =
            (flow->vlan_tci & htons(VLAN_CFI)) == htons(VLAN_CFI);
        if (mf->id == MFF_VLAN_TCI) {
            /* The set field may add or remove the vlan tag,
             * Mark the status temporarily. */
            flow->vlan_tci = ofpact_get_SET_FIELD(a)->value.be16;
        }
        return 0;

    case OFPACT_STACK_PUSH:
        return nxm_stack_push_check(ofpact_get_STACK_PUSH(a), flow);

    case OFPACT_STACK_POP:
        return nxm_stack_pop_check(ofpact_get_STACK_POP(a), flow);

    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
        if (!eth_type_mpls(flow->dl_type)) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_RESUBMIT:
        return 0;

    case OFPACT_FIN_TIMEOUT:
        if (flow->nw_proto != IPPROTO_TCP) {
            inconsistent_match(usable_protocols);
        }
        return 0;

    case OFPACT_LEARN:
        return learn_check(ofpact_get_LEARN(a), flow);

    case OFPACT_MULTIPATH:
        return multipath_check(ofpact_get_MULTIPATH(a), flow);

    case OFPACT_NOTE:
    case OFPACT_EXIT:
        return 0;

    case OFPACT_PUSH_MPLS:
        flow->dl_type = ofpact_get_PUSH_MPLS(a)->ethertype;
        /* The packet is now MPLS and the MPLS payload is opaque.
         * Thus nothing can be assumed about the network protocol.
         * Temporarily mark that we have no nw_proto. */
        flow->nw_proto = 0;
        return 0;

    case OFPACT_POP_MPLS:
        if (!eth_type_mpls(flow->dl_type)) {
            inconsistent_match(usable_protocols);
        }
        flow->dl_type = ofpact_get_POP_MPLS(a)->ethertype;
        return 0;

    case OFPACT_SAMPLE:
        return 0;

    case OFPACT_CLEAR_ACTIONS:
        return 0;

    case OFPACT_WRITE_ACTIONS: {
        /* Use a temporary copy of 'usable_protocols' because we can't check
         * consistency of an action set. */
        struct ofpact_nest *on = ofpact_get_WRITE_ACTIONS(a);
        enum ofputil_protocol p = *usable_protocols;
        return ofpacts_check(on->actions, ofpact_nest_get_action_len(on),
                             flow, max_ports, table_id, n_tables, &p);
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
            return OFPERR_OFPBRC_BAD_TABLE_ID;
        }
        return 0;
    }

    case OFPACT_GROUP:
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
 * May annotate ofpacts with information gathered from the 'flow'.
 *
 * May temporarily modify 'flow', but restores the changes before returning. */
enum ofperr
ofpacts_check(struct ofpact ofpacts[], size_t ofpacts_len,
              struct flow *flow, ofp_port_t max_ports,
              uint8_t table_id, uint8_t n_tables,
              enum ofputil_protocol *usable_protocols)
{
    struct ofpact *a;
    ovs_be16 dl_type = flow->dl_type;
    ovs_be16 vlan_tci = flow->vlan_tci;
    uint8_t nw_proto = flow->nw_proto;
    enum ofperr error = 0;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        error = ofpact_check__(usable_protocols, a, flow,
                               max_ports, table_id, n_tables);
        if (error) {
            break;
        }
    }
    /* Restore fields that may have been modified. */
    flow->dl_type = dl_type;
    flow->vlan_tci = vlan_tci;
    flow->nw_proto = nw_proto;
    return error;
}

/* Like ofpacts_check(), but reports inconsistencies as
 * OFPERR_OFPBAC_MATCH_INCONSISTENT rather than clearing bits. */
enum ofperr
ofpacts_check_consistency(struct ofpact ofpacts[], size_t ofpacts_len,
                          struct flow *flow, ofp_port_t max_ports,
                          uint8_t table_id, uint8_t n_tables,
                          enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol p = usable_protocols;
    enum ofperr error;

    error = ofpacts_check(ofpacts, ofpacts_len, flow, max_ports,
                          table_id, n_tables, &p);
    return (error ? error
            : p != usable_protocols ? OFPERR_OFPBAC_MATCH_INCONSISTENT
            : 0);
}

/* Verifies that the 'ofpacts_len' bytes of actions in 'ofpacts' are
 * in the appropriate order as defined by the OpenFlow spec. */
enum ofperr
ofpacts_verify(const struct ofpact ofpacts[], size_t ofpacts_len)
{
    const struct ofpact *a;
    enum ovs_instruction_type inst;

    inst = OVSINST_OFPIT13_METER;
    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        enum ovs_instruction_type next;

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

        inst = next;
    }

    return 0;
}

/* Converting ofpacts to Nicira OpenFlow extensions. */

static void
ofpact_output_reg_to_nxast(const struct ofpact_output_reg *output_reg,
                                struct ofpbuf *out)
{
    struct nx_action_output_reg *naor = ofputil_put_NXAST_OUTPUT_REG(out);

    naor->ofs_nbits = nxm_encode_ofs_nbits(output_reg->src.ofs,
                                           output_reg->src.n_bits);
    naor->src = htonl(output_reg->src.field->nxm_header);
    naor->max_len = htons(output_reg->max_len);
}

static void
ofpact_resubmit_to_nxast(const struct ofpact_resubmit *resubmit,
                         struct ofpbuf *out)
{
    struct nx_action_resubmit *nar;

    if (resubmit->table_id == 0xff
        && resubmit->ofpact.compat != OFPUTIL_NXAST_RESUBMIT_TABLE) {
        nar = ofputil_put_NXAST_RESUBMIT(out);
    } else {
        nar = ofputil_put_NXAST_RESUBMIT_TABLE(out);
        nar->table = resubmit->table_id;
    }
    nar->in_port = htons(ofp_to_u16(resubmit->in_port));
}

static void
ofpact_set_tunnel_to_nxast(const struct ofpact_tunnel *tunnel,
                           struct ofpbuf *out)
{
    uint64_t tun_id = tunnel->tun_id;

    if (tun_id <= UINT32_MAX
        && tunnel->ofpact.compat != OFPUTIL_NXAST_SET_TUNNEL64) {
        ofputil_put_NXAST_SET_TUNNEL(out)->tun_id = htonl(tun_id);
    } else {
        ofputil_put_NXAST_SET_TUNNEL64(out)->tun_id = htonll(tun_id);
    }
}

static void
ofpact_write_metadata_to_nxast(const struct ofpact_metadata *om,
                               struct ofpbuf *out)
{
    struct nx_action_write_metadata *nawm;

    nawm = ofputil_put_NXAST_WRITE_METADATA(out);
    nawm->metadata = om->metadata;
    nawm->mask = om->mask;
}

static void
ofpact_note_to_nxast(const struct ofpact_note *note, struct ofpbuf *out)
{
    size_t start_ofs = ofpbuf_size(out);
    struct nx_action_note *nan;
    unsigned int remainder;
    unsigned int len;

    nan = ofputil_put_NXAST_NOTE(out);
    ofpbuf_set_size(out, ofpbuf_size(out) - sizeof nan->note);

    ofpbuf_put(out, note->data, note->length);

    len = ofpbuf_size(out) - start_ofs;
    remainder = len % OFP_ACTION_ALIGN;
    if (remainder) {
        ofpbuf_put_zeros(out, OFP_ACTION_ALIGN - remainder);
    }
    nan = ofpbuf_at(out, start_ofs, sizeof *nan);
    nan->len = htons(ofpbuf_size(out) - start_ofs);
}

static void
ofpact_controller_to_nxast(const struct ofpact_controller *oc,
                           struct ofpbuf *out)
{
    struct nx_action_controller *nac;

    nac = ofputil_put_NXAST_CONTROLLER(out);
    nac->max_len = htons(oc->max_len);
    nac->controller_id = htons(oc->controller_id);
    nac->reason = oc->reason;
}

static void
ofpact_dec_ttl_to_nxast(const struct ofpact_cnt_ids *oc_ids,
                        struct ofpbuf *out)
{
    if (oc_ids->ofpact.compat == OFPUTIL_NXAST_DEC_TTL) {
        ofputil_put_NXAST_DEC_TTL(out);
    } else {
        struct nx_action_cnt_ids *nac_ids =
            ofputil_put_NXAST_DEC_TTL_CNT_IDS(out);
        int ids_len = ROUND_UP(2 * oc_ids->n_controllers, OFP_ACTION_ALIGN);
        ovs_be16 *ids;
        size_t i;

        nac_ids->len = htons(ntohs(nac_ids->len) + ids_len);
        nac_ids->n_controllers = htons(oc_ids->n_controllers);

        ids = ofpbuf_put_zeros(out, ids_len);
        for (i = 0; i < oc_ids->n_controllers; i++) {
            ids[i] = htons(oc_ids->cnt_ids[i]);
        }
    }
}

static void
ofpact_fin_timeout_to_nxast(const struct ofpact_fin_timeout *fin_timeout,
                            struct ofpbuf *out)
{
    struct nx_action_fin_timeout *naft = ofputil_put_NXAST_FIN_TIMEOUT(out);
    naft->fin_idle_timeout = htons(fin_timeout->fin_idle_timeout);
    naft->fin_hard_timeout = htons(fin_timeout->fin_hard_timeout);
}

static void
ofpact_sample_to_nxast(const struct ofpact_sample *os,
                       struct ofpbuf *out)
{
    struct nx_action_sample *nas;

    nas = ofputil_put_NXAST_SAMPLE(out);
    nas->probability = htons(os->probability);
    nas->collector_set_id = htonl(os->collector_set_id);
    nas->obs_domain_id = htonl(os->obs_domain_id);
    nas->obs_point_id = htonl(os->obs_point_id);
}

static void
ofpact_to_nxast(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_CONTROLLER:
        ofpact_controller_to_nxast(ofpact_get_CONTROLLER(a), out);
        break;

    case OFPACT_OUTPUT_REG:
        ofpact_output_reg_to_nxast(ofpact_get_OUTPUT_REG(a), out);
        break;

    case OFPACT_BUNDLE:
        bundle_to_nxast(ofpact_get_BUNDLE(a), out);
        break;

    case OFPACT_REG_MOVE:
        nxm_reg_move_to_nxast(ofpact_get_REG_MOVE(a), out);
        break;

    case OFPACT_REG_LOAD:
        nxm_reg_load_to_nxast(ofpact_get_REG_LOAD(a), out);
        break;

    case OFPACT_STACK_PUSH:
        nxm_stack_push_to_nxast(ofpact_get_STACK_PUSH(a), out);
        break;

    case OFPACT_STACK_POP:
        nxm_stack_pop_to_nxast(ofpact_get_STACK_POP(a), out);
        break;

    case OFPACT_DEC_TTL:
        ofpact_dec_ttl_to_nxast(ofpact_get_DEC_TTL(a), out);
        break;

    case OFPACT_SET_MPLS_LABEL:
        ofputil_put_NXAST_SET_MPLS_LABEL(out)->label
            = ofpact_get_SET_MPLS_LABEL(a)->label;
        break;

    case OFPACT_SET_MPLS_TC:
        ofputil_put_NXAST_SET_MPLS_TC(out)->tc
            = ofpact_get_SET_MPLS_TC(a)->tc;
        break;

    case OFPACT_SET_MPLS_TTL:
        ofputil_put_NXAST_SET_MPLS_TTL(out)->ttl
            = ofpact_get_SET_MPLS_TTL(a)->ttl;
        break;

    case OFPACT_DEC_MPLS_TTL:
        ofputil_put_NXAST_DEC_MPLS_TTL(out);
        break;

    case OFPACT_SET_TUNNEL:
        ofpact_set_tunnel_to_nxast(ofpact_get_SET_TUNNEL(a), out);
        break;

    case OFPACT_WRITE_METADATA:
        ofpact_write_metadata_to_nxast(ofpact_get_WRITE_METADATA(a), out);
        break;

    case OFPACT_SET_QUEUE:
        ofputil_put_NXAST_SET_QUEUE(out)->queue_id
            = htonl(ofpact_get_SET_QUEUE(a)->queue_id);
        break;

    case OFPACT_POP_QUEUE:
        ofputil_put_NXAST_POP_QUEUE(out);
        break;

    case OFPACT_FIN_TIMEOUT:
        ofpact_fin_timeout_to_nxast(ofpact_get_FIN_TIMEOUT(a), out);
        break;

    case OFPACT_RESUBMIT:
        ofpact_resubmit_to_nxast(ofpact_get_RESUBMIT(a), out);
        break;

    case OFPACT_LEARN:
        learn_to_nxast(ofpact_get_LEARN(a), out);
        break;

    case OFPACT_MULTIPATH:
        multipath_to_nxast(ofpact_get_MULTIPATH(a), out);
        break;

    case OFPACT_NOTE:
        ofpact_note_to_nxast(ofpact_get_NOTE(a), out);
        break;

    case OFPACT_EXIT:
        ofputil_put_NXAST_EXIT(out);
        break;

    case OFPACT_PUSH_MPLS:
        ofputil_put_NXAST_PUSH_MPLS(out)->ethertype =
            ofpact_get_PUSH_MPLS(a)->ethertype;
        break;

    case OFPACT_POP_MPLS:
        ofputil_put_NXAST_POP_MPLS(out)->ethertype =
            ofpact_get_POP_MPLS(a)->ethertype;
        break;

    case OFPACT_SAMPLE:
        ofpact_sample_to_nxast(ofpact_get_SAMPLE(a), out);
        break;

    case OFPACT_GROUP:
    case OFPACT_OUTPUT:
    case OFPACT_ENQUEUE:
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
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
    case OFPACT_SET_FIELD:
        OVS_NOT_REACHED();
    }
}

/* Converting ofpacts to OpenFlow 1.0. */

static void
ofpact_output_to_openflow10(const struct ofpact_output *output,
                            struct ofpbuf *out)
{
    struct ofp10_action_output *oao;

    oao = ofputil_put_OFPAT10_OUTPUT(out);
    oao->port = htons(ofp_to_u16(output->port));
    oao->max_len = htons(output->max_len);
}

static void
ofpact_enqueue_to_openflow10(const struct ofpact_enqueue *enqueue,
                             struct ofpbuf *out)
{
    struct ofp10_action_enqueue *oae;

    oae = ofputil_put_OFPAT10_ENQUEUE(out);
    oae->port = htons(ofp_to_u16(enqueue->port));
    oae->queue_id = htonl(enqueue->queue);
}

static void
ofpact_to_openflow10(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_OUTPUT:
        ofpact_output_to_openflow10(ofpact_get_OUTPUT(a), out);
        break;

    case OFPACT_ENQUEUE:
        ofpact_enqueue_to_openflow10(ofpact_get_ENQUEUE(a), out);
        break;

    case OFPACT_SET_VLAN_VID:
        ofputil_put_OFPAT10_SET_VLAN_VID(out)->vlan_vid
            = htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        ofputil_put_OFPAT10_SET_VLAN_PCP(out)->vlan_pcp
            = ofpact_get_SET_VLAN_PCP(a)->vlan_pcp;
        break;

    case OFPACT_STRIP_VLAN:
        ofputil_put_OFPAT10_STRIP_VLAN(out);
        break;

    case OFPACT_SET_ETH_SRC:
        memcpy(ofputil_put_OFPAT10_SET_DL_SRC(out)->dl_addr,
               ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_ETH_DST:
        memcpy(ofputil_put_OFPAT10_SET_DL_DST(out)->dl_addr,
               ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_IPV4_SRC:
        ofputil_put_OFPAT10_SET_NW_SRC(out)->nw_addr
            = ofpact_get_SET_IPV4_SRC(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DST:
        ofputil_put_OFPAT10_SET_NW_DST(out)->nw_addr
            = ofpact_get_SET_IPV4_DST(a)->ipv4;
        break;

    case OFPACT_SET_IP_DSCP:
        ofputil_put_OFPAT10_SET_NW_TOS(out)->nw_tos
            = ofpact_get_SET_IP_DSCP(a)->dscp;
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ofputil_put_OFPAT10_SET_TP_SRC(out)->tp_port
            = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ofputil_put_OFPAT10_SET_TP_DST(out)->tp_port
            = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_PUSH_VLAN:
        /* PUSH is a side effect of a SET_VLAN_VID/PCP, which should
         * follow this action. */
        break;

    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
        /* XXX */
        break;

    case OFPACT_GROUP:
        break;

    case OFPACT_SET_FIELD:
        set_field_to_openflow(ofpact_get_SET_FIELD(a), out);
        break;

    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
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
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_SAMPLE:
        ofpact_to_nxast(a, out);
        break;
    }
}

/* Converting ofpacts to OpenFlow 1.1. */

static void
ofpact_output_to_openflow11(const struct ofpact_output *output,
                            struct ofpbuf *out)
{
    struct ofp11_action_output *oao;

    oao = ofputil_put_OFPAT11_OUTPUT(out);
    oao->port = ofputil_port_to_ofp11(output->port);
    oao->max_len = htons(output->max_len);
}

static void
ofpact_dec_ttl_to_openflow11(const struct ofpact_cnt_ids *dec_ttl,
                             struct ofpbuf *out)
{
    if (dec_ttl->n_controllers == 1 && dec_ttl->cnt_ids[0] == 0
        && (!dec_ttl->ofpact.compat ||
            dec_ttl->ofpact.compat == OFPUTIL_OFPAT11_DEC_NW_TTL)) {
        ofputil_put_OFPAT11_DEC_NW_TTL(out);
    } else {
        ofpact_dec_ttl_to_nxast(dec_ttl, out);
    }
}

static void
ofpact_to_openflow11(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_OUTPUT:
        return ofpact_output_to_openflow11(ofpact_get_OUTPUT(a), out);

    case OFPACT_ENQUEUE:
        /* XXX */
        break;

    case OFPACT_SET_VLAN_VID:
        /* Push a VLAN tag, if one was not seen at action validation time. */
        if (!ofpact_get_SET_VLAN_VID(a)->flow_has_vlan
            && ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
            ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype
                = htons(ETH_TYPE_VLAN_8021Q);
        }
        ofputil_put_OFPAT11_SET_VLAN_VID(out)->vlan_vid
            = htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        /* Push a VLAN tag, if one was not seen at action validation time. */
        if (!ofpact_get_SET_VLAN_PCP(a)->flow_has_vlan
            && ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
            ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype
                = htons(ETH_TYPE_VLAN_8021Q);
        }
        ofputil_put_OFPAT11_SET_VLAN_PCP(out)->vlan_pcp
            = ofpact_get_SET_VLAN_PCP(a)->vlan_pcp;
        break;

    case OFPACT_STRIP_VLAN:
        ofputil_put_OFPAT11_POP_VLAN(out);
        break;

    case OFPACT_PUSH_VLAN:
        /* XXX ETH_TYPE_VLAN_8021AD case */
        ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype =
            htons(ETH_TYPE_VLAN_8021Q);
        break;

    case OFPACT_SET_QUEUE:
        ofputil_put_OFPAT11_SET_QUEUE(out)->queue_id
            = htonl(ofpact_get_SET_QUEUE(a)->queue_id);
        break;

    case OFPACT_SET_ETH_SRC:
        memcpy(ofputil_put_OFPAT11_SET_DL_SRC(out)->dl_addr,
               ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_ETH_DST:
        memcpy(ofputil_put_OFPAT11_SET_DL_DST(out)->dl_addr,
               ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_IPV4_SRC:
        ofputil_put_OFPAT11_SET_NW_SRC(out)->nw_addr
            = ofpact_get_SET_IPV4_SRC(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DST:
        ofputil_put_OFPAT11_SET_NW_DST(out)->nw_addr
            = ofpact_get_SET_IPV4_DST(a)->ipv4;
        break;

    case OFPACT_SET_IP_DSCP:
        ofputil_put_OFPAT11_SET_NW_TOS(out)->nw_tos
            = ofpact_get_SET_IP_DSCP(a)->dscp;
        break;

    case OFPACT_SET_IP_ECN:
        ofputil_put_OFPAT11_SET_NW_ECN(out)->nw_ecn
            = ofpact_get_SET_IP_ECN(a)->ecn;
        break;

    case OFPACT_SET_IP_TTL:
        ofputil_put_OFPAT11_SET_NW_TTL(out)->nw_ttl
            = ofpact_get_SET_IP_TTL(a)->ttl;
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ofputil_put_OFPAT11_SET_TP_SRC(out)->tp_port
            = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ofputil_put_OFPAT11_SET_TP_DST(out)->tp_port
            = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_DEC_TTL:
        ofpact_dec_ttl_to_openflow11(ofpact_get_DEC_TTL(a), out);
        break;

    case OFPACT_SET_MPLS_LABEL:
        ofputil_put_OFPAT11_SET_MPLS_LABEL(out)->mpls_label
            = ofpact_get_SET_MPLS_LABEL(a)->label;
        break;

    case OFPACT_SET_MPLS_TC:
        ofputil_put_OFPAT11_SET_MPLS_TC(out)->mpls_tc
            = ofpact_get_SET_MPLS_TC(a)->tc;
        break;

    case OFPACT_SET_MPLS_TTL:
        ofputil_put_OFPAT11_SET_MPLS_TTL(out)->mpls_ttl
            = ofpact_get_SET_MPLS_TTL(a)->ttl;
        break;

    case OFPACT_DEC_MPLS_TTL:
        ofputil_put_OFPAT11_DEC_MPLS_TTL(out);
        break;

    case OFPACT_WRITE_METADATA:
        /* OpenFlow 1.1 uses OFPIT_WRITE_METADATA to express this action. */
        break;

    case OFPACT_PUSH_MPLS:
        ofputil_put_OFPAT11_PUSH_MPLS(out)->ethertype =
            ofpact_get_PUSH_MPLS(a)->ethertype;
        break;

    case OFPACT_POP_MPLS:
        ofputil_put_OFPAT11_POP_MPLS(out)->ethertype =
            ofpact_get_POP_MPLS(a)->ethertype;

        break;

    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
        OVS_NOT_REACHED();

    case OFPACT_GROUP:
        ofputil_put_OFPAT11_GROUP(out)->group_id =
            htonl(ofpact_get_GROUP(a)->group_id);
        break;

    case OFPACT_SET_FIELD:
        set_field_to_openflow(ofpact_get_SET_FIELD(a), out);
        break;

    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_STACK_PUSH:
    case OFPACT_STACK_POP:
    case OFPACT_SET_TUNNEL:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SAMPLE:
        ofpact_to_nxast(a, out);
        break;
    }
}

/* Output deprecated set actions as set_field actions. */
static void
ofpact_to_openflow12(const struct ofpact *a, struct ofpbuf *out)
{
    enum mf_field_id field;
    union mf_value value;
    struct ofpact_l4_port *l4port;
    uint8_t proto;

    /*
     * Convert actions deprecated in OpenFlow 1.2 to Set Field actions,
     * if possible.
     */
    switch ((int)a->type) {
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_TUNNEL:  /* Convert to a set_field, too. */

        switch ((int)a->type) {

        case OFPACT_SET_VLAN_VID:
            if (!ofpact_get_SET_VLAN_VID(a)->flow_has_vlan &&
                ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
                ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype
                    = htons(ETH_TYPE_VLAN_8021Q);
            }
            field = MFF_VLAN_VID;
            /* Set-Field on OXM_OF_VLAN_VID must have OFPVID_PRESENT set. */
            value.be16 = htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid
                               | OFPVID12_PRESENT);
            break;

        case OFPACT_SET_VLAN_PCP:
            if (!ofpact_get_SET_VLAN_PCP(a)->flow_has_vlan &&
                ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
                ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype
                    = htons(ETH_TYPE_VLAN_8021Q);
            }
            field = MFF_VLAN_PCP;
            value.u8 = ofpact_get_SET_VLAN_PCP(a)->vlan_pcp;
            break;

        case OFPACT_SET_ETH_SRC:
            field = MFF_ETH_SRC;
            memcpy(value.mac, ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_ETH_DST:
            field = MFF_ETH_DST;
            memcpy(value.mac, ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
            break;

        case OFPACT_SET_IPV4_SRC:
            field = MFF_IPV4_SRC;
            value.be32 = ofpact_get_SET_IPV4_SRC(a)->ipv4;
            break;

        case OFPACT_SET_IPV4_DST:
            field = MFF_IPV4_DST;
            value.be32 = ofpact_get_SET_IPV4_DST(a)->ipv4;
            break;

        case OFPACT_SET_IP_DSCP:
            field = MFF_IP_DSCP_SHIFTED; /* OXM_OF_IP_DSCP */
            value.u8 = ofpact_get_SET_IP_DSCP(a)->dscp >> 2;
            break;

        case OFPACT_SET_IP_ECN:
            field = MFF_IP_ECN;
            value.u8 = ofpact_get_SET_IP_ECN(a)->ecn;
            break;

        case OFPACT_SET_L4_SRC_PORT:
            /* We keep track of IP protocol while translating actions to be
             * able to translate to the proper OXM type.
             * If the IP protocol type is unknown, the translation cannot
             * be performed and we will send the action using the original
             * action type. */
            l4port = ofpact_get_SET_L4_SRC_PORT(a);
            proto = l4port->flow_ip_proto;
            field = proto == IPPROTO_TCP ? MFF_TCP_SRC
                : proto == IPPROTO_UDP ? MFF_UDP_SRC
                : proto == IPPROTO_SCTP ? MFF_SCTP_SRC
                : MFF_N_IDS; /* RFC: Unknown IP proto, do not translate. */
            value.be16 = htons(l4port->port);
            break;

        case OFPACT_SET_L4_DST_PORT:
            l4port = ofpact_get_SET_L4_DST_PORT(a);
            proto = l4port->flow_ip_proto;
            field = proto == IPPROTO_TCP ? MFF_TCP_DST
                : proto == IPPROTO_UDP ? MFF_UDP_DST
                : proto == IPPROTO_SCTP ? MFF_SCTP_DST
                : MFF_N_IDS; /* RFC: Unknown IP proto, do not translate. */
            value.be16 = htons(l4port->port);
            break;

        case OFPACT_SET_MPLS_LABEL:
            field = MFF_MPLS_LABEL;
            value.be32 = ofpact_get_SET_MPLS_LABEL(a)->label;
            break;

        case OFPACT_SET_MPLS_TC:
            field = MFF_MPLS_TC;
            value.u8 = ofpact_get_SET_MPLS_TC(a)->tc;
            break;

        case OFPACT_SET_TUNNEL:
            field = MFF_TUN_ID;
            value.be64 = htonll(ofpact_get_SET_TUNNEL(a)->tun_id);
            break;

        default:
            field = MFF_N_IDS;
        }

        /* Put the action out as a set field action, if possible. */
        if (field < MFF_N_IDS) {
            uint64_t ofpacts_stub[128 / 8];
            struct ofpbuf sf_act;
            struct ofpact_set_field *sf;

            ofpbuf_use_stub(&sf_act, ofpacts_stub, sizeof ofpacts_stub);
            sf = ofpact_put_SET_FIELD(&sf_act);
            sf->field = mf_from_id(field);
            memcpy(&sf->value, &value, sf->field->n_bytes);
            set_field_to_openflow(sf, out);
            return;
        }
    }

    ofpact_to_openflow11(a, out);
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
    size_t start_size = ofpbuf_size(openflow);

    void (*translate)(const struct ofpact *a, struct ofpbuf *out) =
        (ofp_version == OFP10_VERSION) ? ofpact_to_openflow10 :
        (ofp_version == OFP11_VERSION) ? ofpact_to_openflow11 :
        ofpact_to_openflow12;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        translate(a, openflow);
    }
    return ofpbuf_size(openflow) - start_size;
}

static void
ofpacts_update_instruction_actions(struct ofpbuf *openflow, size_t ofs)
{
    struct ofp11_instruction_actions *oia;

    /* Update the instruction's length (or, if it's empty, delete it). */
    oia = ofpbuf_at_assert(openflow, ofs, sizeof *oia);
    if (ofpbuf_size(openflow) > ofs + sizeof *oia) {
        oia->len = htons(ofpbuf_size(openflow) - ofs);
    } else {
        ofpbuf_set_size(openflow, ofs);
    }
}

void
ofpacts_put_openflow_instructions(const struct ofpact ofpacts[],
                                  size_t ofpacts_len,
                                  struct ofpbuf *openflow,
                                  enum ofp_version ofp_version)
{
    const struct ofpact *a;

    ovs_assert(ofp_version >= OFP11_VERSION);

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        switch (ovs_instruction_type_from_ofpact_type(a->type)) {
        case OVSINST_OFPIT11_CLEAR_ACTIONS:
            instruction_put_OFPIT11_CLEAR_ACTIONS(openflow);
            break;

        case OVSINST_OFPIT11_GOTO_TABLE: {
            struct ofp11_instruction_goto_table *oigt;
            oigt = instruction_put_OFPIT11_GOTO_TABLE(openflow);
            oigt->table_id = ofpact_get_GOTO_TABLE(a)->table_id;
            memset(oigt->pad, 0, sizeof oigt->pad);
            break;
        }

        case OVSINST_OFPIT11_WRITE_METADATA: {
            const struct ofpact_metadata *om;
            struct ofp11_instruction_write_metadata *oiwm;

            om = ofpact_get_WRITE_METADATA(a);
            oiwm = instruction_put_OFPIT11_WRITE_METADATA(openflow);
            oiwm->metadata = om->metadata;
            oiwm->metadata_mask = om->mask;
            break;
        }

        case OVSINST_OFPIT13_METER:
            if (ofp_version >= OFP13_VERSION) {
                const struct ofpact_meter *om;
                struct ofp13_instruction_meter *oim;

                om = ofpact_get_METER(a);
                oim = instruction_put_OFPIT13_METER(openflow);
                oim->meter_id = htonl(om->meter_id);
            }
            break;

        case OVSINST_OFPIT11_APPLY_ACTIONS: {
            const size_t ofs = ofpbuf_size(openflow);
            const size_t ofpacts_len_left =
                (uint8_t*)ofpact_end(ofpacts, ofpacts_len) - (uint8_t*)a;
            const struct ofpact *action;
            const struct ofpact *processed = a;

            instruction_put_OFPIT11_APPLY_ACTIONS(openflow);
            OFPACT_FOR_EACH(action, a, ofpacts_len_left) {
                if (ovs_instruction_type_from_ofpact_type(action->type)
                    != OVSINST_OFPIT11_APPLY_ACTIONS) {
                    break;
                }
                if (ofp_version == OFP11_VERSION) {
                    ofpact_to_openflow11(action, openflow);
                } else {
                    ofpact_to_openflow12(action, openflow);
                }
                processed = action;
            }
            ofpacts_update_instruction_actions(openflow, ofs);
            a = processed;
            break;
        }

        case OVSINST_OFPIT11_WRITE_ACTIONS: {
            const size_t ofs = ofpbuf_size(openflow);
            const struct ofpact_nest *on;

            on = ofpact_get_WRITE_ACTIONS(a);
            instruction_put_OFPIT11_WRITE_ACTIONS(openflow);
            ofpacts_put_openflow_actions(on->actions,
                                         ofpact_nest_get_action_len(on),
                                         openflow, ofp_version);
            ofpacts_update_instruction_actions(openflow, ofs);

            break;
        }
        }
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
    case OFPACT_REG_LOAD:
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
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_SAMPLE:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_GOTO_TABLE:
    case OFPACT_METER:
    case OFPACT_GROUP:
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

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
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

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        if (a->type == OFPACT_GROUP
            && ofpact_get_GROUP(a)->group_id == group_id) {
            return true;
        }
    }

    return false;
}

bool
ofpacts_equal(const struct ofpact *a, size_t a_len,
              const struct ofpact *b, size_t b_len)
{
    return a_len == b_len && !memcmp(a, b, a_len);
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
print_note(const struct ofpact_note *note, struct ds *string)
{
    size_t i;

    ds_put_cstr(string, "note:");
    for (i = 0; i < note->length; i++) {
        if (i) {
            ds_put_char(string, '.');
        }
        ds_put_format(string, "%02"PRIx8, note->data[i]);
    }
}

static void
print_dec_ttl(const struct ofpact_cnt_ids *ids,
              struct ds *s)
{
    size_t i;

    ds_put_cstr(s, "dec_ttl");
    if (ids->ofpact.compat == OFPUTIL_NXAST_DEC_TTL_CNT_IDS) {
        ds_put_cstr(s, "(");
        for (i = 0; i < ids->n_controllers; i++) {
            if (i) {
                ds_put_cstr(s, ",");
            }
            ds_put_format(s, "%"PRIu16, ids->cnt_ids[i]);
        }
        ds_put_cstr(s, ")");
    }
}

static void
print_fin_timeout(const struct ofpact_fin_timeout *fin_timeout,
                  struct ds *s)
{
    ds_put_cstr(s, "fin_timeout(");
    if (fin_timeout->fin_idle_timeout) {
        ds_put_format(s, "idle_timeout=%"PRIu16",",
                      fin_timeout->fin_idle_timeout);
    }
    if (fin_timeout->fin_hard_timeout) {
        ds_put_format(s, "hard_timeout=%"PRIu16",",
                      fin_timeout->fin_hard_timeout);
    }
    ds_chomp(s, ',');
    ds_put_char(s, ')');
}

static void
ofpact_format(const struct ofpact *a, struct ds *s)
{
    const struct ofpact_enqueue *enqueue;
    const struct ofpact_resubmit *resubmit;
    const struct ofpact_controller *controller;
    const struct ofpact_metadata *metadata;
    const struct ofpact_tunnel *tunnel;
    const struct ofpact_sample *sample;
    const struct ofpact_set_field *set_field;
    const struct mf_field *mf;
    ofp_port_t port;

    switch (a->type) {
    case OFPACT_OUTPUT:
        port = ofpact_get_OUTPUT(a)->port;
        if (ofp_to_u16(port) < ofp_to_u16(OFPP_MAX)) {
            ds_put_format(s, "output:%"PRIu16, port);
        } else {
            ofputil_format_port(port, s);
            if (port == OFPP_CONTROLLER) {
                ds_put_format(s, ":%"PRIu16, ofpact_get_OUTPUT(a)->max_len);
            }
        }
        break;

    case OFPACT_CONTROLLER:
        controller = ofpact_get_CONTROLLER(a);
        if (controller->reason == OFPR_ACTION &&
            controller->controller_id == 0) {
            ds_put_format(s, "CONTROLLER:%"PRIu16,
                          ofpact_get_CONTROLLER(a)->max_len);
        } else {
            enum ofp_packet_in_reason reason = controller->reason;

            ds_put_cstr(s, "controller(");
            if (reason != OFPR_ACTION) {
                char reasonbuf[OFPUTIL_PACKET_IN_REASON_BUFSIZE];

                ds_put_format(s, "reason=%s,",
                              ofputil_packet_in_reason_to_string(
                                  reason, reasonbuf, sizeof reasonbuf));
            }
            if (controller->max_len != UINT16_MAX) {
                ds_put_format(s, "max_len=%"PRIu16",", controller->max_len);
            }
            if (controller->controller_id != 0) {
                ds_put_format(s, "id=%"PRIu16",", controller->controller_id);
            }
            ds_chomp(s, ',');
            ds_put_char(s, ')');
        }
        break;

    case OFPACT_ENQUEUE:
        enqueue = ofpact_get_ENQUEUE(a);
        ds_put_format(s, "enqueue:");
        ofputil_format_port(enqueue->port, s);
        ds_put_format(s, ":%"PRIu32, enqueue->queue);
        break;

    case OFPACT_OUTPUT_REG:
        ds_put_cstr(s, "output:");
        mf_format_subfield(&ofpact_get_OUTPUT_REG(a)->src, s);
        break;

    case OFPACT_BUNDLE:
        bundle_format(ofpact_get_BUNDLE(a), s);
        break;

    case OFPACT_SET_VLAN_VID:
        ds_put_format(s, "%s:%"PRIu16,
                      (a->compat == OFPUTIL_OFPAT11_SET_VLAN_VID
                       ? "set_vlan_vid"
                       : "mod_vlan_vid"),
                      ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        ds_put_format(s, "%s:%"PRIu8,
                      (a->compat == OFPUTIL_OFPAT11_SET_VLAN_PCP
                       ? "set_vlan_pcp"
                       : "mod_vlan_pcp"),
                      ofpact_get_SET_VLAN_PCP(a)->vlan_pcp);
        break;

    case OFPACT_STRIP_VLAN:
        ds_put_cstr(s, a->compat == OFPUTIL_OFPAT11_POP_VLAN
                    ? "pop_vlan" : "strip_vlan");
        break;

    case OFPACT_PUSH_VLAN:
        /* XXX 802.1AD case*/
        ds_put_format(s, "push_vlan:%#"PRIx16, ETH_TYPE_VLAN_8021Q);
        break;

    case OFPACT_SET_ETH_SRC:
        ds_put_format(s, "mod_dl_src:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(ofpact_get_SET_ETH_SRC(a)->mac));
        break;

    case OFPACT_SET_ETH_DST:
        ds_put_format(s, "mod_dl_dst:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(ofpact_get_SET_ETH_DST(a)->mac));
        break;

    case OFPACT_SET_IPV4_SRC:
        ds_put_format(s, "mod_nw_src:"IP_FMT,
                      IP_ARGS(ofpact_get_SET_IPV4_SRC(a)->ipv4));
        break;

    case OFPACT_SET_IPV4_DST:
        ds_put_format(s, "mod_nw_dst:"IP_FMT,
                      IP_ARGS(ofpact_get_SET_IPV4_DST(a)->ipv4));
        break;

    case OFPACT_SET_IP_DSCP:
        ds_put_format(s, "mod_nw_tos:%d", ofpact_get_SET_IP_DSCP(a)->dscp);
        break;

    case OFPACT_SET_IP_ECN:
        ds_put_format(s, "mod_nw_ecn:%d", ofpact_get_SET_IP_ECN(a)->ecn);
        break;

    case OFPACT_SET_IP_TTL:
        ds_put_format(s, "mod_nw_ttl:%d", ofpact_get_SET_IP_TTL(a)->ttl);
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ds_put_format(s, "mod_tp_src:%d", ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ds_put_format(s, "mod_tp_dst:%d", ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_REG_MOVE:
        nxm_format_reg_move(ofpact_get_REG_MOVE(a), s);
        break;

    case OFPACT_REG_LOAD:
        nxm_format_reg_load(ofpact_get_REG_LOAD(a), s);
        break;

    case OFPACT_SET_FIELD:
        set_field = ofpact_get_SET_FIELD(a);
        mf = set_field->field;
        ds_put_format(s, "set_field:");
        mf_format(mf, &set_field->value, NULL, s);
        ds_put_format(s, "->%s", mf->name);
        break;

    case OFPACT_STACK_PUSH:
        nxm_format_stack_push(ofpact_get_STACK_PUSH(a), s);
        break;

    case OFPACT_STACK_POP:
        nxm_format_stack_pop(ofpact_get_STACK_POP(a), s);
        break;

    case OFPACT_DEC_TTL:
        print_dec_ttl(ofpact_get_DEC_TTL(a), s);
        break;

    case OFPACT_SET_MPLS_LABEL:
        ds_put_format(s, "set_mpls_label(%"PRIu32")",
                      ntohl(ofpact_get_SET_MPLS_LABEL(a)->label));
        break;

    case OFPACT_SET_MPLS_TC:
        ds_put_format(s, "set_mpls_ttl(%"PRIu8")",
                      ofpact_get_SET_MPLS_TC(a)->tc);
        break;

    case OFPACT_SET_MPLS_TTL:
        ds_put_format(s, "set_mpls_ttl(%"PRIu8")",
                      ofpact_get_SET_MPLS_TTL(a)->ttl);
        break;

    case OFPACT_DEC_MPLS_TTL:
        ds_put_cstr(s, "dec_mpls_ttl");
        break;

    case OFPACT_SET_TUNNEL:
        tunnel = ofpact_get_SET_TUNNEL(a);
        ds_put_format(s, "set_tunnel%s:%#"PRIx64,
                      (tunnel->tun_id > UINT32_MAX
                       || a->compat == OFPUTIL_NXAST_SET_TUNNEL64 ? "64" : ""),
                      tunnel->tun_id);
        break;

    case OFPACT_SET_QUEUE:
        ds_put_format(s, "set_queue:%"PRIu32,
                      ofpact_get_SET_QUEUE(a)->queue_id);
        break;

    case OFPACT_POP_QUEUE:
        ds_put_cstr(s, "pop_queue");
        break;

    case OFPACT_FIN_TIMEOUT:
        print_fin_timeout(ofpact_get_FIN_TIMEOUT(a), s);
        break;

    case OFPACT_RESUBMIT:
        resubmit = ofpact_get_RESUBMIT(a);
        if (resubmit->in_port != OFPP_IN_PORT && resubmit->table_id == 255) {
            ds_put_cstr(s, "resubmit:");
            ofputil_format_port(resubmit->in_port, s);
        } else {
            ds_put_format(s, "resubmit(");
            if (resubmit->in_port != OFPP_IN_PORT) {
                ofputil_format_port(resubmit->in_port, s);
            }
            ds_put_char(s, ',');
            if (resubmit->table_id != 255) {
                ds_put_format(s, "%"PRIu8, resubmit->table_id);
            }
            ds_put_char(s, ')');
        }
        break;

    case OFPACT_LEARN:
        learn_format(ofpact_get_LEARN(a), s);
        break;

    case OFPACT_MULTIPATH:
        multipath_format(ofpact_get_MULTIPATH(a), s);
        break;

    case OFPACT_NOTE:
        print_note(ofpact_get_NOTE(a), s);
        break;

    case OFPACT_PUSH_MPLS:
        ds_put_format(s, "push_mpls:0x%04"PRIx16,
                      ntohs(ofpact_get_PUSH_MPLS(a)->ethertype));
        break;

    case OFPACT_POP_MPLS:
        ds_put_format(s, "pop_mpls:0x%04"PRIx16,
                      ntohs(ofpact_get_POP_MPLS(a)->ethertype));
        break;

    case OFPACT_EXIT:
        ds_put_cstr(s, "exit");
        break;

    case OFPACT_SAMPLE:
        sample = ofpact_get_SAMPLE(a);
        ds_put_format(
            s, "sample(probability=%"PRIu16",collector_set_id=%"PRIu32
            ",obs_domain_id=%"PRIu32",obs_point_id=%"PRIu32")",
            sample->probability, sample->collector_set_id,
            sample->obs_domain_id, sample->obs_point_id);
        break;

    case OFPACT_WRITE_ACTIONS: {
        struct ofpact_nest *on = ofpact_get_WRITE_ACTIONS(a);
        ds_put_format(s, "%s(",
                      ovs_instruction_name_from_type(
                          OVSINST_OFPIT11_WRITE_ACTIONS));
        ofpacts_format(on->actions, ofpact_nest_get_action_len(on), s);
        ds_put_char(s, ')');
        break;
    }

    case OFPACT_CLEAR_ACTIONS:
        ds_put_format(s, "%s",
                      ovs_instruction_name_from_type(
                          OVSINST_OFPIT11_CLEAR_ACTIONS));
        break;

    case OFPACT_WRITE_METADATA:
        metadata = ofpact_get_WRITE_METADATA(a);
        ds_put_format(s, "%s:%#"PRIx64,
                      ovs_instruction_name_from_type(
                          OVSINST_OFPIT11_WRITE_METADATA),
                      ntohll(metadata->metadata));
        if (metadata->mask != OVS_BE64_MAX) {
            ds_put_format(s, "/%#"PRIx64, ntohll(metadata->mask));
        }
        break;

    case OFPACT_GOTO_TABLE:
        ds_put_format(s, "%s:%"PRIu8,
                      ovs_instruction_name_from_type(
                          OVSINST_OFPIT11_GOTO_TABLE),
                      ofpact_get_GOTO_TABLE(a)->table_id);
        break;

    case OFPACT_METER:
        ds_put_format(s, "%s:%"PRIu32,
                      ovs_instruction_name_from_type(OVSINST_OFPIT13_METER),
                      ofpact_get_METER(a)->meter_id);
        break;

    case OFPACT_GROUP:
        ds_put_format(s, "group:%"PRIu32,
                      ofpact_get_GROUP(a)->group_id);
        break;
    }
}

/* Appends a string representing the 'ofpacts_len' bytes of ofpacts in
 * 'ofpacts' to 'string'. */
void
ofpacts_format(const struct ofpact *ofpacts, size_t ofpacts_len,
               struct ds *string)
{
    if (!ofpacts_len) {
        ds_put_cstr(string, "drop");
    } else {
        const struct ofpact *a;

        OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
            if (a != ofpacts) {
                ds_put_cstr(string, ",");
            }

            /* XXX write-actions */
            ofpact_format(a, string);
        }
    }
}

/* Internal use by helpers. */

void *
ofpact_put(struct ofpbuf *ofpacts, enum ofpact_type type, size_t len)
{
    struct ofpact *ofpact;

    ofpact_pad(ofpacts);
    ofpact = ofpacts->frame = ofpbuf_put_uninit(ofpacts, len);
    ofpact_init(ofpact, type, len);
    return ofpact;
}

void
ofpact_init(struct ofpact *ofpact, enum ofpact_type type, size_t len)
{
    memset(ofpact, 0, len);
    ofpact->type = type;
    ofpact->compat = OFPUTIL_ACTION_INVALID;
    ofpact->len = len;
}

/* Updates 'ofpact->len' to the number of bytes in the tail of 'ofpacts'
 * starting at 'ofpact'.
 *
 * This is the correct way to update a variable-length ofpact's length after
 * adding the variable-length part of the payload.  (See the large comment
 * near the end of ofp-actions.h for more information.) */
void
ofpact_update_len(struct ofpbuf *ofpacts, struct ofpact *ofpact)
{
    ovs_assert(ofpact == ofpacts->frame);
    ofpact->len = (char *) ofpbuf_tail(ofpacts) - (char *) ofpact;
}

/* Pads out 'ofpacts' to a multiple of OFPACT_ALIGNTO bytes in length.  Each
 * ofpact_put_<ENUM>() calls this function automatically beforehand, but the
 * client must call this itself after adding the final ofpact to an array of
 * them.
 *
 * (The consequences of failing to call this function are probably not dire.
 * OFPACT_FOR_EACH will calculate a pointer beyond the end of the ofpacts, but
 * not dereference it.  That's undefined behavior, technically, but it will not
 * cause a real problem on common systems.  Still, it seems better to call
 * it.) */
void
ofpact_pad(struct ofpbuf *ofpacts)
{
    unsigned int pad = PAD_SIZE(ofpbuf_size(ofpacts), OFPACT_ALIGNTO);
    if (pad) {
        ofpbuf_put_zeros(ofpacts, pad);
    }
}
