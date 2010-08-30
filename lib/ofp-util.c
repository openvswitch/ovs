/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include "ofp-print.h"
#include <inttypes.h>
#include <stdlib.h>
#include "ofp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "random.h"
#include "vlog.h"
#include "xtoxll.h"

VLOG_DEFINE_THIS_MODULE(ofp_util)

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* XXX we should really use consecutive xids to avoid probabilistic
 * failures. */
static inline uint32_t
alloc_xid(void)
{
    return random_uint32();
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * an arbitrary transaction id.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, alloc_xid(), *bufferp);
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * transaction id 'xid'.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                  struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, xid, *bufferp);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an arbitrary transaction id.  Allocated bytes
 * beyond the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *buffer)
{
    return put_openflow_xid(openflow_len, type, alloc_xid(), buffer);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an transaction id 'xid'.  Allocated bytes beyond
 * the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                 struct ofpbuf *buffer)
{
    struct ofp_header *oh;

    assert(openflow_len >= sizeof *oh);
    assert(openflow_len <= UINT16_MAX);

    oh = ofpbuf_put_uninit(buffer, openflow_len);
    oh->version = OFP_VERSION;
    oh->type = type;
    oh->length = htons(openflow_len);
    oh->xid = xid;
    memset(oh + 1, 0, openflow_len - sizeof *oh);
    return oh;
}

/* Updates the 'length' field of the OpenFlow message in 'buffer' to
 * 'buffer->size'. */
void
update_openflow_length(struct ofpbuf *buffer)
{
    struct ofp_header *oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    oh->length = htons(buffer->size);
}

struct ofpbuf *
make_flow_mod(uint16_t command, const flow_t *flow, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t size = sizeof *ofm + actions_len;
    struct ofpbuf *out = ofpbuf_new(size);
    ofm = ofpbuf_put_zeros(out, sizeof *ofm);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->cookie = 0;
    ofm->match.wildcards = htonl(0);
    ofm->match.in_port = htons(flow->in_port == ODPP_LOCAL ? OFPP_LOCAL
                               : flow->in_port);
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.nw_tos = flow->nw_tos;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(command);
    return out;
}

struct ofpbuf *
make_add_flow(const flow_t *flow, uint32_t buffer_id,
              uint16_t idle_timeout, size_t actions_len)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_ADD, flow, actions_len);
    struct ofp_flow_mod *ofm = out->data;
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->buffer_id = htonl(buffer_id);
    return out;
}

struct ofpbuf *
make_del_flow(const flow_t *flow)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_DELETE_STRICT, flow, 0);
    struct ofp_flow_mod *ofm = out->data;
    ofm->out_port = htons(OFPP_NONE);
    return out;
}

struct ofpbuf *
make_add_simple_flow(const flow_t *flow,
                     uint32_t buffer_id, uint16_t out_port,
                     uint16_t idle_timeout)
{
    if (out_port != OFPP_NONE) {
        struct ofp_action_output *oao;
        struct ofpbuf *buffer;

        buffer = make_add_flow(flow, buffer_id, idle_timeout, sizeof *oao);
        oao = ofpbuf_put_zeros(buffer, sizeof *oao);
        oao->type = htons(OFPAT_OUTPUT);
        oao->len = htons(sizeof *oao);
        oao->port = htons(out_port);
        return buffer;
    } else {
        return make_add_flow(flow, buffer_id, idle_timeout, 0);
    }
}

struct ofpbuf *
make_packet_in(uint32_t buffer_id, uint16_t in_port, uint8_t reason,
               const struct ofpbuf *payload, int max_send_len)
{
    struct ofp_packet_in *opi;
    struct ofpbuf *buf;
    int send_len;

    send_len = MIN(max_send_len, payload->size);
    buf = ofpbuf_new(sizeof *opi + send_len);
    opi = put_openflow_xid(offsetof(struct ofp_packet_in, data),
                           OFPT_PACKET_IN, 0, buf);
    opi->buffer_id = htonl(buffer_id);
    opi->total_len = htons(payload->size);
    opi->in_port = htons(in_port);
    opi->reason = reason;
    ofpbuf_put(buf, payload->data, send_len);
    update_openflow_length(buf);

    return buf;
}

struct ofpbuf *
make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                uint16_t in_port,
                const struct ofp_action_header *actions, size_t n_actions)
{
    size_t actions_len = n_actions * sizeof *actions;
    struct ofp_packet_out *opo;
    size_t size = sizeof *opo + actions_len + (packet ? packet->size : 0);
    struct ofpbuf *out = ofpbuf_new(size);

    opo = ofpbuf_put_uninit(out, sizeof *opo);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->header.length = htons(size);
    opo->header.xid = htonl(0);
    opo->buffer_id = htonl(buffer_id);
    opo->in_port = htons(in_port == ODPP_LOCAL ? OFPP_LOCAL : in_port);
    opo->actions_len = htons(actions_len);
    ofpbuf_put(out, actions, actions_len);
    if (packet) {
        ofpbuf_put(out, packet->data, packet->size);
    }
    return out;
}

struct ofpbuf *
make_unbuffered_packet_out(const struct ofpbuf *packet,
                           uint16_t in_port, uint16_t out_port)
{
    struct ofp_action_output action;
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof action);
    action.port = htons(out_port);
    return make_packet_out(packet, UINT32_MAX, in_port,
                           (struct ofp_action_header *) &action, 1);
}

struct ofpbuf *
make_buffered_packet_out(uint32_t buffer_id,
                         uint16_t in_port, uint16_t out_port)
{
    if (out_port != OFPP_NONE) {
        struct ofp_action_output action;
        action.type = htons(OFPAT_OUTPUT);
        action.len = htons(sizeof action);
        action.port = htons(out_port);
        return make_packet_out(NULL, buffer_id, in_port,
                               (struct ofp_action_header *) &action, 1);
    } else {
        return make_packet_out(NULL, buffer_id, in_port, NULL, 0);
    }
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(void)
{
    struct ofp_header *rq;
    struct ofpbuf *out = ofpbuf_new(sizeof *rq);
    rq = ofpbuf_put_uninit(out, sizeof *rq);
    rq->version = OFP_VERSION;
    rq->type = OFPT_ECHO_REQUEST;
    rq->length = htons(sizeof *rq);
    rq->xid = 0;
    return out;
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
make_echo_reply(const struct ofp_header *rq)
{
    size_t size = ntohs(rq->length);
    struct ofpbuf *out = ofpbuf_new(size);
    struct ofp_header *reply = ofpbuf_put(out, rq, size);
    reply->type = OFPT_ECHO_REPLY;
    return out;
}

static int
check_message_type(uint8_t got_type, uint8_t want_type)
{
    if (got_type != want_type) {
        char *want_type_name = ofp_message_type_to_string(want_type);
        char *got_type_name = ofp_message_type_to_string(got_type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received bad message type %s (expected %s)",
                     got_type_name, want_type_name);
        free(want_type_name);
        free(got_type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
    }
    return 0;
}

/* Checks that 'msg' has type 'type' and that it is exactly 'size' bytes long.
 * Returns 0 if the checks pass, otherwise an OpenFlow error code (produced
 * with ofp_mkerr()). */
int
check_ofp_message(const struct ofp_header *msg, uint8_t type, size_t size)
{
    size_t got_size;
    int error;

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size != size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received %s message of length %zu (expected %zu)",
                     type_name, got_size, size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    return 0;
}

/* Checks that 'msg' has type 'type' and that 'msg' is 'size' plus a
 * nonnegative integer multiple of 'array_elt_size' bytes long.  Returns 0 if
 * the checks pass, otherwise an OpenFlow error code (produced with
 * ofp_mkerr()).
 *
 * If 'n_array_elts' is nonnull, then '*n_array_elts' is set to the number of
 * 'array_elt_size' blocks in 'msg' past the first 'min_size' bytes, when
 * successful. */
int
check_ofp_message_array(const struct ofp_header *msg, uint8_t type,
                        size_t min_size, size_t array_elt_size,
                        size_t *n_array_elts)
{
    size_t got_size;
    int error;

    assert(array_elt_size);

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size < min_size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl, "received %s message of length %zu "
                     "(expected at least %zu)",
                     type_name, got_size, min_size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if ((got_size - min_size) % array_elt_size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received %s message of bad length %zu: the "
                     "excess over %zu (%zu) is not evenly divisible by %zu "
                     "(remainder is %zu)",
                     type_name, got_size, min_size, got_size - min_size,
                     array_elt_size, (got_size - min_size) % array_elt_size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (n_array_elts) {
        *n_array_elts = (got_size - min_size) / array_elt_size;
    }
    return 0;
}

int
check_ofp_packet_out(const struct ofp_header *oh, struct ofpbuf *data,
                     int *n_actionsp, int max_ports)
{
    const struct ofp_packet_out *opo;
    unsigned int actions_len, n_actions;
    size_t extra;
    int error;

    *n_actionsp = 0;
    error = check_ofp_message_array(oh, OFPT_PACKET_OUT,
                                    sizeof *opo, 1, &extra);
    if (error) {
        return error;
    }
    opo = (const struct ofp_packet_out *) oh;

    actions_len = ntohs(opo->actions_len);
    if (actions_len > extra) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out claims %u bytes of actions "
                     "but message has room for only %zu bytes",
                     actions_len, extra);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (actions_len % sizeof(union ofp_action)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out claims %u bytes of actions, "
                     "which is not a multiple of %zu",
                     actions_len, sizeof(union ofp_action));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    n_actions = actions_len / sizeof(union ofp_action);
    error = validate_actions((const union ofp_action *) opo->actions,
                             n_actions, max_ports);
    if (error) {
        return error;
    }

    data->data = (void *) &opo->actions[n_actions];
    data->size = extra - actions_len;
    *n_actionsp = n_actions;
    return 0;
}

const struct ofp_flow_stats *
flow_stats_first(struct flow_stats_iterator *iter,
                 const struct ofp_stats_reply *osr)
{
    iter->pos = osr->body;
    iter->end = osr->body + (ntohs(osr->header.length)
                             - offsetof(struct ofp_stats_reply, body));
    return flow_stats_next(iter);
}

const struct ofp_flow_stats *
flow_stats_next(struct flow_stats_iterator *iter)
{
    ptrdiff_t bytes_left = iter->end - iter->pos;
    const struct ofp_flow_stats *fs;
    size_t length;

    if (bytes_left < sizeof *fs) {
        if (bytes_left != 0) {
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "%td leftover bytes in flow stats reply", bytes_left);
        }
        return NULL;
    }

    fs = (const void *) iter->pos;
    length = ntohs(fs->length);
    if (length < sizeof *fs) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu is shorter than "
                     "min %zu", length, sizeof *fs);
        return NULL;
    } else if (length > bytes_left) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu but only %td "
                     "bytes left", length, bytes_left);
        return NULL;
    } else if ((length - sizeof *fs) % sizeof fs->actions[0]) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu has %zu bytes "
                     "left over in final action", length,
                     (length - sizeof *fs) % sizeof fs->actions[0]);
        return NULL;
    }
    iter->pos += length;
    return fs;
}

/* Alignment of ofp_actions. */
#define ACTION_ALIGNMENT 8

static int
check_action_exact_len(const union ofp_action *a, unsigned int len,
                       unsigned int required_len)
{
    if (len != required_len) {
        VLOG_DBG_RL(&bad_ofmsg_rl,
                    "action %u has invalid length %"PRIu16" (must be %u)\n",
                    a->type, ntohs(a->header.len), required_len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

/* Checks that 'port' is a valid output port for the OFPAT_OUTPUT action, given
 * that the switch will never have more than 'max_ports' ports.  Returns 0 if
 * 'port' is valid, otherwise an ofp_mkerr() return code. */
static int
check_output_port(uint16_t port, int max_ports)
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

    default:
        if (port < max_ports) {
            return 0;
        }
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown output port %x", port);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
    }
}

/* Checks that 'action' is a valid OFPAT_ENQUEUE action, given that the switch
 * will never have more than 'max_ports' ports.  Returns 0 if 'port' is valid,
 * otherwise an ofp_mkerr() return code. */
static int
check_enqueue_action(const union ofp_action *a, unsigned int len,
                     int max_ports)
{
    const struct ofp_action_enqueue *oae;
    uint16_t port;
    int error;

    error = check_action_exact_len(a, len, 16);
    if (error) {
        return error;
    }

    oae = (const struct ofp_action_enqueue *) a;
    port = ntohs(oae->port);
    if (port < max_ports || port == OFPP_IN_PORT) {
        return 0;
    }
    VLOG_WARN_RL(&bad_ofmsg_rl, "unknown enqueue port %x", port);
    return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
}

static int
check_nicira_action(const union ofp_action *a, unsigned int len)
{
    const struct nx_action_header *nah;

    if (len < 16) {
        VLOG_DBG_RL(&bad_ofmsg_rl,
                    "Nicira vendor action only %u bytes", len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    nah = (const struct nx_action_header *) a;

    switch (ntohs(nah->subtype)) {
    case NXAST_RESUBMIT:
    case NXAST_SET_TUNNEL:
        return check_action_exact_len(a, len, 16);
    default:
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR_TYPE);
    }
}

static int
check_action(const union ofp_action *a, unsigned int len, int max_ports)
{
    int error;

    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT:
        error = check_action_exact_len(a, len, 8);
        if (error) {
            return error;
        }
        return check_output_port(ntohs(a->output.port), max_ports);

    case OFPAT_SET_VLAN_VID:
    case OFPAT_SET_VLAN_PCP:
    case OFPAT_STRIP_VLAN:
    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
    case OFPAT_SET_NW_TOS:
    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
        return check_action_exact_len(a, len, 8);

    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
        return check_action_exact_len(a, len, 16);

    case OFPAT_VENDOR:
        return (a->vendor.vendor == htonl(NX_VENDOR_ID)
                ? check_nicira_action(a, len)
                : ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR));

    case OFPAT_ENQUEUE:
        return check_enqueue_action(a, len, max_ports);

    default:
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown action type %"PRIu16,
                ntohs(a->type));
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }
}

int
validate_actions(const union ofp_action *actions, size_t n_actions,
                 int max_ports)
{
    const union ofp_action *a;

    for (a = actions; a < &actions[n_actions]; ) {
        unsigned int len = ntohs(a->header.len);
        unsigned int n_slots = len / ACTION_ALIGNMENT;
        unsigned int slots_left = &actions[n_actions] - a;
        int error;

        if (n_slots > slots_left) {
            VLOG_DBG_RL(&bad_ofmsg_rl,
                        "action requires %u slots but only %u remain",
                        n_slots, slots_left);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (!len) {
            VLOG_DBG_RL(&bad_ofmsg_rl, "action has invalid length 0");
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (len % ACTION_ALIGNMENT) {
            VLOG_DBG_RL(&bad_ofmsg_rl, "action length %u is not a multiple "
                        "of %d", len, ACTION_ALIGNMENT);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        }

        error = check_action(a, len, max_ports);
        if (error) {
            return error;
        }
        a += n_slots;
    }
    return 0;
}

/* Returns true if 'action' outputs to 'port' (which must be in network byte
 * order), false otherwise. */
bool
action_outputs_to_port(const union ofp_action *action, uint16_t port)
{
    switch (ntohs(action->type)) {
    case OFPAT_OUTPUT:
        return action->output.port == port;
    case OFPAT_ENQUEUE:
        return ((const struct ofp_action_enqueue *) action)->port == port;
    default:
        return false;
    }
}

/* The set of actions must either come from a trusted source or have been
 * previously validated with validate_actions(). */
const union ofp_action *
actions_first(struct actions_iterator *iter,
              const union ofp_action *oa, size_t n_actions)
{
    iter->pos = oa;
    iter->end = oa + n_actions;
    return actions_next(iter);
}

const union ofp_action *
actions_next(struct actions_iterator *iter)
{
    if (iter->pos < iter->end) {
        const union ofp_action *a = iter->pos;
        unsigned int len = ntohs(a->header.len);
        iter->pos += len / ACTION_ALIGNMENT;
        return a;
    } else {
        return NULL;
    }
}

void
normalize_match(struct ofp_match *m)
{
    enum { OFPFW_NW = OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK | OFPFW_NW_PROTO };
    enum { OFPFW_TP = OFPFW_TP_SRC | OFPFW_TP_DST };
    uint32_t wc;

    wc = ntohl(m->wildcards) & OVSFW_ALL;
    if (wc & OFPFW_DL_TYPE) {
        m->dl_type = 0;

        /* Can't sensibly match on network or transport headers if the
         * data link type is unknown. */
        wc |= OFPFW_NW | OFPFW_TP;
        m->nw_src = m->nw_dst = m->nw_proto = m->nw_tos = 0;
        m->tp_src = m->tp_dst = 0;
    } else if (m->dl_type == htons(ETH_TYPE_IP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;

            /* Can't sensibly match on transport headers if the network
             * protocol is unknown. */
            wc |= OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        } else if (m->nw_proto == IPPROTO_TCP ||
                   m->nw_proto == IPPROTO_UDP ||
                   m->nw_proto == IPPROTO_ICMP) {
            if (wc & OFPFW_TP_SRC) {
                m->tp_src = 0;
            }
            if (wc & OFPFW_TP_DST) {
                m->tp_dst = 0;
            }
        } else {
            /* Transport layer fields will always be extracted as zeros, so we
             * can do an exact-match on those values.  */
            wc &= ~OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= flow_nw_bits_to_mask(wc, OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= flow_nw_bits_to_mask(wc, OFPFW_NW_DST_SHIFT);
        }
        if (wc & OFPFW_NW_TOS) {
            m->nw_tos = 0;
        } else {
            m->nw_tos &= IP_DSCP_MASK;
        }
    } else if (m->dl_type == htons(ETH_TYPE_ARP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= flow_nw_bits_to_mask(wc, OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= flow_nw_bits_to_mask(wc, OFPFW_NW_DST_SHIFT);
        }
        m->tp_src = m->tp_dst = m->nw_tos = 0;
    } else {
        /* Network and transport layer fields will always be extracted as
         * zeros, so we can do an exact-match on those values. */
        wc &= ~(OFPFW_NW | OFPFW_TP);
        m->nw_proto = m->nw_src = m->nw_dst = m->nw_tos = 0;
        m->tp_src = m->tp_dst = 0;
    }
    if (wc & OFPFW_DL_SRC) {
        memset(m->dl_src, 0, sizeof m->dl_src);
    }
    if (wc & OFPFW_DL_DST) {
        memset(m->dl_dst, 0, sizeof m->dl_dst);
    }
    m->wildcards = htonl(wc);
}

/* Returns a string that describes 'match' in a very literal way, without
 * interpreting its contents except in a very basic fashion.  The returned
 * string is intended to be fixed-length, so that it is easy to see differences
 * between two such strings if one is put above another.  This is useful for
 * describing changes made by normalize_match().
 *
 * The caller must free the returned string (with free()). */
char *
ofp_match_to_literal_string(const struct ofp_match *match)
{
    return xasprintf("wildcards=%#10"PRIx32" "
                     " in_port=%5"PRId16" "
                     " dl_src="ETH_ADDR_FMT" "
                     " dl_dst="ETH_ADDR_FMT" "
                     " dl_vlan=%5"PRId16" "
                     " dl_vlan_pcp=%3"PRId8" "
                     " dl_type=%#6"PRIx16" "
                     " nw_tos=%#4"PRIx8" "
                     " nw_proto=%#4"PRIx16" "
                     " nw_src=%#10"PRIx32" "
                     " nw_dst=%#10"PRIx32" "
                     " tp_src=%5"PRId16" "
                     " tp_dst=%5"PRId16,
                     ntohl(match->wildcards),
                     ntohs(match->in_port),
                     ETH_ADDR_ARGS(match->dl_src),
                     ETH_ADDR_ARGS(match->dl_dst),
                     ntohs(match->dl_vlan),
                     match->dl_vlan_pcp,
                     ntohs(match->dl_type),
                     match->nw_tos,
                     match->nw_proto,
                     ntohl(match->nw_src),
                     ntohl(match->nw_dst),
                     ntohs(match->tp_src),
                     ntohs(match->tp_dst));
}
