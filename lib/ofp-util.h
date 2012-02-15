/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira Networks.
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

#ifndef OFP_UTIL_H
#define OFP_UTIL_H 1

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "classifier.h"
#include "flow.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

struct cls_rule;
struct ofpbuf;

/* Basic decoding and length validation of OpenFlow messages. */
enum ofputil_msg_code {
    OFPUTIL_MSG_INVALID,

    /* OFPT_* messages. */
    OFPUTIL_OFPT_HELLO,
    OFPUTIL_OFPT_ERROR,
    OFPUTIL_OFPT_ECHO_REQUEST,
    OFPUTIL_OFPT_ECHO_REPLY,
    OFPUTIL_OFPT_FEATURES_REQUEST,
    OFPUTIL_OFPT_FEATURES_REPLY,
    OFPUTIL_OFPT_GET_CONFIG_REQUEST,
    OFPUTIL_OFPT_GET_CONFIG_REPLY,
    OFPUTIL_OFPT_SET_CONFIG,
    OFPUTIL_OFPT_PACKET_IN,
    OFPUTIL_OFPT_FLOW_REMOVED,
    OFPUTIL_OFPT_PORT_STATUS,
    OFPUTIL_OFPT_PACKET_OUT,
    OFPUTIL_OFPT_FLOW_MOD,
    OFPUTIL_OFPT_PORT_MOD,
    OFPUTIL_OFPT_BARRIER_REQUEST,
    OFPUTIL_OFPT_BARRIER_REPLY,
    OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST,
    OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY,

    /* OFPST_* stat requests. */
    OFPUTIL_OFPST_DESC_REQUEST,
    OFPUTIL_OFPST_FLOW_REQUEST,
    OFPUTIL_OFPST_AGGREGATE_REQUEST,
    OFPUTIL_OFPST_TABLE_REQUEST,
    OFPUTIL_OFPST_PORT_REQUEST,
    OFPUTIL_OFPST_QUEUE_REQUEST,

    /* OFPST_* stat replies. */
    OFPUTIL_OFPST_DESC_REPLY,
    OFPUTIL_OFPST_FLOW_REPLY,
    OFPUTIL_OFPST_QUEUE_REPLY,
    OFPUTIL_OFPST_PORT_REPLY,
    OFPUTIL_OFPST_TABLE_REPLY,
    OFPUTIL_OFPST_AGGREGATE_REPLY,

    /* NXT_* messages. */
    OFPUTIL_NXT_ROLE_REQUEST,
    OFPUTIL_NXT_ROLE_REPLY,
    OFPUTIL_NXT_SET_FLOW_FORMAT,
    OFPUTIL_NXT_FLOW_MOD_TABLE_ID,
    OFPUTIL_NXT_FLOW_MOD,
    OFPUTIL_NXT_FLOW_REMOVED,
    OFPUTIL_NXT_SET_PACKET_IN_FORMAT,
    OFPUTIL_NXT_PACKET_IN,
    OFPUTIL_NXT_FLOW_AGE,
    OFPUTIL_NXT_SET_ASYNC_CONFIG,

    /* NXST_* stat requests. */
    OFPUTIL_NXST_FLOW_REQUEST,
    OFPUTIL_NXST_AGGREGATE_REQUEST,

    /* NXST_* stat replies. */
    OFPUTIL_NXST_FLOW_REPLY,
    OFPUTIL_NXST_AGGREGATE_REPLY
};

struct ofputil_msg_type;
enum ofperr ofputil_decode_msg_type(const struct ofp_header *,
                                    const struct ofputil_msg_type **);
enum ofperr ofputil_decode_msg_type_partial(const struct ofp_header *,
                                            size_t length,
                                            const struct ofputil_msg_type **);
enum ofputil_msg_code ofputil_msg_type_code(const struct ofputil_msg_type *);
const char *ofputil_msg_type_name(const struct ofputil_msg_type *);

/* Port numbers. */
enum ofperr ofputil_check_output_port(uint16_t ofp_port, int max_ports);
bool ofputil_port_from_string(const char *, uint16_t *port);
void ofputil_format_port(uint16_t port, struct ds *);

/* Converting OFPFW_NW_SRC_MASK and OFPFW_NW_DST_MASK wildcard bit counts to
 * and from IP bitmasks. */
ovs_be32 ofputil_wcbits_to_netmask(int wcbits);
int ofputil_netmask_to_wcbits(ovs_be32 netmask);

/* Work with OpenFlow 1.0 ofp_match. */
void ofputil_wildcard_from_openflow(uint32_t ofpfw, struct flow_wildcards *);
void ofputil_cls_rule_from_match(const struct ofp_match *,
                                 unsigned int priority, struct cls_rule *);
void ofputil_normalize_rule(struct cls_rule *, enum nx_flow_format);
void ofputil_cls_rule_to_match(const struct cls_rule *, struct ofp_match *);

/* dl_type translation between OpenFlow and 'struct flow' format. */
ovs_be16 ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type);
ovs_be16 ofputil_dl_type_from_openflow(ovs_be16 ofp_dl_type);

/* Flow formats. */
bool ofputil_flow_format_is_valid(enum nx_flow_format);
const char *ofputil_flow_format_to_string(enum nx_flow_format);
int ofputil_flow_format_from_string(const char *);
enum nx_flow_format ofputil_min_flow_format(const struct cls_rule *);

struct ofpbuf *ofputil_make_set_flow_format(enum nx_flow_format);

/* PACKET_IN. */
bool ofputil_packet_in_format_is_valid(enum nx_packet_in_format);
int ofputil_packet_in_format_from_string(const char *);
const char *ofputil_packet_in_format_to_string(enum nx_packet_in_format);
struct ofpbuf *ofputil_make_set_packet_in_format(enum nx_packet_in_format);

/* NXT_FLOW_MOD_TABLE_ID extension. */
struct ofpbuf *ofputil_make_flow_mod_table_id(bool flow_mod_table_id);

/* Flow format independent flow_mod. */
struct ofputil_flow_mod {
    struct cls_rule cr;
    ovs_be64 cookie;
    ovs_be64 cookie_mask;
    uint8_t table_id;
    uint16_t command;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t buffer_id;
    uint16_t out_port;
    uint16_t flags;
    union ofp_action *actions;
    size_t n_actions;
};

enum ofperr ofputil_decode_flow_mod(struct ofputil_flow_mod *,
                                    const struct ofp_header *,
                                    bool flow_mod_table_id);
struct ofpbuf *ofputil_encode_flow_mod(const struct ofputil_flow_mod *,
                                       enum nx_flow_format,
                                       bool flow_mod_table_id);

/* Flow stats or aggregate stats request, independent of flow format. */
struct ofputil_flow_stats_request {
    bool aggregate;             /* Aggregate results? */
    struct cls_rule match;
    ovs_be64 cookie;
    ovs_be64 cookie_mask;
    uint16_t out_port;
    uint8_t table_id;
};

enum ofperr ofputil_decode_flow_stats_request(
    struct ofputil_flow_stats_request *, const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_stats_request(
    const struct ofputil_flow_stats_request *, enum nx_flow_format);

/* Flow stats reply, independent of flow format. */
struct ofputil_flow_stats {
    struct cls_rule rule;
    ovs_be64 cookie;
    uint8_t table_id;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    int idle_age;               /* Seconds since last packet, -1 if unknown. */
    int hard_age;               /* Seconds since last change, -1 if unknown. */
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    union ofp_action *actions;
    size_t n_actions;
};

int ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *,
                                    struct ofpbuf *msg,
                                    bool flow_age_extension);
void ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *,
                                     struct list *replies);

/* Aggregate stats reply, independent of flow format. */
struct ofputil_aggregate_stats {
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t flow_count;
};

struct ofpbuf *ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_stats_msg *request);

/* Flow removed message, independent of flow format. */
struct ofputil_flow_removed {
    struct cls_rule rule;
    ovs_be64 cookie;
    uint8_t reason;             /* One of OFPRR_*. */
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t idle_timeout;
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
};

enum ofperr ofputil_decode_flow_removed(struct ofputil_flow_removed *,
                                        const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_removed(const struct ofputil_flow_removed *,
                                           enum nx_flow_format);

/* Abstract packet-in message. */
struct ofputil_packet_in {
    const void *packet;
    size_t packet_len;

    enum ofp_packet_in_reason reason;    /* One of OFPRR_*. */
    uint8_t table_id;
    ovs_be64 cookie;

    uint32_t buffer_id;
    int send_len;
    uint16_t total_len;         /* Full length of frame. */

    struct flow_metadata fmd;   /* Metadata at creation time. */
};

int ofputil_decode_packet_in(struct ofputil_packet_in *,
                             const struct ofp_header *);
struct ofpbuf *ofputil_encode_packet_in(const struct ofputil_packet_in *,
                                        enum nx_packet_in_format);
int ofputil_decode_packet_in(struct ofputil_packet_in *pi,
                             const struct ofp_header *oh);

/* Abstract packet-out message. */
struct ofputil_packet_out {
    const void *packet;         /* Packet data, if buffer_id == UINT32_MAX. */
    size_t packet_len;          /* Length of packet data in bytes. */
    uint32_t buffer_id;         /* Buffer id or UINT32_MAX if no buffer. */
    uint16_t in_port;           /* Packet's input port or OFPP_NONE. */
    union ofp_action *actions;  /* Actions. */
    size_t n_actions;           /* Number of elements in 'actions' array. */
};

enum ofperr ofputil_decode_packet_out(struct ofputil_packet_out *,
                                      const struct ofp_packet_out *);
struct ofpbuf *ofputil_encode_packet_out(const struct ofputil_packet_out *);

/* OpenFlow protocol utility functions. */
void *make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **);
void *make_nxmsg(size_t openflow_len, uint32_t subtype, struct ofpbuf **);

void *make_openflow_xid(size_t openflow_len, uint8_t type,
                        ovs_be32 xid, struct ofpbuf **);
void *make_nxmsg_xid(size_t openflow_len, uint32_t subtype, ovs_be32 xid,
                     struct ofpbuf **);

void *put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *);
void *put_openflow_xid(size_t openflow_len, uint8_t type, ovs_be32 xid,
                       struct ofpbuf *);

void *put_nxmsg(size_t openflow_len, uint32_t subtype, struct ofpbuf *);
void *put_nxmsg_xid(size_t openflow_len, uint32_t subtype, ovs_be32 xid,
                    struct ofpbuf *);

void update_openflow_length(struct ofpbuf *);

void *ofputil_make_stats_request(size_t openflow_len, uint16_t type,
                                 uint32_t subtype, struct ofpbuf **);
void *ofputil_make_stats_reply(size_t openflow_len,
                               const struct ofp_stats_msg *request,
                               struct ofpbuf **);

void ofputil_start_stats_reply(const struct ofp_stats_msg *request,
                               struct list *);
struct ofpbuf *ofputil_reserve_stats_reply(size_t len, struct list *);
void *ofputil_append_stats_reply(size_t len, struct list *);

const void *ofputil_stats_body(const struct ofp_header *);
size_t ofputil_stats_body_len(const struct ofp_header *);

const void *ofputil_nxstats_body(const struct ofp_header *);
size_t ofputil_nxstats_body_len(const struct ofp_header *);

struct ofpbuf *make_flow_mod(uint16_t command, const struct cls_rule *,
                             size_t actions_len);
struct ofpbuf *make_add_flow(const struct cls_rule *, uint32_t buffer_id,
                             uint16_t max_idle, size_t actions_len);
struct ofpbuf *make_del_flow(const struct cls_rule *);
struct ofpbuf *make_add_simple_flow(const struct cls_rule *,
                                    uint32_t buffer_id, uint16_t out_port,
                                    uint16_t max_idle);
struct ofpbuf *make_packet_in(uint32_t buffer_id, uint16_t in_port,
                              uint8_t reason,
                              const struct ofpbuf *payload, int max_send_len);
struct ofpbuf *make_echo_request(void);
struct ofpbuf *make_echo_reply(const struct ofp_header *rq);

struct ofpbuf *ofputil_encode_barrier_request(void);

const char *ofputil_frag_handling_to_string(enum ofp_config_flags);
bool ofputil_frag_handling_from_string(const char *, enum ofp_config_flags *);

/* Actions. */

/* The type of an action.
 *
 * For each implemented OFPAT_* and NXAST_* action type, there is a
 * corresponding constant prefixed with OFPUTIL_, e.g.:
 *
 * OFPUTIL_OFPAT_OUTPUT
 * OFPUTIL_OFPAT_SET_VLAN_VID
 * OFPUTIL_OFPAT_SET_VLAN_PCP
 * OFPUTIL_OFPAT_STRIP_VLAN
 * OFPUTIL_OFPAT_SET_DL_SRC
 * OFPUTIL_OFPAT_SET_DL_DST
 * OFPUTIL_OFPAT_SET_NW_SRC
 * OFPUTIL_OFPAT_SET_NW_DST
 * OFPUTIL_OFPAT_SET_NW_TOS
 * OFPUTIL_OFPAT_SET_TP_SRC
 * OFPUTIL_OFPAT_SET_TP_DST
 * OFPUTIL_OFPAT_ENQUEUE
 * OFPUTIL_NXAST_RESUBMIT
 * OFPUTIL_NXAST_SET_TUNNEL
 * OFPUTIL_NXAST_SET_QUEUE
 * OFPUTIL_NXAST_POP_QUEUE
 * OFPUTIL_NXAST_REG_MOVE
 * OFPUTIL_NXAST_REG_LOAD
 * OFPUTIL_NXAST_NOTE
 * OFPUTIL_NXAST_SET_TUNNEL64
 * OFPUTIL_NXAST_MULTIPATH
 * OFPUTIL_NXAST_AUTOPATH
 * OFPUTIL_NXAST_BUNDLE
 * OFPUTIL_NXAST_BUNDLE_LOAD
 * OFPUTIL_NXAST_RESUBMIT_TABLE
 * OFPUTIL_NXAST_OUTPUT_REG
 * OFPUTIL_NXAST_LEARN
 * OFPUTIL_NXAST_DEC_TTL
 * OFPUTIL_NXAST_FIN_TIMEOUT
 *
 * (The above list helps developers who want to "grep" for these definitions.)
 */
enum ofputil_action_code {
#define OFPAT_ACTION(ENUM, STRUCT, NAME)             OFPUTIL_##ENUM,
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) OFPUTIL_##ENUM,
#include "ofp-util.def"
};

/* The number of values of "enum ofputil_action_code". */
enum {
#define OFPAT_ACTION(ENUM, STRUCT, NAME)             + 1
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) + 1
    OFPUTIL_N_ACTIONS = 0
#include "ofp-util.def"
};

int ofputil_decode_action(const union ofp_action *);
enum ofputil_action_code ofputil_decode_action_unsafe(
    const union ofp_action *);

int ofputil_action_code_from_name(const char *);

void *ofputil_put_action(enum ofputil_action_code, struct ofpbuf *buf);

/* For each OpenFlow action <ENUM> that has a corresponding action structure
 * struct <STRUCT>, this defines two functions:
 *
 *   void ofputil_init_<ENUM>(struct <STRUCT> *action);
 *
 *     Initializes the parts of 'action' that identify it as having type <ENUM>
 *     and length 'sizeof *action' and zeros the rest.  For actions that have
 *     variable length, the length used and cleared is that of struct <STRUCT>.
 *
 *  struct <STRUCT> *ofputil_put_<ENUM>(struct ofpbuf *buf);
 *
 *     Appends a new 'action', of length 'sizeof(struct <STRUCT>)', to 'buf',
 *     initializes it with ofputil_init_<ENUM>(), and returns it.
 */
#define OFPAT_ACTION(ENUM, STRUCT, NAME)                \
    void ofputil_init_##ENUM(struct STRUCT *);          \
    struct STRUCT *ofputil_put_##ENUM(struct ofpbuf *);
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)    \
    void ofputil_init_##ENUM(struct STRUCT *);          \
    struct STRUCT *ofputil_put_##ENUM(struct ofpbuf *);
#include "ofp-util.def"

#define OFP_ACTION_ALIGN 8      /* Alignment of ofp_actions. */

static inline union ofp_action *
ofputil_action_next(const union ofp_action *a)
{
    return ((union ofp_action *) (void *)
            ((uint8_t *) a + ntohs(a->header.len)));
}

static inline bool
ofputil_action_is_valid(const union ofp_action *a, size_t n_actions)
{
    uint16_t len = ntohs(a->header.len);
    return (!(len % OFP_ACTION_ALIGN)
            && len >= sizeof *a
            && len / sizeof *a <= n_actions);
}

/* This macro is careful to check for actions with bad lengths. */
#define OFPUTIL_ACTION_FOR_EACH(ITER, LEFT, ACTIONS, N_ACTIONS)         \
    for ((ITER) = (ACTIONS), (LEFT) = (N_ACTIONS);                      \
         (LEFT) > 0 && ofputil_action_is_valid(ITER, LEFT);             \
         ((LEFT) -= ntohs((ITER)->header.len) / sizeof(union ofp_action), \
          (ITER) = ofputil_action_next(ITER)))

/* This macro does not check for actions with bad lengths.  It should only be
 * used with actions from trusted sources or with actions that have already
 * been validated (e.g. with OFPUTIL_ACTION_FOR_EACH).  */
#define OFPUTIL_ACTION_FOR_EACH_UNSAFE(ITER, LEFT, ACTIONS, N_ACTIONS)  \
    for ((ITER) = (ACTIONS), (LEFT) = (N_ACTIONS);                      \
         (LEFT) > 0;                                                    \
         ((LEFT) -= ntohs((ITER)->header.len) / sizeof(union ofp_action), \
          (ITER) = ofputil_action_next(ITER)))

enum ofperr validate_actions(const union ofp_action *, size_t n_actions,
                             const struct flow *, int max_ports);
bool action_outputs_to_port(const union ofp_action *, ovs_be16 port);

enum ofperr ofputil_pull_actions(struct ofpbuf *, unsigned int actions_len,
                                 union ofp_action **, size_t *);

bool ofputil_actions_equal(const union ofp_action *a, size_t n_a,
                           const union ofp_action *b, size_t n_b);
union ofp_action *ofputil_actions_clone(const union ofp_action *, size_t n);

/* Handy utility for parsing flows and actions. */
bool ofputil_parse_key_value(char **stringp, char **keyp, char **valuep);

#endif /* ofp-util.h */
