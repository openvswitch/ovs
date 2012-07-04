/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "compiler.h"
#include "flow.h"
#include "netdev.h"
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
    OFPUTIL_OFPST_PORT_DESC_REQUEST,

    /* OFPST_* stat replies. */
    OFPUTIL_OFPST_DESC_REPLY,
    OFPUTIL_OFPST_FLOW_REPLY,
    OFPUTIL_OFPST_QUEUE_REPLY,
    OFPUTIL_OFPST_PORT_REPLY,
    OFPUTIL_OFPST_TABLE_REPLY,
    OFPUTIL_OFPST_AGGREGATE_REPLY,
    OFPUTIL_OFPST_PORT_DESC_REPLY,

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
    OFPUTIL_NXT_SET_CONTROLLER_ID,

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
enum ofperr ofputil_port_from_ofp11(ovs_be32 ofp11_port, uint16_t *ofp10_port);
ovs_be32 ofputil_port_to_ofp11(uint16_t ofp10_port);

enum ofperr ofputil_check_output_port(uint16_t ofp_port, int max_ports);
bool ofputil_port_from_string(const char *, uint16_t *port);
void ofputil_format_port(uint16_t port, struct ds *);

/* Converting OFPFW10_NW_SRC_MASK and OFPFW10_NW_DST_MASK wildcard bit counts
 * to and from IP bitmasks. */
ovs_be32 ofputil_wcbits_to_netmask(int wcbits);
int ofputil_netmask_to_wcbits(ovs_be32 netmask);

/* Protocols.
 *
 * These are arranged from most portable to least portable, or alternatively
 * from least powerful to most powerful.  Formats earlier on the list are more
 * likely to be understood for the purpose of making requests, but formats
 * later on the list are more likely to accurately describe a flow within a
 * switch.
 *
 * On any given OpenFlow connection, a single protocol is in effect at any
 * given time.  These values use separate bits only because that makes it easy
 * to test whether a particular protocol is within a given set of protocols and
 * to implement set union and intersection.
 */
enum ofputil_protocol {
    /* OpenFlow 1.0-based protocols. */
    OFPUTIL_P_OF10     = 1 << 0, /* OpenFlow 1.0 flow format. */
    OFPUTIL_P_OF10_TID = 1 << 1, /* OF1.0 + flow_mod_table_id extension. */
#define OFPUTIL_P_OF10_ANY (OFPUTIL_P_OF10 | OFPUTIL_P_OF10_TID)

    /* OpenFlow 1.0 with NXM-based flow formats. */
    OFPUTIL_P_NXM      = 1 << 2, /* Nicira extended match. */
    OFPUTIL_P_NXM_TID  = 1 << 3, /* NXM + flow_mod_table_id extension. */
#define OFPUTIL_P_NXM_ANY (OFPUTIL_P_NXM | OFPUTIL_P_NXM_TID)

    /* All protocols. */
#define OFPUTIL_P_ANY (OFPUTIL_P_OF10_ANY | OFPUTIL_P_NXM_ANY)

    /* Protocols in which a specific table may be specified in flow_mods. */
#define OFPUTIL_P_TID (OFPUTIL_P_OF10_TID | OFPUTIL_P_NXM_TID)
};

/* Protocols to use for flow dumps, from most to least preferred. */
extern enum ofputil_protocol ofputil_flow_dump_protocols[];
extern size_t ofputil_n_flow_dump_protocols;

enum ofputil_protocol ofputil_protocol_from_ofp_version(int version);
uint8_t ofputil_protocol_to_ofp_version(enum ofputil_protocol);

bool ofputil_protocol_is_valid(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocol_set_tid(enum ofputil_protocol,
                                               bool enable);
enum ofputil_protocol ofputil_protocol_to_base(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocol_set_base(
    enum ofputil_protocol cur, enum ofputil_protocol new_base);

const char *ofputil_protocol_to_string(enum ofputil_protocol);
char *ofputil_protocols_to_string(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocols_from_string(const char *);
enum ofputil_protocol ofputil_usable_protocols(const struct cls_rule *);

struct ofpbuf *ofputil_encode_set_protocol(enum ofputil_protocol current,
                                           enum ofputil_protocol want,
                                           enum ofputil_protocol *next);

/* nx_flow_format */
struct ofpbuf *ofputil_encode_nx_set_flow_format(enum nx_flow_format);
enum ofputil_protocol ofputil_nx_flow_format_to_protocol(enum nx_flow_format);
bool ofputil_nx_flow_format_is_valid(enum nx_flow_format);
const char *ofputil_nx_flow_format_to_string(enum nx_flow_format);

/* Work with ofp10_match. */
void ofputil_wildcard_from_ofpfw10(uint32_t ofpfw, struct flow_wildcards *);
void ofputil_cls_rule_from_ofp10_match(const struct ofp10_match *,
                                       unsigned int priority,
                                       struct cls_rule *);
void ofputil_normalize_rule(struct cls_rule *);
void ofputil_cls_rule_to_ofp10_match(const struct cls_rule *,
                                     struct ofp10_match *);

/* Work with ofp11_match. */
enum ofperr ofputil_cls_rule_from_ofp11_match(const struct ofp11_match *,
                                              unsigned int priority,
                                              struct cls_rule *);
void ofputil_cls_rule_to_ofp11_match(const struct cls_rule *,
                                     struct ofp11_match *);

/* dl_type translation between OpenFlow and 'struct flow' format. */
ovs_be16 ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type);
ovs_be16 ofputil_dl_type_from_openflow(ovs_be16 ofp_dl_type);

/* PACKET_IN. */
bool ofputil_packet_in_format_is_valid(enum nx_packet_in_format);
int ofputil_packet_in_format_from_string(const char *);
const char *ofputil_packet_in_format_to_string(enum nx_packet_in_format);
struct ofpbuf *ofputil_make_set_packet_in_format(enum nx_packet_in_format);

/* NXT_FLOW_MOD_TABLE_ID extension. */
struct ofpbuf *ofputil_make_flow_mod_table_id(bool flow_mod_table_id);

/* Protocol-independent flow_mod.
 *
 * The handling of cookies across multiple versions of OpenFlow is a bit
 * confusing.  A full description of Open vSwitch's cookie handling is
 * in the DESIGN file.  The following table shows the expected values of
 * the cookie-related fields for the different flow_mod commands in
 * OpenFlow 1.0 ("OF10") and NXM.  "<used>" and "-" indicate a value
 * that may be populated and an ignored field, respectively.
 *
 *               cookie  cookie_mask  new_cookie
 *               ======  ===========  ==========
 * OF10 Add        -          0         <used>
 * OF10 Modify     -          0         <used>
 * OF10 Delete     -          0           -
 * NXM Add         -          0         <used>
 * NXM Modify    <used>     <used>      <used>
 * NXM Delete    <used>     <used>        -
 */
struct ofputil_flow_mod {
    struct cls_rule cr;
    ovs_be64 cookie;         /* Cookie bits to match. */
    ovs_be64 cookie_mask;    /* 1-bit in each 'cookie' bit to match. */
    ovs_be64 new_cookie;     /* New cookie to install or -1. */
    uint8_t table_id;
    uint16_t command;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t buffer_id;
    uint16_t out_port;
    uint16_t flags;
    struct ofpact *ofpacts;     /* Series of "struct ofpact"s. */
    size_t ofpacts_len;         /* Length of ofpacts, in bytes. */
};

enum ofperr ofputil_decode_flow_mod(struct ofputil_flow_mod *,
                                    const struct ofp_header *,
                                    enum ofputil_protocol,
                                    struct ofpbuf *ofpacts);
struct ofpbuf *ofputil_encode_flow_mod(const struct ofputil_flow_mod *,
                                       enum ofputil_protocol);

enum ofputil_protocol ofputil_flow_mod_usable_protocols(
    const struct ofputil_flow_mod *fms, size_t n_fms);

/* Flow stats or aggregate stats request, independent of protocol. */
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
    const struct ofputil_flow_stats_request *, enum ofputil_protocol);
enum ofputil_protocol ofputil_flow_stats_request_usable_protocols(
    const struct ofputil_flow_stats_request *);

/* Flow stats reply, independent of protocol. */
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
    struct ofpact *ofpacts;
    size_t ofpacts_len;
};

int ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *,
                                    struct ofpbuf *msg,
                                    bool flow_age_extension,
                                    struct ofpbuf *ofpacts);
void ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *,
                                     struct list *replies);

/* Aggregate stats reply, independent of protocol. */
struct ofputil_aggregate_stats {
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t flow_count;
};

struct ofpbuf *ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_stats_msg *request);

/* Flow removed message, independent of protocol. */
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
                                           enum ofputil_protocol);

/* Abstract packet-in message. */
struct ofputil_packet_in {
    const void *packet;
    size_t packet_len;

    enum ofp_packet_in_reason reason;    /* One of OFPR_*. */
    uint16_t controller_id;              /* Controller ID to send to. */
    uint8_t table_id;
    ovs_be64 cookie;

    uint32_t buffer_id;
    int send_len;
    uint16_t total_len;         /* Full length of frame. */

    struct flow_metadata fmd;   /* Metadata at creation time. */
};

enum ofperr ofputil_decode_packet_in(struct ofputil_packet_in *,
                                     const struct ofp_header *);
struct ofpbuf *ofputil_encode_packet_in(const struct ofputil_packet_in *,
                                        enum nx_packet_in_format);

const char *ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason);
bool ofputil_packet_in_reason_from_string(const char *,
                                          enum ofp_packet_in_reason *);

/* Abstract packet-out message.
 *
 * ofputil_decode_packet_out() will ensure that 'in_port' is a physical port
 * (OFPP_MAX or less) or one of OFPP_LOCAL, OFPP_NONE, or OFPP_CONTROLLER. */
struct ofputil_packet_out {
    const void *packet;         /* Packet data, if buffer_id == UINT32_MAX. */
    size_t packet_len;          /* Length of packet data in bytes. */
    uint32_t buffer_id;         /* Buffer id or UINT32_MAX if no buffer. */
    uint16_t in_port;           /* Packet's input port. */
    struct ofpact *ofpacts;     /* Actions. */
    size_t ofpacts_len;         /* Size of ofpacts in bytes. */
};

enum ofperr ofputil_decode_packet_out(struct ofputil_packet_out *,
                                      const struct ofp_packet_out *,
                                      struct ofpbuf *ofpacts);
struct ofpbuf *ofputil_encode_packet_out(const struct ofputil_packet_out *);

enum ofputil_port_config {
    /* OpenFlow 1.0 and 1.1 share these values for these port config bits. */
    OFPUTIL_PC_PORT_DOWN    = 1 << 0, /* Port is administratively down. */
    OFPUTIL_PC_NO_RECV      = 1 << 2, /* Drop all packets received by port. */
    OFPUTIL_PC_NO_FWD       = 1 << 5, /* Drop packets forwarded to port. */
    OFPUTIL_PC_NO_PACKET_IN = 1 << 6, /* No send packet-in msgs for port. */
    /* OpenFlow 1.0 only. */
    OFPUTIL_PC_NO_STP       = 1 << 1, /* No 802.1D spanning tree for port. */
    OFPUTIL_PC_NO_RECV_STP  = 1 << 3, /* Drop received 802.1D STP packets. */
    OFPUTIL_PC_NO_FLOOD     = 1 << 4, /* Do not include port when flooding. */
    /* There are no OpenFlow 1.1-only bits. */
};

enum ofputil_port_state {
    /* OpenFlow 1.0 and 1.1 share this values for these port state bits. */
    OFPUTIL_PS_LINK_DOWN   = 1 << 0, /* No physical link present. */
    /* OpenFlow 1.1 only. */
    OFPUTIL_PS_BLOCKED     = 1 << 1, /* Port is blocked */
    OFPUTIL_PS_LIVE        = 1 << 2, /* Live for Fast Failover Group. */
    /* OpenFlow 1.0 only. */
    OFPUTIL_PS_STP_LISTEN  = 0 << 8, /* Not learning or relaying frames. */
    OFPUTIL_PS_STP_LEARN   = 1 << 8, /* Learning but not relaying frames. */
    OFPUTIL_PS_STP_FORWARD = 2 << 8, /* Learning and relaying frames. */
    OFPUTIL_PS_STP_BLOCK   = 3 << 8, /* Not part of spanning tree. */
    OFPUTIL_PS_STP_MASK    = 3 << 8  /* Bit mask for OFPPS10_STP_* values. */
};

/* Abstract ofp10_phy_port or ofp11_port. */
struct ofputil_phy_port {
    uint16_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    char name[OFP_MAX_PORT_NAME_LEN];
    enum ofputil_port_config config;
    enum ofputil_port_state state;

    /* NETDEV_F_* feature bitmasks. */
    enum netdev_features curr;       /* Current features. */
    enum netdev_features advertised; /* Features advertised by the port. */
    enum netdev_features supported;  /* Features supported by the port. */
    enum netdev_features peer;       /* Features advertised by peer. */

    /* Speed. */
    uint32_t curr_speed;        /* Current speed, in kbps. */
    uint32_t max_speed;         /* Maximum supported speed, in kbps. */
};

enum ofputil_capabilities {
    /* OpenFlow 1.0 and 1.1 share these values for these capabilities. */
    OFPUTIL_C_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPUTIL_C_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPUTIL_C_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPUTIL_C_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPUTIL_C_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
    OFPUTIL_C_ARP_MATCH_IP   = 1 << 7,  /* Match IP addresses in ARP pkts. */

    /* OpenFlow 1.0 only. */
    OFPUTIL_C_STP            = 1 << 3,  /* 802.1d spanning tree. */

    /* OpenFlow 1.1 only. */
    OFPUTIL_C_GROUP_STATS    = 1 << 4,  /* Group statistics. */
};

enum ofputil_action_bitmap {
    OFPUTIL_A_OUTPUT         = 1 << 0,
    OFPUTIL_A_SET_VLAN_VID   = 1 << 1,
    OFPUTIL_A_SET_VLAN_PCP   = 1 << 2,
    OFPUTIL_A_STRIP_VLAN     = 1 << 3,
    OFPUTIL_A_SET_DL_SRC     = 1 << 4,
    OFPUTIL_A_SET_DL_DST     = 1 << 5,
    OFPUTIL_A_SET_NW_SRC     = 1 << 6,
    OFPUTIL_A_SET_NW_DST     = 1 << 7,
    OFPUTIL_A_SET_NW_ECN     = 1 << 8,
    OFPUTIL_A_SET_NW_TOS     = 1 << 9,
    OFPUTIL_A_SET_TP_SRC     = 1 << 10,
    OFPUTIL_A_SET_TP_DST     = 1 << 11,
    OFPUTIL_A_ENQUEUE        = 1 << 12,
    OFPUTIL_A_COPY_TTL_OUT   = 1 << 13,
    OFPUTIL_A_COPY_TTL_IN    = 1 << 14,
    OFPUTIL_A_SET_MPLS_LABEL = 1 << 15,
    OFPUTIL_A_SET_MPLS_TC    = 1 << 16,
    OFPUTIL_A_SET_MPLS_TTL   = 1 << 17,
    OFPUTIL_A_DEC_MPLS_TTL   = 1 << 18,
    OFPUTIL_A_PUSH_VLAN      = 1 << 19,
    OFPUTIL_A_POP_VLAN       = 1 << 20,
    OFPUTIL_A_PUSH_MPLS      = 1 << 21,
    OFPUTIL_A_POP_MPLS       = 1 << 22,
    OFPUTIL_A_SET_QUEUE      = 1 << 23,
    OFPUTIL_A_GROUP          = 1 << 24,
    OFPUTIL_A_SET_NW_TTL     = 1 << 25,
    OFPUTIL_A_DEC_NW_TTL     = 1 << 26,
};

/* Abstract ofp_switch_features. */
struct ofputil_switch_features {
    uint64_t datapath_id;       /* Datapath unique ID. */
    uint32_t n_buffers;         /* Max packets buffered at once. */
    uint8_t n_tables;           /* Number of tables supported by datapath. */
    enum ofputil_capabilities capabilities;
    enum ofputil_action_bitmap actions;
};

enum ofperr ofputil_decode_switch_features(const struct ofp_switch_features *,
                                           struct ofputil_switch_features *,
                                           struct ofpbuf *);

struct ofpbuf *ofputil_encode_switch_features(
    const struct ofputil_switch_features *, enum ofputil_protocol,
    ovs_be32 xid);
void ofputil_put_switch_features_port(const struct ofputil_phy_port *,
                                      struct ofpbuf *);
bool ofputil_switch_features_ports_trunc(struct ofpbuf *b);

/* phy_port helper functions. */
int ofputil_pull_phy_port(uint8_t ofp_version, struct ofpbuf *,
                          struct ofputil_phy_port *);
size_t ofputil_count_phy_ports(uint8_t ofp_version, struct ofpbuf *);

/* Abstract ofp_port_status. */
struct ofputil_port_status {
    enum ofp_port_reason reason;
    struct ofputil_phy_port desc;
};

enum ofperr ofputil_decode_port_status(const struct ofp_port_status *,
                                       struct ofputil_port_status *);
struct ofpbuf *ofputil_encode_port_status(const struct ofputil_port_status *,
                                          enum ofputil_protocol);

/* Abstract ofp_port_mod. */
struct ofputil_port_mod {
    uint16_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    enum ofputil_port_config config;
    enum ofputil_port_config mask;
    enum netdev_features advertise;
};

enum ofperr ofputil_decode_port_mod(const struct ofp_header *,
                                    struct ofputil_port_mod *);
struct ofpbuf *ofputil_encode_port_mod(const struct ofputil_port_mod *,
                                       enum ofputil_protocol);

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
void ofputil_postappend_stats_reply(size_t start_ofs, struct list *);

void ofputil_append_port_desc_stats_reply(uint8_t ofp_version,
                                          const struct ofputil_phy_port *pp,
                                          struct list *replies);

const void *ofputil_stats_body(const struct ofp_header *);
size_t ofputil_stats_body_len(const struct ofp_header *);

const void *ofputil_nxstats_body(const struct ofp_header *);
size_t ofputil_nxstats_body_len(const struct ofp_header *);

/*  */
struct ofpbuf *make_echo_request(void);
struct ofpbuf *make_echo_reply(const struct ofp_header *rq);

struct ofpbuf *ofputil_encode_barrier_request(void);

const char *ofputil_frag_handling_to_string(enum ofp_config_flags);
bool ofputil_frag_handling_from_string(const char *, enum ofp_config_flags *);


/* Actions. */

/* The type of an action.
 *
 * For each implemented OFPAT10_* and NXAST_* action type, there is a
 * corresponding constant prefixed with OFPUTIL_, e.g.:
 *
 * OFPUTIL_OFPAT10_OUTPUT
 * OFPUTIL_OFPAT10_SET_VLAN_VID
 * OFPUTIL_OFPAT10_SET_VLAN_PCP
 * OFPUTIL_OFPAT10_STRIP_VLAN
 * OFPUTIL_OFPAT10_SET_DL_SRC
 * OFPUTIL_OFPAT10_SET_DL_DST
 * OFPUTIL_OFPAT10_SET_NW_SRC
 * OFPUTIL_OFPAT10_SET_NW_DST
 * OFPUTIL_OFPAT10_SET_NW_TOS
 * OFPUTIL_OFPAT10_SET_TP_SRC
 * OFPUTIL_OFPAT10_SET_TP_DST
 * OFPUTIL_OFPAT10_ENQUEUE
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
enum OVS_PACKED_ENUM ofputil_action_code {
    OFPUTIL_ACTION_INVALID,
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)             OFPUTIL_##ENUM,
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) OFPUTIL_##ENUM,
#include "ofp-util.def"
};

/* The number of values of "enum ofputil_action_code". */
enum {
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)             + 1
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) + 1
    OFPUTIL_N_ACTIONS = 1
#include "ofp-util.def"
};

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
#define OFPAT10_ACTION(ENUM, STRUCT, NAME)              \
    void ofputil_init_##ENUM(struct STRUCT *);          \
    struct STRUCT *ofputil_put_##ENUM(struct ofpbuf *);
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)    \
    void ofputil_init_##ENUM(struct STRUCT *);          \
    struct STRUCT *ofputil_put_##ENUM(struct ofpbuf *);
#include "ofp-util.def"

#define OFP_ACTION_ALIGN 8      /* Alignment of ofp_actions. */

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
