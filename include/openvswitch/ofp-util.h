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

#ifndef OPENVSWITCH_OFP_UTIL_H
#define OPENVSWITCH_OFP_UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openvswitch/flow.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/netdev.h"
#include "openflow/netronome-ext.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/types.h"
#include "openvswitch/type-props.h"
#include "openvswitch/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofpbuf;
union ofp_action;
struct ofpact_set_field;
struct vl_mff_map;

/* Mapping between port numbers and names. */
struct ofputil_port_map {
    struct hmap by_name;
    struct hmap by_number;
};

#define OFPUTIL_PORT_MAP_INITIALIZER(MAP)  \
    { HMAP_INITIALIZER(&(MAP)->by_name), HMAP_INITIALIZER(&(MAP)->by_number) }

void ofputil_port_map_init(struct ofputil_port_map *);
const char *ofputil_port_map_get_name(const struct ofputil_port_map *,
                                      ofp_port_t);
ofp_port_t ofputil_port_map_get_number(const struct ofputil_port_map *,
                                      const char *name);
void ofputil_port_map_put(struct ofputil_port_map *,
                          ofp_port_t, const char *name);
void ofputil_port_map_destroy(struct ofputil_port_map *);

/* Port numbers. */
enum ofperr ofputil_port_from_ofp11(ovs_be32 ofp11_port,
                                    ofp_port_t *ofp10_port);
ovs_be32 ofputil_port_to_ofp11(ofp_port_t ofp10_port);

bool ofputil_port_from_string(const char *, const struct ofputil_port_map *,
                              ofp_port_t *portp);
const char *ofputil_port_get_reserved_name(ofp_port_t);
void ofputil_format_port(ofp_port_t port, const struct ofputil_port_map *,
                         struct ds *);
void ofputil_port_to_string(ofp_port_t, const struct ofputil_port_map *,
                            char *namebuf, size_t bufsize);

/* Group numbers. */
enum { MAX_GROUP_NAME_LEN = INT_STRLEN(uint32_t) };
bool ofputil_group_from_string(const char *, uint32_t *group_id);
void ofputil_format_group(uint32_t group_id, struct ds *);
void ofputil_group_to_string(uint32_t group_id,
                             char namebuf[MAX_GROUP_NAME_LEN + 1],
                             size_t bufsize);

/* Converting OFPFW10_NW_SRC_MASK and OFPFW10_NW_DST_MASK wildcard bit counts
 * to and from IP bitmasks. */
ovs_be32 ofputil_wcbits_to_netmask(int wcbits);
int ofputil_netmask_to_wcbits(ovs_be32 netmask);

/* Protocols.
 *
 * A "protocol" is an OpenFlow version plus, for some OpenFlow versions,
 * a bit extra about the flow match format in use.
 *
 * These are arranged from most portable to least portable, or alternatively
 * from least powerful to most powerful.  Protocols earlier on the list are
 * more likely to be understood for the purpose of making requests, but
 * protocol later on the list are more likely to accurately describe a flow
 * within a switch.
 *
 * On any given OpenFlow connection, a single protocol is in effect at any
 * given time.  These values use separate bits only because that makes it easy
 * to test whether a particular protocol is within a given set of protocols and
 * to implement set union and intersection.
 */
enum ofputil_protocol {
    /* OpenFlow 1.0 protocols.
     *
     * The "STD" protocols use the standard OpenFlow 1.0 flow format.
     * The "NXM" protocols use the Nicira Extensible Match (NXM) flow format.
     *
     * The protocols with "TID" mean that the nx_flow_mod_table_id Nicira
     * extension has been enabled.  The other protocols have it disabled.
     */
#define OFPUTIL_P_NONE 0
    OFPUTIL_P_OF10_STD     = 1 << 0,
    OFPUTIL_P_OF10_STD_TID = 1 << 1,
    OFPUTIL_P_OF10_NXM     = 1 << 2,
    OFPUTIL_P_OF10_NXM_TID = 1 << 3,
#define OFPUTIL_P_OF10_STD_ANY (OFPUTIL_P_OF10_STD | OFPUTIL_P_OF10_STD_TID)
#define OFPUTIL_P_OF10_NXM_ANY (OFPUTIL_P_OF10_NXM | OFPUTIL_P_OF10_NXM_TID)
#define OFPUTIL_P_OF10_ANY (OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY)

    /* OpenFlow 1.1 protocol.
     *
     * We only support the standard OpenFlow 1.1 flow format.
     *
     * OpenFlow 1.1 always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF11_STD     = 1 << 4,

    /* OpenFlow 1.2+ protocols (only one variant each).
     *
     * These use the standard OpenFlow Extensible Match (OXM) flow format.
     *
     * OpenFlow 1.2+ always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF12_OXM      = 1 << 5,
    OFPUTIL_P_OF13_OXM      = 1 << 6,
    OFPUTIL_P_OF14_OXM      = 1 << 7,
    OFPUTIL_P_OF15_OXM      = 1 << 8,
    OFPUTIL_P_OF16_OXM      = 1 << 9,
#define OFPUTIL_P_ANY_OXM (OFPUTIL_P_OF12_OXM | \
                           OFPUTIL_P_OF13_OXM | \
                           OFPUTIL_P_OF14_OXM | \
                           OFPUTIL_P_OF15_OXM | \
                           OFPUTIL_P_OF16_OXM)

#define OFPUTIL_P_NXM_OF11_UP (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_OF11_STD | \
                               OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_NXM_OXM_ANY (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF11_UP (OFPUTIL_P_OF11_STD | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF12_UP (OFPUTIL_P_OF12_OXM | OFPUTIL_P_OF13_UP)
#define OFPUTIL_P_OF13_UP (OFPUTIL_P_OF13_OXM | OFPUTIL_P_OF14_UP)
#define OFPUTIL_P_OF14_UP (OFPUTIL_P_OF14_OXM | OFPUTIL_P_OF15_UP)
#define OFPUTIL_P_OF15_UP (OFPUTIL_P_OF15_OXM | OFPUTIL_P_OF16_UP)
#define OFPUTIL_P_OF16_UP OFPUTIL_P_OF16_OXM

    /* All protocols. */
#define OFPUTIL_P_ANY ((1 << 10) - 1)

    /* Protocols in which a specific table may be specified in flow_mods. */
#define OFPUTIL_P_TID (OFPUTIL_P_OF10_STD_TID | \
                       OFPUTIL_P_OF10_NXM_TID | \
                       OFPUTIL_P_OF11_STD |     \
                       OFPUTIL_P_ANY_OXM)
};

/* Protocols to use for flow dumps, from most to least preferred. */
extern enum ofputil_protocol ofputil_flow_dump_protocols[];
extern size_t ofputil_n_flow_dump_protocols;

enum ofputil_protocol ofputil_protocol_from_ofp_version(enum ofp_version);
enum ofputil_protocol ofputil_protocols_from_ofp_version(enum ofp_version);
enum ofp_version ofputil_protocol_to_ofp_version(enum ofputil_protocol);

bool ofputil_protocol_is_valid(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocol_set_tid(enum ofputil_protocol,
                                               bool enable);
enum ofputil_protocol ofputil_protocol_to_base(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocol_set_base(
    enum ofputil_protocol cur, enum ofputil_protocol new_base);

const char *ofputil_protocol_to_string(enum ofputil_protocol);
char *ofputil_protocols_to_string(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocols_from_string(const char *);

void ofputil_format_version(struct ds *, enum ofp_version);
void ofputil_format_version_name(struct ds *, enum ofp_version);

/* A bitmap of version numbers
 *
 * Bit offsets correspond to ofp_version numbers which in turn correspond to
 * wire-protocol numbers for OpenFlow versions, e.g. (1u << OFP11_VERSION)
 * is the mask for OpenFlow 1.1.  If the bit for a version is set then it is
 * allowed, otherwise it is disallowed. */

void ofputil_format_version_bitmap(struct ds *msg, uint32_t bitmap);
void ofputil_format_version_bitmap_names(struct ds *msg, uint32_t bitmap);

enum ofp_version ofputil_version_from_string(const char *s);

uint32_t ofputil_protocols_to_version_bitmap(enum ofputil_protocol);
enum ofputil_protocol ofputil_protocols_from_version_bitmap(uint32_t bitmap);

/* Bitmaps of OpenFlow versions that Open vSwitch supports, and that it enables
 * by default.  When Open vSwitch has experimental or incomplete support for
 * newer versions of OpenFlow, those versions should not be supported by
 * default and thus should be omitted from the latter bitmap. */
#define OFPUTIL_SUPPORTED_VERSIONS ((1u << OFP10_VERSION) | \
                                    (1u << OFP11_VERSION) | \
                                    (1u << OFP12_VERSION) | \
                                    (1u << OFP13_VERSION) | \
                                    (1u << OFP14_VERSION))
#define OFPUTIL_DEFAULT_VERSIONS OFPUTIL_SUPPORTED_VERSIONS

enum ofputil_protocol ofputil_protocols_from_string(const char *s);

const char *ofputil_version_to_string(enum ofp_version ofp_version);
uint32_t ofputil_versions_from_string(const char *s);
uint32_t ofputil_versions_from_strings(char ** const s, size_t count);

bool ofputil_decode_hello(const struct ofp_header *,
                          uint32_t *allowed_versions);
struct ofpbuf *ofputil_encode_hello(uint32_t version_bitmap);

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
void ofputil_match_from_ofp10_match(const struct ofp10_match *,
                                    struct match *);
void ofputil_normalize_match(struct match *);
void ofputil_normalize_match_quiet(struct match *);
void ofputil_match_to_ofp10_match(const struct match *, struct ofp10_match *);

/* Work with ofp11_match. */
enum ofperr ofputil_pull_ofp11_match(struct ofpbuf *, const struct tun_table *,
                                     const struct vl_mff_map *, struct match *,
                                     uint16_t *padded_match_len);
enum ofperr ofputil_match_from_ofp11_match(const struct ofp11_match *,
                                           struct match *);
int ofputil_put_ofp11_match(struct ofpbuf *, const struct match *,
                            enum ofputil_protocol);
void ofputil_match_to_ofp11_match(const struct match *, struct ofp11_match *);
int ofputil_match_typical_len(enum ofputil_protocol);

/* dl_type translation between OpenFlow and 'struct flow' format. */
ovs_be16 ofputil_dl_type_to_openflow(ovs_be16 flow_dl_type);
ovs_be16 ofputil_dl_type_from_openflow(ovs_be16 ofp_dl_type);

/* PACKET_IN. */
bool ofputil_packet_in_format_is_valid(enum nx_packet_in_format);
int ofputil_packet_in_format_from_string(const char *);
const char *ofputil_packet_in_format_to_string(enum nx_packet_in_format);
struct ofpbuf *ofputil_make_set_packet_in_format(enum ofp_version,
                                                 enum nx_packet_in_format);

/* NXT_FLOW_MOD_TABLE_ID extension. */
struct ofpbuf *ofputil_make_flow_mod_table_id(bool flow_mod_table_id);

/* Protocol-independent flow_mod flags. */
enum ofputil_flow_mod_flags {
    /* Flags that are maintained with a flow as part of its state.
     *
     * (OFPUTIL_FF_EMERG would be here too, if OVS supported it.) */
    OFPUTIL_FF_SEND_FLOW_REM = 1 << 0, /* All versions. */
    OFPUTIL_FF_NO_PKT_COUNTS = 1 << 1, /* OpenFlow 1.3+. */
    OFPUTIL_FF_NO_BYT_COUNTS = 1 << 2, /* OpenFlow 1.3+. */

    /* These flags primarily affects flow_mod behavior.  They are not
     * particularly useful as part of flow state.  We include them in flow
     * state only because OpenFlow implies that they should be. */
    OFPUTIL_FF_CHECK_OVERLAP = 1 << 3, /* All versions. */
    OFPUTIL_FF_RESET_COUNTS  = 1 << 4, /* OpenFlow 1.2+. */

    /* Not supported by OVS. */
    OFPUTIL_FF_EMERG         = 1 << 5, /* OpenFlow 1.0 only. */

    /* The set of flags maintained as part of a flow table entry. */
#define OFPUTIL_FF_STATE (OFPUTIL_FF_SEND_FLOW_REM      \
                          | OFPUTIL_FF_NO_PKT_COUNTS    \
                          | OFPUTIL_FF_NO_BYT_COUNTS    \
                          | OFPUTIL_FF_CHECK_OVERLAP    \
                          | OFPUTIL_FF_RESET_COUNTS)

    /* Flags that are only set by OVS for its internal use.  Cannot be set via
     * OpenFlow. */
    OFPUTIL_FF_HIDDEN_FIELDS = 1 << 6, /* Allow hidden match fields to be
                                          set or modified. */
    OFPUTIL_FF_NO_READONLY   = 1 << 7, /* Allow rules within read only tables
                                          to be modified */
};

/* Protocol-independent flow_mod.
 *
 * The handling of cookies across multiple versions of OpenFlow is a bit
 * confusing.  See the topics/design doc for the details. */
struct ofputil_flow_mod {
    struct ovs_list list_node; /* For queuing flow_mods. */

    struct match match;
    int priority;

    /* Cookie matching.  The flow_mod affects only flows that have cookies that
     * bitwise match 'cookie' bits in positions where 'cookie_mask has 1-bits.
     *
     * 'cookie_mask' should be zero for OFPFC_ADD flow_mods. */
    ovs_be64 cookie;         /* Cookie bits to match. */
    ovs_be64 cookie_mask;    /* 1-bit in each 'cookie' bit to match. */

    /* Cookie changes.
     *
     * OFPFC_ADD uses 'new_cookie' as the new flow's cookie.  'new_cookie'
     * should not be UINT64_MAX.
     *
     * OFPFC_MODIFY and OFPFC_MODIFY_STRICT have two cases:
     *
     *   - If one or more matching flows exist and 'modify_cookie' is true,
     *     then the flow_mod changes the existing flows' cookies to
     *     'new_cookie'.  'new_cookie' should not be UINT64_MAX.
     *
     *   - If no matching flow exists, 'new_cookie' is not UINT64_MAX, and
     *     'cookie_mask' is 0, then the flow_mod adds a new flow with
     *     'new_cookie' as its cookie.
     */
    ovs_be64 new_cookie;     /* New cookie to install or UINT64_MAX. */
    bool modify_cookie;      /* Set cookie of existing flow to 'new_cookie'? */

    uint8_t table_id;
    uint16_t command;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t buffer_id;
    ofp_port_t out_port;
    uint32_t out_group;
    enum ofputil_flow_mod_flags flags;
    uint16_t importance;     /* Eviction precedence. */
    struct ofpact *ofpacts;  /* Series of "struct ofpact"s. */
    size_t ofpacts_len;      /* Length of ofpacts, in bytes. */
    uint64_t ofpacts_tlv_bitmap; /* 1-bit for each present TLV in 'ofpacts'. */
};

enum ofperr ofputil_decode_flow_mod(struct ofputil_flow_mod *,
                                    const struct ofp_header *,
                                    enum ofputil_protocol,
                                    const struct tun_table *,
                                    const struct vl_mff_map *,
                                    struct ofpbuf *ofpacts,
                                    ofp_port_t max_port,
                                    uint8_t max_table);
struct ofpbuf *ofputil_encode_flow_mod(const struct ofputil_flow_mod *,
                                       enum ofputil_protocol);

/* Flow stats or aggregate stats request, independent of protocol. */
struct ofputil_flow_stats_request {
    bool aggregate;             /* Aggregate results? */
    struct match match;
    ovs_be64 cookie;
    ovs_be64 cookie_mask;
    ofp_port_t out_port;
    uint32_t out_group;
    uint8_t table_id;
};

enum ofperr ofputil_decode_flow_stats_request(
    struct ofputil_flow_stats_request *, const struct ofp_header *,
    const struct tun_table *, const struct vl_mff_map *);
struct ofpbuf *ofputil_encode_flow_stats_request(
    const struct ofputil_flow_stats_request *, enum ofputil_protocol);

/* Flow stats reply, independent of protocol. */
struct ofputil_flow_stats {
    struct match match;
    ovs_be64 cookie;
    uint8_t table_id;
    uint16_t priority;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    int idle_age;               /* Seconds since last packet, -1 if unknown. */
    int hard_age;               /* Seconds since last change, -1 if unknown. */
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    const struct ofpact *ofpacts;
    size_t ofpacts_len;
    enum ofputil_flow_mod_flags flags;
    uint16_t importance;        /* Eviction precedence. */
};

int ofputil_decode_flow_stats_reply(struct ofputil_flow_stats *,
                                    struct ofpbuf *msg,
                                    bool flow_age_extension,
                                    struct ofpbuf *ofpacts);
void ofputil_append_flow_stats_reply(const struct ofputil_flow_stats *,
                                     struct ovs_list *replies,
                                     const struct tun_table *);

/* Aggregate stats reply, independent of protocol. */
struct ofputil_aggregate_stats {
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t flow_count;
};

struct ofpbuf *ofputil_encode_aggregate_stats_reply(
    const struct ofputil_aggregate_stats *stats,
    const struct ofp_header *request);
enum ofperr ofputil_decode_aggregate_stats_reply(
    struct ofputil_aggregate_stats *,
    const struct ofp_header *reply);

/* Flow removed message, independent of protocol. */
struct ofputil_flow_removed {
    struct match match;
    ovs_be64 cookie;
    uint16_t priority;
    uint8_t reason;             /* One of OFPRR_*. */
    uint8_t table_id;           /* 255 if message didn't include table ID. */
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
};

enum ofperr ofputil_decode_flow_removed(struct ofputil_flow_removed *,
                                        const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_removed(const struct ofputil_flow_removed *,
                                           enum ofputil_protocol);

/* Abstract packet-in message.
 *
 * This omits the 'total_len' and 'buffer_id' fields, which we handle
 * differently for encoding and decoding.*/
struct ofputil_packet_in {
    /* Packet data and metadata.
     *
     * On encoding, the full packet should be supplied, but depending on its
     * other parameters ofputil_encode_packet_in() might send only the first
     * part of the packet.
     *
     * On decoding, the 'len' bytes in 'packet' might only be the first part of
     * the original packet.  ofputil_decode_packet_in() reports the full
     * original length of the packet using its 'total_len' output parameter. */
    void *packet;               /* The packet. */
    size_t packet_len;          /* Length of 'packet' in bytes. */

    /* Input port and other metadata for packet. */
    struct match flow_metadata;

    /* Reason that the packet-in is being sent. */
    enum ofp_packet_in_reason reason;    /* One of OFPR_*. */

    /* Information about the OpenFlow flow that triggered the packet-in.
     *
     * A packet-in triggered by a flow table miss has no associated flow.  In
     * that case, 'cookie' is UINT64_MAX. */
    uint8_t table_id;                    /* OpenFlow table ID. */
    ovs_be64 cookie;                     /* Flow's cookie. */

    /* Arbitrary user-provided data. */
    uint8_t *userdata;
    size_t userdata_len;
};

void ofputil_packet_in_destroy(struct ofputil_packet_in *);

enum ofperr ofputil_decode_packet_in(const struct ofp_header *, bool loose,
                                     const struct tun_table *,
                                     const struct vl_mff_map *,
                                     struct ofputil_packet_in *,
                                     size_t *total_len, uint32_t *buffer_id,
                                     struct ofpbuf *continuation);

struct ofpbuf *ofputil_encode_resume(const struct ofputil_packet_in *pin,
                                     const struct ofpbuf *continuation,
                                     enum ofputil_protocol);

enum { OFPUTIL_PACKET_IN_REASON_BUFSIZE = INT_STRLEN(int) + 1 };
const char *ofputil_packet_in_reason_to_string(enum ofp_packet_in_reason,
                                               char *reasonbuf,
                                               size_t bufsize);
bool ofputil_packet_in_reason_from_string(const char *,
                                          enum ofp_packet_in_reason *);

/* A packet-in message, including continuation data.  The format of
 * continuation data is subject to change and thus it is supposed to be opaque
 * to any process other than ovs-vswitchd.  Therefore, only ovs-vswitchd should
 * use ofputil_packet_in_private and the functions that operate on it. */
struct ofputil_packet_in_private {
    struct ofputil_packet_in base;

    /* NXCPT_BRIDGE. */
    struct uuid bridge;

    /* NXCPT_STACK. */
    uint8_t *stack;
    size_t stack_size;

    /* NXCPT_MIRRORS. */
    uint32_t mirrors;

    /* NXCPT_CONNTRACKED. */
    bool conntracked;

    /* NXCPT_ACTIONS. */
    struct ofpact *actions;
    size_t actions_len;

    /* NXCPT_ACTION_SET. */
    struct ofpact *action_set;
    size_t action_set_len;
};

struct ofpbuf *ofputil_encode_packet_in_private(
    const struct ofputil_packet_in_private *,
    enum ofputil_protocol protocol,
    enum nx_packet_in_format);

enum ofperr ofputil_decode_packet_in_private(
    const struct ofp_header *, bool loose,
    const struct tun_table *,
    const struct vl_mff_map *,
    struct ofputil_packet_in_private *,
    size_t *total_len, uint32_t *buffer_id);

void ofputil_packet_in_private_destroy(struct ofputil_packet_in_private *);

/* Abstract packet-out message.
 *
 * ofputil_decode_packet_out() will ensure that 'in_port' is a physical port
 * (OFPP_MAX or less) or one of OFPP_LOCAL, OFPP_NONE, or OFPP_CONTROLLER. */
struct ofputil_packet_out {
    const void *packet;         /* Packet data, if buffer_id == UINT32_MAX. */
    size_t packet_len;          /* Length of packet data in bytes. */
    uint32_t buffer_id;         /* Buffer id or UINT32_MAX if no buffer. */
    struct match flow_metadata; /* Packet's input port and other metadata. */
    struct ofpact *ofpacts;     /* Actions. */
    size_t ofpacts_len;         /* Size of ofpacts in bytes. */
};

enum ofperr ofputil_decode_packet_out(struct ofputil_packet_out *,
                                      const struct ofp_header *,
                                      const struct tun_table *,
                                      struct ofpbuf *ofpacts);
struct ofpbuf *ofputil_encode_packet_out(const struct ofputil_packet_out *,
                                         enum ofputil_protocol protocol);

enum ofputil_frag_handling {
    OFPUTIL_FRAG_NORMAL = OFPC_FRAG_NORMAL,    /* No special handling. */
    OFPUTIL_FRAG_DROP = OFPC_FRAG_DROP,        /* Drop fragments. */
    OFPUTIL_FRAG_REASM = OFPC_FRAG_REASM,      /* Reassemble (if supported). */
    OFPUTIL_FRAG_NX_MATCH = OFPC_FRAG_NX_MATCH /* Match on frag bits. */
};

const char *ofputil_frag_handling_to_string(enum ofputil_frag_handling);
bool ofputil_frag_handling_from_string(const char *,
                                       enum ofputil_frag_handling *);

/* Abstract struct ofp_switch_config. */
struct ofputil_switch_config {
    /* Fragment handling. */
    enum ofputil_frag_handling frag;

    /* 0: Do not send packet to controller when decrementing invalid IP TTL.
     * 1: Do send packet to controller when decrementing invalid IP TTL.
     * -1: Unspecified (only OpenFlow 1.1 and 1.2 support this setting. */
    int invalid_ttl_to_controller;

    /* Maximum bytes of packet to send to controller on miss. */
    uint16_t miss_send_len;
};

void ofputil_decode_get_config_reply(const struct ofp_header *,
                                     struct ofputil_switch_config *);
struct ofpbuf *ofputil_encode_get_config_reply(
    const struct ofp_header *request, const struct ofputil_switch_config *);

enum ofperr ofputil_decode_set_config(const struct ofp_header *,
                                      struct ofputil_switch_config *);
struct ofpbuf *ofputil_encode_set_config(
    const struct ofputil_switch_config *, enum ofp_version);

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

/* Abstract ofp10_phy_port, ofp11_port, ofp14_port, or ofp16_port. */
struct ofputil_phy_port {
    ofp_port_t port_no;

    /* Hardware addresses.
     *
     * Most hardware has a normal 48-bit Ethernet address, in hw_addr.
     * Some hardware might have a 64-bit address in hw_addr64.
     * All-bits-0 indicates that a given address is not present. */
    struct eth_addr hw_addr;
    struct eth_addr64 hw_addr64;

    char name[OFP16_MAX_PORT_NAME_LEN]; /* 64 bytes in OF1.6+, 16 otherwise. */
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
    /* All OpenFlow versions share these capability values. */
    OFPUTIL_C_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPUTIL_C_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPUTIL_C_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPUTIL_C_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPUTIL_C_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */

    /* OpenFlow 1.0 and 1.1 share this capability. */
    OFPUTIL_C_ARP_MATCH_IP   = 1 << 7,  /* Match IP addresses in ARP pkts. */

    /* OpenFlow 1.0 only. */
    OFPUTIL_C_STP            = 1 << 3,  /* 802.1d spanning tree. */

    /* OpenFlow 1.1+ only.  Note that this bit value does not match the one
     * in the OpenFlow message. */
    OFPUTIL_C_GROUP_STATS    = 1 << 4,  /* Group statistics. */

    /* OpenFlow 1.2+ only. */
    OFPUTIL_C_PORT_BLOCKED   = 1 << 8,  /* Switch will block looping ports */

    /* OpenFlow 1.4+ only. */
    OFPUTIL_C_BUNDLES         = 1 << 9,  /* Switch supports bundles. */
    OFPUTIL_C_FLOW_MONITORING = 1 << 10, /* Switch supports flow monitoring. */
};

/* Abstract ofp_switch_features. */
struct ofputil_switch_features {
    uint64_t datapath_id;       /* Datapath unique ID. */
    uint32_t n_buffers;         /* Max packets buffered at once. */
    uint8_t n_tables;           /* Number of tables supported by datapath. */
    uint8_t auxiliary_id;       /* Identify auxiliary connections */
    enum ofputil_capabilities capabilities;
    uint64_t ofpacts;           /* Bitmap of OFPACT_* bits. */
};

enum ofperr ofputil_pull_switch_features(struct ofpbuf *,
                                         struct ofputil_switch_features *);

struct ofpbuf *ofputil_encode_switch_features(
    const struct ofputil_switch_features *, enum ofputil_protocol,
    ovs_be32 xid);
void ofputil_put_switch_features_port(const struct ofputil_phy_port *,
                                      struct ofpbuf *);
bool ofputil_switch_features_has_ports(struct ofpbuf *b);

/* phy_port helper functions. */
int ofputil_pull_phy_port(enum ofp_version ofp_version, struct ofpbuf *,
                          struct ofputil_phy_port *);

/* Abstract ofp_port_status. */
struct ofputil_port_status {
    enum ofp_port_reason reason;
    struct ofputil_phy_port desc;
};

enum ofperr ofputil_decode_port_status(const struct ofp_header *,
                                       struct ofputil_port_status *);
struct ofpbuf *ofputil_encode_port_status(const struct ofputil_port_status *,
                                          enum ofputil_protocol);

/* Abstract ofp_port_mod. */
struct ofputil_port_mod {
    ofp_port_t port_no;
    struct eth_addr hw_addr;
    struct eth_addr64 hw_addr64;
    enum ofputil_port_config config;
    enum ofputil_port_config mask;
    enum netdev_features advertise;
};

enum ofperr ofputil_decode_port_mod(const struct ofp_header *,
                                    struct ofputil_port_mod *, bool loose);
struct ofpbuf *ofputil_encode_port_mod(const struct ofputil_port_mod *,
                                       enum ofputil_protocol);

/* Abstract version of OFPTC11_TABLE_MISS_*.
 *
 * OpenFlow 1.0 always sends packets that miss to the next flow table, or to
 * the controller if they miss in the last flow table.
 *
 * OpenFlow 1.1 and 1.2 can configure table miss behavior via a "table-mod"
 * that specifies "send to controller", "miss", or "drop".
 *
 * OpenFlow 1.3 and later never sends packets that miss to the controller.
 */
enum ofputil_table_miss {
    /* Protocol-specific default behavior.  On OpenFlow 1.0 through 1.2
     * connections, the packet is sent to the controller, and on OpenFlow 1.3
     * and later connections, the packet is dropped.
     *
     * This is also used as a result of decoding OpenFlow 1.3+ "config" values
     * in table-mods, to indicate that no table-miss was specified. */
    OFPUTIL_TABLE_MISS_DEFAULT,    /* Protocol default behavior. */

    /* These constants have the same meanings as those in OpenFlow with the
     * same names. */
    OFPUTIL_TABLE_MISS_CONTROLLER, /* Send to controller. */
    OFPUTIL_TABLE_MISS_CONTINUE,   /* Go to next table. */
    OFPUTIL_TABLE_MISS_DROP,       /* Drop the packet. */
};

/* Abstract version of OFPTC14_EVICTION.
 *
 * OpenFlow 1.0 through 1.3 don't know anything about eviction, so decoding a
 * message for one of these protocols always yields
 * OFPUTIL_TABLE_EVICTION_DEFAULT. */
enum ofputil_table_eviction {
    OFPUTIL_TABLE_EVICTION_DEFAULT, /* No value. */
    OFPUTIL_TABLE_EVICTION_ON,      /* Enable eviction. */
    OFPUTIL_TABLE_EVICTION_OFF      /* Disable eviction. */
};

/* Abstract version of OFPTC14_VACANCY_EVENTS.
 *
 * OpenFlow 1.0 through 1.3 don't know anything about vacancy events, so
 * decoding a message for one of these protocols always yields
 * OFPUTIL_TABLE_VACANCY_DEFAULT. */
enum ofputil_table_vacancy {
    OFPUTIL_TABLE_VACANCY_DEFAULT, /* No value. */
    OFPUTIL_TABLE_VACANCY_ON,      /* Enable vacancy events. */
    OFPUTIL_TABLE_VACANCY_OFF      /* Disable vacancy events. */
};

/* Abstract version of OFPTMPT_VACANCY.
 *
 * Openflow 1.4+ defines vacancy events.
 * The fields vacancy_down and vacancy_up are the threshold for generating
 * vacancy events that should be configured on the flow table, expressed as
 * a percent.
 * The vacancy field is only used when this property in included in a
 * OFPMP_TABLE_DESC multipart reply or a OFPT_TABLE_STATUS message and
 * represent the current vacancy of the table, expressed as a percent. In
 * OFP_TABLE_MOD requests, this field must be set to 0 */
struct ofputil_table_mod_prop_vacancy {
    uint8_t vacancy_down;    /* Vacancy threshold when space decreases (%). */
    uint8_t vacancy_up;      /* Vacancy threshold when space increases (%). */
    uint8_t vacancy;         /* Current vacancy (%). */
};

/* Abstract ofp_table_mod. */
struct ofputil_table_mod {
    uint8_t table_id;         /* ID of the table, 0xff indicates all tables. */

    /* OpenFlow 1.1 and 1.2 only.  For other versions, ignored on encoding,
     * decoded to OFPUTIL_TABLE_MISS_DEFAULT. */
    enum ofputil_table_miss miss;

    /* OpenFlow 1.4+ only.  For other versions, ignored on encoding, decoded to
     * OFPUTIL_TABLE_EVICTION_DEFAULT. */
    enum ofputil_table_eviction eviction;

    /* OpenFlow 1.4+ only and optional even there; UINT32_MAX indicates
     * absence.  For other versions, ignored on encoding, decoded to
     * UINT32_MAX.*/
    uint32_t eviction_flags;    /* OFPTMPEF14_*. */

    /* OpenFlow 1.4+ only. For other versions, ignored on encoding, decoded to
     * OFPUTIL_TABLE_VACANCY_DEFAULT. */
    enum ofputil_table_vacancy vacancy;

    /* Openflow 1.4+ only. Defines threshold values of vacancy expressed as
     * percent, value of current vacancy is set to zero for table-mod.
     * For other versions, ignored on encoding, all values decoded to
     * zero. */
    struct ofputil_table_mod_prop_vacancy table_vacancy;
};

/* Abstract ofp14_table_desc. */
struct ofputil_table_desc {
    uint8_t table_id;         /* ID of the table. */
    enum ofputil_table_eviction eviction;
    uint32_t eviction_flags;    /* UINT32_MAX if not present. */
    enum ofputil_table_vacancy vacancy;
    struct ofputil_table_mod_prop_vacancy table_vacancy;
};

enum ofperr ofputil_decode_table_mod(const struct ofp_header *,
                                    struct ofputil_table_mod *);
struct ofpbuf *ofputil_encode_table_mod(const struct ofputil_table_mod *,
                                       enum ofputil_protocol);

/* Abstract ofp_table_features.
 *
 * This is used for all versions of OpenFlow, even though ofp_table_features
 * was only introduced in OpenFlow 1.3, because earlier versions of OpenFlow
 * include support for a subset of ofp_table_features through OFPST_TABLE (aka
 * OFPMP_TABLE). */
struct ofputil_table_features {
    uint8_t table_id;         /* Identifier of table. Lower numbered tables
                                 are consulted first. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    ovs_be64 metadata_match;  /* Bits of metadata table can match. */
    ovs_be64 metadata_write;  /* Bits of metadata table can write. */
    uint32_t max_entries;     /* Max number of entries supported. */

    /* Flags.
     *
     * 'miss_config' is relevant for OpenFlow 1.1 and 1.2 only, because those
     * versions include OFPTC_MISS_* flags in OFPST_TABLE.  For other versions,
     * it is decoded to OFPUTIL_TABLE_MISS_DEFAULT and ignored for encoding.
     *
     * 'supports_eviction' and 'supports_vacancy_events' are relevant only for
     * OpenFlow 1.4 and later only.  For OF1.4, they are boolean: 1 if
     * supported, otherwise 0.  For other versions, they are decoded as -1 and
     * ignored for encoding.
     *
     * Search for "OFPTC_* Table Configuration" in the documentation for more
     * details of how OpenFlow has changed in this area.
     */
    enum ofputil_table_miss miss_config; /* OF1.1 and 1.2 only. */
    int supports_eviction;               /* OF1.4+ only. */
    int supports_vacancy_events;         /* OF1.4+ only. */

    /* Table features related to instructions.  There are two instances:
     *
     *   - 'miss' reports features available in the table miss flow.
     *
     *   - 'nonmiss' reports features available in other flows. */
    struct ofputil_table_instruction_features {
        /* Tables that "goto-table" may jump to. */
        unsigned long int next[BITMAP_N_LONGS(255)];

        /* Bitmap of OVSINST_* for supported instructions. */
        uint32_t instructions;

        /* Table features related to actions.  There are two instances:
         *
         *    - 'write' reports features available in a "write_actions"
         *      instruction.
         *
         *    - 'apply' reports features available in an "apply_actions"
         *      instruction. */
        struct ofputil_table_action_features {
            uint64_t ofpacts;     /* Bitmap of supported OFPACT_*. */
            struct mf_bitmap set_fields; /* Fields for "set-field". */
        } write, apply;
    } nonmiss, miss;

    /* MFF_* bitmaps.
     *
     * For any given field the following combinations are valid:
     *
     *    - match=0, wildcard=0, mask=0: Flows in this table cannot match on
     *      this field.
     *
     *    - match=1, wildcard=0, mask=0: Flows in this table must match on all
     *      the bits in this field.
     *
     *    - match=1, wildcard=1, mask=0: Flows in this table must either match
     *      on all the bits in the field or wildcard the field entirely.
     *
     *    - match=1, wildcard=1, mask=1: Flows in this table may arbitrarily
     *      mask this field (as special cases, they may match on all the bits
     *      or wildcard it entirely).
     *
     * Other combinations do not make sense.
     */
    struct mf_bitmap match;     /* Fields that may be matched. */
    struct mf_bitmap mask;      /* Subset of 'match' that may have masks. */
    struct mf_bitmap wildcard;  /* Subset of 'match' that may be wildcarded. */
};

int ofputil_decode_table_features(struct ofpbuf *,
                                  struct ofputil_table_features *, bool loose);

int ofputil_decode_table_desc(struct ofpbuf *,
                              struct ofputil_table_desc *,
                              enum ofp_version);

struct ofpbuf *ofputil_encode_table_features_request(enum ofp_version);

struct ofpbuf *ofputil_encode_table_desc_request(enum ofp_version);

void ofputil_append_table_features_reply(
    const struct ofputil_table_features *tf, struct ovs_list *replies);

void ofputil_append_table_desc_reply(const struct ofputil_table_desc *td,
                                     struct ovs_list *replies,
                                     enum ofp_version);

/* Meter band configuration for all supported band types. */
struct ofputil_meter_band {
    uint16_t type;
    uint8_t prec_level;         /* Non-zero if type == OFPMBT_DSCP_REMARK. */
    uint32_t rate;
    uint32_t burst_size;
};

struct ofputil_meter_band_stats {
    uint64_t packet_count;
    uint64_t byte_count;
};

struct ofputil_meter_config {
    uint32_t meter_id;
    uint16_t flags;
    uint16_t n_bands;
    struct ofputil_meter_band *bands;
};

/* Abstract ofp_meter_mod. */
struct ofputil_meter_mod {
    uint16_t command;
    struct ofputil_meter_config meter;
};

struct ofputil_meter_stats {
    uint32_t meter_id;
    uint32_t flow_count;
    uint64_t packet_in_count;
    uint64_t byte_in_count;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t n_bands;
    struct ofputil_meter_band_stats *bands;
};

struct ofputil_meter_features {
    uint32_t max_meters;        /* Maximum number of meters. */
    uint32_t band_types;        /* Can support max 32 band types. */
    uint32_t capabilities;      /* Supported flags. */
    uint8_t  max_bands;
    uint8_t  max_color;
};

enum ofperr ofputil_decode_meter_mod(const struct ofp_header *,
                                     struct ofputil_meter_mod *,
                                     struct ofpbuf *bands);
struct ofpbuf *ofputil_encode_meter_mod(enum ofp_version,
                                        const struct ofputil_meter_mod *);

void ofputil_decode_meter_features(const struct ofp_header *,
                                   struct ofputil_meter_features *);
struct ofpbuf *ofputil_encode_meter_features_reply(const struct
                                                   ofputil_meter_features *,
                                                   const struct ofp_header *
                                                   request);
void ofputil_decode_meter_request(const struct ofp_header *,
                                  uint32_t *meter_id);

void ofputil_append_meter_config(struct ovs_list *replies,
                                 const struct ofputil_meter_config *);

void ofputil_append_meter_stats(struct ovs_list *replies,
                                const struct ofputil_meter_stats *);

enum ofputil_meter_request_type {
    OFPUTIL_METER_FEATURES,
    OFPUTIL_METER_CONFIG,
    OFPUTIL_METER_STATS
};

struct ofpbuf *ofputil_encode_meter_request(enum ofp_version,
                                            enum ofputil_meter_request_type,
                                            uint32_t meter_id);

int ofputil_decode_meter_stats(struct ofpbuf *,
                               struct ofputil_meter_stats *,
                               struct ofpbuf *bands);

int ofputil_decode_meter_config(struct ofpbuf *,
                                struct ofputil_meter_config *,
                                struct ofpbuf *bands);

/* Type for meter_id in ofproto provider interface, UINT32_MAX if invalid. */
typedef struct { uint32_t uint32; } ofproto_meter_id;

/* Abstract ofp_role_request and reply. */
struct ofputil_role_request {
    enum ofp12_controller_role role;
    bool have_generation_id;
    uint64_t generation_id;
};

struct ofputil_role_status {
    enum ofp12_controller_role role;
    enum ofp14_controller_role_reason reason;
    uint64_t generation_id;
};

enum ofperr ofputil_decode_role_message(const struct ofp_header *,
                                        struct ofputil_role_request *);
struct ofpbuf *ofputil_encode_role_reply(const struct ofp_header *,
                                         const struct ofputil_role_request *);

struct ofpbuf *ofputil_encode_role_status(
                                const struct ofputil_role_status *status,
                                enum ofputil_protocol protocol);

enum ofperr ofputil_decode_role_status(const struct ofp_header *oh,
                                       struct ofputil_role_status *rs);

/* Abstract table stats.
 *
 * This corresponds to the OpenFlow 1.3 table statistics structure, which only
 * includes actual statistics.  In earlier versions of OpenFlow, several
 * members describe table features, so this structure has to be paired with
 * struct ofputil_table_features to get all information. */
struct ofputil_table_stats {
    uint8_t table_id;           /* Identifier of table. */
    uint32_t active_count;      /* Number of active entries. */
    uint64_t lookup_count;      /* Number of packets looked up in table. */
    uint64_t matched_count;     /* Number of packets that hit table. */
};

struct ofpbuf *ofputil_encode_table_stats_reply(const struct ofp_header *rq);

struct ofpbuf *ofputil_encode_table_desc_reply(const struct ofp_header *rq);

void ofputil_append_table_stats_reply(struct ofpbuf *reply,
                                      const struct ofputil_table_stats *,
                                      const struct ofputil_table_features *);

int ofputil_decode_table_stats_reply(struct ofpbuf *reply,
                                     struct ofputil_table_stats *,
                                     struct ofputil_table_features *);

/* Queue configuration request. */
struct ofpbuf *ofputil_encode_queue_get_config_request(enum ofp_version,
                                                       ofp_port_t port,
                                                       uint32_t queue);
enum ofperr ofputil_decode_queue_get_config_request(const struct ofp_header *,
                                                    ofp_port_t *port,
                                                    uint32_t *queue);

/* Queue configuration reply. */
struct ofputil_queue_config {
    ofp_port_t port;
    uint32_t queue;

    /* Each of these optional values is expressed in tenths of a percent.
     * Values greater than 1000 indicate that the feature is disabled.
     * UINT16_MAX indicates that the value is omitted. */
    uint16_t min_rate;
    uint16_t max_rate;
};

void ofputil_start_queue_get_config_reply(const struct ofp_header *request,
                                          struct ovs_list *replies);
void ofputil_append_queue_get_config_reply(
    const struct ofputil_queue_config *, struct ovs_list *replies);

int ofputil_pull_queue_get_config_reply(struct ofpbuf *reply,
                                        struct ofputil_queue_config *);


/* Abstract nx_flow_monitor_request. */
struct ofputil_flow_monitor_request {
    uint32_t id;
    enum nx_flow_monitor_flags flags;
    ofp_port_t out_port;
    uint8_t table_id;
    struct match match;
};

int ofputil_decode_flow_monitor_request(struct ofputil_flow_monitor_request *,
                                        struct ofpbuf *msg);
void ofputil_append_flow_monitor_request(
    const struct ofputil_flow_monitor_request *, struct ofpbuf *msg);

/* Abstract nx_flow_update. */
struct ofputil_flow_update {
    enum nx_flow_update_event event;

    /* Used only for NXFME_ADDED, NXFME_DELETED, NXFME_MODIFIED. */
    enum ofp_flow_removed_reason reason;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint8_t table_id;
    uint16_t priority;
    ovs_be64 cookie;
    struct match match;
    const struct ofpact *ofpacts;
    size_t ofpacts_len;

    /* Used only for NXFME_ABBREV. */
    ovs_be32 xid;
};

int ofputil_decode_flow_update(struct ofputil_flow_update *,
                               struct ofpbuf *msg, struct ofpbuf *ofpacts);
void ofputil_start_flow_update(struct ovs_list *replies);
void ofputil_append_flow_update(const struct ofputil_flow_update *,
                                struct ovs_list *replies,
                                const struct tun_table *);

/* Abstract nx_flow_monitor_cancel. */
uint32_t ofputil_decode_flow_monitor_cancel(const struct ofp_header *);
struct ofpbuf *ofputil_encode_flow_monitor_cancel(uint32_t id);

/* Port desc stats requests and replies. */
enum ofperr ofputil_decode_port_desc_stats_request(const struct ofp_header *,
                                                   ofp_port_t *portp);
struct ofpbuf *ofputil_encode_port_desc_stats_request(
    enum ofp_version ofp_version, ofp_port_t);

void ofputil_append_port_desc_stats_reply(const struct ofputil_phy_port *pp,
                                          struct ovs_list *replies);

/* Encoding simple OpenFlow messages. */
struct ofpbuf *make_echo_request(enum ofp_version);
struct ofpbuf *make_echo_reply(const struct ofp_header *rq);

struct ofpbuf *ofputil_encode_barrier_request(enum ofp_version);

/* Actions. */

bool action_outputs_to_port(const union ofp_action *, ovs_be16 port);

enum ofperr ofputil_pull_actions(struct ofpbuf *, unsigned int actions_len,
                                 union ofp_action **, size_t *);

bool ofputil_actions_equal(const union ofp_action *a, size_t n_a,
                           const union ofp_action *b, size_t n_b);
union ofp_action *ofputil_actions_clone(const union ofp_action *, size_t n);

/* Handy utility for parsing flows and actions. */
bool ofputil_parse_key_value(char **stringp, char **keyp, char **valuep);

struct ofputil_port_stats {
    ofp_port_t port_no;
    struct netdev_stats stats;
    struct netdev_custom_stats custom_stats;
    uint32_t duration_sec;      /* UINT32_MAX if unknown. */
    uint32_t duration_nsec;
};

struct ofpbuf *ofputil_encode_dump_ports_request(enum ofp_version ofp_version,
                                                 ofp_port_t port);
void ofputil_append_port_stat(struct ovs_list *replies,
                              const struct ofputil_port_stats *ops);
size_t ofputil_count_port_stats(const struct ofp_header *);
int ofputil_decode_port_stats(struct ofputil_port_stats *, struct ofpbuf *msg);
enum ofperr ofputil_decode_port_stats_request(const struct ofp_header *request,
                                              ofp_port_t *ofp10_port);

struct ofputil_ipfix_stats {
    uint32_t collector_set_id;  /* Used only for flow-based IPFIX statistics. */
    uint64_t total_flows;  /* Totabl flows of this IPFIX exporter. */
    uint64_t current_flows;  /* Current flows of this IPFIX exporter. */
    uint64_t pkts;  /* Successfully sampled packets. */
    uint64_t ipv4_pkts;  /* Successfully sampled IPV4 packets. */
    uint64_t ipv6_pkts;  /* Successfully sampled IPV6 packets. */
    uint64_t error_pkts;  /* Error packets when sampling. */
    uint64_t ipv4_error_pkts;  /* Error IPV4 packets when sampling. */
    uint64_t ipv6_error_pkts;  /* Error IPV6 packets when sampling. */
    uint64_t tx_pkts;  /* TX IPFIX packets. */
    uint64_t tx_errors;  /* IPFIX packets TX errors. */
};

void ofputil_append_ipfix_stat(struct ovs_list *replies,
                              const struct ofputil_ipfix_stats *ois);
size_t ofputil_count_ipfix_stats(const struct ofp_header *);
int ofputil_pull_ipfix_stats(struct ofputil_ipfix_stats *, struct ofpbuf *msg);

struct ofputil_queue_stats_request {
    ofp_port_t port_no;           /* OFPP_ANY means "all ports". */
    uint32_t queue_id;
};

enum ofperr
ofputil_decode_queue_stats_request(const struct ofp_header *request,
                                   struct ofputil_queue_stats_request *oqsr);
struct ofpbuf *
ofputil_encode_queue_stats_request(enum ofp_version ofp_version,
                                   const struct ofputil_queue_stats_request *oqsr);

struct ofputil_queue_stats {
    ofp_port_t port_no;
    uint32_t queue_id;

    /* Values of unsupported statistics are set to all-1-bits (UINT64_MAX). */
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;

    /* UINT32_MAX if unknown. */
    uint32_t duration_sec;
    uint32_t duration_nsec;
};

size_t ofputil_count_queue_stats(const struct ofp_header *);
int ofputil_decode_queue_stats(struct ofputil_queue_stats *qs, struct ofpbuf *msg);
void ofputil_append_queue_stat(struct ovs_list *replies,
                               const struct ofputil_queue_stats *oqs);

struct bucket_counter {
    uint64_t packet_count;   /* Number of packets processed by bucket. */
    uint64_t byte_count;     /* Number of bytes processed by bucket. */
};

/* Bucket for use in groups. */
struct ofputil_bucket {
    struct ovs_list list_node;
    uint16_t weight;            /* Relative weight, for "select" groups. */
    ofp_port_t watch_port;      /* Port whose state affects whether this bucket
                                 * is live. Only required for fast failover
                                 * groups. */
    uint32_t watch_group;       /* Group whose state affects whether this
                                 * bucket is live. Only required for fast
                                 * failover groups. */
    uint32_t bucket_id;         /* Bucket Id used to identify bucket*/
    struct ofpact *ofpacts;     /* Series of "struct ofpact"s. */
    size_t ofpacts_len;         /* Length of ofpacts, in bytes. */

    struct bucket_counter stats;
};

/* Protocol-independent group_mod. */
struct ofputil_group_props {
    /* NTR selection method */
    char selection_method[NTR_MAX_SELECTION_METHOD_LEN];
    uint64_t selection_method_param;
    struct field_array fields;
};

/* Protocol-independent group_mod. */
struct ofputil_group_mod {
    uint16_t command;             /* One of OFPGC15_*. */
    uint8_t type;                 /* One of OFPGT11_*. */
    uint32_t group_id;            /* Group identifier. */
    uint32_t command_bucket_id;   /* Bucket Id used as part of
                                   * OFPGC15_INSERT_BUCKET and
                                   * OFPGC15_REMOVE_BUCKET commands
                                   * execution.*/
    struct ovs_list buckets;      /* Contains "struct ofputil_bucket"s. */
    struct ofputil_group_props props; /* Group properties. */
};

/* Group stats reply, independent of protocol. */
struct ofputil_group_stats {
    uint32_t group_id;    /* Group identifier. */
    uint32_t ref_count;
    uint64_t packet_count;      /* Packet count, UINT64_MAX if unknown. */
    uint64_t byte_count;        /* Byte count, UINT64_MAX if unknown. */
    uint32_t duration_sec;      /* UINT32_MAX if unknown. */
    uint32_t duration_nsec;
    uint32_t n_buckets;
    struct bucket_counter *bucket_stats;
};

/* Group features reply, independent of protocol.
 *
 * Only OF1.2 and later support group features replies. */
struct ofputil_group_features {
    uint32_t  types;           /* Bitmap of OFPGT_* values supported. */
    uint32_t  capabilities;    /* Bitmap of OFPGFC12_* capability supported. */
    uint32_t  max_groups[4];   /* Maximum number of groups for each type. */
    uint64_t  ofpacts[4];      /* Bitmaps of supported OFPACT_* */
};

/* Group desc reply, independent of protocol. */
struct ofputil_group_desc {
    uint8_t type;               /* One of OFPGT_*. */
    uint32_t group_id;          /* Group identifier. */
    struct ovs_list buckets;    /* Contains "struct ofputil_bucket"s. */
    struct ofputil_group_props props; /* Group properties. */
};

void ofputil_group_properties_destroy(struct ofputil_group_props *);
void ofputil_group_properties_copy(struct ofputil_group_props *to,
                                   const struct ofputil_group_props *from);
void ofputil_bucket_list_destroy(struct ovs_list *buckets);
void ofputil_bucket_clone_list(struct ovs_list *dest,
                               const struct ovs_list *src,
                               const struct ofputil_bucket *);
struct ofputil_bucket *ofputil_bucket_find(const struct ovs_list *,
                                           uint32_t bucket_id);
bool ofputil_bucket_check_duplicate_id(const struct ovs_list *);
struct ofputil_bucket *ofputil_bucket_list_front(const struct ovs_list *);
struct ofputil_bucket *ofputil_bucket_list_back(const struct ovs_list *);

static inline bool
ofputil_bucket_has_liveness(const struct ofputil_bucket *bucket)
{
    return (bucket->watch_port != OFPP_ANY ||
            bucket->watch_group != OFPG_ANY);
}

struct ofpbuf *ofputil_encode_group_stats_request(enum ofp_version,
                                                  uint32_t group_id);
enum ofperr ofputil_decode_group_stats_request(
    const struct ofp_header *request, uint32_t *group_id);
void ofputil_append_group_stats(struct ovs_list *replies,
                                const struct ofputil_group_stats *);
struct ofpbuf *ofputil_encode_group_features_request(enum ofp_version);
struct ofpbuf *ofputil_encode_group_features_reply(
    const struct ofputil_group_features *, const struct ofp_header *request);
void ofputil_decode_group_features_reply(const struct ofp_header *,
                                         struct ofputil_group_features *);
void ofputil_uninit_group_mod(struct ofputil_group_mod *gm);
struct ofpbuf *ofputil_encode_group_mod(enum ofp_version ofp_version,
                                        const struct ofputil_group_mod *gm);

enum ofperr ofputil_decode_group_mod(const struct ofp_header *,
                                     struct ofputil_group_mod *);

int ofputil_decode_group_stats_reply(struct ofpbuf *,
                                     struct ofputil_group_stats *);

void ofputil_uninit_group_desc(struct ofputil_group_desc *gd);
uint32_t ofputil_decode_group_desc_request(const struct ofp_header *);
struct ofpbuf *ofputil_encode_group_desc_request(enum ofp_version,
                                                 uint32_t group_id);

int ofputil_decode_group_desc_reply(struct ofputil_group_desc *,
                                    struct ofpbuf *, enum ofp_version);

void ofputil_append_group_desc_reply(const struct ofputil_group_desc *,
                                     const struct ovs_list *buckets,
                                     struct ovs_list *replies);

struct ofputil_bundle_ctrl_msg {
    uint32_t    bundle_id;
    uint16_t    type;
    uint16_t    flags;
};

struct ofputil_bundle_add_msg {
    uint32_t            bundle_id;
    uint16_t            flags;
    const struct ofp_header   *msg;
};

enum ofperr ofputil_decode_bundle_ctrl(const struct ofp_header *,
                                       struct ofputil_bundle_ctrl_msg *);

struct ofpbuf *ofputil_encode_bundle_ctrl_request(enum ofp_version,
                                                  struct ofputil_bundle_ctrl_msg *);
struct ofpbuf *ofputil_encode_bundle_ctrl_reply(const struct ofp_header *,
                                                struct ofputil_bundle_ctrl_msg *);

struct ofpbuf *ofputil_encode_bundle_add(enum ofp_version ofp_version,
                                         struct ofputil_bundle_add_msg *msg);

enum ofperr ofputil_decode_bundle_add(const struct ofp_header *,
                                      struct ofputil_bundle_add_msg *,
                                      enum ofptype *type);

/* Bundle message as produced by ofp-parse. */
struct ofputil_bundle_msg {
    enum ofptype type;
    union {
        struct ofputil_flow_mod fm;
        struct ofputil_group_mod gm;
        struct ofputil_packet_out po;
    };
};

void ofputil_encode_bundle_msgs(const struct ofputil_bundle_msg *bms,
                                size_t n_bms, struct ovs_list *requests,
                                enum ofputil_protocol);
void ofputil_free_bundle_msgs(struct ofputil_bundle_msg *bms, size_t n_bms);

struct ofputil_tlv_map {
    struct ovs_list list_node;

    uint16_t option_class;
    uint8_t  option_type;
    uint8_t  option_len;
    uint16_t index;
};

struct ofputil_tlv_table_mod {
    uint16_t command;
    struct ovs_list mappings;      /* Contains "struct ofputil_tlv_map"s. */
};

struct ofputil_tlv_table_reply {
    uint32_t max_option_space;
    uint16_t max_fields;
    struct ovs_list mappings;      /* Contains "struct ofputil_tlv_map"s. */
};

struct ofpbuf *ofputil_encode_tlv_table_mod(enum ofp_version ofp_version,
                                               struct ofputil_tlv_table_mod *);
enum ofperr ofputil_decode_tlv_table_mod(const struct ofp_header *,
                                            struct ofputil_tlv_table_mod *);
struct ofpbuf *ofputil_encode_tlv_table_reply(const struct ofp_header *,
                                               struct ofputil_tlv_table_reply *);
enum ofperr ofputil_decode_tlv_table_reply(const struct ofp_header *,
                                              struct ofputil_tlv_table_reply *);
void ofputil_uninit_tlv_table(struct ovs_list *mappings);

enum ofputil_async_msg_type {
    /* Standard asynchronous messages. */
    OAM_PACKET_IN,              /* OFPT_PACKET_IN or NXT_PACKET_IN. */
    OAM_PORT_STATUS,            /* OFPT_PORT_STATUS. */
    OAM_FLOW_REMOVED,           /* OFPT_FLOW_REMOVED or NXT_FLOW_REMOVED. */
    OAM_ROLE_STATUS,            /* OFPT_ROLE_STATUS. */
    OAM_TABLE_STATUS,           /* OFPT_TABLE_STATUS. */
    OAM_REQUESTFORWARD,         /* OFPT_REQUESTFORWARD. */

    /* Extension asynchronous messages (none yet--coming soon!). */
#define OAM_EXTENSIONS 0        /* Bitmap of all extensions. */

    OAM_N_TYPES
};
const char *ofputil_async_msg_type_to_string(enum ofputil_async_msg_type);

struct ofputil_async_cfg {
    uint32_t master[OAM_N_TYPES];
    uint32_t slave[OAM_N_TYPES];
};
#define OFPUTIL_ASYNC_CFG_INIT (struct ofputil_async_cfg) { .master[0] = 0 }

enum ofperr ofputil_decode_set_async_config(const struct ofp_header *,
                                            bool loose,
                                            const struct ofputil_async_cfg *,
                                            struct ofputil_async_cfg *);

struct ofpbuf *ofputil_encode_get_async_reply(
    const struct ofp_header *, const struct ofputil_async_cfg *);
struct ofpbuf *ofputil_encode_set_async_config(
    const struct ofputil_async_cfg *, uint32_t oams, enum ofp_version);

struct ofputil_async_cfg ofputil_async_cfg_default(enum ofp_version);

struct ofputil_requestforward {
    ovs_be32 xid;
    enum ofp14_requestforward_reason reason;
    union {
        /* reason == OFPRFR_METER_MOD. */
        struct {
            struct ofputil_meter_mod *meter_mod;
            struct ofpbuf bands;
        };

        /* reason == OFPRFR_GROUP_MOD. */
        struct ofputil_group_mod *group_mod;
    };
};

struct ofpbuf *ofputil_encode_requestforward(
    const struct ofputil_requestforward *, enum ofputil_protocol);
enum ofperr ofputil_decode_requestforward(const struct ofp_header *,
                                          struct ofputil_requestforward *);
void ofputil_destroy_requestforward(struct ofputil_requestforward *);

/* Abstract ofp14_table_status. */
struct ofputil_table_status {
    enum ofp14_table_reason reason;     /* One of OFPTR_*. */
    struct ofputil_table_desc desc;   /* New table config. */
};

enum ofperr ofputil_decode_table_status(const struct ofp_header *oh,
                                        struct ofputil_table_status *ts);

struct ofpbuf *
ofputil_encode_table_status(const struct ofputil_table_status *ts,
                            enum ofputil_protocol protocol);

#ifdef __cplusplus
}
#endif

#endif /* ofp-util.h */
