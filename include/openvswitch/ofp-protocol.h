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

#ifndef OPENVSWITCH_OFP_PROTOCOL_H
#define OPENVSWITCH_OFP_PROTOCOL_H 1

#include "openflow/openflow.h"

struct ds;

#ifdef __cplusplus
extern "C" {
#endif

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

/* Messages for changing the protocol. */

/* Changing the protocol at a high level.  */
struct ofpbuf *ofputil_encode_set_protocol(enum ofputil_protocol current,
                                           enum ofputil_protocol want,
                                           enum ofputil_protocol *next);

/* Changing the protocol at a low level. */
struct ofpbuf *ofputil_encode_nx_set_flow_format(enum ofputil_protocol);
enum ofputil_protocol ofputil_decode_nx_set_flow_format(
    const struct ofp_header *);

struct ofpbuf *ofputil_encode_nx_flow_mod_table_id(bool enable);
bool ofputil_decode_nx_flow_mod_table_id(const struct ofp_header *);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-protocol.h */
