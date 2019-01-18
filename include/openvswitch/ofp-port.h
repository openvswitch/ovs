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

#ifndef OPENVSWITCH_OFP_PORT_H
#define OPENVSWITCH_OFP_PORT_H 1

#include "openvswitch/hmap.h"
#include "openvswitch/netdev.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-protocol.h"
#include "openvswitch/namemap.h"

struct ds;
struct ofpbuf;
struct ovs_list;

#ifdef __cplusplus
extern "C" {
#endif

/* Mapping between port numbers and names. */
struct ofputil_port_map {
    struct namemap map;
};
#define OFPUTIL_PORT_MAP_INITIALIZER(MAP) { NAMEMAP_INITIALIZER(&(MAP)->map) }

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

void ofputil_port_config_format(struct ds *, enum ofputil_port_config);

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

void ofputil_port_state_format(struct ds *, enum ofputil_port_state);

/* Abstract ofp10_phy_port, ofp11_port, or ofp14_port. */
struct ofputil_phy_port {
    ofp_port_t port_no;

    struct eth_addr hw_addr;
    char name[OFP_MAX_PORT_NAME_LEN]; /* 16 bytes. */
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

void ofputil_put_phy_port(enum ofp_version,
                          const struct ofputil_phy_port *, struct ofpbuf *);
int ofputil_pull_phy_port(enum ofp_version, struct ofpbuf *,
                          struct ofputil_phy_port *);
void ofputil_phy_port_format(struct ds *, const struct ofputil_phy_port *);
enum ofperr ofputil_phy_ports_format(struct ds *, uint8_t ofp_version,
                                     struct ofpbuf *);

/* Abstract ofp_port_status. */
struct ofputil_port_status {
    enum ofp_port_reason reason;
    struct ofputil_phy_port desc;
};

enum ofperr ofputil_decode_port_status(const struct ofp_header *,
                                       struct ofputil_port_status *);
struct ofpbuf *ofputil_encode_port_status(const struct ofputil_port_status *,
                                          enum ofputil_protocol);
void ofputil_port_status_format(struct ds *,
                                const struct ofputil_port_status *);

/* Abstract ofp_port_mod. */
struct ofputil_port_mod {
    ofp_port_t port_no;
    struct eth_addr hw_addr;
    enum ofputil_port_config config;
    enum ofputil_port_config mask;
    enum netdev_features advertise;
};

enum ofperr ofputil_decode_port_mod(const struct ofp_header *,
                                    struct ofputil_port_mod *, bool loose);
struct ofpbuf *ofputil_encode_port_mod(const struct ofputil_port_mod *,
                                       enum ofputil_protocol);
void ofputil_port_mod_format(struct ds *, const struct ofputil_port_mod *,
                             const struct ofputil_port_map *);

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
void ofputil_format_port_stats(struct ds *, const struct ofputil_port_stats *,
                               const struct ofputil_port_map *);

enum ofperr ofputil_decode_port_stats_request(const struct ofp_header *request,
                                              ofp_port_t *ofp10_port);

/* Port desc stats requests and replies. */
enum ofperr ofputil_decode_port_desc_stats_request(const struct ofp_header *,
                                                   ofp_port_t *portp);
struct ofpbuf *ofputil_encode_port_desc_stats_request(
    enum ofp_version ofp_version, ofp_port_t);

void ofputil_append_port_desc_stats_reply(const struct ofputil_phy_port *pp,
                                          struct ovs_list *replies);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-port.h */
