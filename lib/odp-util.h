/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#ifndef ODP_UTIL_H
#define ODP_UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <linux/openvswitch.h>
#include "hash.h"
#include "openflow/openflow.h"
#include "util.h"

struct ds;
struct flow;
struct nlattr;
struct ofpbuf;
struct simap;

#define OVSP_NONE UINT16_MAX

static inline uint16_t
ofp_port_to_odp_port(uint16_t ofp_port)
{
    switch (ofp_port) {
    case OFPP_LOCAL:
        return OVSP_LOCAL;
    case OFPP_NONE:
        return OVSP_NONE;
    default:
        return ofp_port;
    }
}

static inline uint16_t
odp_port_to_ofp_port(uint16_t odp_port)
{
    switch (odp_port) {
    case OVSP_LOCAL:
        return OFPP_LOCAL;
    case OVSP_NONE:
        return OFPP_NONE;
    default:
        return odp_port;
    }
}

void format_odp_actions(struct ds *, const struct nlattr *odp_actions,
                        size_t actions_len);
int odp_actions_from_string(const char *, const struct simap *port_names,
                            struct ofpbuf *odp_actions);

/* The maximum number of bytes that odp_flow_key_from_flow() appends to a
 * buffer.  This is the upper bound on the length of a nlattr-formatted flow
 * key that ovs-vswitchd fully understands.
 *
 * OVS doesn't insist that ovs-vswitchd and the datapath have exactly the same
 * idea of a flow, so therefore this value isn't necessarily an upper bound on
 * the length of a flow key that the datapath can pass to ovs-vswitchd.
 *
 * The longest nlattr-formatted flow key appended by odp_flow_key_from_flow()
 * would be:
 *
 *                                     struct  pad  nl hdr  total
 *                                     ------  ---  ------  -----
 *  OVS_KEY_ATTR_PRIORITY                4    --     4      8
 *  OVS_KEY_ATTR_TUN_ID                  8    --     4     12
 *  OVS_KEY_ATTR_TUNNEL                  0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_ID             8    --     4     12
 *  - OVS_TUNNEL_KEY_ATTR_IPV4_SRC       4    --     4      8
 *  - OVS_TUNNEL_KEY_ATTR_IPV4_DST       4    --     4      8
 *  - OVS_TUNNEL_KEY_ATTR_TOS            1    3      4      8
 *  - OVS_TUNNEL_KEY_ATTR_TTL            1    3      4      8
 *  - OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT  0    --     4      4
 *  - OVS_TUNNEL_KEY_ATTR_CSUM           0    --     4      4
 *  OVS_KEY_ATTR_IN_PORT                 4    --     4      8
 *  OVS_KEY_ATTR_SKB_MARK                4    --     4      8
 *  OVS_KEY_ATTR_ETHERNET               12    --     4     16
 *  OVS_KEY_ATTR_ETHERTYPE               2     2     4      8  (outer VLAN ethertype)
 *  OVS_KEY_ATTR_8021Q                   4    --     4      8
 *  OVS_KEY_ATTR_ENCAP                   0    --     4      4  (VLAN encapsulation)
 *  OVS_KEY_ATTR_ETHERTYPE               2     2     4      8  (inner VLAN ethertype)
 *  OVS_KEY_ATTR_IPV6                   40    --     4     44
 *  OVS_KEY_ATTR_ICMPV6                  2     2     4      8
 *  OVS_KEY_ATTR_ND                     28    --     4     32
 *  ----------------------------------------------------------
 *  total                                                 220
 *
 * We include some slack space in case the calculation isn't quite right or we
 * add another field and forget to adjust this value.
 */
#define ODPUTIL_FLOW_KEY_BYTES 256

/* A buffer with sufficient size and alignment to hold an nlattr-formatted flow
 * key.  An array of "struct nlattr" might not, in theory, be sufficiently
 * aligned because it only contains 16-bit types. */
struct odputil_keybuf {
    uint32_t keybuf[DIV_ROUND_UP(ODPUTIL_FLOW_KEY_BYTES, 4)];
};

void odp_flow_key_format(const struct nlattr *, size_t, struct ds *);
int odp_flow_key_from_string(const char *s, const struct simap *port_names,
                             struct ofpbuf *);

void odp_flow_key_from_flow(struct ofpbuf *, const struct flow *);

uint32_t odp_flow_key_hash(const struct nlattr *, size_t);

/* How well a kernel-provided flow key (a sequence of OVS_KEY_ATTR_*
 * attributes) matches OVS userspace expectations.
 *
 * These values are arranged so that greater values are "more important" than
 * lesser ones.  In particular, a single flow key can fit the descriptions for
 * both ODP_FIT_TOO_LITTLE and ODP_FIT_TOO_MUCH.  Such a key is treated as
 * ODP_FIT_TOO_LITTLE. */
enum odp_key_fitness {
    ODP_FIT_PERFECT,            /* The key had exactly the fields we expect. */
    ODP_FIT_TOO_MUCH,           /* The key had fields we don't understand. */
    ODP_FIT_TOO_LITTLE,         /* The key lacked fields we expected to see. */
    ODP_FIT_ERROR,              /* The key was invalid. */
};
enum odp_key_fitness odp_flow_key_to_flow(const struct nlattr *, size_t,
                                          struct flow *);
const char *odp_key_fitness_to_string(enum odp_key_fitness);

void commit_odp_actions(const struct flow *, struct flow *base,
                        struct ofpbuf *odp_actions);

/* ofproto-dpif interface.
 *
 * The following types and functions are logically part of ofproto-dpif.
 * ofproto-dpif puts values of these types into the flows that it installs in
 * the kernel datapath, though, so ovs-dpctl needs to interpret them so that
 * it can print flows in a more human-readable manner. */

enum user_action_cookie_type {
    USER_ACTION_COOKIE_UNSPEC,
    USER_ACTION_COOKIE_SFLOW,        /* Packet for sFlow sampling. */
    USER_ACTION_COOKIE_SLOW_PATH     /* Userspace must process this flow. */
};

/* user_action_cookie is passed as argument to OVS_ACTION_ATTR_USERSPACE.
 * Since it is passed to kernel as u64, its size has to be 8 bytes. */
union user_action_cookie {
    uint16_t type;              /* enum user_action_cookie_type. */

    struct {
        uint16_t type;          /* USER_ACTION_COOKIE_SFLOW. */
        ovs_be16 vlan_tci;      /* Destination VLAN TCI. */
        uint32_t output;        /* SFL_FLOW_SAMPLE_TYPE 'output' value. */
    } sflow;

    struct {
        uint16_t type;          /* USER_ACTION_COOKIE_SLOW_PATH. */
        uint16_t unused;
        uint32_t reason;        /* enum slow_path_reason. */
    } slow_path;
};
BUILD_ASSERT_DECL(sizeof(union user_action_cookie) == 8);

size_t odp_put_userspace_action(uint32_t pid,
                                const union user_action_cookie *,
                                struct ofpbuf *odp_actions);

/* Reasons why a subfacet might not be fast-pathable. */
enum slow_path_reason {
    /* These reasons are mutually exclusive. */
    SLOW_CFM = 1 << 0,          /* CFM packets need per-packet processing. */
    SLOW_LACP = 1 << 1,         /* LACP packets need per-packet processing. */
    SLOW_STP = 1 << 2,          /* STP packets need per-packet processing. */
    SLOW_IN_BAND = 1 << 3,      /* In-band control needs every packet. */

    /* Mutually exclusive with SLOW_CFM, SLOW_LACP, SLOW_STP.
     * Could possibly appear with SLOW_IN_BAND. */
    SLOW_CONTROLLER = 1 << 4,   /* Packets must go to OpenFlow controller. */

    /* This can appear on its own, or, theoretically at least, along with any
     * other combination of reasons. */
    SLOW_MATCH = 1 << 5,        /* Datapath can't match specifically enough. */
};

#endif /* odp-util.h */
