/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#define OVSP_NONE ((uint16_t) -1)

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

/* Upper bound on the length of a nlattr-formatted flow key.  The longest
 * nlattr-formatted flow key would be:
 *
 *                         struct  pad  nl hdr  total
 *                         ------  ---  ------  -----
 *  OVS_KEY_ATTR_PRIORITY      4    --     4      8
 *  OVS_KEY_ATTR_TUN_ID        8    --     4     12
 *  OVS_KEY_ATTR_IN_PORT       4    --     4      8
 *  OVS_KEY_ATTR_ETHERNET     12    --     4     16
 *  OVS_KEY_ATTR_8021Q         4    --     4      8
 *  OVS_KEY_ATTR_ETHERTYPE     2     2     4      8
 *  OVS_KEY_ATTR_IPV6         38     2     4     44
 *  OVS_KEY_ATTR_ICMPV6        2     2     4      8
 *  OVS_KEY_ATTR_ND           28    --     4     32
 *  -------------------------------------------------
 *  total                                       144
 */
#define ODPUTIL_FLOW_KEY_BYTES 144

/* A buffer with sufficient size and alignment to hold an nlattr-formatted flow
 * key.  An array of "struct nlattr" might not, in theory, be sufficiently
 * aligned because it only contains 16-bit types. */
struct odputil_keybuf {
    uint32_t keybuf[DIV_ROUND_UP(ODPUTIL_FLOW_KEY_BYTES, 4)];
};

void odp_flow_key_format(const struct nlattr *, size_t, struct ds *);
int odp_flow_key_from_string(const char *s, struct ofpbuf *);

void odp_flow_key_from_flow(struct ofpbuf *, const struct flow *);
int odp_flow_key_to_flow(const struct nlattr *, size_t, struct flow *);

enum user_action_cookie_type {
    USER_ACTION_COOKIE_UNSPEC,
    USER_ACTION_COOKIE_CONTROLLER,   /* Packet for controller. */
    USER_ACTION_COOKIE_SFLOW,        /* Packet for sFlow sampling. */
};

/* user_action_cookie is passed as argument to OVS_ACTION_ATTR_USERSPACE.
 * Since is it passed to kernel as u64, its size has to be 8 bytes. */
struct user_action_cookie {
    uint8_t   type;                 /* enum user_action_cookie_type. */
    uint8_t   n_output;             /* No of output ports. used by sflow. */
    ovs_be16  vlan_tci;             /* Used by sFlow */
    uint32_t  data;                 /* Data is len for OFPP_CONTROLLER action.
                                       For sFlow it is port_ifindex. */
};

BUILD_ASSERT_DECL(sizeof(struct user_action_cookie) == 8);

#endif /* odp-util.h */
