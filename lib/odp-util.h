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
#include "hash.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "util.h"

struct ds;
struct flow;
struct ofpbuf;

#define ODPP_NONE ((uint16_t) -1)

static inline uint16_t
ofp_port_to_odp_port(uint16_t ofp_port)
{
    switch (ofp_port) {
    case OFPP_LOCAL:
        return ODPP_LOCAL;
    case OFPP_NONE:
        return ODPP_NONE;
    default:
        return ofp_port;
    }
}

static inline uint16_t
odp_port_to_ofp_port(uint16_t odp_port)
{
    switch (odp_port) {
    case ODPP_LOCAL:
        return OFPP_LOCAL;
    case ODPP_NONE:
        return OFPP_NONE;
    default:
        return odp_port;
    }
}

int odp_action_len(uint16_t type);
void format_odp_action(struct ds *, const struct nlattr *);
void format_odp_actions(struct ds *, const struct nlattr *odp_actions,
                        size_t actions_len);

/* Upper bound on the length of a nlattr-formatted flow key.  The longest
 * nlattr-formatted flow key would be:
 *
 *                         struct  pad  nl hdr  total
 *                         ------  ---  ------  -----
 *  ODP_KEY_ATTR_TUN_ID        8    --     4     12
 *  ODP_KEY_ATTR_IN_PORT       4    --     4      8
 *  ODP_KEY_ATTR_ETHERNET     12    --     4     16
 *  ODP_KEY_ATTR_8021Q         4    --     4      8
 *  ODP_KEY_ATTR_ETHERTYPE     2     2     4      8
 *  ODP_KEY_ATTR_IPV6         34     2     4     40
 *  ODP_KEY_ATTR_ICMPV6        2     2     4      8
 *  ODP_KEY_ATTR_ND           28    --     4     32
 *  -------------------------------------------------
 *  total                                       132
 */
#define ODPUTIL_FLOW_KEY_BYTES 132

/* This is an imperfect sanity-check that ODPUTIL_FLOW_KEY_BYTES doesn't
 * need to be updated, but will at least raise awareness when new ODP
 * key types are added. */
BUILD_ASSERT_DECL(__ODP_KEY_ATTR_MAX == 14);

/* A buffer with sufficient size and alignment to hold an nlattr-formatted flow
 * key.  An array of "struct nlattr" might not, in theory, be sufficiently
 * aligned because it only contains 16-bit types. */
struct odputil_keybuf {
    uint32_t keybuf[DIV_ROUND_UP(ODPUTIL_FLOW_KEY_BYTES, 4)];
};

void odp_flow_key_format(const struct nlattr *, size_t, struct ds *);

void odp_flow_key_from_flow(struct ofpbuf *, const struct flow *);
int odp_flow_key_to_flow(const struct nlattr *, size_t, struct flow *);

#endif /* odp-util.h */
