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

#include <config.h>
#include "openvswitch/ofp-port.h"
#include <ctype.h>
#include "byte-order.h"
#include "flow.h"
#include "openflow/intel-ext.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_port);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* ofputil_port_map.  */

void
ofputil_port_map_init(struct ofputil_port_map *map)
{
    namemap_init(&map->map);
}

void
ofputil_port_map_put(struct ofputil_port_map *map,
                     ofp_port_t ofp_port, const char *name)
{
    namemap_put(&map->map, ofp_to_u16(ofp_port), name);
}

const char *
ofputil_port_map_get_name(const struct ofputil_port_map *map,
                          ofp_port_t ofp_port)
{
    struct namemap_node *node
        = (map
           ? namemap_find_by_number(&map->map, ofp_to_u16(ofp_port))
           : NULL);
    return node && !node->duplicate ? node->name : NULL;
}

ofp_port_t
ofputil_port_map_get_number(const struct ofputil_port_map *map,
                            const char *name)
{
    struct namemap_node *node
        = map ? namemap_find_by_name(&map->map, name) : NULL;
    return node && !node->duplicate ? u16_to_ofp(node->number) : OFPP_NONE;
}

void
ofputil_port_map_destroy(struct ofputil_port_map *map)
{
    namemap_destroy(&map->map);
}

/* Converts the OpenFlow 1.1+ port number 'ofp11_port' into an OpenFlow 1.0
 * port number and stores the latter in '*ofp10_port', for the purpose of
 * decoding OpenFlow 1.1+ protocol messages.  Returns 0 if successful,
 * otherwise an OFPERR_* number.  On error, stores OFPP_NONE in '*ofp10_port'.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
enum ofperr
ofputil_port_from_ofp11(ovs_be32 ofp11_port, ofp_port_t *ofp10_port)
{
    uint32_t ofp11_port_h = ntohl(ofp11_port);

    if (ofp11_port_h < ofp_to_u16(OFPP_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h);
        return 0;
    } else if (ofp11_port_h >= ofp11_to_u32(OFPP11_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h - OFPP11_OFFSET);
        return 0;
    } else {
        *ofp10_port = OFPP_NONE;

        static struct vlog_rate_limit rll = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rll, "port %"PRIu32" is outside the supported "
                     "range 0 through %d or 0x%"PRIx32" through 0x%"PRIx32,
                     ofp11_port_h, ofp_to_u16(OFPP_MAX) - 1,
                     ofp11_to_u32(OFPP11_MAX), UINT32_MAX);

        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}

/* Returns the OpenFlow 1.1+ port number equivalent to the OpenFlow 1.0 port
 * number 'ofp10_port', for encoding OpenFlow 1.1+ protocol messages.
 *
 * See the definition of OFP11_MAX for an explanation of the mapping. */
ovs_be32
ofputil_port_to_ofp11(ofp_port_t ofp10_port)
{
    return htonl(ofp_to_u16(ofp10_port) < ofp_to_u16(OFPP_MAX)
                 ? ofp_to_u16(ofp10_port)
                 : ofp_to_u16(ofp10_port) + OFPP11_OFFSET);
}

#define OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(IN_PORT)             \
        OFPUTIL_NAMED_PORT(TABLE)               \
        OFPUTIL_NAMED_PORT(NORMAL)              \
        OFPUTIL_NAMED_PORT(FLOOD)               \
        OFPUTIL_NAMED_PORT(ALL)                 \
        OFPUTIL_NAMED_PORT(CONTROLLER)          \
        OFPUTIL_NAMED_PORT(LOCAL)               \
        OFPUTIL_NAMED_PORT(ANY)                 \
        OFPUTIL_NAMED_PORT(UNSET)

/* For backwards compatibility, so that "none" is recognized as OFPP_ANY */
#define OFPUTIL_NAMED_PORTS_WITH_NONE           \
        OFPUTIL_NAMED_PORTS                     \
        OFPUTIL_NAMED_PORT(NONE)

/* Stores the port number represented by 's' into '*portp'.  's' may be an
 * integer or, for reserved ports, the standard OpenFlow name for the port
 * (e.g. "LOCAL").  If 'port_map' is nonnull, also accepts names in it (quoted
 * or unquoted).
 *
 * Returns true if successful, false if 's' is not a valid OpenFlow port number
 * or name.  The caller should issue an error message in this case, because
 * this function usually does not.  (This gives the caller an opportunity to
 * look up the port name another way, e.g. by contacting the switch and listing
 * the names of all its ports).
 *
 * This function accepts OpenFlow 1.0 port numbers.  It also accepts a subset
 * of OpenFlow 1.1+ port numbers, mapping those port numbers into the 16-bit
 * range as described in include/openflow/openflow-1.1.h. */
bool
ofputil_port_from_string(const char *s,
                         const struct ofputil_port_map *port_map,
                         ofp_port_t *portp)
{
    unsigned int port32; /* int is at least 32 bits wide. */

    if (*s == '-') {
        VLOG_WARN("Negative value %s is not a valid port number.", s);
        return false;
    }
    *portp = 0;
    if (str_to_uint(s, 10, &port32)) {
        if (port32 < ofp_to_u16(OFPP_MAX)) {
            /* Pass. */
        } else if (port32 < ofp_to_u16(OFPP_FIRST_RESV)) {
            VLOG_WARN("port %u is a reserved OF1.0 port number that will "
                      "be translated to %u when talking to an OF1.1 or "
                      "later controller", port32, port32 + OFPP11_OFFSET);
        } else if (port32 <= ofp_to_u16(OFPP_LAST_RESV)) {
            char name[OFP10_MAX_PORT_NAME_LEN];

            ofputil_port_to_string(u16_to_ofp(port32), NULL,
                                   name, sizeof name);
            VLOG_WARN_ONCE("referring to port %s as %"PRIu32" is deprecated "
                           "for compatibility with OpenFlow 1.1 and later",
                           name, port32);
        } else if (port32 < ofp11_to_u32(OFPP11_MAX)) {
            VLOG_WARN("port %u is outside the supported range 0 through "
                      "%x or 0x%x through 0x%"PRIx32, port32,
                      UINT16_MAX, ofp11_to_u32(OFPP11_MAX), UINT32_MAX);
            return false;
        } else {
            port32 -= OFPP11_OFFSET;
        }

        *portp = u16_to_ofp(port32);
        return true;
    } else {
        struct pair {
            const char *name;
            ofp_port_t value;
        };
        static const struct pair pairs[] = {
#define OFPUTIL_NAMED_PORT(NAME) {#NAME, OFPP_##NAME},
            OFPUTIL_NAMED_PORTS_WITH_NONE
#undef OFPUTIL_NAMED_PORT
        };
        const struct pair *p;

        for (p = pairs; p < &pairs[ARRAY_SIZE(pairs)]; p++) {
            if (!strcasecmp(s, p->name)) {
                *portp = p->value;
                return true;
            }
        }

        ofp_port_t ofp_port = OFPP_NONE;
        if (s[0] != '"') {
            ofp_port = ofputil_port_map_get_number(port_map, s);
        } else {
            size_t length = strlen(s);
            char *name = NULL;
            if (length > 1
                && s[length - 1] == '"'
                && json_string_unescape(s + 1, length - 2, &name)) {
                ofp_port = ofputil_port_map_get_number(port_map, name);
            }
            free(name);
        }
        if (ofp_port != OFPP_NONE) {
            *portp = ofp_port;
            return true;
        }

        return false;
    }
}

const char *
ofputil_port_get_reserved_name(ofp_port_t port)
{
    switch (port) {
#define OFPUTIL_NAMED_PORT(NAME) case OFPP_##NAME: return #NAME;
        OFPUTIL_NAMED_PORTS
#undef OFPUTIL_NAMED_PORT

    default:
        return NULL;
    }
}

/* Appends to 's' a string representation of the OpenFlow port number 'port'.
 * Most ports' string representation is just the port number, but for special
 * ports, e.g. OFPP_LOCAL, it is the name, e.g. "LOCAL". */
void
ofputil_format_port(ofp_port_t port, const struct ofputil_port_map *port_map,
                    struct ds *s)
{
    const char *reserved_name = ofputil_port_get_reserved_name(port);
    if (reserved_name) {
        ds_put_cstr(s, reserved_name);
        return;
    }

    const char *port_name = ofputil_port_map_get_name(port_map, port);
    if (port_name) {
        namemap_put_name(port_name, s);
        return;
    }

    ds_put_format(s, "%"PRIu32, port);
}

/* Puts in the 'bufsize' byte in 'namebuf' a null-terminated string
 * representation of OpenFlow port number 'port'.  Most ports are represented
 * as just the port number, but special ports, e.g. OFPP_LOCAL, are represented
 * by name, e.g. "LOCAL". */
void
ofputil_port_to_string(ofp_port_t port,
                       const struct ofputil_port_map *port_map,
                       char *namebuf, size_t bufsize)
{
    const char *reserved_name = ofputil_port_get_reserved_name(port);
    if (reserved_name) {
        ovs_strlcpy(namebuf, reserved_name, bufsize);
        return;
    }

    const char *port_name = ofputil_port_map_get_name(port_map, port);
    if (port_name) {
        struct ds s = DS_EMPTY_INITIALIZER;
        namemap_put_name(port_name, &s);
        ovs_strlcpy(namebuf, ds_cstr(&s), bufsize);
        ds_destroy(&s);
        return;
    }

    snprintf(namebuf, bufsize, "%"PRIu32, port);
}

/* ofputil_port_config */

static const char *
ofputil_port_config_to_name(uint32_t bit)
{
    enum ofputil_port_config pc = bit;

    switch (pc) {
    case OFPUTIL_PC_PORT_DOWN:    return "PORT_DOWN";
    case OFPUTIL_PC_NO_STP:       return "NO_STP";
    case OFPUTIL_PC_NO_RECV:      return "NO_RECV";
    case OFPUTIL_PC_NO_RECV_STP:  return "NO_RECV_STP";
    case OFPUTIL_PC_NO_FLOOD:     return "NO_FLOOD";
    case OFPUTIL_PC_NO_FWD:       return "NO_FWD";
    case OFPUTIL_PC_NO_PACKET_IN: return "NO_PACKET_IN";
    }

    return NULL;
}

void
ofputil_port_config_format(struct ds *s, enum ofputil_port_config config)
{
    ofp_print_bit_names(s, config, ofputil_port_config_to_name, ' ');
    ds_put_char(s, '\n');
}

/* ofputil_port_state */

static const char *
ofputil_port_state_to_name(uint32_t bit)
{
    enum ofputil_port_state ps = bit;

    switch (ps) {
    case OFPUTIL_PS_LINK_DOWN: return "LINK_DOWN";
    case OFPUTIL_PS_BLOCKED:   return "BLOCKED";
    case OFPUTIL_PS_LIVE:      return "LIVE";

    case OFPUTIL_PS_STP_LISTEN:
    case OFPUTIL_PS_STP_LEARN:
    case OFPUTIL_PS_STP_FORWARD:
    case OFPUTIL_PS_STP_BLOCK:
        /* Handled elsewhere. */
        return NULL;
    }

    return NULL;
}

void
ofputil_port_state_format(struct ds *s, enum ofputil_port_state state)
{
    enum ofputil_port_state stp_state;

    /* The STP state is a 2-bit field so it doesn't fit in with the bitmask
     * pattern.  We have to special case it.
     *
     * OVS doesn't support STP, so this field will always be 0 if we are
     * talking to OVS, so we'd always print STP_LISTEN in that case.
     * Therefore, we don't print anything at all if the value is STP_LISTEN, to
     * avoid confusing users. */
    stp_state = state & OFPUTIL_PS_STP_MASK;
    if (stp_state) {
        ds_put_cstr(s, (stp_state == OFPUTIL_PS_STP_LEARN ? "STP_LEARN"
                        : stp_state == OFPUTIL_PS_STP_FORWARD ? "STP_FORWARD"
                        : "STP_BLOCK"));
        state &= ~OFPUTIL_PS_STP_MASK;
        if (state) {
            ofp_print_bit_names(s, state, ofputil_port_state_to_name, ' ');
        }
    } else {
        ofp_print_bit_names(s, state, ofputil_port_state_to_name, ' ');
    }
    ds_put_char(s, '\n');
}

/* ofputil_phy_port */

/* NETDEV_F_* to and from OFPPF_* and OFPPF10_*. */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_HD    == OFPPF_10MB_HD);  /* bit 0 */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_FD    == OFPPF_10MB_FD);  /* bit 1 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_HD   == OFPPF_100MB_HD); /* bit 2 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_FD   == OFPPF_100MB_FD); /* bit 3 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_HD     == OFPPF_1GB_HD);   /* bit 4 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_FD     == OFPPF_1GB_FD);   /* bit 5 */
BUILD_ASSERT_DECL((int) NETDEV_F_10GB_FD    == OFPPF_10GB_FD);  /* bit 6 */

/* NETDEV_F_ bits 11...15 are OFPPF10_ bits 7...11: */
BUILD_ASSERT_DECL((int) NETDEV_F_COPPER == (OFPPF10_COPPER << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_FIBER == (OFPPF10_FIBER << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_AUTONEG == (OFPPF10_AUTONEG << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE == (OFPPF10_PAUSE << 4));
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE_ASYM == (OFPPF10_PAUSE_ASYM << 4));

static enum netdev_features
netdev_port_features_from_ofp10(ovs_be32 ofp10_)
{
    uint32_t ofp10 = ntohl(ofp10_);
    return (ofp10 & 0x7f) | ((ofp10 & 0xf80) << 4);
}

static ovs_be32
netdev_port_features_to_ofp10(enum netdev_features features)
{
    return htonl((features & 0x7f) | ((features & 0xf800) >> 4));
}

BUILD_ASSERT_DECL((int) NETDEV_F_10MB_HD    == OFPPF_10MB_HD);     /* bit 0 */
BUILD_ASSERT_DECL((int) NETDEV_F_10MB_FD    == OFPPF_10MB_FD);     /* bit 1 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_HD   == OFPPF_100MB_HD);    /* bit 2 */
BUILD_ASSERT_DECL((int) NETDEV_F_100MB_FD   == OFPPF_100MB_FD);    /* bit 3 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_HD     == OFPPF_1GB_HD);      /* bit 4 */
BUILD_ASSERT_DECL((int) NETDEV_F_1GB_FD     == OFPPF_1GB_FD);      /* bit 5 */
BUILD_ASSERT_DECL((int) NETDEV_F_10GB_FD    == OFPPF_10GB_FD);     /* bit 6 */
BUILD_ASSERT_DECL((int) NETDEV_F_40GB_FD    == OFPPF11_40GB_FD);   /* bit 7 */
BUILD_ASSERT_DECL((int) NETDEV_F_100GB_FD   == OFPPF11_100GB_FD);  /* bit 8 */
BUILD_ASSERT_DECL((int) NETDEV_F_1TB_FD     == OFPPF11_1TB_FD);    /* bit 9 */
BUILD_ASSERT_DECL((int) NETDEV_F_OTHER      == OFPPF11_OTHER);     /* bit 10 */
BUILD_ASSERT_DECL((int) NETDEV_F_COPPER     == OFPPF11_COPPER);    /* bit 11 */
BUILD_ASSERT_DECL((int) NETDEV_F_FIBER      == OFPPF11_FIBER);     /* bit 12 */
BUILD_ASSERT_DECL((int) NETDEV_F_AUTONEG    == OFPPF11_AUTONEG);   /* bit 13 */
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE      == OFPPF11_PAUSE);     /* bit 14 */
BUILD_ASSERT_DECL((int) NETDEV_F_PAUSE_ASYM == OFPPF11_PAUSE_ASYM);/* bit 15 */

static enum netdev_features
netdev_port_features_from_ofp11(ovs_be32 ofp11)
{
    return ntohl(ofp11) & 0xffff;
}

static ovs_be32
netdev_port_features_to_ofp11(enum netdev_features features)
{
    return htonl(features & 0xffff);
}

static enum ofperr
ofputil_decode_ofp10_phy_port(struct ofputil_phy_port *pp,
                              const struct ofp10_phy_port *opp)
{
    pp->port_no = u16_to_ofp(ntohs(opp->port_no));
    pp->hw_addr = opp->hw_addr;
    ovs_strlcpy_arrays(pp->name, opp->name);

    pp->config = ntohl(opp->config) & OFPPC10_ALL;
    pp->state = ntohl(opp->state) & OFPPS10_ALL;

    pp->curr = netdev_port_features_from_ofp10(opp->curr);
    pp->advertised = netdev_port_features_from_ofp10(opp->advertised);
    pp->supported = netdev_port_features_from_ofp10(opp->supported);
    pp->peer = netdev_port_features_from_ofp10(opp->peer);

    pp->curr_speed = netdev_features_to_bps(pp->curr, 0) / 1000;
    pp->max_speed = netdev_features_to_bps(pp->supported, 0) / 1000;

    return 0;
}

static enum ofperr
ofputil_decode_ofp11_port(struct ofputil_phy_port *pp,
                          const struct ofp11_port *op)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    pp->curr = netdev_port_features_from_ofp11(op->curr);
    pp->advertised = netdev_port_features_from_ofp11(op->advertised);
    pp->supported = netdev_port_features_from_ofp11(op->supported);
    pp->peer = netdev_port_features_from_ofp11(op->peer);

    pp->curr_speed = ntohl(op->curr_speed);
    pp->max_speed = ntohl(op->max_speed);

    return 0;
}

static enum ofperr
parse_ofp14_port_ethernet_property(const struct ofpbuf *payload,
                                   struct ofputil_phy_port *pp)
{
    struct ofp14_port_desc_prop_ethernet *eth = payload->data;

    if (payload->size != sizeof *eth) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    pp->curr = netdev_port_features_from_ofp11(eth->curr);
    pp->advertised = netdev_port_features_from_ofp11(eth->advertised);
    pp->supported = netdev_port_features_from_ofp11(eth->supported);
    pp->peer = netdev_port_features_from_ofp11(eth->peer);

    pp->curr_speed = ntohl(eth->curr_speed);
    pp->max_speed = ntohl(eth->max_speed);

    return 0;
}

static enum ofperr
ofputil_pull_ofp14_port_properties(const void *props, size_t len,
                                   struct ofputil_phy_port *pp)
{
    struct ofpbuf properties = ofpbuf_const_initializer(props, len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPDPT14_ETHERNET:
            error = parse_ofp14_port_ethernet_property(&payload, pp);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "port", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

static enum ofperr
ofputil_pull_ofp14_port(struct ofputil_phy_port *pp, struct ofpbuf *msg)
{
    const struct ofp14_port *op = ofpbuf_try_pull(msg, sizeof *op);
    if (!op) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(op->length);
    if (len < sizeof *op || len - sizeof *op > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *op;

    enum ofperr error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    return ofputil_pull_ofp14_port_properties(ofpbuf_pull(msg, len), len, pp);
}

static enum ofperr
ofputil_pull_ofp16_port(struct ofputil_phy_port *pp, struct ofpbuf *msg)
{
    const struct ofp16_port *op = ofpbuf_try_pull(msg, sizeof *op);
    if (!op) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(op->length);
    if (len < sizeof *op || len - sizeof *op > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *op;

    enum ofperr error = ofputil_port_from_ofp11(op->port_no, &pp->port_no);
    if (error) {
        return error;
    }
    pp->hw_addr = op->hw_addr;
    pp->hw_addr64 = op->hw_addr64;
    ovs_strlcpy_arrays(pp->name, op->name);

    pp->config = ntohl(op->config) & OFPPC11_ALL;
    pp->state = ntohl(op->state) & OFPPS11_ALL;

    return ofputil_pull_ofp14_port_properties(ofpbuf_pull(msg, len), len, pp);
}

static void
ofputil_encode_ofp10_phy_port(const struct ofputil_phy_port *pp,
                              struct ofp10_phy_port *opp)
{
    memset(opp, 0, sizeof *opp);

    opp->port_no = htons(ofp_to_u16(pp->port_no));
    opp->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(opp->name, pp->name);

    opp->config = htonl(pp->config & OFPPC10_ALL);
    opp->state = htonl(pp->state & OFPPS10_ALL);

    opp->curr = netdev_port_features_to_ofp10(pp->curr);
    opp->advertised = netdev_port_features_to_ofp10(pp->advertised);
    opp->supported = netdev_port_features_to_ofp10(pp->supported);
    opp->peer = netdev_port_features_to_ofp10(pp->peer);
}

static void
ofputil_encode_ofp11_port(const struct ofputil_phy_port *pp,
                          struct ofp11_port *op)
{
    memset(op, 0, sizeof *op);

    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(op->name, pp->name);

    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    op->curr = netdev_port_features_to_ofp11(pp->curr);
    op->advertised = netdev_port_features_to_ofp11(pp->advertised);
    op->supported = netdev_port_features_to_ofp11(pp->supported);
    op->peer = netdev_port_features_to_ofp11(pp->peer);

    op->curr_speed = htonl(pp->curr_speed);
    op->max_speed = htonl(pp->max_speed);
}

static void
ofputil_encode_ofp14_port_ethernet_prop(
    const struct ofputil_phy_port *pp,
    struct ofp14_port_desc_prop_ethernet *eth)
{
    eth->curr = netdev_port_features_to_ofp11(pp->curr);
    eth->advertised = netdev_port_features_to_ofp11(pp->advertised);
    eth->supported = netdev_port_features_to_ofp11(pp->supported);
    eth->peer = netdev_port_features_to_ofp11(pp->peer);
    eth->curr_speed = htonl(pp->curr_speed);
    eth->max_speed = htonl(pp->max_speed);
}

static void
ofputil_put_ofp14_port(const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    struct ofp14_port *op;
    struct ofp14_port_desc_prop_ethernet *eth;

    ofpbuf_prealloc_tailroom(b, sizeof *op + sizeof *eth);

    op = ofpbuf_put_zeros(b, sizeof *op);
    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->length = htons(sizeof *op + sizeof *eth);
    op->hw_addr = pp->hw_addr;
    ovs_strlcpy_arrays(op->name, pp->name);
    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    eth = ofpprop_put_zeros(b, OFPPDPT14_ETHERNET, sizeof *eth);
    ofputil_encode_ofp14_port_ethernet_prop(pp, eth);
}

static void
ofputil_put_ofp16_port(const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    struct ofp16_port *op;
    struct ofp14_port_desc_prop_ethernet *eth;

    ofpbuf_prealloc_tailroom(b, sizeof *op + sizeof *eth);

    op = ofpbuf_put_zeros(b, sizeof *op);
    op->port_no = ofputil_port_to_ofp11(pp->port_no);
    op->length = htons(sizeof *op + sizeof *eth);
    op->hw_addr = pp->hw_addr;
    op->hw_addr64 = pp->hw_addr64;
    ovs_strlcpy_arrays(op->name, pp->name);
    op->config = htonl(pp->config & OFPPC11_ALL);
    op->state = htonl(pp->state & OFPPS11_ALL);

    eth = ofpprop_put_zeros(b, OFPPDPT14_ETHERNET, sizeof *eth);
    ofputil_encode_ofp14_port_ethernet_prop(pp, eth);
}

void
ofputil_put_phy_port(enum ofp_version ofp_version,
                     const struct ofputil_phy_port *pp, struct ofpbuf *b)
{
    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_phy_port *opp = ofpbuf_put_uninit(b, sizeof *opp);
        ofputil_encode_ofp10_phy_port(pp, opp);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port *op = ofpbuf_put_uninit(b, sizeof *op);
        ofputil_encode_ofp11_port(pp, op);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
        ofputil_put_ofp14_port(pp, b);
        break;
    case OFP16_VERSION:
        ofputil_put_ofp16_port(pp, b);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

enum ofperr
ofputil_decode_port_desc_stats_request(const struct ofp_header *request,
                                       ofp_port_t *port)
{
    struct ofpbuf b = ofpbuf_const_initializer(request,
                                               ntohs(request->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPST10_PORT_DESC_REQUEST) {
        *port = OFPP_ANY;
        return 0;
    } else if (raw == OFPRAW_OFPST15_PORT_DESC_REQUEST) {
        ovs_be32 *ofp11_port;

        ofp11_port = ofpbuf_pull(&b, sizeof *ofp11_port);
        return ofputil_port_from_ofp11(*ofp11_port, port);
    } else {
        OVS_NOT_REACHED();
    }
}

struct ofpbuf *
ofputil_encode_port_desc_stats_request(enum ofp_version ofp_version,
                                       ofp_port_t port)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
        request = ofpraw_alloc(OFPRAW_OFPST10_PORT_DESC_REQUEST,
                               ofp_version, 0);
        break;
    case OFP15_VERSION:
    case OFP16_VERSION:{
        struct ofp15_port_desc_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST15_PORT_DESC_REQUEST,
                               ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(port);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

void
ofputil_append_port_desc_stats_reply(const struct ofputil_phy_port *pp,
                                     struct ovs_list *replies)
{
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;

    ofputil_put_phy_port(ofpmp_version(replies), pp, reply);
    ofpmp_postappend(replies, start_ofs);
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', tries to pull the first element from the array.  If
 * successful, initializes '*pp' with an abstract representation of the
 * port and returns 0.  If no ports remain to be decoded, returns EOF.
 * On an error, returns a positive OFPERR_* value. */
int
ofputil_pull_phy_port(enum ofp_version ofp_version, struct ofpbuf *b,
                      struct ofputil_phy_port *pp)
{
    memset(pp, 0, sizeof *pp);

    switch (ofp_version) {
    case OFP10_VERSION: {
        const struct ofp10_phy_port *opp = ofpbuf_try_pull(b, sizeof *opp);
        return opp ? ofputil_decode_ofp10_phy_port(pp, opp) : EOF;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        const struct ofp11_port *op = ofpbuf_try_pull(b, sizeof *op);
        return op ? ofputil_decode_ofp11_port(pp, op) : EOF;
    }
    case OFP14_VERSION:
    case OFP15_VERSION:
        return b->size ? ofputil_pull_ofp14_port(pp, b) : EOF;
    case OFP16_VERSION:
        return b->size ? ofputil_pull_ofp16_port(pp, b) : EOF;
    default:
        OVS_NOT_REACHED();
    }
}

void
ofputil_phy_port_format(struct ds *s, const struct ofputil_phy_port *port)
{
    char name[sizeof port->name];
    int j;

    memcpy(name, port->name, sizeof name);
    for (j = 0; j < sizeof name - 1; j++) {
        if (!isprint((unsigned char) name[j])) {
            break;
        }
    }
    name[j] = '\0';

    ds_put_char(s, ' ');
    ofputil_format_port(port->port_no, NULL, s);
    ds_put_format(s, "(%s): addr:"ETH_ADDR_FMT"\n",
                  name, ETH_ADDR_ARGS(port->hw_addr));

    if (!eth_addr64_is_zero(port->hw_addr64)) {
        ds_put_format(s, "     addr64: "ETH_ADDR64_FMT"\n",
                      ETH_ADDR64_ARGS(port->hw_addr64));
    }

    ds_put_cstr(s, "     config:     ");
    ofputil_port_config_format(s, port->config);

    ds_put_cstr(s, "     state:      ");
    ofputil_port_state_format(s, port->state);

    if (port->curr) {
        ds_put_format(s, "     current:    ");
        netdev_features_format(s, port->curr);
    }
    if (port->advertised) {
        ds_put_format(s, "     advertised: ");
        netdev_features_format(s, port->advertised);
    }
    if (port->supported) {
        ds_put_format(s, "     supported:  ");
        netdev_features_format(s, port->supported);
    }
    if (port->peer) {
        ds_put_format(s, "     peer:       ");
        netdev_features_format(s, port->peer);
    }
    ds_put_format(s, "     speed: %"PRIu32" Mbps now, "
                  "%"PRIu32" Mbps max\n",
                  port->curr_speed / UINT32_C(1000),
                  port->max_speed / UINT32_C(1000));
}

/* qsort comparison function. */
static int
compare_ports(const void *a_, const void *b_)
{
    const struct ofputil_phy_port *a = a_;
    const struct ofputil_phy_port *b = b_;
    uint16_t ap = ofp_to_u16(a->port_no);
    uint16_t bp = ofp_to_u16(b->port_no);

    return ap < bp ? -1 : ap > bp;
}

/* Given a buffer 'b' that contains an array of OpenFlow ports of type
 * 'ofp_version', writes a detailed description of each port into 'string'. */
enum ofperr
ofputil_phy_ports_format(struct ds *string, uint8_t ofp_version,
                         struct ofpbuf *b)
{
    struct ofputil_phy_port *ports;
    size_t allocated_ports, n_ports;
    int retval;
    size_t i;

    ports = NULL;
    allocated_ports = 0;
    for (n_ports = 0; ; n_ports++) {
        if (n_ports >= allocated_ports) {
            ports = x2nrealloc(ports, &allocated_ports, sizeof *ports);
        }

        retval = ofputil_pull_phy_port(ofp_version, b, &ports[n_ports]);
        if (retval) {
            break;
        }
    }

    qsort(ports, n_ports, sizeof *ports, compare_ports);
    for (i = 0; i < n_ports; i++) {
        ofputil_phy_port_format(string, &ports[i]);
    }
    free(ports);

    return retval != EOF ? retval : 0;
}

/* ofputil_port_status */

/* Decodes the OpenFlow "port status" message in '*ops' into an abstract form
 * in '*ps'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_status(const struct ofp_header *oh,
                           struct ofputil_port_status *ps)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    const struct ofp_port_status *ops = ofpbuf_pull(&b, sizeof *ops);
    if (ops->reason != OFPPR_ADD &&
        ops->reason != OFPPR_DELETE &&
        ops->reason != OFPPR_MODIFY) {
        return OFPERR_NXBRC_BAD_REASON;
    }
    ps->reason = ops->reason;

    int retval = ofputil_pull_phy_port(oh->version, &b, &ps->desc);
    ovs_assert(retval != EOF);
    return retval;
}

/* Converts the abstract form of a "port status" message in '*ps' into an
 * OpenFlow message suitable for 'protocol', and returns that encoded form in
 * a buffer owned by the caller. */
struct ofpbuf *
ofputil_encode_port_status(const struct ofputil_port_status *ps,
                           enum ofputil_protocol protocol)
{
    struct ofp_port_status *ops;
    struct ofpbuf *b;
    enum ofp_version version;
    enum ofpraw raw;

    version = ofputil_protocol_to_ofp_version(protocol);
    switch (version) {
    case OFP10_VERSION:
        raw = OFPRAW_OFPT10_PORT_STATUS;
        break;

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
        raw = OFPRAW_OFPT11_PORT_STATUS;
        break;

    case OFP14_VERSION:
    case OFP15_VERSION:
        raw = OFPRAW_OFPT14_PORT_STATUS;
        break;

    case OFP16_VERSION:
        raw = OFPRAW_OFPT16_PORT_STATUS;
        break;

    default:
        OVS_NOT_REACHED();
    }

    b = ofpraw_alloc_xid(raw, version, htonl(0), 0);
    ops = ofpbuf_put_zeros(b, sizeof *ops);
    ops->reason = ps->reason;
    ofputil_put_phy_port(version, &ps->desc, b);
    ofpmsg_update_length(b);
    return b;
}

void
ofputil_port_status_format(struct ds *s,
                           const struct ofputil_port_status *ps)
{
    if (ps->reason == OFPPR_ADD) {
        ds_put_format(s, " ADD:");
    } else if (ps->reason == OFPPR_DELETE) {
        ds_put_format(s, " DEL:");
    } else if (ps->reason == OFPPR_MODIFY) {
        ds_put_format(s, " MOD:");
    }

    ofputil_phy_port_format(s, &ps->desc);
}

/* ofputil_port_mod */

static enum ofperr
parse_port_mod_ethernet_property(struct ofpbuf *property,
                                 struct ofputil_port_mod *pm)
{
    ovs_be32 advertise;
    enum ofperr error;

    error = ofpprop_parse_be32(property, &advertise);
    if (!error) {
        pm->advertise = netdev_port_features_from_ofp11(advertise);
    }
    return error;
}

static enum ofperr
ofputil_decode_ofp10_port_mod(const struct ofp10_port_mod *opm,
                              struct ofputil_port_mod *pm)
{
    pm->port_no = u16_to_ofp(ntohs(opm->port_no));
    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC10_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC10_ALL;
    pm->advertise = netdev_port_features_from_ofp10(opm->advertise);
    return 0;
}

static enum ofperr
ofputil_decode_ofp11_port_mod(const struct ofp11_port_mod *opm,
                              struct ofputil_port_mod *pm)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;
    pm->advertise = netdev_port_features_from_ofp11(opm->advertise);

    return 0;
}

static enum ofperr
ofputil_decode_ofp14_port_mod_properties(struct ofpbuf *b, bool loose,
                                         struct ofputil_port_mod *pm)
{
    while (b->size > 0) {
        struct ofpbuf property;
        enum ofperr error;
        uint64_t type;

        error = ofpprop_pull(b, &property, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPPMPT14_ETHERNET:
            error = parse_port_mod_ethernet_property(&property, pm);
            break;

        default:
            error = OFPPROP_UNKNOWN(loose, "port_mod", type);
            break;
        }

        if (error) {
            return error;
        }
    }
    return 0;
}

static enum ofperr
ofputil_decode_ofp14_port_mod(struct ofpbuf *b, bool loose,
                              struct ofputil_port_mod *pm)
{
    const struct ofp14_port_mod *opm = ofpbuf_pull(b, sizeof *opm);
    enum ofperr error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;

    return ofputil_decode_ofp14_port_mod_properties(b, loose, pm);
}

static enum ofperr
ofputil_decode_ofp16_port_mod(struct ofpbuf *b, bool loose,
                              struct ofputil_port_mod *pm)
{
    const struct ofp16_port_mod *opm = ofpbuf_pull(b, sizeof *opm);
    enum ofperr error = ofputil_port_from_ofp11(opm->port_no, &pm->port_no);
    if (error) {
        return error;
    }

    pm->hw_addr = opm->hw_addr;
    pm->hw_addr64 = opm->hw_addr64;
    pm->config = ntohl(opm->config) & OFPPC11_ALL;
    pm->mask = ntohl(opm->mask) & OFPPC11_ALL;

    return ofputil_decode_ofp14_port_mod_properties(b, loose, pm);
}

/* Decodes the OpenFlow "port mod" message in '*oh' into an abstract form in
 * '*pm'.  Returns 0 if successful, otherwise an OFPERR_* value. */
enum ofperr
ofputil_decode_port_mod(const struct ofp_header *oh,
                        struct ofputil_port_mod *pm, bool loose)
{
    memset(pm, 0, sizeof *pm);

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    enum ofperr error;
    if (raw == OFPRAW_OFPT10_PORT_MOD) {
        error = ofputil_decode_ofp10_port_mod(b.data, pm);
    } else if (raw == OFPRAW_OFPT11_PORT_MOD) {
        error = ofputil_decode_ofp11_port_mod(b.data, pm);
    } else if (raw == OFPRAW_OFPT14_PORT_MOD) {
        error = ofputil_decode_ofp14_port_mod(&b, loose, pm);
    } else if (raw == OFPRAW_OFPT16_PORT_MOD) {
        error = ofputil_decode_ofp16_port_mod(&b, loose, pm);
    } else {
        error = OFPERR_OFPBRC_BAD_TYPE;
    }

    pm->config &= pm->mask;
    return error;
}

/* Converts the abstract form of a "port mod" message in '*pm' into an OpenFlow
 * message suitable for 'protocol', and returns that encoded form in a buffer
 * owned by the caller. */
struct ofpbuf *
ofputil_encode_port_mod(const struct ofputil_port_mod *pm,
                        enum ofputil_protocol protocol)
{
    enum ofp_version ofp_version = ofputil_protocol_to_ofp_version(protocol);
    struct ofpbuf *b;

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT10_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = htons(ofp_to_u16(pm->port_no));
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC10_ALL);
        opm->mask = htonl(pm->mask & OFPPC10_ALL);
        opm->advertise = netdev_port_features_to_ofp10(pm->advertise);
        break;
    }

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION: {
        struct ofp11_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT11_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);
        opm->advertise = netdev_port_features_to_ofp11(pm->advertise);
        break;
    }
    case OFP14_VERSION:
    case OFP15_VERSION: {
        struct ofp14_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT14_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);

        if (pm->advertise) {
            ofpprop_put_be32(b, OFPPMPT14_ETHERNET,
                             netdev_port_features_to_ofp11(pm->advertise));
        }
        break;
    }
    case OFP16_VERSION: {
        struct ofp16_port_mod *opm;

        b = ofpraw_alloc(OFPRAW_OFPT16_PORT_MOD, ofp_version, 0);
        opm = ofpbuf_put_zeros(b, sizeof *opm);
        opm->port_no = ofputil_port_to_ofp11(pm->port_no);
        opm->hw_addr = pm->hw_addr;
        opm->hw_addr64 = pm->hw_addr64;
        opm->config = htonl(pm->config & OFPPC11_ALL);
        opm->mask = htonl(pm->mask & OFPPC11_ALL);

        if (pm->advertise) {
            ofpprop_put_be32(b, OFPPMPT14_ETHERNET,
                             netdev_port_features_to_ofp11(pm->advertise));
        }
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return b;
}

void
ofputil_port_mod_format(struct ds *s, const struct ofputil_port_mod *pm,
                        const struct ofputil_port_map *port_map)
{
    ds_put_cstr(s, " port: ");
    ofputil_format_port(pm->port_no, port_map, s);
    ds_put_format(s, ": addr:"ETH_ADDR_FMT"\n",
                  ETH_ADDR_ARGS(pm->hw_addr));
    if (!eth_addr64_is_zero(pm->hw_addr64)) {
        ds_put_format(s, "     addr64: "ETH_ADDR64_FMT"\n",
                      ETH_ADDR64_ARGS(pm->hw_addr64));
    }

    ds_put_cstr(s, "     config: ");
    ofputil_port_config_format(s, pm->config);

    ds_put_cstr(s, "     mask:   ");
    ofputil_port_config_format(s, pm->mask);

    ds_put_cstr(s, "     advertise: ");
    if (pm->advertise) {
        netdev_features_format(s, pm->advertise);
    } else {
        ds_put_cstr(s, "UNCHANGED\n");
    }
}

/* Encode a dump ports request for 'port', the encoded message
 * will be for OpenFlow version 'ofp_version'. Returns message
 * as a struct ofpbuf. Returns encoded message on success, NULL on error */
struct ofpbuf *
ofputil_encode_dump_ports_request(enum ofp_version ofp_version,
                                  ofp_port_t port)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP10_VERSION: {
        struct ofp10_port_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST10_PORT_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = htons(ofp_to_u16(port));
        break;
    }
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_port_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_PORT_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(port);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

static void
ofputil_port_stats_to_ofp10(const struct ofputil_port_stats *ops,
                            struct ofp10_port_stats *ps10)
{
    ps10->port_no = htons(ofp_to_u16(ops->port_no));
    memset(ps10->pad, 0, sizeof ps10->pad);
    put_32aligned_be64(&ps10->rx_packets, htonll(ops->stats.rx_packets));
    put_32aligned_be64(&ps10->tx_packets, htonll(ops->stats.tx_packets));
    put_32aligned_be64(&ps10->rx_bytes, htonll(ops->stats.rx_bytes));
    put_32aligned_be64(&ps10->tx_bytes, htonll(ops->stats.tx_bytes));
    put_32aligned_be64(&ps10->rx_dropped, htonll(ops->stats.rx_dropped));
    put_32aligned_be64(&ps10->tx_dropped, htonll(ops->stats.tx_dropped));
    put_32aligned_be64(&ps10->rx_errors, htonll(ops->stats.rx_errors));
    put_32aligned_be64(&ps10->tx_errors, htonll(ops->stats.tx_errors));
    put_32aligned_be64(&ps10->rx_frame_err,
                       htonll(ops->stats.rx_frame_errors));
    put_32aligned_be64(&ps10->rx_over_err, htonll(ops->stats.rx_over_errors));
    put_32aligned_be64(&ps10->rx_crc_err, htonll(ops->stats.rx_crc_errors));
    put_32aligned_be64(&ps10->collisions, htonll(ops->stats.collisions));
}

static void
ofputil_port_stats_to_ofp11(const struct ofputil_port_stats *ops,
                            struct ofp11_port_stats *ps11)
{
    ps11->port_no = ofputil_port_to_ofp11(ops->port_no);
    memset(ps11->pad, 0, sizeof ps11->pad);
    ps11->rx_packets = htonll(ops->stats.rx_packets);
    ps11->tx_packets = htonll(ops->stats.tx_packets);
    ps11->rx_bytes = htonll(ops->stats.rx_bytes);
    ps11->tx_bytes = htonll(ops->stats.tx_bytes);
    ps11->rx_dropped = htonll(ops->stats.rx_dropped);
    ps11->tx_dropped = htonll(ops->stats.tx_dropped);
    ps11->rx_errors = htonll(ops->stats.rx_errors);
    ps11->tx_errors = htonll(ops->stats.tx_errors);
    ps11->rx_frame_err = htonll(ops->stats.rx_frame_errors);
    ps11->rx_over_err = htonll(ops->stats.rx_over_errors);
    ps11->rx_crc_err = htonll(ops->stats.rx_crc_errors);
    ps11->collisions = htonll(ops->stats.collisions);
}

static void
ofputil_port_stats_to_ofp13(const struct ofputil_port_stats *ops,
                            struct ofp13_port_stats *ps13)
{
    ofputil_port_stats_to_ofp11(ops, &ps13->ps);
    ps13->duration_sec = htonl(ops->duration_sec);
    ps13->duration_nsec = htonl(ops->duration_nsec);
}

static void
ofputil_append_ofp14_port_stats(const struct ofputil_port_stats *ops,
                                struct ovs_list *replies)
{
    struct ofp14_port_stats_prop_ethernet *eth;
    struct intel_port_stats_rfc2819 *stats_rfc2819;
    struct intel_port_custom_stats *stats_custom;
    struct ofp14_port_stats *ps14;
    struct ofpbuf *reply;
    uint16_t i;
    ovs_be64 counter_value;
    size_t custom_stats_start, start_ofs;

    reply = ofpbuf_from_list(ovs_list_back(replies));
    start_ofs = reply->size;

    ps14 = ofpbuf_put_uninit(reply, sizeof *ps14);

    memset(ps14->pad, 0, sizeof ps14->pad);
    ps14->port_no = ofputil_port_to_ofp11(ops->port_no);
    ps14->duration_sec = htonl(ops->duration_sec);
    ps14->duration_nsec = htonl(ops->duration_nsec);
    ps14->rx_packets = htonll(ops->stats.rx_packets);
    ps14->tx_packets = htonll(ops->stats.tx_packets);
    ps14->rx_bytes = htonll(ops->stats.rx_bytes);
    ps14->tx_bytes = htonll(ops->stats.tx_bytes);
    ps14->rx_dropped = htonll(ops->stats.rx_dropped);
    ps14->tx_dropped = htonll(ops->stats.tx_dropped);
    ps14->rx_errors = htonll(ops->stats.rx_errors);
    ps14->tx_errors = htonll(ops->stats.tx_errors);

    eth = ofpprop_put_zeros(reply, OFPPSPT14_ETHERNET, sizeof *eth);
    eth->rx_frame_err = htonll(ops->stats.rx_frame_errors);
    eth->rx_over_err = htonll(ops->stats.rx_over_errors);
    eth->rx_crc_err = htonll(ops->stats.rx_crc_errors);
    eth->collisions = htonll(ops->stats.collisions);

    uint64_t prop_type_stats = OFPPROP_EXP(INTEL_VENDOR_ID,
                                     INTEL_PORT_STATS_RFC2819);

    stats_rfc2819 = ofpprop_put_zeros(reply, prop_type_stats,
                                      sizeof *stats_rfc2819);

    memset(stats_rfc2819->pad, 0, sizeof stats_rfc2819->pad);
    stats_rfc2819->rx_1_to_64_packets = htonll(ops->stats.rx_1_to_64_packets);
    stats_rfc2819->rx_65_to_127_packets =
        htonll(ops->stats.rx_65_to_127_packets);
    stats_rfc2819->rx_128_to_255_packets =
        htonll(ops->stats.rx_128_to_255_packets);
    stats_rfc2819->rx_256_to_511_packets =
        htonll(ops->stats.rx_256_to_511_packets);
    stats_rfc2819->rx_512_to_1023_packets =
        htonll(ops->stats.rx_512_to_1023_packets);
    stats_rfc2819->rx_1024_to_1522_packets =
        htonll(ops->stats.rx_1024_to_1522_packets);
    stats_rfc2819->rx_1523_to_max_packets =
        htonll(ops->stats.rx_1523_to_max_packets);

    stats_rfc2819->tx_1_to_64_packets = htonll(ops->stats.tx_1_to_64_packets);
    stats_rfc2819->tx_65_to_127_packets =
        htonll(ops->stats.tx_65_to_127_packets);
    stats_rfc2819->tx_128_to_255_packets =
        htonll(ops->stats.tx_128_to_255_packets);
    stats_rfc2819->tx_256_to_511_packets =
        htonll(ops->stats.tx_256_to_511_packets);
    stats_rfc2819->tx_512_to_1023_packets =
        htonll(ops->stats.tx_512_to_1023_packets);
    stats_rfc2819->tx_1024_to_1522_packets =
        htonll(ops->stats.tx_1024_to_1522_packets);
    stats_rfc2819->tx_1523_to_max_packets =
        htonll(ops->stats.tx_1523_to_max_packets);

    stats_rfc2819->tx_multicast_packets =
        htonll(ops->stats.tx_multicast_packets);
    stats_rfc2819->rx_broadcast_packets =
        htonll(ops->stats.rx_broadcast_packets);
    stats_rfc2819->tx_broadcast_packets =
        htonll(ops->stats.tx_broadcast_packets);
    stats_rfc2819->rx_undersized_errors =
        htonll(ops->stats.rx_undersized_errors);
    stats_rfc2819->rx_oversize_errors =
        htonll(ops->stats.rx_oversize_errors);
    stats_rfc2819->rx_fragmented_errors =
        htonll(ops->stats.rx_fragmented_errors);
    stats_rfc2819->rx_jabber_errors =
        htonll(ops->stats.rx_jabber_errors);

    if (ops->custom_stats.counters && ops->custom_stats.size) {
        custom_stats_start = reply->size;

        uint64_t prop_type_custom = OFPPROP_EXP(INTEL_VENDOR_ID,
                                                INTEL_PORT_STATS_CUSTOM);

        stats_custom = ofpprop_put_zeros(reply, prop_type_custom,
                                         sizeof *stats_custom);

        stats_custom->stats_array_size = htons(ops->custom_stats.size);

        for (i = 0; i < ops->custom_stats.size; i++) {
            uint8_t counter_size = strlen(ops->custom_stats.counters[i].name);
            /* Counter name size */
            ofpbuf_put(reply, &counter_size, sizeof(counter_size));
            /* Counter name */
            ofpbuf_put(reply, ops->custom_stats.counters[i].name,
                       counter_size);
            /* Counter value */
            counter_value = htonll(ops->custom_stats.counters[i].value);
            ofpbuf_put(reply, &counter_value,
                       sizeof(ops->custom_stats.counters[i].value));
        }

        ofpprop_end(reply, custom_stats_start);
    }

    ps14 = ofpbuf_at_assert(reply, start_ofs, sizeof *ps14);
    ps14->length = htons(reply->size - start_ofs);

    ofpmp_postappend(replies, start_ofs);
}

/* Encode a ports stat for 'ops' and append it to 'replies'. */
void
ofputil_append_port_stat(struct ovs_list *replies,
                         const struct ofputil_port_stats *ops)
{
    switch (ofpmp_version(replies)) {
    case OFP13_VERSION: {
        struct ofp13_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp13(ops, reply);
        break;
    }
    case OFP12_VERSION:
    case OFP11_VERSION: {
        struct ofp11_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp11(ops, reply);
        break;
    }

    case OFP10_VERSION: {
        struct ofp10_port_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_port_stats_to_ofp10(ops, reply);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION:
        ofputil_append_ofp14_port_stats(ops, replies);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static enum ofperr
ofputil_port_stats_from_ofp10(struct ofputil_port_stats *ops,
                              const struct ofp10_port_stats *ps10)
{

    ops->port_no = u16_to_ofp(ntohs(ps10->port_no));
    ops->stats.rx_packets = ntohll(get_32aligned_be64(&ps10->rx_packets));
    ops->stats.tx_packets = ntohll(get_32aligned_be64(&ps10->tx_packets));
    ops->stats.rx_bytes = ntohll(get_32aligned_be64(&ps10->rx_bytes));
    ops->stats.tx_bytes = ntohll(get_32aligned_be64(&ps10->tx_bytes));
    ops->stats.rx_dropped = ntohll(get_32aligned_be64(&ps10->rx_dropped));
    ops->stats.tx_dropped = ntohll(get_32aligned_be64(&ps10->tx_dropped));
    ops->stats.rx_errors = ntohll(get_32aligned_be64(&ps10->rx_errors));
    ops->stats.tx_errors = ntohll(get_32aligned_be64(&ps10->tx_errors));
    ops->stats.rx_frame_errors =
        ntohll(get_32aligned_be64(&ps10->rx_frame_err));
    ops->stats.rx_over_errors = ntohll(get_32aligned_be64(&ps10->rx_over_err));
    ops->stats.rx_crc_errors = ntohll(get_32aligned_be64(&ps10->rx_crc_err));
    ops->stats.collisions = ntohll(get_32aligned_be64(&ps10->collisions));
    ops->duration_sec = ops->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_port_stats_from_ofp11(struct ofputil_port_stats *ops,
                              const struct ofp11_port_stats *ps11)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(ps11->port_no, &ops->port_no);
    if (error) {
        return error;
    }

    ops->stats.rx_packets = ntohll(ps11->rx_packets);
    ops->stats.tx_packets = ntohll(ps11->tx_packets);
    ops->stats.rx_bytes = ntohll(ps11->rx_bytes);
    ops->stats.tx_bytes = ntohll(ps11->tx_bytes);
    ops->stats.rx_dropped = ntohll(ps11->rx_dropped);
    ops->stats.tx_dropped = ntohll(ps11->tx_dropped);
    ops->stats.rx_errors = ntohll(ps11->rx_errors);
    ops->stats.tx_errors = ntohll(ps11->tx_errors);
    ops->stats.rx_frame_errors = ntohll(ps11->rx_frame_err);
    ops->stats.rx_over_errors = ntohll(ps11->rx_over_err);
    ops->stats.rx_crc_errors = ntohll(ps11->rx_crc_err);
    ops->stats.collisions = ntohll(ps11->collisions);
    ops->duration_sec = ops->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_port_stats_from_ofp13(struct ofputil_port_stats *ops,
                              const struct ofp13_port_stats *ps13)
{
    enum ofperr error = ofputil_port_stats_from_ofp11(ops, &ps13->ps);
    if (!error) {
        ops->duration_sec = ntohl(ps13->duration_sec);
        ops->duration_nsec = ntohl(ps13->duration_nsec);
    }
    return error;
}

static enum ofperr
parse_ofp14_port_stats_ethernet_property(const struct ofpbuf *payload,
                                         struct ofputil_port_stats *ops)
{
    const struct ofp14_port_stats_prop_ethernet *eth = payload->data;

    if (payload->size != sizeof *eth) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    ops->stats.rx_frame_errors = ntohll(eth->rx_frame_err);
    ops->stats.rx_over_errors = ntohll(eth->rx_over_err);
    ops->stats.rx_crc_errors = ntohll(eth->rx_crc_err);
    ops->stats.collisions = ntohll(eth->collisions);

    return 0;
}

static enum ofperr
parse_intel_port_stats_rfc2819_property(const struct ofpbuf *payload,
                                        struct ofputil_port_stats *ops)
{
    const struct intel_port_stats_rfc2819 *rfc2819 = payload->data;

    if (payload->size != sizeof *rfc2819) {
        return OFPERR_OFPBPC_BAD_LEN;
    }
    ops->stats.rx_1_to_64_packets = ntohll(rfc2819->rx_1_to_64_packets);
    ops->stats.rx_65_to_127_packets = ntohll(rfc2819->rx_65_to_127_packets);
    ops->stats.rx_128_to_255_packets = ntohll(rfc2819->rx_128_to_255_packets);
    ops->stats.rx_256_to_511_packets = ntohll(rfc2819->rx_256_to_511_packets);
    ops->stats.rx_512_to_1023_packets =
        ntohll(rfc2819->rx_512_to_1023_packets);
    ops->stats.rx_1024_to_1522_packets =
        ntohll(rfc2819->rx_1024_to_1522_packets);
    ops->stats.rx_1523_to_max_packets =
        ntohll(rfc2819->rx_1523_to_max_packets);

    ops->stats.tx_1_to_64_packets = ntohll(rfc2819->tx_1_to_64_packets);
    ops->stats.tx_65_to_127_packets = ntohll(rfc2819->tx_65_to_127_packets);
    ops->stats.tx_128_to_255_packets = ntohll(rfc2819->tx_128_to_255_packets);
    ops->stats.tx_256_to_511_packets = ntohll(rfc2819->tx_256_to_511_packets);
    ops->stats.tx_512_to_1023_packets =
        ntohll(rfc2819->tx_512_to_1023_packets);
    ops->stats.tx_1024_to_1522_packets =
        ntohll(rfc2819->tx_1024_to_1522_packets);
    ops->stats.tx_1523_to_max_packets =
        ntohll(rfc2819->tx_1523_to_max_packets);

    ops->stats.tx_multicast_packets = ntohll(rfc2819->tx_multicast_packets);
    ops->stats.rx_broadcast_packets = ntohll(rfc2819->rx_broadcast_packets);
    ops->stats.tx_broadcast_packets = ntohll(rfc2819->tx_broadcast_packets);
    ops->stats.rx_undersized_errors = ntohll(rfc2819->rx_undersized_errors);

    ops->stats.rx_oversize_errors = ntohll(rfc2819->rx_oversize_errors);
    ops->stats.rx_fragmented_errors = ntohll(rfc2819->rx_fragmented_errors);
    ops->stats.rx_jabber_errors = ntohll(rfc2819->rx_jabber_errors);

    return 0;
}

static enum ofperr
parse_intel_port_custom_property(struct ofpbuf *payload,
                                 struct ofputil_port_stats *ops)
{
    const struct intel_port_custom_stats *custom_stats
        = ofpbuf_try_pull(payload, sizeof *custom_stats);
    if (!custom_stats) {
        return OFPERR_OFPBPC_BAD_LEN;
    }

    ops->custom_stats.size = ntohs(custom_stats->stats_array_size);

    ops->custom_stats.counters = xcalloc(ops->custom_stats.size,
                                         sizeof *ops->custom_stats.counters);

    for (int i = 0; i < ops->custom_stats.size; i++) {
        struct netdev_custom_counter *c = &ops->custom_stats.counters[i];

        /* Counter name. */
        uint8_t *name_len = ofpbuf_try_pull(payload, sizeof *name_len);
        char *name = name_len ? ofpbuf_try_pull(payload, *name_len) : NULL;
        if (!name_len || !name) {
            return OFPERR_OFPBPC_BAD_LEN;
        }

        size_t len = MIN(*name_len, sizeof c->name - 1);
        memcpy(c->name, name, len);
        c->name[len] = '\0';

        /* Counter value. */
        ovs_be64 *value = ofpbuf_try_pull(payload, sizeof *value);
        if (!value) {
            return OFPERR_OFPBPC_BAD_LEN;
        }
        c->value = ntohll(get_unaligned_be64(value));
    }

    return 0;
}

static enum ofperr
ofputil_pull_ofp14_port_stats(struct ofputil_port_stats *ops,
                              struct ofpbuf *msg)
{
    const struct ofp14_port_stats *ps14 = ofpbuf_try_pull(msg, sizeof *ps14);
    if (!ps14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    size_t len = ntohs(ps14->length);
    if (len < sizeof *ps14 || len - sizeof *ps14 > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *ps14;

    enum ofperr error = ofputil_port_from_ofp11(ps14->port_no, &ops->port_no);
    if (error) {
        return error;
    }

    ops->duration_sec = ntohl(ps14->duration_sec);
    ops->duration_nsec = ntohl(ps14->duration_nsec);
    ops->stats.rx_packets = ntohll(ps14->rx_packets);
    ops->stats.tx_packets = ntohll(ps14->tx_packets);
    ops->stats.rx_bytes = ntohll(ps14->rx_bytes);
    ops->stats.tx_bytes = ntohll(ps14->tx_bytes);
    ops->stats.rx_dropped = ntohll(ps14->rx_dropped);
    ops->stats.tx_dropped = ntohll(ps14->tx_dropped);
    ops->stats.rx_errors = ntohll(ps14->rx_errors);
    ops->stats.tx_errors = ntohll(ps14->tx_errors);


    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type = 0;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }
        switch (type) {
        case OFPPSPT14_ETHERNET:
            error = parse_ofp14_port_stats_ethernet_property(&payload, ops);
            break;
        case OFPPROP_EXP(INTEL_VENDOR_ID, INTEL_PORT_STATS_RFC2819):
            error = parse_intel_port_stats_rfc2819_property(&payload, ops);
            break;
        case OFPPROP_EXP(INTEL_VENDOR_ID, INTEL_PORT_STATS_CUSTOM):
            error = parse_intel_port_custom_property(&payload, ops);
            break;
        default:
            error = OFPPROP_UNKNOWN(true, "port stats", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Returns the number of port stats elements in OFPTYPE_PORT_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_port_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    for (size_t n = 0; ; n++) {
        struct ofputil_port_stats ps;
        if (ofputil_decode_port_stats(&ps, &b)) {
            return n;
        }
    }
}

/* Converts an OFPST_PORT_STATS reply in 'msg' into an abstract
 * ofputil_port_stats in 'ps'.
 *
 * Multiple OFPST_PORT_STATS replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_port_stats(struct ofputil_port_stats *ps, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    memset(&(ps->stats), 0xFF, sizeof (ps->stats));
    memset(&(ps->custom_stats), 0, sizeof (ps->custom_stats));

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_PORT_REPLY) {
        return ofputil_pull_ofp14_port_stats(ps, msg);
    } else if (raw == OFPRAW_OFPST13_PORT_REPLY) {
        const struct ofp13_port_stats *ps13;
        ps13 = ofpbuf_try_pull(msg, sizeof *ps13);
        if (!ps13) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp13(ps, ps13);
    } else if (raw == OFPRAW_OFPST11_PORT_REPLY) {
        const struct ofp11_port_stats *ps11;

        ps11 = ofpbuf_try_pull(msg, sizeof *ps11);
        if (!ps11) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp11(ps, ps11);
    } else if (raw == OFPRAW_OFPST10_PORT_REPLY) {
        const struct ofp10_port_stats *ps10;

        ps10 = ofpbuf_try_pull(msg, sizeof *ps10);
        if (!ps10) {
            goto bad_len;
        }
        return ofputil_port_stats_from_ofp10(ps, ps10);
    } else {
        OVS_NOT_REACHED();
    }

 bad_len:
    VLOG_WARN_RL(&rl, "OFPST_PORT reply has %"PRIu32" leftover "
                 "bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

static void
print_port_stat(struct ds *string, const char *leader, uint64_t stat, int more)
{
    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, stat);
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

static void
print_port_stat_cond(struct ds *string, const char *leader, uint64_t stat)
{
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%s%"PRIu64", ", leader, stat);
    }
}

void
ofputil_format_port_stats(struct ds *string,
                          const struct ofputil_port_stats *ps,
                          const struct ofputil_port_map *port_map)
{
    ds_put_cstr(string, "  port ");
    if (ofp_to_u16(ps->port_no) < 10) {
        ds_put_char(string, ' ');
    }
    ofputil_format_port(ps->port_no, port_map, string);

    ds_put_cstr(string, ": rx ");
    print_port_stat(string, "pkts=", ps->stats.rx_packets, 1);
    print_port_stat(string, "bytes=", ps->stats.rx_bytes, 1);
    print_port_stat(string, "drop=", ps->stats.rx_dropped, 1);
    print_port_stat(string, "errs=", ps->stats.rx_errors, 1);
    print_port_stat(string, "frame=", ps->stats.rx_frame_errors, 1);
    print_port_stat(string, "over=", ps->stats.rx_over_errors, 1);
    print_port_stat(string, "crc=", ps->stats.rx_crc_errors, 0);

    ds_put_cstr(string, "           tx ");
    print_port_stat(string, "pkts=", ps->stats.tx_packets, 1);
    print_port_stat(string, "bytes=", ps->stats.tx_bytes, 1);
    print_port_stat(string, "drop=", ps->stats.tx_dropped, 1);
    print_port_stat(string, "errs=", ps->stats.tx_errors, 1);
    print_port_stat(string, "coll=", ps->stats.collisions, 0);

    if (ps->duration_sec != UINT32_MAX) {
        ds_put_cstr(string, "           duration=");
        ofp_print_duration(string, ps->duration_sec, ps->duration_nsec);
        ds_put_char(string, '\n');
    }
    struct ds string_ext_stats = DS_EMPTY_INITIALIZER;

    ds_init(&string_ext_stats);

    print_port_stat_cond(&string_ext_stats, "1_to_64_packets=",
                         ps->stats.rx_1_to_64_packets);
    print_port_stat_cond(&string_ext_stats, "65_to_127_packets=",
                         ps->stats.rx_65_to_127_packets);
    print_port_stat_cond(&string_ext_stats, "128_to_255_packets=",
                         ps->stats.rx_128_to_255_packets);
    print_port_stat_cond(&string_ext_stats, "256_to_511_packets=",
                         ps->stats.rx_256_to_511_packets);
    print_port_stat_cond(&string_ext_stats, "512_to_1023_packets=",
                         ps->stats.rx_512_to_1023_packets);
    print_port_stat_cond(&string_ext_stats, "1024_to_1522_packets=",
                         ps->stats.rx_1024_to_1522_packets);
    print_port_stat_cond(&string_ext_stats, "1523_to_max_packets=",
                         ps->stats.rx_1523_to_max_packets);
    print_port_stat_cond(&string_ext_stats, "broadcast_packets=",
                         ps->stats.rx_broadcast_packets);
    print_port_stat_cond(&string_ext_stats, "undersized_errors=",
                         ps->stats.rx_undersized_errors);
    print_port_stat_cond(&string_ext_stats, "oversize_errors=",
                         ps->stats.rx_oversize_errors);
    print_port_stat_cond(&string_ext_stats, "rx_fragmented_errors=",
                         ps->stats.rx_fragmented_errors);
    print_port_stat_cond(&string_ext_stats, "rx_jabber_errors=",
                         ps->stats.rx_jabber_errors);

    if (string_ext_stats.length != 0) {
        /* If at least one statistics counter is reported: */
        ds_put_cstr(string, "           rx rfc2819 ");
        ds_put_buffer(string, string_ext_stats.string,
                      string_ext_stats.length);
        ds_put_cstr(string, "\n");
        ds_destroy(&string_ext_stats);
    }

    ds_init(&string_ext_stats);

    print_port_stat_cond(&string_ext_stats, "1_to_64_packets=",
                         ps->stats.tx_1_to_64_packets);
    print_port_stat_cond(&string_ext_stats, "65_to_127_packets=",
                         ps->stats.tx_65_to_127_packets);
    print_port_stat_cond(&string_ext_stats, "128_to_255_packets=",
                         ps->stats.tx_128_to_255_packets);
    print_port_stat_cond(&string_ext_stats, "256_to_511_packets=",
                         ps->stats.tx_256_to_511_packets);
    print_port_stat_cond(&string_ext_stats, "512_to_1023_packets=",
                         ps->stats.tx_512_to_1023_packets);
    print_port_stat_cond(&string_ext_stats, "1024_to_1522_packets=",
                         ps->stats.tx_1024_to_1522_packets);
    print_port_stat_cond(&string_ext_stats, "1523_to_max_packets=",
                         ps->stats.tx_1523_to_max_packets);
    print_port_stat_cond(&string_ext_stats, "multicast_packets=",
                         ps->stats.tx_multicast_packets);
    print_port_stat_cond(&string_ext_stats, "broadcast_packets=",
                         ps->stats.tx_broadcast_packets);

    if (string_ext_stats.length != 0) {
        /* If at least one statistics counter is reported: */
        ds_put_cstr(string, "           tx rfc2819 ");
        ds_put_buffer(string, string_ext_stats.string,
                      string_ext_stats.length);
        ds_put_cstr(string, "\n");
        ds_destroy(&string_ext_stats);
    }

    if (ps->custom_stats.size) {
        ds_put_cstr(string, "           CUSTOM Statistics");
        for (int i = 0; i < ps->custom_stats.size; i++) {
            /* 3 counters in the row */
            if (ps->custom_stats.counters[i].name[0]) {
                if (i % 3 == 0) {
                    ds_put_cstr(string, "\n");
                    ds_put_cstr(string, "                      ");
                } else {
                    ds_put_char(string, ' ');
                }
                ds_put_format(string, "%s=%"PRIu64",",
                              ps->custom_stats.counters[i].name,
                              ps->custom_stats.counters[i].value);
            }
        }
        ds_put_cstr(string, "\n");
    }
}


/* Parse a port status request message into a 16 bit OpenFlow 1.0
 * port number and stores the latter in '*ofp10_port'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_port_stats_request(const struct ofp_header *request,
                                  ofp_port_t *ofp10_port)
{
    switch ((enum ofp_version)request->version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_port_stats_request *psr11 = ofpmsg_body(request);
        return ofputil_port_from_ofp11(psr11->port_no, ofp10_port);
    }

    case OFP10_VERSION: {
        const struct ofp10_port_stats_request *psr10 = ofpmsg_body(request);
        *ofp10_port = u16_to_ofp(ntohs(psr10->port_no));
        return 0;
    }

    default:
        OVS_NOT_REACHED();
    }
}

