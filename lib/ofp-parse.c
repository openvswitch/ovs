/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#include "ofp-parse.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

#include "autopath.h"
#include "bundle.h"
#include "byte-order.h"
#include "dynamic-string.h"
#include "netdev.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "socket-util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_parse);

static uint32_t
str_to_u32(const char *str)
{
    char *tail;
    uint32_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static uint64_t
str_to_u64(const char *str)
{
    char *tail;
    uint64_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoull(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6])
{
    if (sscanf(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
        != ETH_ADDR_SCAN_COUNT) {
        ovs_fatal(0, "invalid mac address %s", str);
    }
}

static void
str_to_eth_dst(const char *str,
               uint8_t mac[ETH_ADDR_LEN], uint8_t mask[ETH_ADDR_LEN])
{
    if (sscanf(str, ETH_ADDR_SCAN_FMT"/"ETH_ADDR_SCAN_FMT,
               ETH_ADDR_SCAN_ARGS(mac), ETH_ADDR_SCAN_ARGS(mask))
        == ETH_ADDR_SCAN_COUNT * 2) {
        if (!flow_wildcards_is_dl_dst_mask_valid(mask)) {
            ovs_fatal(0, "%s: invalid Ethernet destination mask (only "
                      "00:00:00:00:00:00, 01:00:00:00:00:00, "
                      "fe:ff:ff:ff:ff:ff, and ff:ff:ff:ff:ff:ff are allowed)",
                      str);
        }
    } else if (sscanf(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
               == ETH_ADDR_SCAN_COUNT) {
        memset(mask, 0xff, ETH_ADDR_LEN);
    } else {
        ovs_fatal(0, "invalid mac address %s", str);
    }
}

static void
str_to_ip(const char *str_, ovs_be32 *ip, ovs_be32 *maskp)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in_addr in_addr;
    ovs_be32 mask;
    int retval;

    name = strtok_r(str, "/", &save_ptr);
    retval = name ? lookup_ip(name, &in_addr) : EINVAL;
    if (retval) {
        ovs_fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;

    netmask = strtok_r(NULL, "/", &save_ptr);
    if (netmask) {
        uint8_t o[4];
        if (sscanf(netmask, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
                   &o[0], &o[1], &o[2], &o[3]) == 4) {
            mask = htonl((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]);
        } else {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 32) {
                ovs_fatal(0, "%s: network prefix bits not between 1 and 32",
                          str);
            } else if (prefix == 32) {
                mask = htonl(UINT32_MAX);
            } else {
                mask = htonl(((1u << prefix) - 1) << (32 - prefix));
            }
        }
    } else {
        mask = htonl(UINT32_MAX);
    }
    *ip &= mask;

    if (maskp) {
        *maskp = mask;
    } else {
        if (mask != htonl(UINT32_MAX)) {
            ovs_fatal(0, "%s: netmask not allowed here", str_);
        }
    }

    free(str);
}

static void
str_to_tun_id(const char *str, ovs_be64 *tun_idp, ovs_be64 *maskp)
{
    uint64_t tun_id, mask;
    char *tail;

    errno = 0;
    tun_id = strtoull(str, &tail, 0);
    if (errno || (*tail != '\0' && *tail != '/')) {
        goto error;
    }

    if (*tail == '/') {
        mask = strtoull(tail + 1, &tail, 0);
        if (errno || *tail != '\0') {
            goto error;
        }
    } else {
        mask = UINT64_MAX;
    }

    *tun_idp = htonll(tun_id);
    *maskp = htonll(mask);
    return;

error:
    ovs_fatal(0, "%s: bad syntax for tunnel id", str);
}

static void
str_to_vlan_tci(const char *str, ovs_be16 *vlan_tcip, ovs_be16 *maskp)
{
    uint16_t vlan_tci, mask;
    char *tail;

    errno = 0;
    vlan_tci = strtol(str, &tail, 0);
    if (errno || (*tail != '\0' && *tail != '/')) {
        goto error;
    }

    if (*tail == '/') {
        mask = strtol(tail + 1, &tail, 0);
        if (errno || *tail != '\0') {
            goto error;
        }
    } else {
        mask = UINT16_MAX;
    }

    *vlan_tcip = htons(vlan_tci);
    *maskp = htons(mask);
    return;

error:
    ovs_fatal(0, "%s: bad syntax for vlan_tci", str);
}

static void
str_to_ipv6(const char *str_, struct in6_addr *addrp, struct in6_addr *maskp)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in6_addr addr, mask;
    int retval;

    name = strtok_r(str, "/", &save_ptr);
    retval = name ? lookup_ipv6(name, &addr) : EINVAL;
    if (retval) {
        ovs_fatal(0, "%s: could not convert to IPv6 address", str);
    }

    netmask = strtok_r(NULL, "/", &save_ptr);
    if (netmask) {
        int prefix = atoi(netmask);
        if (prefix <= 0 || prefix > 128) {
            ovs_fatal(0, "%s: network prefix bits not between 1 and 128",
                      str);
        } else {
            mask = ipv6_create_mask(prefix);
        }
    } else {
        mask = in6addr_exact;
    }
    *addrp = ipv6_addr_bitand(&addr, &mask);

    if (maskp) {
        *maskp = mask;
    } else {
        if (!ipv6_mask_is_exact(&mask)) {
            ovs_fatal(0, "%s: netmask not allowed here", str_);
        }
    }

    free(str);
}

static void *
put_action(struct ofpbuf *b, size_t size, uint16_t type)
{
    struct ofp_action_header *ah = ofpbuf_put_zeros(b, size);
    ah->type = htons(type);
    ah->len = htons(size);
    return ah;
}

static struct ofp_action_output *
put_output_action(struct ofpbuf *b, uint16_t port)
{
    struct ofp_action_output *oao = put_action(b, sizeof *oao, OFPAT_OUTPUT);
    oao->port = htons(port);
    return oao;
}

static void
put_enqueue_action(struct ofpbuf *b, uint16_t port, uint32_t queue)
{
    struct ofp_action_enqueue *oae = put_action(b, sizeof *oae, OFPAT_ENQUEUE);
    oae->port = htons(port);
    oae->queue_id = htonl(queue);
}

static void
put_dl_addr_action(struct ofpbuf *b, uint16_t type, const char *addr)
{
    struct ofp_action_dl_addr *oada = put_action(b, sizeof *oada, type);
    str_to_mac(addr, oada->dl_addr);
}


static bool
parse_port_name(const char *name, uint16_t *port)
{
    struct pair {
        const char *name;
        uint16_t value;
    };
    static const struct pair pairs[] = {
#define DEF_PAIR(NAME) {#NAME, OFPP_##NAME}
        DEF_PAIR(IN_PORT),
        DEF_PAIR(TABLE),
        DEF_PAIR(NORMAL),
        DEF_PAIR(FLOOD),
        DEF_PAIR(ALL),
        DEF_PAIR(CONTROLLER),
        DEF_PAIR(LOCAL),
        DEF_PAIR(NONE),
#undef DEF_PAIR
    };
    static const int n_pairs = ARRAY_SIZE(pairs);
    size_t i;

    for (i = 0; i < n_pairs; i++) {
        if (!strcasecmp(name, pairs[i].name)) {
            *port = pairs[i].value;
            return true;
        }
    }
    return false;
}

static void
str_to_action(char *str, struct ofpbuf *b)
{
    bool drop = false;
    int n_actions;
    char *pos;

    pos = str;
    n_actions = 0;
    for (;;) {
        char empty_string[] = "";
        char *act, *arg;
        size_t actlen;
        uint16_t port;

        pos += strspn(pos, ", \t\r\n");
        if (*pos == '\0') {
            break;
        }

        if (drop) {
            ovs_fatal(0, "Drop actions must not be followed by other actions");
        }

        act = pos;
        actlen = strcspn(pos, ":(, \t\r\n");
        if (act[actlen] == ':') {
            /* The argument can be separated by a colon. */
            size_t arglen;

            arg = act + actlen + 1;
            arglen = strcspn(arg, ", \t\r\n");
            pos = arg + arglen + (arg[arglen] != '\0');
            arg[arglen] = '\0';
        } else if (act[actlen] == '(') {
            /* The argument can be surrounded by balanced parentheses.  The
             * outermost set of parentheses is removed. */
            int level = 1;
            size_t arglen;

            arg = act + actlen + 1;
            for (arglen = 0; level > 0; arglen++) {
                switch (arg[arglen]) {
                case '\0':
                    ovs_fatal(0, "unbalanced parentheses in argument to %s "
                              "action", act);

                case '(':
                    level++;
                    break;

                case ')':
                    level--;
                    break;
                }
            }
            arg[arglen - 1] = '\0';
            pos = arg + arglen;
        } else {
            /* There might be no argument at all. */
            arg = empty_string;
            pos = act + actlen + (act[actlen] != '\0');
        }
        act[actlen] = '\0';

        if (!strcasecmp(act, "mod_vlan_vid")) {
            struct ofp_action_vlan_vid *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_VID);
            va->vlan_vid = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_vlan_pcp")) {
            struct ofp_action_vlan_pcp *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_PCP);
            va->vlan_pcp = str_to_u32(arg);
        } else if (!strcasecmp(act, "strip_vlan")) {
            struct ofp_action_header *ah;
            ah = put_action(b, sizeof *ah, OFPAT_STRIP_VLAN);
            ah->type = htons(OFPAT_STRIP_VLAN);
        } else if (!strcasecmp(act, "mod_dl_src")) {
            put_dl_addr_action(b, OFPAT_SET_DL_SRC, arg);
        } else if (!strcasecmp(act, "mod_dl_dst")) {
            put_dl_addr_action(b, OFPAT_SET_DL_DST, arg);
        } else if (!strcasecmp(act, "mod_nw_src")) {
            struct ofp_action_nw_addr *na;
            na = put_action(b, sizeof *na, OFPAT_SET_NW_SRC);
            str_to_ip(arg, &na->nw_addr, NULL);
        } else if (!strcasecmp(act, "mod_nw_dst")) {
            struct ofp_action_nw_addr *na;
            na = put_action(b, sizeof *na, OFPAT_SET_NW_DST);
            str_to_ip(arg, &na->nw_addr, NULL);
        } else if (!strcasecmp(act, "mod_tp_src")) {
            struct ofp_action_tp_port *ta;
            ta = put_action(b, sizeof *ta, OFPAT_SET_TP_SRC);
            ta->tp_port = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_tp_dst")) {
            struct ofp_action_tp_port *ta;
            ta = put_action(b, sizeof *ta, OFPAT_SET_TP_DST);
            ta->tp_port = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_nw_tos")) {
            struct ofp_action_nw_tos *nt;
            nt = put_action(b, sizeof *nt, OFPAT_SET_NW_TOS);
            nt->nw_tos = str_to_u32(arg);
        } else if (!strcasecmp(act, "resubmit")) {
            struct nx_action_resubmit *nar;
            nar = put_action(b, sizeof *nar, OFPAT_VENDOR);
            nar->vendor = htonl(NX_VENDOR_ID);
            nar->subtype = htons(NXAST_RESUBMIT);
            nar->in_port = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "set_tunnel")
                   || !strcasecmp(act, "set_tunnel64")) {
            uint64_t tun_id = str_to_u64(arg);
            if (!strcasecmp(act, "set_tunnel64") || tun_id > UINT32_MAX) {
                struct nx_action_set_tunnel64 *nast64;
                nast64 = put_action(b, sizeof *nast64, OFPAT_VENDOR);
                nast64->vendor = htonl(NX_VENDOR_ID);
                nast64->subtype = htons(NXAST_SET_TUNNEL64);
                nast64->tun_id = htonll(tun_id);
            } else {
                struct nx_action_set_tunnel *nast;
                nast = put_action(b, sizeof *nast, OFPAT_VENDOR);
                nast->vendor = htonl(NX_VENDOR_ID);
                nast->subtype = htons(NXAST_SET_TUNNEL);
                nast->tun_id = htonl(tun_id);
            }
        } else if (!strcasecmp(act, "set_queue")) {
            struct nx_action_set_queue *nasq;
            nasq = put_action(b, sizeof *nasq, OFPAT_VENDOR);
            nasq->vendor = htonl(NX_VENDOR_ID);
            nasq->subtype = htons(NXAST_SET_QUEUE);
            nasq->queue_id = htonl(str_to_u32(arg));
        } else if (!strcasecmp(act, "pop_queue")) {
            struct nx_action_header *nah;
            nah = put_action(b, sizeof *nah, OFPAT_VENDOR);
            nah->vendor = htonl(NX_VENDOR_ID);
            nah->subtype = htons(NXAST_POP_QUEUE);
        } else if (!strcasecmp(act, "note")) {
            size_t start_ofs = b->size;
            struct nx_action_note *nan;
            int remainder;
            size_t len;

            nan = put_action(b, sizeof *nan, OFPAT_VENDOR);
            nan->vendor = htonl(NX_VENDOR_ID);
            nan->subtype = htons(NXAST_NOTE);

            b->size -= sizeof nan->note;
            while (*arg != '\0') {
                uint8_t byte;
                bool ok;

                if (*arg == '.') {
                    arg++;
                }
                if (*arg == '\0') {
                    break;
                }

                byte = hexits_value(arg, 2, &ok);
                if (!ok) {
                    ovs_fatal(0, "bad hex digit in `note' argument");
                }
                ofpbuf_put(b, &byte, 1);

                arg += 2;
            }

            len = b->size - start_ofs;
            remainder = len % OFP_ACTION_ALIGN;
            if (remainder) {
                ofpbuf_put_zeros(b, OFP_ACTION_ALIGN - remainder);
            }
            nan = (struct nx_action_note *)((char *)b->data + start_ofs);
            nan->len = htons(b->size - start_ofs);
        } else if (!strcasecmp(act, "move")) {
            struct nx_action_reg_move *move;
            move = ofpbuf_put_uninit(b, sizeof *move);
            nxm_parse_reg_move(move, arg);
        } else if (!strcasecmp(act, "load")) {
            struct nx_action_reg_load *load;
            load = ofpbuf_put_uninit(b, sizeof *load);
            nxm_parse_reg_load(load, arg);
        } else if (!strcasecmp(act, "multipath")) {
            struct nx_action_multipath *nam;
            nam = ofpbuf_put_uninit(b, sizeof *nam);
            multipath_parse(nam, arg);
        } else if (!strcasecmp(act, "autopath")) {
            struct nx_action_autopath *naa;
            naa = ofpbuf_put_uninit(b, sizeof *naa);
            autopath_parse(naa, arg);
        } else if (!strcasecmp(act, "bundle")) {
            bundle_parse(b, arg);
        } else if (!strcasecmp(act, "bundle_load")) {
            bundle_parse_load(b, arg);
        } else if (!strcasecmp(act, "output")) {
            put_output_action(b, str_to_u32(arg));
        } else if (!strcasecmp(act, "enqueue")) {
            char *sp = NULL;
            char *port_s = strtok_r(arg, ":q", &sp);
            char *queue = strtok_r(NULL, "", &sp);
            if (port_s == NULL || queue == NULL) {
                ovs_fatal(0, "\"enqueue\" syntax is \"enqueue:PORT:QUEUE\"");
            }
            put_enqueue_action(b, str_to_u32(port_s), str_to_u32(queue));
        } else if (!strcasecmp(act, "drop")) {
            /* A drop action in OpenFlow occurs by just not setting
             * an action. */
            drop = true;
            if (n_actions) {
                ovs_fatal(0, "Drop actions must not be preceded by other "
                          "actions");
            }
        } else if (!strcasecmp(act, "CONTROLLER")) {
            struct ofp_action_output *oao;
            oao = put_output_action(b, OFPP_CONTROLLER);

            /* Unless a numeric argument is specified, we send the whole
             * packet to the controller. */
            if (arg[0] && (strspn(arg, "0123456789") == strlen(arg))) {
               oao->max_len = htons(str_to_u32(arg));
            } else {
                oao->max_len = htons(UINT16_MAX);
            }
        } else if (parse_port_name(act, &port)) {
            put_output_action(b, port);
        } else if (strspn(act, "0123456789") == strlen(act)) {
            put_output_action(b, str_to_u32(act));
        } else {
            ovs_fatal(0, "Unknown action: %s", act);
        }
        n_actions++;
    }
}

struct protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

static bool
parse_protocol(const char *name, const struct protocol **p_out)
{
    static const struct protocol protocols[] = {
        { "ip", ETH_TYPE_IP, 0 },
        { "arp", ETH_TYPE_ARP, 0 },
        { "icmp", ETH_TYPE_IP, IPPROTO_ICMP },
        { "tcp", ETH_TYPE_IP, IPPROTO_TCP },
        { "udp", ETH_TYPE_IP, IPPROTO_UDP },
        { "ipv6", ETH_TYPE_IPV6, 0 },
        { "ip6", ETH_TYPE_IPV6, 0 },
        { "icmp6", ETH_TYPE_IPV6, IPPROTO_ICMPV6 },
        { "tcp6", ETH_TYPE_IPV6, IPPROTO_TCP },
        { "udp6", ETH_TYPE_IPV6, IPPROTO_UDP },
    };
    const struct protocol *p;

    for (p = protocols; p < &protocols[ARRAY_SIZE(protocols)]; p++) {
        if (!strcmp(p->name, name)) {
            *p_out = p;
            return true;
        }
    }
    *p_out = NULL;
    return false;
}

#define FIELDS                                              \
    FIELD(F_TUN_ID,      "tun_id",      0)                  \
    FIELD(F_IN_PORT,     "in_port",     FWW_IN_PORT)        \
    FIELD(F_DL_VLAN,     "dl_vlan",     0)                  \
    FIELD(F_DL_VLAN_PCP, "dl_vlan_pcp", 0)                  \
    FIELD(F_VLAN_TCI,    "vlan_tci",    0)                  \
    FIELD(F_DL_SRC,      "dl_src",      FWW_DL_SRC)         \
    FIELD(F_DL_DST,      "dl_dst",      FWW_DL_DST | FWW_ETH_MCAST) \
    FIELD(F_DL_TYPE,     "dl_type",     FWW_DL_TYPE)        \
    FIELD(F_NW_SRC,      "nw_src",      0)                  \
    FIELD(F_NW_DST,      "nw_dst",      0)                  \
    FIELD(F_NW_PROTO,    "nw_proto",    FWW_NW_PROTO)       \
    FIELD(F_NW_TOS,      "nw_tos",      FWW_NW_TOS)         \
    FIELD(F_TP_SRC,      "tp_src",      FWW_TP_SRC)         \
    FIELD(F_TP_DST,      "tp_dst",      FWW_TP_DST)         \
    FIELD(F_ICMP_TYPE,   "icmp_type",   FWW_TP_SRC)         \
    FIELD(F_ICMP_CODE,   "icmp_code",   FWW_TP_DST)         \
    FIELD(F_ARP_SHA,     "arp_sha",     FWW_ARP_SHA)        \
    FIELD(F_ARP_THA,     "arp_tha",     FWW_ARP_THA)        \
    FIELD(F_IPV6_SRC,    "ipv6_src",    0)                  \
    FIELD(F_IPV6_DST,    "ipv6_dst",    0)                  \
    FIELD(F_ND_TARGET,   "nd_target",   FWW_ND_TARGET)      \
    FIELD(F_ND_SLL,      "nd_sll",      FWW_ARP_SHA)        \
    FIELD(F_ND_TLL,      "nd_tll",      FWW_ARP_THA)

enum field_index {
#define FIELD(ENUM, NAME, WILDCARD) ENUM,
    FIELDS
#undef FIELD
    N_FIELDS
};

struct field {
    enum field_index index;
    const char *name;
    flow_wildcards_t wildcard;  /* FWW_* bit. */
};

static void
ofp_fatal(const char *flow, bool verbose, const char *format, ...)
{
    va_list args;

    if (verbose) {
        fprintf(stderr, "%s:\n", flow);
    }

    va_start(args, format);
    ovs_fatal_valist(0, format, args);
}

static bool
parse_field_name(const char *name, const struct field **f_out)
{
    static const struct field fields[N_FIELDS] = {
#define FIELD(ENUM, NAME, WILDCARD) { ENUM, NAME, WILDCARD },
        FIELDS
#undef FIELD
    };
    const struct field *f;

    for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
        if (!strcmp(f->name, name)) {
            *f_out = f;
            return true;
        }
    }
    *f_out = NULL;
    return false;
}

static void
parse_field_value(struct cls_rule *rule, enum field_index index,
                  const char *value)
{
    uint8_t mac[ETH_ADDR_LEN], mac_mask[ETH_ADDR_LEN];
    ovs_be64 tun_id, tun_mask;
    ovs_be32 ip, mask;
    ovs_be16 tci, tci_mask;
    struct in6_addr ipv6, ipv6_mask;
    uint16_t port_no;

    switch (index) {
    case F_TUN_ID:
        str_to_tun_id(value, &tun_id, &tun_mask);
        cls_rule_set_tun_id_masked(rule, tun_id, tun_mask);
        break;

    case F_IN_PORT:
        if (!parse_port_name(value, &port_no)) {
            port_no = atoi(value);
        }
        cls_rule_set_in_port(rule, port_no);
        break;

    case F_DL_VLAN:
        cls_rule_set_dl_vlan(rule, htons(str_to_u32(value)));
        break;

    case F_DL_VLAN_PCP:
        cls_rule_set_dl_vlan_pcp(rule, str_to_u32(value));
        break;

    case F_VLAN_TCI:
        str_to_vlan_tci(value, &tci, &tci_mask);
        cls_rule_set_dl_tci_masked(rule, tci, tci_mask);
        break;

    case F_DL_SRC:
        str_to_mac(value, mac);
        cls_rule_set_dl_src(rule, mac);
        break;

    case F_DL_DST:
        str_to_eth_dst(value, mac, mac_mask);
        cls_rule_set_dl_dst_masked(rule, mac, mac_mask);
        break;

    case F_DL_TYPE:
        cls_rule_set_dl_type(rule, htons(str_to_u32(value)));
        break;

    case F_NW_SRC:
        str_to_ip(value, &ip, &mask);
        cls_rule_set_nw_src_masked(rule, ip, mask);
        break;

    case F_NW_DST:
        str_to_ip(value, &ip, &mask);
        cls_rule_set_nw_dst_masked(rule, ip, mask);
        break;

    case F_NW_PROTO:
        cls_rule_set_nw_proto(rule, str_to_u32(value));
        break;

    case F_NW_TOS:
        cls_rule_set_nw_tos(rule, str_to_u32(value));
        break;

    case F_TP_SRC:
        cls_rule_set_tp_src(rule, htons(str_to_u32(value)));
        break;

    case F_TP_DST:
        cls_rule_set_tp_dst(rule, htons(str_to_u32(value)));
        break;

    case F_ICMP_TYPE:
        cls_rule_set_icmp_type(rule, str_to_u32(value));
        break;

    case F_ICMP_CODE:
        cls_rule_set_icmp_code(rule, str_to_u32(value));
        break;

    case F_ARP_SHA:
        str_to_mac(value, mac);
        cls_rule_set_arp_sha(rule, mac);
        break;

    case F_ARP_THA:
        str_to_mac(value, mac);
        cls_rule_set_arp_tha(rule, mac);
        break;

    case F_IPV6_SRC:
        str_to_ipv6(value, &ipv6, &ipv6_mask);
        cls_rule_set_ipv6_src_masked(rule, &ipv6, &ipv6_mask);
        break;

    case F_IPV6_DST:
        str_to_ipv6(value, &ipv6, &ipv6_mask);
        cls_rule_set_ipv6_dst_masked(rule, &ipv6, &ipv6_mask);
        break;

    case F_ND_TARGET:
        str_to_ipv6(value, &ipv6, NULL);
        cls_rule_set_nd_target(rule, ipv6);
        break;

    case F_ND_SLL:
        str_to_mac(value, mac);
        cls_rule_set_arp_sha(rule, mac);
        break;

    case F_ND_TLL:
        str_to_mac(value, mac);
        cls_rule_set_arp_tha(rule, mac);
        break;

    case N_FIELDS:
        NOT_REACHED();
    }
}

static void
parse_reg_value(struct cls_rule *rule, int reg_idx, const char *value)
{
    /* This uses an oversized destination field (64 bits when 32 bits would do)
     * because some sscanf() implementations truncate the range of %i
     * directives, so that e.g. "%"SCNi16 interprets input of "0xfedc" as a
     * value of 0x7fff.  The other alternatives are to allow only a single
     * radix (e.g. decimal or hexadecimal) or to write more sophisticated
     * parsers. */
    unsigned long long int reg_value, reg_mask;

    if (!strcmp(value, "ANY") || !strcmp(value, "*")) {
        cls_rule_set_reg_masked(rule, reg_idx, 0, 0);
    } else if (sscanf(value, "%lli/%lli",
                      &reg_value, &reg_mask) == 2) {
        cls_rule_set_reg_masked(rule, reg_idx, reg_value, reg_mask);
    } else if (sscanf(value, "%lli", &reg_value)) {
        cls_rule_set_reg(rule, reg_idx, reg_value);
    } else {
        ovs_fatal(0, "register fields must take the form <value> "
                  "or <value>/<mask>");
    }
}

/* Convert 'str_' (as described in the Flow Syntax section of the ovs-ofctl man
 * page) into 'fm' for sending the specified flow_mod 'command' to a switch.
 * If 'actions' is specified, an action must be in 'string' and may be expanded
 * or reallocated.
 *
 * To parse syntax for an OFPT_FLOW_MOD (or NXT_FLOW_MOD), use an OFPFC_*
 * constant for 'command'.  To parse syntax for an OFPST_FLOW or
 * OFPST_AGGREGATE (or NXST_FLOW or NXST_AGGREGATE), use -1 for 'command'. */
void
parse_ofp_str(struct flow_mod *fm, int command, const char *str_, bool verbose)
{
    enum {
        F_OUT_PORT = 1 << 0,
        F_ACTIONS = 1 << 1,
        F_COOKIE = 1 << 2,
        F_TIMEOUT = 1 << 3,
        F_PRIORITY = 1 << 4
    } fields;
    char *string = xstrdup(str_);
    char *save_ptr = NULL;
    char *name;

    switch (command) {
    case -1:
        fields = F_OUT_PORT;
        break;

    case OFPFC_ADD:
        fields = F_ACTIONS | F_COOKIE | F_TIMEOUT | F_PRIORITY;
        break;

    case OFPFC_DELETE:
        fields = F_OUT_PORT;
        break;

    case OFPFC_DELETE_STRICT:
        fields = F_OUT_PORT | F_PRIORITY;
        break;

    case OFPFC_MODIFY:
        fields = F_ACTIONS | F_COOKIE;
        break;

    case OFPFC_MODIFY_STRICT:
        fields = F_ACTIONS | F_COOKIE | F_PRIORITY;
        break;

    default:
        NOT_REACHED();
    }

    cls_rule_init_catchall(&fm->cr, OFP_DEFAULT_PRIORITY);
    fm->cookie = htonll(0);
    fm->table_id = 0xff;
    fm->command = command;
    fm->idle_timeout = OFP_FLOW_PERMANENT;
    fm->hard_timeout = OFP_FLOW_PERMANENT;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = 0;
    if (fields & F_ACTIONS) {
        struct ofpbuf actions;
        char *act_str;

        act_str = strstr(string, "action");
        if (!act_str) {
            ofp_fatal(str_, verbose, "must specify an action");
        }
        *act_str = '\0';

        act_str = strchr(act_str + 1, '=');
        if (!act_str) {
            ofp_fatal(str_, verbose, "must specify an action");
        }

        act_str++;

        ofpbuf_init(&actions, sizeof(union ofp_action));
        str_to_action(act_str, &actions);
        fm->actions = ofpbuf_steal_data(&actions);
        fm->n_actions = actions.size / sizeof(union ofp_action);
    } else {
        fm->actions = NULL;
        fm->n_actions = 0;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            cls_rule_set_dl_type(&fm->cr, htons(p->dl_type));
            if (p->nw_proto) {
                cls_rule_set_nw_proto(&fm->cr, p->nw_proto);
            }
        } else {
            const struct field *f;
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ofp_fatal(str_, verbose, "field %s missing value", name);
            }

            if (!strcmp(name, "table")) {
                fm->table_id = atoi(value);
            } else if (!strcmp(name, "out_port")) {
                fm->out_port = atoi(value);
            } else if (fields & F_PRIORITY && !strcmp(name, "priority")) {
                fm->cr.priority = atoi(value);
            } else if (fields & F_TIMEOUT && !strcmp(name, "idle_timeout")) {
                fm->idle_timeout = atoi(value);
            } else if (fields & F_TIMEOUT && !strcmp(name, "hard_timeout")) {
                fm->hard_timeout = atoi(value);
            } else if (fields & F_COOKIE && !strcmp(name, "cookie")) {
                fm->cookie = htonll(str_to_u64(value));
            } else if (parse_field_name(name, &f)) {
                if (!strcmp(value, "*") || !strcmp(value, "ANY")) {
                    if (f->wildcard) {
                        fm->cr.wc.wildcards |= f->wildcard;
                        cls_rule_zero_wildcarded_fields(&fm->cr);
                    } else if (f->index == F_NW_SRC) {
                        cls_rule_set_nw_src_masked(&fm->cr, 0, 0);
                    } else if (f->index == F_NW_DST) {
                        cls_rule_set_nw_dst_masked(&fm->cr, 0, 0);
                    } else if (f->index == F_IPV6_SRC) {
                        cls_rule_set_ipv6_src_masked(&fm->cr,
                                &in6addr_any, &in6addr_any);
                    } else if (f->index == F_IPV6_DST) {
                        cls_rule_set_ipv6_dst_masked(&fm->cr,
                                &in6addr_any, &in6addr_any);
                    } else if (f->index == F_DL_VLAN) {
                        cls_rule_set_any_vid(&fm->cr);
                    } else if (f->index == F_DL_VLAN_PCP) {
                        cls_rule_set_any_pcp(&fm->cr);
                    } else {
                        NOT_REACHED();
                    }
                } else {
                    parse_field_value(&fm->cr, f->index, value);
                }
            } else if (!strncmp(name, "reg", 3)
                       && isdigit((unsigned char) name[3])) {
                unsigned int reg_idx = atoi(name + 3);
                if (reg_idx >= FLOW_N_REGS) {
                    if (verbose) {
                        fprintf(stderr, "%s:\n", str_);
                    }
                    ofp_fatal(str_, verbose, "only %d registers supported", FLOW_N_REGS);
                }
                parse_reg_value(&fm->cr, reg_idx, value);
            } else if (!strcmp(name, "duration")
                       || !strcmp(name, "n_packets")
                       || !strcmp(name, "n_bytes")) {
                /* Ignore these, so that users can feed the output of
                 * "ovs-ofctl dump-flows" back into commands that parse
                 * flows. */
            } else {
                ofp_fatal(str_, verbose, "unknown keyword %s", name);
            }
        }
    }

    free(string);
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) and appends the parsed OpenFlow message to 'packets'.
 * '*cur_format' should initially contain the flow format currently configured
 * on the connection; this function will add a message to change the flow
 * format and update '*cur_format', if this is necessary to add the parsed
 * flow. */
void
parse_ofp_flow_mod_str(struct list *packets, enum nx_flow_format *cur_format,
                       bool *flow_mod_table_id, char *string, uint16_t command,
                       bool verbose)
{
    enum nx_flow_format min_format, next_format;
    struct cls_rule rule_copy;
    struct ofpbuf actions;
    struct ofpbuf *ofm;
    struct flow_mod fm;

    ofpbuf_init(&actions, 64);
    parse_ofp_str(&fm, command, string, verbose);

    min_format = ofputil_min_flow_format(&fm.cr);
    next_format = MAX(*cur_format, min_format);
    if (next_format != *cur_format) {
        struct ofpbuf *sff = ofputil_make_set_flow_format(next_format);
        list_push_back(packets, &sff->list_node);
        *cur_format = next_format;
    }

    /* Normalize a copy of the rule.  This ensures that non-normalized flows
     * get logged but doesn't affect what gets sent to the switch, so that the
     * switch can do whatever it likes with the flow. */
    rule_copy = fm.cr;
    ofputil_normalize_rule(&rule_copy, next_format);

    if (fm.table_id != 0xff && !*flow_mod_table_id) {
        struct ofpbuf *sff = ofputil_make_flow_mod_table_id(true);
        list_push_back(packets, &sff->list_node);
        *flow_mod_table_id = true;
    }

    ofm = ofputil_encode_flow_mod(&fm, *cur_format, *flow_mod_table_id);
    list_push_back(packets, &ofm->list_node);

    ofpbuf_uninit(&actions);
}

/* Similar to parse_ofp_flow_mod_str(), except that the string is read from
 * 'stream' and the command is always OFPFC_ADD.  Returns false if end-of-file
 * is reached before reading a flow, otherwise true. */
bool
parse_ofp_flow_mod_file(struct list *packets,
                        enum nx_flow_format *cur, bool *flow_mod_table_id,
                        FILE *stream, uint16_t command)
{
    struct ds s;
    bool ok;

    ds_init(&s);
    ok = ds_get_preprocessed_line(&s, stream) == 0;
    if (ok) {
        parse_ofp_flow_mod_str(packets, cur, flow_mod_table_id,
                               ds_cstr(&s), command, true);
    }
    ds_destroy(&s);

    return ok;
}

void
parse_ofp_flow_stats_request_str(struct flow_stats_request *fsr,
                                 bool aggregate, char *string)
{
    struct flow_mod fm;

    parse_ofp_str(&fm, -1, string, false);
    fsr->aggregate = aggregate;
    fsr->match = fm.cr;
    fsr->out_port = fm.out_port;
    fsr->table_id = fm.table_id;
}
