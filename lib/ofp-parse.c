/*
 * Copyright (c) 2010 Nicira Networks.
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

#include <errno.h>
#include <stdlib.h>

#include "netdev.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "socket-util.h"
#include "vconn.h"
#include "vlog.h"


VLOG_DEFINE_THIS_MODULE(ofp_parse)

#define DEFAULT_IDLE_TIMEOUT 60

static uint32_t
str_to_u32(const char *str)
{
    char *tail;
    uint32_t value;

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

static uint32_t
str_to_ip(const char *str_, uint32_t *ip)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in_addr in_addr;
    int n_wild, retval;

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
            uint32_t nm = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
            int i;

            /* Find first 1-bit. */
            for (i = 0; i < 32; i++) {
                if (nm & (1u << i)) {
                    break;
                }
            }
            n_wild = i;

            /* Verify that the rest of the bits are 1-bits. */
            for (; i < 32; i++) {
                if (!(nm & (1u << i))) {
                    ovs_fatal(0, "%s: %s is not a valid netmask",
                              str, netmask);
                }
            }
        } else {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 32) {
                ovs_fatal(0, "%s: network prefix bits not between 1 and 32",
                          str);
            }
            n_wild = 32 - prefix;
        }
    } else {
        n_wild = 0;
    }

    free(str);
    return n_wild;
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
    char *act, *arg;
    char *saveptr = NULL;
    bool drop = false;
    int n_actions;

    for (act = strtok_r(str, ", \t\r\n", &saveptr), n_actions = 0; act;
         act = strtok_r(NULL, ", \t\r\n", &saveptr), n_actions++)
    {
        uint16_t port;

        if (drop) {
            ovs_fatal(0, "Drop actions must not be followed by other actions");
        }

        /* Arguments are separated by colons */
        arg = strchr(act, ':');
        if (arg) {
            *arg = '\0';
            arg++;
        }

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
            str_to_ip(arg, &na->nw_addr);
        } else if (!strcasecmp(act, "mod_nw_dst")) {
            struct ofp_action_nw_addr *na;
            na = put_action(b, sizeof *na, OFPAT_SET_NW_DST);
            str_to_ip(arg, &na->nw_addr);
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
        } else if (!strcasecmp(act, "set_tunnel")) {
            struct nx_action_set_tunnel *nast;
            nast = put_action(b, sizeof *nast, OFPAT_VENDOR);
            nast->vendor = htonl(NX_VENDOR_ID);
            nast->subtype = htons(NXAST_SET_TUNNEL);
            nast->tun_id = htonl(str_to_u32(arg));
        } else if (!strcasecmp(act, "drop_spoofed_arp")) {
            struct nx_action_header *nah;
            nah = put_action(b, sizeof *nah, OFPAT_VENDOR);
            nah->vendor = htonl(NX_VENDOR_ID);
            nah->subtype = htons(NXAST_DROP_SPOOFED_ARP);
        } else if (!strcasecmp(act, "output")) {
            put_output_action(b, str_to_u32(arg));
        } else if (!strcasecmp(act, "enqueue")) {
            char *sp = NULL;
            char *port = strtok_r(arg, ":q", &sp);
            char *queue = strtok_r(NULL, "", &sp);
            if (port == NULL || queue == NULL) {
                ovs_fatal(0, "\"enqueue\" syntax is \"enqueue:PORT:QUEUE\"");
            }
            put_enqueue_action(b, str_to_u32(port), str_to_u32(queue));
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
            if (arg && (strspn(arg, "0123456789") == strlen(arg))) {
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
        { "icmp", ETH_TYPE_IP, IP_TYPE_ICMP },
        { "tcp", ETH_TYPE_IP, IP_TYPE_TCP },
        { "udp", ETH_TYPE_IP, IP_TYPE_UDP },
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

struct field {
    const char *name;
    uint32_t wildcard;
    enum { F_U8, F_U16, F_MAC, F_IP } type;
    size_t offset, shift;
};

static bool
parse_field(const char *name, const struct field **f_out)
{
#define F_OFS(MEMBER) offsetof(struct ofp_match, MEMBER)
    static const struct field fields[] = {
        { "in_port", OFPFW_IN_PORT, F_U16, F_OFS(in_port), 0 },
        { "dl_vlan", OFPFW_DL_VLAN, F_U16, F_OFS(dl_vlan), 0 },
        { "dl_vlan_pcp", OFPFW_DL_VLAN_PCP, F_U8, F_OFS(dl_vlan_pcp), 0 },
        { "dl_src", OFPFW_DL_SRC, F_MAC, F_OFS(dl_src), 0 },
        { "dl_dst", OFPFW_DL_DST, F_MAC, F_OFS(dl_dst), 0 },
        { "dl_type", OFPFW_DL_TYPE, F_U16, F_OFS(dl_type), 0 },
        { "nw_src", OFPFW_NW_SRC_MASK, F_IP,
          F_OFS(nw_src), OFPFW_NW_SRC_SHIFT },
        { "nw_dst", OFPFW_NW_DST_MASK, F_IP,
          F_OFS(nw_dst), OFPFW_NW_DST_SHIFT },
        { "nw_proto", OFPFW_NW_PROTO, F_U8, F_OFS(nw_proto), 0 },
        { "nw_tos", OFPFW_NW_TOS, F_U8, F_OFS(nw_tos), 0 },
        { "tp_src", OFPFW_TP_SRC, F_U16, F_OFS(tp_src), 0 },
        { "tp_dst", OFPFW_TP_DST, F_U16, F_OFS(tp_dst), 0 },
        { "icmp_type", OFPFW_ICMP_TYPE, F_U16, F_OFS(icmp_type), 0 },
        { "icmp_code", OFPFW_ICMP_CODE, F_U16, F_OFS(icmp_code), 0 }
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

/* Convert 'string' (as described in the Flow Syntax section of the
 * ovs-ofctl man page) into 'match'.  The other arguments are optional
 * and may be NULL if their value is not needed.  If 'actions' is
 * specified, an action must be in 'string' and may be expanded or
 * reallocated. */
void
parse_ofp_str(char *string, struct ofp_match *match, struct ofpbuf *actions,
              uint8_t *table_idx, uint16_t *out_port, uint16_t *priority,
              uint16_t *idle_timeout, uint16_t *hard_timeout,
              uint64_t *cookie)
{
    struct ofp_match normalized;
    char *save_ptr = NULL;
    char *name;
    uint32_t wildcards;

    if (table_idx) {
        *table_idx = 0xff;
    }
    if (out_port) {
        *out_port = OFPP_NONE;
    }
    if (priority) {
        *priority = OFP_DEFAULT_PRIORITY;
    }
    if (idle_timeout) {
        *idle_timeout = DEFAULT_IDLE_TIMEOUT;
    }
    if (hard_timeout) {
        *hard_timeout = OFP_FLOW_PERMANENT;
    }
    if (cookie) {
        *cookie = 0;
    }
    if (actions) {
        char *act_str = strstr(string, "action");
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }
        *act_str = '\0';

        act_str = strchr(act_str + 1, '=');
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }

        act_str++;

        str_to_action(act_str, actions);
    }
    memset(match, 0, sizeof *match);
    wildcards = OFPFW_ALL;
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            wildcards &= ~OFPFW_DL_TYPE;
            match->dl_type = htons(p->dl_type);
            if (p->nw_proto) {
                wildcards &= ~OFPFW_NW_PROTO;
                match->nw_proto = p->nw_proto;
            }
        } else {
            const struct field *f;
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ovs_fatal(0, "field %s missing value", name);
            }

            if (table_idx && !strcmp(name, "table")) {
                *table_idx = atoi(value);
            } else if (out_port && !strcmp(name, "out_port")) {
                *out_port = atoi(value);
            } else if (priority && !strcmp(name, "priority")) {
                *priority = atoi(value);
            } else if (idle_timeout && !strcmp(name, "idle_timeout")) {
                *idle_timeout = atoi(value);
            } else if (hard_timeout && !strcmp(name, "hard_timeout")) {
                *hard_timeout = atoi(value);
            } else if (cookie && !strcmp(name, "cookie")) {
                *cookie = str_to_u64(value);
            } else if (!strcmp(name, "tun_id_wild")) {
                wildcards |= NXFW_TUN_ID;
            } else if (parse_field(name, &f)) {
                void *data = (char *) match + f->offset;
                if (!strcmp(value, "*") || !strcmp(value, "ANY")) {
                    wildcards |= f->wildcard;
                } else {
                    wildcards &= ~f->wildcard;
                    if (f->wildcard == OFPFW_IN_PORT
                        && parse_port_name(value, (uint16_t *) data)) {
                        /* Nothing to do. */
                    } else if (f->type == F_U8) {
                        *(uint8_t *) data = str_to_u32(value);
                    } else if (f->type == F_U16) {
                        *(uint16_t *) data = htons(str_to_u32(value));
                    } else if (f->type == F_MAC) {
                        str_to_mac(value, data);
                    } else if (f->type == F_IP) {
                        wildcards |= str_to_ip(value, data) << f->shift;
                    } else {
                        NOT_REACHED();
                    }
                }
            } else {
                ovs_fatal(0, "unknown keyword %s", name);
            }
        }
    }
    match->wildcards = htonl(wildcards);

    normalized = *match;
    normalize_match(&normalized);
    if (memcmp(match, &normalized, sizeof normalized)) {
        char *old = ofp_match_to_literal_string(match);
        char *new = ofp_match_to_literal_string(&normalized);
        VLOG_WARN("The specified flow is not in normal form:");
        VLOG_WARN(" as specified: %s", old);
        VLOG_WARN("as normalized: %s", new);
        free(old);
        free(new);
    }
}
