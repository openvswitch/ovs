/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_ACTIONS_H
#define OVN_ACTIONS_H 1

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "openvswitch/hmap.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

struct expr;
struct lexer;
struct ofpbuf;
struct shash;
struct simap;

#define MAX_OVN_GROUPS 65535

struct group_table {
    unsigned long *group_ids;  /* Used as a bitmap with value set
                                * for allocated group ids in either
                                * desired_groups or existing_groups. */
    struct hmap desired_groups;
    struct hmap existing_groups;
};

struct group_info {
    struct hmap_node hmap_node;
    struct ds group;
    uint32_t group_id;
};

enum action_opcode {
    /* "arp { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ARP,

    /* "put_arp(port, ip, mac)"
     *
     * Arguments are passed through the packet metadata and data, as follows:
     *
     *     MFF_REG0 = ip
     *     MFF_LOG_INPORT = port
     *     MFF_ETH_SRC = mac
     */
    ACTION_OPCODE_PUT_ARP,

    /* "result = put_dhcp_opts(offer_ip, option, ...)".
     *
     * Arguments follow the action_header, in this format:
     *   - A 32-bit or 64-bit OXM header designating the result field.
     *   - A 32-bit integer specifying a bit offset within the result field.
     *   - The 32-bit DHCP offer IP.
     *   - Any number of DHCP options.
     */
    ACTION_OPCODE_PUT_DHCP_OPTS,

    /* "nd_na { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ND_NA,
};

/* Header. */
struct action_header {
    ovs_be32 opcode;            /* One of ACTION_OPCODE_* */
    uint8_t pad[4];
};
BUILD_ASSERT_DECL(sizeof(struct action_header) == 8);

struct action_params {
    /* A table of "struct expr_symbol"s to support (as one would provide to
     * expr_parse()). */
    const struct shash *symtab;

    /* hmap of 'struct dhcp_opts_map'  to support 'put_dhcp_opts' action */
    const struct hmap *dhcp_opts;

    /* Looks up logical port 'port_name'.  If found, stores its port number in
     * '*portp' and returns true; otherwise, returns false. */
    bool (*lookup_port)(const void *aux, const char *port_name,
                        unsigned int *portp);
    const void *aux;

    /* A map from a port name to its connection tracking zone. */
    const struct simap *ct_zones;

    /* A struct to figure out the group_id for group actions. */
    struct group_table *group_table;

    /* OVN maps each logical flow table (ltable), one-to-one, onto a physical
     * OpenFlow flow table (ptable).  A number of parameters describe this
     * mapping and data related to flow tables:
     *
     *     - 'first_ptable' and 'n_tables' define the range of OpenFlow tables
     *        to which the logical "next" action should be able to jump.
     *        Logical table 0 maps to OpenFlow table 'first_ptable', logical
     *        table 1 to 'first_ptable + 1', and so on.  If 'n_tables' is 0
     *        then "next" is disallowed entirely.
     *
     *     - 'cur_ltable' is an offset from 'first_ptable' (e.g. 0 <=
     *       cur_ltable < n_ptables) of the logical flow that contains the
     *       actions.  If cur_ltable + 1 < n_tables, then this defines the
     *       default table that "next" will jump to.
     *
     *     - 'output_ptable' should be the OpenFlow table to which the logical
     *       "output" action will resubmit. */
    uint8_t n_tables;           /* Number of flow tables. */
    uint8_t first_ptable;       /* First OpenFlow table. */
    uint8_t cur_ltable;         /* 0 <= cur_ltable < n_tables. */
    uint8_t output_ptable;      /* OpenFlow table for 'output' to resubmit. */
    uint8_t arp_ptable;         /* OpenFlow table for 'get_arp' to resubmit. */
};

char *actions_parse(struct lexer *, const struct action_params *,
                    struct ofpbuf *ofpacts, struct expr **prereqsp)
    OVS_WARN_UNUSED_RESULT;
char *actions_parse_string(const char *s, const struct action_params *,
                           struct ofpbuf *ofpacts, struct expr **prereqsp)
    OVS_WARN_UNUSED_RESULT;

#endif /* ovn/actions.h */
