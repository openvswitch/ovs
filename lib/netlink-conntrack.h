/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef NETLINK_CONNTRACK_H
#define NETLINK_CONNTRACK_H

#include <linux/netfilter/nfnetlink_cttimeout.h>

#include "byte-order.h"
#include "compiler.h"
#include "ct-dpif.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/ofpbuf.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

enum nl_ct_event_type {
    NL_CT_EVENT_NEW    = 1 << 0,
    NL_CT_EVENT_UPDATE = 1 << 1,
    NL_CT_EVENT_DELETE = 1 << 2,
};

#define NL_CT_TIMEOUT_POLICY_MAX_ATTR (CTA_TIMEOUT_TCP_MAX + 1)

struct nl_ct_timeout_policy {
    char        name[CTNL_TIMEOUT_NAME_MAX];
    uint16_t    l3num;
    uint8_t     l4num;
    uint32_t    attrs[NL_CT_TIMEOUT_POLICY_MAX_ATTR];
    uint32_t    present;
};

struct nl_ct_dump_state;
struct nl_ct_timeout_policy_dump_state;

int nl_ct_dump_start(struct nl_ct_dump_state **, const uint16_t *zone,
                     int *ptot_bkts);
int nl_ct_dump_next(struct nl_ct_dump_state *, struct ct_dpif_entry *);
int nl_ct_dump_done(struct nl_ct_dump_state *);

int nl_ct_flush(void);
int nl_ct_flush_zone(uint16_t zone);
int nl_ct_flush_tuple(const struct ct_dpif_tuple *, uint16_t zone);

int nl_ct_set_timeout_policy(const struct nl_ct_timeout_policy *nl_tp);
int nl_ct_get_timeout_policy(const char *tp_name,
                             struct nl_ct_timeout_policy *nl_tp);
int nl_ct_del_timeout_policy(const char *tp_name);
int nl_ct_timeout_policy_dump_start(
    struct nl_ct_timeout_policy_dump_state **statep);
int nl_ct_timeout_policy_dump_next(
    struct nl_ct_timeout_policy_dump_state *state,
    struct nl_ct_timeout_policy *nl_tp);
int nl_ct_timeout_policy_dump_done(
    struct nl_ct_timeout_policy_dump_state *state);

bool nl_ct_parse_entry(struct ofpbuf *, struct ct_dpif_entry *,
                       enum nl_ct_event_type *);
void nl_ct_format_event_entry(const struct ct_dpif_entry *,
                              enum nl_ct_event_type, struct ds *,
                              bool verbose, bool print_stats);

#endif /* NETLINK_CONNTRACK_H */
