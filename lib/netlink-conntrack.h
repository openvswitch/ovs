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

#include "byte-order.h"
#include "compiler.h"
#include "ct-dpif.h"
#include "openvswitch/dynamic-string.h"
#include "hmap.h"
#include "openvswitch/ofpbuf.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

enum nl_ct_event_type {
    NL_CT_EVENT_NEW    = 1 << 0,
    NL_CT_EVENT_UPDATE = 1 << 1,
    NL_CT_EVENT_DELETE = 1 << 2,
};

struct nl_ct_dump_state;

int nl_ct_dump_start(struct nl_ct_dump_state **, const uint16_t *zone);
int nl_ct_dump_next(struct nl_ct_dump_state *, struct ct_dpif_entry *);
int nl_ct_dump_done(struct nl_ct_dump_state *);

int nl_ct_flush(void);
int nl_ct_flush_zone(uint16_t zone);

bool nl_ct_parse_entry(struct ofpbuf *, struct ct_dpif_entry *,
                       enum nl_ct_event_type *);
void nl_ct_format_event_entry(const struct ct_dpif_entry *,
                              enum nl_ct_event_type, struct ds *,
                              bool verbose, bool print_stats);

#endif /* NETLINK_CONNTRACK_H */
