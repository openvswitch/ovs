/*
 * Copyright (c) 2013, 2014 Alexandru Copot <alex.mihai.c@gmail.com>, with support from IXIA.
 * Copyright (c) 2013, 2014 Daniel Baluta <dbaluta@ixiacom.com>
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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

#ifndef BUNDLES_H
#define BUNDLES_H 1

#include <sys/types.h>

#include "connmgr.h"
#include "ofproto-provider.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-util.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ofp_bundle_entry {
    struct ovs_list   node;
    enum ofptype      type;  /* OFPTYPE_FLOW_MOD, OFPTYPE_PORT_MOD,
                              * OFPTYPE_GROUP_MOD, OFPTYPE_PACKET_OUT. */
    struct ofp_header *msg;  /* Original request, for error reporting. */
    union {
        struct ofproto_flow_mod ofm;
        struct ofproto_port_mod opm;
        struct ofproto_group_mod ogm;
        struct ofproto_packet_out opo;
    };
};

enum bundle_state {
    BS_OPEN,
    BS_CLOSED
};

struct ofp_bundle {
    struct hmap_node  node;      /* In struct ofconn's "bundles" hmap. */
    long long int     used;      /* Last time bundle was used. */
    uint32_t          id;
    uint16_t          flags;
    enum bundle_state state;
    struct ofp_header *msg;      /* Original request, for error reporting. */
    struct ovs_list   msg_list;  /* List of 'struct bundle_message's */
};

static inline struct ofp_bundle_entry *ofp_bundle_entry_alloc(
    enum ofptype type, const struct ofp_header *oh);
static inline void ofp_bundle_entry_free(struct ofp_bundle_entry *);

enum ofperr ofp_bundle_open(struct ofconn *, uint32_t id, uint16_t flags,
                            const struct ofp_header *);
enum ofperr ofp_bundle_close(struct ofconn *, uint32_t id, uint16_t flags);
enum ofperr ofp_bundle_discard(struct ofconn *, uint32_t id);
enum ofperr ofp_bundle_add_message(struct ofconn *, uint32_t id,
                                   uint16_t flags, struct ofp_bundle_entry *,
                                   const struct ofp_header *);

void ofp_bundle_remove__(struct ofconn *, struct ofp_bundle *);

static inline struct ofp_bundle_entry *
ofp_bundle_entry_alloc(enum ofptype type, const struct ofp_header *oh)
{
    struct ofp_bundle_entry *entry = xmalloc(sizeof *entry);

    entry->type = type;
    entry->msg = xmemdup(oh, ntohs(oh->length));

    return entry;
}

static inline void
ofp_bundle_entry_free(struct ofp_bundle_entry *entry)
{
    if (entry) {
        if (entry->type == OFPTYPE_FLOW_MOD) {
            ofproto_flow_mod_uninit(&entry->ofm);
        } else if (entry->type == OFPTYPE_GROUP_MOD) {
            ofputil_uninit_group_mod(&entry->ogm.gm);
        } else if (entry->type == OFPTYPE_PACKET_OUT) {
            ofproto_packet_out_uninit(&entry->opo);
        }
        free(entry->msg);
        free(entry);
    }
}

#ifdef  __cplusplus
}
#endif

#endif
