/*
 * Copyright (c) 2013, 2014 Alexandru Copot <alex.mihai.c@gmail.com>, with support from IXIA.
 * Copyright (c) 2013, 2014 Daniel Baluta <dbaluta@ixiacom.com>
 * Copyright (c) 2014, 2015 Nicira, Inc.
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
#include "ofp-msgs.h"
#include "ofp-util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ofp_bundle_entry {
    struct ovs_list   node;
    ovs_be32          xid;   /* For error returns. */
    enum ofptype      type;  /* OFPTYPE_FLOW_MOD or OFPTYPE_PORT_MOD. */
    union {
        struct ofputil_flow_mod fm;   /* 'fm.ofpacts' must be malloced. */
        struct ofputil_port_mod pm;
    };
};

enum bundle_state {
    BS_OPEN,
    BS_CLOSED
};

struct ofp_bundle {
    struct hmap_node  node;      /* In struct ofconn's "bundles" hmap. */
    uint32_t          id;
    uint16_t          flags;
    enum bundle_state state;

    /* List of 'struct bundle_message's */
    struct ovs_list   msg_list;
};

static inline struct ofp_bundle_entry *ofp_bundle_entry_alloc(
    enum ofptype type, ovs_be32 xid);
static inline void ofp_bundle_entry_free(struct ofp_bundle_entry *);

enum ofperr ofp_bundle_open(struct ofconn *, uint32_t id, uint16_t flags);
enum ofperr ofp_bundle_close(struct ofconn *, uint32_t id, uint16_t flags);
enum ofperr ofp_bundle_commit(struct ofconn *, uint32_t id, uint16_t flags);
enum ofperr ofp_bundle_discard(struct ofconn *, uint32_t id);
enum ofperr ofp_bundle_add_message(struct ofconn *, uint32_t id,
                                   uint16_t flags, struct ofp_bundle_entry *);

void ofp_bundle_remove__(struct ofconn *ofconn, struct ofp_bundle *bundle);

static inline struct ofp_bundle_entry *
ofp_bundle_entry_alloc(enum ofptype type, ovs_be32 xid)
{
    struct ofp_bundle_entry *entry = xmalloc(sizeof *entry);

    entry->xid = xid;
    entry->type = type;

    return entry;
}

static inline void ofp_bundle_entry_free(struct ofp_bundle_entry *entry)
{
    if (entry) {
        if (entry->type == OFPTYPE_FLOW_MOD) {
            free(entry->fm.ofpacts);
        }
        free(entry);
    }
}

#ifdef  __cplusplus
}
#endif

#endif
