/*
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

#ifndef OFPROTO_DPIF_RID_H
#define OFPROTO_DPIF_RID_H

#include <stddef.h>
#include <stdint.h>

#include "cmap.h"
#include "ofproto-dpif-mirror.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-actions.h"
#include "ovs-thread.h"
#include "uuid.h"

struct ofproto_dpif;
struct rule;

/*
 * Freezing and recirculation
 * ==========================
 *
 * Freezing is a technique for halting and checkpointing packet translation in
 * a way that it can be restarted again later.  This file has a couple of data
 * structures related to freezing in general; their names begin with "frozen".
 *
 * Recirculation is the use of freezing to allow a frame to re-enter the
 * datapath packet processing path to achieve more flexible packet processing,
 * such as modifying header fields after MPLS POP action and selecting a slave
 * port for bond ports.
 *
 *
 * Data path and user space interface
 * -----------------------------------
 *
 * Recirculation uses two uint32_t fields, recirc_id and dp_hash, and a RECIRC
 * action.  recirc_id is used to select the next packet processing steps among
 * multiple instances of recirculation.  When a packet initially enters the
 * datapath it is assigned with recirc_id 0, which indicates no recirculation.
 * Recirc_ids are managed by the user space, opaque to the datapath.
 *
 * On the other hand, dp_hash can only be computed by the datapath, opaque to
 * the user space, as the datapath is free to choose the hashing algorithm
 * without informing user space about it.  The dp_hash value should be
 * wildcarded for newly received packets.  HASH action specifies whether the
 * hash is computed, and if computed, how many fields are to be included in the
 * hash computation.  The computed hash value is stored into the dp_hash field
 * prior to recirculation.
 *
 * The RECIRC action sets the recirc_id field and then reprocesses the packet
 * as if it was received again on the same input port.  RECIRC action works
 * like a function call; actions listed after the RECIRC action will be
 * executed after recirculation.  RECIRC action can be nested, but datapath
 * implementation limits the number of nested recirculations to prevent
 * unreasonable nesting depth or infinite loop.
 *
 * User space recirculation context
 * ---------------------------------
 *
 * Recirculation is usually hidden from the OpenFlow controllers.  Action
 * translation code deduces when recirculation is necessary and issues a
 * datapath recirculation action.  All OpenFlow actions to be performed after
 * recirculation are derived from the OpenFlow pipeline and are stored with the
 * recirculation ID.  When the OpenFlow tables are changed in a way affecting
 * the recirculation flows, new recirculation ID with new metadata and actions
 * is allocated and the old one is timed out.
 *
 * Recirculation ID pool
 * ----------------------
 *
 * Recirculation ID needs to be unique for all datapaths.  Recirculation ID
 * pool keeps track of recirculation ids and stores OpenFlow pipeline
 * translation context so that flow processing may continue after
 * recirculation.
 *
 * A Recirculation ID can be any uint32_t value, except for that the value 0 is
 * reserved for 'no recirculation' case.
 *
 * Thread-safety
 * --------------
 *
 * All APIs are thread safe.
 */

/* Metadata for restoring pipeline context after recirculation.  Helpers
 * are inlined below to keep them together with the definition for easier
 * updates. */
BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

struct frozen_metadata {
    /* Metadata in struct flow. */
    struct flow_tnl tunnel;       /* Encapsulating tunnel parameters. */
    ovs_be64 metadata;            /* OpenFlow Metadata. */
    uint64_t regs[FLOW_N_XREGS];  /* Registers. */
    ofp_port_t in_port;           /* Incoming port. */
};

static inline void
frozen_metadata_from_flow(struct frozen_metadata *md,
                          const struct flow *flow)
{
    memset(md, 0, sizeof *md);
    md->tunnel = flow->tunnel;
    md->metadata = flow->metadata;
    memcpy(md->regs, flow->regs, sizeof md->regs);
    md->in_port = flow->in_port.ofp_port;
}

static inline void
frozen_metadata_to_flow(const struct frozen_metadata *md,
                        struct flow *flow)
{
    flow->tunnel = md->tunnel;
    flow->metadata = md->metadata;
    memcpy(flow->regs, md->regs, sizeof flow->regs);
    flow->in_port.ofp_port = md->in_port;
}

/* State that flow translation can save, to restore when translation
 * resumes.  */
struct frozen_state {
    /* Initial table for processing when thawing. */
    uint8_t table_id;

    /* Pipeline context for processing when thawing. */
    struct uuid ofproto_uuid;     /* Bridge to resume from. */
    struct frozen_metadata metadata; /* Flow metadata. */
    uint8_t *stack;               /* Stack if any. */
    size_t stack_size;
    mirror_mask_t mirrors;        /* Mirrors already output. */
    bool conntracked;             /* Conntrack occurred prior to freeze. */
    struct uuid xport_uuid;       /* UUID of 1st port packet received on. */

    /* Actions to be translated when thawing. */
    struct ofpact *ofpacts;
    size_t ofpacts_len;           /* Size of 'ofpacts', in bytes. */
    struct ofpact *action_set;
    size_t action_set_len;        /* Size of 'action_set', in bytes. */

    /* User data for controller userspace cookie. */
    uint8_t *userdata;
    size_t userdata_len;
};

/* This maps a recirculation ID to saved state that flow translation can
 * restore when recirculation occurs. */
struct recirc_id_node {
    /* Index data. */
    struct ovs_list exp_node OVS_GUARDED;
    struct cmap_node id_node;
    struct cmap_node metadata_node;
    uint32_t id;
    uint32_t hash;
    struct ovs_refcount refcount;

    /* Saved state.
     *
     * This state should not be modified after inserting a node in the pool,
     * hence the 'const' to emphasize that. */
    const struct frozen_state state;
};

/* This is only used for bonds and will go away when bonds implementation is
 * updated to use this mechanism instead of internal rules. */
uint32_t recirc_alloc_id(struct ofproto_dpif *);

uint32_t recirc_alloc_id_ctx(const struct frozen_state *);
uint32_t recirc_find_id(const struct frozen_state *);
void recirc_free_id(uint32_t recirc_id);
void recirc_free_ofproto(struct ofproto_dpif *, const char *ofproto_name);

const struct recirc_id_node *recirc_id_node_find(uint32_t recirc_id);
bool recirc_id_node_find_and_ref(uint32_t id);

static inline struct recirc_id_node *
recirc_id_node_from_state(const struct frozen_state *state)
{
    return CONTAINER_OF(state, struct recirc_id_node, state);
}

static inline bool recirc_id_node_try_ref_rcu(const struct recirc_id_node *n_)
{
    struct recirc_id_node *node = CONST_CAST(struct recirc_id_node *, n_);

    return node ? ovs_refcount_try_ref_rcu(&node->refcount) : false;
}

void recirc_id_node_unref(const struct recirc_id_node *);

void recirc_run(void);

/* Recirculation IDs on which references are held. */
struct recirc_refs {
    unsigned n_recircs;
    union {
        uint32_t recirc[2];   /* When n_recircs == 1 or 2 */
        uint32_t *recircs;    /* When 'n_recircs' > 2 */
    };
};

#define RECIRC_REFS_EMPTY_INITIALIZER ((struct recirc_refs) \
                                       { 0, { { 0, 0 } } })
/* Helpers to abstract the recirculation union away. */
static inline void
recirc_refs_init(struct recirc_refs *rr)
{
    *rr = RECIRC_REFS_EMPTY_INITIALIZER;
}

static inline void
recirc_refs_add(struct recirc_refs *rr, uint32_t id)
{
    if (OVS_LIKELY(rr->n_recircs < ARRAY_SIZE(rr->recirc))) {
        rr->recirc[rr->n_recircs++] = id;
    } else {
        if (rr->n_recircs == ARRAY_SIZE(rr->recirc)) {
            uint32_t *recircs = xmalloc(sizeof rr->recirc + sizeof id);

            memcpy(recircs, rr->recirc, sizeof rr->recirc);
            rr->recircs = recircs;
        } else {
            rr->recircs = xrealloc(rr->recircs,
                                   (rr->n_recircs + 1) * sizeof id);
        }
        rr->recircs[rr->n_recircs++] = id;
    }
}

static inline void
recirc_refs_swap(struct recirc_refs *a, struct recirc_refs *b)
{
    struct recirc_refs tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

static inline void
recirc_refs_unref(struct recirc_refs *rr)
{
    if (OVS_LIKELY(rr->n_recircs <= ARRAY_SIZE(rr->recirc))) {
        for (int i = 0; i < rr->n_recircs; i++) {
            recirc_free_id(rr->recirc[i]);
        }
    } else {
        for (int i = 0; i < rr->n_recircs; i++) {
            recirc_free_id(rr->recircs[i]);
        }
        free(rr->recircs);
    }
    rr->n_recircs = 0;
}

#endif
