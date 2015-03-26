/*
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

#ifndef OFPROTO_DPIF_RID_H
#define OFPROTO_DPIF_RID_H

#include <stddef.h>
#include <stdint.h>

#include "cmap.h"
#include "list.h"
#include "ofp-actions.h"
#include "ovs-thread.h"

struct ofproto_dpif;
struct rule;

/*
 * Recirculation
 * =============
 *
 * Recirculation is a technique to allow a frame to re-enter the datapath
 * packet processing path for one or multiple times to achieve more flexible
 * packet processing, such modifying header fields after MPLS POP action and
 * selecting bond a slave port for bond ports.
 *
 * Data path and user space interface
 * -----------------------------------
 *
 * Recirculation uses two uint32_t fields, recirc_id and dp_hash, and a RECIRC
 * action.  The value recirc_id is used to select the next packet processing
 * steps among multiple instances of recirculation.  When a packet initially
 * enters the data path it is assigned with recirc_id 0, which indicates no
 * recirculation.  Recirc_ids are managed by the user space, opaque to the
 * data path.
 *
 * On the other hand, dp_hash can only be computed by the data path, opaque to
 * the user space.  In fact, user space may not able to recompute the hash
 * value.  The dp_hash value should be wildcarded for a newly received
 * packet.  HASH action specifies whether the hash is computed, and if
 * computed, how many fields are to be included in the hash computation.  The
 * computed hash value is stored into the dp_hash field prior to recirculation.
 *
 * The RECIRC action sets the recirc_id field and then reprocesses the packet
 * as if it was received on the same input port.  RECIRC action works like a
 * function call; actions listed behind the RECIRC action will be executed
 * after its execution.  RECIRC action can be nested, data path implementation
 * limits the number of recirculation executed to prevent unreasonable nesting
 * depth or infinite loop.
 *
 * User space recirculation context
 * ---------------------------------
 *
 * Recirculation is hidden from the OpenFlow controllers.  Action translation
 * code deduces when recirculation is necessary and issues a data path
 * recirculation action.  All OpenFlow actions to be performed after
 * recirculation are derived from the OpenFlow pipeline and are stored with the
 * recirculation ID.  When the OpenFlow tables are changed in a way affecting
 * the recirculation flows, new recirculation ID with new metadata and actions
 * is allocated and the old one is timed out.
 *
 * Recirculation ID pool
 * ----------------------
 *
 * Recirculation ID needs to be unique for all data paths.  Recirculation ID
 * pool keeps track recirculation ids and stores OpenFlow pipeline translation
 * context so that flow processing may continue after recirculation.
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
BUILD_ASSERT_DECL(FLOW_WC_SEQ == 31);

struct recirc_metadata {
    /* Metadata in struct flow. */
    struct flow_tnl tunnel;       /* Encapsulating tunnel parameters. */
    ovs_be64 metadata;            /* OpenFlow Metadata. */
    uint64_t regs[FLOW_N_XREGS];  /* Registers. */
    ofp_port_t in_port;           /* Incoming port. */
    ofp_port_t actset_output;     /* Output port in action set. */
};

static inline void
recirc_metadata_from_flow(struct recirc_metadata *md,
                          const struct flow *flow)
{
    memset(md, 0, sizeof *md);
    md->tunnel = flow->tunnel;
    md->metadata = flow->metadata;
    memcpy(md->regs, flow->regs, sizeof md->regs);
    md->in_port = flow->in_port.ofp_port;
    md->actset_output = flow->actset_output;
}

static inline void
recirc_metadata_to_flow(const struct recirc_metadata *md,
                        struct flow *flow)
{
    flow->tunnel = md->tunnel;
    flow->metadata = md->metadata;
    memcpy(flow->regs, md->regs, sizeof flow->regs);
    flow->in_port.ofp_port = md->in_port;
    flow->actset_output = md->actset_output;
}

/* Pool node fields should NOT be modified after placing the node in the pool.
 */
struct recirc_id_node {
    struct ovs_list exp_node OVS_GUARDED;
    struct cmap_node id_node;
    struct cmap_node metadata_node;
    uint32_t id;
    uint32_t hash;
    struct ovs_refcount refcount;

    /* Initial table for post-recirculation processing. */
    uint8_t table_id;

    /* Pipeline context for post-recirculation processing. */
    struct ofproto_dpif *ofproto; /* Post-recirculation bridge. */
    struct recirc_metadata metadata; /* Flow metadata. */
    struct ofpbuf *stack;         /* Stack if any. */

    /* Actions to be translated on recirculation. */
    uint32_t action_set_len;      /* How much of 'ofpacts' consists of an
                                   * action set? */
    uint32_t ofpacts_len;         /* Size of 'ofpacts', in bytes. */
    struct ofpact ofpacts[];      /* Sequence of "struct ofpacts". */
};

void recirc_init(void);

/* This is only used for bonds and will go away when bonds implementation is
 * updated to use this mechanism instead of internal rules. */
uint32_t recirc_alloc_id(struct ofproto_dpif *);

uint32_t recirc_alloc_id_ctx(struct ofproto_dpif *, uint8_t table_id,
                             struct recirc_metadata *, struct ofpbuf *stack,
                             uint32_t action_set_len, uint32_t ofpacts_len,
                             const struct ofpact *);
uint32_t recirc_find_id(struct ofproto_dpif *, uint8_t table_id,
                        struct recirc_metadata *, struct ofpbuf *stack,
                        uint32_t action_set_len, uint32_t ofpacts_len,
                        const struct ofpact *);
void recirc_free_id(uint32_t recirc_id);
void recirc_free_ofproto(struct ofproto_dpif *, const char *ofproto_name);

const struct recirc_id_node *recirc_id_node_find(uint32_t recirc_id);

static inline bool recirc_id_node_try_ref_rcu(const struct recirc_id_node *n_)
{
    struct recirc_id_node *node = CONST_CAST(struct recirc_id_node *, n_);

    return node ? ovs_refcount_try_ref_rcu(&node->refcount) : false;
}

void recirc_id_node_unref(const struct recirc_id_node *);

void recirc_run(void);

#endif
