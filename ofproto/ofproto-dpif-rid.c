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

#include <config.h>

#include "openvswitch/ofpbuf.h"
#include "ofproto-dpif.h"
#include "ofproto-dpif-rid.h"
#include "ofproto-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_rid);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

static struct cmap id_map = CMAP_INITIALIZER;
static struct cmap metadata_map = CMAP_INITIALIZER;

static struct ovs_list expiring OVS_GUARDED_BY(mutex)
    = OVS_LIST_INITIALIZER(&expiring);
static struct ovs_list expired OVS_GUARDED_BY(mutex)
    = OVS_LIST_INITIALIZER(&expired);

static uint32_t next_id OVS_GUARDED_BY(mutex) = 1; /* Possible next free id. */

#define RECIRC_POOL_STATIC_IDS 1024

static void recirc_id_node_free(struct recirc_id_node *);

/* This should be called by the revalidator once at each round (every 500ms or
 * more). */
void
recirc_run(void)
{
    static long long int last = 0;
    long long int now = time_msec();

    /* Do maintenance at most 4 times / sec. */
    ovs_mutex_lock(&mutex);
    if (now - last > 250) {
        struct recirc_id_node *node;

        last = now;

        /* Nodes in 'expiring' and 'expired' lists have the refcount of zero,
         * which means that while they can still be found (by id), no new
         * references can be taken on them.  We have removed the entry from the
         * 'metadata_map', at the time when refcount reached zero, causing any
         * new translations to allocate a new ID.  This allows the expiring
         * entry to be safely deleted while any sudden new use of the similar
         * recirculation will safely start using a new recirculation ID.  When
         * the refcount gets to zero, the node is also added to the 'expiring'
         * list.  At any time after that the nodes in the 'expiring' list can
         * be moved to the 'expired' list, from which they are deleted at least
         * 250ms afterwards. */

        /* Delete the expired.  These have been lingering for at least 250 ms,
         * which should be enough for any ongoing recirculations to be
         * finished. */
        LIST_FOR_EACH_POP (node, exp_node, &expired) {
            cmap_remove(&id_map, &node->id_node, node->id);
            ovsrcu_postpone(recirc_id_node_free, node);
        }

        if (!ovs_list_is_empty(&expiring)) {
            /* 'expired' is now empty, move nodes in 'expiring' to it. */
            ovs_list_splice(&expired, ovs_list_front(&expiring), &expiring);
        }
    }
    ovs_mutex_unlock(&mutex);
}

/* We use the id as the hash value, which works due to cmap internal rehashing.
 * We also only insert nodes with unique IDs, so all possible hash collisions
 * remain internal to the cmap. */
static struct recirc_id_node *
recirc_find__(uint32_t id)
    OVS_REQUIRES(mutex)
{
    struct cmap_node *node = cmap_find_protected(&id_map, id);

    return node ? CONTAINER_OF(node, struct recirc_id_node, id_node) : NULL;
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should copy the contents. */
const struct recirc_id_node *
recirc_id_node_find(uint32_t id)
{
    const struct cmap_node *node = cmap_find(&id_map, id);

    return node
        ? CONTAINER_OF(node, const struct recirc_id_node, id_node)
        : NULL;
}

bool
recirc_id_node_find_and_ref(uint32_t id)
{
    struct recirc_id_node *rid_node =
        CONST_CAST(struct recirc_id_node *, recirc_id_node_find(id));

    if (!rid_node) {
        return false;
    }

    return ovs_refcount_try_ref_rcu(&rid_node->refcount);
}

static uint32_t
frozen_state_hash(const struct frozen_state *state)
{
    uint32_t hash;

    hash = uuid_hash(&state->ofproto_uuid);
    hash = hash_int(state->table_id, hash);
    hash = hash_bytes64((const uint64_t *) &state->metadata,
                        sizeof state->metadata, hash);
    hash = hash_boolean(state->conntracked, hash);
    hash = hash_boolean(state->was_mpls, hash);
    if (state->stack && state->stack_size) {
        hash = hash_bytes(state->stack, state->stack_size, hash);
    }
    hash = hash_int(state->mirrors, hash);
    if (state->action_set_len) {
        hash = hash_bytes64(ALIGNED_CAST(const uint64_t *, state->action_set),
                            state->action_set_len, hash);
    }
    if (state->ofpacts_len) {
        hash = hash_bytes64(ALIGNED_CAST(const uint64_t *, state->ofpacts),
                            state->ofpacts_len, hash);
    }
    if (state->userdata && state->userdata_len) {
        hash = hash_bytes(state->userdata, state->userdata_len, hash);
    }
    return hash;
}

static bool
frozen_state_equal(const struct frozen_state *a, const struct frozen_state *b)
{
    return (a->table_id == b->table_id
            && uuid_equals(&a->ofproto_uuid, &b->ofproto_uuid)
            && !memcmp(&a->metadata, &b->metadata, sizeof a->metadata)
            && a->stack_size == b->stack_size
            && !memcmp(a->stack, b->stack, a->stack_size)
            && a->mirrors == b->mirrors
            && a->conntracked == b->conntracked
            && a->was_mpls == b->was_mpls
            && ofpacts_equal(a->ofpacts, a->ofpacts_len,
                             b->ofpacts, b->ofpacts_len)
            && ofpacts_equal(a->action_set, a->action_set_len,
                             b->action_set, b->action_set_len)
            && !memcmp(a->userdata, b->userdata, a->userdata_len)
            && uuid_equals(&a->xport_uuid, &b->xport_uuid));
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should take a reference. */
static struct recirc_id_node *
recirc_find_equal(const struct frozen_state *target, uint32_t hash)
{
    struct recirc_id_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, metadata_node, hash, &metadata_map) {
        if (frozen_state_equal(&node->state, target)) {
            return node;
        }
    }
    return NULL;
}

static struct recirc_id_node *
recirc_ref_equal(const struct frozen_state *target, uint32_t hash)
{
    struct recirc_id_node *node;

    do {
        node = recirc_find_equal(target, hash);

        /* Try again if the node was released before we get the reference. */
    } while (node && !ovs_refcount_try_ref_rcu(&node->refcount));

    return node;
}

static void
frozen_state_clone(struct frozen_state *new, const struct frozen_state *old)
{
    *new = *old;
    new->stack = (new->stack_size
                  ? xmemdup(new->stack, new->stack_size)
                  : NULL);
    new->ofpacts = (new->ofpacts_len
                    ? xmemdup(new->ofpacts, new->ofpacts_len)
                    : NULL);
    new->action_set = (new->action_set_len
                       ? xmemdup(new->action_set, new->action_set_len)
                       : NULL);
    new->userdata = (new->userdata_len
                     ? xmemdup(new->userdata, new->userdata_len)
                     : NULL);
}

static void
frozen_state_free(struct frozen_state *state)
{
    free(state->stack);
    free(state->ofpacts);
    free(state->action_set);
    free(state->userdata);
}

/* Allocate a unique recirculation id for the given set of flow metadata.
 * The ID space is 2^^32, so there should never be a situation in which all
 * the IDs are used up.  We loop until we find a free one. */
static struct recirc_id_node *
recirc_alloc_id__(const struct frozen_state *state, uint32_t hash)
{
    ovs_assert(state->action_set_len <= state->ofpacts_len);

    struct recirc_id_node *node = xzalloc(sizeof *node);

    node->hash = hash;
    ovs_refcount_init(&node->refcount);
    frozen_state_clone(CONST_CAST(struct frozen_state *, &node->state), state);

    ovs_mutex_lock(&mutex);
    for (;;) {
        /* Claim the next ID.  The ID space should be sparse enough for the
           allocation to succeed at the first try.  We do skip the first
           RECIRC_POOL_STATIC_IDS IDs on the later rounds, though, as some of
           the initial allocations may be for long term uses (like bonds). */
        node->id = next_id++;
        if (OVS_UNLIKELY(!node->id)) {
            next_id = RECIRC_POOL_STATIC_IDS + 1;
            node->id = next_id++;
        }
        /* Find if the id is free. */
        if (OVS_LIKELY(!recirc_find__(node->id))) {
            break;
        }
    }
    cmap_insert(&id_map, &node->id_node, node->id);
    cmap_insert(&metadata_map, &node->metadata_node, node->hash);
    ovs_mutex_unlock(&mutex);
    return node;
}

/* Look up an existing ID for the given flow's metadata and optional actions.
 */
uint32_t
recirc_find_id(const struct frozen_state *target)
{
    uint32_t hash = frozen_state_hash(target);
    struct recirc_id_node *node = recirc_find_equal(target, hash);
    return node ? node->id : 0;
}

/* Allocate a unique recirculation id for the given set of flow metadata and
   optional actions. */
uint32_t
recirc_alloc_id_ctx(const struct frozen_state *state)
{
    uint32_t hash = frozen_state_hash(state);
    struct recirc_id_node *node = recirc_ref_equal(state, hash);
    if (!node) {
        node = recirc_alloc_id__(state, hash);
    }
    return node->id;
}

/* Allocate a unique recirculation id. */
uint32_t
recirc_alloc_id(struct ofproto_dpif *ofproto)
{
    struct frozen_state state = {
        .table_id = TBL_INTERNAL,
        .ofproto_uuid = ofproto->uuid,
        .metadata = {
            .tunnel = {
                .ip_dst = htonl(0),
                .ipv6_dst = in6addr_any,
            },
            .in_port = OFPP_NONE },
    };
    /* In order to make sparse happy, xport_uuid needs to be set separately. */
    state.xport_uuid = UUID_ZERO;
    return recirc_alloc_id__(&state, frozen_state_hash(&state))->id;
}

static void
recirc_id_node_free(struct recirc_id_node *node)
{
    frozen_state_free(CONST_CAST(struct frozen_state *, &node->state));
    free(node);
}

void
recirc_id_node_unref(const struct recirc_id_node *node_)
    OVS_EXCLUDED(mutex)
{
    struct recirc_id_node *node = CONST_CAST(struct recirc_id_node *, node_);

    if (node && ovs_refcount_unref(&node->refcount) == 1) {
        ovs_mutex_lock(&mutex);
        /* Prevent re-use of this node by removing the node from 'metadata_map'
         */
        cmap_remove(&metadata_map, &node->metadata_node, node->hash);
        /* We keep the node in the 'id_map' so that it can be found as long
         * as it lingers, and add it to the 'expiring' list. */
        ovs_list_insert(&expiring, &node->exp_node);
        ovs_mutex_unlock(&mutex);
    }
}

void
recirc_free_id(uint32_t id)
{
    const struct recirc_id_node *node;

    node = recirc_id_node_find(id);
    if (node) {
        recirc_id_node_unref(node);
    } else {
        VLOG_ERR("Freeing nonexistent recirculation ID: %"PRIu32, id);
    }
}

/* Called when 'ofproto' is destructed.  Checks for and clears any
 * recirc_id leak.
 * No other thread may have access to the 'ofproto' being destructed.
 * All related datapath flows must be deleted before calling this. */
void
recirc_free_ofproto(struct ofproto_dpif *ofproto, const char *ofproto_name)
{
    struct recirc_id_node *n;

    CMAP_FOR_EACH (n, metadata_node, &metadata_map) {
        if (uuid_equals(&n->state.ofproto_uuid, &ofproto->uuid)) {
            VLOG_ERR("recirc_id %"PRIu32
                     " left allocated when ofproto (%s)"
                     " is destructed", n->id, ofproto_name);
        }
    }
}
