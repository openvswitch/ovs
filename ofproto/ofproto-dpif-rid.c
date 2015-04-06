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

#include <config.h>

#include "ofpbuf.h"
#include "ofproto-dpif.h"
#include "ofproto-dpif-rid.h"
#include "ofproto-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_rid);

static struct ovs_mutex mutex;

static struct cmap id_map;
static struct cmap metadata_map;

static struct ovs_list expiring OVS_GUARDED_BY(mutex);
static struct ovs_list expired OVS_GUARDED_BY(mutex);

static uint32_t next_id OVS_GUARDED_BY(mutex); /* Possible next free id. */

#define RECIRC_POOL_STATIC_IDS 1024

void
recirc_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init(&mutex);
        ovs_mutex_lock(&mutex);
        next_id = 1; /* 0 is not a valid ID. */
        cmap_init(&id_map);
        cmap_init(&metadata_map);
        list_init(&expiring);
        list_init(&expired);
        ovs_mutex_unlock(&mutex);

        ovsthread_once_done(&once);
    }

}

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
            ovsrcu_postpone(free, node);
        }

        if (!list_is_empty(&expiring)) {
            /* 'expired' is now empty, move nodes in 'expiring' to it. */
            list_splice(&expired, list_front(&expiring), &expiring);
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

static uint32_t
recirc_metadata_hash(struct ofproto_dpif *ofproto, uint8_t table_id,
                     struct recirc_metadata *md, struct ofpbuf *stack,
                     uint32_t action_set_len, uint32_t ofpacts_len,
                     const struct ofpact *ofpacts)
{
    uint32_t hash;

    BUILD_ASSERT(OFPACT_ALIGNTO == sizeof(uint64_t));

    hash = hash_pointer(ofproto, 0);
    hash = hash_int(table_id, hash);
    hash = hash_words64((const uint64_t *)md, sizeof *md / sizeof(uint64_t),
                        hash);
    if (stack && stack->size != 0) {
        hash = hash_words64((const uint64_t *)stack->data,
                            stack->size / sizeof(uint64_t), hash);
    }
    hash = hash_int(action_set_len, hash);
    if (ofpacts_len) {
        hash = hash_words64(ALIGNED_CAST(const uint64_t *, ofpacts),
                            OFPACT_ALIGN(ofpacts_len) / sizeof(uint64_t),
                            hash);
    }
    return hash;
}

static bool
recirc_metadata_equal(const struct recirc_id_node *node,
                      struct ofproto_dpif *ofproto, uint8_t table_id,
                      struct recirc_metadata *md, struct ofpbuf *stack,
                      uint32_t action_set_len, uint32_t ofpacts_len,
                      const struct ofpact *ofpacts)
{
    return node->ofproto == ofproto
        && node->table_id == table_id
        && !memcmp(&node->metadata, md, sizeof *md)
        && ((!node->stack && (!stack || stack->size == 0))
            || (node->stack && stack && ofpbuf_equal(node->stack, stack)))
        && node->action_set_len == action_set_len
        && node->ofpacts_len == ofpacts_len
        && (ofpacts_len == 0 || !memcmp(node->ofpacts, ofpacts, ofpacts_len));
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should take a reference. */
static struct recirc_id_node *
recirc_find_equal(struct ofproto_dpif *ofproto, uint8_t table_id,
                  struct recirc_metadata *md, struct ofpbuf *stack,
                  uint32_t action_set_len, uint32_t ofpacts_len,
                  const struct ofpact *ofpacts, uint32_t hash)
{
    struct recirc_id_node *node;

    CMAP_FOR_EACH_WITH_HASH(node, metadata_node, hash, &metadata_map) {
        if (recirc_metadata_equal(node, ofproto, table_id, md, stack,
                                  action_set_len, ofpacts_len, ofpacts)) {
            return node;
        }
    }
    return NULL;
}

static struct recirc_id_node *
recirc_ref_equal(struct ofproto_dpif *ofproto, uint8_t table_id,
                 struct recirc_metadata *md, struct ofpbuf *stack,
                 uint32_t action_set_len, uint32_t ofpacts_len,
                 const struct ofpact *ofpacts, uint32_t hash)
{
    struct recirc_id_node *node;

    do {
        node = recirc_find_equal(ofproto, table_id, md, stack, action_set_len,
                                 ofpacts_len, ofpacts, hash);

        /* Try again if the node was released before we get the reference. */
    } while (node && !ovs_refcount_try_ref_rcu(&node->refcount));

    return node;
}

/* Allocate a unique recirculation id for the given set of flow metadata.
 * The ID space is 2^^32, so there should never be a situation in which all
 * the IDs are used up.  We loop until we find a free one.
 * hash is recomputed if it is passed in as 0. */
static struct recirc_id_node *
recirc_alloc_id__(struct ofproto_dpif *ofproto, uint8_t table_id,
                  struct recirc_metadata *md, struct ofpbuf *stack,
                  uint32_t action_set_len, uint32_t ofpacts_len,
                  const struct ofpact *ofpacts, uint32_t hash)
{
    struct recirc_id_node *node = xzalloc(sizeof *node +
                                          OFPACT_ALIGN(ofpacts_len));
    node->hash = hash;
    ovs_refcount_init(&node->refcount);

    node->ofproto = ofproto;
    node->table_id = table_id;
    memcpy(&node->metadata, md, sizeof node->metadata);
    node->stack = (stack && stack->size) ? ofpbuf_clone(stack) : NULL;
    node->action_set_len = action_set_len;
    node->ofpacts_len = ofpacts_len;
    if (ofpacts_len) {
        memcpy(node->ofpacts, ofpacts, ofpacts_len);
    }

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
recirc_find_id(struct ofproto_dpif *ofproto, uint8_t table_id,
               struct recirc_metadata *md, struct ofpbuf *stack,
               uint32_t action_set_len, uint32_t ofpacts_len,
               const struct ofpact *ofpacts)
{
    /* Check if an ID with the given metadata already exists. */
    struct recirc_id_node *node;
    uint32_t hash;

    hash = recirc_metadata_hash(ofproto, table_id, md, stack, action_set_len,
                                ofpacts_len, ofpacts);
    node = recirc_find_equal(ofproto, table_id, md, stack, action_set_len,
                             ofpacts_len, ofpacts, hash);

    return node ? node->id : 0;
}

/* Allocate a unique recirculation id for the given set of flow metadata and
   optional actions. */
uint32_t
recirc_alloc_id_ctx(struct ofproto_dpif *ofproto, uint8_t table_id,
                    struct recirc_metadata *md, struct ofpbuf *stack,
                    uint32_t action_set_len, uint32_t ofpacts_len,
                    const struct ofpact *ofpacts)
{
    struct recirc_id_node *node;
    uint32_t hash;

    /* Look up an existing ID. */
    hash = recirc_metadata_hash(ofproto, table_id, md, stack, action_set_len,
                                ofpacts_len, ofpacts);
    node = recirc_ref_equal(ofproto, table_id, md, stack, action_set_len,
                            ofpacts_len, ofpacts, hash);

    /* Allocate a new recirc ID if needed. */
    if (!node) {
        ovs_assert(action_set_len <= ofpacts_len);

        node = recirc_alloc_id__(ofproto, table_id, md, stack, action_set_len,
                                 ofpacts_len, ofpacts, hash);
    }

    return node->id;
}

/* Allocate a unique recirculation id. */
uint32_t
recirc_alloc_id(struct ofproto_dpif *ofproto)
{
    struct recirc_metadata md;
    struct recirc_id_node *node;
    uint32_t hash;

    memset(&md, 0, sizeof md);
    md.in_port = OFPP_NONE;
    hash = recirc_metadata_hash(ofproto, TBL_INTERNAL, &md, NULL, 0, 0, NULL);
    node = recirc_alloc_id__(ofproto, TBL_INTERNAL, &md, NULL, 0, 0, NULL,
                             hash);
    return node->id;
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
        list_insert(&expiring, &node->exp_node);
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
        if (n->ofproto == ofproto) {
            VLOG_ERR("recirc_id %"PRIu32
                     " left allocated when ofproto (%s)"
                     " is destructed", n->id, ofproto_name);
        }
    }
}
