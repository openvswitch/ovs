/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include "mac-learning.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "bitmap.h"
#include "coverage.h"
#include "hash.h"
#include "list.h"
#include "poll-loop.h"
#include "tag.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(mac_learning);

COVERAGE_DEFINE(mac_learning_learned);
COVERAGE_DEFINE(mac_learning_expired);

/* Returns the number of seconds since 'e' was last learned. */
int
mac_entry_age(const struct mac_entry *e)
{
    time_t remaining = e->expires - time_now();
    return MAC_ENTRY_IDLE_TIME - remaining;
}

static uint32_t
mac_table_hash(const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan)
{
    return hash_bytes(mac, ETH_ADDR_LEN, vlan);
}

static struct mac_entry *
mac_entry_from_lru_node(struct list *list)
{
    return CONTAINER_OF(list, struct mac_entry, lru_node);
}

/* Returns a tag that represents that 'mac' is on an unknown port in 'vlan'.
 * (When we learn where 'mac' is in 'vlan', this allows flows that were
 * flooded to be revalidated.) */
static tag_type
make_unknown_mac_tag(const struct mac_learning *ml,
                     const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan)
{
    uint32_t h = hash_int(ml->secret, mac_table_hash(mac, vlan));
    return tag_create_deterministic(h);
}

static struct list *
mac_table_bucket(const struct mac_learning *ml,
                 const uint8_t mac[ETH_ADDR_LEN],
                 uint16_t vlan)
{
    uint32_t hash = mac_table_hash(mac, vlan);
    const struct list *list = &ml->table[hash & MAC_HASH_BITS];
    return (struct list *) list;
}

static struct mac_entry *
search_bucket(struct list *bucket, const uint8_t mac[ETH_ADDR_LEN],
              uint16_t vlan)
{
    struct mac_entry *e;
    LIST_FOR_EACH (e, hash_node, bucket) {
        if (eth_addr_equals(e->mac, mac) && e->vlan == vlan) {
            return e;
        }
    }
    return NULL;
}

/* If the LRU list is not empty, stores the least-recently-used entry in '*e'
 * and returns true.  Otherwise, if the LRU list is empty, stores NULL in '*e'
 * and return false. */
static bool
get_lru(struct mac_learning *ml, struct mac_entry **e)
{
    if (!list_is_empty(&ml->lrus)) {
        *e = mac_entry_from_lru_node(ml->lrus.next);
        return true;
    } else {
        *e = NULL;
        return false;
    }
}

/* Creates and returns a new MAC learning table. */
struct mac_learning *
mac_learning_create(void)
{
    struct mac_learning *ml;
    int i;

    ml = xmalloc(sizeof *ml);
    list_init(&ml->lrus);
    list_init(&ml->free);
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        list_init(&ml->table[i]);
    }
    for (i = 0; i < MAC_MAX; i++) {
        struct mac_entry *s = &ml->entries[i];
        list_push_front(&ml->free, &s->lru_node);
    }
    ml->secret = random_uint32();
    ml->flood_vlans = NULL;
    return ml;
}

/* Destroys MAC learning table 'ml'. */
void
mac_learning_destroy(struct mac_learning *ml)
{
    if (ml) {
        bitmap_free(ml->flood_vlans);
    }
    free(ml);
}

/* Provides a bitmap of VLANs which have learning disabled, that is, VLANs on
 * which all packets are flooded.  It takes ownership of the bitmap.  Returns
 * true if the set has changed from the previous value. */
bool
mac_learning_set_flood_vlans(struct mac_learning *ml, unsigned long *bitmap)
{
    bool ret = (bitmap == NULL
                ? ml->flood_vlans != NULL
                : (ml->flood_vlans == NULL
                   || !bitmap_equal(bitmap, ml->flood_vlans, 4096)));

    bitmap_free(ml->flood_vlans);
    ml->flood_vlans = bitmap;

    return ret;
}

static bool
is_learning_vlan(const struct mac_learning *ml, uint16_t vlan)
{
    return !(ml->flood_vlans && bitmap_is_set(ml->flood_vlans, vlan));
}

/* Returns true if 'src_mac' may be learned on 'vlan' for 'ml'.
 * Returns false if 'ml' is NULL, if src_mac is not valid for learning, or if
 * 'vlan' is configured on 'ml' to flood all packets. */
bool
mac_learning_may_learn(const struct mac_learning *ml,
                       const uint8_t src_mac[ETH_ADDR_LEN], uint16_t vlan)
{
    return ml && is_learning_vlan(ml, vlan) && !eth_addr_is_multicast(src_mac);
}

/* Searches 'ml' for and returns a MAC learning entry for 'src_mac' in 'vlan',
 * inserting a new entry if necessary.  The caller must have already verified,
 * by calling mac_learning_may_learn(), that 'src_mac' and 'vlan' are
 * learnable.
 *
 * If the returned MAC entry is new (as may be determined by calling
 * mac_entry_is_new()), then the caller must pass the new entry to
 * mac_learning_changed().  The caller must also initialize the new entry's
 * 'port' member.  Otherwise calling those functions is at the caller's
 * discretion. */
struct mac_entry *
mac_learning_insert(struct mac_learning *ml,
                    const uint8_t src_mac[ETH_ADDR_LEN], uint16_t vlan)
{
    struct mac_entry *e;
    struct list *bucket;

    bucket = mac_table_bucket(ml, src_mac, vlan);
    e = search_bucket(bucket, src_mac, vlan);
    if (!e) {
        if (!list_is_empty(&ml->free)) {
            e = mac_entry_from_lru_node(ml->free.next);
        } else {
            e = mac_entry_from_lru_node(ml->lrus.next);
            list_remove(&e->hash_node);
        }
        list_push_front(bucket, &e->hash_node);
        memcpy(e->mac, src_mac, ETH_ADDR_LEN);
        e->vlan = vlan;
        e->tag = 0;
        e->grat_arp_lock = TIME_MIN;
    }

    /* Mark 'e' as recently used. */
    list_remove(&e->lru_node);
    list_push_back(&ml->lrus, &e->lru_node);
    e->expires = time_now() + MAC_ENTRY_IDLE_TIME;

    return e;
}

/* Changes 'e''s tag to a new, randomly selected one, and returns the tag that
 * would have been previously used for this entry's MAC and VLAN (either before
 * 'e' was inserted, if it is new, or otherwise before its port was updated.)
 *
 * The client should call this function after obtaining a MAC learning entry
 * from mac_learning_insert(), if the entry is either new or if its learned
 * port has changed. */
tag_type
mac_learning_changed(struct mac_learning *ml, struct mac_entry *e)
{
    tag_type old_tag = e->tag;

    COVERAGE_INC(mac_learning_learned);

    e->tag = tag_create_random();
    return old_tag ? old_tag : make_unknown_mac_tag(ml, e->mac, e->vlan);
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml' and returns the associated MAC
 * learning entry, if any.  If 'tag' is nonnull, then the tag that associates
 * 'dst' and 'vlan' with its currently learned port will be OR'd into
 * '*tag'. */
struct mac_entry *
mac_learning_lookup(const struct mac_learning *ml,
                    const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan,
                    tag_type *tag)
{
    if (eth_addr_is_multicast(dst)) {
        /* No tag because the treatment of multicast destinations never
         * changes. */
        return NULL;
    } else if (!is_learning_vlan(ml, vlan)) {
        /* We don't tag this property.  The set of learning VLANs changes so
         * rarely that we revalidate every flow when it changes. */
        return NULL;
    } else {
        struct mac_entry *e = search_bucket(mac_table_bucket(ml, dst, vlan),
                                            dst, vlan);
        assert(e == NULL || e->tag != 0);
        if (tag) {
            /* Tag either the learned port or the lack thereof. */
            *tag |= e ? e->tag : make_unknown_mac_tag(ml, dst, vlan);
        }
        return e;
    }
}

/* Expires 'e' from the 'ml' hash table.  'e' must not already be on the free
 * list. */
void
mac_learning_expire(struct mac_learning *ml, struct mac_entry *e)
{
    list_remove(&e->hash_node);
    list_remove(&e->lru_node);
    list_push_front(&ml->free, &e->lru_node);
}

/* Expires all the mac-learning entries in 'ml'.  The tags in 'ml' are
 * discarded, so the client is responsible for revalidating any flows that
 * depend on 'ml', if necessary. */
void
mac_learning_flush(struct mac_learning *ml)
{
    struct mac_entry *e;
    while (get_lru(ml, &e)){
        mac_learning_expire(ml, e);
    }
}

void
mac_learning_run(struct mac_learning *ml, struct tag_set *set)
{
    struct mac_entry *e;
    while (get_lru(ml, &e) && time_now() >= e->expires) {
        COVERAGE_INC(mac_learning_expired);
        if (set) {
            tag_set_add(set, e->tag);
        }
        mac_learning_expire(ml, e);
    }
}

void
mac_learning_wait(struct mac_learning *ml)
{
    if (!list_is_empty(&ml->lrus)) {
        struct mac_entry *e = mac_entry_from_lru_node(ml->lrus.next);
        poll_timer_wait_until(e->expires * 1000LL);
    }
}
