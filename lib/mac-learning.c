/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include <inttypes.h>
#include <stdlib.h>

#include "bitmap.h"
#include "coverage.h"
#include "hash.h"
#include "list.h"
#include "poll-loop.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "vlan-bitmap.h"

COVERAGE_DEFINE(mac_learning_learned);
COVERAGE_DEFINE(mac_learning_expired);

/* Returns the number of seconds since 'e' (within 'ml') was last learned. */
int
mac_entry_age(const struct mac_learning *ml, const struct mac_entry *e)
{
    time_t remaining = e->expires - time_now();
    return ml->idle_time - remaining;
}

static uint32_t
mac_table_hash(const struct mac_learning *ml, const uint8_t mac[ETH_ADDR_LEN],
               uint16_t vlan)
{
    return hash_mac(mac, vlan, ml->secret);
}

static struct mac_entry *
mac_entry_from_lru_node(struct list *list)
{
    return CONTAINER_OF(list, struct mac_entry, lru_node);
}

static struct mac_entry *
mac_entry_lookup(const struct mac_learning *ml,
                 const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan)
{
    struct mac_entry *e;

    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, mac_table_hash(ml, mac, vlan),
                             &ml->table) {
        if (e->vlan == vlan && eth_addr_equals(e->mac, mac)) {
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
    OVS_REQ_RDLOCK(ml->rwlock)
{
    if (!list_is_empty(&ml->lrus)) {
        *e = mac_entry_from_lru_node(ml->lrus.next);
        return true;
    } else {
        *e = NULL;
        return false;
    }
}

static unsigned int
normalize_idle_time(unsigned int idle_time)
{
    return (idle_time < 15 ? 15
            : idle_time > 3600 ? 3600
            : idle_time);
}

/* Creates and returns a new MAC learning table with an initial MAC aging
 * timeout of 'idle_time' seconds and an initial maximum of MAC_DEFAULT_MAX
 * entries. */
struct mac_learning *
mac_learning_create(unsigned int idle_time)
{
    struct mac_learning *ml;

    ml = xmalloc(sizeof *ml);
    list_init(&ml->lrus);
    hmap_init(&ml->table);
    ml->secret = random_uint32();
    ml->flood_vlans = NULL;
    ml->idle_time = normalize_idle_time(idle_time);
    ml->max_entries = MAC_DEFAULT_MAX;
    ml->need_revalidate = false;
    ovs_refcount_init(&ml->ref_cnt);
    ovs_rwlock_init(&ml->rwlock);
    return ml;
}

struct mac_learning *
mac_learning_ref(const struct mac_learning *ml_)
{
    struct mac_learning *ml = CONST_CAST(struct mac_learning *, ml_);
    if (ml) {
        ovs_refcount_ref(&ml->ref_cnt);
    }
    return ml;
}

/* Unreferences (and possibly destroys) MAC learning table 'ml'. */
void
mac_learning_unref(struct mac_learning *ml)
{
    if (ml && ovs_refcount_unref(&ml->ref_cnt) == 1) {
        struct mac_entry *e, *next;

        HMAP_FOR_EACH_SAFE (e, next, hmap_node, &ml->table) {
            hmap_remove(&ml->table, &e->hmap_node);
            free(e);
        }
        hmap_destroy(&ml->table);

        bitmap_free(ml->flood_vlans);
        ovs_rwlock_destroy(&ml->rwlock);
        free(ml);
    }
}

/* Provides a bitmap of VLANs which have learning disabled, that is, VLANs on
 * which all packets are flooded.  Returns true if the set has changed from the
 * previous value. */
bool
mac_learning_set_flood_vlans(struct mac_learning *ml,
                             const unsigned long *bitmap)
{
    if (vlan_bitmap_equal(ml->flood_vlans, bitmap)) {
        return false;
    } else {
        bitmap_free(ml->flood_vlans);
        ml->flood_vlans = vlan_bitmap_clone(bitmap);
        return true;
    }
}

/* Changes the MAC aging timeout of 'ml' to 'idle_time' seconds. */
void
mac_learning_set_idle_time(struct mac_learning *ml, unsigned int idle_time)
{
    idle_time = normalize_idle_time(idle_time);
    if (idle_time != ml->idle_time) {
        struct mac_entry *e;
        int delta;

        delta = (int) idle_time - (int) ml->idle_time;
        LIST_FOR_EACH (e, lru_node, &ml->lrus) {
            e->expires += delta;
        }
        ml->idle_time = idle_time;
    }
}

/* Sets the maximum number of entries in 'ml' to 'max_entries', adjusting it
 * to be within a reasonable range. */
void
mac_learning_set_max_entries(struct mac_learning *ml, size_t max_entries)
{
    ml->max_entries = (max_entries < 10 ? 10
                       : max_entries > 1000 * 1000 ? 1000 * 1000
                       : max_entries);
}

static bool
is_learning_vlan(const struct mac_learning *ml, uint16_t vlan)
{
    return !ml->flood_vlans || !bitmap_is_set(ml->flood_vlans, vlan);
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

    e = mac_entry_lookup(ml, src_mac, vlan);
    if (!e) {
        uint32_t hash = mac_table_hash(ml, src_mac, vlan);

        if (hmap_count(&ml->table) >= ml->max_entries) {
            get_lru(ml, &e);
            mac_learning_expire(ml, e);
        }

        e = xmalloc(sizeof *e);
        hmap_insert(&ml->table, &e->hmap_node, hash);
        memcpy(e->mac, src_mac, ETH_ADDR_LEN);
        e->vlan = vlan;
        e->grat_arp_lock = TIME_MIN;
        e->port.p = NULL;
    } else {
        list_remove(&e->lru_node);
    }

    /* Mark 'e' as recently used. */
    list_push_back(&ml->lrus, &e->lru_node);
    e->expires = time_now() + ml->idle_time;

    return e;
}

/* Changes 'e''s tag to a new, randomly selected one.  Causes
 * mac_learning_run() to flag for revalidation the tag that would have been
 * previously used for this entry's MAC and VLAN (either before 'e' was
 * inserted, if it is new, or otherwise before its port was updated.)
 *
 * The client should call this function after obtaining a MAC learning entry
 * from mac_learning_insert(), if the entry is either new or if its learned
 * port has changed. */
void
mac_learning_changed(struct mac_learning *ml)
{
    COVERAGE_INC(mac_learning_learned);
    ml->need_revalidate = true;
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml' and returns the associated MAC
 * learning entry, if any.  If 'tag' is nonnull, then the tag that associates
 * 'dst' and 'vlan' with its currently learned port will be OR'd into
 * '*tag'. */
struct mac_entry *
mac_learning_lookup(const struct mac_learning *ml,
                    const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan)
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
        struct mac_entry *e = mac_entry_lookup(ml, dst, vlan);

        ovs_assert(e == NULL || e->port.p != NULL);
        return e;
    }
}

/* Expires 'e' from the 'ml' hash table. */
void
mac_learning_expire(struct mac_learning *ml, struct mac_entry *e)
{
    hmap_remove(&ml->table, &e->hmap_node);
    list_remove(&e->lru_node);
    free(e);
}

/* Expires all the mac-learning entries in 'ml'.  If not NULL, the tags in 'ml'
 * are added to 'tags'.  Otherwise the tags in 'ml' are discarded.  The client
 * is responsible for revalidating any flows that depend on 'ml', if
 * necessary. */
void
mac_learning_flush(struct mac_learning *ml)
{
    struct mac_entry *e;
    while (get_lru(ml, &e)){
        ml->need_revalidate = true;
        mac_learning_expire(ml, e);
    }
    hmap_shrink(&ml->table);
}

/* Does periodic work required by 'ml'.  Returns true if something changed that
 * may require flow revalidation. */
bool
mac_learning_run(struct mac_learning *ml)
{
    bool need_revalidate;
    struct mac_entry *e;

    while (get_lru(ml, &e)
           && (hmap_count(&ml->table) > ml->max_entries
               || time_now() >= e->expires)) {
        COVERAGE_INC(mac_learning_expired);
        ml->need_revalidate = true;
        mac_learning_expire(ml, e);
    }

    need_revalidate = ml->need_revalidate;
    ml->need_revalidate = false;
    return need_revalidate;
}

void
mac_learning_wait(struct mac_learning *ml)
{
    if (hmap_count(&ml->table) > ml->max_entries
        || ml->need_revalidate) {
        poll_immediate_wake();
    } else if (!list_is_empty(&ml->lrus)) {
        struct mac_entry *e = mac_entry_from_lru_node(ml->lrus.next);
        poll_timer_wait_until(e->expires * 1000LL);
    }
}
