/*
 * Copyright (c) 2008, 2009, 2010, 2012 Nicira Networks.
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

/* Returns the number of seconds since 'e' (within 'ml') was last learned. */
int
mac_entry_age(const struct mac_learning *ml, const struct mac_entry *e)
{
    time_t remaining = e->expires - time_now();
    return ml->idle_time - remaining;
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
    const struct list *list = &ml->table[hash & MAC_HASH_MASK];
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

/* Removes 'e' from the 'ml' hash table.  'e' must not already be on the free
 * list. */
static void
free_mac_entry(struct mac_learning *ml, struct mac_entry *e)
{
    list_remove(&e->hash_node);
    list_remove(&e->lru_node);
    list_push_front(&ml->free, &e->lru_node);
}

static unsigned int
normalize_idle_time(unsigned int idle_time)
{
    return (idle_time < 15 ? 15
            : idle_time > 3600 ? 3600
            : idle_time);
}

/* Creates and returns a new MAC learning table with an initial MAC aging
 * timeout of 'idle_time' seconds. */
struct mac_learning *
mac_learning_create(unsigned int idle_time)
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
    ml->idle_time = normalize_idle_time(idle_time);
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

static bool
is_learning_vlan(const struct mac_learning *ml, uint16_t vlan)
{
    return !(ml->flood_vlans && bitmap_is_set(ml->flood_vlans, vlan));
}

/* Attempts to make 'ml' learn from the fact that a frame from 'src_mac' was
 * just observed arriving from 'src_port' on the given 'vlan'.
 *
 * Returns nonzero if we actually learned something from this, zero if it just
 * confirms what we already knew.  The nonzero return value is the tag of flows
 * that now need revalidation.
 *
 * The 'vlan' parameter is used to maintain separate per-VLAN learning tables.
 * Specify 0 if this behavior is undesirable.
 *
 * 'lock_type' specifies whether the entry should be locked or existing locks
 * are check. */
tag_type
mac_learning_learn(struct mac_learning *ml,
                   const uint8_t src_mac[ETH_ADDR_LEN], uint16_t vlan,
                   uint16_t src_port, enum grat_arp_lock_type lock_type)
{
    struct mac_entry *e;
    struct list *bucket;

    if (!is_learning_vlan(ml, vlan)) {
        return 0;
    }

    if (eth_addr_is_multicast(src_mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 30);
        VLOG_DBG_RL(&rl, "multicast packet source "ETH_ADDR_FMT,
                    ETH_ADDR_ARGS(src_mac));
        return 0;
    }

    bucket = mac_table_bucket(ml, src_mac, vlan);
    e = search_bucket(bucket, src_mac, vlan);
    if (!e) {
        if (!list_is_empty(&ml->free)) {
            e = mac_entry_from_lru_node(ml->free.next);
        } else {
            e = mac_entry_from_lru_node(ml->lrus.next);
            list_remove(&e->hash_node);
        }
        memcpy(e->mac, src_mac, ETH_ADDR_LEN);
        list_push_front(bucket, &e->hash_node);
        e->port = -1;
        e->vlan = vlan;
        e->tag = make_unknown_mac_tag(ml, src_mac, vlan);
        e->grat_arp_lock = TIME_MIN;
    }

    if (lock_type != GRAT_ARP_LOCK_CHECK || time_now() >= e->grat_arp_lock) {
        /* Make the entry most-recently-used. */
        list_remove(&e->lru_node);
        list_push_back(&ml->lrus, &e->lru_node);
        e->expires = time_now() + ml->idle_time;
        if (lock_type == GRAT_ARP_LOCK_SET) {
            e->grat_arp_lock = time_now() + MAC_GRAT_ARP_LOCK_TIME;
        }

        /* Did we learn something? */
        if (e->port != src_port) {
            tag_type old_tag = e->tag;
            e->port = src_port;
            e->tag = tag_create_random();
            COVERAGE_INC(mac_learning_learned);
            return old_tag;
        }
    }

    return 0;
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml'.  Returns the port on which a
 * frame destined for 'dst' should be sent, -1 if unknown. 'is_grat_arp_locked'
 * is an optional parameter that returns whether the entry is currently
 * locked. */
int
mac_learning_lookup(const struct mac_learning *ml,
                    const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan,
                    bool *is_grat_arp_locked)
{
    tag_type tag = 0;
    return mac_learning_lookup_tag(ml, dst, vlan, &tag, is_grat_arp_locked);
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml'.  Returns the port on which a
 * frame destined for 'dst' should be sent, -1 if unknown.
 *
 * Adds to '*tag' (which the caller must have initialized) the tag that should
 * be attached to any flow created based on the return value, if any, to allow
 * those flows to be revalidated when the MAC learning entry changes.
 *
 * 'is_grat_arp_locked' is an optional parameter that returns whether the entry
 * is currently locked.*/
int
mac_learning_lookup_tag(const struct mac_learning *ml,
                        const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan,
                        tag_type *tag, bool *is_grat_arp_locked)
{
    if (eth_addr_is_multicast(dst) || !is_learning_vlan(ml, vlan)) {
        return -1;
    } else {
        struct mac_entry *e = search_bucket(mac_table_bucket(ml, dst, vlan),
                                            dst, vlan);
        if (e) {
            *tag |= e->tag;

            if (is_grat_arp_locked) {
                *is_grat_arp_locked = time_now() < e->grat_arp_lock;
            }

            return e->port;
        } else {
            *tag |= make_unknown_mac_tag(ml, dst, vlan);
            return -1;
        }
    }
}

/* Expires all the mac-learning entries in 'ml'.  The tags in 'ml' are
 * discarded, so the client is responsible for revalidating any flows that
 * depend on 'ml', if necessary. */
void
mac_learning_flush(struct mac_learning *ml)
{
    struct mac_entry *e;
    while (get_lru(ml, &e)){
        free_mac_entry(ml, e);
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
        free_mac_entry(ml, e);
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
