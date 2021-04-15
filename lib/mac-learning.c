/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "vlan-bitmap.h"

COVERAGE_DEFINE(mac_learning_learned);
COVERAGE_DEFINE(mac_learning_expired);
COVERAGE_DEFINE(mac_learning_evicted);
COVERAGE_DEFINE(mac_learning_moved);

/* Returns the number of seconds since 'e' (within 'ml') was last learned. */
int
mac_entry_age(const struct mac_learning *ml, const struct mac_entry *e)
{
    time_t remaining = e->expires - time_now();
    return ml->idle_time - remaining;
}

static uint32_t
mac_table_hash(const struct mac_learning *ml, const struct eth_addr mac,
               uint16_t vlan)
{
    return hash_mac(mac, vlan, ml->secret);
}

static struct mac_entry *
mac_entry_from_lru_node(struct ovs_list *list)
{
    return CONTAINER_OF(list, struct mac_entry, lru_node);
}

static struct mac_entry *
mac_entry_lookup(const struct mac_learning *ml,
                 const struct eth_addr mac, uint16_t vlan)
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

static struct mac_learning_port *
mac_learning_port_lookup(struct mac_learning *ml, void *port)
{
    struct mac_learning_port *mlport;

    HMAP_FOR_EACH_IN_BUCKET (mlport, hmap_node, hash_pointer(port, ml->secret),
                             &ml->ports_by_ptr) {
        if (mlport->port == port) {
            return mlport;
        }
    }
    return NULL;
}

/* Changes the client-owned pointer for entry 'e' in 'ml' to 'port'.  The
 * pointer can be retrieved with mac_entry_get_port().
 *
 * The MAC-learning implementation treats the data that 'port' points to as
 * opaque and never tries to dereference it.  However, when a MAC learning
 * table becomes overfull, so that eviction is required, the implementation
 * does first evict MAC entries for the most common 'port's values in 'ml', so
 * that there is a degree of fairness, that is, each port is entitled to its
 * fair share of MAC entries. */
void
mac_entry_set_port(struct mac_learning *ml, struct mac_entry *e, void *port)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    if (mac_entry_get_port(ml, e) != port) {
        ml->need_revalidate = true;

        if (e->mlport) {
            struct mac_learning_port *mlport = e->mlport;
            ovs_list_remove(&e->port_lru_node);

            if (ovs_list_is_empty(&mlport->port_lrus)) {
                ovs_assert(mlport->heap_node.priority == 1);
                hmap_remove(&ml->ports_by_ptr, &mlport->hmap_node);
                heap_remove(&ml->ports_by_usage, &mlport->heap_node);
                free(mlport);
            } else {
                ovs_assert(mlport->heap_node.priority > 1);
                heap_change(&ml->ports_by_usage, &mlport->heap_node,
                            mlport->heap_node.priority - 1);
            }
            e->mlport = NULL;
        }

        if (port) {
            struct mac_learning_port *mlport;

            mlport = mac_learning_port_lookup(ml, port);
            if (!mlport) {
                mlport = xzalloc(sizeof *mlport);
                hmap_insert(&ml->ports_by_ptr, &mlport->hmap_node,
                            hash_pointer(port, ml->secret));
                heap_insert(&ml->ports_by_usage, &mlport->heap_node, 1);
                mlport->port = port;
                ovs_list_init(&mlport->port_lrus);
            } else {
                heap_change(&ml->ports_by_usage, &mlport->heap_node,
                            mlport->heap_node.priority + 1);
            }
            ovs_list_push_back(&mlport->port_lrus, &e->port_lru_node);
            e->mlport = mlport;
        }
    }
}

/* Finds one of the ports with the most MAC entries and evicts its least
 * recently used entry. */
static void
evict_mac_entry_fairly(struct mac_learning *ml)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    struct mac_learning_port *mlport;
    struct mac_entry *e;

    mlport = CONTAINER_OF(heap_max(&ml->ports_by_usage),
                          struct mac_learning_port, heap_node);
    e = CONTAINER_OF(ovs_list_front(&mlport->port_lrus),
                     struct mac_entry, port_lru_node);
    COVERAGE_INC(mac_learning_evicted);
    ml->total_evicted++;
    mac_learning_expire(ml, e);
}

/* If the LRU list is not empty, stores the least-recently-used entry in '*e'
 * and returns true.  Otherwise, if the LRU list is empty, stores NULL in '*e'
 * and return false. */
static bool
get_lru(struct mac_learning *ml, struct mac_entry **e)
    OVS_REQ_RDLOCK(ml->rwlock)
{
    if (!ovs_list_is_empty(&ml->lrus)) {
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

/* Clear all the mac_learning statistics */
void
mac_learning_clear_statistics(struct mac_learning *ml)
{
    if (ml != NULL) {
        ml->total_learned = 0;
        ml->total_expired = 0;
        ml->total_evicted = 0;
        ml->total_moved = 0;
    }
}

/* Creates and returns a new MAC learning table with an initial MAC aging
 * timeout of 'idle_time' seconds and an initial maximum of MAC_DEFAULT_MAX
 * entries. */
struct mac_learning *
mac_learning_create(unsigned int idle_time)
{
    struct mac_learning *ml;

    ml = xmalloc(sizeof *ml);
    ovs_list_init(&ml->lrus);
    hmap_init(&ml->table);
    ml->secret = random_uint32();
    ml->flood_vlans = NULL;
    ml->idle_time = normalize_idle_time(idle_time);
    ml->max_entries = MAC_DEFAULT_MAX;
    ml->need_revalidate = false;
    hmap_init(&ml->ports_by_ptr);
    heap_init(&ml->ports_by_usage);
    ovs_refcount_init(&ml->ref_cnt);
    ovs_rwlock_init(&ml->rwlock);
    mac_learning_clear_statistics(ml);
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

        ovs_rwlock_wrlock(&ml->rwlock);
        HMAP_FOR_EACH_SAFE (e, next, hmap_node, &ml->table) {
            mac_learning_expire(ml, e);
        }
        hmap_destroy(&ml->table);
        hmap_destroy(&ml->ports_by_ptr);
        heap_destroy(&ml->ports_by_usage);

        bitmap_free(ml->flood_vlans);
        ovs_rwlock_unlock(&ml->rwlock);
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
                       const struct eth_addr src_mac, uint16_t vlan)
{
    return ml && is_learning_vlan(ml, vlan) && !eth_addr_is_multicast(src_mac);
}

/* Searches 'ml' for and returns a MAC learning entry for 'src_mac' in 'vlan',
 * inserting a new entry if necessary.  The caller must have already verified,
 * by calling mac_learning_may_learn(), that 'src_mac' and 'vlan' are
 * learnable.
 *
 * If the returned MAC entry is new (that is, if it has a NULL client-provided
 * port, as returned by mac_entry_get_port()), then the caller must initialize
 * the new entry's port to a nonnull value with mac_entry_set_port(). */
struct mac_entry *
mac_learning_insert(struct mac_learning *ml,
                    const struct eth_addr src_mac, uint16_t vlan)
{
    struct mac_entry *e;

    e = mac_entry_lookup(ml, src_mac, vlan);
    if (!e) {
        uint32_t hash = mac_table_hash(ml, src_mac, vlan);

        if (hmap_count(&ml->table) >= ml->max_entries) {
            evict_mac_entry_fairly(ml);
        }

        e = xmalloc(sizeof *e);
        hmap_insert(&ml->table, &e->hmap_node, hash);
        e->mac = src_mac;
        e->vlan = vlan;
        e->grat_arp_lock = TIME_MIN;
        e->mlport = NULL;
        COVERAGE_INC(mac_learning_learned);
        ml->total_learned++;
    } else {
        ovs_list_remove(&e->lru_node);
    }

    /* Mark 'e' as recently used. */
    ovs_list_push_back(&ml->lrus, &e->lru_node);
    if (e->mlport) {
        ovs_list_remove(&e->port_lru_node);
        ovs_list_push_back(&e->mlport->port_lrus, &e->port_lru_node);
    }
    e->expires = time_now() + ml->idle_time;

    return e;
}

/* Checks whether a MAC learning update is necessary for MAC learning table
 * 'ml' given that a packet matching 'src' was received on 'in_port' in 'vlan',
 * and given that the packet was gratuitous ARP if 'is_gratuitous_arp' is
 * 'true' and 'in_port' is a bond port if 'is_bond' is 'true'.
 *
 * Most packets processed through the MAC learning table do not actually
 * change it in any way.  This function requires only a read lock on the MAC
 * learning table, so it is much cheaper in this common case.
 *
 * Keep the code here synchronized with that in update_learning_table__()
 * below. */
static bool
is_mac_learning_update_needed(const struct mac_learning *ml,
                              struct eth_addr src, int vlan,
                              bool is_gratuitous_arp, bool is_bond,
                              void *in_port)
    OVS_REQ_RDLOCK(ml->rwlock)
{
    struct mac_entry *mac;

    if (!mac_learning_may_learn(ml, src, vlan)) {
        return false;
    }

    mac = mac_learning_lookup(ml, src, vlan);
    if (!mac || mac_entry_age(ml, mac)) {
        return true;
    }

    if (is_gratuitous_arp) {
        /* We don't want to learn from gratuitous ARP packets that are
         * reflected back over bond members so we lock the learning table.  For
         * more detail, see the bigger comment in update_learning_table__(). */
        if (!is_bond) {
            return true;   /* Need to set the gratuitous ARP lock. */
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return false;
        }
    }

    return mac_entry_get_port(ml, mac) != in_port /* ofbundle */;
}

/* Updates MAC learning table 'ml' given that a packet matching 'src' was
 * received on 'in_port' in 'vlan', and given that the packet was gratuitous
 * ARP if 'is_gratuitous_arp' is 'true' and 'in_port' is a bond port if
 * 'is_bond' is 'true'.
 *
 * This code repeats all the checks in is_mac_learning_update_needed() because
 * the lock was released between there and here and thus the MAC learning state
 * could have changed.
 *
 * Returns 'true' if 'ml' was updated, 'false' otherwise.
 *
 * Keep the code here synchronized with that in is_mac_learning_update_needed()
 * above. */
static bool
update_learning_table__(struct mac_learning *ml, struct eth_addr src,
                        int vlan, bool is_gratuitous_arp, bool is_bond,
                        void *in_port)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    struct mac_entry *mac;

    if (!mac_learning_may_learn(ml, src, vlan)) {
        return false;
    }

    mac = mac_learning_insert(ml, src, vlan);
    if (is_gratuitous_arp) {
        /* Gratuitous ARP packets received over non-bond interfaces could be
         * reflected back over bond members.  We don't want to learn from these
         * reflected packets, so we lock each entry for which a gratuitous ARP
         * packet was received over a non-bond interface and refrain from
         * learning from gratuitous ARP packets that arrive over bond
         * interfaces for this entry while the lock is in effect. Refer to the
         * 'ovs-vswitch Internals' document for more in-depth discussion on
         * this topic. */
        if (!is_bond) {
            mac_entry_set_grat_arp_lock(mac);
        } else if (mac_entry_is_grat_arp_locked(mac)) {
            return false;
        }
    }

    if (mac_entry_get_port(ml, mac) != in_port) {
        if (mac_entry_get_port(ml, mac) != NULL) {
            COVERAGE_INC(mac_learning_moved);
            ml->total_moved++;
        }
        mac_entry_set_port(ml, mac, in_port);
        return true;
    }
    return false;
}

/* Updates MAC learning table 'ml' given that a packet matching 'src' was
 * received on 'in_port' in 'vlan', and given that the packet was gratuitous
 * ARP if 'is_gratuitous_arp' is 'true' and 'in_port' is a bond port if
 * 'is_bond' is 'true'.
 *
 * Returns 'true' if 'ml' was updated, 'false' otherwise. */
bool
mac_learning_update(struct mac_learning *ml, struct eth_addr src,
                    int vlan, bool is_gratuitous_arp, bool is_bond,
                    void *in_port)
    OVS_EXCLUDED(ml->rwlock)
{
    bool need_update;
    bool updated = false;

    /* Don't learn the OFPP_NONE port. */
    if (in_port != NULL) {
        /* First try the common case: no change to MAC learning table. */
        ovs_rwlock_rdlock(&ml->rwlock);
        need_update = is_mac_learning_update_needed(ml, src, vlan,
                                                    is_gratuitous_arp, is_bond,
                                                    in_port);
        ovs_rwlock_unlock(&ml->rwlock);

        if (need_update) {
            /* Slow path: MAC learning table might need an update. */
            ovs_rwlock_wrlock(&ml->rwlock);
            updated = update_learning_table__(ml, src, vlan, is_gratuitous_arp,
                                              is_bond, in_port);
            ovs_rwlock_unlock(&ml->rwlock);
        }
    }
    return updated;
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml' and returns the associated MAC
 * learning entry, if any. */
struct mac_entry *
mac_learning_lookup(const struct mac_learning *ml,
                    const struct eth_addr dst, uint16_t vlan)
{
    if (eth_addr_is_multicast(dst)) {
        return NULL;
    } else if (!is_learning_vlan(ml, vlan)) {
        return NULL;
    } else {
        struct mac_entry *e = mac_entry_lookup(ml, dst, vlan);

        ovs_assert(e == NULL || mac_entry_get_port(ml, e) != NULL);
        return e;
    }
}

/* Expires 'e' from the 'ml' hash table. */
void
mac_learning_expire(struct mac_learning *ml, struct mac_entry *e)
{
    ml->need_revalidate = true;
    mac_entry_set_port(ml, e, NULL);
    hmap_remove(&ml->table, &e->hmap_node);
    ovs_list_remove(&e->lru_node);
    free(e);
}

/* Expires all the mac-learning entries in 'ml'. */
void
mac_learning_flush(struct mac_learning *ml)
{
    struct mac_entry *e;
    while (get_lru(ml, &e)){
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
        ml->total_expired++;
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
    } else if (!ovs_list_is_empty(&ml->lrus)) {
        struct mac_entry *e = mac_entry_from_lru_node(ml->lrus.next);
        poll_timer_wait_until(e->expires * 1000LL);
    }
}
