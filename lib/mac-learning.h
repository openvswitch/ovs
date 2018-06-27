/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef MAC_LEARNING_H
#define MAC_LEARNING_H 1

#include <time.h>
#include "heap.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "packets.h"
#include "timeval.h"

/* MAC learning table
 * ==================
 *
 * A MAC learning table is a dictionary data structure that is specialized to
 * map from an (Ethernet address, VLAN ID) pair to a user-provided pointer.  In
 * an Ethernet switch implementation, it used to keep track of the port on
 * which a packet from a given Ethernet address was last seen.  This knowledge
 * is useful when the switch receives a packet to such an Ethernet address, so
 * that the switch can send the packet directly to the correct port instead of
 * having to flood it to every port.
 *
 * A few complications make the implementation into more than a simple wrapper
 * around a hash table.  First, and most simply, MAC learning can be disabled
 * on a per-VLAN basis. (This is most useful for RSPAN; see
 * ovs-vswitchd.conf.db(5) documentation of the "output_vlan" column in the
 * Mirror table for more information.).  The data structure maintains a bitmap
 * to track such VLANs.
 *
 * Second, the implementation has the ability to "lock" a MAC table entry
 * updated by a gratuitous ARP.  This is a simple feature but the rationale for
 * it is complicated.  Refer to the description of SLB bonding in the
 * 'ovs-vswitchd Internals' guide for an explanation.
 *
 * Third, the implementation expires entries that are idle for longer than a
 * configurable amount of time.  This is implemented by keeping all of the
 * current table entries on a list ordered from least recently used (LRU) to
 * most recently used (MRU).  Each time a MAC entry is used, it is moved to the
 * MRU end of the list.  Periodically mac_learning_run() sweeps through the
 * list starting from the LRU end, deleting each entry that has been idle too
 * long.
 *
 * Finally, the number of MAC learning table entries has a configurable maximum
 * size to prevent memory exhaustion.  When a new entry must be inserted but
 * the table is already full, the implementation uses an eviction strategy
 * based on fairness: it chooses the port that currently has greatest number of
 * learned MACs (choosing arbitrarily in case of a tie), and among that port's
 * entries it evicts the least recently used.  (This is a security feature
 * because it prevents an attacker from forcing other ports' MACs out of the
 * MAC learning table with a "MAC flooding attack" that causes the other ports'
 * traffic to be flooded so that the attacker can easily sniff it.)  The
 * implementation of this feature is like a specialized form of the
 * general-purpose "eviction groups" that OVS implements in OpenFlow (see the
 * documentation of the "groups" column in the Flow_Table table in
 * ovs-vswitchd.conf.db(5) for details).
 *
 *
 * Thread-safety
 * =============
 *
 * Many operations require the caller to take the MAC learning table's rwlock
 * for writing (please refer to the Clang thread safety annotations).  The
 * important exception to this is mac_learning_lookup(), which only needs a
 * read lock.  This is useful for the common case where a MAC learning entry
 * being looked up already exists and does not need an update.  However,
 * there's no deadlock-free way to upgrade a read lock to a write lock, so in
 * the case where the lookup result means that an update is required, the
 * caller must drop the read lock, take the write lock, and then repeat the
 * lookup (in case some other thread has already made a change).
 */

struct mac_learning;

/* Default maximum size of a MAC learning table, in entries. */
#define MAC_DEFAULT_MAX 8192

/* Time, in seconds, before expiring a mac_entry due to inactivity. */
#define MAC_ENTRY_DEFAULT_IDLE_TIME 300

/* Time, in seconds, to lock an entry updated by a gratuitous ARP to avoid
 * relearning based on a reflection from a bond slave. */
#define MAC_GRAT_ARP_LOCK_TIME 5

/* A MAC learning table entry.
 * Guarded by owning 'mac_learning''s rwlock. */
struct mac_entry {
    struct hmap_node hmap_node; /* Node in a mac_learning hmap. */
    time_t expires;             /* Expiration time. */
    time_t grat_arp_lock;       /* Gratuitous ARP lock expiration time. */
    struct eth_addr mac;        /* Known MAC address. */
    uint16_t vlan;              /* VLAN tag. */

    /* The following are marked guarded to prevent users from iterating over or
     * accessing a mac_entry without holding the parent mac_learning rwlock. */
    struct ovs_list lru_node OVS_GUARDED; /* Element in 'lrus' list. */

    /* Learned port.
     *
     * The client-specified data is mlport->port. */
    struct mac_learning_port *mlport;
    struct ovs_list port_lru_node; /* In mac_learning_port's "port_lru"s. */
};

static inline void *mac_entry_get_port(const struct mac_learning *ml,
                                       const struct mac_entry *);
void mac_entry_set_port(struct mac_learning *, struct mac_entry *, void *port);

/* Information about client-provided port pointers (the 'port' member), to
 * allow for per-port fairness.
 *
 * The client-provided pointer is opaque to the MAC-learning table, which never
 * dereferences it. */
struct mac_learning_port {
    struct hmap_node hmap_node; /* In mac_learning's "ports_by_ptr". */
    struct heap_node heap_node; /* In mac_learning's "ports_by_usage". */
    void *port;                 /* Client-provided port pointer. */
    struct ovs_list port_lrus;  /* Contains "struct mac_entry"s by port_lru. */
};

/* Sets a gratuitous ARP lock on 'mac' that will expire in
 * MAC_GRAT_ARP_LOCK_TIME seconds. */
static inline void mac_entry_set_grat_arp_lock(struct mac_entry *mac)
{
    mac->grat_arp_lock = time_now() + MAC_GRAT_ARP_LOCK_TIME;
}

/* Returns true if a gratuitous ARP lock is in effect on 'mac', false if none
 * has ever been asserted or if it has expired. */
static inline bool mac_entry_is_grat_arp_locked(const struct mac_entry *mac)
{
    return time_now() < mac->grat_arp_lock;
}

/* MAC learning table. */
struct mac_learning {
    struct hmap table;          /* Learning table. */
    struct ovs_list lrus OVS_GUARDED; /* In-use entries, LRU at front. */
    uint32_t secret;            /* Secret for randomizing hash table. */
    unsigned long *flood_vlans; /* Bitmap of learning disabled VLANs. */
    unsigned int idle_time;     /* Max age before deleting an entry. */
    size_t max_entries;         /* Max number of learned MACs. */
    struct ovs_refcount ref_cnt;
    struct ovs_rwlock rwlock;
    bool need_revalidate;

    /* Fairness.
     *
     * Both of these data structures include the same "struct
     * mac_learning_port" but indexed differently.
     *
     * ports_by_usage is a per-port max-heap, in which the priority is the
     * number of MAC addresses for the port.  When the MAC learning table
     * overflows, this allows us to evict a MAC entry from one of the ports
     * that have the largest number of MAC entries, achieving a form of
     * fairness.
     *
     * ports_by_ptr is a hash table indexed by the client-provided pointer. */
    struct hmap ports_by_ptr;   /* struct mac_learning_port hmap_nodes. */
    struct heap ports_by_usage; /* struct mac_learning_port heap_nodes. */
};

int mac_entry_age(const struct mac_learning *ml, const struct mac_entry *e)
    OVS_REQ_RDLOCK(ml->rwlock);

/* Basics. */
struct mac_learning *mac_learning_create(unsigned int idle_time);
struct mac_learning *mac_learning_ref(const struct mac_learning *);
void mac_learning_unref(struct mac_learning *);

bool mac_learning_run(struct mac_learning *ml) OVS_REQ_WRLOCK(ml->rwlock);
void mac_learning_wait(struct mac_learning *ml)
    OVS_REQ_RDLOCK(ml->rwlock);

/* Configuration. */
bool mac_learning_set_flood_vlans(struct mac_learning *ml,
                                  const unsigned long *bitmap)
    OVS_REQ_WRLOCK(ml->rwlock);
void mac_learning_set_idle_time(struct mac_learning *ml,
                                unsigned int idle_time)
    OVS_REQ_WRLOCK(ml->rwlock);
void mac_learning_set_max_entries(struct mac_learning *ml, size_t max_entries)
    OVS_REQ_WRLOCK(ml->rwlock);

/* Learning. */
bool mac_learning_may_learn(const struct mac_learning *ml,
                            const struct eth_addr src_mac,
                            uint16_t vlan)
    OVS_REQ_RDLOCK(ml->rwlock);
struct mac_entry *mac_learning_insert(struct mac_learning *ml,
                                      const struct eth_addr src,
                                      uint16_t vlan)
    OVS_REQ_WRLOCK(ml->rwlock);
bool mac_learning_update(struct mac_learning *ml, struct eth_addr src,
                         int vlan, bool is_gratuitous_arp, bool is_bond,
                         void *in_port)
    OVS_EXCLUDED(ml->rwlock);

/* Lookup. */
struct mac_entry *mac_learning_lookup(const struct mac_learning *ml,
                                      const struct eth_addr dst,
                                      uint16_t vlan)
    OVS_REQ_RDLOCK(ml->rwlock);

/* Flushing. */
void mac_learning_expire(struct mac_learning *ml, struct mac_entry *e)
    OVS_REQ_WRLOCK(ml->rwlock);
void mac_learning_flush(struct mac_learning *ml) OVS_REQ_WRLOCK(ml->rwlock);

/* Inlines. */

static inline void *
mac_entry_get_port(const struct mac_learning *ml OVS_UNUSED,
                   const struct mac_entry *e)
    OVS_REQ_RDLOCK(ml->rwlock)
{
    return e->mlport ? e->mlport->port : NULL;
}

#endif /* mac-learning.h */
