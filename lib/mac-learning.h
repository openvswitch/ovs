/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "hmap.h"
#include "list.h"
#include "packets.h"
#include "tag.h"
#include "timeval.h"

struct mac_learning;

#define MAC_MAX 2048

/* Time, in seconds, before expiring a mac_entry due to inactivity. */
#define MAC_ENTRY_DEFAULT_IDLE_TIME 300

/* Time, in seconds, to lock an entry updated by a gratuitous ARP to avoid
 * relearning based on a reflection from a bond slave. */
#define MAC_GRAT_ARP_LOCK_TIME 5

/* A MAC learning table entry. */
struct mac_entry {
    struct hmap_node hmap_node; /* Node in a mac_learning hmap. */
    struct list lru_node;       /* Element in 'lrus' list. */
    time_t expires;             /* Expiration time. */
    time_t grat_arp_lock;       /* Gratuitous ARP lock expiration time. */
    uint8_t mac[ETH_ADDR_LEN];  /* Known MAC address. */
    uint16_t vlan;              /* VLAN tag. */
    tag_type tag;               /* Tag for this learning entry. */

    /* Learned port. */
    union {
        void *p;
        int i;
    } port;
};

int mac_entry_age(const struct mac_learning *, const struct mac_entry *);

/* Returns true if mac_learning_insert() just created 'mac' and the caller has
 * not yet properly initialized it. */
static inline bool mac_entry_is_new(const struct mac_entry *mac)
{
    return !mac->tag;
}

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
    struct list lrus;           /* In-use entries, least recently used at the
                                   front, most recently used at the back. */
    uint32_t secret;            /* Secret for randomizing hash table. */
    unsigned long *flood_vlans; /* Bitmap of learning disabled VLANs. */
    unsigned int idle_time;     /* Max age before deleting an entry. */
};

/* Basics. */
struct mac_learning *mac_learning_create(unsigned int idle_time);
void mac_learning_destroy(struct mac_learning *);

void mac_learning_run(struct mac_learning *, struct tag_set *);
void mac_learning_wait(struct mac_learning *);

/* Configuration. */
bool mac_learning_set_flood_vlans(struct mac_learning *,
                                  const unsigned long *bitmap);
void mac_learning_set_idle_time(struct mac_learning *, unsigned int idle_time);

/* Learning. */
bool mac_learning_may_learn(const struct mac_learning *,
                            const uint8_t src_mac[ETH_ADDR_LEN],
                            uint16_t vlan);
struct mac_entry *mac_learning_insert(struct mac_learning *,
                                      const uint8_t src[ETH_ADDR_LEN],
                                      uint16_t vlan);
tag_type mac_learning_changed(struct mac_learning *, struct mac_entry *);

/* Lookup. */
struct mac_entry *mac_learning_lookup(const struct mac_learning *,
                                      const uint8_t dst[ETH_ADDR_LEN],
                                      uint16_t vlan, tag_type *);

/* Flushing. */
void mac_learning_expire(struct mac_learning *, struct mac_entry *);
void mac_learning_flush(struct mac_learning *, struct tag_set *);

#endif /* mac-learning.h */
