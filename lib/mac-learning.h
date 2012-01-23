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

#ifndef MAC_LEARNING_H
#define MAC_LEARNING_H 1

#include <time.h>
#include "list.h"
#include "packets.h"
#include "tag.h"

#define MAC_HASH_BITS 10
#define MAC_HASH_MASK (MAC_HASH_SIZE - 1)
#define MAC_HASH_SIZE (1u << MAC_HASH_BITS)

#define MAC_MAX 2048

/* Time, in seconds, before expiring a mac_entry due to inactivity. */
#define MAC_ENTRY_IDLE_TIME 300

/* Time, in seconds, to lock an entry updated by a gratuitous ARP to avoid
 * relearning based on a reflection from a bond slave. */
#define MAC_GRAT_ARP_LOCK_TIME 5

enum grat_arp_lock_type {
    GRAT_ARP_LOCK_NONE,
    GRAT_ARP_LOCK_SET,
    GRAT_ARP_LOCK_CHECK
};

/* A MAC learning table entry. */
struct mac_entry {
    struct list hash_node;      /* Element in a mac_learning 'table' list. */
    struct list lru_node;       /* Element in 'lrus' or 'free' list. */
    time_t expires;             /* Expiration time. */
    time_t grat_arp_lock;       /* Gratuitous ARP lock expiration time. */
    uint8_t mac[ETH_ADDR_LEN];  /* Known MAC address. */
    uint16_t vlan;              /* VLAN tag. */
    int port;                   /* Port on which MAC was most recently seen. */
    tag_type tag;               /* Tag for this learning entry. */
};

int mac_entry_age(const struct mac_entry *);

/* MAC learning table. */
struct mac_learning {
    struct list free;           /* Not-in-use entries. */
    struct list lrus;           /* In-use entries, least recently used at the
                                   front, most recently used at the back. */
    struct list table[MAC_HASH_SIZE]; /* Hash table. */
    struct mac_entry entries[MAC_MAX]; /* All entries. */
    uint32_t secret;            /* Secret for randomizing hash table. */
    unsigned long *flood_vlans; /* Bitmap of learning disabled VLANs. */
};

struct mac_learning *mac_learning_create(void);
void mac_learning_destroy(struct mac_learning *);
bool mac_learning_set_flood_vlans(struct mac_learning *,
                                  unsigned long *bitmap);
tag_type mac_learning_learn(struct mac_learning *,
                            const uint8_t src[ETH_ADDR_LEN], uint16_t vlan,
                            uint16_t src_port, enum grat_arp_lock_type
                            lock_type);
int mac_learning_lookup(const struct mac_learning *,
                        const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan,
                        bool *is_grat_arp_locked);
int mac_learning_lookup_tag(const struct mac_learning *,
                            const uint8_t dst[ETH_ADDR_LEN],
                            uint16_t vlan, tag_type *tag,
                            bool *is_grat_arp_locked);
void mac_learning_flush(struct mac_learning *);
void mac_learning_run(struct mac_learning *, struct tag_set *);
void mac_learning_wait(struct mac_learning *);

#endif /* mac-learning.h */
