/*
 * Copyright (c) 2014 Red Hat, Inc.
 *
 * Based on mac-learning implementation.
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

#ifndef MCAST_SNOOPING_H
#define MCAST_SNOOPING_H 1

#include <time.h>
#include "dp-packet.h"
#include "hmap.h"
#include "openvswitch/list.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "packets.h"
#include "timeval.h"

struct mcast_snooping;

/* Default maximum size of a mcast snooping table, in entries. */
#define MCAST_DEFAULT_MAX_ENTRIES 2048

/* Time, in seconds, before expiring a mcast_group due to inactivity. */
#define MCAST_ENTRY_DEFAULT_IDLE_TIME 300

/* Time, in seconds, before expiring a mrouter_port due to inactivity. */
#define MCAST_MROUTER_PORT_IDLE_TIME 180

/* Multicast group entry.
 * Guarded by owning 'mcast_snooping''s rwlock. */
struct mcast_group {
    /* Node in parent struct mcast_snooping hmap. */
    struct hmap_node hmap_node;

    /* Multicast group IPv6/IPv4 address. */
    struct in6_addr addr;

    /* VLAN tag. */
    uint16_t vlan;

    /* Node in parent struct mcast_snooping group_lru. */
    struct ovs_list group_node OVS_GUARDED;

    /* Contains struct mcast_group_bundle (ports), least recently used
     * at the front, most recently used at the back. */
    struct ovs_list bundle_lru OVS_GUARDED;
};

/* The bundle associated to the multicast group.
 * Guarded by owning 'mcast_snooping''s rwlock. */
struct mcast_group_bundle {
    /* Node in parent struct mcast_group bundle_lru list. */
    struct ovs_list bundle_node OVS_GUARDED;

    /* When this node expires. */
    time_t expires;

    /* Learned port. */
    void *port OVS_GUARDED;
};

/* The bundle connected to a multicast router.
 * Guarded by owning 'mcast_snooping''s rwlock. */
struct mcast_mrouter_bundle {
    /* Node in parent struct mcast_group mrouter_lru list. */
    struct ovs_list mrouter_node OVS_GUARDED;

    /* When this node expires. */
    time_t expires;

    /* VLAN tag. */
    uint16_t vlan;

    /* Learned port. */
    void *port OVS_GUARDED;
};

/* The bundle to send multicast traffic or Reports.
 * Guarded by owning 'mcast_snooping''s rwlock */
struct mcast_port_bundle {
    /* Node in parent struct mcast_snooping. */
    struct ovs_list node;

    /* VLAN tag. */
    uint16_t vlan;

    /* Learned port. */
    void *port;
};

/* Multicast snooping table. */
struct mcast_snooping {
    /* Snooping/learning table. */
    struct hmap table;

    /* Contains struct mcast_group, least recently used at the front,
     * most recently used at the back. */
    struct ovs_list group_lru OVS_GUARDED;

    /* Contains struct mcast_mrouter_bundle, least recently used at the
     * front, most recently used at the back. */
    struct ovs_list mrouter_lru OVS_GUARDED;

    /* Contains struct mcast_port_bundle to be flooded with multicast
     * packets in no special order. */
    struct ovs_list fport_list OVS_GUARDED;

    /* Contains struct mcast_port_bundle to forward Reports in
     * no special order. */
    struct ovs_list rport_list OVS_GUARDED;

    /* Secret for randomizing hash table. */
    uint32_t secret;

    /* Maximum age before deleting an entry. */
    unsigned int idle_time;

    /* Maximum number of multicast groups learned. */
    size_t max_entries;

    /* True if flow revalidation is needed. */
    bool need_revalidate;

    /* True if unregistered multicast packets should be flooded to all
     * ports, otherwise send them to ports connected to multicast routers. */
    bool flood_unreg;

    struct ovs_refcount ref_cnt;
    struct ovs_rwlock rwlock;
};

/* Basics. */
bool mcast_snooping_enabled(const struct mcast_snooping *ms);
bool mcast_snooping_flood_unreg(const struct mcast_snooping *ms);
int mcast_mrouter_age(const struct mcast_snooping *ms,
                      const struct mcast_mrouter_bundle *m);
int mcast_bundle_age(const struct mcast_snooping *ms,
                     const struct mcast_group_bundle *b);
struct mcast_snooping *mcast_snooping_create(void);
struct mcast_snooping *mcast_snooping_ref(const struct mcast_snooping *);
void mcast_snooping_unref(struct mcast_snooping *);
bool mcast_snooping_run(struct mcast_snooping *ms);
void mcast_snooping_wait(struct mcast_snooping *ms);

/* Configuration. */
void mcast_snooping_set_idle_time(struct mcast_snooping *ms,
                                  unsigned int idle_time)
    OVS_REQ_WRLOCK(ms->rwlock);
void mcast_snooping_set_max_entries(struct mcast_snooping *ms,
                                    size_t max_entries)
    OVS_REQ_WRLOCK(ms->rwlock);
bool
mcast_snooping_set_flood_unreg(struct mcast_snooping *ms, bool enable)
    OVS_REQ_WRLOCK(ms->rwlock);
void mcast_snooping_set_port_flood(struct mcast_snooping *ms, void *port,
                                   bool flood)
    OVS_REQ_WRLOCK(ms->rwlock);
void mcast_snooping_set_port_flood_reports(struct mcast_snooping *ms,
                                           void *port, bool flood)
    OVS_REQ_WRLOCK(ms->rwlock);

/* Lookup. */
struct mcast_group *
mcast_snooping_lookup(const struct mcast_snooping *ms,
                      const struct in6_addr *dip, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock);
struct mcast_group *
mcast_snooping_lookup4(const struct mcast_snooping *ms, ovs_be32 ip4,
                       uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock);

/* Learning. */
bool mcast_snooping_add_group(struct mcast_snooping *ms,
                              const struct in6_addr *addr,
                              uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
bool mcast_snooping_add_group4(struct mcast_snooping *ms, ovs_be32 ip4,
                               uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
int mcast_snooping_add_report(struct mcast_snooping *ms,
                              const struct dp_packet *p,
                              uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
int mcast_snooping_add_mld(struct mcast_snooping *ms,
                           const struct dp_packet *p,
                           uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
bool mcast_snooping_leave_group(struct mcast_snooping *ms,
                                const struct in6_addr *addr,
                                uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
bool mcast_snooping_leave_group4(struct mcast_snooping *ms, ovs_be32 ip4,
                                 uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
bool mcast_snooping_add_mrouter(struct mcast_snooping *ms, uint16_t vlan,
                                void *port)
    OVS_REQ_WRLOCK(ms->rwlock);
bool mcast_snooping_is_query(ovs_be16 igmp_type);
bool mcast_snooping_is_membership(ovs_be16 igmp_type);

/* Flush. */
void mcast_snooping_mdb_flush(struct mcast_snooping *ms);
void mcast_snooping_flush(struct mcast_snooping *ms);

#endif /* mcast-snooping.h */
