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

#include <config.h>
#include "mcast-snooping.h"

#include <inttypes.h>
#include <stdlib.h>

#include "bitmap.h"
#include "byte-order.h"
#include "coverage.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "timeval.h"
#include "entropy.h"
#include "unaligned.h"
#include "util.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"

COVERAGE_DEFINE(mcast_snooping_learned);
COVERAGE_DEFINE(mcast_snooping_expired);

static struct mcast_port_bundle *
mcast_snooping_port_lookup(struct ovs_list *list, void *port);
static struct mcast_mrouter_bundle *
mcast_snooping_mrouter_lookup(struct mcast_snooping *ms, uint16_t vlan,
                              void *port)
    OVS_REQ_RDLOCK(ms->rwlock);

bool
mcast_snooping_enabled(const struct mcast_snooping *ms)
{
    return !!ms;
}

bool
mcast_snooping_flood_unreg(const struct mcast_snooping *ms)
{
    return ms->flood_unreg;
}

bool
mcast_snooping_is_query(ovs_be16 igmp_type)
{
    return igmp_type == htons(IGMP_HOST_MEMBERSHIP_QUERY);
}

bool
mcast_snooping_is_membership(ovs_be16 igmp_type)
{
    switch (ntohs(igmp_type)) {
    case IGMP_HOST_MEMBERSHIP_REPORT:
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
    case IGMP_HOST_LEAVE_MESSAGE:
        return true;
    }
    return false;
}

/* Returns the number of seconds since multicast group 'b' was learned in a
 * port on 'ms'. */
int
mcast_bundle_age(const struct mcast_snooping *ms,
                 const struct mcast_group_bundle *b)
{
    time_t remaining = b->expires - time_now();
    return ms->idle_time - remaining;
}

static uint32_t
mcast_table_hash(const struct mcast_snooping *ms,
                 const struct in6_addr *grp_addr, uint16_t vlan)
{
    return hash_bytes(grp_addr->s6_addr, 16,
                      hash_2words(ms->secret, vlan));
}

static struct mcast_group_bundle *
mcast_group_bundle_from_lru_node(struct ovs_list *list)
{
    return CONTAINER_OF(list, struct mcast_group_bundle, bundle_node);
}

static struct mcast_group *
mcast_group_from_lru_node(struct ovs_list *list)
{
    return CONTAINER_OF(list, struct mcast_group, group_node);
}

/* Searches 'ms' for and returns an mcast group for destination address
 * 'dip' in 'vlan'. */
struct mcast_group *
mcast_snooping_lookup(const struct mcast_snooping *ms,
                      const struct in6_addr *dip, uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_group *grp;
    uint32_t hash;

    hash = mcast_table_hash(ms, dip, vlan);
    HMAP_FOR_EACH_WITH_HASH (grp, hmap_node, hash, &ms->table) {
        if (grp->vlan == vlan && ipv6_addr_equals(&grp->addr, dip)) {
           return grp;
        }
    }
    return NULL;
}

struct mcast_group *
mcast_snooping_lookup4(const struct mcast_snooping *ms, ovs_be32 ip4,
                      uint16_t vlan)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct in6_addr addr = in6_addr_mapped_ipv4(ip4);
    return mcast_snooping_lookup(ms, &addr, vlan);
}

/* If the LRU list is not empty, stores the least-recently-used entry
 * in '*e' and returns true.  Otherwise, if the LRU list is empty,
 * stores NULL in '*e' and return false. */
static bool
group_get_lru(const struct mcast_snooping *ms, struct mcast_group **grp)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    if (!ovs_list_is_empty(&ms->group_lru)) {
        *grp = mcast_group_from_lru_node(ms->group_lru.next);
        return true;
    } else {
        *grp = NULL;
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

/* Creates and returns a new mcast table with an initial mcast aging
 * timeout of MCAST_ENTRY_DEFAULT_IDLE_TIME seconds and an initial maximum of
 * MCAST_DEFAULT_MAX entries. */
struct mcast_snooping *
mcast_snooping_create(void)
{
    struct mcast_snooping *ms;

    ms = xmalloc(sizeof *ms);
    hmap_init(&ms->table);
    ovs_list_init(&ms->group_lru);
    ovs_list_init(&ms->mrouter_lru);
    ovs_list_init(&ms->fport_list);
    ovs_list_init(&ms->rport_list);
    ms->secret = random_uint32();
    ms->idle_time = MCAST_ENTRY_DEFAULT_IDLE_TIME;
    ms->max_entries = MCAST_DEFAULT_MAX_ENTRIES;
    ms->need_revalidate = false;
    ms->flood_unreg = true;
    ovs_refcount_init(&ms->ref_cnt);
    ovs_rwlock_init(&ms->rwlock);
    return ms;
}

struct mcast_snooping *
mcast_snooping_ref(const struct mcast_snooping *ms_)
{
    struct mcast_snooping *ms = CONST_CAST(struct mcast_snooping *, ms_);
    if (ms) {
        ovs_refcount_ref(&ms->ref_cnt);
    }
    return ms;
}

/* Unreferences (and possibly destroys) mcast snooping table 'ms'. */
void
mcast_snooping_unref(struct mcast_snooping *ms)
{
    if (!mcast_snooping_enabled(ms)) {
        return;
    }

    if (ovs_refcount_unref_relaxed(&ms->ref_cnt) == 1) {
        mcast_snooping_flush(ms);
        hmap_destroy(&ms->table);
        ovs_rwlock_destroy(&ms->rwlock);
        free(ms);
    }
}

/* Changes the mcast aging timeout of 'ms' to 'idle_time' seconds. */
void
mcast_snooping_set_idle_time(struct mcast_snooping *ms, unsigned int idle_time)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group *grp;
    struct mcast_group_bundle *b;
    int delta;

    idle_time = normalize_idle_time(idle_time);
    if (idle_time != ms->idle_time) {
        delta = (int) idle_time - (int) ms->idle_time;
        LIST_FOR_EACH (grp, group_node, &ms->group_lru) {
            LIST_FOR_EACH (b, bundle_node, &grp->bundle_lru) {
                b->expires += delta;
            }
        }
        ms->idle_time = idle_time;
    }
}

/* Sets the maximum number of entries in 'ms' to 'max_entries', adjusting it
 * to be within a reasonable range. */
void
mcast_snooping_set_max_entries(struct mcast_snooping *ms,
                               size_t max_entries)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    ms->max_entries = (max_entries < 10 ? 10
                       : max_entries > 1000 * 1000 ? 1000 * 1000
                       : max_entries);
}

/* Sets if unregistered multicast packets should be flooded to
 * all ports or only to ports connected to multicast routers
 *
 * Returns true if previous state differs from current state,
 * false otherwise. */
bool
mcast_snooping_set_flood_unreg(struct mcast_snooping *ms, bool enable)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    bool prev = ms->flood_unreg;
    ms->flood_unreg = enable;
    return prev != enable;
}

static struct mcast_group_bundle *
mcast_group_bundle_lookup(struct mcast_snooping *ms OVS_UNUSED,
                          struct mcast_group *grp, void *port)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_group_bundle *b;

    LIST_FOR_EACH (b, bundle_node, &grp->bundle_lru) {
        if (b->port == port) {
            return b;
        }
    }
    return NULL;
}

/* Insert a new bundle to the mcast group or update its
 * position and expiration if it is already there. */
static struct mcast_group_bundle *
mcast_group_insert_bundle(struct mcast_snooping *ms OVS_UNUSED,
                          struct mcast_group *grp, void *port, int idle_time)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group_bundle *b;

    b = mcast_group_bundle_lookup(ms, grp, port);
    if (b) {
        ovs_list_remove(&b->bundle_node);
    } else {
        b = xmalloc(sizeof *b);
        ovs_list_init(&b->bundle_node);
        b->port = port;
        ms->need_revalidate = true;
    }

    b->expires = time_now() + idle_time;
    ovs_list_push_back(&grp->bundle_lru, &b->bundle_node);
    return b;
}

/* Return true if multicast still has bundles associated.
 * Return false if there is no bundles. */
static bool
mcast_group_has_bundles(struct mcast_group *grp)
{
    return !ovs_list_is_empty(&grp->bundle_lru);
}

/* Delete 'grp' from the 'ms' hash table.
 * Caller is responsible to clean bundle lru first. */
static void
mcast_snooping_flush_group__(struct mcast_snooping *ms,
                             struct mcast_group *grp)
{
    ovs_assert(ovs_list_is_empty(&grp->bundle_lru));
    hmap_remove(&ms->table, &grp->hmap_node);
    ovs_list_remove(&grp->group_node);
    free(grp);
}

/* Flush out mcast group and its bundles */
static void
mcast_snooping_flush_group(struct mcast_snooping *ms, struct mcast_group *grp)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group_bundle *b;

    LIST_FOR_EACH_POP (b, bundle_node, &grp->bundle_lru) {
        free(b);
    }
    mcast_snooping_flush_group__(ms, grp);
    ms->need_revalidate = true;
}


/* Delete bundle returning true if it succeeds,
 * false if it didn't find the group. */
static bool
mcast_group_delete_bundle(struct mcast_snooping *ms OVS_UNUSED,
                          struct mcast_group *grp, void *port)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group_bundle *b;

    LIST_FOR_EACH (b, bundle_node, &grp->bundle_lru) {
        if (b->port == port) {
            ovs_list_remove(&b->bundle_node);
            free(b);
            return true;
        }
    }
    return false;
}

/* If any bundle has expired, delete it.  Returns the number of deleted
 * bundles. */
static int
mcast_snooping_prune_expired(struct mcast_snooping *ms,
                             struct mcast_group *grp)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    int expired;
    struct mcast_group_bundle *b, *next_b;
    time_t timenow = time_now();

    expired = 0;
    LIST_FOR_EACH_SAFE (b, next_b, bundle_node, &grp->bundle_lru) {
        /* This list is sorted on expiration time. */
        if (b->expires > timenow) {
            break;
        }
        ovs_list_remove(&b->bundle_node);
        free(b);
        expired++;
    }

    if (!mcast_group_has_bundles(grp)) {
        mcast_snooping_flush_group__(ms, grp);
        expired++;
    }

    if (expired) {
        ms->need_revalidate = true;
        COVERAGE_ADD(mcast_snooping_expired, expired);
    }

    return expired;
}

/* Add a multicast group to the mdb. If it exists, then
 * move to the last position in the LRU list.
 */
bool
mcast_snooping_add_group(struct mcast_snooping *ms,
                         const struct in6_addr *addr,
                         uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    bool learned;
    struct mcast_group *grp;

    /* Avoid duplicate packets. */
    if (mcast_snooping_mrouter_lookup(ms, vlan, port)
        || mcast_snooping_port_lookup(&ms->fport_list, port)) {
        return false;
    }

    learned = false;
    grp = mcast_snooping_lookup(ms, addr, vlan);
    if (!grp) {
        uint32_t hash = mcast_table_hash(ms, addr, vlan);

        if (hmap_count(&ms->table) >= ms->max_entries) {
            group_get_lru(ms, &grp);
            mcast_snooping_flush_group(ms, grp);
        }

        grp = xmalloc(sizeof *grp);
        hmap_insert(&ms->table, &grp->hmap_node, hash);
        grp->addr = *addr;
        grp->vlan = vlan;
        ovs_list_init(&grp->bundle_lru);
        learned = true;
        ms->need_revalidate = true;
        COVERAGE_INC(mcast_snooping_learned);
    } else {
        ovs_list_remove(&grp->group_node);
    }
    mcast_group_insert_bundle(ms, grp, port, ms->idle_time);

    /* Mark 'grp' as recently used. */
    ovs_list_push_back(&ms->group_lru, &grp->group_node);
    return learned;
}

bool
mcast_snooping_add_group4(struct mcast_snooping *ms, ovs_be32 ip4,
                         uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct in6_addr addr = in6_addr_mapped_ipv4(ip4);
    return mcast_snooping_add_group(ms, &addr, vlan, port);
}

int
mcast_snooping_add_report(struct mcast_snooping *ms,
                          const struct dp_packet *p,
                          uint16_t vlan, void *port)
{
    ovs_be32 ip4;
    size_t offset;
    const struct igmpv3_header *igmpv3;
    const struct igmpv3_record *record;
    int count = 0;
    int ngrp;

    offset = (char *) dp_packet_l4(p) - (char *) dp_packet_data(p);
    igmpv3 = dp_packet_at(p, offset, IGMPV3_HEADER_LEN);
    if (!igmpv3) {
        return 0;
    }
    ngrp = ntohs(igmpv3->ngrp);
    offset += IGMPV3_HEADER_LEN;
    while (ngrp--) {
        bool ret;
        record = dp_packet_at(p, offset, sizeof(struct igmpv3_record));
        if (!record) {
            break;
        }
        /* Only consider known record types. */
        if (record->type < IGMPV3_MODE_IS_INCLUDE
            || record->type > IGMPV3_BLOCK_OLD_SOURCES) {
            continue;
        }
        ip4 = get_16aligned_be32(&record->maddr);
        /*
         * If record is INCLUDE MODE and there are no sources, it's equivalent
         * to a LEAVE.
         */
        if (ntohs(record->nsrcs) == 0
            && (record->type == IGMPV3_MODE_IS_INCLUDE
                || record->type == IGMPV3_CHANGE_TO_INCLUDE_MODE)) {
            ret = mcast_snooping_leave_group4(ms, ip4, vlan, port);
        } else {
            ret = mcast_snooping_add_group4(ms, ip4, vlan, port);
        }
        if (ret) {
            count++;
        }
        offset += sizeof(*record)
                  + ntohs(record->nsrcs) * sizeof(ovs_be32) + record->aux_len;
    }
    return count;
}

int
mcast_snooping_add_mld(struct mcast_snooping *ms,
                          const struct dp_packet *p,
                          uint16_t vlan, void *port)
{
    const struct in6_addr *addr;
    size_t offset;
    const struct mld_header *mld;
    const struct mld2_record *record;
    int count = 0;
    int ngrp;
    bool ret;

    offset = (char *) dp_packet_l4(p) - (char *) dp_packet_data(p);
    mld = dp_packet_at(p, offset, MLD_HEADER_LEN);
    if (!mld) {
        return 0;
    }
    ngrp = ntohs(mld->ngrp);
    offset += MLD_HEADER_LEN;
    addr = dp_packet_at(p, offset, sizeof(struct in6_addr));

    switch (mld->type) {
    case MLD_REPORT:
        ret = mcast_snooping_add_group(ms, addr, vlan, port);
        if (ret) {
            count++;
        }
        break;
    case MLD_DONE:
        ret = mcast_snooping_leave_group(ms, addr, vlan, port);
        if (ret) {
            count++;
        }
        break;
    case MLD2_REPORT:
        while (ngrp--) {
            record = dp_packet_at(p, offset, sizeof(struct mld2_record));
            if (!record) {
                break;
            }
            /* Only consider known record types. */
            if (record->type >= IGMPV3_MODE_IS_INCLUDE
                && record->type <= IGMPV3_BLOCK_OLD_SOURCES) {
                struct in6_addr maddr;
                memcpy(maddr.s6_addr, record->maddr.be16, 16);
                addr = &maddr;
                /*
                 * If record is INCLUDE MODE and there are no sources, it's
                 * equivalent to a LEAVE.
                 */
                if (record->nsrcs == htons(0)
                    && (record->type == IGMPV3_MODE_IS_INCLUDE
                        || record->type == IGMPV3_CHANGE_TO_INCLUDE_MODE)) {
                    ret = mcast_snooping_leave_group(ms, addr, vlan, port);
                } else {
                    ret = mcast_snooping_add_group(ms, addr, vlan, port);
                }
                if (ret) {
                    count++;
                }
            }
            offset += sizeof(*record)
                      + ntohs(record->nsrcs) * sizeof(struct in6_addr)
                      + record->aux_len;
        }
    }

    return count;
}

bool
mcast_snooping_leave_group(struct mcast_snooping *ms,
                           const struct in6_addr *addr,
                           uint16_t vlan, void *port)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group *grp;

    /* Ports flagged to forward Reports usually have more
     * than one host behind it, so don't leave the group
     * on the first message and just let it expire */
    if (mcast_snooping_port_lookup(&ms->rport_list, port)) {
        return false;
    }

    grp = mcast_snooping_lookup(ms, addr, vlan);
    if (grp && mcast_group_delete_bundle(ms, grp, port)) {
        ms->need_revalidate = true;
        return true;
    }
    return false;
}

bool
mcast_snooping_leave_group4(struct mcast_snooping *ms, ovs_be32 ip4,
                           uint16_t vlan, void *port)
{
    struct in6_addr addr = in6_addr_mapped_ipv4(ip4);
    return mcast_snooping_leave_group(ms, &addr, vlan, port);
}


/* Router ports. */

/* Returns the number of seconds since the multicast router
 * was learned in a port. */
int
mcast_mrouter_age(const struct mcast_snooping *ms OVS_UNUSED,
                  const struct mcast_mrouter_bundle *mrouter)
{
    time_t remaining = mrouter->expires - time_now();
    return MCAST_MROUTER_PORT_IDLE_TIME - remaining;
}

static struct mcast_mrouter_bundle *
mcast_mrouter_from_lru_node(struct ovs_list *list)
{
    return CONTAINER_OF(list, struct mcast_mrouter_bundle, mrouter_node);
}

/* If the LRU list is not empty, stores the least-recently-used mrouter
 * in '*m' and returns true.  Otherwise, if the LRU list is empty,
 * stores NULL in '*m' and return false. */
static bool
mrouter_get_lru(const struct mcast_snooping *ms,
                struct mcast_mrouter_bundle **m)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    if (!ovs_list_is_empty(&ms->mrouter_lru)) {
        *m = mcast_mrouter_from_lru_node(ms->mrouter_lru.next);
        return true;
    } else {
        *m = NULL;
        return false;
    }
}

static struct mcast_mrouter_bundle *
mcast_snooping_mrouter_lookup(struct mcast_snooping *ms, uint16_t vlan,
                              void *port)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    struct mcast_mrouter_bundle *mrouter;

    LIST_FOR_EACH (mrouter, mrouter_node, &ms->mrouter_lru) {
        if (mrouter->vlan == vlan && mrouter->port == port) {
            return mrouter;
        }
    }
    return NULL;
}

bool
mcast_snooping_add_mrouter(struct mcast_snooping *ms, uint16_t vlan,
                           void *port)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_mrouter_bundle *mrouter;

    /* Avoid duplicate packets. */
    if (mcast_snooping_port_lookup(&ms->fport_list, port)) {
        return false;
    }

    mrouter = mcast_snooping_mrouter_lookup(ms, vlan, port);
    if (mrouter) {
        ovs_list_remove(&mrouter->mrouter_node);
    } else {
        mrouter = xmalloc(sizeof *mrouter);
        mrouter->vlan = vlan;
        mrouter->port = port;
        COVERAGE_INC(mcast_snooping_learned);
        ms->need_revalidate = true;
    }

    mrouter->expires = time_now() + MCAST_MROUTER_PORT_IDLE_TIME;
    ovs_list_push_back(&ms->mrouter_lru, &mrouter->mrouter_node);
    return ms->need_revalidate;
}

static void
mcast_snooping_flush_mrouter(struct mcast_mrouter_bundle *mrouter)
{
    ovs_list_remove(&mrouter->mrouter_node);
    free(mrouter);
}

/* Ports */

static struct mcast_port_bundle *
mcast_port_from_list_node(struct ovs_list *list)
{
    return CONTAINER_OF(list, struct mcast_port_bundle, node);
}

/* If the list is not empty, stores the fport in '*f' and returns true.
 * Otherwise, if the list is empty, stores NULL in '*f' and return false. */
static bool
mcast_snooping_port_get(const struct ovs_list *list,
                        struct mcast_port_bundle **f)
{
    if (!ovs_list_is_empty(list)) {
        *f = mcast_port_from_list_node(list->next);
        return true;
    } else {
        *f = NULL;
        return false;
    }
}

static struct mcast_port_bundle *
mcast_snooping_port_lookup(struct ovs_list *list, void *port)
{
    struct mcast_port_bundle *pbundle;

    LIST_FOR_EACH (pbundle, node, list) {
        if (pbundle->port == port) {
            return pbundle;
        }
    }
    return NULL;
}

static void
mcast_snooping_add_port(struct ovs_list *list, void *port)
{
    struct mcast_port_bundle *pbundle;

    pbundle = xmalloc(sizeof *pbundle);
    pbundle->port = port;
    ovs_list_insert(list, &pbundle->node);
}

static void
mcast_snooping_flush_port(struct mcast_port_bundle *pbundle)
{
    ovs_list_remove(&pbundle->node);
    free(pbundle);
}


/* Flood ports. */
void
mcast_snooping_set_port_flood(struct mcast_snooping *ms, void *port,
                              bool flood)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_port_bundle *fbundle;

    fbundle = mcast_snooping_port_lookup(&ms->fport_list, port);
    if (flood && !fbundle) {
        mcast_snooping_add_port(&ms->fport_list, port);
        ms->need_revalidate = true;
    } else if (!flood && fbundle) {
        mcast_snooping_flush_port(fbundle);
        ms->need_revalidate = true;
    }
}

/* Flood Reports ports. */

void
mcast_snooping_set_port_flood_reports(struct mcast_snooping *ms, void *port,
                                      bool flood)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_port_bundle *pbundle;

    pbundle = mcast_snooping_port_lookup(&ms->rport_list, port);
    if (flood && !pbundle) {
        mcast_snooping_add_port(&ms->rport_list, port);
        ms->need_revalidate = true;
    } else if (!flood && pbundle) {
        mcast_snooping_flush_port(pbundle);
        ms->need_revalidate = true;
    }
}

/* Run and flush. */

static void
mcast_snooping_mdb_flush__(struct mcast_snooping *ms)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group *grp;
    struct mcast_mrouter_bundle *mrouter;

    while (group_get_lru(ms, &grp)) {
        mcast_snooping_flush_group(ms, grp);
    }

    hmap_shrink(&ms->table);

    while (mrouter_get_lru(ms, &mrouter)) {
        mcast_snooping_flush_mrouter(mrouter);
    }
}

void
mcast_snooping_mdb_flush(struct mcast_snooping *ms)
{
    if (!mcast_snooping_enabled(ms)) {
        return;
    }

    ovs_rwlock_wrlock(&ms->rwlock);
    mcast_snooping_mdb_flush__(ms);
    ovs_rwlock_unlock(&ms->rwlock);
}

/* Flushes mdb and flood ports. */
static void
mcast_snooping_flush__(struct mcast_snooping *ms)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    struct mcast_group *grp;
    struct mcast_mrouter_bundle *mrouter;
    struct mcast_port_bundle *pbundle;

    while (group_get_lru(ms, &grp)) {
        mcast_snooping_flush_group(ms, grp);
    }

    hmap_shrink(&ms->table);

    /* flush multicast routers */
    while (mrouter_get_lru(ms, &mrouter)) {
        mcast_snooping_flush_mrouter(mrouter);
    }

    /* flush flood ports */
    while (mcast_snooping_port_get(&ms->fport_list, &pbundle)) {
        mcast_snooping_flush_port(pbundle);
    }

    /* flush flood report ports */
    while (mcast_snooping_port_get(&ms->rport_list, &pbundle)) {
        mcast_snooping_flush_port(pbundle);
    }
}

void
mcast_snooping_flush(struct mcast_snooping *ms)
{
    if (!mcast_snooping_enabled(ms)) {
        return;
    }

    ovs_rwlock_wrlock(&ms->rwlock);
    mcast_snooping_flush__(ms);
    ovs_rwlock_unlock(&ms->rwlock);
}

static bool
mcast_snooping_run__(struct mcast_snooping *ms)
    OVS_REQ_WRLOCK(ms->rwlock)
{
    bool need_revalidate;
    struct mcast_group *grp;
    struct mcast_mrouter_bundle *mrouter;
    int mrouter_expired;

    while (group_get_lru(ms, &grp)) {
        if (hmap_count(&ms->table) > ms->max_entries) {
            mcast_snooping_flush_group(ms, grp);
        } else {
            if (!mcast_snooping_prune_expired(ms, grp)) {
                break;
            }
        }
    }

    hmap_shrink(&ms->table);

    mrouter_expired = 0;
    while (mrouter_get_lru(ms, &mrouter)
           && time_now() >= mrouter->expires) {
        mcast_snooping_flush_mrouter(mrouter);
        mrouter_expired++;
    }

    if (mrouter_expired) {
        ms->need_revalidate = true;
        COVERAGE_ADD(mcast_snooping_expired, mrouter_expired);
    }

    need_revalidate = ms->need_revalidate;
    ms->need_revalidate = false;
    return need_revalidate;
}

/* Does periodic work required by 'ms'. Returns true if something changed
 * that may require flow revalidation. */
bool
mcast_snooping_run(struct mcast_snooping *ms)
{
    bool need_revalidate;

    if (!mcast_snooping_enabled(ms)) {
        return false;
    }

    ovs_rwlock_wrlock(&ms->rwlock);
    need_revalidate = mcast_snooping_run__(ms);
    ovs_rwlock_unlock(&ms->rwlock);

    return need_revalidate;
}

static void
mcast_snooping_wait__(struct mcast_snooping *ms)
    OVS_REQ_RDLOCK(ms->rwlock)
{
    if (hmap_count(&ms->table) > ms->max_entries
        || ms->need_revalidate) {
        poll_immediate_wake();
    } else {
        struct mcast_group *grp;
        struct mcast_group_bundle *bundle;
        struct mcast_mrouter_bundle *mrouter;
        long long int mrouter_msec;
        long long int msec = 0;

        if (!ovs_list_is_empty(&ms->group_lru)) {
            grp = mcast_group_from_lru_node(ms->group_lru.next);
            bundle = mcast_group_bundle_from_lru_node(grp->bundle_lru.next);
            msec = bundle->expires * 1000LL;
        }

        if (!ovs_list_is_empty(&ms->mrouter_lru)) {
            mrouter = mcast_mrouter_from_lru_node(ms->mrouter_lru.next);
            mrouter_msec = mrouter->expires * 1000LL;
            msec = msec ? MIN(msec, mrouter_msec) : mrouter_msec;
        }

        if (msec) {
            poll_timer_wait_until(msec);
        }
    }
}

void
mcast_snooping_wait(struct mcast_snooping *ms)
{
    if (!mcast_snooping_enabled(ms)) {
        return;
    }

    ovs_rwlock_rdlock(&ms->rwlock);
    mcast_snooping_wait__(ms);
    ovs_rwlock_unlock(&ms->rwlock);
}

void
mcast_snooping_flush_bundle(struct mcast_snooping *ms, void *port)
{
    struct mcast_group *g, *next_g;
    struct mcast_mrouter_bundle *m, *next_m;

    if (!mcast_snooping_enabled(ms)) {
        return;
    }

    ovs_rwlock_wrlock(&ms->rwlock);
    LIST_FOR_EACH_SAFE (g, next_g, group_node, &ms->group_lru) {
        if (mcast_group_delete_bundle(ms, g, port)) {
            ms->need_revalidate = true;

            if (!mcast_group_has_bundles(g)) {
                mcast_snooping_flush_group__(ms, g);
            }
        }
    }

    LIST_FOR_EACH_SAFE (m, next_m, mrouter_node, &ms->mrouter_lru) {
        if (m->port == port) {
            mcast_snooping_flush_mrouter(m);
            ms->need_revalidate = true;
        }
    }

    ovs_rwlock_unlock(&ms->rwlock);
}
