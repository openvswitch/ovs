/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "ofproto-dpif-monitor.h"

#include <string.h>

#include "bfd.h"
#include "cfm.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "ofproto-dpif.h"
#include "util.h"
#include "vlog.h"

/* Monitored port.  It owns references to ofport, bfd, cfm structs. */
struct mport {
    struct hmap_node hmap_node;       /* In monitor_hmap. */
    const struct ofport_dpif *ofport; /* The corresponding ofport. */

    struct cfm *cfm;                  /* Reference to cfm. */
    struct bfd *bfd;                  /* Reference to bfd. */
    uint8_t hw_addr[OFP_ETH_ALEN];    /* Hardware address. */
};

/* hmap that contains "struct mport"s. */
static struct hmap monitor_hmap = HMAP_INITIALIZER(&monitor_hmap);

static struct ovs_rwlock monitor_rwlock = OVS_RWLOCK_INITIALIZER;

static void mport_register(const struct ofport_dpif *, struct bfd *,
                           struct cfm *, uint8_t[ETH_ADDR_LEN])
    OVS_REQ_WRLOCK(monitor_rwlock);
static void mport_unregister(const struct ofport_dpif *)
    OVS_REQ_WRLOCK(monitor_rwlock);
static void mport_update(struct mport *, struct bfd *, struct cfm *,
                         uint8_t[ETH_ADDR_LEN]) OVS_REQ_WRLOCK(monitor_rwlock);
static struct mport *mport_find(const struct ofport_dpif *)
    OVS_REQ_WRLOCK(monitor_rwlock);

/* Tries finding and returning the 'mport' from the monitor_hmap.
 * If there is no such 'mport', returns NULL. */
static struct mport *
mport_find(const struct ofport_dpif *ofport) OVS_REQ_WRLOCK(monitor_rwlock)
{
    struct mport *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash_pointer(ofport, 0),
                             &monitor_hmap) {
        if (node->ofport == ofport) {
            return node;
        }
    }
    return NULL;
}

/* Creates a new mport and inserts it into monitor_hmap, if it doesn't exist.
 * Otherwise, just updates its fields. */
static void
mport_register(const struct ofport_dpif *ofport, struct bfd *bfd,
               struct cfm *cfm, uint8_t *hw_addr)
    OVS_REQ_WRLOCK(monitor_rwlock)
{
    struct mport *mport = mport_find(ofport);

    if (!mport) {
        mport = xzalloc(sizeof *mport);
        mport->ofport = ofport;
        hmap_insert(&monitor_hmap, &mport->hmap_node, hash_pointer(ofport, 0));
    }
    mport_update(mport, bfd, cfm, hw_addr);
}

/* Removes mport from monitor_hmap and frees it. */
static void
mport_unregister(const struct ofport_dpif *ofport)
    OVS_REQ_WRLOCK(monitor_rwlock)
{
    struct mport *mport = mport_find(ofport);

    if (mport) {
        mport_update(mport, NULL, NULL, NULL);
        hmap_remove(&monitor_hmap, &mport->hmap_node);
        free(mport);
    }
}

/* Updates the fields of an existing mport struct. */
static void
mport_update(struct mport *mport, struct bfd *bfd, struct cfm *cfm,
             uint8_t hw_addr[ETH_ADDR_LEN]) OVS_REQ_WRLOCK(monitor_rwlock)
{
    ovs_assert(mport);

    if (mport->cfm != cfm) {
        cfm_unref(mport->cfm);
        mport->cfm = cfm_ref(cfm);
    }
    if (mport->bfd != bfd) {
        bfd_unref(mport->bfd);
        mport->bfd = bfd_ref(bfd);
    }
    if (hw_addr && memcmp(mport->hw_addr, hw_addr, ETH_ADDR_LEN)) {
        memcpy(mport->hw_addr, hw_addr, ETH_ADDR_LEN);
    }
}


/* Creates the mport in monitor module if either bfd or cfm
 * is configured.  Otherwise, deletes the mport. */
void
ofproto_dpif_monitor_port_update(const struct ofport_dpif *ofport,
                                 struct bfd *bfd, struct cfm *cfm,
                                 uint8_t hw_addr[ETH_ADDR_LEN])
{
    ovs_rwlock_wrlock(&monitor_rwlock);
    if (!cfm && !bfd) {
        mport_unregister(ofport);
    } else {
        mport_register(ofport, bfd, cfm, hw_addr);
    }
    ovs_rwlock_unlock(&monitor_rwlock);
}

/* Checks the sending of control packets on all mports.  Sends the control
 * packets if needed. */
void
ofproto_dpif_monitor_run_fast(void)
{
    struct mport *mport;
    static uint32_t buf_stub[128 / 4];
    struct ofpbuf packet;

    ovs_rwlock_rdlock(&monitor_rwlock);
    HMAP_FOR_EACH (mport, hmap_node, &monitor_hmap) {
        if (mport->cfm && cfm_should_send_ccm(mport->cfm)) {
            ofpbuf_use_stub(&packet, buf_stub, sizeof buf_stub);
            cfm_compose_ccm(mport->cfm, &packet, mport->hw_addr);
            ofproto_dpif_send_packet(mport->ofport, &packet);
        }
        if (mport->bfd && bfd_should_send_packet(mport->bfd)) {
            ofpbuf_use_stub(&packet, buf_stub, sizeof buf_stub);
            bfd_put_packet(mport->bfd, &packet, mport->hw_addr);
            ofproto_dpif_send_packet(mport->ofport, &packet);
        }
    }
    ovs_rwlock_unlock(&monitor_rwlock);
}

/* Executes bfd_run(), cfm_run() on all mports. */
void
ofproto_dpif_monitor_run(void)
{
    struct mport *mport;

    ovs_rwlock_rdlock(&monitor_rwlock);
    HMAP_FOR_EACH (mport, hmap_node, &monitor_hmap) {
        if (mport->cfm) {
            cfm_run(mport->cfm);
        }
        if (mport->bfd) {
            bfd_run(mport->bfd);
        }
    }
    ovs_rwlock_unlock(&monitor_rwlock);
}

/* Executes the bfd_wait() and cfm_wait() functions on all mports. */
void
ofproto_dpif_monitor_wait(void)
{
    struct mport *mport;

    ovs_rwlock_rdlock(&monitor_rwlock);
    HMAP_FOR_EACH (mport, hmap_node, &monitor_hmap) {
        if (mport->cfm) {
            cfm_wait(mport->cfm);
        }
        if (mport->bfd) {
            bfd_wait(mport->bfd);
        }
    }
    ovs_rwlock_unlock(&monitor_rwlock);
}
