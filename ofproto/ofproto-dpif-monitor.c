/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "dp-packet.h"
#include "guarded-list.h"
#include "hash.h"
#include "heap.h"
#include "openvswitch/hmap.h"
#include "latch.h"
#include "openvswitch/ofpbuf.h"
#include "ofproto-dpif.h"
#include "ovs-lldp.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_monitor);

/* Converts the time in millisecond to heap priority. */
#define MSEC_TO_PRIO(TIME) (LLONG_MAX - (TIME))
/* Converts the heap priority to time in millisecond. */
#define PRIO_TO_MSEC(PRIO) (LLONG_MAX - (PRIO))

/* Monitored port.  It owns references to ofport, bfd, cfm, and lldp structs. */
struct mport {
    struct hmap_node hmap_node;       /* In monitor_hmap. */
    struct heap_node heap_node;       /* In monitor_heap. */
    const struct ofport_dpif *ofport; /* The corresponding ofport. */

    struct cfm *cfm;                  /* Reference to cfm. */
    struct bfd *bfd;                  /* Reference to bfd. */
    struct lldp *lldp;                /* Reference to lldp. */
    struct eth_addr hw_addr;          /* Hardware address. */
};

/* Entry of the 'send_soon' list.  Contains the pointer to the
 * 'ofport_dpif'.  Note, the pointed object is not protected, so
 * users should always use the mport_find() to convert it to 'mport'. */
struct send_soon_entry {
    struct ovs_list list_node;        /* In send_soon. */
    const struct ofport_dpif *ofport;
};

/* hmap that contains "struct mport"s. */
static struct hmap monitor_hmap = HMAP_INITIALIZER(&monitor_hmap);

/* heap for ordering mport based on bfd/cfm wakeup time. */
static struct heap monitor_heap;

/* guarded-list for storing the mports that need to send bfd/cfm control
 * packet soon. */
static struct guarded_list send_soon = GUARDED_OVS_LIST_INITIALIZER(&send_soon);

/* The monitor thread id. */
static pthread_t monitor_tid;
/* True if the monitor thread is running. */
static bool monitor_running;

static struct latch monitor_exit_latch;
static struct ovs_mutex monitor_mutex = OVS_MUTEX_INITIALIZER;

static void *monitor_main(void *);
static void monitor_check_send_soon(struct dp_packet *);
static void monitor_run(void);
static void monitor_mport_run(struct mport *, struct dp_packet *);

static void mport_register(const struct ofport_dpif *, struct bfd *,
                           struct cfm *, struct lldp *,
                           const struct eth_addr *)
    OVS_REQUIRES(monitor_mutex);
static void mport_unregister(const struct ofport_dpif *)
    OVS_REQUIRES(monitor_mutex);
static void mport_update(struct mport *, struct bfd *, struct cfm *,
                         struct lldp *, const struct eth_addr *)
    OVS_REQUIRES(monitor_mutex);
static struct mport *mport_find(const struct ofport_dpif *)
    OVS_REQUIRES(monitor_mutex);

/* Tries finding and returning the 'mport' from the monitor_hmap.
 * If there is no such 'mport', returns NULL. */
static struct mport *
mport_find(const struct ofport_dpif *ofport) OVS_REQUIRES(monitor_mutex)
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

/* Creates a new mport and inserts it into monitor_hmap and monitor_heap,
 * if it doesn't exist.  Otherwise, just updates its fields. */
static void
mport_register(const struct ofport_dpif *ofport, struct bfd *bfd,
               struct cfm *cfm, struct lldp *lldp,
               const struct eth_addr *hw_addr)
    OVS_REQUIRES(monitor_mutex)
{
    struct mport *mport = mport_find(ofport);

    if (!mport) {
        mport = xzalloc(sizeof *mport);
        mport->ofport = ofport;
        hmap_insert(&monitor_hmap, &mport->hmap_node, hash_pointer(ofport, 0));
        heap_insert(&monitor_heap, &mport->heap_node, 0);
    }
    mport_update(mport, bfd, cfm, lldp, hw_addr);
}

/* Removes mport from monitor_hmap and monitor_heap and frees it. */
static void
mport_unregister(const struct ofport_dpif *ofport)
    OVS_REQUIRES(monitor_mutex)
{
    struct mport *mport = mport_find(ofport);

    if (mport) {
        mport_update(mport, NULL, NULL, NULL, NULL);
        hmap_remove(&monitor_hmap, &mport->hmap_node);
        heap_remove(&monitor_heap, &mport->heap_node);
        free(mport);
    }
}

/* Updates the fields of an existing mport struct. */
static void
mport_update(struct mport *mport, struct bfd *bfd, struct cfm *cfm,
             struct lldp *lldp, const struct eth_addr *hw_addr)
    OVS_REQUIRES(monitor_mutex)
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
    if (mport->lldp != lldp) {
        lldp_unref(mport->lldp);
        mport->lldp = lldp_ref(lldp);
    }
    if (hw_addr && !eth_addr_equals(mport->hw_addr, *hw_addr)) {
        mport->hw_addr = *hw_addr;
    }
    /* If bfd/cfm/lldp is added or reconfigured, move the mport on top of the heap
     * so that the monitor thread can run the mport next time it wakes up. */
    if (mport->bfd || mport->cfm || mport->lldp) {
        heap_change(&monitor_heap, &mport->heap_node, LLONG_MAX);
    }
}


/* The 'main' function for the monitor thread. */
static void *
monitor_main(void * args OVS_UNUSED)
{
    VLOG_INFO("monitor thread created");
    while (!latch_is_set(&monitor_exit_latch)) {
        monitor_run();
        latch_wait(&monitor_exit_latch);
        poll_block();
    }
    VLOG_INFO("monitor thread terminated");
    return NULL;
}

/* The monitor thread should wake up this often to ensure that newly added or
 * reconfigured monitoring ports are run in a timely manner. */
#define MONITOR_INTERVAL_MSEC 100

/* Checks the 'send_soon' list and the heap for mports that have timed
 * out bfd/cfm sessions. */
static void
monitor_run(void)
{
    uint32_t stub[512 / 4];
    long long int prio_now;
    struct dp_packet packet;

    dp_packet_use_stub(&packet, stub, sizeof stub);
    ovs_mutex_lock(&monitor_mutex);

    /* The monitor_check_send_soon() needs to be run twice.  The first
     * time is for preventing the same 'mport' from being processed twice
     * (i.e. once from heap, the other from the 'send_soon' array).
     * The second run is to cover the case when the control packet is sent
     * via patch port and the other end needs to send back immediately. */
    monitor_check_send_soon(&packet);

    prio_now = MSEC_TO_PRIO(time_msec());
    /* Peeks the top of heap and checks if we should run this mport. */
    while (!heap_is_empty(&monitor_heap)
           && heap_max(&monitor_heap)->priority >= prio_now) {
        struct mport *mport;

        mport = CONTAINER_OF(heap_max(&monitor_heap), struct mport, heap_node);
        monitor_mport_run(mport, &packet);
    }

    monitor_check_send_soon(&packet);

    /* Waits on the earliest next wakeup time. */
    if (!heap_is_empty(&monitor_heap)) {
        long long int next_timeout, next_mport_wakeup;

        next_timeout = time_msec() + MONITOR_INTERVAL_MSEC;
        next_mport_wakeup = PRIO_TO_MSEC(heap_max(&monitor_heap)->priority);
        poll_timer_wait_until(MIN(next_timeout, next_mport_wakeup));
    }
    ovs_mutex_unlock(&monitor_mutex);
    dp_packet_uninit(&packet);
}

/* Checks the 'send_soon' list for any mport that needs to send cfm/bfd
 * control packet immediately, and calls monitor_mport_run(). */
static void
monitor_check_send_soon(struct dp_packet *packet)
    OVS_REQUIRES(monitor_mutex)
{
    while (!guarded_list_is_empty(&send_soon)) {
        struct send_soon_entry *entry;
        struct mport *mport;

        entry = CONTAINER_OF(guarded_list_pop_front(&send_soon),
                             struct send_soon_entry, list_node);
        mport = mport_find(entry->ofport);
        if (mport) {
            monitor_mport_run(mport, packet);
        }
        free(entry);
    }
}

/* Checks the sending of control packet on 'mport'.  Sends the control
 * packet if needed.  Executes bfd and cfm periodic functions (run, wait)
 * on 'mport'.  And changes the location of 'mport' in heap based on next
 * timeout. */
static void
monitor_mport_run(struct mport *mport, struct dp_packet *packet)
    OVS_REQUIRES(monitor_mutex)
{
    long long int next_wake_time;
    long long int bfd_wake_time = LLONG_MAX;
    long long int cfm_wake_time = LLONG_MAX;
    long long int lldp_wake_time = LLONG_MAX;

    if (mport->cfm && cfm_should_send_ccm(mport->cfm)) {
        dp_packet_clear(packet);
        cfm_compose_ccm(mport->cfm, packet, mport->hw_addr);
        ofproto_dpif_send_packet(mport->ofport, false, packet);
    }
    if (mport->bfd && bfd_should_send_packet(mport->bfd)) {
        bool oam;

        dp_packet_clear(packet);
        bfd_put_packet(mport->bfd, packet, mport->hw_addr, &oam);
        ofproto_dpif_send_packet(mport->ofport, oam, packet);
    }
    if (mport->lldp && lldp_should_send_packet(mport->lldp)) {
        dp_packet_clear(packet);
        lldp_put_packet(mport->lldp, packet, mport->hw_addr);
        ofproto_dpif_send_packet(mport->ofport, false, packet);
    }

    if (mport->cfm) {
        cfm_run(mport->cfm);
        cfm_wake_time = cfm_wait(mport->cfm);
    }
    if (mport->bfd) {
        bfd_run(mport->bfd);
        bfd_wake_time = bfd_wait(mport->bfd);
    }
    if (mport->lldp) {
        lldp_wake_time = lldp_wait(mport->lldp);
    }
    /* Computes the next wakeup time for this mport. */
    next_wake_time = MIN(bfd_wake_time,
                         cfm_wake_time);
    next_wake_time = MIN(next_wake_time, lldp_wake_time);
    heap_change(&monitor_heap, &mport->heap_node,
                MSEC_TO_PRIO(next_wake_time));
}


/* Creates the mport in monitor module if either bfd or cfm
 * is configured.  Otherwise, deletes the mport.
 * Also checks whether the monitor thread should be started
 * or terminated. */
void
ofproto_dpif_monitor_port_update(const struct ofport_dpif *ofport,
                                 struct bfd *bfd, struct cfm *cfm,
                                 struct lldp *lldp,
                                 const struct eth_addr *hw_addr)
{
    ovs_mutex_lock(&monitor_mutex);
    if (!cfm && !bfd && !lldp) {
        mport_unregister(ofport);
    } else {
        mport_register(ofport, bfd, cfm, lldp, hw_addr);
    }
    ovs_mutex_unlock(&monitor_mutex);

    /* If the monitor thread is not running and the hmap
     * is not empty, starts it.  If it is and the hmap is empty,
     * terminates it. */
    if (!monitor_running && !hmap_is_empty(&monitor_hmap))  {
        latch_init(&monitor_exit_latch);
        monitor_tid = ovs_thread_create("monitor", monitor_main, NULL);
        monitor_running = true;
    } else if (monitor_running && hmap_is_empty(&monitor_hmap))  {
        latch_set(&monitor_exit_latch);
        xpthread_join(monitor_tid, NULL);
        latch_destroy(&monitor_exit_latch);
        monitor_running = false;
    }
}

/* Registers the 'ofport' in the 'send_soon' list.  We cannot directly
 * insert the corresponding mport to the 'send_soon' list, since the
 * 'send_soon' list is not updated when the mport is removed.
 *
 * Reader of the 'send_soon' list is responsible for freeing the entry. */
void
ofproto_dpif_monitor_port_send_soon(const struct ofport_dpif *ofport)
{
    struct send_soon_entry *entry = xzalloc(sizeof *entry);
    entry->ofport = ofport;

    guarded_list_push_back(&send_soon, &entry->list_node, SIZE_MAX);
}
