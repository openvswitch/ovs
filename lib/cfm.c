/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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
#include "cfm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "timer.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(cfm);

#define CCM_OPCODE 1              /* CFM message opcode meaning CCM. */

struct cfm_internal {
    struct cfm cfm;
    uint32_t seq;          /* The sequence number of our last CCM. */

    uint8_t ccm_interval;  /* The CCM transmission interval. */
    int ccm_interval_ms;   /* 'ccm_interval' in milliseconds. */

    struct timer tx_timer;    /* Send CCM when expired. */
    struct timer fault_timer; /* Check for faults when expired. */

    long long x_recv_time;
};

static int
ccm_interval_to_ms(uint8_t interval)
{
    switch (interval) {
    case 0:  NOT_REACHED(); /* Explicitly not supported by 802.1ag. */
    case 1:  return 3;      /* Not recommended due to timer resolution. */
    case 2:  return 10;     /* Not recommended due to timer resolution. */
    case 3:  return 100;
    case 4:  return 1000;
    case 5:  return 10000;
    case 6:  return 60000;
    case 7:  return 600000;
    default: NOT_REACHED(); /* Explicitly not supported by 802.1ag. */
    }

    NOT_REACHED();
}

static long long int
cfm_fault_interval(struct cfm_internal *cfmi)
{
    /* According to the 802.1ag specification we should assume every other MP
     * with the same MAID has the same transmission interval that we have.  If
     * an MP has a different interval, cfm_process_heartbeat will register it
     * as a fault (likely due to a configuration error).  Thus we can check all
     * MPs at once making this quite a bit simpler.
     *
     * According to the specification we should check when (ccm_interval_ms *
     * 3.5)ms have passed. */
    return (cfmi->ccm_interval_ms * 7) / 2;
}

static uint8_t
ms_to_ccm_interval(int interval_ms)
{
    uint8_t i;

    for (i = 7; i > 0; i--) {
        if (ccm_interval_to_ms(i) <= interval_ms) {
            return i;
        }
    }

    return 1;
}

static struct cfm_internal *
cfm_to_internal(const struct cfm *cfm)
{
    return CONTAINER_OF(cfm, struct cfm_internal, cfm);
}

static uint32_t
hash_mpid(uint8_t mpid)
{
    return hash_int(mpid, 0);
}

static bool
cfm_is_valid_mpid(uint32_t mpid)
{
    /* 802.1ag specification requires MPIDs to be within the range [1, 8191] */
    return mpid >= 1 && mpid <= 8191;
}

static struct remote_mp *
lookup_remote_mp(const struct hmap *hmap, uint16_t mpid)
{
    struct remote_mp *rmp;

    HMAP_FOR_EACH_IN_BUCKET (rmp, node, hash_mpid(mpid), hmap) {
        if (rmp->mpid == mpid) {
            return rmp;
        }
    }

    return NULL;
}

/* Allocates a 'cfm' object.  This object should have its 'mpid', 'maid',
 * 'eth_src', and 'interval' filled out.  When changes are made to the 'cfm'
 * object, cfm_configure should be called before using it. */
struct cfm *
cfm_create(void)
{
    struct cfm *cfm;
    struct cfm_internal *cfmi;

    cfmi = xzalloc(sizeof *cfmi);
    cfm  = &cfmi->cfm;
    cfmi->x_recv_time = LLONG_MIN;

    hmap_init(&cfm->remote_mps);
    return cfm;
}

void
cfm_destroy(struct cfm *cfm)
{
    struct cfm_internal *cfmi = cfm_to_internal(cfm);
    struct remote_mp *rmp, *rmp_next;

    if (!cfm) {
        return;
    }

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {
        hmap_remove(&cfm->remote_mps, &rmp->node);
        free(rmp);
    }

    hmap_destroy(&cfm->remote_mps);
    free(cfmi);
}

/* Should be run periodically to update fault statistics messages. */
void
cfm_run(struct cfm *cfm)
{
    long long now = time_msec();
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    if (timer_expired(&cfmi->fault_timer)) {
        bool fault;
        struct remote_mp *rmp;
        long long int interval;

        interval = cfm_fault_interval(cfmi);
        fault = now < cfmi->x_recv_time + interval;

        HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
            if (rmp->recv_time < timer_enabled_at(&cfmi->fault_timer, interval)
                || timer_expired_at(&cfmi->fault_timer, rmp->recv_time)) {
                rmp->fault = true;
            }

            if (rmp->fault) {
                fault = true;
            }
        }

        cfm->fault = fault;
        timer_set_duration(&cfmi->fault_timer, interval);
    }
}

/* Should be run periodically to check if the CFM module has a CCM message it
 * wishes to send. */
bool
cfm_should_send_ccm(struct cfm *cfm)
{
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    return timer_expired(&cfmi->tx_timer);
}

/* Composes a CCM message into 'ccm'.  Messages generated with this function
 * should be sent whenever cfm_should_send_ccm() indicates. */
void
cfm_compose_ccm(struct cfm *cfm, struct ccm *ccm)
{
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    timer_set_duration(&cfmi->tx_timer, cfmi->ccm_interval_ms);

    ccm->mdlevel_version = 0;
    ccm->opcode = CCM_OPCODE;
    ccm->tlv_offset = 70;
    ccm->seq = htonl(++cfmi->seq);
    ccm->mpid = htons(cfmi->cfm.mpid);
    ccm->flags = cfmi->ccm_interval;
    memcpy(ccm->maid, cfmi->cfm.maid, sizeof ccm->maid);
}

void
cfm_wait(struct cfm *cfm)
{
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    timer_wait(&cfmi->tx_timer);
    timer_wait(&cfmi->fault_timer);
}

/* Should be called whenever a client of the cfm library changes the internals
 * of 'cfm'. Returns true if 'cfm' is valid. */
bool
cfm_configure(struct cfm *cfm)
{
    struct cfm_internal *cfmi = cfm_to_internal(cfm);
    uint8_t interval;

    if (!cfm_is_valid_mpid(cfm->mpid) || !cfm->interval) {
        return false;
    }

    interval = ms_to_ccm_interval(cfm->interval);

    if (interval != cfmi->ccm_interval) {
        cfmi->ccm_interval = interval;
        cfmi->ccm_interval_ms = ccm_interval_to_ms(interval);

        timer_set_expired(&cfmi->tx_timer);
        timer_set_duration(&cfmi->fault_timer, cfm_fault_interval(cfmi));
    }

    return true;
}

/* Given an array of MPIDs, updates the 'remote_mps' map of 'cfm' to reflect
 * it.  Invalid MPIDs are skipped. */
void
cfm_update_remote_mps(struct cfm *cfm, const uint16_t *mpids, size_t n_mpids)
{
    size_t i;
    struct hmap new_rmps;
    struct remote_mp *rmp, *rmp_next;

    hmap_init(&new_rmps);

    for (i = 0; i < n_mpids; i++) {
        uint16_t mpid = mpids[i];

        if (!cfm_is_valid_mpid(mpid)
            || lookup_remote_mp(&new_rmps, mpid)) {
            continue;
        }

        if ((rmp = lookup_remote_mp(&cfm->remote_mps, mpid))) {
            hmap_remove(&cfm->remote_mps, &rmp->node);
        } else {
            rmp = xzalloc(sizeof *rmp);
            rmp->mpid = mpid;
        }

        hmap_insert(&new_rmps, &rmp->node, hash_mpid(mpid));
    }

    hmap_swap(&new_rmps, &cfm->remote_mps);

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &new_rmps) {
        hmap_remove(&new_rmps, &rmp->node);
        free(rmp);
    }

    hmap_destroy(&new_rmps);
}

/* Finds a 'remote_mp' with 'mpid' in 'cfm'.  If no such 'remote_mp' exists
 * returns NULL. */
const struct remote_mp *
cfm_get_remote_mp(const struct cfm *cfm, uint16_t mpid)
{
    return lookup_remote_mp(&cfm->remote_mps, mpid);
}

/* Generates 'maid' from 'md_name' and 'ma_name'.  A NULL parameter indicates
 * the default should be used. Returns false if unsuccessful. */
bool
cfm_generate_maid(const char *md_name, const char *ma_name,
                  uint8_t maid[CCM_MAID_LEN])
{
    uint8_t *ma_p;
    size_t md_len, ma_len;

    if (!md_name) {
        md_name = "ovs";
    }

    if (!ma_name) {
        ma_name = "ovs";
    }

    memset(maid, 0, CCM_MAID_LEN);

    md_len = strlen(md_name);
    ma_len = strlen(ma_name);

    if (!md_len || !ma_len || md_len + ma_len + 4 > CCM_MAID_LEN) {
        return false;
    }

    maid[0] = 4;                       /* MD name string format. */
    maid[1] = md_len;                  /* MD name size. */
    memcpy(&maid[2], md_name, md_len); /* MD name. */

    ma_p    = maid + 2 + md_len;
    ma_p[0] = 2;                       /* MA name string format. */
    ma_p[1] = ma_len;                  /* MA name size. */
    memcpy(&ma_p[2], ma_name, ma_len); /* MA name. */
    return true;
}

/* Returns true if the CFM library should process packets from 'flow'. */
bool
cfm_should_process_flow(const struct flow *flow)
{
    return (ntohs(flow->dl_type) == ETH_TYPE_CFM
            && eth_addr_equals(flow->dl_dst, eth_addr_ccm));
}

/* Updates internal statistics relevant to packet 'p'.  Should be called on
 * every packet whose flow returned true when passed to
 * cfm_should_process_flow. */
void
cfm_process_heartbeat(struct cfm *cfm, const struct ofpbuf *p)
{
    struct ccm *ccm;
    uint16_t ccm_mpid;
    uint8_t ccm_interval;
    struct remote_mp *rmp;
    struct eth_header *eth;

    struct cfm_internal *cfmi        = cfm_to_internal(cfm);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

    eth = p->l2;
    ccm = ofpbuf_at(p, (uint8_t *)p->l3 - (uint8_t *)p->data, CCM_LEN);

    if (!ccm) {
        VLOG_INFO_RL(&rl, "Received an un-parseable 802.1ag CCM heartbeat.");
        return;
    }

    if (ccm->opcode != CCM_OPCODE) {
        VLOG_INFO_RL(&rl, "Received an unsupported 802.1ag message. "
                     "(opcode %u)", ccm->opcode);
        return;
    }

    if (memcmp(ccm->maid, cfm->maid, sizeof ccm->maid)) {
        cfmi->x_recv_time = time_msec();
        cfm->fault = true;
        VLOG_WARN_RL(&rl, "Received unexpected remote MAID from MAC "
                     ETH_ADDR_FMT, ETH_ADDR_ARGS(eth->eth_src));
    } else {
        ccm_mpid = ntohs(ccm->mpid);
        ccm_interval = ccm->flags & 0x7;

        rmp = lookup_remote_mp(&cfm->remote_mps, ccm_mpid);

        if (rmp) {
            rmp->recv_time = time_msec();
            rmp->fault = ccm_interval != cfmi->ccm_interval;
            cfm->fault = rmp->fault || cfm->fault;
        } else {
            cfmi->x_recv_time = time_msec();
            cfm->fault = true;
            VLOG_WARN_RL(&rl, "Received unexpected remote MPID %d from MAC "
                         ETH_ADDR_FMT, ccm_mpid, ETH_ADDR_ARGS(eth->eth_src));
        }
    }
}

void
cfm_dump_ds(const struct cfm *cfm, struct ds *ds)
{
    const struct cfm_internal *cfmi = cfm_to_internal(cfm);
    long long int now = time_msec();
    struct remote_mp *rmp;

    ds_put_format(ds, "MPID %"PRIu16": %s\n", cfm->mpid,
                  cfm->fault ? "fault" : "");

    ds_put_format(ds, "\tinterval: %dms\n", cfmi->ccm_interval_ms);
    ds_put_format(ds, "\tnext CCM tx: %lldms\n",
                  timer_msecs_until_expired(&cfmi->tx_timer));
    ds_put_format(ds, "\tnext fault check: %lldms\n",
                  timer_msecs_until_expired(&cfmi->fault_timer));

    if (cfmi->x_recv_time != LLONG_MIN) {
        ds_put_format(ds, "\ttime since bad CCM rx: %lldms\n",
                      now - cfmi->x_recv_time);
    }

    ds_put_cstr(ds, "\n");
    HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
        ds_put_format(ds, "Remote MPID %"PRIu16": %s\n", rmp->mpid,
                      rmp->fault ? "fault" : "");
        ds_put_format(ds, "\ttime since CCM rx: %lldms\n",
                      time_msec() - rmp->recv_time);
    }
}
