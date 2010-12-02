/*
 * Copyright (c) 2010 Nicira Networks.
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

#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(cfm);

#define CCM_OPCODE 1              /* CFM message opcode meaning CCM. */
#define DEST_ADDR  UINT64_C(0x0180C2000030) /* MD level 0 CCM destination. */

struct cfm_internal {
    struct cfm cfm;
    uint32_t seq;          /* The sequence number of our last CCM. */

    uint8_t ccm_interval;  /* The CCM transmission interval. */
    int ccm_interval_ms;   /* 'ccm_interval' in milliseconds. */

    long long ccm_sent;    /* The time we last sent a CCM. */
    long long fault_check; /* The time we last checked for faults. */
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
cfm_to_internal(struct cfm *cfm)
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

static struct ofpbuf *
compose_ccm(struct cfm_internal *cfmi)
{
    struct ccm *ccm;
    struct ofpbuf *packet;
    struct eth_header *eth;

    packet = ofpbuf_new(ETH_HEADER_LEN + CCM_LEN + 2);

    ofpbuf_reserve(packet, 2);

    eth = ofpbuf_put_zeros(packet, ETH_HEADER_LEN);
    ccm = ofpbuf_put_zeros(packet, CCM_LEN);

    eth_addr_from_uint64(DEST_ADDR, eth->eth_dst);
    memcpy(eth->eth_src, cfmi->cfm.eth_src, sizeof eth->eth_src);
    eth->eth_type = htons(ETH_TYPE_CFM);

    ccm->mdlevel_version = 0;
    ccm->opcode          = CCM_OPCODE;
    ccm->tlv_offset      = 70;
    ccm->seq             = htonl(++cfmi->seq);
    ccm->mpid            = htons(cfmi->cfm.mpid);
    ccm->flags           = cfmi->ccm_interval;
    memcpy(ccm->maid, cfmi->cfm.maid, sizeof ccm->maid);
    return packet;
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

    hmap_init(&cfm->remote_mps);
    hmap_init(&cfm->x_remote_mps);
    hmap_init(&cfm->x_remote_maids);
    return cfm;
}

void
cfm_destroy(struct cfm *cfm)
{
    struct remote_mp *rmp, *rmp_next;
    struct remote_maid *rmaid, *rmaid_next;

    if (!cfm) {
        return;
    }

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {
        hmap_remove(&cfm->remote_mps, &rmp->node);
        free(rmp);
    }

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->x_remote_mps) {
        hmap_remove(&cfm->x_remote_mps, &rmp->node);
        free(rmp);
    }

    HMAP_FOR_EACH_SAFE (rmaid, rmaid_next, node, &cfm->x_remote_maids) {
        hmap_remove(&cfm->x_remote_maids, &rmaid->node);
        free(rmaid);
    }

    hmap_destroy(&cfm->remote_mps);
    hmap_destroy(&cfm->x_remote_mps);
    hmap_destroy(&cfm->x_remote_maids);
    free(cfm_to_internal(cfm));
}

/* Should be run periodically to update fault statistics and generate CCM
 * messages.  If necessary, returns a packet which the caller is responsible
 * for sending, un-initing, and deallocating.  Otherwise returns NULL. */
struct ofpbuf *
cfm_run(struct cfm *cfm)
{
    long long now = time_msec();
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    /* According to the 802.1ag specification we should assume every other MP
     * with the same MAID has the same transmission interval that we have.  If
     * an MP has a different interval, cfm_process_heartbeat will register it
     * as a fault (likely due to a configuration error).  Thus we can check all
     * MPs at once making this quite a bit simpler.
     *
     * According to the specification we should check when (ccm_interval_ms *
     * 3.5)ms have passed.  We changed the multiplier to 4 to avoid messy
     * floating point arithmetic and add a bit of wiggle room. */
    if (now >= cfmi->fault_check + cfmi->ccm_interval_ms * 4) {
        bool fault;
        struct remote_mp *rmp, *rmp_next;
        struct remote_maid *rmaid, *rmaid_next;

        fault = false;

        HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
            rmp->fault = rmp->fault || cfmi->fault_check > rmp->recv_time;
            fault      = rmp->fault || fault;
        }

        HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->x_remote_mps) {
            if (cfmi->fault_check > rmp->recv_time) {
                hmap_remove(&cfm->x_remote_mps, &rmp->node);
                free(rmp);
            }
        }

        HMAP_FOR_EACH_SAFE (rmaid, rmaid_next, node, &cfm->x_remote_maids) {
            if (cfmi->fault_check > rmaid->recv_time) {
                hmap_remove(&cfm->x_remote_maids, &rmaid->node);
                free(rmaid);
            }
        }

        fault = (fault || !hmap_is_empty(&cfm->x_remote_mps)
                 || !hmap_is_empty(&cfm->x_remote_maids));

        cfm->fault        = fault;
        cfmi->fault_check = now;
    }

    if (now >= cfmi->ccm_sent + cfmi->ccm_interval_ms) {
        cfmi->ccm_sent = now;
        return compose_ccm(cfmi);
    }

    return NULL;
}

void
cfm_wait(struct cfm *cfm)
{
    long long wait;
    struct cfm_internal *cfmi = cfm_to_internal(cfm);

    wait = MIN(cfmi->ccm_sent + cfmi->ccm_interval_ms,
               cfmi->fault_check + cfmi->ccm_interval_ms * 4);
    poll_timer_wait_until(wait);
}

/* Should be called whenever a client of the cfm library changes the internals
 * of 'cfm'. Returns true if 'cfm' is valid. */
bool
cfm_configure(struct cfm *cfm)
{
    struct cfm_internal *cfmi;

    if (!cfm_is_valid_mpid(cfm->mpid) || !cfm->interval) {
        return false;
    }

    cfmi                  = cfm_to_internal(cfm);
    cfmi->ccm_interval    = ms_to_ccm_interval(cfm->interval);
    cfmi->ccm_interval_ms = ccm_interval_to_ms(cfmi->ccm_interval);

    /* Force a resend and check in case anything changed. */
    cfmi->ccm_sent    = 0;
    cfmi->fault_check = 0;
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
        } else if ((rmp = lookup_remote_mp(&cfm->x_remote_mps, mpid))) {
            hmap_remove(&cfm->x_remote_mps, &rmp->node);
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
            && eth_addr_to_uint64(flow->dl_dst) == DEST_ADDR);
}

/* Updates internal statistics relevant to packet 'p'.  Should be called on
 * every packet whose flow returned true when passed to
 * cfm_should_process_flow. */
void
cfm_process_heartbeat(struct cfm *cfm, const struct ofpbuf *p)
{
    struct ccm *ccm;
    uint16_t ccm_mpid;
    uint32_t ccm_seq;
    uint8_t ccm_interval;
    struct remote_mp *rmp;

    struct cfm_internal *cfmi        = cfm_to_internal(cfm);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

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
        uint32_t hash;
        struct remote_maid *rmaid;

        hash = hash_bytes(ccm->maid, sizeof ccm->maid, 0);

        HMAP_FOR_EACH_IN_BUCKET (rmaid, node, hash, &cfm->x_remote_maids) {
            if (memcmp(rmaid->maid, ccm->maid, sizeof rmaid->maid) == 0) {
                rmaid->recv_time = time_msec();
                return;
            }
        }

        rmaid            = xzalloc(sizeof *rmaid);
        rmaid->recv_time = time_msec();
        memcpy(rmaid->maid, ccm->maid, sizeof rmaid->maid);
        hmap_insert(&cfm->x_remote_maids, &rmaid->node, hash);
        return;
    }

    ccm_mpid     = ntohs(ccm->mpid);
    ccm_seq      = ntohl(ccm->seq);
    ccm_interval = ccm->flags & 0x7;

    rmp = lookup_remote_mp(&cfm->remote_mps, ccm_mpid);

    if (!rmp) {
        rmp = lookup_remote_mp(&cfm->x_remote_mps, ccm_mpid);
    }

    if (!rmp) {
        rmp       = xzalloc(sizeof *rmp);
        rmp->mpid = ccm_mpid;
        hmap_insert(&cfm->x_remote_mps, &rmp->node, hash_mpid(ccm_mpid));
    }

    rmp->recv_time = time_msec();
    rmp->fault     = ccm_interval != cfmi->ccm_interval;
}
