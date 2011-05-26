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

#include <assert.h>
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
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(cfm);

/* Ethernet destination address of CCM packets. */
static const uint8_t eth_addr_ccm[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x30 };

#define ETH_TYPE_CFM 0x8902

/* A 'ccm' represents a Continuity Check Message from the 802.1ag
 * specification.  Continuity Check Messages are broadcast periodically so that
 * hosts can determine whom they have connectivity to. */
#define CCM_LEN 74
#define CCM_MAID_LEN 48
#define CCM_OPCODE 1 /* CFM message opcode meaning CCM. */
#define CCM_RDI_MASK 0x80
struct ccm {
    uint8_t  mdlevel_version; /* MD Level and Version */
    uint8_t  opcode;
    uint8_t  flags;
    uint8_t  tlv_offset;
    ovs_be32 seq;
    ovs_be16 mpid;
    uint8_t  maid[CCM_MAID_LEN];
    uint8_t  zero[16]; /* Defined by ITU-T Y.1731 should be zero */
} __attribute__((packed));
BUILD_ASSERT_DECL(CCM_LEN == sizeof(struct ccm));

struct cfm {
    char *name;                 /* Name of this CFM object. */
    struct hmap_node hmap_node; /* Node in all_cfms list. */

    uint16_t mpid;
    bool fault;            /* Indicates connectivity fault. */
    bool recv_fault;       /* Indicates an inability to receive CCMs. */

    uint32_t seq;          /* The sequence number of our last CCM. */
    uint8_t ccm_interval;  /* The CCM transmission interval. */
    int ccm_interval_ms;   /* 'ccm_interval' in milliseconds. */
    uint8_t maid[CCM_MAID_LEN]; /* The MAID of this CFM. */

    struct timer tx_timer;    /* Send CCM when expired. */
    struct timer fault_timer; /* Check for faults when expired. */

    struct hmap remote_mps; /* Expected remote MPs. */
};

/* Remote MPs represent foreign network entities that are configured to have
 * the same MAID as this CFM instance. */
struct remote_mp {
    uint16_t mpid;         /* The Maintenance Point ID of this 'remote_mp'. */
    struct hmap_node node; /* Node in 'remote_mps' map. */

    bool recv;           /* CCM was received since last fault check. */
    bool fault;          /* Indicates a connectivity fault. */
    bool rdi;            /* Remote Defect Indicator. Indicates remote_mp isn't
                            receiving CCMs that it's expecting to. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
static struct hmap all_cfms = HMAP_INITIALIZER(&all_cfms);

static void cfm_unixctl_show(struct unixctl_conn *, const char *args,
                             void *aux);

static void
cfm_generate_maid(struct cfm *cfm)
{
    const char *ovs_md_name = "ovs";
    const char *ovs_ma_name = "ovs";
    uint8_t *ma_p;
    size_t md_len, ma_len;

    memset(cfm->maid, 0, CCM_MAID_LEN);

    md_len = strlen(ovs_md_name);
    ma_len = strlen(ovs_ma_name);

    assert(md_len && ma_len && md_len + ma_len + 4 <= CCM_MAID_LEN);

    cfm->maid[0] = 4;                           /* MD name string format. */
    cfm->maid[1] = md_len;                      /* MD name size. */
    memcpy(&cfm->maid[2], ovs_md_name, md_len); /* MD name. */

    ma_p = cfm->maid + 2 + md_len;
    ma_p[0] = 2;                           /* MA name string format. */
    ma_p[1] = ma_len;                      /* MA name size. */
    memcpy(&ma_p[2], ovs_ma_name, ma_len); /* MA name. */
}

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
cfm_fault_interval(struct cfm *cfm)
{
    /* According to the 802.1ag specification we should assume every other MP
     * with the same MAID has the same transmission interval that we have.  If
     * an MP has a different interval, cfm_process_heartbeat will register it
     * as a fault (likely due to a configuration error).  Thus we can check all
     * MPs at once making this quite a bit simpler.
     *
     * According to the specification we should check when (ccm_interval_ms *
     * 3.5)ms have passed. */
    return (cfm->ccm_interval_ms * 7) / 2;
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

void
cfm_init(void)
{
    unixctl_command_register("cfm/show", cfm_unixctl_show, NULL);
}

/* Allocates a 'cfm' object called 'name'.  'cfm' should be initialized by
 * cfm_configure() before use. */
struct cfm *
cfm_create(const char *name)
{
    struct cfm *cfm;

    cfm = xzalloc(sizeof *cfm);
    cfm->name = xstrdup(name);
    hmap_init(&cfm->remote_mps);
    cfm_generate_maid(cfm);
    hmap_insert(&all_cfms, &cfm->hmap_node, hash_string(cfm->name, 0));
    return cfm;
}

void
cfm_destroy(struct cfm *cfm)
{
    struct remote_mp *rmp, *rmp_next;

    if (!cfm) {
        return;
    }

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {
        hmap_remove(&cfm->remote_mps, &rmp->node);
        free(rmp);
    }

    hmap_destroy(&cfm->remote_mps);
    hmap_remove(&all_cfms, &cfm->hmap_node);
    free(cfm->name);
    free(cfm);
}

/* Should be run periodically to update fault statistics messages. */
void
cfm_run(struct cfm *cfm)
{
    if (timer_expired(&cfm->fault_timer)) {
        long long int interval = cfm_fault_interval(cfm);
        struct remote_mp *rmp;

        cfm->fault = false;
        cfm->recv_fault = false;
        HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
            rmp->fault = !rmp->recv;
            rmp->recv = false;

            if (rmp->fault) {
                cfm->recv_fault = true;
                VLOG_DBG("%s: No CCM from RMP %"PRIu16" in the last %lldms",
                         cfm->name, rmp->mpid, interval);
            } else if (rmp->rdi) {
                cfm->fault = true;
                VLOG_DBG("%s: RDI bit flagged from RMP %"PRIu16, cfm->name,
                         rmp->mpid);
            }
        }

        if (cfm->recv_fault) {
            cfm->fault = true;
        } else {
            VLOG_DBG("%s: All RMPs received CCMs in the last %lldms",
                     cfm->name, interval);
        }

        timer_set_duration(&cfm->fault_timer, interval);
    }
}

/* Should be run periodically to check if the CFM module has a CCM message it
 * wishes to send. */
bool
cfm_should_send_ccm(struct cfm *cfm)
{
    return timer_expired(&cfm->tx_timer);
}

/* Composes a CCM message into 'packet'.  Messages generated with this function
 * should be sent whenever cfm_should_send_ccm() indicates. */
void
cfm_compose_ccm(struct cfm *cfm, struct ofpbuf *packet,
                uint8_t eth_src[ETH_ADDR_LEN])
{
    struct ccm *ccm;

    timer_set_duration(&cfm->tx_timer, cfm->ccm_interval_ms);

    ccm = eth_compose(packet, eth_addr_ccm, eth_src, ETH_TYPE_CFM,
                      sizeof *ccm);
    ccm->mdlevel_version = 0;
    ccm->opcode = CCM_OPCODE;
    ccm->tlv_offset = 70;
    ccm->seq = htonl(++cfm->seq);
    ccm->mpid = htons(cfm->mpid);
    ccm->flags = cfm->ccm_interval;
    memcpy(ccm->maid, cfm->maid, sizeof ccm->maid);

    if (cfm->recv_fault) {
        ccm->flags |= CCM_RDI_MASK;
    }
}

void
cfm_wait(struct cfm *cfm)
{

    timer_wait(&cfm->tx_timer);
    timer_wait(&cfm->fault_timer);
}

/* Configures 'cfm' with settings from 's'. */
bool
cfm_configure(struct cfm *cfm, const struct cfm_settings *s)
{
    size_t i;
    uint8_t interval;
    struct hmap new_rmps;
    struct remote_mp *rmp, *rmp_next;

    if (!cfm_is_valid_mpid(s->mpid) || s->interval <= 0
        || s->n_remote_mpids <= 0) {
        return false;
    }

    cfm->mpid = s->mpid;
    interval = ms_to_ccm_interval(s->interval);

    if (interval != cfm->ccm_interval) {
        cfm->ccm_interval = interval;
        cfm->ccm_interval_ms = ccm_interval_to_ms(interval);

        timer_set_expired(&cfm->tx_timer);
        timer_set_duration(&cfm->fault_timer, cfm_fault_interval(cfm));
    }

    hmap_init(&new_rmps);
    for (i = 0; i < s->n_remote_mpids; i++) {
        uint16_t mpid = s->remote_mpids[i];

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
    bool ccm_rdi;
    uint16_t ccm_mpid;
    uint8_t ccm_interval;
    struct remote_mp *rmp;
    struct eth_header *eth;

    eth = p->l2;
    ccm = ofpbuf_at(p, (uint8_t *)p->l3 - (uint8_t *)p->data, CCM_LEN);

    if (!ccm) {
        VLOG_INFO_RL(&rl, "%s: Received an unparseable 802.1ag CCM heartbeat.",
                     cfm->name);
        return;
    }

    if (ccm->opcode != CCM_OPCODE) {
        VLOG_INFO_RL(&rl, "%s: Received an unsupported 802.1ag message. "
                     "(opcode %u)", cfm->name, ccm->opcode);
        return;
    }

    /* According to the 802.1ag specification, reception of a CCM with an
     * incorrect ccm_interval, unexpected MAID, or unexpected MPID should
     * trigger a fault.  We ignore this requirement for several reasons.
     *
     * Faults can cause a controller or Open vSwitch to make potentially
     * expensive changes to the network topology.  It seems prudent to trigger
     * them judiciously, especially when CFM is used to check slave status of
     * bonds. Furthermore, faults can be maliciously triggered by crafting
     * invalid CCMs. */
    if (memcmp(ccm->maid, cfm->maid, sizeof ccm->maid)) {
        VLOG_WARN_RL(&rl, "%s: Received unexpected remote MAID from MAC "
                     ETH_ADDR_FMT, cfm->name, ETH_ADDR_ARGS(eth->eth_src));
    } else {
        ccm_mpid = ntohs(ccm->mpid);
        ccm_interval = ccm->flags & 0x7;
        ccm_rdi = ccm->flags & CCM_RDI_MASK;

        rmp = lookup_remote_mp(&cfm->remote_mps, ccm_mpid);

        if (rmp) {
            rmp->recv = true;
            rmp->rdi = ccm_rdi;

            if (ccm_interval != cfm->ccm_interval) {
                VLOG_WARN_RL(&rl, "%s: received a CCM with an invalid interval"
                             " (%"PRIu8") from RMP %"PRIu16, cfm->name,
                             ccm_interval, rmp->mpid);
            }
        } else {
            VLOG_WARN_RL(&rl, "%s: Received unexpected remote MPID %d from"
                         " MAC " ETH_ADDR_FMT, cfm->name, ccm_mpid,
                         ETH_ADDR_ARGS(eth->eth_src));
        }

        VLOG_DBG("%s: Received CCM (seq %"PRIu32") (mpid %"PRIu16")"
                 " (interval %"PRIu8") (RDI %s)", cfm->name, ntohl(ccm->seq),
                 ccm_mpid, ccm_interval, ccm_rdi ? "true" : "false");
    }
}

/* Gets the fault status of 'cfm'.  Returns true when 'cfm' has detected
 * connectivity problems, false otherwise. */
bool
cfm_get_fault(const struct cfm *cfm)
{
    return cfm->fault;
}

static struct cfm *
cfm_find(const char *name)
{
    struct cfm *cfm;

    HMAP_FOR_EACH_WITH_HASH (cfm, hmap_node, hash_string(name, 0), &all_cfms) {
        if (!strcmp(cfm->name, name)) {
            return cfm;
        }
    }
    return NULL;
}

static void
cfm_unixctl_show(struct unixctl_conn *conn,
                 const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct cfm *cfm;
    struct remote_mp *rmp;

    cfm = cfm_find(args);
    if (!cfm) {
        unixctl_command_reply(conn, 501, "no such CFM object");
        return;
    }

    ds_put_format(&ds, "MPID %"PRIu16":%s%s\n", cfm->mpid,
                  cfm->fault ? " fault" : "",
                  cfm->recv_fault ? " recv_fault" : "");

    ds_put_format(&ds, "\tinterval: %dms\n", cfm->ccm_interval_ms);
    ds_put_format(&ds, "\tnext CCM tx: %lldms\n",
                  timer_msecs_until_expired(&cfm->tx_timer));
    ds_put_format(&ds, "\tnext fault check: %lldms\n",
                  timer_msecs_until_expired(&cfm->fault_timer));

    ds_put_cstr(&ds, "\n");
    HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
        ds_put_format(&ds, "Remote MPID %"PRIu16": %s\n", rmp->mpid,
                      rmp->fault ? "fault" : "");
        ds_put_format(&ds, "\trecv since check: %s",
                      rmp->recv ? "true" : "false");
    }

    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}
