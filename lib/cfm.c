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

#include "byte-order.h"
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

#define CFM_MAX_RMPS 256

/* Ethernet destination address of CCM packets. */
static const uint8_t eth_addr_ccm[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x30 };
static const uint8_t eth_addr_ccm_x[6] = {
    0x01, 0x23, 0x20, 0x00, 0x00, 0x30
};

#define ETH_TYPE_CFM 0x8902

/* A 'ccm' represents a Continuity Check Message from the 802.1ag
 * specification.  Continuity Check Messages are broadcast periodically so that
 * hosts can determine whom they have connectivity to.
 *
 * The minimum length of a CCM as specified by IEEE 802.1ag is 75 bytes.
 * Previous versions of Open vSwitch generated 74-byte CCM messages, so we
 * accept such messages too. */
#define CCM_LEN 75
#define CCM_ACCEPT_LEN 74
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

    /* Defined by ITU-T Y.1731 should be zero */
    ovs_be16 interval_ms_x;      /* Transmission interval in ms. */
    ovs_be64 mpid64;             /* MPID in extended mode. */
    uint8_t opdown;              /* Operationally down. */
    uint8_t  zero[5];

    /* TLV space. */
    uint8_t end_tlv;
} __attribute__((packed));
BUILD_ASSERT_DECL(CCM_LEN == sizeof(struct ccm));

struct cfm {
    char *name;                 /* Name of this CFM object. */
    struct hmap_node hmap_node; /* Node in all_cfms list. */

    uint64_t mpid;
    bool extended;         /* Extended mode. */
    bool fault;            /* Indicates connectivity fault. */
    bool unexpected_recv;  /* Received an unexpected CCM. */
    bool opup;             /* Operational State. */
    bool remote_opup;      /* Remote Operational State. */

    uint32_t seq;          /* The sequence number of our last CCM. */
    uint8_t ccm_interval;  /* The CCM transmission interval. */
    int ccm_interval_ms;   /* 'ccm_interval' in milliseconds. */
    uint16_t ccm_vlan;     /* Vlan tag of CCM PDUs. */
    uint8_t maid[CCM_MAID_LEN]; /* The MAID of this CFM. */

    struct timer tx_timer;    /* Send CCM when expired. */
    struct timer fault_timer; /* Check for faults when expired. */

    struct hmap remote_mps;   /* Remote MPs. */

    /* Result of cfm_get_remote_mpids(). Updated only during fault check to
     * avoid flapping. */
    uint64_t *rmps_array;     /* Cache of remote_mps. */
    size_t rmps_array_len;    /* Number of rmps in 'rmps_array'. */
};

/* Remote MPs represent foreign network entities that are configured to have
 * the same MAID as this CFM instance. */
struct remote_mp {
    uint64_t mpid;         /* The Maintenance Point ID of this 'remote_mp'. */
    struct hmap_node node; /* Node in 'remote_mps' map. */

    bool recv;           /* CCM was received since last fault check. */
    bool rdi;            /* Remote Defect Indicator. Indicates remote_mp isn't
                            receiving CCMs that it's expecting to. */
    bool opup;           /* Operational State. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
static struct hmap all_cfms = HMAP_INITIALIZER(&all_cfms);

static void cfm_unixctl_show(struct unixctl_conn *, const char *args,
                             void *aux);

static const uint8_t *
cfm_ccm_addr(const struct cfm *cfm)
{
    return cfm->extended ? eth_addr_ccm_x : eth_addr_ccm;
}

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
hash_mpid(uint64_t mpid)
{
    return hash_bytes(&mpid, sizeof mpid, 0);
}

static bool
cfm_is_valid_mpid(bool extended, uint64_t mpid)
{
    /* 802.1ag specification requires MPIDs to be within the range [1, 8191].
     * In extended mode we relax this requirement. */
    return mpid >= 1 && (extended || mpid <= 8191);
}

static struct remote_mp *
lookup_remote_mp(const struct cfm *cfm, uint64_t mpid)
{
    struct remote_mp *rmp;

    HMAP_FOR_EACH_IN_BUCKET (rmp, node, hash_mpid(mpid), &cfm->remote_mps) {
        if (rmp->mpid == mpid) {
            return rmp;
        }
    }

    return NULL;
}

void
cfm_init(void)
{
    unixctl_command_register("cfm/show", "[interface]", cfm_unixctl_show,
                             NULL);
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
    cfm->remote_opup = true;
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
    free(cfm->rmps_array);
    free(cfm->name);
    free(cfm);
}

/* Should be run periodically to update fault statistics messages. */
void
cfm_run(struct cfm *cfm)
{
    if (timer_expired(&cfm->fault_timer)) {
        long long int interval = cfm_fault_interval(cfm);
        struct remote_mp *rmp, *rmp_next;

        cfm->fault = cfm->unexpected_recv;
        cfm->unexpected_recv = false;

        cfm->rmps_array_len = 0;
        free(cfm->rmps_array);
        cfm->rmps_array = xmalloc(hmap_count(&cfm->remote_mps) *
                                  sizeof *cfm->rmps_array);

        cfm->remote_opup = true;
        HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {

            if (!rmp->recv) {
                VLOG_DBG("%s: no CCM from RMP %"PRIu64" in the last %lldms",
                         cfm->name, rmp->mpid, interval);
                hmap_remove(&cfm->remote_mps, &rmp->node);
                free(rmp);
            } else {
                rmp->recv = false;

                if (rmp->mpid == cfm->mpid) {
                    VLOG_WARN_RL(&rl,"%s: received CCM with local MPID"
                                 " %"PRIu64, cfm->name, rmp->mpid);
                    cfm->fault = true;
                }

                if (rmp->rdi) {
                    VLOG_DBG("%s: RDI bit flagged from RMP %"PRIu64, cfm->name,
                             rmp->mpid);
                    cfm->fault = true;
                }

                if (!rmp->opup) {
                    cfm->remote_opup = rmp->opup;
                }

                cfm->rmps_array[cfm->rmps_array_len++] = rmp->mpid;
            }
        }

        if (hmap_is_empty(&cfm->remote_mps)) {
            cfm->fault = true;
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
    eth_compose(packet, cfm_ccm_addr(cfm), eth_src, ETH_TYPE_CFM, sizeof *ccm);

    if (cfm->ccm_vlan) {
        eth_push_vlan(packet, htons(cfm->ccm_vlan));
    }

    ccm = packet->l3;
    ccm->mdlevel_version = 0;
    ccm->opcode = CCM_OPCODE;
    ccm->tlv_offset = 70;
    ccm->seq = htonl(++cfm->seq);
    ccm->flags = cfm->ccm_interval;
    memcpy(ccm->maid, cfm->maid, sizeof ccm->maid);
    memset(ccm->zero, 0, sizeof ccm->zero);
    ccm->end_tlv = 0;

    if (cfm->extended) {
        ccm->mpid = htons(hash_mpid(cfm->mpid));
        ccm->mpid64 = htonll(cfm->mpid);
        ccm->opdown = !cfm->opup;
    } else {
        ccm->mpid = htons(cfm->mpid);
        ccm->mpid64 = htonll(0);
        ccm->opdown = 0;
    }

    if (cfm->ccm_interval == 0) {
        assert(cfm->extended);
        ccm->interval_ms_x = htons(cfm->ccm_interval_ms);
    }

    if (hmap_is_empty(&cfm->remote_mps)) {
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
    uint8_t interval;
    int interval_ms;

    if (!cfm_is_valid_mpid(s->extended, s->mpid) || s->interval <= 0) {
        return false;
    }

    cfm->mpid = s->mpid;
    cfm->extended = s->extended;
    cfm->opup = s->opup;
    interval = ms_to_ccm_interval(s->interval);
    interval_ms = ccm_interval_to_ms(interval);

    cfm->ccm_vlan = s->ccm_vlan & VLAN_VID_MASK;
    if (cfm->extended && interval_ms != s->interval) {
        interval = 0;
        interval_ms = MIN(s->interval, UINT16_MAX);
    }

    if (interval != cfm->ccm_interval || interval_ms != cfm->ccm_interval_ms) {
        cfm->ccm_interval = interval;
        cfm->ccm_interval_ms = interval_ms;

        timer_set_expired(&cfm->tx_timer);
        timer_set_duration(&cfm->fault_timer, cfm_fault_interval(cfm));
    }

    return true;
}

/* Returns true if 'cfm' should process packets from 'flow'. */
bool
cfm_should_process_flow(const struct cfm *cfm, const struct flow *flow)
{
    return (ntohs(flow->dl_type) == ETH_TYPE_CFM
            && eth_addr_equals(flow->dl_dst, cfm_ccm_addr(cfm)));
}

/* Updates internal statistics relevant to packet 'p'.  Should be called on
 * every packet whose flow returned true when passed to
 * cfm_should_process_flow. */
void
cfm_process_heartbeat(struct cfm *cfm, const struct ofpbuf *p)
{
    struct ccm *ccm;
    struct eth_header *eth;

    eth = p->l2;
    ccm = ofpbuf_at(p, (uint8_t *)p->l3 - (uint8_t *)p->data, CCM_ACCEPT_LEN);

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
        cfm->unexpected_recv = true;
        VLOG_WARN_RL(&rl, "%s: Received unexpected remote MAID from MAC "
                     ETH_ADDR_FMT, cfm->name, ETH_ADDR_ARGS(eth->eth_src));
    } else {
        uint8_t ccm_interval = ccm->flags & 0x7;
        bool ccm_rdi = ccm->flags & CCM_RDI_MASK;
        uint16_t ccm_interval_ms_x = ntohs(ccm->interval_ms_x);

        struct remote_mp *rmp;
        uint64_t ccm_mpid;
        bool ccm_opdown;

        if (cfm->extended) {
            ccm_mpid = ntohll(ccm->mpid64);
            ccm_opdown = ccm->opdown;
        } else {
            ccm_mpid = ntohs(ccm->mpid);
            ccm_opdown = false;
        }

        if (ccm_interval != cfm->ccm_interval) {
            VLOG_WARN_RL(&rl, "%s: received a CCM with an invalid interval"
                         " (%"PRIu8") from RMP %"PRIu64, cfm->name,
                         ccm_interval, ccm_mpid);
        }

        if (cfm->extended && ccm_interval == 0
            && ccm_interval_ms_x != cfm->ccm_interval_ms) {
            VLOG_WARN_RL(&rl, "%s: received a CCM with an invalid extended"
                         " interval (%"PRIu16"ms) from RMP %"PRIu64, cfm->name,
                         ccm_interval_ms_x, ccm_mpid);
        }

        rmp = lookup_remote_mp(cfm, ccm_mpid);
        if (!rmp) {
            if (hmap_count(&cfm->remote_mps) < CFM_MAX_RMPS) {
                rmp = xmalloc(sizeof *rmp);
                hmap_insert(&cfm->remote_mps, &rmp->node, hash_mpid(ccm_mpid));
            } else {
                cfm->unexpected_recv = true;
                VLOG_WARN_RL(&rl,
                             "%s: dropped CCM with MPID %"PRIu64" from MAC "
                             ETH_ADDR_FMT, cfm->name, ccm_mpid,
                             ETH_ADDR_ARGS(eth->eth_src));
            }
        }

        if (rmp) {
            rmp->mpid = ccm_mpid;
            rmp->recv = true;
            rmp->rdi = ccm_rdi;
            rmp->opup = !ccm_opdown;
        }

        VLOG_DBG("%s: received CCM (seq %"PRIu32") (mpid %"PRIu64")"
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

/* Gets the operational state of 'cfm'.  'cfm' is considered operationally down
 * if it has received a CCM with the operationally down bit set from any of its
 * remote maintenance points. Returns true if 'cfm' is operationally up. False
 * otherwise. */
bool
cfm_get_opup(const struct cfm *cfm)
{
    return cfm->remote_opup;
}

/* Populates 'rmps' with an array of remote maintenance points reachable by
 * 'cfm'. The number of remote maintenance points is written to 'n_rmps'.
 * 'cfm' retains ownership of the array written to 'rmps' */
void
cfm_get_remote_mpids(const struct cfm *cfm, const uint64_t **rmps,
                     size_t *n_rmps)
{
    *rmps = cfm->rmps_array;
    *n_rmps = cfm->rmps_array_len;
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
cfm_print_details(struct ds *ds, const struct cfm *cfm)
{
    struct remote_mp *rmp;

    ds_put_format(ds, "---- %s ----\n", cfm->name);
    ds_put_format(ds, "MPID %"PRIu64":%s%s%s\n", cfm->mpid,
                  cfm->extended ? " extended" : "",
                  cfm->fault ? " fault" : "",
                  cfm->unexpected_recv ? " unexpected_recv" : "");

    ds_put_format(ds, "\topstate: %s\n", cfm->opup ? "up" : "down");
    ds_put_format(ds, "\tremote_opstate: %s\n",
                  cfm->remote_opup ? "up" : "down");
    ds_put_format(ds, "\tinterval: %dms\n", cfm->ccm_interval_ms);
    ds_put_format(ds, "\tnext CCM tx: %lldms\n",
                  timer_msecs_until_expired(&cfm->tx_timer));
    ds_put_format(ds, "\tnext fault check: %lldms\n",
                  timer_msecs_until_expired(&cfm->fault_timer));

    HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
        ds_put_format(ds, "Remote MPID %"PRIu64":%s\n",
                      rmp->mpid,
                      rmp->rdi ? " rdi" : "");
        ds_put_format(ds, "\trecv since check: %s\n",
                      rmp->recv ? "true" : "false");
        ds_put_format(ds, "\topstate: %s\n", rmp->opup? "up" : "down");
    }
}

static void
cfm_unixctl_show(struct unixctl_conn *conn,
                 const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct cfm *cfm;

    if (strlen(args)) {
        cfm = cfm_find(args);
        if (!cfm) {
            unixctl_command_reply(conn, 501, "no such CFM object");
            return;
        }
        cfm_print_details(&ds, cfm);
    } else {
        HMAP_FOR_EACH (cfm, hmap_node, &all_cfms) {
            cfm_print_details(&ds, cfm);
        }
    }

    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}
