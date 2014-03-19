/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include "byte-order.h"
#include "connectivity.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
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
#define CFM_HEALTH_INTERVAL 6

OVS_PACKED(
struct ccm {
    uint8_t mdlevel_version; /* MD Level and Version */
    uint8_t opcode;
    uint8_t flags;
    uint8_t tlv_offset;
    ovs_be32 seq;
    ovs_be16 mpid;
    uint8_t maid[CCM_MAID_LEN];

    /* Defined by ITU-T Y.1731 should be zero */
    ovs_be16 interval_ms_x;      /* Transmission interval in ms. */
    ovs_be64 mpid64;             /* MPID in extended mode. */
    uint8_t opdown;              /* Operationally down. */
    uint8_t zero[5];

    /* TLV space. */
    uint8_t end_tlv;
});
BUILD_ASSERT_DECL(CCM_LEN == sizeof(struct ccm));

struct cfm {
    const char *name;           /* Name of this CFM object. */
    struct hmap_node hmap_node; /* Node in all_cfms list. */

    struct netdev *netdev;
    uint64_t rx_packets;        /* Packets received by 'netdev'. */

    uint64_t mpid;
    bool demand;           /* Demand mode. */
    bool booted;           /* A full fault interval has occurred. */
    enum cfm_fault_reason fault;  /* Connectivity fault status. */
    enum cfm_fault_reason recv_fault;  /* Bit mask of faults occurring on
                                          receive. */
    bool opup;             /* Operational State. */
    bool remote_opup;      /* Remote Operational State. */

    int fault_override;    /* Manual override of 'fault' status.
                              Ignored if negative. */

    uint32_t seq;          /* The sequence number of our last CCM. */
    uint8_t ccm_interval;  /* The CCM transmission interval. */
    int ccm_interval_ms;   /* 'ccm_interval' in milliseconds. */
    uint16_t ccm_vlan;     /* Vlan tag of CCM PDUs.  CFM_RANDOM_VLAN if
                              random. */
    uint8_t ccm_pcp;       /* Priority of CCM PDUs. */
    uint8_t maid[CCM_MAID_LEN]; /* The MAID of this CFM. */

    struct timer tx_timer;    /* Send CCM when expired. */
    struct timer fault_timer; /* Check for faults when expired. */

    struct hmap remote_mps;   /* Remote MPs. */

    /* Result of cfm_get_remote_mpids(). Updated only during fault check to
     * avoid flapping. */
    uint64_t *rmps_array;     /* Cache of remote_mps. */
    size_t rmps_array_len;    /* Number of rmps in 'rmps_array'. */

    int health;               /* Percentage of the number of CCM frames
                                 received. */
    int health_interval;      /* Number of fault_intervals since health was
                                 recomputed. */
    long long int last_tx;    /* Last CCM transmission time. */

    atomic_bool check_tnl_key; /* Verify the tunnel key of inbound packets? */
    atomic_bool extended;      /* Extended mode. */
    atomic_int ref_cnt;

    uint64_t flap_count;       /* Count the flaps since boot. */
};

/* Remote MPs represent foreign network entities that are configured to have
 * the same MAID as this CFM instance. */
struct remote_mp {
    uint64_t mpid;         /* The Maintenance Point ID of this 'remote_mp'. */
    struct hmap_node node; /* Node in 'remote_mps' map. */

    bool recv;           /* CCM was received since last fault check. */
    bool opup;           /* Operational State. */
    uint32_t seq;        /* Most recently received sequence number. */
    uint8_t num_health_ccm; /* Number of received ccm frames every
                               CFM_HEALTH_INTERVAL * 'fault_interval'. */
    long long int last_rx; /* Last CCM reception time. */

};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 30);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct hmap all_cfms__ = HMAP_INITIALIZER(&all_cfms__);
static struct hmap *const all_cfms OVS_GUARDED_BY(mutex) = &all_cfms__;

static unixctl_cb_func cfm_unixctl_show;
static unixctl_cb_func cfm_unixctl_set_fault;

static uint64_t
cfm_rx_packets(const struct cfm *cfm) OVS_REQUIRES(mutex)
{
    struct netdev_stats stats;

    if (!netdev_get_stats(cfm->netdev, &stats)) {
        return stats.rx_packets;
    } else {
        return 0;
    }
}

static const uint8_t *
cfm_ccm_addr(struct cfm *cfm)
{
    bool extended;
    atomic_read(&cfm->extended, &extended);
    return extended ? eth_addr_ccm_x : eth_addr_ccm;
}

/* Returns the string representation of the given cfm_fault_reason 'reason'. */
const char *
cfm_fault_reason_to_str(int reason)
{
    switch (reason) {
#define CFM_FAULT_REASON(NAME, STR) case CFM_FAULT_##NAME: return #STR;
        CFM_FAULT_REASONS
#undef CFM_FAULT_REASON
    default: return "<unknown>";
    }
}

static void
ds_put_cfm_fault(struct ds *ds, int fault)
{
    int i;

    for (i = 0; i < CFM_FAULT_N_REASONS; i++) {
        int reason = 1 << i;

        if (fault & reason) {
            ds_put_format(ds, "%s ", cfm_fault_reason_to_str(reason));
        }
    }

    ds_chomp(ds, ' ');
}

static void
cfm_generate_maid(struct cfm *cfm) OVS_REQUIRES(mutex)
{
    const char *ovs_md_name = "ovs";
    const char *ovs_ma_name = "ovs";
    uint8_t *ma_p;
    size_t md_len, ma_len;

    memset(cfm->maid, 0, CCM_MAID_LEN);

    md_len = strlen(ovs_md_name);
    ma_len = strlen(ovs_ma_name);

    ovs_assert(md_len && ma_len && md_len + ma_len + 4 <= CCM_MAID_LEN);

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
    case 0:  OVS_NOT_REACHED(); /* Explicitly not supported by 802.1ag. */
    case 1:  return 3;      /* Not recommended due to timer resolution. */
    case 2:  return 10;     /* Not recommended due to timer resolution. */
    case 3:  return 100;
    case 4:  return 1000;
    case 5:  return 10000;
    case 6:  return 60000;
    case 7:  return 600000;
    default: OVS_NOT_REACHED(); /* Explicitly not supported by 802.1ag. */
    }

    OVS_NOT_REACHED();
}

static long long int
cfm_fault_interval(struct cfm *cfm) OVS_REQUIRES(mutex)
{
    /* According to the 802.1ag specification we should assume every other MP
     * with the same MAID has the same transmission interval that we have.  If
     * an MP has a different interval, cfm_process_heartbeat will register it
     * as a fault (likely due to a configuration error).  Thus we can check all
     * MPs at once making this quite a bit simpler.
     *
     * When cfm is not in demand mode, we check when (ccm_interval_ms * 3.5) ms
     * have passed.  When cfm is in demand mode, we check when
     * (MAX(ccm_interval_ms, 500) * 3.5) ms have passed.  This ensures that
     * ovs-vswitchd has enough time to pull statistics from the datapath. */

    return (MAX(cfm->ccm_interval_ms, cfm->demand ? 500 : cfm->ccm_interval_ms)
            * 7) / 2;
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
lookup_remote_mp(const struct cfm *cfm, uint64_t mpid) OVS_REQUIRES(mutex)
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
    unixctl_command_register("cfm/show", "[interface]", 0, 1, cfm_unixctl_show,
                             NULL);
    unixctl_command_register("cfm/set-fault", "[interface] normal|false|true",
                             1, 2, cfm_unixctl_set_fault, NULL);
}

/* Allocates a 'cfm' object called 'name'.  'cfm' should be initialized by
 * cfm_configure() before use. */
struct cfm *
cfm_create(const struct netdev *netdev) OVS_EXCLUDED(mutex)
{
    struct cfm *cfm;

    cfm = xzalloc(sizeof *cfm);
    cfm->netdev = netdev_ref(netdev);
    cfm->name = netdev_get_name(cfm->netdev);
    hmap_init(&cfm->remote_mps);
    cfm->remote_opup = true;
    cfm->fault_override = -1;
    cfm->health = -1;
    cfm->last_tx = 0;
    cfm->flap_count = 0;
    atomic_init(&cfm->extended, false);
    atomic_init(&cfm->check_tnl_key, false);
    atomic_init(&cfm->ref_cnt, 1);

    ovs_mutex_lock(&mutex);
    cfm_generate_maid(cfm);
    hmap_insert(all_cfms, &cfm->hmap_node, hash_string(cfm->name, 0));
    ovs_mutex_unlock(&mutex);
    return cfm;
}

void
cfm_unref(struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    struct remote_mp *rmp, *rmp_next;
    int orig;

    if (!cfm) {
        return;
    }

    atomic_sub(&cfm->ref_cnt, 1, &orig);
    ovs_assert(orig > 0);
    if (orig != 1) {
        return;
    }

    ovs_mutex_lock(&mutex);
    hmap_remove(all_cfms, &cfm->hmap_node);
    ovs_mutex_unlock(&mutex);

    HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {
        hmap_remove(&cfm->remote_mps, &rmp->node);
        free(rmp);
    }

    hmap_destroy(&cfm->remote_mps);
    netdev_close(cfm->netdev);
    free(cfm->rmps_array);
    free(cfm);
}

struct cfm *
cfm_ref(const struct cfm *cfm_)
{
    struct cfm *cfm = CONST_CAST(struct cfm *, cfm_);
    if (cfm) {
        int orig;
        atomic_add(&cfm->ref_cnt, 1, &orig);
        ovs_assert(orig > 0);
    }
    return cfm;
}

/* Should be run periodically to update fault statistics messages. */
void
cfm_run(struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    if (timer_expired(&cfm->fault_timer)) {
        long long int interval = cfm_fault_interval(cfm);
        struct remote_mp *rmp, *rmp_next;
        enum cfm_fault_reason old_cfm_fault = cfm->fault;
        uint64_t old_flap_count = cfm->flap_count;
        int old_health = cfm->health;
        size_t old_rmps_array_len = cfm->rmps_array_len;
        bool old_rmps_deleted = false;
        bool old_rmp_opup = cfm->remote_opup;
        bool demand_override;
        bool rmp_set_opup = false;
        bool rmp_set_opdown = false;

        cfm->fault = cfm->recv_fault;
        cfm->recv_fault = 0;

        cfm->rmps_array_len = 0;
        free(cfm->rmps_array);
        cfm->rmps_array = xmalloc(hmap_count(&cfm->remote_mps) *
                                  sizeof *cfm->rmps_array);

        if (cfm->health_interval == CFM_HEALTH_INTERVAL) {
            /* Calculate the cfm health of the interface.  If the number of
             * remote_mpids of a cfm interface is > 1, the cfm health is
             * undefined. If the number of remote_mpids is 1, the cfm health is
             * the percentage of the ccm frames received in the
             * (CFM_HEALTH_INTERVAL * 3.5)ms, else it is 0. */
            if (hmap_count(&cfm->remote_mps) > 1) {
                cfm->health = -1;
            } else if (hmap_is_empty(&cfm->remote_mps)) {
                cfm->health = 0;
            } else {
                int exp_ccm_recvd;

                rmp = CONTAINER_OF(hmap_first(&cfm->remote_mps),
                                   struct remote_mp, node);
                exp_ccm_recvd = (CFM_HEALTH_INTERVAL * 7) / 2;
                /* Calculate the percentage of healthy ccm frames received.
                 * Since the 'fault_interval' is (3.5 * cfm_interval), and
                 * 1 CCM packet must be received every cfm_interval,
                 * the 'remote_mpid' health reports the percentage of
                 * healthy CCM frames received every
                 * 'CFM_HEALTH_INTERVAL'th 'fault_interval'. */
                cfm->health = (rmp->num_health_ccm * 100) / exp_ccm_recvd;
                cfm->health = MIN(cfm->health, 100);
                rmp->num_health_ccm = 0;
                ovs_assert(cfm->health >= 0 && cfm->health <= 100);
            }
            cfm->health_interval = 0;
        }
        cfm->health_interval++;

        demand_override = false;
        if (cfm->demand) {
            uint64_t rx_packets = cfm_rx_packets(cfm);
            demand_override = hmap_count(&cfm->remote_mps) == 1
                && rx_packets > cfm->rx_packets;
            cfm->rx_packets = rx_packets;
        }

        HMAP_FOR_EACH_SAFE (rmp, rmp_next, node, &cfm->remote_mps) {
            if (!rmp->recv) {
                VLOG_INFO("%s: Received no CCM from RMP %"PRIu64" in the last"
                          " %lldms", cfm->name, rmp->mpid,
                          time_msec() - rmp->last_rx);
                if (!demand_override) {
                    old_rmps_deleted = true;
                    hmap_remove(&cfm->remote_mps, &rmp->node);
                    free(rmp);
                }
            } else {
                rmp->recv = false;

                if (rmp->opup) {
                    rmp_set_opup = true;
                } else {
                    rmp_set_opdown = true;
                }

                cfm->rmps_array[cfm->rmps_array_len++] = rmp->mpid;
            }
        }

        if (rmp_set_opdown) {
            cfm->remote_opup = false;
        }
        else if (rmp_set_opup) {
            cfm->remote_opup = true;
        }

        if (hmap_is_empty(&cfm->remote_mps)) {
            cfm->fault |= CFM_FAULT_RECV;
        }

        if (old_cfm_fault != cfm->fault) {
            if (!VLOG_DROP_INFO(&rl)) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ds_put_cstr(&ds, "from [");
                ds_put_cfm_fault(&ds, old_cfm_fault);
                ds_put_cstr(&ds, "] to [");
                ds_put_cfm_fault(&ds, cfm->fault);
                ds_put_char(&ds, ']');
                VLOG_INFO("%s: CFM faults changed %s.", cfm->name, ds_cstr(&ds));
                ds_destroy(&ds);
            }

            /* If there is a flap, increments the counter. */
            if (old_cfm_fault == 0 || cfm->fault == 0) {
                cfm->flap_count++;
            }
        }

        /* These variables represent the cfm session status, it is desirable
         * to update them to database immediately after change. */
        if (old_health != cfm->health
            || old_rmp_opup != cfm->remote_opup
            || (old_rmps_array_len != cfm->rmps_array_len || old_rmps_deleted)
            || old_cfm_fault != cfm->fault
            || old_flap_count != cfm->flap_count) {
            seq_change(connectivity_seq_get());
        }

        cfm->booted = true;
        timer_set_duration(&cfm->fault_timer, interval);
        VLOG_DBG("%s: new fault interval", cfm->name);
    }
    ovs_mutex_unlock(&mutex);
}

/* Should be run periodically to check if the CFM module has a CCM message it
 * wishes to send. */
bool
cfm_should_send_ccm(struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = timer_expired(&cfm->tx_timer);
    ovs_mutex_unlock(&mutex);
    return ret;
}

/* Composes a CCM message into 'packet'.  Messages generated with this function
 * should be sent whenever cfm_should_send_ccm() indicates. */
void
cfm_compose_ccm(struct cfm *cfm, struct ofpbuf *packet,
                uint8_t eth_src[ETH_ADDR_LEN]) OVS_EXCLUDED(mutex)
{
    uint16_t ccm_vlan;
    struct ccm *ccm;
    bool extended;

    ovs_mutex_lock(&mutex);
    timer_set_duration(&cfm->tx_timer, cfm->ccm_interval_ms);
    eth_compose(packet, cfm_ccm_addr(cfm), eth_src, ETH_TYPE_CFM, sizeof *ccm);

    ccm_vlan = (cfm->ccm_vlan != CFM_RANDOM_VLAN
                ? cfm->ccm_vlan
                : random_uint16());
    ccm_vlan = ccm_vlan & VLAN_VID_MASK;

    if (ccm_vlan || cfm->ccm_pcp) {
        uint16_t tci = ccm_vlan | (cfm->ccm_pcp << VLAN_PCP_SHIFT);
        eth_push_vlan(packet, htons(tci));
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

    atomic_read(&cfm->extended, &extended);
    if (extended) {
        ccm->mpid = htons(hash_mpid(cfm->mpid));
        ccm->mpid64 = htonll(cfm->mpid);
        ccm->opdown = !cfm->opup;
    } else {
        ccm->mpid = htons(cfm->mpid);
        ccm->mpid64 = htonll(0);
        ccm->opdown = 0;
    }

    if (cfm->ccm_interval == 0) {
        ovs_assert(extended);
        ccm->interval_ms_x = htons(cfm->ccm_interval_ms);
    } else {
        ccm->interval_ms_x = htons(0);
    }

    if (cfm->booted && hmap_is_empty(&cfm->remote_mps)) {
        ccm->flags |= CCM_RDI_MASK;
    }

    if (cfm->last_tx) {
        long long int delay = time_msec() - cfm->last_tx;
        if (delay > (cfm->ccm_interval_ms * 3 / 2)) {
            VLOG_WARN("%s: long delay of %lldms (expected %dms) sending CCM"
                      " seq %"PRIu32, cfm->name, delay, cfm->ccm_interval_ms,
                      cfm->seq);
        }
    }
    cfm->last_tx = time_msec();
    ovs_mutex_unlock(&mutex);
}

void
cfm_wait(struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    poll_timer_wait_until(cfm_wake_time(cfm));
}


/* Returns the next cfm wakeup time. */
long long int
cfm_wake_time(struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    long long int retval;

    if (!cfm) {
        return LLONG_MAX;
    }

    ovs_mutex_lock(&mutex);
    retval = MIN(cfm->tx_timer.t, cfm->fault_timer.t);
    ovs_mutex_unlock(&mutex);
    return retval;
}


/* Configures 'cfm' with settings from 's'. */
bool
cfm_configure(struct cfm *cfm, const struct cfm_settings *s)
    OVS_EXCLUDED(mutex)
{
    uint8_t interval;
    int interval_ms;

    if (!cfm_is_valid_mpid(s->extended, s->mpid) || s->interval <= 0) {
        return false;
    }

    ovs_mutex_lock(&mutex);
    cfm->mpid = s->mpid;
    cfm->opup = s->opup;
    interval = ms_to_ccm_interval(s->interval);
    interval_ms = ccm_interval_to_ms(interval);

    atomic_store(&cfm->check_tnl_key, s->check_tnl_key);
    atomic_store(&cfm->extended, s->extended);

    cfm->ccm_vlan = s->ccm_vlan;
    cfm->ccm_pcp = s->ccm_pcp & (VLAN_PCP_MASK >> VLAN_PCP_SHIFT);
    if (s->extended && interval_ms != s->interval) {
        interval = 0;
        interval_ms = MIN(s->interval, UINT16_MAX);
    }

    if (s->extended && s->demand) {
        if (!cfm->demand) {
            cfm->demand = true;
            cfm->rx_packets = cfm_rx_packets(cfm);
        }
    } else {
        cfm->demand = false;
    }

    if (interval != cfm->ccm_interval || interval_ms != cfm->ccm_interval_ms) {
        cfm->ccm_interval = interval;
        cfm->ccm_interval_ms = interval_ms;

        timer_set_expired(&cfm->tx_timer);
        timer_set_duration(&cfm->fault_timer, cfm_fault_interval(cfm));
    }

    ovs_mutex_unlock(&mutex);
    return true;
}

/* Must be called when the netdev owned by 'cfm' should change. */
void
cfm_set_netdev(struct cfm *cfm, const struct netdev *netdev)
    OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    if (cfm->netdev != netdev) {
        netdev_close(cfm->netdev);
        cfm->netdev = netdev_ref(netdev);
    }
    ovs_mutex_unlock(&mutex);
}

/* Returns true if 'cfm' should process packets from 'flow'.  Sets
 * fields in 'wc' that were used to make the determination. */
bool
cfm_should_process_flow(const struct cfm *cfm_, const struct flow *flow,
                        struct flow_wildcards *wc)
{
    struct cfm *cfm = CONST_CAST(struct cfm *, cfm_);
    bool check_tnl_key;

    atomic_read(&cfm->check_tnl_key, &check_tnl_key);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    if (check_tnl_key) {
        memset(&wc->masks.tunnel.tun_id, 0xff, sizeof wc->masks.tunnel.tun_id);
    }
    return (ntohs(flow->dl_type) == ETH_TYPE_CFM
            && eth_addr_equals(flow->dl_dst, cfm_ccm_addr(cfm))
            && (!check_tnl_key || flow->tunnel.tun_id == htonll(0)));
}

/* Updates internal statistics relevant to packet 'p'.  Should be called on
 * every packet whose flow returned true when passed to
 * cfm_should_process_flow. */
void
cfm_process_heartbeat(struct cfm *cfm, const struct ofpbuf *p)
    OVS_EXCLUDED(mutex)
{
    struct ccm *ccm;
    struct eth_header *eth;

    ovs_mutex_lock(&mutex);

    eth = p->l2;
    ccm = ofpbuf_at(p, (uint8_t *)p->l3 - (uint8_t *)p->data, CCM_ACCEPT_LEN);

    if (!ccm) {
        VLOG_INFO_RL(&rl, "%s: Received an unparseable 802.1ag CCM heartbeat.",
                     cfm->name);
        goto out;
    }

    if (ccm->opcode != CCM_OPCODE) {
        VLOG_INFO_RL(&rl, "%s: Received an unsupported 802.1ag message. "
                     "(opcode %u)", cfm->name, ccm->opcode);
        goto out;
    }

    /* According to the 802.1ag specification, reception of a CCM with an
     * incorrect ccm_interval, unexpected MAID, or unexpected MPID should
     * trigger a fault.  We ignore this requirement for several reasons.
     *
     * Faults can cause a controller or Open vSwitch to make potentially
     * expensive changes to the network topology.  It seems prudent to trigger
     * them judiciously, especially when CFM is used to check slave status of
     * bonds. Furthermore, faults can be maliciously triggered by crafting
     * unexpected CCMs. */
    if (memcmp(ccm->maid, cfm->maid, sizeof ccm->maid)) {
        cfm->recv_fault |= CFM_FAULT_MAID;
        VLOG_WARN_RL(&rl, "%s: Received unexpected remote MAID from MAC "
                     ETH_ADDR_FMT, cfm->name, ETH_ADDR_ARGS(eth->eth_src));
    } else {
        uint8_t ccm_interval = ccm->flags & 0x7;
        bool ccm_rdi = ccm->flags & CCM_RDI_MASK;
        uint16_t ccm_interval_ms_x = ntohs(ccm->interval_ms_x);

        struct remote_mp *rmp;
        uint64_t ccm_mpid;
        uint32_t ccm_seq;
        bool ccm_opdown;
        bool extended;
        enum cfm_fault_reason cfm_fault = 0;

        atomic_read(&cfm->extended, &extended);
        if (extended) {
            ccm_mpid = ntohll(ccm->mpid64);
            ccm_opdown = ccm->opdown;
        } else {
            ccm_mpid = ntohs(ccm->mpid);
            ccm_opdown = false;
        }
        ccm_seq = ntohl(ccm->seq);

        if (ccm_interval != cfm->ccm_interval) {
            VLOG_WARN_RL(&rl, "%s: received a CCM with an unexpected interval"
                         " (%"PRIu8") from RMP %"PRIu64, cfm->name,
                         ccm_interval, ccm_mpid);
        }

        if (extended && ccm_interval == 0
            && ccm_interval_ms_x != cfm->ccm_interval_ms) {
            VLOG_WARN_RL(&rl, "%s: received a CCM with an unexpected extended"
                         " interval (%"PRIu16"ms) from RMP %"PRIu64, cfm->name,
                         ccm_interval_ms_x, ccm_mpid);
        }

        rmp = lookup_remote_mp(cfm, ccm_mpid);
        if (!rmp) {
            if (hmap_count(&cfm->remote_mps) < CFM_MAX_RMPS) {
                rmp = xzalloc(sizeof *rmp);
                hmap_insert(&cfm->remote_mps, &rmp->node, hash_mpid(ccm_mpid));
            } else {
                cfm_fault |= CFM_FAULT_OVERFLOW;
                VLOG_WARN_RL(&rl,
                             "%s: dropped CCM with MPID %"PRIu64" from MAC "
                             ETH_ADDR_FMT, cfm->name, ccm_mpid,
                             ETH_ADDR_ARGS(eth->eth_src));
            }
        }

        if (ccm_rdi) {
            cfm_fault |= CFM_FAULT_RDI;
            VLOG_DBG("%s: RDI bit flagged from RMP %"PRIu64, cfm->name,
                     ccm_mpid);
        }

        VLOG_DBG("%s: received CCM (seq %"PRIu32") (mpid %"PRIu64")"
                 " (interval %"PRIu8") (RDI %s)", cfm->name, ccm_seq,
                 ccm_mpid, ccm_interval, ccm_rdi ? "true" : "false");

        if (rmp) {
            if (rmp->mpid == cfm->mpid) {
                cfm_fault |= CFM_FAULT_LOOPBACK;
                VLOG_WARN_RL(&rl,"%s: received CCM with local MPID"
                             " %"PRIu64, cfm->name, rmp->mpid);
            }

            if (rmp->seq && ccm_seq != (rmp->seq + 1)) {
                VLOG_WARN_RL(&rl, "%s: (mpid %"PRIu64") detected sequence"
                             " numbers which indicate possible connectivity"
                             " problems (previous %"PRIu32") (current %"PRIu32
                             ")", cfm->name, ccm_mpid, rmp->seq, ccm_seq);
            }

            rmp->mpid = ccm_mpid;
            if (!cfm_fault) {
                rmp->num_health_ccm++;
            }
            rmp->recv = true;
            cfm->recv_fault |= cfm_fault;
            rmp->seq = ccm_seq;
            rmp->opup = !ccm_opdown;
            rmp->last_rx = time_msec();
        }
    }

out:
    ovs_mutex_unlock(&mutex);
}

static int
cfm_get_fault__(const struct cfm *cfm) OVS_REQUIRES(mutex)
{
    if (cfm->fault_override >= 0) {
        return cfm->fault_override ? CFM_FAULT_OVERRIDE : 0;
    }
    return cfm->fault;
}

/* Gets the fault status of 'cfm'.  Returns a bit mask of 'cfm_fault_reason's
 * indicating the cause of the connectivity fault, or zero if there is no
 * fault. */
int
cfm_get_fault(const struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    int fault;

    ovs_mutex_lock(&mutex);
    fault = cfm_get_fault__(cfm);
    ovs_mutex_unlock(&mutex);
    return fault;
}

/* Gets the number of cfm fault flapping since start. */
uint64_t
cfm_get_flap_count(const struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    uint64_t flap_count;
    ovs_mutex_lock(&mutex);
    flap_count = cfm->flap_count;
    ovs_mutex_unlock(&mutex);
    return flap_count;
}

/* Gets the health of 'cfm'.  Returns an integer between 0 and 100 indicating
 * the health of the link as a percentage of ccm frames received in
 * CFM_HEALTH_INTERVAL * 'fault_interval' if there is only 1 remote_mpid,
 * returns 0 if there are no remote_mpids, and returns -1 if there are more
 * than 1 remote_mpids. */
int
cfm_get_health(const struct cfm *cfm) OVS_EXCLUDED(mutex)
{
    int health;

    ovs_mutex_lock(&mutex);
    health = cfm->health;
    ovs_mutex_unlock(&mutex);
    return health;
}

/* Gets the operational state of 'cfm'.  'cfm' is considered operationally down
 * if it has received a CCM with the operationally down bit set from any of its
 * remote maintenance points. Returns 1 if 'cfm' is operationally up, 0 if
 * 'cfm' is operationally down, or -1 if 'cfm' has no operational state
 * (because it isn't in extended mode). */
int
cfm_get_opup(const struct cfm *cfm_) OVS_EXCLUDED(mutex)
{
    struct cfm *cfm = CONST_CAST(struct cfm *, cfm_);
    bool extended;
    int opup;

    ovs_mutex_lock(&mutex);
    atomic_read(&cfm->extended, &extended);
    opup = extended ? cfm->remote_opup : -1;
    ovs_mutex_unlock(&mutex);

    return opup;
}

/* Populates 'rmps' with an array of remote maintenance points reachable by
 * 'cfm'. The number of remote maintenance points is written to 'n_rmps'.
 * 'cfm' retains ownership of the array written to 'rmps' */
void
cfm_get_remote_mpids(const struct cfm *cfm, uint64_t **rmps, size_t *n_rmps)
    OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    *rmps = xmemdup(cfm->rmps_array, cfm->rmps_array_len * sizeof **rmps);
    *n_rmps = cfm->rmps_array_len;
    ovs_mutex_unlock(&mutex);
}

static struct cfm *
cfm_find(const char *name) OVS_REQUIRES(mutex)
{
    struct cfm *cfm;

    HMAP_FOR_EACH_WITH_HASH (cfm, hmap_node, hash_string(name, 0), all_cfms) {
        if (!strcmp(cfm->name, name)) {
            return cfm;
        }
    }
    return NULL;
}

static void
cfm_print_details(struct ds *ds, struct cfm *cfm) OVS_REQUIRES(mutex)
{
    struct remote_mp *rmp;
    bool extended;
    int fault;

    atomic_read(&cfm->extended, &extended);

    ds_put_format(ds, "---- %s ----\n", cfm->name);
    ds_put_format(ds, "MPID %"PRIu64":%s%s\n", cfm->mpid,
                  extended ? " extended" : "",
                  cfm->fault_override >= 0 ? " fault_override" : "");

    fault = cfm_get_fault__(cfm);
    if (fault) {
        ds_put_cstr(ds, "\tfault: ");
        ds_put_cfm_fault(ds, fault);
        ds_put_cstr(ds, "\n");
    }

    if (cfm->health == -1) {
        ds_put_format(ds, "\taverage health: undefined\n");
    } else {
        ds_put_format(ds, "\taverage health: %d\n", cfm->health);
    }
    ds_put_format(ds, "\topstate: %s\n", cfm->opup ? "up" : "down");
    ds_put_format(ds, "\tremote_opstate: %s\n",
                  cfm->remote_opup ? "up" : "down");
    ds_put_format(ds, "\tinterval: %dms\n", cfm->ccm_interval_ms);
    ds_put_format(ds, "\tnext CCM tx: %lldms\n",
                  timer_msecs_until_expired(&cfm->tx_timer));
    ds_put_format(ds, "\tnext fault check: %lldms\n",
                  timer_msecs_until_expired(&cfm->fault_timer));

    HMAP_FOR_EACH (rmp, node, &cfm->remote_mps) {
        ds_put_format(ds, "Remote MPID %"PRIu64"\n", rmp->mpid);
        ds_put_format(ds, "\trecv since check: %s\n",
                      rmp->recv ? "true" : "false");
        ds_put_format(ds, "\topstate: %s\n", rmp->opup? "up" : "down");
    }
}

static void
cfm_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct cfm *cfm;

    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        cfm = cfm_find(argv[1]);
        if (!cfm) {
            unixctl_command_reply_error(conn, "no such CFM object");
            goto out;
        }
        cfm_print_details(&ds, cfm);
    } else {
        HMAP_FOR_EACH (cfm, hmap_node, all_cfms) {
            cfm_print_details(&ds, cfm);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
out:
    ovs_mutex_unlock(&mutex);
}

static void
cfm_unixctl_set_fault(struct unixctl_conn *conn, int argc, const char *argv[],
                      void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    const char *fault_str = argv[argc - 1];
    int fault_override;
    struct cfm *cfm;

    ovs_mutex_lock(&mutex);
    if (!strcasecmp("true", fault_str)) {
        fault_override = 1;
    } else if (!strcasecmp("false", fault_str)) {
        fault_override = 0;
    } else if (!strcasecmp("normal", fault_str)) {
        fault_override = -1;
    } else {
        unixctl_command_reply_error(conn, "unknown fault string");
        goto out;
    }

    if (argc > 2) {
        cfm = cfm_find(argv[1]);
        if (!cfm) {
            unixctl_command_reply_error(conn, "no such CFM object");
            goto out;
        }
        cfm->fault_override = fault_override;
    } else {
        HMAP_FOR_EACH (cfm, hmap_node, all_cfms) {
            cfm->fault_override = fault_override;
        }
    }

    seq_change(connectivity_seq_get());
    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&mutex);
}
