/* Copyright (c) 2013, 2014 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>
#include "bfd.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "byte-order.h"
#include "connectivity.h"
#include "csum.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "ovs-thread.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(bfd);

/* XXX Finish BFD.
 *
 * The goal of this module is to replace CFM with something both more flexible
 * and standards compliant.  In service of this goal, the following needs to be
 * done.
 *
 * - Compliance
 *   * Implement Demand mode.
 *   * Go through the RFC line by line and verify we comply.
 *   * Test against a hardware implementation.  Preferably a popular one.
 *   * Delete BFD packets with nw_ttl != 255 in the datapath to prevent DOS
 *     attacks.
 *
 * - Unit tests.
 *
 * - Set TOS/PCP on the outer tunnel header when encapped.
 *
 * - Sending BFD messages should be in its own thread/process.
 *
 * - Scale testing.  How does it operate when there are large number of bfd
 *   sessions?  Do we ever have random flaps?  What's the CPU utilization?
 *
 * - Rely on data traffic for liveness by using BFD demand mode.
 *   If we're receiving traffic on a port, we can safely assume it's up (modulo
 *   unidrectional failures).  BFD has a demand mode in which it can stay quiet
 *   unless it feels the need to check the status of the port.  Using this, we
 *   can implement a strategy in which BFD only sends control messages on dark
 *   interfaces.
 *
 * - Depending on how one interprets the spec, it appears that a BFD session
 *   can never change bfd.LocalDiag to "No Diagnostic".  We should verify that
 *   this is what hardware implementations actually do.  Seems like "No
 *   Diagnostic" should be set once a BFD session state goes UP. */

#define BFD_VERSION 1

enum flags {
    FLAG_MULTIPOINT = 1 << 0,
    FLAG_DEMAND = 1 << 1,
    FLAG_AUTH = 1 << 2,
    FLAG_CTL = 1 << 3,
    FLAG_FINAL = 1 << 4,
    FLAG_POLL = 1 << 5
};

enum state {
    STATE_ADMIN_DOWN = 0 << 6,
    STATE_DOWN = 1 << 6,
    STATE_INIT = 2 << 6,
    STATE_UP = 3 << 6
};

enum diag {
    DIAG_NONE = 0,                /* No Diagnostic. */
    DIAG_EXPIRED = 1,             /* Control Detection Time Expired. */
    DIAG_ECHO_FAILED = 2,         /* Echo Function Failed. */
    DIAG_RMT_DOWN = 3,            /* Neighbor Signaled Session Down. */
    DIAG_FWD_RESET = 4,           /* Forwarding Plane Reset. */
    DIAG_PATH_DOWN = 5,           /* Path Down. */
    DIAG_CPATH_DOWN = 6,          /* Concatenated Path Down. */
    DIAG_ADMIN_DOWN = 7,          /* Administratively Down. */
    DIAG_RCPATH_DOWN = 8          /* Reverse Concatenated Path Down. */
};

/* RFC 5880 Section 4.1
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       My Discriminator                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Your Discriminator                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Desired Min TX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Required Min RX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Required Min Echo RX Interval                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
struct msg {
    uint8_t vers_diag;    /* Version and diagnostic. */
    uint8_t flags;        /* 2bit State field followed by flags. */
    uint8_t mult;         /* Fault detection multiplier. */
    uint8_t length;       /* Length of this BFD message. */
    ovs_be32 my_disc;     /* My discriminator. */
    ovs_be32 your_disc;   /* Your discriminator. */
    ovs_be32 min_tx;      /* Desired minimum tx interval. */
    ovs_be32 min_rx;      /* Required minimum rx interval. */
    ovs_be32 min_rx_echo; /* Required minimum echo rx interval. */
};
BUILD_ASSERT_DECL(BFD_PACKET_LEN == sizeof(struct msg));

#define DIAG_MASK 0x1f
#define VERS_SHIFT 5
#define STATE_MASK 0xC0
#define FLAGS_MASK 0x3f

struct bfd {
    struct hmap_node node;        /* In 'all_bfds'. */
    uint32_t disc;                /* bfd.LocalDiscr. Key in 'all_bfds' hmap. */

    char *name;                   /* Name used for logging. */

    bool cpath_down;              /* Concatenated Path Down. */
    uint8_t mult;                 /* bfd.DetectMult. */

    struct netdev *netdev;
    uint64_t rx_packets;          /* Packets received by 'netdev'. */

    enum state state;             /* bfd.SessionState. */
    enum state rmt_state;         /* bfd.RemoteSessionState. */

    enum diag diag;               /* bfd.LocalDiag. */
    enum diag rmt_diag;           /* Remote diagnostic. */

    enum flags flags;             /* Flags sent on messages. */
    enum flags rmt_flags;         /* Flags last received. */

    uint32_t rmt_disc;            /* bfd.RemoteDiscr. */

    uint8_t local_eth_src[ETH_ADDR_LEN]; /* Local eth src address. */
    uint8_t local_eth_dst[ETH_ADDR_LEN]; /* Local eth dst address. */

    uint8_t rmt_eth_dst[ETH_ADDR_LEN];   /* Remote eth dst address. */

    ovs_be32 ip_src;              /* IPv4 source address. */
    ovs_be32 ip_dst;              /* IPv4 destination address. */

    uint16_t udp_src;             /* UDP source port. */

    /* All timers in milliseconds. */
    long long int rmt_min_rx;     /* bfd.RemoteMinRxInterval. */
    long long int rmt_min_tx;     /* Remote minimum TX interval. */

    long long int cfg_min_tx;     /* Configured minimum TX rate. */
    long long int cfg_min_rx;     /* Configured required minimum RX rate. */
    long long int poll_min_tx;    /* Min TX negotating in a poll sequence. */
    long long int poll_min_rx;    /* Min RX negotating in a poll sequence. */
    long long int min_tx;         /* bfd.DesiredMinTxInterval. */
    long long int min_rx;         /* bfd.RequiredMinRxInterval. */

    long long int last_tx;        /* Last TX time. */
    long long int next_tx;        /* Next TX time. */
    long long int detect_time;    /* RFC 5880 6.8.4 Detection time. */

    bool last_forwarding;         /* Last calculation of forwarding flag. */
    int forwarding_override;      /* Manual override of 'forwarding' status. */

    atomic_bool check_tnl_key;    /* Verify tunnel key of inbound packets? */
    struct ovs_refcount ref_cnt;

    /* When forward_if_rx is true, bfd_forwarding() will return
     * true as long as there are incoming packets received.
     * Note, forwarding_override still has higher priority. */
    bool forwarding_if_rx;
    long long int forwarding_if_rx_detect_time;

    /* When 'bfd->forwarding_if_rx' is set, at least one bfd control packet
     * is required to be received every 100 * bfd->cfg_min_rx.  If bfd
     * control packet is not received within this interval, even if data
     * packets are received, the bfd->forwarding will still be false. */
    long long int demand_rx_bfd_time;

    /* BFD decay related variables. */
    bool in_decay;                /* True when bfd is in decay. */
    int decay_min_rx;             /* min_rx is set to decay_min_rx when */
                                  /* in decay. */
    int decay_rx_ctl;             /* Count bfd packets received within decay */
                                  /* detect interval. */
    uint64_t decay_rx_packets;    /* Packets received by 'netdev'. */
    long long int decay_detect_time; /* Decay detection time. */

    uint64_t flap_count;          /* Counts bfd forwarding flaps. */

    /* True when the variables returned by bfd_get_status() are changed
     * since last check. */
    bool status_changed;
};

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct hmap all_bfds__ = HMAP_INITIALIZER(&all_bfds__);
static struct hmap *const all_bfds OVS_GUARDED_BY(mutex) = &all_bfds__;

static bool bfd_lookup_ip(const char *host_name, struct in_addr *)
    OVS_REQUIRES(mutex);
static bool bfd_forwarding__(struct bfd *) OVS_REQUIRES(mutex);
static bool bfd_in_poll(const struct bfd *) OVS_REQUIRES(mutex);
static void bfd_poll(struct bfd *bfd) OVS_REQUIRES(mutex);
static const char *bfd_diag_str(enum diag) OVS_REQUIRES(mutex);
static const char *bfd_state_str(enum state) OVS_REQUIRES(mutex);
static long long int bfd_min_tx(const struct bfd *) OVS_REQUIRES(mutex);
static long long int bfd_tx_interval(const struct bfd *)
    OVS_REQUIRES(mutex);
static long long int bfd_rx_interval(const struct bfd *)
    OVS_REQUIRES(mutex);
static void bfd_set_next_tx(struct bfd *) OVS_REQUIRES(mutex);
static void bfd_set_state(struct bfd *, enum state, enum diag)
    OVS_REQUIRES(mutex);
static uint32_t generate_discriminator(void) OVS_REQUIRES(mutex);
static void bfd_put_details(struct ds *, const struct bfd *)
    OVS_REQUIRES(mutex);
static uint64_t bfd_rx_packets(const struct bfd *) OVS_REQUIRES(mutex);
static void bfd_try_decay(struct bfd *) OVS_REQUIRES(mutex);
static void bfd_decay_update(struct bfd *) OVS_REQUIRES(mutex);
static void bfd_status_changed(struct bfd *) OVS_REQUIRES(mutex);

static void bfd_forwarding_if_rx_update(struct bfd *) OVS_REQUIRES(mutex);
static void bfd_unixctl_show(struct unixctl_conn *, int argc,
                             const char *argv[], void *aux OVS_UNUSED);
static void bfd_unixctl_set_forwarding_override(struct unixctl_conn *,
                                                int argc, const char *argv[],
                                                void *aux OVS_UNUSED);
static void log_msg(enum vlog_level, const struct msg *, const char *message,
                    const struct bfd *) OVS_REQUIRES(mutex);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 20);

/* Returns true if the interface on which 'bfd' is running may be used to
 * forward traffic according to the BFD session state. */
bool
bfd_forwarding(struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = bfd_forwarding__(bfd);
    ovs_mutex_unlock(&mutex);
    return ret;
}

/* When forwarding_if_rx is enabled, if there are packets received,
 * updates forwarding_if_rx_detect_time. */
void
bfd_account_rx(struct bfd *bfd, const struct dpif_flow_stats *stats)
{
    if (stats->n_packets && bfd->forwarding_if_rx) {
        ovs_mutex_lock(&mutex);
        bfd_forwarding__(bfd);
        bfd_forwarding_if_rx_update(bfd);
        bfd_forwarding__(bfd);
        ovs_mutex_unlock(&mutex);
    }
}

/* Returns and resets the 'bfd->status_changed'. */
bool
bfd_check_status_change(struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    bool ret;

    ovs_mutex_lock(&mutex);
    ret = bfd->status_changed;
    bfd->status_changed = false;
    ovs_mutex_unlock(&mutex);

    return ret;
}

/* Returns a 'smap' of key value pairs representing the status of 'bfd'
 * intended for the OVS database. */
void
bfd_get_status(const struct bfd *bfd, struct smap *smap)
    OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    smap_add(smap, "forwarding",
             bfd_forwarding__(CONST_CAST(struct bfd *, bfd))
             ? "true" : "false");
    smap_add(smap, "state", bfd_state_str(bfd->state));
    smap_add(smap, "diagnostic", bfd_diag_str(bfd->diag));
    smap_add_format(smap, "flap_count", "%"PRIu64, bfd->flap_count);

    if (bfd->state != STATE_DOWN) {
        smap_add(smap, "remote_state", bfd_state_str(bfd->rmt_state));
        smap_add(smap, "remote_diagnostic", bfd_diag_str(bfd->rmt_diag));
    }
    ovs_mutex_unlock(&mutex);
}

/* Initializes, destroys, or reconfigures the BFD session 'bfd' (named 'name'),
 * according to the database configuration contained in 'cfg'.  Takes ownership
 * of 'bfd', which may be NULL.  Returns a BFD object which may be used as a
 * handle for the session, or NULL if BFD is not enabled according to 'cfg'.
 * Also returns NULL if cfg is NULL. */
struct bfd *
bfd_configure(struct bfd *bfd, const char *name, const struct smap *cfg,
              struct netdev *netdev) OVS_EXCLUDED(mutex)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static atomic_uint16_t udp_src = ATOMIC_VAR_INIT(0);

    int decay_min_rx;
    long long int min_tx, min_rx;
    bool need_poll = false;
    bool cfg_min_rx_changed = false;
    bool cpath_down, forwarding_if_rx;
    const char *hwaddr, *ip_src, *ip_dst;
    struct in_addr in_addr;
    uint8_t ea[ETH_ADDR_LEN];

    if (ovsthread_once_start(&once)) {
        unixctl_command_register("bfd/show", "[interface]", 0, 1,
                                 bfd_unixctl_show, NULL);
        unixctl_command_register("bfd/set-forwarding",
                                 "[interface] normal|false|true", 1, 2,
                                 bfd_unixctl_set_forwarding_override, NULL);
        ovsthread_once_done(&once);
    }

    if (!cfg || !smap_get_bool(cfg, "enable", false)) {
        bfd_unref(bfd);
        return NULL;
    }

    ovs_mutex_lock(&mutex);
    if (!bfd) {
        bfd = xzalloc(sizeof *bfd);
        bfd->name = xstrdup(name);
        bfd->forwarding_override = -1;
        bfd->disc = generate_discriminator();
        hmap_insert(all_bfds, &bfd->node, bfd->disc);

        bfd->diag = DIAG_NONE;
        bfd->min_tx = 1000;
        bfd->mult = 3;
        ovs_refcount_init(&bfd->ref_cnt);
        bfd->netdev = netdev_ref(netdev);
        bfd->rx_packets = bfd_rx_packets(bfd);
        bfd->in_decay = false;
        bfd->flap_count = 0;

        /* RFC 5881 section 4
         * The source port MUST be in the range 49152 through 65535.  The same
         * UDP source port number MUST be used for all BFD Control packets
         * associated with a particular session.  The source port number SHOULD
         * be unique among all BFD sessions on the system. */
        atomic_add(&udp_src, 1, &bfd->udp_src);
        bfd->udp_src = (bfd->udp_src % 16384) + 49152;

        bfd_set_state(bfd, STATE_DOWN, DIAG_NONE);

        bfd_status_changed(bfd);
    }

    atomic_store(&bfd->check_tnl_key,
                 smap_get_bool(cfg, "check_tnl_key", false));
    min_tx = smap_get_int(cfg, "min_tx", 100);
    min_tx = MAX(min_tx, 100);
    if (bfd->cfg_min_tx != min_tx) {
        bfd->cfg_min_tx = min_tx;
        if (bfd->state != STATE_UP
            || (!bfd_in_poll(bfd) && bfd->cfg_min_tx < bfd->min_tx)) {
            bfd->min_tx = bfd->cfg_min_tx;
        }
        need_poll = true;
    }

    min_rx = smap_get_int(cfg, "min_rx", 1000);
    min_rx = MAX(min_rx, 100);
    if (bfd->cfg_min_rx != min_rx) {
        bfd->cfg_min_rx = min_rx;
        if (bfd->state != STATE_UP
            || (!bfd_in_poll(bfd) && bfd->cfg_min_rx > bfd->min_rx)) {
            bfd->min_rx = bfd->cfg_min_rx;
        }
        cfg_min_rx_changed = true;
        need_poll = true;
    }

    decay_min_rx = smap_get_int(cfg, "decay_min_rx", 0);
    if (bfd->decay_min_rx != decay_min_rx || cfg_min_rx_changed) {
        if (decay_min_rx > 0 && decay_min_rx < bfd->cfg_min_rx) {
            VLOG_WARN("%s: decay_min_rx cannot be less than %lld ms",
                      bfd->name, bfd->cfg_min_rx);
            bfd->decay_min_rx = 0;
        } else {
            bfd->decay_min_rx = decay_min_rx;
        }
        /* Resets decay. */
        bfd->in_decay = false;
        bfd_decay_update(bfd);
        need_poll = true;
    }

    cpath_down = smap_get_bool(cfg, "cpath_down", false);
    if (bfd->cpath_down != cpath_down) {
        bfd->cpath_down = cpath_down;
        bfd_set_state(bfd, bfd->state, DIAG_NONE);
        need_poll = true;
    }

    hwaddr = smap_get(cfg, "bfd_local_src_mac");
    if (hwaddr && eth_addr_from_string(hwaddr, ea)) {
        memcpy(bfd->local_eth_src, ea, ETH_ADDR_LEN);
    } else {
        memset(bfd->local_eth_src, 0, ETH_ADDR_LEN);
    }

    hwaddr = smap_get(cfg, "bfd_local_dst_mac");
    if (hwaddr && eth_addr_from_string(hwaddr, ea)) {
        memcpy(bfd->local_eth_dst, ea, ETH_ADDR_LEN);
    } else {
        memset(bfd->local_eth_dst, 0, ETH_ADDR_LEN);
    }

    hwaddr = smap_get(cfg, "bfd_remote_dst_mac");
    if (hwaddr && eth_addr_from_string(hwaddr, ea)) {
        memcpy(bfd->rmt_eth_dst, ea, ETH_ADDR_LEN);
    } else {
        memset(bfd->rmt_eth_dst, 0, ETH_ADDR_LEN);
    }

    ip_src = smap_get(cfg, "bfd_src_ip");
    if (ip_src && bfd_lookup_ip(ip_src, &in_addr)) {
        memcpy(&bfd->ip_src, &in_addr, sizeof in_addr);
    } else {
        bfd->ip_src = htonl(0xA9FE0101); /* 169.254.1.1. */
    }

    ip_dst = smap_get(cfg, "bfd_dst_ip");
    if (ip_dst && bfd_lookup_ip(ip_dst, &in_addr)) {
        memcpy(&bfd->ip_dst, &in_addr, sizeof in_addr);
    } else {
        bfd->ip_dst = htonl(0xA9FE0100); /* 169.254.1.0. */
    }

    forwarding_if_rx = smap_get_bool(cfg, "forwarding_if_rx", false);
    if (bfd->forwarding_if_rx != forwarding_if_rx) {
        bfd->forwarding_if_rx = forwarding_if_rx;
        if (bfd->state == STATE_UP && bfd->forwarding_if_rx) {
            bfd_forwarding_if_rx_update(bfd);
        } else {
            bfd->forwarding_if_rx_detect_time = 0;
        }
    }

    if (need_poll) {
        bfd_poll(bfd);
    }
    ovs_mutex_unlock(&mutex);
    return bfd;
}

struct bfd *
bfd_ref(const struct bfd *bfd_)
{
    struct bfd *bfd = CONST_CAST(struct bfd *, bfd_);
    if (bfd) {
        ovs_refcount_ref(&bfd->ref_cnt);
    }
    return bfd;
}

void
bfd_unref(struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    if (bfd && ovs_refcount_unref(&bfd->ref_cnt) == 1) {
        ovs_mutex_lock(&mutex);
        bfd_status_changed(bfd);
        hmap_remove(all_bfds, &bfd->node);
        netdev_close(bfd->netdev);
        free(bfd->name);
        free(bfd);
        ovs_mutex_unlock(&mutex);
    }
}

void
bfd_wait(const struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    poll_timer_wait_until(bfd_wake_time(bfd));
}

/* Returns the next wake up time. */
long long int
bfd_wake_time(const struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    long long int retval;

    if (!bfd) {
        return LLONG_MAX;
    }

    ovs_mutex_lock(&mutex);
    if (bfd->flags & FLAG_FINAL) {
        retval = 0;
    } else {
        retval = bfd->next_tx;
        if (bfd->state > STATE_DOWN) {
            retval = MIN(bfd->detect_time, retval);
        }
    }
    ovs_mutex_unlock(&mutex);
    return retval;
}

void
bfd_run(struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    long long int now;
    bool old_in_decay;

    ovs_mutex_lock(&mutex);
    now = time_msec();
    old_in_decay = bfd->in_decay;

    if (bfd->state > STATE_DOWN && now >= bfd->detect_time) {
        bfd_set_state(bfd, STATE_DOWN, DIAG_EXPIRED);
    }
    bfd_forwarding__(bfd);

    /* Decay may only happen when state is STATE_UP, bfd->decay_min_rx is
     * configured, and decay_detect_time is reached. */
    if (bfd->state == STATE_UP && bfd->decay_min_rx > 0
        && now >= bfd->decay_detect_time) {
        bfd_try_decay(bfd);
    }

    if (bfd->min_tx != bfd->cfg_min_tx
        || (bfd->min_rx != bfd->cfg_min_rx && bfd->min_rx != bfd->decay_min_rx)
        || bfd->in_decay != old_in_decay) {
        bfd_poll(bfd);
    }
    ovs_mutex_unlock(&mutex);
}

bool
bfd_should_send_packet(const struct bfd *bfd) OVS_EXCLUDED(mutex)
{
    bool ret;
    ovs_mutex_lock(&mutex);
    ret = bfd->flags & FLAG_FINAL || time_msec() >= bfd->next_tx;
    ovs_mutex_unlock(&mutex);
    return ret;
}

void
bfd_put_packet(struct bfd *bfd, struct ofpbuf *p,
               uint8_t eth_src[ETH_ADDR_LEN]) OVS_EXCLUDED(mutex)
{
    long long int min_tx, min_rx;
    struct udp_header *udp;
    struct eth_header *eth;
    struct ip_header *ip;
    struct msg *msg;

    ovs_mutex_lock(&mutex);
    if (bfd->next_tx) {
        long long int delay = time_msec() - bfd->next_tx;
        long long int interval = bfd_tx_interval(bfd);
        if (delay > interval * 3 / 2) {
            VLOG_INFO("%s: long delay of %lldms (expected %lldms) sending BFD"
                      " control message", bfd->name, delay, interval);
        }
    }

    /* RFC 5880 Section 6.5
     * A BFD Control packet MUST NOT have both the Poll (P) and Final (F) bits
     * set. */
    ovs_assert(!(bfd->flags & FLAG_POLL) || !(bfd->flags & FLAG_FINAL));

    ofpbuf_reserve(p, 2); /* Properly align after the ethernet header. */
    eth = ofpbuf_put_uninit(p, sizeof *eth);
    memcpy(eth->eth_src,
           eth_addr_is_zero(bfd->local_eth_src) ? eth_src
                                                : bfd->local_eth_src,
           ETH_ADDR_LEN);
    memcpy(eth->eth_dst,
           eth_addr_is_zero(bfd->local_eth_dst) ? eth_addr_bfd
                                                : bfd->local_eth_dst,
           ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_IP);

    ip = ofpbuf_put_zeros(p, sizeof *ip);
    ip->ip_ihl_ver = IP_IHL_VER(5, 4);
    ip->ip_tot_len = htons(sizeof *ip + sizeof *udp + sizeof *msg);
    ip->ip_ttl = MAXTTL;
    ip->ip_tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
    ip->ip_proto = IPPROTO_UDP;
    put_16aligned_be32(&ip->ip_src, bfd->ip_src);
    put_16aligned_be32(&ip->ip_dst, bfd->ip_dst);
    ip->ip_csum = csum(ip, sizeof *ip);

    udp = ofpbuf_put_zeros(p, sizeof *udp);
    udp->udp_src = htons(bfd->udp_src);
    udp->udp_dst = htons(BFD_DEST_PORT);
    udp->udp_len = htons(sizeof *udp + sizeof *msg);

    msg = ofpbuf_put_uninit(p, sizeof *msg);
    msg->vers_diag = (BFD_VERSION << 5) | bfd->diag;
    msg->flags = (bfd->state & STATE_MASK) | bfd->flags;

    msg->mult = bfd->mult;
    msg->length = BFD_PACKET_LEN;
    msg->my_disc = htonl(bfd->disc);
    msg->your_disc = htonl(bfd->rmt_disc);
    msg->min_rx_echo = htonl(0);

    if (bfd_in_poll(bfd)) {
        min_tx = bfd->poll_min_tx;
        min_rx = bfd->poll_min_rx;
    } else {
        min_tx = bfd_min_tx(bfd);
        min_rx = bfd->min_rx;
    }

    msg->min_tx = htonl(min_tx * 1000);
    msg->min_rx = htonl(min_rx * 1000);

    bfd->flags &= ~FLAG_FINAL;

    log_msg(VLL_DBG, msg, "Sending BFD Message", bfd);

    bfd->last_tx = time_msec();
    bfd_set_next_tx(bfd);
    ovs_mutex_unlock(&mutex);
}

bool
bfd_should_process_flow(const struct bfd *bfd_, const struct flow *flow,
                        struct flow_wildcards *wc)
{
    struct bfd *bfd = CONST_CAST(struct bfd *, bfd_);
    bool check_tnl_key;

    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    if (!eth_addr_is_zero(bfd->rmt_eth_dst)
        && memcmp(bfd->rmt_eth_dst, flow->dl_dst, ETH_ADDR_LEN)) {
        return false;
    }

    memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);

    atomic_read(&bfd->check_tnl_key, &check_tnl_key);
    if (check_tnl_key) {
        memset(&wc->masks.tunnel.tun_id, 0xff, sizeof wc->masks.tunnel.tun_id);
    }
    return (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_UDP
            && flow->tp_dst == htons(BFD_DEST_PORT)
            && (!check_tnl_key || flow->tunnel.tun_id == htonll(0)));
}

void
bfd_process_packet(struct bfd *bfd, const struct flow *flow,
                   const struct ofpbuf *p) OVS_EXCLUDED(mutex)
{
    uint32_t rmt_min_rx, pkt_your_disc;
    enum state rmt_state;
    enum flags flags;
    uint8_t version;
    struct msg *msg;
    const uint8_t *l7 = ofpbuf_get_udp_payload(p);

    if (!l7) {
        return; /* No UDP payload. */
    }

    /* This function is designed to follow section RFC 5880 6.8.6 closely. */

    ovs_mutex_lock(&mutex);
    /* Increments the decay rx counter. */
    bfd->decay_rx_ctl++;

    bfd_forwarding__(bfd);

    if (flow->nw_ttl != 255) {
        /* XXX Should drop in the kernel to prevent DOS. */
        goto out;
    }

    msg = ofpbuf_at(p, l7 - (uint8_t *)ofpbuf_data(p), BFD_PACKET_LEN);
    if (!msg) {
        VLOG_INFO_RL(&rl, "%s: Received too-short BFD control message (only "
                     "%"PRIdPTR" bytes long, at least %d required).",
                     bfd->name, (uint8_t *) ofpbuf_tail(p) - l7,
                     BFD_PACKET_LEN);
        goto out;
    }

    /* RFC 5880 Section 6.8.6
     * If the Length field is greater than the payload of the encapsulating
     * protocol, the packet MUST be discarded.
     *
     * Note that we make this check implicity.  Above we use ofpbuf_at() to
     * ensure that there are at least BFD_PACKET_LEN bytes in the payload of
     * the encapsulating protocol.  Below we require msg->length to be exactly
     * BFD_PACKET_LEN bytes. */

    flags = msg->flags & FLAGS_MASK;
    rmt_state = msg->flags & STATE_MASK;
    version = msg->vers_diag >> VERS_SHIFT;

    log_msg(VLL_DBG, msg, "Received BFD control message", bfd);

    if (version != BFD_VERSION) {
        log_msg(VLL_WARN, msg, "Incorrect version", bfd);
        goto out;
    }

    /* Technically this should happen after the length check. We don't support
     * authentication however, so it's simpler to do the check first. */
    if (flags & FLAG_AUTH) {
        log_msg(VLL_WARN, msg, "Authenticated control message with"
                   " authentication disabled", bfd);
        goto out;
    }

    if (msg->length != BFD_PACKET_LEN) {
        log_msg(VLL_WARN, msg, "Unexpected length", bfd);
        if (msg->length < BFD_PACKET_LEN) {
            goto out;
        }
    }

    if (!msg->mult) {
        log_msg(VLL_WARN, msg, "Zero multiplier", bfd);
        goto out;
    }

    if (flags & FLAG_MULTIPOINT) {
        log_msg(VLL_WARN, msg, "Unsupported multipoint flag", bfd);
        goto out;
    }

    if (!msg->my_disc) {
        log_msg(VLL_WARN, msg, "NULL my_disc", bfd);
        goto out;
    }

    pkt_your_disc = ntohl(msg->your_disc);
    if (pkt_your_disc) {
        /* Technically, we should use the your discriminator field to figure
         * out which 'struct bfd' this packet is destined towards.  That way a
         * bfd session could migrate from one interface to another
         * transparently.  This doesn't fit in with the OVS structure very
         * well, so in this respect, we are not compliant. */
       if (pkt_your_disc != bfd->disc) {
           log_msg(VLL_WARN, msg, "Incorrect your_disc", bfd);
           goto out;
       }
    } else if (rmt_state > STATE_DOWN) {
        log_msg(VLL_WARN, msg, "Null your_disc", bfd);
        goto out;
    }

    if (bfd->rmt_state != rmt_state) {
        bfd_status_changed(bfd);
    }

    bfd->rmt_disc = ntohl(msg->my_disc);
    bfd->rmt_state = rmt_state;
    bfd->rmt_flags = flags;
    bfd->rmt_diag = msg->vers_diag & DIAG_MASK;

    if (flags & FLAG_FINAL && bfd_in_poll(bfd)) {
        bfd->min_tx = bfd->poll_min_tx;
        bfd->min_rx = bfd->poll_min_rx;
        bfd->flags &= ~FLAG_POLL;
        log_msg(VLL_INFO, msg, "Poll sequence terminated", bfd);
    }

    if (flags & FLAG_POLL) {
        /* RFC 5880 Section 6.5
         * When the other system receives a Poll, it immediately transmits a
         * BFD Control packet with the Final (F) bit set, independent of any
         * periodic BFD Control packets it may be sending
         * (see section 6.8.7). */
        bfd->flags &= ~FLAG_POLL;
        bfd->flags |= FLAG_FINAL;
    }

    rmt_min_rx = MAX(ntohl(msg->min_rx) / 1000, 1);
    if (bfd->rmt_min_rx != rmt_min_rx) {
        bfd->rmt_min_rx = rmt_min_rx;
        if (bfd->next_tx) {
            bfd_set_next_tx(bfd);
        }
        log_msg(VLL_INFO, msg, "New remote min_rx", bfd);
    }

    bfd->rmt_min_tx = MAX(ntohl(msg->min_tx) / 1000, 1);
    bfd->detect_time = bfd_rx_interval(bfd) * bfd->mult + time_msec();

    if (bfd->state == STATE_ADMIN_DOWN) {
        VLOG_DBG_RL(&rl, "Administratively down, dropping control message.");
        goto out;
    }

    if (rmt_state == STATE_ADMIN_DOWN) {
        if (bfd->state != STATE_DOWN) {
            bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN);
        }
    } else {
        switch (bfd->state) {
        case STATE_DOWN:
            if (rmt_state == STATE_DOWN) {
                bfd_set_state(bfd, STATE_INIT, bfd->diag);
            } else if (rmt_state == STATE_INIT) {
                bfd_set_state(bfd, STATE_UP, bfd->diag);
            }
            break;
        case STATE_INIT:
            if (rmt_state > STATE_DOWN) {
                bfd_set_state(bfd, STATE_UP, bfd->diag);
            }
            break;
        case STATE_UP:
            if (rmt_state <= STATE_DOWN) {
                bfd_set_state(bfd, STATE_DOWN, DIAG_RMT_DOWN);
                log_msg(VLL_INFO, msg, "Remote signaled STATE_DOWN", bfd);
            }
            break;
        case STATE_ADMIN_DOWN:
        default:
            OVS_NOT_REACHED();
        }
    }
    /* XXX: RFC 5880 Section 6.8.6 Demand mode related calculations here. */

    if (bfd->forwarding_if_rx) {
        bfd->demand_rx_bfd_time = time_msec() + 100 * bfd->cfg_min_rx;
    }

out:
    bfd_forwarding__(bfd);
    ovs_mutex_unlock(&mutex);
}

/* Must be called when the netdev owned by 'bfd' should change. */
void
bfd_set_netdev(struct bfd *bfd, const struct netdev *netdev)
    OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    if (bfd->netdev != netdev) {
        netdev_close(bfd->netdev);
        bfd->netdev = netdev_ref(netdev);
        if (bfd->decay_min_rx && bfd->state == STATE_UP) {
            bfd_decay_update(bfd);
        }
        if (bfd->forwarding_if_rx && bfd->state == STATE_UP) {
            bfd_forwarding_if_rx_update(bfd);
        }
        bfd->rx_packets = bfd_rx_packets(bfd);
    }
    ovs_mutex_unlock(&mutex);
}


/* Updates the forwarding flag.  If override is not configured and
 * the forwarding flag value changes, increments the flap count.
 *
 * Note this function may be called multiple times in a function
 * (e.g. bfd_account_rx) before and after the bfd state or status
 * change.  This is to capture any forwarding flag flap. */
static bool
bfd_forwarding__(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    long long int now = time_msec();
    bool forwarding_if_rx;
    bool last_forwarding = bfd->last_forwarding;

    if (bfd->forwarding_override != -1) {
        return bfd->forwarding_override == 1;
    }

    forwarding_if_rx = bfd->forwarding_if_rx
                       && bfd->forwarding_if_rx_detect_time > now
                       && bfd->demand_rx_bfd_time > now;

    bfd->last_forwarding = (bfd->state == STATE_UP || forwarding_if_rx)
                           && bfd->rmt_diag != DIAG_PATH_DOWN
                           && bfd->rmt_diag != DIAG_CPATH_DOWN
                           && bfd->rmt_diag != DIAG_RCPATH_DOWN;
    if (bfd->last_forwarding != last_forwarding) {
        bfd->flap_count++;
        bfd_status_changed(bfd);
    }
    return bfd->last_forwarding;
}

/* Helpers. */
static bool
bfd_lookup_ip(const char *host_name, struct in_addr *addr)
{
    if (!inet_pton(AF_INET, host_name, addr)) {
        VLOG_ERR_RL(&rl, "\"%s\" is not a valid IP address", host_name);
        return false;
    }
    return true;
}

static bool
bfd_in_poll(const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    return (bfd->flags & FLAG_POLL) != 0;
}

static void
bfd_poll(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    if (bfd->state > STATE_DOWN && !bfd_in_poll(bfd)
        && !(bfd->flags & FLAG_FINAL)) {
        bfd->poll_min_tx = bfd->cfg_min_tx;
        bfd->poll_min_rx = bfd->in_decay ? bfd->decay_min_rx : bfd->cfg_min_rx;
        bfd->flags |= FLAG_POLL;
        bfd->next_tx = 0;
        VLOG_INFO_RL(&rl, "%s: Initiating poll sequence", bfd->name);
    }
}

static long long int
bfd_min_tx(const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    /* RFC 5880 Section 6.8.3
     * When bfd.SessionState is not Up, the system MUST set
     * bfd.DesiredMinTxInterval to a value of not less than one second
     * (1,000,000 microseconds).  This is intended to ensure that the
     * bandwidth consumed by BFD sessions that are not Up is negligible,
     * particularly in the case where a neighbor may not be running BFD. */
    return (bfd->state == STATE_UP ? bfd->min_tx : MAX(bfd->min_tx, 1000));
}

static long long int
bfd_tx_interval(const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    long long int interval = bfd_min_tx(bfd);
    return MAX(interval, bfd->rmt_min_rx);
}

static long long int
bfd_rx_interval(const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    return MAX(bfd->min_rx, bfd->rmt_min_tx);
}

static void
bfd_set_next_tx(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    long long int interval = bfd_tx_interval(bfd);
    interval -= interval * random_range(26) / 100;
    bfd->next_tx = bfd->last_tx + interval;
}

static const char *
bfd_flag_str(enum flags flags)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    static char flag_str[128];

    if (!flags) {
        return "none";
    }

    if (flags & FLAG_MULTIPOINT) {
        ds_put_cstr(&ds, "multipoint ");
    }

    if (flags & FLAG_DEMAND) {
        ds_put_cstr(&ds, "demand ");
    }

    if (flags & FLAG_AUTH) {
        ds_put_cstr(&ds, "auth ");
    }

    if (flags & FLAG_CTL) {
        ds_put_cstr(&ds, "ctl ");
    }

    if (flags & FLAG_FINAL) {
        ds_put_cstr(&ds, "final ");
    }

    if (flags & FLAG_POLL) {
        ds_put_cstr(&ds, "poll ");
    }

    /* Do not copy the trailing whitespace. */
    ds_chomp(&ds, ' ');
    ovs_strlcpy(flag_str, ds_cstr(&ds), sizeof flag_str);
    ds_destroy(&ds);
    return flag_str;
}

static const char *
bfd_state_str(enum state state)
{
    switch (state) {
    case STATE_ADMIN_DOWN: return "admin_down";
    case STATE_DOWN: return "down";
    case STATE_INIT: return "init";
    case STATE_UP: return "up";
    default: return "invalid";
    }
}

static const char *
bfd_diag_str(enum diag diag) {
    switch (diag) {
    case DIAG_NONE: return "No Diagnostic";
    case DIAG_EXPIRED: return "Control Detection Time Expired";
    case DIAG_ECHO_FAILED: return "Echo Function Failed";
    case DIAG_RMT_DOWN: return "Neighbor Signaled Session Down";
    case DIAG_FWD_RESET: return "Forwarding Plane Reset";
    case DIAG_PATH_DOWN: return "Path Down";
    case DIAG_CPATH_DOWN: return "Concatenated Path Down";
    case DIAG_ADMIN_DOWN: return "Administratively Down";
    case DIAG_RCPATH_DOWN: return "Reverse Concatenated Path Down";
    default: return "Invalid Diagnostic";
    }
};

static void
log_msg(enum vlog_level level, const struct msg *p, const char *message,
        const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (vlog_should_drop(THIS_MODULE, level, &rl)) {
        return;
    }

    ds_put_format(&ds,
                  "%s: %s."
                  "\n\tvers:%"PRIu8" diag:\"%s\" state:%s mult:%"PRIu8
                  " length:%"PRIu8
                  "\n\tflags: %s"
                  "\n\tmy_disc:0x%"PRIx32" your_disc:0x%"PRIx32
                  "\n\tmin_tx:%"PRIu32"us (%"PRIu32"ms)"
                  "\n\tmin_rx:%"PRIu32"us (%"PRIu32"ms)"
                  "\n\tmin_rx_echo:%"PRIu32"us (%"PRIu32"ms)",
                  bfd->name, message, p->vers_diag >> VERS_SHIFT,
                  bfd_diag_str(p->vers_diag & DIAG_MASK),
                  bfd_state_str(p->flags & STATE_MASK),
                  p->mult, p->length, bfd_flag_str(p->flags & FLAGS_MASK),
                  ntohl(p->my_disc), ntohl(p->your_disc),
                  ntohl(p->min_tx), ntohl(p->min_tx) / 1000,
                  ntohl(p->min_rx), ntohl(p->min_rx) / 1000,
                  ntohl(p->min_rx_echo), ntohl(p->min_rx_echo) / 1000);
    bfd_put_details(&ds, bfd);
    VLOG(level, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bfd_set_state(struct bfd *bfd, enum state state, enum diag diag)
    OVS_REQUIRES(mutex)
{
    if (bfd->cpath_down) {
        diag = DIAG_CPATH_DOWN;
    }

    if (bfd->state != state || bfd->diag != diag) {
        if (!VLOG_DROP_INFO(&rl)) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            ds_put_format(&ds, "%s: BFD state change: %s->%s"
                          " \"%s\"->\"%s\".\n",
                          bfd->name, bfd_state_str(bfd->state),
                          bfd_state_str(state), bfd_diag_str(bfd->diag),
                          bfd_diag_str(diag));
            bfd_put_details(&ds, bfd);
            VLOG_INFO("%s", ds_cstr(&ds));
            ds_destroy(&ds);
        }

        bfd->state = state;
        bfd->diag = diag;

        if (bfd->state <= STATE_DOWN) {
            bfd->rmt_state = STATE_DOWN;
            bfd->rmt_diag = DIAG_NONE;
            bfd->rmt_min_rx = 1;
            bfd->rmt_flags = 0;
            bfd->rmt_disc = 0;
            bfd->rmt_min_tx = 0;
            /* Resets the min_rx if in_decay. */
            if (bfd->in_decay) {
                bfd->min_rx = bfd->cfg_min_rx;
                bfd->in_decay = false;
            }
        }
        /* Resets the decay when state changes to STATE_UP
         * and decay_min_rx is configured. */
        if (bfd->state == STATE_UP && bfd->decay_min_rx) {
            bfd_decay_update(bfd);
        }

        bfd_status_changed(bfd);
    }
}

static uint64_t
bfd_rx_packets(const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    struct netdev_stats stats;

    if (!netdev_get_stats(bfd->netdev, &stats)) {
        return stats.rx_packets;
    } else {
        return 0;
    }
}

/* Decays the bfd->min_rx to bfd->decay_min_rx when 'diff' is less than
 * the 'expect' value. */
static void
bfd_try_decay(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    int64_t diff, expect;

    /* The 'diff' is the difference between current interface rx_packets
     * stats and last-time check.  The 'expect' is the recorded number of
     * bfd control packets received within an approximately decay_min_rx
     * (2000 ms if decay_min_rx is less than 2000 ms) interval.
     *
     * Since the update of rx_packets stats at interface happens
     * asynchronously to the bfd_rx_packets() function, the 'diff' value
     * can be jittered.  Thusly, we double the decay_rx_ctl to provide
     * more wiggle room. */
    diff = bfd_rx_packets(bfd) - bfd->decay_rx_packets;
    expect = 2 * MAX(bfd->decay_rx_ctl, 1);
    bfd->in_decay = diff <= expect ? true : false;
    bfd_decay_update(bfd);
}

/* Updates the rx_packets, decay_rx_ctl and decay_detect_time. */
static void
bfd_decay_update(struct bfd * bfd) OVS_REQUIRES(mutex)
{
    bfd->decay_rx_packets = bfd_rx_packets(bfd);
    bfd->decay_rx_ctl = 0;
    bfd->decay_detect_time = MAX(bfd->decay_min_rx, 2000) + time_msec();
}

/* Records the status change and changes the global connectivity seq. */
static void
bfd_status_changed(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    seq_change(connectivity_seq_get());
    bfd->status_changed = true;
}

static void
bfd_forwarding_if_rx_update(struct bfd *bfd) OVS_REQUIRES(mutex)
{
    int64_t incr = bfd_rx_interval(bfd) * bfd->mult;
    bfd->forwarding_if_rx_detect_time = MAX(incr, 2000) + time_msec();
}

static uint32_t
generate_discriminator(void)
{
    uint32_t disc = 0;

    /* RFC 5880 Section 6.8.1
     * It SHOULD be set to a random (but still unique) value to improve
     * security.  The value is otherwise outside the scope of this
     * specification. */

    while (!disc) {
        struct bfd *bfd;

        /* 'disc' is by definition random, so there's no reason to waste time
         * hashing it. */
        disc = random_uint32();
        HMAP_FOR_EACH_IN_BUCKET (bfd, node, disc, all_bfds) {
            if (bfd->disc == disc) {
                disc = 0;
                break;
            }
        }
    }

    return disc;
}

static struct bfd *
bfd_find_by_name(const char *name) OVS_REQUIRES(mutex)
{
    struct bfd *bfd;

    HMAP_FOR_EACH (bfd, node, all_bfds) {
        if (!strcmp(bfd->name, name)) {
            return bfd;
        }
    }
    return NULL;
}

static void
bfd_put_details(struct ds *ds, const struct bfd *bfd) OVS_REQUIRES(mutex)
{
    ds_put_format(ds, "\tForwarding: %s\n",
                  bfd_forwarding__(CONST_CAST(struct bfd *, bfd))
                  ? "true" : "false");
    ds_put_format(ds, "\tDetect Multiplier: %d\n", bfd->mult);
    ds_put_format(ds, "\tConcatenated Path Down: %s\n",
                  bfd->cpath_down ? "true" : "false");
    ds_put_format(ds, "\tTX Interval: Approx %lldms\n", bfd_tx_interval(bfd));
    ds_put_format(ds, "\tRX Interval: Approx %lldms\n", bfd_rx_interval(bfd));
    ds_put_format(ds, "\tDetect Time: now %+lldms\n",
                  time_msec() - bfd->detect_time);
    ds_put_format(ds, "\tNext TX Time: now %+lldms\n",
                  time_msec() - bfd->next_tx);
    ds_put_format(ds, "\tLast TX Time: now %+lldms\n",
                  time_msec() - bfd->last_tx);

    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "\tLocal Flags: %s\n", bfd_flag_str(bfd->flags));
    ds_put_format(ds, "\tLocal Session State: %s\n",
                  bfd_state_str(bfd->state));
    ds_put_format(ds, "\tLocal Diagnostic: %s\n", bfd_diag_str(bfd->diag));
    ds_put_format(ds, "\tLocal Discriminator: 0x%"PRIx32"\n", bfd->disc);
    ds_put_format(ds, "\tLocal Minimum TX Interval: %lldms\n",
                  bfd_min_tx(bfd));
    ds_put_format(ds, "\tLocal Minimum RX Interval: %lldms\n", bfd->min_rx);

    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "\tRemote Flags: %s\n", bfd_flag_str(bfd->rmt_flags));
    ds_put_format(ds, "\tRemote Session State: %s\n",
                  bfd_state_str(bfd->rmt_state));
    ds_put_format(ds, "\tRemote Diagnostic: %s\n",
                  bfd_diag_str(bfd->rmt_diag));
    ds_put_format(ds, "\tRemote Discriminator: 0x%"PRIx32"\n", bfd->rmt_disc);
    ds_put_format(ds, "\tRemote Minimum TX Interval: %lldms\n",
                  bfd->rmt_min_tx);
    ds_put_format(ds, "\tRemote Minimum RX Interval: %lldms\n",
                  bfd->rmt_min_rx);
}

static void
bfd_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct bfd *bfd;

    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        bfd = bfd_find_by_name(argv[1]);
        if (!bfd) {
            unixctl_command_reply_error(conn, "no such bfd object");
            goto out;
        }
        bfd_put_details(&ds, bfd);
    } else {
        HMAP_FOR_EACH (bfd, node, all_bfds) {
            ds_put_format(&ds, "---- %s ----\n", bfd->name);
            bfd_put_details(&ds, bfd);
        }
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    ovs_mutex_unlock(&mutex);
}


static void
bfd_unixctl_set_forwarding_override(struct unixctl_conn *conn, int argc,
                                    const char *argv[], void *aux OVS_UNUSED)
    OVS_EXCLUDED(mutex)
{
    const char *forward_str = argv[argc - 1];
    int forwarding_override;
    struct bfd *bfd;

    ovs_mutex_lock(&mutex);
    if (!strcasecmp("true", forward_str)) {
        forwarding_override = 1;
    } else if (!strcasecmp("false", forward_str)) {
        forwarding_override = 0;
    } else if (!strcasecmp("normal", forward_str)) {
        forwarding_override = -1;
    } else {
        unixctl_command_reply_error(conn, "unknown fault string");
        goto out;
    }

    if (argc > 2) {
        bfd = bfd_find_by_name(argv[1]);
        if (!bfd) {
            unixctl_command_reply_error(conn, "no such BFD object");
            goto out;
        }
        bfd->forwarding_override = forwarding_override;
        bfd_status_changed(bfd);
    } else {
        HMAP_FOR_EACH (bfd, node, all_bfds) {
            bfd->forwarding_override = forwarding_override;
            bfd_status_changed(bfd);
        }
    }

    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&mutex);
}
