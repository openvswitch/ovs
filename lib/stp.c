/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

/* Based on sample implementation in 802.1D-1998.  Above copyright and license
 * applies to all modifications. */

#include <config.h>

#include "stp.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include "byte-order.h"
#include "connectivity.h"
#include "ofpbuf.h"
#include "packets.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stp);

#define STP_PROTOCOL_ID 0x0000
#define STP_PROTOCOL_VERSION 0x00
#define STP_TYPE_CONFIG 0x00
#define STP_TYPE_TCN 0x80

OVS_PACKED(
struct stp_bpdu_header {
    ovs_be16 protocol_id;       /* STP_PROTOCOL_ID. */
    uint8_t protocol_version;   /* STP_PROTOCOL_VERSION. */
    uint8_t bpdu_type;          /* One of STP_TYPE_*. */
});
BUILD_ASSERT_DECL(sizeof(struct stp_bpdu_header) == 4);

enum stp_config_bpdu_flags {
    STP_CONFIG_TOPOLOGY_CHANGE_ACK = 0x80,
    STP_CONFIG_TOPOLOGY_CHANGE = 0x01
};

OVS_PACKED(
struct stp_config_bpdu {
    struct stp_bpdu_header header; /* Type STP_TYPE_CONFIG. */
    uint8_t flags;                 /* STP_CONFIG_* flags. */
    ovs_be64 root_id;              /* 8.5.1.1: Bridge believed to be root. */
    ovs_be32 root_path_cost;       /* 8.5.1.2: Cost of path to root. */
    ovs_be64 bridge_id;            /* 8.5.1.3: ID of transmitting bridge. */
    ovs_be16 port_id;              /* 8.5.1.4: Port transmitting the BPDU. */
    ovs_be16 message_age;          /* 8.5.1.5: Age of BPDU at tx time. */
    ovs_be16 max_age;              /* 8.5.1.6: Timeout for received data. */
    ovs_be16 hello_time;           /* 8.5.1.7: Time between BPDU generation. */
    ovs_be16 forward_delay;        /* 8.5.1.8: State progression delay. */
});
BUILD_ASSERT_DECL(sizeof(struct stp_config_bpdu) == 35);

OVS_PACKED(
struct stp_tcn_bpdu {
    struct stp_bpdu_header header; /* Type STP_TYPE_TCN. */
});
BUILD_ASSERT_DECL(sizeof(struct stp_tcn_bpdu) == 4);

struct stp_timer {
    bool active;                 /* Timer in use? */
    int value;                   /* Current value of timer, counting up. */
};

struct stp_port {
    struct stp *stp;
    void *aux;                      /* Auxiliary data the user may retrieve. */
    int port_id;                    /* 8.5.5.1: Unique port identifier. */
    enum stp_state state;           /* 8.5.5.2: Current state. */
    int path_cost;                  /* 8.5.5.3: Cost of tx/rx on this port. */
    stp_identifier designated_root; /* 8.5.5.4. */
    int designated_cost;            /* 8.5.5.5: Path cost to root on port. */
    stp_identifier designated_bridge; /* 8.5.5.6. */
    int designated_port;            /* 8.5.5.7: Port to send config msgs on. */
    bool topology_change_ack;       /* 8.5.5.8: Flag for next config BPDU. */
    bool config_pending;            /* 8.5.5.9: Send BPDU when hold expires? */
    bool change_detection_enabled;  /* 8.5.5.10: Detect topology changes? */

    struct stp_timer message_age_timer; /* 8.5.6.1: Age of received info. */
    struct stp_timer forward_delay_timer; /* 8.5.6.2: State change timer. */
    struct stp_timer hold_timer;        /* 8.5.6.3: BPDU rate limit timer. */

    int tx_count;                   /* Number of BPDUs transmitted. */
    int rx_count;                   /* Number of valid BPDUs received. */
    int error_count;                /* Number of bad BPDUs received. */

    bool state_changed;
};

struct stp {
    struct list node;               /* Node in all_stps list. */

    /* Static bridge data. */
    char *name;                     /* Human-readable name for log messages. */
    stp_identifier bridge_id;       /* 8.5.3.7: This bridge. */
    int max_age;                    /* 8.5.3.4: Time to drop received data. */
    int hello_time;                 /* 8.5.3.5: Time between sending BPDUs. */
    int forward_delay;              /* 8.5.3.6: Delay between state changes. */
    int bridge_max_age;             /* 8.5.3.8: max_age when we're root. */
    int bridge_hello_time;          /* 8.5.3.9: hello_time as root. */
    int bridge_forward_delay;       /* 8.5.3.10: forward_delay as root. */
    int rq_max_age;                 /* User-requested max age, in ms. */
    int rq_hello_time;              /* User-requested hello time, in ms. */
    int rq_forward_delay;           /* User-requested forward delay, in ms. */
    int elapsed_remainder;          /* Left-over msecs from last stp_tick(). */

    /* Dynamic bridge data. */
    stp_identifier designated_root; /* 8.5.3.1: Bridge believed to be root. */
    unsigned int root_path_cost;    /* 8.5.3.2: Cost of path to root. */
    struct stp_port *root_port;     /* 8.5.3.3: Lowest cost port to root. */
    bool topology_change_detected;  /* 8.5.3.11: Detected a topology change? */
    bool topology_change;           /* 8.5.3.12: Received topology change? */

    /* Bridge timers. */
    struct stp_timer hello_timer;   /* 8.5.4.1: Hello timer. */
    struct stp_timer tcn_timer;     /* 8.5.4.2: Topology change timer. */
    struct stp_timer topology_change_timer; /* 8.5.4.3. */

    /* Ports. */
    struct stp_port ports[STP_MAX_PORTS];

    /* Interface to client. */
    bool fdb_needs_flush;          /* MAC learning tables needs flushing. */
    struct stp_port *first_changed_port;
    void (*send_bpdu)(struct ofpbuf *bpdu, int port_no, void *aux);
    void *aux;

    atomic_int ref_cnt;
};

static struct ovs_mutex mutex;
static struct list all_stps__ = LIST_INITIALIZER(&all_stps__);
static struct list *const all_stps OVS_GUARDED_BY(mutex) = &all_stps__;

#define FOR_EACH_ENABLED_PORT(PORT, STP)                        \
    for ((PORT) = stp_next_enabled_port((STP), (STP)->ports);   \
         (PORT);                                                \
         (PORT) = stp_next_enabled_port((STP), (PORT) + 1))
static struct stp_port *
stp_next_enabled_port(const struct stp *stp, const struct stp_port *port)
    OVS_REQUIRES(mutex)
{
    for (; port < &stp->ports[ARRAY_SIZE(stp->ports)]; port++) {
        if (port->state != STP_DISABLED) {
            return CONST_CAST(struct stp_port *, port);
        }
    }
    return NULL;
}

#define MESSAGE_AGE_INCREMENT 1

static void stp_transmit_config(struct stp_port *) OVS_REQUIRES(mutex);
static bool stp_supersedes_port_info(const struct stp_port *,
                                     const struct stp_config_bpdu *)
    OVS_REQUIRES(mutex);
static void stp_record_config_information(struct stp_port *,
                                          const struct stp_config_bpdu *)
    OVS_REQUIRES(mutex);
static void stp_record_config_timeout_values(struct stp *,
                                             const struct stp_config_bpdu  *)
    OVS_REQUIRES(mutex);
static bool stp_is_designated_port(const struct stp_port *)
    OVS_REQUIRES(mutex);
static void stp_config_bpdu_generation(struct stp *) OVS_REQUIRES(mutex);
static void stp_transmit_tcn(struct stp *) OVS_REQUIRES(mutex);
static void stp_configuration_update(struct stp *) OVS_REQUIRES(mutex);
static bool stp_supersedes_root(const struct stp_port *root,
                                const struct stp_port *) OVS_REQUIRES(mutex);
static void stp_root_selection(struct stp *) OVS_REQUIRES(mutex);
static void stp_designated_port_selection(struct stp *) OVS_REQUIRES(mutex);
static void stp_become_designated_port(struct stp_port *)
    OVS_REQUIRES(mutex);
static void stp_port_state_selection(struct stp *) OVS_REQUIRES(mutex);
static void stp_make_forwarding(struct stp_port *) OVS_REQUIRES(mutex);
static void stp_make_blocking(struct stp_port *) OVS_REQUIRES(mutex);
static void stp_set_port_state(struct stp_port *, enum stp_state)
    OVS_REQUIRES(mutex);
static void stp_topology_change_detection(struct stp *) OVS_REQUIRES(mutex);
static void stp_topology_change_acknowledged(struct stp *)
    OVS_REQUIRES(mutex);
static void stp_acknowledge_topology_change(struct stp_port *)
    OVS_REQUIRES(mutex);
static void stp_received_config_bpdu(struct stp *, struct stp_port *,
                                     const struct stp_config_bpdu *)
    OVS_REQUIRES(mutex);
static void stp_received_tcn_bpdu(struct stp *, struct stp_port *)
    OVS_REQUIRES(mutex);
static void stp_hello_timer_expiry(struct stp *) OVS_REQUIRES(mutex);
static void stp_message_age_timer_expiry(struct stp_port *)
    OVS_REQUIRES(mutex);
static bool stp_is_designated_for_some_port(const struct stp *)
    OVS_REQUIRES(mutex);
static void stp_forward_delay_timer_expiry(struct stp_port *)
    OVS_REQUIRES(mutex);
static void stp_tcn_timer_expiry(struct stp *) OVS_REQUIRES(mutex);
static void stp_topology_change_timer_expiry(struct stp *)
    OVS_REQUIRES(mutex);
static void stp_hold_timer_expiry(struct stp_port *) OVS_REQUIRES(mutex);
static void stp_initialize_port(struct stp_port *, enum stp_state)
    OVS_REQUIRES(mutex);
static void stp_become_root_bridge(struct stp *) OVS_REQUIRES(mutex);
static void stp_update_bridge_timers(struct stp *) OVS_REQUIRES(mutex);

static int clamp(int x, int min, int max);
static int ms_to_timer(int ms);
static int timer_to_ms(int timer);
static void stp_start_timer(struct stp_timer *, int value);
static void stp_stop_timer(struct stp_timer *);
static bool stp_timer_expired(struct stp_timer *, int elapsed, int timeout);

static void stp_send_bpdu(struct stp_port *, const void *, size_t)
    OVS_REQUIRES(mutex);
static void stp_unixctl_tcn(struct unixctl_conn *, int argc,
                            const char *argv[], void *aux);

void
stp_init(void)
{
    unixctl_command_register("stp/tcn", "[bridge]", 0, 1, stp_unixctl_tcn,
                             NULL);
}

/* Creates and returns a new STP instance that initially has no ports enabled.
 *
 * 'bridge_id' should be a 48-bit MAC address as returned by
 * eth_addr_to_uint64().  'bridge_id' may also have a priority value in its top
 * 16 bits; if those bits are set to 0, STP_DEFAULT_BRIDGE_PRIORITY is used.
 * (This priority may be changed with stp_set_bridge_priority().)
 *
 * When the bridge needs to send out a BPDU, it calls 'send_bpdu'.  This
 * callback may be called from stp_tick() or stp_received_bpdu().  The
 * arguments to 'send_bpdu' are an STP BPDU encapsulated in 'bpdu',
 * the spanning tree port number 'port_no' that should transmit the
 * packet, and auxiliary data to be passed to the callback in 'aux'.
 */
struct stp *
stp_create(const char *name, stp_identifier bridge_id,
           void (*send_bpdu)(struct ofpbuf *bpdu, int port_no, void *aux),
           void *aux)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct stp *stp;
    struct stp_port *p;

    if (ovsthread_once_start(&once)) {
        /* We need a recursive mutex because stp_send_bpdu() could loop back
         * into the stp module through a patch port.  This happens
         * intentionally as part of the unit tests.  Ideally we'd ditch
         * the call back function, but for now this is what we have. */
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }

    ovs_mutex_lock(&mutex);
    stp = xzalloc(sizeof *stp);
    stp->name = xstrdup(name);
    stp->bridge_id = bridge_id;
    if (!(stp->bridge_id >> 48)) {
        stp->bridge_id |= (uint64_t) STP_DEFAULT_BRIDGE_PRIORITY << 48;
    }

    stp->rq_max_age = STP_DEFAULT_MAX_AGE;
    stp->rq_hello_time = STP_DEFAULT_HELLO_TIME;
    stp->rq_forward_delay = STP_DEFAULT_FWD_DELAY;
    stp_update_bridge_timers(stp);
    stp->max_age = stp->bridge_max_age;
    stp->hello_time = stp->bridge_hello_time;
    stp->forward_delay = stp->bridge_forward_delay;

    stp->designated_root = stp->bridge_id;
    stp->root_path_cost = 0;
    stp->root_port = NULL;
    stp->topology_change_detected = false;
    stp->topology_change = false;

    stp_stop_timer(&stp->tcn_timer);
    stp_stop_timer(&stp->topology_change_timer);
    stp_start_timer(&stp->hello_timer, 0);

    stp->send_bpdu = send_bpdu;
    stp->aux = aux;

    stp->first_changed_port = &stp->ports[ARRAY_SIZE(stp->ports)];
    for (p = stp->ports; p < &stp->ports[ARRAY_SIZE(stp->ports)]; p++) {
        p->stp = stp;
        p->port_id = (stp_port_no(p) + 1) | (STP_DEFAULT_PORT_PRIORITY << 8);
        p->path_cost = 19;      /* Recommended default for 100 Mb/s link. */
        stp_initialize_port(p, STP_DISABLED);
    }
    atomic_init(&stp->ref_cnt, 1);

    list_push_back(all_stps, &stp->node);
    ovs_mutex_unlock(&mutex);
    return stp;
}

struct stp *
stp_ref(const struct stp *stp_)
{
    struct stp *stp = CONST_CAST(struct stp *, stp_);
    if (stp) {
        int orig;
        atomic_add(&stp->ref_cnt, 1, &orig);
        ovs_assert(orig > 0);
    }
    return stp;
}

/* Destroys 'stp'. */
void
stp_unref(struct stp *stp)
{
    int orig;

    if (!stp) {
        return;
    }

    atomic_sub(&stp->ref_cnt, 1, &orig);
    ovs_assert(orig > 0);
    if (orig == 1) {
        ovs_mutex_lock(&mutex);
        list_remove(&stp->node);
        ovs_mutex_unlock(&mutex);
        free(stp->name);
        free(stp);
    }
}

/* Runs 'stp' given that 'ms' milliseconds have passed. */
void
stp_tick(struct stp *stp, int ms)
{
    struct stp_port *p;
    int elapsed;

    ovs_mutex_lock(&mutex);
    /* Convert 'ms' to STP timer ticks.  Preserve any leftover milliseconds
     * from previous stp_tick() calls so that we don't lose STP ticks when we
     * are called too frequently. */
    ms = clamp(ms, 0, INT_MAX - 1000) + stp->elapsed_remainder;
    elapsed = ms_to_timer(ms);
    stp->elapsed_remainder = ms - timer_to_ms(elapsed);
    if (!elapsed) {
        goto out;
    }

    if (stp_timer_expired(&stp->hello_timer, elapsed, stp->hello_time)) {
        stp_hello_timer_expiry(stp);
    }
    if (stp_timer_expired(&stp->tcn_timer, elapsed, stp->bridge_hello_time)) {
        stp_tcn_timer_expiry(stp);
    }
    if (stp_timer_expired(&stp->topology_change_timer, elapsed,
                          stp->max_age + stp->forward_delay)) {
        stp_topology_change_timer_expiry(stp);
    }
    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_timer_expired(&p->message_age_timer, elapsed, stp->max_age)) {
            stp_message_age_timer_expiry(p);
        }
    }
    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_timer_expired(&p->forward_delay_timer, elapsed,
                              stp->forward_delay)) {
            stp_forward_delay_timer_expiry(p);
        }
        if (stp_timer_expired(&p->hold_timer, elapsed, ms_to_timer(1000))) {
            stp_hold_timer_expiry(p);
        }
    }

out:
    ovs_mutex_unlock(&mutex);
}

static void
set_bridge_id(struct stp *stp, stp_identifier new_bridge_id)
    OVS_REQUIRES(mutex)
{
    if (new_bridge_id != stp->bridge_id) {
        bool root;
        struct stp_port *p;

        root = stp_is_root_bridge(stp);
        FOR_EACH_ENABLED_PORT (p, stp) {
            if (stp_is_designated_port(p)) {
                p->designated_bridge = new_bridge_id;
            }
        }
        stp->bridge_id = new_bridge_id;
        stp_configuration_update(stp);
        stp_port_state_selection(stp);
        if (stp_is_root_bridge(stp) && !root) {
            stp_become_root_bridge(stp);
        }
    }
}

void
stp_set_bridge_id(struct stp *stp, stp_identifier bridge_id)
{
    const uint64_t mac_bits = (UINT64_C(1) << 48) - 1;
    const uint64_t pri_bits = ~mac_bits;
    ovs_mutex_lock(&mutex);
    set_bridge_id(stp, (stp->bridge_id & pri_bits) | (bridge_id & mac_bits));
    ovs_mutex_unlock(&mutex);
}

void
stp_set_bridge_priority(struct stp *stp, uint16_t new_priority)
{
    const uint64_t mac_bits = (UINT64_C(1) << 48) - 1;
    ovs_mutex_lock(&mutex);
    set_bridge_id(stp, ((stp->bridge_id & mac_bits)
                        | ((uint64_t) new_priority << 48)));
    ovs_mutex_unlock(&mutex);
}

/* Sets the desired hello time for 'stp' to 'ms', in milliseconds.  The actual
 * hello time is clamped to the range of 1 to 10 seconds and subject to the
 * relationship (bridge_max_age >= 2 * (bridge_hello_time + 1 s)).  The bridge
 * hello time is only used when 'stp' is the root bridge. */
void
stp_set_hello_time(struct stp *stp, int ms)
{
    ovs_mutex_lock(&mutex);
    stp->rq_hello_time = ms;
    stp_update_bridge_timers(stp);
    ovs_mutex_unlock(&mutex);
}

/* Sets the desired max age for 'stp' to 'ms', in milliseconds.  The actual max
 * age is clamped to the range of 6 to 40 seconds and subject to the
 * relationships (2 * (bridge_forward_delay - 1 s) >= bridge_max_age) and
 * (bridge_max_age >= 2 * (bridge_hello_time + 1 s)).  The bridge max age is
 * only used when 'stp' is the root bridge. */
void
stp_set_max_age(struct stp *stp, int ms)
{
    ovs_mutex_lock(&mutex);
    stp->rq_max_age = ms;
    stp_update_bridge_timers(stp);
    ovs_mutex_unlock(&mutex);
}

/* Sets the desired forward delay for 'stp' to 'ms', in milliseconds.  The
 * actual forward delay is clamped to the range of 4 to 30 seconds and subject
 * to the relationship (2 * (bridge_forward_delay - 1 s) >= bridge_max_age).
 * The bridge forward delay is only used when 'stp' is the root bridge. */
void
stp_set_forward_delay(struct stp *stp, int ms)
{
    ovs_mutex_lock(&mutex);
    stp->rq_forward_delay = ms;
    stp_update_bridge_timers(stp);
    ovs_mutex_unlock(&mutex);
}

/* Returns the name given to 'stp' in the call to stp_create(). */
const char *
stp_get_name(const struct stp *stp)
{
    char *name;

    ovs_mutex_lock(&mutex);
    name = stp->name;
    ovs_mutex_unlock(&mutex);
    return name;
}

/* Returns the bridge ID for 'stp'. */
stp_identifier
stp_get_bridge_id(const struct stp *stp)
{
    stp_identifier bridge_id;

    ovs_mutex_lock(&mutex);
    bridge_id = stp->bridge_id;
    ovs_mutex_unlock(&mutex);
    return bridge_id;
}

/* Returns the bridge ID of the bridge currently believed to be the root. */
stp_identifier
stp_get_designated_root(const struct stp *stp)
{
    stp_identifier designated_root;

    ovs_mutex_lock(&mutex);
    designated_root = stp->designated_root;
    ovs_mutex_unlock(&mutex);
    return designated_root;
}

/* Returns true if 'stp' believes itself to the be root of the spanning tree,
 * false otherwise. */
bool
stp_is_root_bridge(const struct stp *stp)
{
    bool is_root;

    ovs_mutex_lock(&mutex);
    is_root = stp->bridge_id == stp->designated_root;
    ovs_mutex_unlock(&mutex);
    return is_root;
}

/* Returns the cost of the path from 'stp' to the root of the spanning tree. */
int
stp_get_root_path_cost(const struct stp *stp)
{
    int cost;

    ovs_mutex_lock(&mutex);
    cost = stp->root_path_cost;
    ovs_mutex_unlock(&mutex);
    return cost;
}

/* Returns the bridge hello time, in ms.  The returned value is not necessarily
 * the value passed to stp_set_hello_time(): it is clamped to the valid range
 * and quantized to the STP timer resolution.  */
int
stp_get_hello_time(const struct stp *stp)
{
    int time;

    ovs_mutex_lock(&mutex);
    time = timer_to_ms(stp->bridge_hello_time);
    ovs_mutex_unlock(&mutex);
    return time;
}

/* Returns the bridge max age, in ms.  The returned value is not necessarily
 * the value passed to stp_set_max_age(): it is clamped to the valid range,
 * quantized to the STP timer resolution, and adjusted to match the constraints
 * due to the hello time.  */
int
stp_get_max_age(const struct stp *stp)
{
    int time;

    ovs_mutex_lock(&mutex);
    time = timer_to_ms(stp->bridge_max_age);
    ovs_mutex_unlock(&mutex);
    return time;
}

/* Returns the bridge forward delay, in ms.  The returned value is not
 * necessarily the value passed to stp_set_forward_delay(): it is clamped to
 * the valid range, quantized to the STP timer resolution, and adjusted to
 * match the constraints due to the forward delay.  */
int
stp_get_forward_delay(const struct stp *stp)
{
    int time;

    ovs_mutex_lock(&mutex);
    time = timer_to_ms(stp->bridge_forward_delay);
    ovs_mutex_unlock(&mutex);
    return time;
}

/* Returns true if something has happened to 'stp' which necessitates flushing
 * the client's MAC learning table.  Calling this function resets 'stp' so that
 * future calls will return false until flushing is required again. */
bool
stp_check_and_reset_fdb_flush(struct stp *stp)
{
    bool needs_flush;

    ovs_mutex_lock(&mutex);
    needs_flush = stp->fdb_needs_flush;
    stp->fdb_needs_flush = false;
    ovs_mutex_unlock(&mutex);
    return needs_flush;
}

/* Returns the port in 'stp' with index 'port_no', which must be between 0 and
 * STP_MAX_PORTS. */
struct stp_port *
stp_get_port(struct stp *stp, int port_no)
{
    struct stp_port *port;

    ovs_mutex_lock(&mutex);
    ovs_assert(port_no >= 0 && port_no < ARRAY_SIZE(stp->ports));
    port = &stp->ports[port_no];
    ovs_mutex_unlock(&mutex);
    return port;
}

/* Returns the port connecting 'stp' to the root bridge, or a null pointer if
 * there is no such port. */
struct stp_port *
stp_get_root_port(struct stp *stp)
{
    struct stp_port *port;

    ovs_mutex_lock(&mutex);
    port = stp->root_port;
    ovs_mutex_unlock(&mutex);
    return port;
}

/* Finds a port whose state has changed.  If successful, stores the port whose
 * state changed in '*portp' and returns true.  If no port has changed, stores
 * NULL in '*portp' and returns false. */
bool
stp_get_changed_port(struct stp *stp, struct stp_port **portp)
{
    struct stp_port *end, *p;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    end = &stp->ports[ARRAY_SIZE(stp->ports)];
    for (p = stp->first_changed_port; p < end; p++) {
        if (p->state_changed) {
            p->state_changed = false;
            stp->first_changed_port = p + 1;
            *portp = p;
            changed = true;
            goto out;
        }
    }
    stp->first_changed_port = end;
    *portp = NULL;

out:
    ovs_mutex_unlock(&mutex);
    return changed;
}

/* Returns the name for the given 'state' (for use in debugging and log
 * messages). */
const char *
stp_state_name(enum stp_state state)
{
    switch (state) {
    case STP_DISABLED:
        return "disabled";
    case STP_LISTENING:
        return "listening";
    case STP_LEARNING:
        return "learning";
    case STP_FORWARDING:
        return "forwarding";
    case STP_BLOCKING:
        return "blocking";
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns true if 'state' is one in which packets received on a port should
 * be forwarded, false otherwise.
 *
 * Returns true if 'state' is STP_DISABLED, since presumably in that case the
 * port should still work, just not have STP applied to it. */
bool
stp_forward_in_state(enum stp_state state)
{
    return (state & (STP_DISABLED | STP_FORWARDING)) != 0;
}

/* Returns true if 'state' is one in which MAC learning should be done on
 * packets received on a port, false otherwise.
 *
 * Returns true if 'state' is STP_DISABLED, since presumably in that case the
 * port should still work, just not have STP applied to it. */
bool
stp_learn_in_state(enum stp_state state)
{
    return (state & (STP_DISABLED | STP_LEARNING | STP_FORWARDING)) != 0;
}

/* Returns true if 'state' is one in which rx&tx bpdu should be done on
 * on a port, false otherwise. */
bool
stp_listen_in_state(enum stp_state state)
{
    return (state &
            (STP_LISTENING | STP_LEARNING | STP_FORWARDING)) != 0;
}

/* Returns the name for the given 'role' (for use in debugging and log
 * messages). */
const char *
stp_role_name(enum stp_role role)
{
    switch (role) {
    case STP_ROLE_ROOT:
        return "root";
    case STP_ROLE_DESIGNATED:
        return "designated";
    case STP_ROLE_ALTERNATE:
        return "alternate";
    case STP_ROLE_DISABLED:
        return "disabled";
    default:
        OVS_NOT_REACHED();
    }
}

/* Notifies the STP entity that bridge protocol data unit 'bpdu', which is
 * 'bpdu_size' bytes in length, was received on port 'p'.
 *
 * This function may call the 'send_bpdu' function provided to stp_create(). */
void
stp_received_bpdu(struct stp_port *p, const void *bpdu, size_t bpdu_size)
{
    struct stp *stp = p->stp;
    const struct stp_bpdu_header *header;

    ovs_mutex_lock(&mutex);
    if (p->state == STP_DISABLED) {
        goto out;
    }

    if (bpdu_size < sizeof(struct stp_bpdu_header)) {
        VLOG_WARN("%s: received runt %"PRIuSIZE"-byte BPDU", stp->name, bpdu_size);
        p->error_count++;
        goto out;
    }

    header = bpdu;
    if (header->protocol_id != htons(STP_PROTOCOL_ID)) {
        VLOG_WARN("%s: received BPDU with unexpected protocol ID %"PRIu16,
                  stp->name, ntohs(header->protocol_id));
        p->error_count++;
        goto out;
    }
    if (header->protocol_version != STP_PROTOCOL_VERSION) {
        VLOG_DBG("%s: received BPDU with unexpected protocol version %"PRIu8,
                 stp->name, header->protocol_version);
    }

    switch (header->bpdu_type) {
    case STP_TYPE_CONFIG:
        if (bpdu_size < sizeof(struct stp_config_bpdu)) {
            VLOG_WARN("%s: received config BPDU with invalid size %"PRIuSIZE,
                      stp->name, bpdu_size);
            p->error_count++;
            goto out;
        }
        stp_received_config_bpdu(stp, p, bpdu);
        break;

    case STP_TYPE_TCN:
        if (bpdu_size != sizeof(struct stp_tcn_bpdu)) {
            VLOG_WARN("%s: received TCN BPDU with invalid size %"PRIuSIZE,
                      stp->name, bpdu_size);
            p->error_count++;
            goto out;
        }
        stp_received_tcn_bpdu(stp, p);
        break;

    default:
        VLOG_WARN("%s: received BPDU of unexpected type %"PRIu8,
                  stp->name, header->bpdu_type);
        p->error_count++;
        goto out;
    }
    p->rx_count++;

out:
    ovs_mutex_unlock(&mutex);
}

/* Returns the STP entity in which 'p' is nested. */
struct stp *
stp_port_get_stp(struct stp_port *p)
{
    struct stp *stp;

    ovs_mutex_lock(&mutex);
    stp = p->stp;
    ovs_mutex_unlock(&mutex);
    return stp;
}

/* Sets the 'aux' member of 'p'.
 *
 * The 'aux' member will be reset to NULL when stp_port_disable() is
 * called or stp_port_enable() is called when the port is in a Disabled
 * state. */
void
stp_port_set_aux(struct stp_port *p, void *aux)
{
    ovs_mutex_lock(&mutex);
    p->aux = aux;
    ovs_mutex_unlock(&mutex);
}

/* Returns the 'aux' member of 'p'. */
void *
stp_port_get_aux(struct stp_port *p)
{
    void *aux;

    ovs_mutex_lock(&mutex);
    aux = p->aux;
    ovs_mutex_unlock(&mutex);
    return aux;
}

/* Returns the index of port 'p' within its bridge. */
int
stp_port_no(const struct stp_port *p)
{
    struct stp *stp;
    int index;

    ovs_mutex_lock(&mutex);
    stp = p->stp;
    ovs_assert(p >= stp->ports && p < &stp->ports[ARRAY_SIZE(stp->ports)]);
    index = p - p->stp->ports;
    ovs_mutex_unlock(&mutex);
    return index;
}

/* Returns the port ID for 'p'. */
int
stp_port_get_id(const struct stp_port *p)
{
    int port_id;

    ovs_mutex_lock(&mutex);
    port_id = p->port_id;
    ovs_mutex_unlock(&mutex);
    return port_id;
}

/* Returns the state of port 'p'. */
enum stp_state
stp_port_get_state(const struct stp_port *p)
{
    enum stp_state state;

    ovs_mutex_lock(&mutex);
    state = p->state;
    ovs_mutex_unlock(&mutex);
    return state;
}

/* Returns the role of port 'p'. */
enum stp_role
stp_port_get_role(const struct stp_port *p)
{
    struct stp_port *root_port;
    enum stp_role role;

    ovs_mutex_lock(&mutex);
    root_port = p->stp->root_port;
    if (root_port && root_port->port_id == p->port_id) {
        role = STP_ROLE_ROOT;
    } else if (stp_is_designated_port(p)) {
        role = STP_ROLE_DESIGNATED;
    } else if (p->state == STP_DISABLED) {
        role = STP_ROLE_DISABLED;
    } else {
        role = STP_ROLE_ALTERNATE;
    }
    ovs_mutex_unlock(&mutex);
    return role;
}

/* Retrieves BPDU transmit and receive counts for 'p'. */
void
stp_port_get_counts(const struct stp_port *p,
                    int *tx_count, int *rx_count, int *error_count)
{
    ovs_mutex_lock(&mutex);
    *tx_count = p->tx_count;
    *rx_count = p->rx_count;
    *error_count = p->error_count;
    ovs_mutex_unlock(&mutex);
}

/* Disables STP on port 'p'. */
void
stp_port_disable(struct stp_port *p)
{
    struct stp *stp;

    ovs_mutex_lock(&mutex);
    stp = p->stp;
    if (p->state != STP_DISABLED) {
        bool root = stp_is_root_bridge(stp);
        stp_become_designated_port(p);
        stp_set_port_state(p, STP_DISABLED);
        p->topology_change_ack = false;
        p->config_pending = false;
        stp_stop_timer(&p->message_age_timer);
        stp_stop_timer(&p->forward_delay_timer);
        stp_configuration_update(stp);
        stp_port_state_selection(stp);
        if (stp_is_root_bridge(stp) && !root) {
            stp_become_root_bridge(stp);
        }
        p->aux = NULL;
    }
    ovs_mutex_unlock(&mutex);
}

/* Enables STP on port 'p'.  The port will initially be in "blocking" state. */
void
stp_port_enable(struct stp_port *p)
{
    ovs_mutex_lock(&mutex);
    if (p->state == STP_DISABLED) {
        stp_initialize_port(p, STP_BLOCKING);
        stp_port_state_selection(p->stp);
    }
    ovs_mutex_unlock(&mutex);
}

/* Sets the priority of port 'p' to 'new_priority'.  Lower numerical values
 * are interpreted as higher priorities. */
void
stp_port_set_priority(struct stp_port *p, uint8_t new_priority)
{
    uint16_t new_port_id;

    ovs_mutex_lock(&mutex);
    new_port_id  = (p->port_id & 0xff) | (new_priority << 8);
    if (p->port_id != new_port_id) {
        struct stp *stp = p->stp;
        if (stp_is_designated_port(p)) {
            p->designated_port = new_port_id;
        }
        p->port_id = new_port_id;
        if (stp->bridge_id == p->designated_bridge
            && p->port_id < p->designated_port) {
            stp_become_designated_port(p);
            stp_port_state_selection(stp);
        }
    }
    ovs_mutex_unlock(&mutex);
}

/* Convert 'speed' (measured in Mb/s) into the path cost. */
uint16_t
stp_convert_speed_to_cost(unsigned int speed)
{
    uint16_t ret;

    ovs_mutex_lock(&mutex);
    ret = speed >= 10000 ? 2  /* 10 Gb/s. */
        : speed >= 1000 ? 4 /* 1 Gb/s. */
        : speed >= 100 ? 19 /* 100 Mb/s. */
        : speed >= 16 ? 62  /* 16 Mb/s. */
        : speed >= 10 ? 100 /* 10 Mb/s. */
        : speed >= 4 ? 250  /* 4 Mb/s. */
        : 19;             /* 100 Mb/s (guess). */
    ovs_mutex_unlock(&mutex);
    return ret;
}

/* Sets the path cost of port 'p' to 'path_cost'.  Lower values are generally
 * used to indicate faster links.  Use stp_port_set_speed() to automatically
 * generate a default path cost from a link speed. */
void
stp_port_set_path_cost(struct stp_port *p, uint16_t path_cost)
{
    ovs_mutex_lock(&mutex);
    if (p->path_cost != path_cost) {
        struct stp *stp = p->stp;
        p->path_cost = path_cost;
        stp_configuration_update(stp);
        stp_port_state_selection(stp);
    }
    ovs_mutex_unlock(&mutex);
}

/* Sets the path cost of port 'p' based on 'speed' (measured in Mb/s). */
void
stp_port_set_speed(struct stp_port *p, unsigned int speed)
{
    stp_port_set_path_cost(p, stp_convert_speed_to_cost(speed));
}

/* Enables topology change detection on port 'p'. */
void
stp_port_enable_change_detection(struct stp_port *p)
{
    p->change_detection_enabled = true;
}

/* Disables topology change detection on port 'p'. */
void
stp_port_disable_change_detection(struct stp_port *p)
{
    p->change_detection_enabled = false;
}

static void
stp_transmit_config(struct stp_port *p) OVS_REQUIRES(mutex)
{
    struct stp *stp = p->stp;
    bool root = stp_is_root_bridge(stp);
    if (!root && !stp->root_port) {
        return;
    }
    if (p->hold_timer.active) {
        p->config_pending = true;
    } else {
        struct stp_config_bpdu config;
        memset(&config, 0, sizeof config);
        config.header.protocol_id = htons(STP_PROTOCOL_ID);
        config.header.protocol_version = STP_PROTOCOL_VERSION;
        config.header.bpdu_type = STP_TYPE_CONFIG;
        config.flags = 0;
        if (p->topology_change_ack) {
            config.flags |= STP_CONFIG_TOPOLOGY_CHANGE_ACK;
        }
        if (stp->topology_change) {
            config.flags |= STP_CONFIG_TOPOLOGY_CHANGE;
        }
        config.root_id = htonll(stp->designated_root);
        config.root_path_cost = htonl(stp->root_path_cost);
        config.bridge_id = htonll(stp->bridge_id);
        config.port_id = htons(p->port_id);
        if (root) {
            config.message_age = htons(0);
        } else {
            config.message_age = htons(stp->root_port->message_age_timer.value
                                       + MESSAGE_AGE_INCREMENT);
        }
        config.max_age = htons(stp->max_age);
        config.hello_time = htons(stp->hello_time);
        config.forward_delay = htons(stp->forward_delay);
        if (ntohs(config.message_age) < stp->max_age) {
            p->topology_change_ack = false;
            p->config_pending = false;
            stp_send_bpdu(p, &config, sizeof config);
            stp_start_timer(&p->hold_timer, 0);
        }
    }
}

static bool
stp_supersedes_port_info(const struct stp_port *p,
                         const struct stp_config_bpdu *config)
     OVS_REQUIRES(mutex)
{
    if (ntohll(config->root_id) != p->designated_root) {
        return ntohll(config->root_id) < p->designated_root;
    } else if (ntohl(config->root_path_cost) != p->designated_cost) {
        return ntohl(config->root_path_cost) < p->designated_cost;
    } else if (ntohll(config->bridge_id) != p->designated_bridge) {
        return ntohll(config->bridge_id) < p->designated_bridge;
    } else {
        return (ntohll(config->bridge_id) != p->stp->bridge_id
                || ntohs(config->port_id) <= p->designated_port);
    }
}

static void
stp_record_config_information(struct stp_port *p,
                              const struct stp_config_bpdu *config)
     OVS_REQUIRES(mutex)
{
    p->designated_root = ntohll(config->root_id);
    p->designated_cost = ntohl(config->root_path_cost);
    p->designated_bridge = ntohll(config->bridge_id);
    p->designated_port = ntohs(config->port_id);
    stp_start_timer(&p->message_age_timer, ntohs(config->message_age));
}

static void
stp_record_config_timeout_values(struct stp *stp,
                                 const struct stp_config_bpdu  *config)
     OVS_REQUIRES(mutex)
{
    stp->max_age = ntohs(config->max_age);
    stp->hello_time = ntohs(config->hello_time);
    stp->forward_delay = ntohs(config->forward_delay);
    stp->topology_change = config->flags & STP_CONFIG_TOPOLOGY_CHANGE;
}

static bool
stp_is_designated_port(const struct stp_port *p) OVS_REQUIRES(mutex)
{
    return (p->designated_bridge == p->stp->bridge_id
            && p->designated_port == p->port_id);
}

static void
stp_config_bpdu_generation(struct stp *stp) OVS_REQUIRES(mutex)
{
    struct stp_port *p;

    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_is_designated_port(p)) {
            stp_transmit_config(p);
        }
    }
}

static void
stp_transmit_tcn(struct stp *stp) OVS_REQUIRES(mutex)
{
    struct stp_port *p = stp->root_port;
    struct stp_tcn_bpdu tcn_bpdu;
    if (!p) {
        return;
    }
    tcn_bpdu.header.protocol_id = htons(STP_PROTOCOL_ID);
    tcn_bpdu.header.protocol_version = STP_PROTOCOL_VERSION;
    tcn_bpdu.header.bpdu_type = STP_TYPE_TCN;
    stp_send_bpdu(p, &tcn_bpdu, sizeof tcn_bpdu);
}

static void
stp_configuration_update(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp_root_selection(stp);
    stp_designated_port_selection(stp);
    seq_change(connectivity_seq_get());
}

static bool
stp_supersedes_root(const struct stp_port *root, const struct stp_port *p)
    OVS_REQUIRES(mutex)
{
    int p_cost = p->designated_cost + p->path_cost;
    int root_cost = root->designated_cost + root->path_cost;

    if (p->designated_root != root->designated_root) {
        return p->designated_root < root->designated_root;
    } else if (p_cost != root_cost) {
        return p_cost < root_cost;
    } else if (p->designated_bridge != root->designated_bridge) {
        return p->designated_bridge < root->designated_bridge;
    } else if (p->designated_port != root->designated_port) {
        return p->designated_port < root->designated_port;
    } else {
        return p->port_id < root->port_id;
    }
}

static void
stp_root_selection(struct stp *stp) OVS_REQUIRES(mutex)
{
    struct stp_port *p, *root;

    root = NULL;
    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_is_designated_port(p)
            || p->designated_root >= stp->bridge_id) {
            continue;
        }
        if (root && !stp_supersedes_root(root, p)) {
            continue;
        }
        root = p;
    }
    stp->root_port = root;
    if (!root) {
        stp->designated_root = stp->bridge_id;
        stp->root_path_cost = 0;
    } else {
        stp->designated_root = root->designated_root;
        stp->root_path_cost = root->designated_cost + root->path_cost;
    }
}

static void
stp_designated_port_selection(struct stp *stp) OVS_REQUIRES(mutex)
{
    struct stp_port *p;

    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_is_designated_port(p)
            || p->designated_root != stp->designated_root
            || stp->root_path_cost < p->designated_cost
            || (stp->root_path_cost == p->designated_cost
                && (stp->bridge_id < p->designated_bridge
                    || (stp->bridge_id == p->designated_bridge
                        && p->port_id <= p->designated_port))))
        {
            stp_become_designated_port(p);
        }
    }
}

static void
stp_become_designated_port(struct stp_port *p) OVS_REQUIRES(mutex)
{
    struct stp *stp = p->stp;
    p->designated_root = stp->designated_root;
    p->designated_cost = stp->root_path_cost;
    p->designated_bridge = stp->bridge_id;
    p->designated_port = p->port_id;
}

static void
stp_port_state_selection(struct stp *stp) OVS_REQUIRES(mutex)
{
    struct stp_port *p;

    FOR_EACH_ENABLED_PORT (p, stp) {
        if (p == stp->root_port) {
            p->config_pending = false;
            p->topology_change_ack = false;
            stp_make_forwarding(p);
        } else if (stp_is_designated_port(p)) {
            stp_stop_timer(&p->message_age_timer);
            stp_make_forwarding(p);
        } else {
            p->config_pending = false;
            p->topology_change_ack = false;
            stp_make_blocking(p);
        }
    }
}

static void
stp_make_forwarding(struct stp_port *p) OVS_REQUIRES(mutex)
{
    if (p->state == STP_BLOCKING) {
        stp_set_port_state(p, STP_LISTENING);
        stp_start_timer(&p->forward_delay_timer, 0);
    }
}

static void
stp_make_blocking(struct stp_port *p) OVS_REQUIRES(mutex)
{
    if (!(p->state & (STP_DISABLED | STP_BLOCKING))) {
        if (p->state & (STP_FORWARDING | STP_LEARNING)) {
            if (p->change_detection_enabled) {
                stp_topology_change_detection(p->stp);
            }
        }
        stp_set_port_state(p, STP_BLOCKING);
        stp_stop_timer(&p->forward_delay_timer);
    }
}

static void
stp_set_port_state(struct stp_port *p, enum stp_state state)
    OVS_REQUIRES(mutex)
{
    if (state != p->state && !p->state_changed) {
        p->state_changed = true;
        if (p < p->stp->first_changed_port) {
            p->stp->first_changed_port = p;
        }
        seq_change(connectivity_seq_get());
    }
    p->state = state;
}

static void
stp_topology_change_detection(struct stp *stp) OVS_REQUIRES(mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (stp_is_root_bridge(stp)) {
        stp->topology_change = true;
        stp_start_timer(&stp->topology_change_timer, 0);
    } else if (!stp->topology_change_detected) {
        stp_transmit_tcn(stp);
        stp_start_timer(&stp->tcn_timer, 0);
    }
    stp->fdb_needs_flush = true;
    stp->topology_change_detected = true;
    seq_change(connectivity_seq_get());
    VLOG_INFO_RL(&rl, "%s: detected topology change.", stp->name);
}

static void
stp_topology_change_acknowledged(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp->topology_change_detected = false;
    stp_stop_timer(&stp->tcn_timer);
}

static void
stp_acknowledge_topology_change(struct stp_port *p) OVS_REQUIRES(mutex)
{
    p->topology_change_ack = true;
    stp_transmit_config(p);
}

static void
stp_received_config_bpdu(struct stp *stp, struct stp_port *p,
                         const struct stp_config_bpdu *config)
    OVS_REQUIRES(mutex)
{
    if (ntohs(config->message_age) >= ntohs(config->max_age)) {
        VLOG_WARN("%s: received config BPDU with message age (%u) greater "
                  "than max age (%u)",
                  stp->name,
                  ntohs(config->message_age), ntohs(config->max_age));
        return;
    }
    if (p->state != STP_DISABLED) {
        bool root = stp_is_root_bridge(stp);
        if (stp_supersedes_port_info(p, config)) {
            stp_record_config_information(p, config);
            stp_configuration_update(stp);
            stp_port_state_selection(stp);
            if (!stp_is_root_bridge(stp) && root) {
                stp_stop_timer(&stp->hello_timer);
                if (stp->topology_change_detected) {
                    stp_stop_timer(&stp->topology_change_timer);
                    stp_transmit_tcn(stp);
                    stp_start_timer(&stp->tcn_timer, 0);
                }
            }
            if (p == stp->root_port) {
                stp_record_config_timeout_values(stp, config);
                stp_config_bpdu_generation(stp);
                if (config->flags & STP_CONFIG_TOPOLOGY_CHANGE_ACK) {
                    stp_topology_change_acknowledged(stp);
                }
                if (config->flags & STP_CONFIG_TOPOLOGY_CHANGE) {
                    stp->fdb_needs_flush = true;
                }
            }
        } else if (stp_is_designated_port(p)) {
            stp_transmit_config(p);
        }
    }
}

static void
stp_received_tcn_bpdu(struct stp *stp, struct stp_port *p)
    OVS_REQUIRES(mutex)
{
    if (p->state != STP_DISABLED) {
        if (stp_is_designated_port(p)) {
            stp_topology_change_detection(stp);
            stp_acknowledge_topology_change(p);
        }
    }
}

static void
stp_hello_timer_expiry(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp_config_bpdu_generation(stp);
    stp_start_timer(&stp->hello_timer, 0);
}

static void
stp_message_age_timer_expiry(struct stp_port *p) OVS_REQUIRES(mutex)
{
    struct stp *stp = p->stp;
    bool root = stp_is_root_bridge(stp);
    stp_become_designated_port(p);
    stp_configuration_update(stp);
    stp_port_state_selection(stp);
    if (stp_is_root_bridge(stp) && !root) {
        stp->max_age = stp->bridge_max_age;
        stp->hello_time = stp->bridge_hello_time;
        stp->forward_delay = stp->bridge_forward_delay;
        stp_topology_change_detection(stp);
        stp_stop_timer(&stp->tcn_timer);
        stp_config_bpdu_generation(stp);
        stp_start_timer(&stp->hello_timer, 0);
    }
}

static bool
stp_is_designated_for_some_port(const struct stp *stp) OVS_REQUIRES(mutex)
{
    const struct stp_port *p;

    FOR_EACH_ENABLED_PORT (p, stp) {
        if (p->designated_bridge == stp->bridge_id) {
            return true;
        }
    }
    return false;
}

static void
stp_forward_delay_timer_expiry(struct stp_port *p) OVS_REQUIRES(mutex)
{
    if (p->state == STP_LISTENING) {
        stp_set_port_state(p, STP_LEARNING);
        stp_start_timer(&p->forward_delay_timer, 0);
    } else if (p->state == STP_LEARNING) {
        stp_set_port_state(p, STP_FORWARDING);
        if (stp_is_designated_for_some_port(p->stp)) {
            if (p->change_detection_enabled) {
                stp_topology_change_detection(p->stp);
            }
        }
    }
}

static void
stp_tcn_timer_expiry(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp_transmit_tcn(stp);
    stp_start_timer(&stp->tcn_timer, 0);
}

static void
stp_topology_change_timer_expiry(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp->topology_change_detected = false;
    stp->topology_change = false;
}

static void
stp_hold_timer_expiry(struct stp_port *p) OVS_REQUIRES(mutex)
{
    if (p->config_pending) {
        stp_transmit_config(p);
    }
}

static void
stp_initialize_port(struct stp_port *p, enum stp_state state)
    OVS_REQUIRES(mutex)
{
    ovs_assert(state & (STP_DISABLED | STP_BLOCKING));
    stp_become_designated_port(p);
    stp_set_port_state(p, state);
    p->topology_change_ack = false;
    p->config_pending = false;
    p->change_detection_enabled = true;
    p->aux = NULL;
    stp_stop_timer(&p->message_age_timer);
    stp_stop_timer(&p->forward_delay_timer);
    stp_stop_timer(&p->hold_timer);
    p->tx_count = p->rx_count = p->error_count = 0;
}

static void
stp_become_root_bridge(struct stp *stp) OVS_REQUIRES(mutex)
{
    stp->max_age = stp->bridge_max_age;
    stp->hello_time = stp->bridge_hello_time;
    stp->forward_delay = stp->bridge_forward_delay;
    stp_topology_change_detection(stp);
    stp_stop_timer(&stp->tcn_timer);
    stp_config_bpdu_generation(stp);
    stp_start_timer(&stp->hello_timer, 0);
}

static void
stp_start_timer(struct stp_timer *timer, int value) OVS_REQUIRES(mutex)
{
    timer->value = value;
    timer->active = true;
}

static void
stp_stop_timer(struct stp_timer *timer) OVS_REQUIRES(mutex)
{
    timer->active = false;
}

static bool
stp_timer_expired(struct stp_timer *timer, int elapsed, int timeout)
    OVS_REQUIRES(mutex)
{
    if (timer->active) {
        timer->value += elapsed;
        if (timer->value >= timeout) {
            timer->active = false;
            return true;
        }
    }
    return false;
}

/* Returns the number of whole STP timer ticks in 'ms' milliseconds.  There
 * are 256 STP timer ticks per second. */
static int
ms_to_timer(int ms)
{
    return ms * 0x100 / 1000;
}

/* Returns the number of whole milliseconds in 'timer' STP timer ticks.  There
 * are 256 STP timer ticks per second. */
static int
timer_to_ms(int timer)
{
    return timer * 1000 / 0x100;
}

static int
clamp(int x, int min, int max)
{
    return x < min ? min : x > max ? max : x;
}

static void
stp_update_bridge_timers(struct stp *stp) OVS_REQUIRES(mutex)
{
    int ht, ma, fd;

    ht = clamp(stp->rq_hello_time, 1000, 10000);
    ma = clamp(stp->rq_max_age, MAX(2 * (ht + 1000), 6000), 40000);
    fd = clamp(stp->rq_forward_delay, ma / 2 + 1000, 30000);

    stp->bridge_hello_time = ms_to_timer(ht);
    stp->bridge_max_age = ms_to_timer(ma);
    stp->bridge_forward_delay = ms_to_timer(fd);

    if (stp_is_root_bridge(stp)) {
        stp->max_age = stp->bridge_max_age;
        stp->hello_time = stp->bridge_hello_time;
        stp->forward_delay = stp->bridge_forward_delay;
    }
}

static void
stp_send_bpdu(struct stp_port *p, const void *bpdu, size_t bpdu_size)
    OVS_REQUIRES(mutex)
{
    struct eth_header *eth;
    struct llc_header *llc;
    struct ofpbuf *pkt;

    /* Skeleton. */
    pkt = ofpbuf_new(ETH_HEADER_LEN + LLC_HEADER_LEN + bpdu_size);
    pkt->l2 = eth = ofpbuf_put_zeros(pkt, sizeof *eth);
    llc = ofpbuf_put_zeros(pkt, sizeof *llc);
    pkt->l3 = ofpbuf_put(pkt, bpdu, bpdu_size);

    /* 802.2 header. */
    memcpy(eth->eth_dst, eth_addr_stp, ETH_ADDR_LEN);
    /* p->stp->send_bpdu() must fill in source address. */
    eth->eth_type = htons(pkt->size - ETH_HEADER_LEN);

    /* LLC header. */
    llc->llc_dsap = STP_LLC_DSAP;
    llc->llc_ssap = STP_LLC_SSAP;
    llc->llc_cntl = STP_LLC_CNTL;

    p->stp->send_bpdu(pkt, stp_port_no(p), p->stp->aux);
    p->tx_count++;
}

/* Unixctl. */

static struct stp *
stp_find(const char *name) OVS_REQUIRES(mutex)
{
    struct stp *stp;

    LIST_FOR_EACH (stp, node, all_stps) {
        if (!strcmp(stp->name, name)) {
            return stp;
        }
    }
    return NULL;
}

static void
stp_unixctl_tcn(struct unixctl_conn *conn, int argc,
                const char *argv[], void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        struct stp *stp = stp_find(argv[1]);

        if (!stp) {
            unixctl_command_reply_error(conn, "no such stp object");
            goto out;
        }
        stp_topology_change_detection(stp);
    } else {
        struct stp *stp;

        LIST_FOR_EACH (stp, node, all_stps) {
            stp_topology_change_detection(stp);
        }
    }

    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&mutex);
}
