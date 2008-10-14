/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* Based on sample implementation in 802.1D-1998.  Above copyright and license
 * applies to all modifications. */

#include "stp.h"
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include "packets.h"
#include "util.h"
#include "xtoxll.h"

#include "vlog.h"
#define THIS_MODULE VLM_stp

/* Ethernet address used as the destination for STP frames. */
const uint8_t stp_eth_addr[ETH_ADDR_LEN]
= { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

#define STP_PROTOCOL_ID 0x0000
#define STP_PROTOCOL_VERSION 0x00
#define STP_TYPE_CONFIG 0x00
#define STP_TYPE_TCN 0x80

struct stp_bpdu_header {
    uint16_t protocol_id;       /* STP_PROTOCOL_ID. */
    uint8_t protocol_version;   /* STP_PROTOCOL_VERSION. */
    uint8_t bpdu_type;          /* One of STP_TYPE_*. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct stp_bpdu_header) == 4);

enum stp_config_bpdu_flags {
    STP_CONFIG_TOPOLOGY_CHANGE_ACK = 0x80,
    STP_CONFIG_TOPOLOGY_CHANGE = 0x01
};

struct stp_config_bpdu {
    struct stp_bpdu_header header; /* Type STP_TYPE_CONFIG. */
    uint8_t flags;                 /* STP_CONFIG_* flags. */
    uint64_t root_id;              /* 8.5.1.1: Bridge believed to be root. */
    uint32_t root_path_cost;       /* 8.5.1.2: Cost of path to root. */
    uint64_t bridge_id;            /* 8.5.1.3: ID of transmitting bridge. */
    uint16_t port_id;              /* 8.5.1.4: Port transmitting the BPDU. */
    uint16_t message_age;          /* 8.5.1.5: Age of BPDU at tx time. */
    uint16_t max_age;              /* 8.5.1.6: Timeout for received data. */
    uint16_t hello_time;           /* 8.5.1.7: Time between BPDU generation. */
    uint16_t forward_delay;        /* 8.5.1.8: State progression delay. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct stp_config_bpdu) == 35);

struct stp_tcn_bpdu {
    struct stp_bpdu_header header; /* Type STP_TYPE_TCN. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct stp_tcn_bpdu) == 4);

struct stp_timer {
    bool active;                 /* Timer in use? */
    int value;                   /* Current value of timer, counting up. */
};

struct stp_port {
    struct stp *stp;
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

    bool state_changed;
};

struct stp {
    /* Static bridge data. */
    char *name;                     /* Human-readable name for log messages. */
    stp_identifier bridge_id;       /* 8.5.3.7: This bridge. */
    int max_age;                    /* 8.5.3.4: Time to drop received data. */
    int hello_time;                 /* 8.5.3.5: Time between sending BPDUs. */
    int forward_delay;              /* 8.5.3.6: Delay between state changes. */
    int bridge_max_age;             /* 8.5.3.8: max_age when we're root. */
    int bridge_hello_time;          /* 8.5.3.9: hello_time as root. */
    int bridge_forward_delay;       /* 8.5.3.10: forward_delay as root. */

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
    struct stp_port *first_changed_port;
    void (*send_bpdu)(const void *bpdu, size_t bpdu_size,
                      int port_no, void *aux);
    void *aux;
};

#define FOR_EACH_ENABLED_PORT(PORT, STP)                        \
    for ((PORT) = stp_next_enabled_port((STP), (STP)->ports);   \
         (PORT);                                                \
         (PORT) = stp_next_enabled_port((STP), (PORT) + 1))
static struct stp_port *
stp_next_enabled_port(const struct stp *stp, const struct stp_port *port)
{
    for (; port < &stp->ports[ARRAY_SIZE(stp->ports)]; port++) {
        if (port->state != STP_DISABLED) {
            return (struct stp_port *) port;
        }
    }
    return NULL;
}

#define SECONDS_TO_TIMER(SECS) ((SECS) * 0x100)

#define MESSAGE_AGE_INCREMENT 1

static void stp_transmit_config(struct stp_port *);
static bool stp_supersedes_port_info(const struct stp_port *,
                                     const struct stp_config_bpdu *);
static void stp_record_config_information(struct stp_port *,
                                          const struct stp_config_bpdu *);
static void stp_record_config_timeout_values(struct stp *,
                                             const struct stp_config_bpdu  *);
static bool stp_is_designated_port(const struct stp_port *);
static void stp_config_bpdu_generation(struct stp *);
static void stp_transmit_tcn(struct stp *);
static void stp_configuration_update(struct stp *);
static bool stp_supersedes_root(const struct stp_port *root,
                                const struct stp_port *);
static void stp_root_selection(struct stp *);
static void stp_designated_port_selection(struct stp *);
static void stp_become_designated_port(struct stp_port *);
static void stp_port_state_selection(struct stp *);
static void stp_make_forwarding(struct stp_port *);
static void stp_make_blocking(struct stp_port *);
static void stp_set_port_state(struct stp_port *, enum stp_state);
static void stp_topology_change_detection(struct stp *);
static void stp_topology_change_acknowledged(struct stp *);
static void stp_acknowledge_topology_change(struct stp_port *);
static void stp_received_config_bpdu(struct stp *, struct stp_port *,
                                     const struct stp_config_bpdu *);
static void stp_received_tcn_bpdu(struct stp *, struct stp_port *,
                                  const struct stp_tcn_bpdu *);
static void stp_hello_timer_expiry(struct stp *);
static void stp_message_age_timer_expiry(struct stp_port *);
static bool stp_is_designated_for_some_port(const struct stp *);
static void stp_forward_delay_timer_expiry(struct stp_port *);
static void stp_tcn_timer_expiry(struct stp *);
static void stp_topology_change_timer_expiry(struct stp *);
static void stp_hold_timer_expiry(struct stp_port *);
static void stp_initialize_port(struct stp_port *, enum stp_state);
static void stp_become_root_bridge(struct stp *stp);

static void stp_start_timer(struct stp_timer *, int value);
static void stp_stop_timer(struct stp_timer *);
static bool stp_timer_expired(struct stp_timer *, int elapsed, int timeout);

/* Creates and returns a new STP instance that initially has no port enabled.
 *
 * 'bridge_id' should be a 48-bit MAC address as returned by
 * eth_addr_to_uint64().  'bridge_id' may also have a priority value in its top
 * 16 bits; if those bits are set to 0, the default bridge priority of 32768 is
 * used.  (This priority may be changed with stp_set_bridge_priority().)
 *
 * When the bridge needs to send out a BPDU, it calls 'send_bpdu', passing
 * 'aux' as auxiliary data.  This callback may be called from stp_tick() or
 * stp_received_bpdu().
 */
struct stp *
stp_create(const char *name, stp_identifier bridge_id,
           void (*send_bpdu)(const void *bpdu, size_t bpdu_size,
                             int port_no, void *aux),
           void *aux)
{
    struct stp *stp;
    struct stp_port *p;

    stp = xcalloc(1, sizeof *stp);
    stp->name = xstrdup(name);
    stp->bridge_id = bridge_id;
    if (!(stp->bridge_id >> 48)) {
        stp->bridge_id |= UINT64_C(32768) << 48;
    }
    stp->max_age = SECONDS_TO_TIMER(6);
    stp->hello_time = SECONDS_TO_TIMER(2);
    stp->forward_delay = SECONDS_TO_TIMER(4);
    stp->bridge_max_age = stp->max_age;
    stp->bridge_hello_time = stp->hello_time;
    stp->bridge_forward_delay = stp->forward_delay;

    /* Verify constraints stated by 802.1D. */
    assert(2 * (stp->forward_delay - SECONDS_TO_TIMER(1)) >= stp->max_age);
    assert(stp->max_age >= 2 * (stp->hello_time + SECONDS_TO_TIMER(1)));

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
        p->port_id = (stp_port_no(p) + 1) | (128 << 8);
        p->path_cost = 19;      /* Recommended default for 100 Mb/s link. */
        stp_initialize_port(p, STP_DISABLED);
    }
    return stp;
}

/* Destroys 'stp'. */
void
stp_destroy(struct stp *stp)
{
    free(stp);
}

void
stp_tick(struct stp *stp, int elapsed)
{
    struct stp_port *p;

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
        if (stp_timer_expired(&p->hold_timer, elapsed, SECONDS_TO_TIMER(1))) {
            stp_hold_timer_expiry(p);
        }
    }
}

static void
set_bridge_id(struct stp *stp, stp_identifier new_bridge_id)
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
    set_bridge_id(stp, (stp->bridge_id & pri_bits) | (bridge_id & mac_bits));
}

void
stp_set_bridge_priority(struct stp *stp, uint16_t new_priority)
{
    const uint64_t mac_bits = (UINT64_C(1) << 48) - 1;
    set_bridge_id(stp, ((stp->bridge_id & mac_bits)
                        | ((uint64_t) new_priority << 48)));
}

/* Returns the name given to 'stp' in the call to stp_create(). */
const char *
stp_get_name(const struct stp *stp)
{
    return stp->name;
}

/* Returns the bridge ID for 'stp'. */
stp_identifier
stp_get_bridge_id(const struct stp *stp)
{
    return stp->bridge_id;
}

/* Returns the bridge ID of the bridge currently believed to be the root. */
stp_identifier
stp_get_designated_root(const struct stp *stp)
{
    return stp->designated_root;
}

/* Returns true if 'stp' believes itself to the be root of the spanning tree,
 * false otherwise. */
bool
stp_is_root_bridge(const struct stp *stp)
{
    return stp->bridge_id == stp->designated_root;
}

/* Returns the cost of the path from 'stp' to the root of the spanning tree. */
int
stp_get_root_path_cost(const struct stp *stp)
{
    return stp->root_path_cost;
}

/* Returns the port in 'stp' with index 'port_no', which must be between 0 and
 * STP_MAX_PORTS. */
struct stp_port *
stp_get_port(struct stp *stp, int port_no)
{
    assert(port_no >= 0 && port_no < ARRAY_SIZE(stp->ports));
    return &stp->ports[port_no];
}

/* Returns the port connecting 'stp' to the root bridge, or a null pointer if
 * there is no such port. */
struct stp_port *
stp_get_root_port(struct stp *stp)
{
    return stp->root_port;
}

/* Finds a port whose state has changed.  If successful, stores the port whose
 * state changed in '*portp' and returns true.  If no port has changed, stores
 * NULL in '*portp' and returns false. */
bool
stp_get_changed_port(struct stp *stp, struct stp_port **portp)
{
    struct stp_port *end = &stp->ports[ARRAY_SIZE(stp->ports)];
    struct stp_port *p;

    for (p = stp->first_changed_port; p < end; p++) {
        if (p->state_changed) {
            p->state_changed = false;
            stp->first_changed_port = p + 1;
            *portp = p;
            return true;
        }
    }
    stp->first_changed_port = end;
    *portp = NULL;
    return false;
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
        NOT_REACHED();
    }
}

/* Returns true if 'state' is one in which packets received on a port should
 * be forwarded, false otherwise. */
bool
stp_forward_in_state(enum stp_state state)
{
    return state == STP_FORWARDING;
}

/* Returns true if 'state' is one in which MAC learning should be done on
 * packets received on a port, false otherwise. */
bool
stp_learn_in_state(enum stp_state state)
{
    return state & (STP_LEARNING | STP_FORWARDING);
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

    if (p->state == STP_DISABLED) {
        return;
    }

    if (bpdu_size < sizeof(struct stp_bpdu_header)) {
        VLOG_WARN("%s: received runt %zu-byte BPDU", stp->name, bpdu_size);
        return;
    }

    header = bpdu;
    if (header->protocol_id != htons(STP_PROTOCOL_ID)) {
        VLOG_WARN("%s: received BPDU with unexpected protocol ID %"PRIu16,
                  stp->name, ntohs(header->protocol_id));
        return;
    }
    if (header->protocol_version != STP_PROTOCOL_VERSION) {
        VLOG_DBG("%s: received BPDU with unexpected protocol version %"PRIu8,
                 stp->name, header->protocol_version);
    }

    switch (header->bpdu_type) {
    case STP_TYPE_CONFIG:
        if (bpdu_size < sizeof(struct stp_config_bpdu)) {
            VLOG_WARN("%s: received config BPDU with invalid size %zu",
                      stp->name, bpdu_size);
            return;
        }
        stp_received_config_bpdu(stp, p, bpdu);
        break;

    case STP_TYPE_TCN:
        if (bpdu_size != sizeof(struct stp_tcn_bpdu)) {
            VLOG_WARN("%s: received TCN BPDU with invalid size %zu",
                      stp->name, bpdu_size);
            return;
        }
        stp_received_tcn_bpdu(stp, p, bpdu);
        break;

    default:
        VLOG_WARN("%s: received BPDU of unexpected type %"PRIu8,
                  stp->name, header->bpdu_type);
        return;
    }
}

/* Returns the STP entity in which 'p' is nested. */
struct stp *
stp_port_get_stp(struct stp_port *p)
{
    return p->stp;
}

/* Returns the index of port 'p' within its bridge. */
int
stp_port_no(const struct stp_port *p)
{
    struct stp *stp = p->stp;
    assert(p >= stp->ports && p < &stp->ports[ARRAY_SIZE(stp->ports)]);
    return p - stp->ports;
}

/* Returns the state of port 'p'. */
enum stp_state
stp_port_get_state(const struct stp_port *p)
{
    return p->state;
}

/* Disables STP on port 'p'. */
void
stp_port_disable(struct stp_port *p)
{
    struct stp *stp = p->stp;
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
    }
}

/* Enables STP on port 'p'.  The port will initially be in "blocking" state. */
void
stp_port_enable(struct stp_port *p)
{
    if (p->state == STP_DISABLED) {
        stp_initialize_port(p, STP_BLOCKING);
        stp_port_state_selection(p->stp);
    }
}

/* Sets the priority of port 'p' to 'new_priority'.  Lower numerical values
 * are interpreted as higher priorities. */
void
stp_port_set_priority(struct stp_port *p, uint8_t new_priority)
{
    uint16_t new_port_id = (p->port_id & 0xff) | (new_priority << 8);
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
}

/* Sets the path cost of port 'p' to 'path_cost'.  Lower values are generally
 * used to indicate faster links.  Use stp_port_set_speed() to automatically
 * generate a default path cost from a link speed. */
void
stp_port_set_path_cost(struct stp_port *p, unsigned int path_cost)
{
    if (p->path_cost != path_cost) {
        struct stp *stp = p->stp;
        p->path_cost = path_cost;
        stp_configuration_update(stp);
        stp_port_state_selection(stp);
    }
}

/* Sets the path cost of port 'p' based on 'speed' (measured in Mb/s). */
void
stp_port_set_speed(struct stp_port *p, unsigned int speed)
{
    stp_port_set_path_cost(p, (speed >= 10000 ? 2  /* 10 Gb/s. */
                               : speed >= 1000 ? 4 /* 1 Gb/s. */
                               : speed >= 100 ? 19 /* 100 Mb/s. */
                               : speed >= 16 ? 62  /* 16 Mb/s. */
                               : speed >= 10 ? 100 /* 10 Mb/s. */
                               : speed >= 4 ? 250  /* 4 Mb/s. */
                               : 19));             /* 100 Mb/s (guess). */
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
stp_transmit_config(struct stp_port *p)
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
            config.flags |= htons(STP_CONFIG_TOPOLOGY_CHANGE_ACK);
        }
        if (stp->topology_change) {
            config.flags |= htons(STP_CONFIG_TOPOLOGY_CHANGE);
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
            stp->send_bpdu(&config, sizeof config, stp_port_no(p), stp->aux);
            stp_start_timer(&p->hold_timer, 0);
        }
    }
}

static bool
stp_supersedes_port_info(const struct stp_port *p,
                         const struct stp_config_bpdu *config)
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
{
    stp->max_age = ntohs(config->max_age);
    stp->hello_time = ntohs(config->hello_time);
    stp->forward_delay = ntohs(config->forward_delay);
    stp->topology_change = config->flags & htons(STP_CONFIG_TOPOLOGY_CHANGE);
}

static bool
stp_is_designated_port(const struct stp_port *p)
{
    return (p->designated_bridge == p->stp->bridge_id
            && p->designated_port == p->port_id);
}

static void
stp_config_bpdu_generation(struct stp *stp)
{
    struct stp_port *p;

    FOR_EACH_ENABLED_PORT (p, stp) {
        if (stp_is_designated_port(p)) {
            stp_transmit_config(p);
        }
    }
}

static void
stp_transmit_tcn(struct stp *stp)
{
    struct stp_port *p = stp->root_port;
    struct stp_tcn_bpdu tcn_bpdu;
    if (!p) {
        return;
    }
    tcn_bpdu.header.protocol_id = htons(STP_PROTOCOL_ID);
    tcn_bpdu.header.protocol_version = STP_PROTOCOL_VERSION;
    tcn_bpdu.header.bpdu_type = STP_TYPE_TCN;
    stp->send_bpdu(&tcn_bpdu, sizeof tcn_bpdu, stp_port_no(p), stp->aux);
}

static void
stp_configuration_update(struct stp *stp)
{
    stp_root_selection(stp);
    stp_designated_port_selection(stp);
}

static bool
stp_supersedes_root(const struct stp_port *root, const struct stp_port *p)
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
stp_root_selection(struct stp *stp)
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
stp_designated_port_selection(struct stp *stp)
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
stp_become_designated_port(struct stp_port *p)
{
    struct stp *stp = p->stp;
    p->designated_root = stp->designated_root;
    p->designated_cost = stp->root_path_cost;
    p->designated_bridge = stp->bridge_id;
    p->designated_port = p->port_id;
}

static void
stp_port_state_selection(struct stp *stp)
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
stp_make_forwarding(struct stp_port *p)
{
    if (p->state == STP_BLOCKING) {
        stp_set_port_state(p, STP_LISTENING);
        stp_start_timer(&p->forward_delay_timer, 0);
    }
}

static void
stp_make_blocking(struct stp_port *p)
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
{
    if (state != p->state && !p->state_changed) {
        p->state_changed = true;
        if (p < p->stp->first_changed_port) {
            p->stp->first_changed_port = p;
        }
    }
    p->state = state;
}

static void
stp_topology_change_detection(struct stp *stp)
{
    if (stp_is_root_bridge(stp)) {
        stp->topology_change = true;
        stp_start_timer(&stp->topology_change_timer, 0);
    } else if (!stp->topology_change_detected) {
        stp_transmit_tcn(stp);
        stp_start_timer(&stp->tcn_timer, 0);
    }
    stp->topology_change_detected = true;
}

static void
stp_topology_change_acknowledged(struct stp *stp)
{
    stp->topology_change_detected = false;
    stp_stop_timer(&stp->tcn_timer);
}

static void
stp_acknowledge_topology_change(struct stp_port *p)
{
    p->topology_change_ack = true;
    stp_transmit_config(p);
}

void
stp_received_config_bpdu(struct stp *stp, struct stp_port *p,
                         const struct stp_config_bpdu *config)
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
                if (config->flags & htons(STP_CONFIG_TOPOLOGY_CHANGE_ACK)) {
                    stp_topology_change_acknowledged(stp);
                }
            }
        } else if (stp_is_designated_port(p)) {
            stp_transmit_config(p);
        }
    }
}

void
stp_received_tcn_bpdu(struct stp *stp, struct stp_port *p,
                      const struct stp_tcn_bpdu *tcn)
{
    if (p->state != STP_DISABLED) {
        if (stp_is_designated_port(p)) {
            stp_topology_change_detection(stp);
            stp_acknowledge_topology_change(p);
        }
    }
}

static void
stp_hello_timer_expiry(struct stp *stp)
{
    stp_config_bpdu_generation(stp);
    stp_start_timer(&stp->hello_timer, 0);
}

static void
stp_message_age_timer_expiry(struct stp_port *p)
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
stp_is_designated_for_some_port(const struct stp *stp)
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
stp_forward_delay_timer_expiry(struct stp_port *p)
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
stp_tcn_timer_expiry(struct stp *stp)
{
    stp_transmit_tcn(stp);
    stp_start_timer(&stp->tcn_timer, 0);
}

static void
stp_topology_change_timer_expiry(struct stp *stp)
{
    stp->topology_change_detected = false;
    stp->topology_change = false;
}

static void
stp_hold_timer_expiry(struct stp_port *p)
{
    if (p->config_pending) {
        stp_transmit_config(p);
    }
}

static void
stp_initialize_port(struct stp_port *p, enum stp_state state)
{
    assert(state & (STP_DISABLED | STP_BLOCKING));
    stp_become_designated_port(p);
    stp_set_port_state(p, state);
    p->topology_change_ack = false;
    p->config_pending = false;
    p->change_detection_enabled = true;
    stp_stop_timer(&p->message_age_timer);
    stp_stop_timer(&p->forward_delay_timer);
    stp_stop_timer(&p->hold_timer);
}

static void
stp_become_root_bridge(struct stp *stp)
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
stp_start_timer(struct stp_timer *timer, int value)
{
    timer->value = value;
    timer->active = true;
}

static void
stp_stop_timer(struct stp_timer *timer)
{
    timer->active = false;
}

static bool
stp_timer_expired(struct stp_timer *timer, int elapsed, int timeout)
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

