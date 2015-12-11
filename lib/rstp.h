/*
 * Copyright (c) 2011-2015 M3S, Srl - Italy
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

/*
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) public interface (header
 * file).
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *         Carlo Andreotti <c.andreotti@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#ifndef RSTP_H
#define RSTP_H 1

#include <stdint.h>
#include <stdbool.h>
#include "compiler.h"
#include "util.h"

/* Thread Safety: Callers passing in RSTP and RSTP port object
 * pointers must hold a reference to the passed object to ensure that
 * the object does not become stale while it is being accessed. */

extern struct ovs_mutex rstp_mutex;

#define RSTP_MAX_PORTS 4095

struct dp_packet;

/* Bridge priority defaults [Table 17-2] */
#define RSTP_MIN_PRIORITY 0
#define RSTP_MAX_PRIORITY 61440
#define RSTP_PRIORITY_STEP 4096
#define RSTP_DEFAULT_PRIORITY 32768

/* Port priority defaults [Table 17-2] */
#define RSTP_MIN_PORT_PRIORITY 0
#define RSTP_MAX_PORT_PRIORITY 240
#define RSTP_STEP_PORT_PRIORITY 16
#define RSTP_DEFAULT_PORT_PRIORITY 128

/* Performance parameters defaults. [Table 7-5] and [Table 17-1]
 * These values are expressed in seconds.
 */
#define RSTP_DEFAULT_AGEING_TIME 300
#define RSTP_MIN_AGEING_TIME 10
#define RSTP_MAX_AGEING_TIME 1000000

#define RSTP_DEFAULT_BRIDGE_MAX_AGE 20
#define RSTP_MIN_BRIDGE_MAX_AGE 6
#define RSTP_MAX_BRIDGE_MAX_AGE 40

#define RSTP_DEFAULT_BRIDGE_FORWARD_DELAY 15
#define RSTP_MIN_BRIDGE_FORWARD_DELAY 4
#define RSTP_MAX_BRIDGE_FORWARD_DELAY 30

#define RSTP_DEFAULT_TRANSMIT_HOLD_COUNT 6
#define RSTP_MIN_TRANSMIT_HOLD_COUNT 1
#define RSTP_MAX_TRANSMIT_HOLD_COUNT 10

#define RSTP_BRIDGE_HELLO_TIME 2 /* Value is fixed [Table 17-1] */

#define RSTP_MIGRATE_TIME 3  /* Value is fixed [Table 17-1] */

/* Port path cost [Table 17-3] */
#define RSTP_MIN_PORT_PATH_COST 1
#define RSTP_MAX_PORT_PATH_COST 200000000
#define RSTP_DEFAULT_PORT_PATH_COST 200000

/* RSTP Bridge identifier [9.2.5].  Top four most significant bits are a
 * priority value. The next most significant twelve bits are a locally
 * assigned system ID extension. Bottom 48 bits are MAC address of bridge.
 */
typedef uint64_t rstp_identifier;

#define RSTP_ID_FMT "%01"PRIx8".%03"PRIx16".%012"PRIx64
#define RSTP_ID_ARGS(rstp_id) \
    (uint8_t)((rstp_id) >> 60), \
    (uint16_t)(((rstp_id) & 0x0fff000000000000ULL) >> 48), \
    (uint64_t)((rstp_id) & 0xffffffffffffULL)

#define RSTP_PORT_ID_FMT "%04"PRIx16

enum rstp_state {
    RSTP_DISABLED,
    RSTP_LEARNING,
    RSTP_FORWARDING,
    RSTP_DISCARDING
};

/* Force Protocol Version [17.13.4] */
enum rstp_force_protocol_version {
    FPV_STP_COMPATIBILITY = 0,
    FPV_DEFAULT = 2
};

enum rstp_port_role {
    ROLE_ROOT,
    ROLE_DESIGNATED,
    ROLE_ALTERNATE,
    ROLE_BACKUP,
    ROLE_DISABLED
};

enum rstp_admin_point_to_point_mac_state {
    RSTP_ADMIN_P2P_MAC_FORCE_FALSE,
    RSTP_ADMIN_P2P_MAC_FORCE_TRUE,
    RSTP_ADMIN_P2P_MAC_AUTO
};

struct rstp;
struct rstp_port;
struct ofproto_rstp_settings;

const char *rstp_state_name(enum rstp_state);
const char *rstp_port_role_name(enum rstp_port_role);
static inline bool rstp_forward_in_state(enum rstp_state);
static inline bool rstp_learn_in_state(enum rstp_state);
static inline bool rstp_should_manage_bpdu(enum rstp_state state);

void rstp_init(void)
    OVS_EXCLUDED(rstp_mutex);

struct rstp * rstp_create(const char *, rstp_identifier bridge_id,
                          void (*send_bpdu)(struct dp_packet *, void *port_aux,
                                            void *rstp_aux),
                          void *aux)
    OVS_EXCLUDED(rstp_mutex);

struct rstp *rstp_ref(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
void rstp_unref(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);

/* Functions used outside RSTP, to call functions defined in
   rstp-state-machines.h */
void rstp_tick_timers(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_received_bpdu(struct rstp_port *, const void *bpdu,
                             size_t bpdu_size)
    OVS_EXCLUDED(rstp_mutex);
void *rstp_check_and_reset_fdb_flush(struct rstp *, struct rstp_port **)
    OVS_EXCLUDED(rstp_mutex);
void *rstp_get_next_changed_port_aux(struct rstp *, struct rstp_port **)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_set_mac_operational(struct rstp_port *,
                                   bool new_mac_operational)
    OVS_EXCLUDED(rstp_mutex);
bool rstp_shift_root_learned_address(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
void *rstp_get_old_root_aux(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
void *rstp_get_new_root_aux(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
void rstp_reset_root_changed(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);

/* Bridge setters */
void rstp_set_bridge_address(struct rstp *, rstp_identifier bridge_address)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_priority(struct rstp *, int new_priority)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_ageing_time(struct rstp *, int new_ageing_time)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_force_protocol_version(struct rstp *,
                                            enum rstp_force_protocol_version)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_max_age(struct rstp *, int new_max_age)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_forward_delay(struct rstp *, int new_forward_delay)
    OVS_EXCLUDED(rstp_mutex);
void rstp_set_bridge_transmit_hold_count(struct rstp *,
                                         int new_transmit_hold_count)
    OVS_EXCLUDED(rstp_mutex);

/* Bridge getters */
const char * rstp_get_name(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
rstp_identifier rstp_get_root_id(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
rstp_identifier rstp_get_bridge_id(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
rstp_identifier rstp_get_designated_id(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
uint32_t rstp_get_root_path_cost(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
uint16_t rstp_get_designated_port_id(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
uint16_t rstp_get_bridge_port_id(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
struct rstp_port * rstp_get_root_port(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
rstp_identifier rstp_get_designated_root(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
bool rstp_is_root_bridge(const struct rstp *)
    OVS_EXCLUDED(rstp_mutex);

/* RSTP ports */
struct rstp_port * rstp_add_port(struct rstp *)
    OVS_EXCLUDED(rstp_mutex);
struct rstp_port *rstp_port_ref(const struct rstp_port *)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_unref(struct rstp_port *)
    OVS_EXCLUDED(rstp_mutex);

uint32_t rstp_convert_speed_to_cost(unsigned int speed);

void rstp_port_set(struct rstp_port *, uint16_t port_num, int priority,
                   uint32_t path_cost, bool is_admin_edge, bool is_auto_edge,
                   enum rstp_admin_point_to_point_mac_state admin_p2p_mac_state,
                   bool admin_port_state, bool do_mcheck, void *aux)
    OVS_EXCLUDED(rstp_mutex);

enum rstp_state rstp_port_get_state(const struct rstp_port *)
    OVS_EXCLUDED(rstp_mutex);

void rstp_port_get_status(const struct rstp_port *, uint16_t *id,
                          enum rstp_state *state, enum rstp_port_role *role,
                          rstp_identifier *designated_bridge_id,
                          uint16_t *designated_port_id,
                          uint32_t *designated_path_cost, int *tx_count,
                          int *rx_count, int *error_count, int *uptime)
    OVS_EXCLUDED(rstp_mutex);

void * rstp_get_port_aux__(struct rstp *rstp, uint16_t port_number)
    OVS_REQUIRES(rstp_mutex);


/* Internal API for rstp-state-machines.c */

void rstp_port_set_state__(struct rstp_port *, enum rstp_state state)
    OVS_REQUIRES(rstp_mutex);


/* Internal API for test-rstp.c */

struct rstp_port *rstp_get_port(struct rstp *rstp, uint16_t port_number)
    OVS_EXCLUDED(rstp_mutex);
void reinitialize_port(struct rstp_port *p)
    OVS_EXCLUDED(rstp_mutex);

int rstp_port_get_number(const struct rstp_port *)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_set_priority(struct rstp_port *port, int priority)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_set_aux(struct rstp_port *p, void *aux)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_set_path_cost(struct rstp_port *port, uint32_t path_cost)
    OVS_EXCLUDED(rstp_mutex);
void rstp_port_set_state(struct rstp_port *p, enum rstp_state state)
    OVS_EXCLUDED(rstp_mutex);


/* Inline functions. */
/* Returns true if 'state' is one in which BPDU packets should be received
 * and transmitted on a port, false otherwise.
 */
static inline bool
rstp_should_manage_bpdu(enum rstp_state state)
{
    return (state == RSTP_DISCARDING || state == RSTP_LEARNING ||
            state == RSTP_FORWARDING);
}

/* Returns true if 'state' is one in which packets received on a port should
 * be forwarded, false otherwise.
 */
static inline bool
rstp_forward_in_state(enum rstp_state state)
{
    return (state == RSTP_FORWARDING);
}

/* Returns true if 'state' is one in which MAC learning should be done on
 * packets received on a port, false otherwise.
 */
static inline bool
rstp_learn_in_state(enum rstp_state state)
{
    return (state == RSTP_LEARNING || state == RSTP_FORWARDING);
}

#endif /* rstp.h */
