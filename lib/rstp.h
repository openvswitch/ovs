/*
 * Copyright (c) 2011-2014 M3S, Srl - Italy
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

#define RSTP_MAX_PORTS 4095

struct ofpbuf;

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

struct rstp;
struct rstp_port;
struct ofproto_rstp_settings;

const char *rstp_state_name(enum rstp_state);
bool rstp_forward_in_state(enum rstp_state);
bool rstp_learn_in_state(enum rstp_state);
bool rstp_should_manage_bpdu(enum rstp_state state);
const char *rstp_port_role_name(enum rstp_port_role);

void rstp_init(void);

struct rstp * rstp_create(const char *, rstp_identifier bridge_id,
        void (*send_bpdu)(struct ofpbuf *, int port_no, void *),
                void *);
struct rstp *rstp_ref(struct rstp *);
void rstp_unref(struct rstp *);

/* Functions used outside RSTP, to call functions defined in
   rstp-state-machines.h */
void rstp_tick_timers(struct rstp *);
void rstp_received_bpdu(struct rstp_port *, const void *, size_t);

bool rstp_check_and_reset_fdb_flush(struct rstp *);
bool rstp_get_changed_port(struct rstp *, struct rstp_port **);
void rstp_port_set_mac_operational(struct rstp_port *,
                                   bool  new_mac_operational);
bool rstp_port_get_mac_operational(struct rstp_port *);

/* Bridge setters */
void rstp_set_bridge_address(struct rstp *, rstp_identifier bridge_address);
void rstp_set_bridge_priority(struct rstp *, int new_priority);
void rstp_set_bridge_ageing_time(struct rstp *, int new_ageing_time);
void rstp_set_bridge_force_protocol_version(struct rstp *,
                enum rstp_force_protocol_version new_force_protocol_version);
void rstp_set_bridge_hello_time(struct rstp *);
void rstp_set_bridge_max_age(struct rstp *, int new_max_age);
void rstp_set_bridge_forward_delay(struct rstp *, int new_forward_delay);
void rstp_set_bridge_transmit_hold_count(struct rstp *,
                                        int new_transmit_hold_count);
void rstp_set_bridge_migrate_time(struct rstp *);
void rstp_set_bridge_times(struct rstp *, int new_forward_delay,
                           int new_hello_time, int new_max_age,
                           int new_message_age);

struct rstp_port * rstp_add_port(struct rstp *);
void reinitialize_port(struct rstp_port *p);
void rstp_delete_port(struct rstp_port *);
/* Port setters */
void rstp_port_set_priority(struct rstp_port *, int new_port_priority);
void rstp_port_set_port_number(struct rstp_port *, uint16_t new_port_number);
uint32_t rstp_convert_speed_to_cost(unsigned int speed);
void rstp_port_set_path_cost(struct rstp_port *, uint32_t new_port_path_cost);
void rstp_port_set_admin_edge(struct rstp_port *, bool new_admin_edge);
void rstp_port_set_auto_edge(struct rstp_port *, bool new_auto_edge);
void rstp_port_set_state(struct rstp_port *, enum rstp_state new_state);
void rstp_port_set_aux(struct rstp_port *, void *aux);
void rstp_port_set_administrative_bridge_port(struct rstp_port *, uint8_t);
void rstp_port_set_oper_point_to_point_mac(struct rstp_port *, uint8_t);
void rstp_port_set_mcheck(struct rstp_port *, bool new_mcheck);

/* Bridge getters */
const char * rstp_get_name(const struct rstp *);
rstp_identifier rstp_get_root_id(const struct rstp *);
rstp_identifier rstp_get_bridge_id(const struct rstp *);
rstp_identifier rstp_get_designated_id(const struct rstp *);
uint32_t rstp_get_root_path_cost(const struct rstp *);
uint16_t rstp_get_designated_port_id(const struct rstp *);
uint16_t rstp_get_bridge_port_id(const struct rstp *);
struct rstp_port * rstp_get_root_port(struct rstp *);
rstp_identifier rstp_get_designated_root(const struct rstp *);
bool rstp_is_root_bridge(const struct rstp *);

/* Port getters */
int rstp_port_number(const struct rstp_port *);
struct rstp_port *rstp_get_port(struct rstp *, int port_no);
uint16_t rstp_port_get_id(const struct rstp_port *);
enum rstp_state rstp_port_get_state(const struct rstp_port *);
enum rstp_port_role rstp_port_get_role(const struct rstp_port *);
void rstp_port_get_counts(const struct rstp_port *, int *tx_count,
                          int *rx_count, int *error_count, int *uptime);
void * rstp_port_get_aux(struct rstp_port *);
#endif /* rstp.h */
