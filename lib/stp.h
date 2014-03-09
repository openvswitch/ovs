/*
 * Copyright (c) 2008, 2011 Nicira, Inc.
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

#ifndef STP_H
#define STP_H 1

/* This is an implementation of Spanning Tree Protocol as described in IEEE
 * 802.1D-1998, clauses 8 and 9.  Section numbers refer to this standard.  */

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "util.h"

struct ofpbuf;

/* LLC field values used for STP frames. */
#define STP_LLC_SSAP 0x42
#define STP_LLC_DSAP 0x42
#define STP_LLC_CNTL 0x03

/* Bridge and port priorities that should be used by default. */
#define STP_DEFAULT_BRIDGE_PRIORITY 32768
#define STP_DEFAULT_PORT_PRIORITY 128

/* Default time values. */
#define STP_DEFAULT_MAX_AGE    20000
#define STP_DEFAULT_HELLO_TIME 2000
#define STP_DEFAULT_FWD_DELAY  15000

/* Bridge identifier.  Top 16 bits are a priority value (numerically lower
 * values are higher priorities).  Bottom 48 bits are MAC address of bridge. */
typedef uint64_t stp_identifier;


#define STP_ID_FMT "%04"PRIx16".%012"PRIx64
#define STP_ID_ARGS(stp_id) \
    (uint16_t)((stp_id) >> 48), \
    (uint64_t)((stp_id) & 0xffffffffffffULL)

#define STP_PORT_ID_FMT "%04"PRIx16

/* Basic STP functionality. */
#define STP_MAX_PORTS 255
void stp_init(void);
struct stp *stp_create(const char *name, stp_identifier bridge_id,
                       void (*send_bpdu)(struct ofpbuf *bpdu, int port_no,
                                         void *aux),
                       void *aux);
struct stp *stp_ref(const struct stp *);
void stp_unref(struct stp *);
void stp_tick(struct stp *, int ms);
void stp_set_bridge_id(struct stp *, stp_identifier bridge_id);
void stp_set_bridge_priority(struct stp *, uint16_t new_priority);
void stp_set_hello_time(struct stp *, int ms);
void stp_set_max_age(struct stp *, int ms);
void stp_set_forward_delay(struct stp *, int ms);

/* STP properties. */
const char *stp_get_name(const struct stp *);
stp_identifier stp_get_bridge_id(const struct stp *);
stp_identifier stp_get_designated_root(const struct stp *);
bool stp_is_root_bridge(const struct stp *);
int stp_get_root_path_cost(const struct stp *);
int stp_get_hello_time(const struct stp *);
int stp_get_max_age(const struct stp *);
int stp_get_forward_delay(const struct stp *);
bool stp_check_and_reset_fdb_flush(struct stp *);

/* Obtaining STP ports. */
struct stp_port *stp_get_port(struct stp *, int port_no);
struct stp_port *stp_get_root_port(struct stp *);
bool stp_get_changed_port(struct stp *, struct stp_port **portp);

/* State of an STP port.
 *
 * A port is in exactly one state at any given time, but distinct bits are used
 * for states to allow testing for more than one state with a bit mask.
 *
 * The STP_DISABLED state means that the port is disabled by management.
 * In our implementation, this state means that the port does not
 * participate in the spanning tree, but it still forwards traffic as if
 * it were in the STP_FORWARDING state.  This may be different from
 * other implementations.
 *
 * The following diagram describes the various states and what they are
 * allowed to do in OVS:
 *
 *                     FWD  LRN  TX_BPDU RX_BPDU
 *                     ---  ---  ------- -------
 *        Disabled      Y    -      -       -
 *        Blocking      -    -      -       Y
 *        Listening     -    -      Y       Y
 *        Learning      -    Y      Y       Y
 *        Forwarding    Y    Y      Y       Y
 *
 * Once again, note that the disabled state forwards traffic, which is
 * likely different than the spec would indicate.
 */
enum stp_state {
    STP_DISABLED = 1 << 0,       /* 8.4.5: See note above. */
    STP_LISTENING = 1 << 1,      /* 8.4.2: Not learning or relaying frames. */
    STP_LEARNING = 1 << 2,       /* 8.4.3: Learning but not relaying frames. */
    STP_FORWARDING = 1 << 3,     /* 8.4.4: Learning and relaying frames. */
    STP_BLOCKING = 1 << 4        /* 8.4.1: Initial boot state. */
};
const char *stp_state_name(enum stp_state);
bool stp_forward_in_state(enum stp_state);
bool stp_learn_in_state(enum stp_state);
bool stp_listen_in_state(enum stp_state);

/* Role of an STP port. */
enum stp_role {
    STP_ROLE_ROOT,               /* Path to root bridge. */
    STP_ROLE_DESIGNATED,         /* Path to LAN segments. */
    STP_ROLE_ALTERNATE,          /* Backup path to root bridge. */
    STP_ROLE_DISABLED            /* Port does not participate in STP. */
};
const char *stp_role_name(enum stp_role);

void stp_received_bpdu(struct stp_port *, const void *bpdu, size_t bpdu_size);

struct stp *stp_port_get_stp(struct stp_port *);
void stp_port_set_aux(struct stp_port *, void *);
void *stp_port_get_aux(struct stp_port *);
int stp_port_no(const struct stp_port *);
int stp_port_get_id(const struct stp_port *);
enum stp_state stp_port_get_state(const struct stp_port *);
enum stp_role stp_port_get_role(const struct stp_port *);
void stp_port_get_counts(const struct stp_port *,
                         int *tx_count, int *rx_count, int *error_count);
void stp_port_enable(struct stp_port *);
void stp_port_disable(struct stp_port *);
void stp_port_set_priority(struct stp_port *, uint8_t new_priority);
uint16_t stp_convert_speed_to_cost(unsigned int speed);
void stp_port_set_path_cost(struct stp_port *, uint16_t path_cost);
void stp_port_set_speed(struct stp_port *, unsigned int speed);
void stp_port_enable_change_detection(struct stp_port *);
void stp_port_disable_change_detection(struct stp_port *);

#endif /* stp.h */
