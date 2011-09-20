/*
 * Copyright (c) 2008, 2011 Nicira Networks.
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

/* Bridge identifier.  Top 16 bits are a priority value (numerically lower
 * values are higher priorities).  Bottom 48 bits are MAC address of bridge. */
typedef uint64_t stp_identifier;

/* Basic STP functionality. */
#define STP_MAX_PORTS 255
struct stp *stp_create(const char *name, stp_identifier bridge_id,
                       void (*send_bpdu)(struct ofpbuf *bpdu, int port_no,
                                         void *aux),
                       void *aux);
void stp_destroy(struct stp *);
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

/* Obtaining STP ports. */
struct stp_port *stp_get_port(struct stp *, int port_no);
struct stp_port *stp_get_root_port(struct stp *);
bool stp_get_changed_port(struct stp *, struct stp_port **portp);

/* State of an STP port.
 *
 * A port is in exactly one state at any given time, but distinct bits are used
 * for states to allow testing for more than one state with a bit mask. */
enum stp_state {
    STP_DISABLED = 1 << 0,       /* 8.4.5: Disabled by management. */
    STP_LISTENING = 1 << 1,      /* 8.4.2: Not learning or relaying frames. */
    STP_LEARNING = 1 << 2,       /* 8.4.3: Learning but not relaying frames. */
    STP_FORWARDING = 1 << 3,     /* 8.4.4: Learning and relaying frames. */
    STP_BLOCKING = 1 << 4        /* 8.4.1: Initial boot state. */
};
const char *stp_state_name(enum stp_state);
bool stp_forward_in_state(enum stp_state);
bool stp_learn_in_state(enum stp_state);

void stp_received_bpdu(struct stp_port *, const void *bpdu, size_t bpdu_size);

struct stp *stp_port_get_stp(struct stp_port *);
int stp_port_no(const struct stp_port *);
enum stp_state stp_port_get_state(const struct stp_port *);
void stp_port_enable(struct stp_port *);
void stp_port_disable(struct stp_port *);
void stp_port_set_priority(struct stp_port *, uint8_t new_priority);
void stp_port_set_path_cost(struct stp_port *, uint16_t path_cost);
void stp_port_set_speed(struct stp_port *, unsigned int speed);
void stp_port_enable_change_detection(struct stp_port *);
void stp_port_disable_change_detection(struct stp_port *);

#endif /* stp.h */
