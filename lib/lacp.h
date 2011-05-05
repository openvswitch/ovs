/*
 * Copyright (c) 2011 Nicira Networks.
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

#ifndef LACP_H
#define LACP_H 1

#include <stdbool.h>
#include <stdint.h>
#include "packets.h"

/* Masks for lacp_info state member. */
#define LACP_STATE_ACT  0x01 /* Activity. Active or passive? */
#define LACP_STATE_TIME 0x02 /* Timeout. Short or long timeout? */
#define LACP_STATE_AGG  0x04 /* Aggregation. Is the link is bondable? */
#define LACP_STATE_SYNC 0x08 /* Synchronization. Is the link in up to date? */
#define LACP_STATE_COL  0x10 /* Collecting. Is the link receiving frames? */
#define LACP_STATE_DIST 0x20 /* Distributing. Is the link sending frames? */
#define LACP_STATE_DEF  0x40 /* Defaulted. Using default partner info? */
#define LACP_STATE_EXP  0x80 /* Expired. Using expired partner info? */

#define LACP_FAST_TIME_TX 1000  /* Fast transmission rate. */
#define LACP_SLOW_TIME_TX 30000 /* Slow transmission rate. */
#define LACP_RX_MULTIPLIER 3    /* Multiply by TX rate to get RX rate. */

#define LACP_INFO_LEN 15
struct lacp_info {
    ovs_be16 sys_priority;            /* System priority. */
    uint8_t sys_id[ETH_ADDR_LEN];     /* System ID. */
    ovs_be16 key;                     /* Operational key. */
    ovs_be16 port_priority;           /* Port priority. */
    ovs_be16 port_id;                 /* Port ID. */
    uint8_t state;                    /* State mask.  See LACP_STATE macros. */
} __attribute__((packed));
BUILD_ASSERT_DECL(LACP_INFO_LEN == sizeof(struct lacp_info));

#define LACP_PDU_LEN 110
struct lacp_pdu {
    uint8_t subtype;          /* Always 1. */
    uint8_t version;          /* Always 1. */

    uint8_t actor_type;       /* Always 1. */
    uint8_t actor_len;        /* Always 20. */
    struct lacp_info actor;   /* LACP actor information. */
    uint8_t z1[3];            /* Reserved.  Always 0. */

    uint8_t partner_type;     /* Always 2. */
    uint8_t partner_len;      /* Always 20. */
    struct lacp_info partner; /* LACP partner information. */
    uint8_t z2[3];            /* Reserved.  Always 0. */

    uint8_t collector_type;   /* Always 3. */
    uint8_t collector_len;    /* Always 16. */
    ovs_be16 collector_delay; /* Maximum collector delay. Set to UINT16_MAX. */
    uint8_t z3[64];           /* Combination of several fields.  Always 0. */
} __attribute__((packed));
BUILD_ASSERT_DECL(LACP_PDU_LEN == sizeof(struct lacp_pdu));

void compose_lacp_pdu(const struct lacp_info *actor,
                      const struct lacp_info *partner, struct lacp_pdu *);

const struct lacp_pdu *parse_lacp_packet(const struct ofpbuf *);

/* LACP Protocol Implementation. */

enum lacp_time {
    LACP_TIME_FAST,
    LACP_TIME_SLOW,
    LACP_TIME_CUSTOM
};

struct lacp_settings {
    char *name;
    uint8_t id[ETH_ADDR_LEN];
    uint16_t priority;
    bool active;
    enum lacp_time lacp_time;
    long long int custom_time;
    bool heartbeat;
};

void lacp_init(void);
struct lacp *lacp_create(void);
void lacp_destroy(struct lacp *);

void lacp_configure(struct lacp *, const struct lacp_settings *);
bool lacp_is_active(const struct lacp *);

void lacp_process_pdu(struct lacp *, const void *slave,
                      const struct lacp_pdu *);
bool lacp_negotiated(const struct lacp *);

struct lacp_slave_settings {
    char *name;
    uint16_t id;
    uint16_t priority;
    uint16_t key;
};

void lacp_slave_register(struct lacp *, void *slave_,
                         const struct lacp_slave_settings *);
void lacp_slave_unregister(struct lacp *, const void *slave);
void lacp_slave_carrier_changed(const struct lacp *, const void *slave);
bool lacp_slave_may_enable(const struct lacp *, const void *slave);
uint16_t lacp_slave_get_port_id(const struct lacp *, const void *slave);
bool lacp_slave_is_current(const struct lacp *, const void *slave_);

/* Callback function for lacp_run() for sending a LACP PDU. */
typedef void lacp_send_pdu(void *slave, const struct lacp_pdu *);

void lacp_run(struct lacp *, lacp_send_pdu *);
void lacp_wait(struct lacp *);

#endif /* lacp.h */
