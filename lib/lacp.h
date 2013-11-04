/*
 * Copyright (c) 2011 Nicira, Inc.
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

/* LACP Protocol Implementation. */

enum lacp_status {
    LACP_NEGOTIATED,                  /* Successful LACP negotations. */
    LACP_CONFIGURED,                  /* LACP is enabled but not negotiated. */
    LACP_DISABLED                     /* LACP is not enabled. */
};

struct lacp_settings {
    char *name;                       /* Name (for debugging). */
    uint8_t id[ETH_ADDR_LEN];         /* System ID. Must be nonzero. */
    uint16_t priority;                /* System priority. */
    bool active;                      /* Active or passive mode? */
    bool fast;                        /* Fast or slow probe interval. */
    bool fallback_ab_cfg;             /* Fallback to BM_SLB on LACP failure. */
};

void lacp_init(void);
struct lacp *lacp_create(void);
void lacp_unref(struct lacp *);
struct lacp *lacp_ref(const struct lacp *);

void lacp_configure(struct lacp *, const struct lacp_settings *);
bool lacp_is_active(const struct lacp *);

void lacp_process_packet(struct lacp *, const void *slave,
                         const struct ofpbuf *packet);
enum lacp_status lacp_status(const struct lacp *);

struct lacp_slave_settings {
    char *name;                       /* Name (for debugging). */
    uint16_t id;                      /* Port ID. */
    uint16_t priority;                /* Port priority. */
    uint16_t key;                     /* Aggregation key. */
};

void lacp_slave_register(struct lacp *, void *slave_,
                         const struct lacp_slave_settings *);
void lacp_slave_unregister(struct lacp *, const void *slave);
void lacp_slave_carrier_changed(const struct lacp *, const void *slave);
bool lacp_slave_may_enable(const struct lacp *, const void *slave);
bool lacp_slave_is_current(const struct lacp *, const void *slave_);

/* Callback function for lacp_run() for sending a LACP PDU. */
typedef void lacp_send_pdu(void *slave, const void *pdu, size_t pdu_size);

void lacp_run(struct lacp *, lacp_send_pdu *);
void lacp_wait(struct lacp *);

#endif /* lacp.h */
