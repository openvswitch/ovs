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

void lacp_process_packet(struct lacp *, const void *slave,
                         const struct ofpbuf *packet);
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
typedef void lacp_send_pdu(void *slave, const void *pdu, size_t pdu_size);

void lacp_run(struct lacp *, lacp_send_pdu *);
void lacp_wait(struct lacp *);

#endif /* lacp.h */
