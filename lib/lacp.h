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

struct ds;
struct lacp;
struct lacp_pdu;
struct ofpbuf;

/* Function called when a LACP PDU is ready to be sent out the given slave */
typedef void lacp_send_pdu(void *slave, const struct lacp_pdu *);

void lacp_init(void);
struct lacp *lacp_create(void);
void lacp_destroy(struct lacp *);
void lacp_configure(struct lacp *, const char *name, uint8_t sys_id[8],
                    uint16_t sys_priority, bool active, bool fast);
void lacp_process_pdu(struct lacp *, const void *slave,
                      const struct lacp_pdu *);
bool lacp_negotiated(const struct lacp *);

void lacp_slave_register(struct lacp *, void *slave_, const char *name,
                         uint16_t port_id, uint16_t port_priority);
void lacp_slave_unregister(struct lacp *, const void *slave);
void lacp_slave_enable(struct lacp *lacp, void *slave_, bool enabled);
void lacp_slave_carrier_changed(const struct lacp *, const void *slave);
bool lacp_slave_may_enable(const struct lacp *, const void *slave);

void lacp_run(struct lacp *, lacp_send_pdu *);
void lacp_wait(struct lacp *);

#endif /* lacp.h */
