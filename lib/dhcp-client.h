/*
 * Copyright (c) 2008, 2010 Nicira Networks.
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

#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H 1

#include <stdbool.h>
#include <stdint.h>

struct dhclient;
struct dhcp_msg;
struct netdev;
int dhclient_create(const char *netdev,
                    void (*modify_request)(struct dhcp_msg *, void *aux),
                    bool (*validate_offer)(const struct dhcp_msg *, void *aux),
                    void *aux, struct dhclient **);
void dhclient_set_max_timeout(struct dhclient *, unsigned int max_timeout);
void dhclient_destroy(struct dhclient *);

struct netdev *dhclient_get_netdev(struct dhclient *);
const char *dhclient_get_name(const struct dhclient *);

void dhclient_init(struct dhclient *, uint32_t requested_ip);
void dhclient_release(struct dhclient *);
void dhclient_force_renew(struct dhclient *, int deadline);
bool dhclient_is_bound(const struct dhclient *);
bool dhclient_changed(struct dhclient *);

const char *dhclient_get_state(const struct dhclient *);
unsigned int dhclient_get_state_elapsed(const struct dhclient *);
unsigned int dhclient_get_lease_remaining(const struct dhclient *);

uint32_t dhclient_get_ip(const struct dhclient *);
uint32_t dhclient_get_netmask(const struct dhclient *);
uint32_t dhclient_get_router(const struct dhclient *);
const struct dhcp_msg *dhclient_get_config(const struct dhclient *);

int dhclient_configure_netdev(struct dhclient *);
int dhclient_update_resolv_conf(struct dhclient *);

void dhclient_run(struct dhclient *);
void dhclient_wait(struct dhclient *);

#endif /* dhcp-client.h */
