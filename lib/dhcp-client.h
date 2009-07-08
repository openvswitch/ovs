/*
 * Copyright (c) 2008 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
