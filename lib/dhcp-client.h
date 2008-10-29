/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
