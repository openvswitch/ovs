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

#ifndef PORT_WATCHER_H
#define PORT_WATCHER_H 1

#include <stdint.h>
#include "compiler.h"
#include "secchan.h"

struct ofp_phy_port;
struct port_watcher;
struct secchan;

void port_watcher_start(struct secchan *,
                        struct rconn *local, struct rconn *remote,
                        struct port_watcher **);
bool port_watcher_is_ready(const struct port_watcher *);
uint32_t port_watcher_get_config(const struct port_watcher *,
                                 uint16_t port_no);
const char *port_watcher_get_name(const struct port_watcher *,
                                  uint16_t port_no) UNUSED;
const uint8_t *port_watcher_get_hwaddr(const struct port_watcher *,
                                       uint16_t port_no);
void port_watcher_set_flags(struct port_watcher *, uint16_t port_no, 
                            uint32_t config, uint32_t c_mask,
                            uint32_t state, uint32_t s_mask);

typedef void port_changed_cb_func(uint16_t port_no,
                                  const struct ofp_phy_port *old,
                                  const struct ofp_phy_port *new,
                                  void *aux);

void port_watcher_register_callback(struct port_watcher *,
                                    port_changed_cb_func *port_changed,
                                    void *aux);

typedef void local_port_changed_cb_func(const struct ofp_phy_port *new,
                                        void *aux);

void port_watcher_register_local_port_callback(struct port_watcher *pw,
                                               local_port_changed_cb_func *cb,
                                               void *aux);

void get_port_name(const struct ofp_phy_port *, char *name, size_t name_size);

#endif /* port-watcher.h */
