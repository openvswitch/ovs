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

#ifndef VCONN_H
#define VCONN_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct buffer;
struct flow;
struct pollfd;
struct ofp_header;
struct vconn;

/* Client interface to vconns, which provide a virtual connection to an
 * OpenFlow device. */

void vconn_usage(bool active, bool passive);
int vconn_open(const char *name, struct vconn **);
void vconn_close(struct vconn *);
bool vconn_is_passive(const struct vconn *);
uint32_t vconn_get_ip(const struct vconn *);
int vconn_connect(struct vconn *);
int vconn_accept(struct vconn *, struct vconn **);
int vconn_recv(struct vconn *, struct buffer **);
int vconn_send(struct vconn *, struct buffer *);
int vconn_transact(struct vconn *, struct buffer *, struct buffer **);

int vconn_open_block(const char *name, struct vconn **);
int vconn_send_block(struct vconn *, struct buffer *);
int vconn_recv_block(struct vconn *, struct buffer **);

enum vconn_wait_type {
    WAIT_CONNECT,
    WAIT_ACCEPT,
    WAIT_RECV,
    WAIT_SEND
};
void vconn_wait(struct vconn *, enum vconn_wait_type);
void vconn_connect_wait(struct vconn *);
void vconn_accept_wait(struct vconn *);
void vconn_recv_wait(struct vconn *);
void vconn_send_wait(struct vconn *);

void *make_openflow(size_t openflow_len, uint8_t type, struct buffer **);
void *make_openflow_xid(size_t openflow_len, uint8_t type,
                        uint32_t xid, struct buffer **);
void update_openflow_length(struct buffer *);
struct buffer *make_add_flow(const struct flow *, uint32_t buffer_id,
                             uint16_t max_idle, size_t n_actions);
struct buffer *make_add_simple_flow(const struct flow *,
                                    uint32_t buffer_id, uint16_t out_port,
                                    uint16_t max_idle);
struct buffer *make_buffered_packet_out(uint32_t buffer_id,
                                        uint16_t in_port, uint16_t out_port);
struct buffer *make_unbuffered_packet_out(const struct buffer *packet,
                                          uint16_t in_port, uint16_t out_port);
struct buffer *make_echo_request(void);
struct buffer *make_echo_reply(const struct ofp_header *rq);

extern struct vconn_class tcp_vconn_class;
extern struct vconn_class ptcp_vconn_class;
extern struct vconn_class unix_vconn_class;
extern struct vconn_class punix_vconn_class;
#ifdef HAVE_OPENSSL
extern struct vconn_class ssl_vconn_class;
extern struct vconn_class pssl_vconn_class;
#endif
#ifdef HAVE_NETLINK
extern struct vconn_class netlink_vconn_class;
#endif

#endif /* vconn.h */
