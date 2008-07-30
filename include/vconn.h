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

/* Client interface. */

/* Virtual connection to an OpenFlow device. */
struct vconn {
    struct vconn_class *class;
    int connect_status;
    uint32_t ip;
};

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
struct buffer *make_add_simple_flow(const struct flow *,
                                    uint32_t buffer_id, uint16_t out_port,
                                    uint16_t max_idle);
struct buffer *make_buffered_packet_out(uint32_t buffer_id,
                                        uint16_t in_port, uint16_t out_port);
struct buffer *make_unbuffered_packet_out(const struct buffer *packet,
                                          uint16_t in_port, uint16_t out_port);
struct buffer *make_echo_request(void);
struct buffer *make_echo_reply(const struct ofp_header *rq);

/* Provider interface. */

struct vconn_class {
    /* Prefix for connection names, e.g. "nl", "tcp". */
    const char *name;

    /* Attempts to connect to an OpenFlow device.  'name' is the full
     * connection name provided by the user, e.g. "nl:0", "tcp:1.2.3.4".  This
     * name is useful for error messages but must not be modified.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*vconnp'.
     *
     * The open function must not block waiting for a connection to complete.
     * If the connection cannot be completed immediately, it should return
     * EAGAIN (not EINPROGRESS, as returned by the connect system call) and
     * continue the connection in the background. */
    int (*open)(const char *name, char *suffix, struct vconn **vconnp);

    /* Closes 'vconn' and frees associated memory. */
    void (*close)(struct vconn *vconn);

    /* Tries to complete the connection on 'vconn', which must be an active
     * vconn.  If 'vconn''s connection is complete, returns 0 if the connection
     * was successful or a positive errno value if it failed.  If the
     * connection is still in progress, returns EAGAIN.
     *
     * The connect function must not block waiting for the connection to
     * complete; instead, it should return EAGAIN immediately. */
    int (*connect)(struct vconn *vconn);

    /* Tries to accept a new connection on 'vconn', which must be a passive
     * vconn.  If successful, stores the new connection in '*new_vconnp' and
     * returns 0.  Otherwise, returns a positive errno value.
     *
     * The accept function must not block waiting for a connection.  If no
     * connection is ready to be accepted, it should return EAGAIN.
     *
     * Nonnull iff this is a passive vconn (one that accepts connections and
     * does not transfer data). */
    int (*accept)(struct vconn *vconn, struct vconn **new_vconnp);

    /* Tries to receive an OpenFlow message from 'vconn', which must be an
     * active vconn.  If successful, stores the received message into '*msgp'
     * and returns 0.  The caller is responsible for destroying the message
     * with buffer_delete().  On failure, returns a positive errno value and
     * stores a null pointer into '*msgp'.
     *
     * If the connection has been closed in the normal fashion, returns EOF.
     *
     * The recv function must not block waiting for a packet to arrive.  If no
     * packets have been received, it should return EAGAIN.
     *
     * Nonnull iff this is an active vconn (one that transfers data and does
     * not accept connections). */
    int (*recv)(struct vconn *vconn, struct buffer **msgp);

    /* Tries to queue 'msg' for transmission on 'vconn', which must be an
     * active vconn.  If successful, returns 0, in which case ownership of
     * 'msg' is transferred to the vconn.  Success does not guarantee that
     * 'msg' has been or ever will be delivered to the peer, only that it has
     * been queued for transmission.
     *
     * Returns a positive errno value on failure, in which case the caller
     * retains ownership of 'msg'.
     *
     * The send function must not block.  If 'msg' cannot be immediately
     * accepted for transmission, it should return EAGAIN.
     *
     * Nonnull iff this is an active vconn (one that transfers data and does
     * not accept connections). */
    int (*send)(struct vconn *vconn, struct buffer *msg);

    void (*wait)(struct vconn *vconn, enum vconn_wait_type);
};

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
