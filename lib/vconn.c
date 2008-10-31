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

#include <config.h>
#include "vconn-provider.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "flow.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "random.h"
#include "util.h"

#define THIS_MODULE VLM_vconn
#include "vlog.h"

/* State of an active vconn.*/
enum vconn_state {
    /* This is the ordinary progression of states. */
    VCS_CONNECTING,             /* Underlying vconn is not connected. */
    VCS_SEND_HELLO,             /* Waiting to send OFPT_HELLO message. */
    VCS_RECV_HELLO,             /* Waiting to receive OFPT_HELLO message. */
    VCS_CONNECTED,              /* Connection established. */

    /* These states are entered only when something goes wrong. */
    VCS_SEND_ERROR,             /* Sending OFPT_ERROR message. */
    VCS_DISCONNECTED            /* Connection failed or connection closed. */
};

static struct vconn_class *vconn_classes[] = {
    &tcp_vconn_class,
    &unix_vconn_class,
#ifdef HAVE_NETLINK
    &netlink_vconn_class,
#endif
#ifdef HAVE_OPENSSL
    &ssl_vconn_class,
#endif
};

static struct pvconn_class *pvconn_classes[] = {
    &ptcp_pvconn_class,
    &punix_pvconn_class,
#ifdef HAVE_OPENSSL
    &pssl_pvconn_class,
#endif
};

/* High rate limit because most of the rate-limiting here is individual
 * OpenFlow messages going over the vconn.  If those are enabled then we
 * really need to see them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

static int do_recv(struct vconn *, struct ofpbuf **);
static int do_send(struct vconn *, struct ofpbuf *);

/* Check the validity of the vconn class structures. */
static void
check_vconn_classes(void)
{
#ifndef NDEBUG
    size_t i;

    for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
        struct vconn_class *class = vconn_classes[i];
        assert(class->name != NULL);
        assert(class->open != NULL);
        if (class->close || class->recv || class->send || class->wait) {
            assert(class->close != NULL);
            assert(class->recv != NULL);
            assert(class->send != NULL);
            assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }

    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        struct pvconn_class *class = pvconn_classes[i];
        assert(class->name != NULL);
        assert(class->listen != NULL);
        if (class->close || class->accept || class->wait) {
            assert(class->close != NULL);
            assert(class->accept != NULL);
            assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }
#endif
}

/* Prints information on active (if 'active') and passive (if 'passive')
 * connection methods supported by the vconn.  If 'bootstrap' is true, also
 * advertises options to bootstrap the CA certificate. */
void
vconn_usage(bool active, bool passive, bool bootstrap UNUSED)
{
    /* Really this should be implemented via callbacks into the vconn
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */
    
    printf("\n");
    if (active) {
        printf("Active OpenFlow connection methods:\n");
#ifdef HAVE_NETLINK
        printf("  nl:DP_IDX               "
               "local datapath DP_IDX\n");
#endif
        printf("  tcp:HOST[:PORT]         "
               "PORT (default: %d) on remote TCP HOST\n", OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:HOST[:PORT]         "
               "SSL PORT (default: %d) on remote HOST\n", OFP_SSL_PORT);
#endif
        printf("  unix:FILE               Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive OpenFlow connection methods:\n");
        printf("  ptcp:[PORT]             "
               "listen to TCP PORT (default: %d)\n",
               OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  pssl:[PORT]             "
               "listen for SSL on PORT (default: %d)\n",
               OFP_SSL_PORT);
#endif
        printf("  punix:FILE              "
               "listen on Unix domain socket FILE\n");
    }

#ifdef HAVE_OPENSSL
    printf("PKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n");
    if (bootstrap) {
        printf("  --bootstrap-ca-cert=FILE  file with peer CA certificate "
               "to read or create\n");
    }
#endif
}

/* Attempts to connect to an OpenFlow device.  'name' is a connection name in
 * the form "TYPE:ARGS", where TYPE is an active vconn class's name and ARGS
 * are vconn class-specific.
 *
 * The vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than OFP_VERSION.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*vconnp', otherwise a null
 * pointer.  */
int
vconn_open(const char *name, int min_version, struct vconn **vconnp)
{
    size_t prefix_len;
    size_t i;

    check_vconn_classes();

    *vconnp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
        struct vconn_class *class = vconn_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            struct vconn *vconn;
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->open(name, suffix_copy, &vconn);
            free(suffix_copy);
            if (!retval) {
                assert(vconn->state != VCS_CONNECTING
                       || vconn->class->connect);
                vconn->min_version = min_version;
                *vconnp = vconn;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
}

int
vconn_open_block(const char *name, int min_version, struct vconn **vconnp)
{
    struct vconn *vconn;
    int error;

    error = vconn_open(name, min_version, &vconn);
    while (error == EAGAIN) {
        vconn_connect_wait(vconn);
        poll_block();
        error = vconn_connect(vconn);
        assert(error != EINPROGRESS);
    }
    if (error) {
        vconn_close(vconn);
        *vconnp = NULL;
    } else {
        *vconnp = vconn;
    }
    return error;
}

/* Closes 'vconn'. */
void
vconn_close(struct vconn *vconn)
{
    if (vconn != NULL) {
        char *name = vconn->name;
        (vconn->class->close)(vconn);
        free(name);
    }
}

/* Returns the name of 'vconn', that is, the string passed to vconn_open(). */
const char *
vconn_get_name(const struct vconn *vconn)
{
    return vconn->name;
}

/* Returns the IP address of the peer, or 0 if the peer is not connected over
 * an IP-based protocol or if its IP address is not yet known. */
uint32_t
vconn_get_ip(const struct vconn *vconn) 
{
    return vconn->ip;
}

static void
vcs_connecting(struct vconn *vconn) 
{
    int retval = (vconn->class->connect)(vconn);
    assert(retval != EINPROGRESS);
    if (!retval) {
        vconn->state = VCS_SEND_HELLO;
    } else if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval;
    }
}

static void
vcs_send_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    make_openflow(sizeof(struct ofp_header), OFPT_HELLO, &b);
    retval = do_send(vconn, b);
    if (!retval) {
        vconn->state = VCS_RECV_HELLO;
    } else {
        ofpbuf_delete(b);
        if (retval != EAGAIN) {
            vconn->state = VCS_DISCONNECTED;
            vconn->error = retval;
        }
    }
}

static void
vcs_recv_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    retval = do_recv(vconn, &b);
    if (!retval) {
        struct ofp_header *oh = b->data;

        if (oh->type == OFPT_HELLO) {
            if (b->size > sizeof *oh) {
                struct ds msg = DS_EMPTY_INITIALIZER;
                ds_put_format(&msg, "%s: extra-long hello:\n", vconn->name);
                ds_put_hex_dump(&msg, b->data, b->size, 0, true);
                VLOG_WARN_RL(&rl, ds_cstr(&msg));
                ds_destroy(&msg);
            }

            vconn->version = MIN(OFP_VERSION, oh->version);
            if (vconn->version < vconn->min_version) {
                VLOG_WARN_RL(&rl, "%s: version negotiation failed: we support "
                             "versions 0x%02x to 0x%02x inclusive but peer "
                             "supports no later than version 0x%02"PRIx8,
                             vconn->name, vconn->min_version, OFP_VERSION,
                             oh->version);
                vconn->state = VCS_SEND_ERROR;
            } else {
                VLOG_DBG("%s: negotiated OpenFlow version 0x%02x "
                         "(we support versions 0x%02x to 0x%02x inclusive, "
                         "peer no later than version 0x%02"PRIx8")",
                         vconn->name, vconn->version, vconn->min_version,
                         OFP_VERSION, oh->version);
                vconn->state = VCS_CONNECTED;
            }
            ofpbuf_delete(b);
            return;
        } else {
            char *s = ofp_to_string(b->data, b->size, 1);
            VLOG_WARN_RL(&rl, "%s: received message while expecting hello: %s",
                         vconn->name, s);
            free(s);
            retval = EPROTO;
            ofpbuf_delete(b);
        }
    }

    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval;
    }
}

static void
vcs_send_error(struct vconn *vconn)
{
    struct ofp_error_msg *error;
    struct ofpbuf *b;
    char s[128];
    int retval;

    snprintf(s, sizeof s, "We support versions 0x%02x to 0x%02x inclusive but "
             "you support no later than version 0x%02"PRIx8".",
             vconn->min_version, OFP_VERSION, vconn->version);
    error = make_openflow(sizeof *error, OFPT_ERROR, &b);
    error->type = htons(OFPET_HELLO_FAILED);
    error->code = htons(OFPHFC_INCOMPATIBLE);
    ofpbuf_put(b, s, strlen(s));
    update_openflow_length(b);
    retval = do_send(vconn, b);
    if (retval) {
        ofpbuf_delete(b);
    }
    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval ? retval : EPROTO;
    }
}

/* Tries to complete the connection on 'vconn', which must be an active
 * vconn.  If 'vconn''s connection is complete, returns 0 if the connection
 * was successful or a positive errno value if it failed.  If the
 * connection is still in progress, returns EAGAIN. */
int
vconn_connect(struct vconn *vconn)
{
    enum vconn_state last_state;

    assert(vconn->min_version >= 0);
    do {
        last_state = vconn->state;
        switch (vconn->state) {
        case VCS_CONNECTING:
            vcs_connecting(vconn);
            break;

        case VCS_SEND_HELLO:
            vcs_send_hello(vconn);
            break;

        case VCS_RECV_HELLO:
            vcs_recv_hello(vconn);
            break;

        case VCS_CONNECTED:
            return 0;

        case VCS_SEND_ERROR:
            vcs_send_error(vconn);
            break;

        case VCS_DISCONNECTED:
            return vconn->error;

        default:
            NOT_REACHED();
        }
    } while (vconn->state != last_state);

    return EAGAIN;
}

/* Tries to receive an OpenFlow message from 'vconn', which must be an active
 * vconn.  If successful, stores the received message into '*msgp' and returns
 * 0.  The caller is responsible for destroying the message with
 * ofpbuf_delete().  On failure, returns a positive errno value and stores a
 * null pointer into '*msgp'.  On normal connection close, returns EOF.
 *
 * vconn_recv will not block waiting for a packet to arrive.  If no packets
 * have been received, it returns EAGAIN immediately. */
int
vconn_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval = vconn_connect(vconn);
    if (!retval) {
        retval = do_recv(vconn, msgp);
    }
    return retval;
}

static int
do_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;

    retval = (vconn->class->recv)(vconn, msgp);
    if (!retval) {
        struct ofp_header *oh;

        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string((*msgp)->data, (*msgp)->size, 1);
            VLOG_DBG_RL(&rl, "%s: received: %s", vconn->name, s);
            free(s);
        }

        oh = ofpbuf_at_assert(*msgp, 0, sizeof *oh);
        if (oh->version != vconn->version
            && oh->type != OFPT_HELLO
            && oh->type != OFPT_ERROR
            && oh->type != OFPT_ECHO_REQUEST
            && oh->type != OFPT_ECHO_REPLY
            && oh->type != OFPT_VENDOR)
        {
            if (vconn->version < 0) {
                VLOG_ERR_RL(&rl, "%s: received OpenFlow message type %"PRIu8" "
                            "before version negotiation complete",
                            vconn->name, oh->type);
            } else {
                VLOG_ERR_RL(&rl, "%s: received OpenFlow version 0x%02"PRIx8" "
                            "!= expected %02x",
                            vconn->name, oh->version, vconn->version);
            }
            ofpbuf_delete(*msgp);
            retval = EPROTO;
        }
    }
    if (retval) {
        *msgp = NULL;
    }
    return retval;
}

/* Tries to queue 'msg' for transmission on 'vconn', which must be an active
 * vconn.  If successful, returns 0, in which case ownership of 'msg' is
 * transferred to the vconn.  Success does not guarantee that 'msg' has been or
 * ever will be delivered to the peer, only that it has been queued for
 * transmission.
 *
 * Returns a positive errno value on failure, in which case the caller
 * retains ownership of 'msg'.
 *
 * vconn_send will not block.  If 'msg' cannot be immediately accepted for
 * transmission, it returns EAGAIN immediately. */
int
vconn_send(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval = vconn_connect(vconn);
    if (!retval) {
        retval = do_send(vconn, msg);
    }
    return retval;
}

static int
do_send(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval;

    assert(msg->size >= sizeof(struct ofp_header));
    assert(((struct ofp_header *) msg->data)->length == htons(msg->size));
    if (!VLOG_IS_DBG_ENABLED()) {
        retval = (vconn->class->send)(vconn, msg);
    } else {
        char *s = ofp_to_string(msg->data, msg->size, 1);
        retval = (vconn->class->send)(vconn, msg);
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&rl, "%s: sent (%s): %s",
                        vconn->name, strerror(retval), s);
        }
        free(s);
    }
    return retval;
}

/* Same as vconn_send, except that it waits until 'msg' can be transmitted. */
int
vconn_send_block(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval;
    while ((retval = vconn_send(vconn, msg)) == EAGAIN) {
        vconn_send_wait(vconn);
        poll_block();
    }
    return retval;
}

/* Same as vconn_recv, except that it waits until a message is received. */
int
vconn_recv_block(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;
    while ((retval = vconn_recv(vconn, msgp)) == EAGAIN) {
        vconn_recv_wait(vconn);
        poll_block();
    }
    return retval;
}

/* Waits until a message with a transaction ID matching 'xid' is recived on
 * 'vconn'.  Returns 0 if successful, in which case the reply is stored in
 * '*replyp' for the caller to examine and free.  Otherwise returns a positive
 * errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_recv_xid(struct vconn *vconn, uint32_t xid, struct ofpbuf **replyp)
{
    for (;;) {
        uint32_t recv_xid;
        struct ofpbuf *reply;
        int error;

        error = vconn_recv_block(vconn, &reply);
        if (error) {
            *replyp = NULL;
            return error;
        }
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (xid == recv_xid) {
            *replyp = reply;
            return 0;
        }

        VLOG_DBG_RL(&rl, "%s: received reply with xid %08"PRIx32" != expected "
                    "%08"PRIx32, vconn->name, recv_xid, xid);
        ofpbuf_delete(reply);
    }
}

/* Sends 'request' to 'vconn' and blocks until it receives a reply with a
 * matching transaction ID.  Returns 0 if successful, in which case the reply
 * is stored in '*replyp' for the caller to examine and free.  Otherwise
 * returns a positive errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact(struct vconn *vconn, struct ofpbuf *request,
               struct ofpbuf **replyp)
{
    uint32_t send_xid = ((struct ofp_header *) request->data)->xid;
    int error;

    *replyp = NULL;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
    }
    return error ? error : vconn_recv_xid(vconn, send_xid, replyp);
}

void
vconn_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    assert(wait == WAIT_CONNECT || wait == WAIT_RECV || wait == WAIT_SEND);

    switch (vconn->state) {
    case VCS_CONNECTING:
        wait = WAIT_CONNECT;
        break;

    case VCS_SEND_HELLO:
    case VCS_SEND_ERROR:
        wait = WAIT_SEND;
        break;

    case VCS_RECV_HELLO:
        wait = WAIT_RECV;
        break;

    case VCS_CONNECTED:
        break;

    case VCS_DISCONNECTED:
        poll_immediate_wake();
        return;
    }
    (vconn->class->wait)(vconn, wait);
}

void
vconn_connect_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_CONNECT);
}

void
vconn_recv_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_RECV);
}

void
vconn_send_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_SEND);
}

/* Attempts to start listening for OpenFlow connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive vconn
 * class's name and ARGS are vconn class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pvconnp', otherwise a null
 * pointer.  */
int
pvconn_open(const char *name, struct pvconn **pvconnp)
{
    size_t prefix_len;
    size_t i;

    check_vconn_classes();

    *pvconnp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        struct pvconn_class *class = pvconn_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->listen(name, suffix_copy, pvconnp);
            free(suffix_copy);
            if (retval) {
                *pvconnp = NULL;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
}

/* Closes 'pvconn'. */
void
pvconn_close(struct pvconn *pvconn)
{
    if (pvconn != NULL) {
        char *name = pvconn->name;
        (pvconn->class->close)(pvconn);
        free(name);
    }
}

/* Tries to accept a new connection on 'pvconn'.  If successful, stores the new
 * connection in '*new_vconn' and returns 0.  Otherwise, returns a positive
 * errno value.
 *
 * The new vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than OFP_VERSION.
 *
 * pvconn_accept() will not block waiting for a connection.  If no connection
 * is ready to be accepted, it returns EAGAIN immediately. */
int
pvconn_accept(struct pvconn *pvconn, int min_version, struct vconn **new_vconn)
{
    int retval = (pvconn->class->accept)(pvconn, new_vconn);
    if (retval) {
        *new_vconn = NULL;
    } else {
        assert((*new_vconn)->state != VCS_CONNECTING
               || (*new_vconn)->class->connect);
        (*new_vconn)->min_version = min_version;
    }
    return retval;
}

void
pvconn_wait(struct pvconn *pvconn)
{
    (pvconn->class->wait)(pvconn);
}

/* Allocates and returns the first byte of a buffer 'openflow_len' bytes long,
 * containing an OpenFlow header with the given 'type' and a random transaction
 * id.  Stores the new buffer in '*bufferp'.  The caller must free the buffer
 * when it is no longer needed. */
void *
make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **bufferp) 
{
    return make_openflow_xid(openflow_len, type, random_uint32(), bufferp);
}

/* Allocates and returns the first byte of a buffer 'openflow_len' bytes long,
 * containing an OpenFlow header with the given 'type' and transaction id
 * 'xid'.  Stores the new buffer in '*bufferp'.  The caller must free the
 * buffer when it is no longer needed. */
void *
make_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                  struct ofpbuf **bufferp)
{
    struct ofpbuf *buffer;
    struct ofp_header *oh;

    assert(openflow_len >= sizeof *oh);
    assert(openflow_len <= UINT16_MAX);
    buffer = *bufferp = ofpbuf_new(openflow_len);
    oh = ofpbuf_put_zeros(buffer, openflow_len);
    oh->version = OFP_VERSION;
    oh->type = type;
    oh->length = htons(openflow_len);
    oh->xid = xid;
    return oh;
}

/* Updates the 'length' field of the OpenFlow message in 'buffer' to
 * 'buffer->size'. */
void
update_openflow_length(struct ofpbuf *buffer) 
{
    struct ofp_header *oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    oh->length = htons(buffer->size); 
}

struct ofpbuf *
make_add_flow(const struct flow *flow, uint32_t buffer_id,
              uint16_t idle_timeout, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t size = sizeof *ofm + actions_len;
    struct ofpbuf *out = ofpbuf_new(size);
    ofm = ofpbuf_put_zeros(out, size);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards = htonl(0);
    ofm->match.in_port = flow->in_port;
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(OFPFC_ADD);
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->buffer_id = htonl(buffer_id);
    return out;
}

struct ofpbuf *
make_add_simple_flow(const struct flow *flow,
                     uint32_t buffer_id, uint16_t out_port,
                     uint16_t idle_timeout)
{
    struct ofp_action_output *oao;
    struct ofpbuf *buffer = make_add_flow(flow, buffer_id, idle_timeout, 
            sizeof *oao);
    struct ofp_flow_mod *ofm = buffer->data;
    oao = (struct ofp_action_output *)&ofm->actions[0];
    oao->type = htons(OFPAT_OUTPUT);
    oao->len = htons(sizeof *oao);
    oao->port = htons(out_port);
    return buffer;
}

struct ofpbuf *
make_unbuffered_packet_out(const struct ofpbuf *packet,
                           uint16_t in_port, uint16_t out_port)
{
    struct ofp_packet_out *opo;
    struct ofp_action_output *oao;
    size_t size = sizeof *opo + sizeof *oao;
    struct ofpbuf *out = ofpbuf_new(size + packet->size);

    opo = ofpbuf_put_zeros(out, size);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->buffer_id = htonl(UINT32_MAX);
    opo->in_port = htons(in_port);

    oao = (struct ofp_action_output *)&opo->actions[0];
    oao->type = htons(OFPAT_OUTPUT);
    oao->len = htons(sizeof *oao);
    oao->port = htons(out_port);

    opo->actions_len = htons(sizeof *oao);

    ofpbuf_put(out, packet->data, packet->size);
    update_openflow_length(out);
    return out;
}

struct ofpbuf *
make_buffered_packet_out(uint32_t buffer_id,
                         uint16_t in_port, uint16_t out_port)
{
    struct ofp_packet_out *opo;
    struct ofp_action_output *oao;
    size_t size = sizeof *opo + sizeof *oao;
    struct ofpbuf *out = ofpbuf_new(size);
    opo = ofpbuf_put_zeros(out, size);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->header.length = htons(size);
    opo->buffer_id = htonl(buffer_id);
    opo->in_port = htons(in_port);

    oao = (struct ofp_action_output *)&opo->actions[0];
    oao->type = htons(OFPAT_OUTPUT);
    oao->len = htons(sizeof *oao);
    oao->port = htons(out_port);

    opo->actions_len = htons(sizeof *oao);
    return out;
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(void)
{
    struct ofp_header *rq;
    struct ofpbuf *out = ofpbuf_new(sizeof *rq);
    rq = ofpbuf_put_uninit(out, sizeof *rq);
    rq->version = OFP_VERSION;
    rq->type = OFPT_ECHO_REQUEST;
    rq->length = htons(sizeof *rq);
    rq->xid = 0;
    return out;
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
make_echo_reply(const struct ofp_header *rq)
{
    size_t size = ntohs(rq->length);
    struct ofpbuf *out = ofpbuf_new(size);
    struct ofp_header *reply = ofpbuf_put(out, rq, size);
    reply->type = OFPT_ECHO_REPLY;
    return out;
}

void
vconn_init(struct vconn *vconn, struct vconn_class *class, int connect_status,
           uint32_t ip, const char *name)
{
    vconn->class = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->version = -1;
    vconn->min_version = -1;
    vconn->ip = ip;
    vconn->name = xstrdup(name);
}

void
pvconn_init(struct pvconn *pvconn, struct pvconn_class *class,
            const char *name)
{
    pvconn->class = class;
    pvconn->name = xstrdup(name);
}
