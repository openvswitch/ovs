/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#include <config.h>
#include "vconn-provider.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
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

/* Rate limit for individual OpenFlow messages going over the vconn, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit ofmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

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
        printf("  tcp:IP[:PORT]         "
               "PORT (default: %d) at remote IP\n", OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:IP[:PORT]         "
               "SSL PORT (default: %d) at remote IP\n", OFP_SSL_PORT);
#endif
        printf("  unix:FILE               Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive OpenFlow connection methods:\n");
        printf("  ptcp:[PORT][:IP]        "
               "listen to TCP PORT (default: %d) on IP\n",
               OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  pssl:[PORT][:IP]        "
               "listen for SSL on PORT (default: %d) on IP\n",
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

    COVERAGE_INC(vconn_open);
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
vconn_get_remote_ip(const struct vconn *vconn) 
{
    return vconn->remote_ip;
}

/* Returns the transport port of the peer, or 0 if the connection does not 
 * contain a port or if the port is not yet known. */
uint16_t
vconn_get_remote_port(const struct vconn *vconn) 
{
    return vconn->remote_port;
}

/* Returns the IP address used to connect to the peer, or 0 if the 
 * connection is not an IP-based protocol or if its IP address is not 
 * yet known. */
uint32_t
vconn_get_local_ip(const struct vconn *vconn) 
{
    return vconn->local_ip;
}

/* Returns the transport port used to connect to the peer, or 0 if the 
 * connection does not contain a port or if the port is not yet known. */
uint16_t
vconn_get_local_port(const struct vconn *vconn) 
{
    return vconn->local_port;
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
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s", ds_cstr(&msg));
                ds_destroy(&msg);
            }

            vconn->version = MIN(OFP_VERSION, oh->version);
            if (vconn->version < vconn->min_version) {
                VLOG_WARN_RL(&bad_ofmsg_rl,
                             "%s: version negotiation failed: we support "
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
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "%s: received message while expecting hello: %s",
                         vconn->name, s);
            free(s);
            retval = EPROTO;
            ofpbuf_delete(b);
        }
    }

    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval == EOF ? ECONNRESET : retval;
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
    int retval = (vconn->class->recv)(vconn, msgp);
    if (!retval) {
        struct ofp_header *oh;

        COVERAGE_INC(vconn_received);
        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string((*msgp)->data, (*msgp)->size, 1);
            VLOG_DBG_RL(&ofmsg_rl, "%s: received: %s", vconn->name, s);
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
                VLOG_ERR_RL(&bad_ofmsg_rl,
                            "%s: received OpenFlow message type %"PRIu8" "
                            "before version negotiation complete",
                            vconn->name, oh->type);
            } else {
                VLOG_ERR_RL(&bad_ofmsg_rl,
                            "%s: received OpenFlow version 0x%02"PRIx8" "
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
        COVERAGE_INC(vconn_sent);
        retval = (vconn->class->send)(vconn, msg);
    } else {
        char *s = ofp_to_string(msg->data, msg->size, 1);
        retval = (vconn->class->send)(vconn, msg);
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&ofmsg_rl, "%s: sent (%s): %s",
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

        VLOG_DBG_RL(&bad_ofmsg_rl, "%s: received reply with xid %08"PRIx32
                    " != expected %08"PRIx32, vconn->name, recv_xid, xid);
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

/* Returns the name that was used to open 'pvconn'.  The caller must not
 * modify or free the name. */
const char *
pvconn_get_name(const struct pvconn *pvconn)
{
    return pvconn->name;
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

/* XXX we should really use consecutive xids to avoid probabilistic
 * failures. */
static inline uint32_t
alloc_xid(void)
{
    return random_uint32();
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * an arbitrary transaction id.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, alloc_xid(), *bufferp);
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * transaction id 'xid'.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                  struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, xid, *bufferp);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an arbitrary transaction id.  Allocated bytes
 * beyond the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *buffer)
{
    return put_openflow_xid(openflow_len, type, alloc_xid(), buffer);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an transaction id 'xid'.  Allocated bytes beyond
 * the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                 struct ofpbuf *buffer)
{
    struct ofp_header *oh;

    assert(openflow_len >= sizeof *oh);
    assert(openflow_len <= UINT16_MAX);

    oh = ofpbuf_put_uninit(buffer, openflow_len);
    oh->version = OFP_VERSION;
    oh->type = type;
    oh->length = htons(openflow_len);
    oh->xid = xid;
    memset(oh + 1, 0, openflow_len - sizeof *oh);
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
make_flow_mod(uint16_t command, const flow_t *flow, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t size = sizeof *ofm + actions_len;
    struct ofpbuf *out = ofpbuf_new(size);
    ofm = ofpbuf_put_zeros(out, sizeof *ofm);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->cookie = 0;
    ofm->match.wildcards = htonl(0);
    ofm->match.in_port = htons(flow->in_port == ODPP_LOCAL ? OFPP_LOCAL
                               : flow->in_port);
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.nw_tos = flow->nw_tos;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(command);
    return out;
}

struct ofpbuf *
make_add_flow(const flow_t *flow, uint32_t buffer_id,
              uint16_t idle_timeout, size_t actions_len)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_ADD, flow, actions_len);
    struct ofp_flow_mod *ofm = out->data;
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->buffer_id = htonl(buffer_id);
    return out;
}

struct ofpbuf *
make_del_flow(const flow_t *flow)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_DELETE_STRICT, flow, 0);
    struct ofp_flow_mod *ofm = out->data;
    ofm->out_port = htons(OFPP_NONE);
    return out;
}

struct ofpbuf *
make_add_simple_flow(const flow_t *flow,
                     uint32_t buffer_id, uint16_t out_port,
                     uint16_t idle_timeout)
{
    struct ofp_action_output *oao;
    struct ofpbuf *buffer = make_add_flow(flow, buffer_id, idle_timeout,
                                          sizeof *oao);
    oao = ofpbuf_put_zeros(buffer, sizeof *oao);
    oao->type = htons(OFPAT_OUTPUT);
    oao->len = htons(sizeof *oao);
    oao->port = htons(out_port);
    return buffer;
}

struct ofpbuf *
make_packet_in(uint32_t buffer_id, uint16_t in_port, uint8_t reason,
               const struct ofpbuf *payload, int max_send_len)
{
    struct ofp_packet_in *opi;
    struct ofpbuf *buf;
    int send_len;

    send_len = MIN(max_send_len, payload->size);
    buf = ofpbuf_new(sizeof *opi + send_len);
    opi = put_openflow_xid(offsetof(struct ofp_packet_in, data),
                           OFPT_PACKET_IN, 0, buf);
    opi->buffer_id = htonl(buffer_id);
    opi->total_len = htons(payload->size);
    opi->in_port = htons(in_port);
    opi->reason = reason;
    ofpbuf_put(buf, payload->data, send_len);
    update_openflow_length(buf);

    return buf;
}

struct ofpbuf *
make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                uint16_t in_port,
                const struct ofp_action_header *actions, size_t n_actions)
{
    size_t actions_len = n_actions * sizeof *actions;
    struct ofp_packet_out *opo;
    size_t size = sizeof *opo + actions_len + (packet ? packet->size : 0);
    struct ofpbuf *out = ofpbuf_new(size);

    opo = ofpbuf_put_uninit(out, sizeof *opo);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->header.length = htons(size);
    opo->header.xid = htonl(0);
    opo->buffer_id = htonl(buffer_id);
    opo->in_port = htons(in_port == ODPP_LOCAL ? OFPP_LOCAL : in_port);
    opo->actions_len = htons(actions_len);
    ofpbuf_put(out, actions, actions_len);
    if (packet) {
        ofpbuf_put(out, packet->data, packet->size);
    }
    return out;
}

struct ofpbuf *
make_unbuffered_packet_out(const struct ofpbuf *packet,
                           uint16_t in_port, uint16_t out_port)
{
    struct ofp_action_output action;
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof action);
    action.port = htons(out_port);
    return make_packet_out(packet, UINT32_MAX, in_port,
                           (struct ofp_action_header *) &action, 1);
}

struct ofpbuf *
make_buffered_packet_out(uint32_t buffer_id,
                         uint16_t in_port, uint16_t out_port)
{
    struct ofp_action_output action;
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof action);
    action.port = htons(out_port);
    return make_packet_out(NULL, buffer_id, in_port,
                           (struct ofp_action_header *) &action, 1);
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

static int
check_message_type(uint8_t got_type, uint8_t want_type) 
{
    if (got_type != want_type) {
        char *want_type_name = ofp_message_type_to_string(want_type);
        char *got_type_name = ofp_message_type_to_string(got_type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received bad message type %s (expected %s)",
                     got_type_name, want_type_name);
        free(want_type_name);
        free(got_type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
    }
    return 0;
}

/* Checks that 'msg' has type 'type' and that it is exactly 'size' bytes long.
 * Returns 0 if the checks pass, otherwise an OpenFlow error code (produced
 * with ofp_mkerr()). */
int
check_ofp_message(const struct ofp_header *msg, uint8_t type, size_t size)
{
    size_t got_size;
    int error;

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size != size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received %s message of length %zu (expected %zu)",
                     type_name, got_size, size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    return 0;
}

/* Checks that 'msg' has type 'type' and that 'msg' is 'size' plus a
 * nonnegative integer multiple of 'array_elt_size' bytes long.  Returns 0 if
 * the checks pass, otherwise an OpenFlow error code (produced with
 * ofp_mkerr()).
 *
 * If 'n_array_elts' is nonnull, then '*n_array_elts' is set to the number of
 * 'array_elt_size' blocks in 'msg' past the first 'min_size' bytes, when
 * successful. */
int
check_ofp_message_array(const struct ofp_header *msg, uint8_t type,
                        size_t min_size, size_t array_elt_size,
                        size_t *n_array_elts)
{
    size_t got_size;
    int error;

    assert(array_elt_size);

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size < min_size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl, "received %s message of length %zu "
                     "(expected at least %zu)",
                     type_name, got_size, min_size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if ((got_size - min_size) % array_elt_size) {
        char *type_name = ofp_message_type_to_string(type);
        VLOG_WARN_RL(&bad_ofmsg_rl,
                     "received %s message of bad length %zu: the "
                     "excess over %zu (%zu) is not evenly divisible by %zu "
                     "(remainder is %zu)",
                     type_name, got_size, min_size, got_size - min_size,
                     array_elt_size, (got_size - min_size) % array_elt_size);
        free(type_name);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (n_array_elts) {
        *n_array_elts = (got_size - min_size) / array_elt_size;
    }
    return 0;
}

int
check_ofp_packet_out(const struct ofp_header *oh, struct ofpbuf *data,
                     int *n_actionsp, int max_ports)
{
    const struct ofp_packet_out *opo;
    unsigned int actions_len, n_actions;
    size_t extra;
    int error;

    *n_actionsp = 0;
    error = check_ofp_message_array(oh, OFPT_PACKET_OUT,
                                    sizeof *opo, 1, &extra);
    if (error) {
        return error;
    }
    opo = (const struct ofp_packet_out *) oh;

    actions_len = ntohs(opo->actions_len);
    if (actions_len > extra) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out claims %u bytes of actions "
                     "but message has room for only %zu bytes",
                     actions_len, extra);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (actions_len % sizeof(union ofp_action)) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "packet-out claims %u bytes of actions, "
                     "which is not a multiple of %zu",
                     actions_len, sizeof(union ofp_action));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    n_actions = actions_len / sizeof(union ofp_action);
    error = validate_actions((const union ofp_action *) opo->actions,
                             n_actions, max_ports);
    if (error) {
        return error;
    }

    data->data = (void *) &opo->actions[n_actions];
    data->size = extra - actions_len;
    *n_actionsp = n_actions;
    return 0;
}

const struct ofp_flow_stats *
flow_stats_first(struct flow_stats_iterator *iter,
                 const struct ofp_stats_reply *osr)
{
    iter->pos = osr->body;
    iter->end = osr->body + (ntohs(osr->header.length)
                             - offsetof(struct ofp_stats_reply, body));
    return flow_stats_next(iter);
}

const struct ofp_flow_stats *
flow_stats_next(struct flow_stats_iterator *iter)
{
    ptrdiff_t bytes_left = iter->end - iter->pos;
    const struct ofp_flow_stats *fs;
    size_t length;

    if (bytes_left < sizeof *fs) {
        if (bytes_left != 0) {
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "%td leftover bytes in flow stats reply", bytes_left);
        }
        return NULL;
    }

    fs = (const void *) iter->pos;
    length = ntohs(fs->length);
    if (length < sizeof *fs) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu is shorter than "
                     "min %zu", length, sizeof *fs);
        return NULL;
    } else if (length > bytes_left) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu but only %td "
                     "bytes left", length, bytes_left);
        return NULL;
    } else if ((length - sizeof *fs) % sizeof fs->actions[0]) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "flow stats length %zu has %zu bytes "
                     "left over in final action", length,
                     (length - sizeof *fs) % sizeof fs->actions[0]);
        return NULL;
    }
    iter->pos += length;
    return fs;
}

/* Alignment of ofp_actions. */
#define ACTION_ALIGNMENT 8

static int
check_action_exact_len(const union ofp_action *a, unsigned int len,
                       unsigned int required_len)
{
    if (len != required_len) {
        VLOG_DBG_RL(&bad_ofmsg_rl,
                    "action %u has invalid length %"PRIu16" (must be %u)\n",
                    a->type, ntohs(a->header.len), required_len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

static int
check_action_port(int port, int max_ports)
{
    switch (port) {
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_LOCAL:
        return 0;

    default:
        if (port >= 0 && port < max_ports) {
            return 0;
        }
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown output port %x", port);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
    }
}

static int
check_nicira_action(const union ofp_action *a, unsigned int len)
{
    const struct nx_action_header *nah;

    if (len < 16) {
        VLOG_DBG_RL(&bad_ofmsg_rl,
                    "Nicira vendor action only %u bytes", len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    nah = (const struct nx_action_header *) a;

    switch (ntohs(nah->subtype)) {
    case NXAST_RESUBMIT:
        return check_action_exact_len(a, len, 16);
    default:
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR_TYPE);
    }
}

static int
check_action(const union ofp_action *a, unsigned int len, int max_ports)
{
    int error;

    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT:
        error = check_action_port(ntohs(a->output.port), max_ports);
        if (error) {
            return error;
        }
        return check_action_exact_len(a, len, 8);

    case OFPAT_SET_VLAN_VID:
    case OFPAT_SET_VLAN_PCP:
    case OFPAT_STRIP_VLAN:
    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
    case OFPAT_SET_NW_TOS:
    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
        return check_action_exact_len(a, len, 8);

    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
        return check_action_exact_len(a, len, 16);

    case OFPAT_VENDOR:
        if (a->vendor.vendor == htonl(NX_VENDOR_ID)) {
            return check_nicira_action(a, len);
        } else {
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_VENDOR);
        }
        break;

    default:
        VLOG_WARN_RL(&bad_ofmsg_rl, "unknown action type %"PRIu16,
                ntohs(a->type));
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }

    if (!len) {
        VLOG_DBG_RL(&bad_ofmsg_rl, "action has invalid length 0");
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    if (len % ACTION_ALIGNMENT) {
        VLOG_DBG_RL(&bad_ofmsg_rl, "action length %u is not a multiple of %d",
                    len, ACTION_ALIGNMENT);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

int
validate_actions(const union ofp_action *actions, size_t n_actions,
                 int max_ports)
{
    const union ofp_action *a;

    for (a = actions; a < &actions[n_actions]; ) {
        unsigned int len = ntohs(a->header.len);
        unsigned int n_slots = len / ACTION_ALIGNMENT;
        unsigned int slots_left = &actions[n_actions] - a;
        int error;

        if (n_slots > slots_left) {
            VLOG_DBG_RL(&bad_ofmsg_rl,
                        "action requires %u slots but only %u remain",
                        n_slots, slots_left);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        }
        error = check_action(a, len, max_ports);
        if (error) {
            return error;
        }
        a += n_slots;
    }
    return 0;
}

/* The set of actions must either come from a trusted source or have been
 * previously validated with validate_actions(). */
const union ofp_action *
actions_first(struct actions_iterator *iter,
              const union ofp_action *oa, size_t n_actions)
{
    iter->pos = oa;
    iter->end = oa + n_actions;
    return actions_next(iter);
}

const union ofp_action *
actions_next(struct actions_iterator *iter)
{
    if (iter->pos < iter->end) {
        const union ofp_action *a = iter->pos;
        unsigned int len = ntohs(a->header.len);
        iter->pos += len / ACTION_ALIGNMENT;
        return a;
    } else {
        return NULL;
    }
}

void
normalize_match(struct ofp_match *m)
{
    enum { OFPFW_NW = OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK | OFPFW_NW_PROTO };
    enum { OFPFW_TP = OFPFW_TP_SRC | OFPFW_TP_DST };
    uint32_t wc;

    wc = ntohl(m->wildcards) & OFPFW_ALL;
    if (wc & OFPFW_DL_TYPE) {
        m->dl_type = 0;

        /* Can't sensibly match on network or transport headers if the
         * data link type is unknown. */
        wc |= OFPFW_NW | OFPFW_TP;
        m->nw_src = m->nw_dst = m->nw_proto = 0;
        m->tp_src = m->tp_dst = 0;
    } else if (m->dl_type == htons(ETH_TYPE_IP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;

            /* Can't sensibly match on transport headers if the network
             * protocol is unknown. */
            wc |= OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        } else if (m->nw_proto == IPPROTO_TCP ||
                   m->nw_proto == IPPROTO_UDP ||
                   m->nw_proto == IPPROTO_ICMP) {
            if (wc & OFPFW_TP_SRC) {
                m->tp_src = 0;
            }
            if (wc & OFPFW_TP_DST) {
                m->tp_dst = 0;
            }
        } else {
            /* Transport layer fields will always be extracted as zeros, so we
             * can do an exact-match on those values.  */
            wc &= ~OFPFW_TP;
            m->tp_src = m->tp_dst = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= flow_nw_bits_to_mask(wc, OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= flow_nw_bits_to_mask(wc, OFPFW_NW_DST_SHIFT);
        }
    } else if (m->dl_type == htons(ETH_TYPE_ARP)) {
        if (wc & OFPFW_NW_PROTO) {
            m->nw_proto = 0;
        }
        if (wc & OFPFW_NW_SRC_MASK) {
            m->nw_src &= flow_nw_bits_to_mask(wc, OFPFW_NW_SRC_SHIFT);
        }
        if (wc & OFPFW_NW_DST_MASK) {
            m->nw_dst &= flow_nw_bits_to_mask(wc, OFPFW_NW_DST_SHIFT);
        }
        m->tp_src = m->tp_dst = 0;
    } else {
        /* Network and transport layer fields will always be extracted as
         * zeros, so we can do an exact-match on those values. */
        wc &= ~(OFPFW_NW | OFPFW_TP);
        m->nw_proto = m->nw_src = m->nw_dst = 0;
        m->tp_src = m->tp_dst = 0;
    }
    if (wc & OFPFW_DL_SRC) {
        memset(m->dl_src, 0, sizeof m->dl_src);
    }
    if (wc & OFPFW_DL_DST) {
        memset(m->dl_dst, 0, sizeof m->dl_dst);
    }
    m->wildcards = htonl(wc);
}

/* Initializes 'vconn' as a new vconn named 'name', implemented via 'class'.
 * The initial connection status, supplied as 'connect_status', is interpreted
 * as follows:
 *
 *      - 0: 'vconn' is connected.  Its 'send' and 'recv' functions may be
 *        called in the normal fashion.
 *
 *      - EAGAIN: 'vconn' is trying to complete a connection.  Its 'connect'
 *        function should be called to complete the connection.
 *
 *      - Other positive errno values indicate that the connection failed with
 *        the specified error.
 *
 * After calling this function, vconn_close() must be used to destroy 'vconn',
 * otherwise resources will be leaked.
 *
 * The caller retains ownership of 'name'. */
void
vconn_init(struct vconn *vconn, struct vconn_class *class, int connect_status,
           const char *name)
{
    vconn->class = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->version = -1;
    vconn->min_version = -1;
    vconn->remote_ip = 0;
    vconn->remote_port = 0;
    vconn->local_ip = 0;
    vconn->local_port = 0;
    vconn->name = xstrdup(name);
}

void
vconn_set_remote_ip(struct vconn *vconn, uint32_t ip)
{
    vconn->remote_ip = ip;
}

void
vconn_set_remote_port(struct vconn *vconn, uint16_t port)
{
    vconn->remote_port = port;
}

void 
vconn_set_local_ip(struct vconn *vconn, uint32_t ip)
{
    vconn->local_ip = ip;
}

void 
vconn_set_local_port(struct vconn *vconn, uint16_t port)
{
    vconn->local_port = port;
}

void
pvconn_init(struct pvconn *pvconn, struct pvconn_class *class,
            const char *name)
{
    pvconn->class = class;
    pvconn->name = xstrdup(name);
}
