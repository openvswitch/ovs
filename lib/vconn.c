/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "fatal-signal.h"
#include "flow.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "util.h"
#include "vlog.h"
#include "socket-util.h"

VLOG_DEFINE_THIS_MODULE(vconn);

COVERAGE_DEFINE(vconn_open);
COVERAGE_DEFINE(vconn_received);
COVERAGE_DEFINE(vconn_sent);

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
        if (class->close || class->recv || class->send
            || class->run || class->run_wait || class->wait) {
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
vconn_usage(bool active, bool passive, bool bootstrap OVS_UNUSED)
{
    /* Really this should be implemented via callbacks into the vconn
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */

    printf("\n");
    if (active) {
        printf("Active OpenFlow connection methods:\n");
        printf("  tcp:IP[:PORT]           "
               "PORT (default: %d) at remote IP\n", OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:IP[:PORT]           "
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

/* Given 'name', a connection name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
vconn_lookup_class(const char *name, struct vconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
            struct vconn_class *class = vconn_classes[i];
            if (strlen(class->name) == prefix_len
                && !memcmp(class->name, name, prefix_len)) {
                *classp = class;
                return 0;
            }
        }
    }

    *classp = NULL;
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a connection name in the form "TYPE:ARGS" and TYPE is
 * a supported connection type, otherwise EAFNOSUPPORT.  */
int
vconn_verify_name(const char *name)
{
    struct vconn_class *class;
    return vconn_lookup_class(name, &class);
}

/* Attempts to connect to an OpenFlow device.  'name' is a connection name in
 * the form "TYPE:ARGS", where TYPE is an active vconn class's name and ARGS
 * are vconn class-specific.
 *
 * The vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than OFP10_VERSION.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*vconnp', otherwise a null
 * pointer.  */
int
vconn_open(const char *name, int min_version, struct vconn **vconnp,
           uint8_t dscp)
{
    struct vconn_class *class;
    struct vconn *vconn;
    char *suffix_copy;
    int error;

    COVERAGE_INC(vconn_open);
    check_vconn_classes();

    /* Look up the class. */
    error = vconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->open(name, suffix_copy, &vconn, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    assert(vconn->state != VCS_CONNECTING || vconn->class->connect);
    vconn->min_version = min_version;
    *vconnp = vconn;
    return 0;

error:
    *vconnp = NULL;
    return error;
}

/* Allows 'vconn' to perform maintenance activities, such as flushing output
 * buffers. */
void
vconn_run(struct vconn *vconn)
{
    if (vconn->state == VCS_CONNECTING ||
        vconn->state == VCS_SEND_HELLO ||
        vconn->state == VCS_RECV_HELLO) {
        vconn_connect(vconn);
    }

    if (vconn->class->run) {
        (vconn->class->run)(vconn);
    }
}

/* Arranges for the poll loop to wake up when 'vconn' needs to perform
 * maintenance activities. */
void
vconn_run_wait(struct vconn *vconn)
{
    if (vconn->state == VCS_CONNECTING ||
        vconn->state == VCS_SEND_HELLO ||
        vconn->state == VCS_RECV_HELLO) {
        vconn_connect_wait(vconn);
    }

    if (vconn->class->run_wait) {
        (vconn->class->run_wait)(vconn);
    }
}

int
vconn_open_block(const char *name, enum ofp_version min_version,
                 struct vconn **vconnp)
{
    struct vconn *vconn;
    int error;

    fatal_signal_run();

    error = vconn_open(name, min_version, &vconn, DSCP_DEFAULT);
    if (!error) {
        error = vconn_connect_block(vconn);
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
ovs_be32
vconn_get_remote_ip(const struct vconn *vconn)
{
    return vconn->remote_ip;
}

/* Returns the transport port of the peer, or 0 if the connection does not
 * contain a port or if the port is not yet known. */
ovs_be16
vconn_get_remote_port(const struct vconn *vconn)
{
    return vconn->remote_port;
}

/* Returns the IP address used to connect to the peer, or 0 if the
 * connection is not an IP-based protocol or if its IP address is not
 * yet known. */
ovs_be32
vconn_get_local_ip(const struct vconn *vconn)
{
    return vconn->local_ip;
}

/* Returns the transport port used to connect to the peer, or 0 if the
 * connection does not contain a port or if the port is not yet known. */
ovs_be16
vconn_get_local_port(const struct vconn *vconn)
{
    return vconn->local_port;
}

/* Returns the OpenFlow version negotiated with the peer, or -1 if version
 * negotiation is not yet complete.
 *
 * A vconn that has successfully connected (that is, vconn_connect() or
 * vconn_send() or vconn_recv() has returned 0) always negotiated a version. */
int
vconn_get_version(const struct vconn *vconn)
{
    return vconn->version ? vconn->version : -1;
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

    b = ofpraw_alloc(OFPRAW_OFPT_HELLO, OFP10_VERSION, 0);
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
        const struct ofp_header *oh = b->data;
        enum ofptype type;
        enum ofperr error;

        error = ofptype_decode(&type, b->data);
        if (!error && type == OFPTYPE_HELLO) {
            if (b->size > sizeof *oh) {
                struct ds msg = DS_EMPTY_INITIALIZER;
                ds_put_format(&msg, "%s: extra-long hello:\n", vconn->name);
                ds_put_hex_dump(&msg, b->data, b->size, 0, true);
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s", ds_cstr(&msg));
                ds_destroy(&msg);
            }

            vconn->version = MIN(OFP10_VERSION, oh->version);
            if (vconn->version < vconn->min_version) {
                VLOG_WARN_RL(&bad_ofmsg_rl,
                             "%s: version negotiation failed: we support "
                             "versions 0x%02x to 0x%02x inclusive but peer "
                             "supports no later than version 0x%02"PRIx8,
                             vconn->name, vconn->min_version, OFP10_VERSION,
                             oh->version);
                vconn->state = VCS_SEND_ERROR;
            } else {
                VLOG_DBG("%s: negotiated OpenFlow version 0x%02x "
                         "(we support versions 0x%02x to 0x%02x inclusive, "
                         "peer no later than version 0x%02"PRIx8")",
                         vconn->name, vconn->version, vconn->min_version,
                         OFP10_VERSION, oh->version);
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
    struct ofpbuf *b;
    char s[128];
    int retval;

    snprintf(s, sizeof s, "We support versions 0x%02x to 0x%02x inclusive but "
             "you support no later than version 0x%02"PRIx8".",
             vconn->min_version, OFP12_VERSION, vconn->version);
    b = ofperr_encode_hello(OFPERR_OFPHFC_INCOMPATIBLE, vconn->version, s);
    retval = do_send(vconn, b);
    if (retval) {
        ofpbuf_delete(b);
    }
    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval ? retval : EPROTO;
    }
}

/* Tries to complete the connection on 'vconn'. If 'vconn''s connection is
 * complete, returns 0 if the connection was successful or a positive errno
 * value if it failed.  If the connection is still in progress, returns
 * EAGAIN. */
int
vconn_connect(struct vconn *vconn)
{
    enum vconn_state last_state;

    assert(vconn->min_version > 0);
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

/* Tries to receive an OpenFlow message from 'vconn'.  If successful, stores
 * the received message into '*msgp' and returns 0.  The caller is responsible
 * for destroying the message with ofpbuf_delete().  On failure, returns a
 * positive errno value and stores a null pointer into '*msgp'.  On normal
 * connection close, returns EOF.
 *
 * vconn_recv will not block waiting for a packet to arrive.  If no packets
 * have been received, it returns EAGAIN immediately. */
int
vconn_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    struct ofpbuf *msg;
    int retval;

    retval = vconn_connect(vconn);
    if (!retval) {
        retval = do_recv(vconn, &msg);
    }
    if (!retval) {
        const struct ofp_header *oh = msg->data;
        if (oh->version != vconn->version) {
            enum ofptype type;

            if (ofptype_decode(&type, msg->data)
                || (type != OFPTYPE_HELLO &&
                    type != OFPTYPE_ERROR &&
                    type != OFPTYPE_ECHO_REQUEST &&
                    type != OFPTYPE_ECHO_REPLY)) {
                VLOG_ERR_RL(&bad_ofmsg_rl, "%s: received OpenFlow version "
                            "0x%02"PRIx8" != expected %02x",
                            vconn->name, oh->version, vconn->version);
                ofpbuf_delete(msg);
                retval = EPROTO;
            }
        }
    }

    *msgp = retval ? NULL : msg;
    return retval;
}

static int
do_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval = (vconn->class->recv)(vconn, msgp);
    if (!retval) {
        COVERAGE_INC(vconn_received);
        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string((*msgp)->data, (*msgp)->size, 1);
            VLOG_DBG_RL(&ofmsg_rl, "%s: received: %s", vconn->name, s);
            free(s);
        }
    }
    return retval;
}

/* Tries to queue 'msg' for transmission on 'vconn'.  If successful, returns 0,
 * in which case ownership of 'msg' is transferred to the vconn.  Success does
 * not guarantee that 'msg' has been or ever will be delivered to the peer,
 * only that it has been queued for transmission.
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

    ofpmsg_update_length(msg);
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

/* Same as vconn_connect(), except that it waits until the connection on
 * 'vconn' completes or fails.  Thus, it will never return EAGAIN. */
int
vconn_connect_block(struct vconn *vconn)
{
    int error;

    while ((error = vconn_connect(vconn)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_connect_wait(vconn);
        poll_block();
    }
    assert(error != EINPROGRESS);

    return error;
}

/* Same as vconn_send, except that it waits until 'msg' can be transmitted. */
int
vconn_send_block(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval;

    fatal_signal_run();

    while ((retval = vconn_send(vconn, msg)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
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

    fatal_signal_run();

    while ((retval = vconn_recv(vconn, msgp)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
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
vconn_recv_xid(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp)
{
    for (;;) {
        ovs_be32 recv_xid;
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
                    " != expected %08"PRIx32,
                    vconn->name, ntohl(recv_xid), ntohl(xid));
        ofpbuf_delete(reply);
    }
}

/* Sends 'request' to 'vconn' and blocks until it receives a reply with a
 * matching transaction ID.  Returns 0 if successful, in which case the reply
 * is stored in '*replyp' for the caller to examine and free.  Otherwise
 * returns a positive errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' should be an OpenFlow request that requires a reply.  Otherwise,
 * if there is no reply, this function can end up blocking forever (or until
 * the peer drops the connection).
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact(struct vconn *vconn, struct ofpbuf *request,
               struct ofpbuf **replyp)
{
    ovs_be32 send_xid = ((struct ofp_header *) request->data)->xid;
    int error;

    *replyp = NULL;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
    }
    return error ? error : vconn_recv_xid(vconn, send_xid, replyp);
}

/* Sends 'request' followed by a barrier request to 'vconn', then blocks until
 * it receives a reply to the barrier.  If successful, stores the reply to
 * 'request' in '*replyp', if one was received, and otherwise NULL, then
 * returns 0.  Otherwise returns a positive errno value, or EOF, and sets
 * '*replyp' to null.
 *
 * This function is useful for sending an OpenFlow request that doesn't
 * ordinarily include a reply but might report an error in special
 * circumstances.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact_noreply(struct vconn *vconn, struct ofpbuf *request,
                       struct ofpbuf **replyp)
{
    ovs_be32 request_xid;
    ovs_be32 barrier_xid;
    struct ofpbuf *barrier;
    int error;

    *replyp = NULL;

    /* Send request. */
    request_xid = ((struct ofp_header *) request->data)->xid;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
        return error;
    }

    /* Send barrier. */
    barrier = ofputil_encode_barrier_request(vconn_get_version(vconn));
    barrier_xid = ((struct ofp_header *) barrier->data)->xid;
    error = vconn_send_block(vconn, barrier);
    if (error) {
        ofpbuf_delete(barrier);
        return error;
    }

    for (;;) {
        struct ofpbuf *msg;
        ovs_be32 msg_xid;
        int error;

        error = vconn_recv_block(vconn, &msg);
        if (error) {
            ofpbuf_delete(*replyp);
            *replyp = NULL;
            return error;
        }

        msg_xid = ((struct ofp_header *) msg->data)->xid;
        if (msg_xid == request_xid) {
            if (*replyp) {
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s: duplicate replies with "
                             "xid %08"PRIx32, vconn->name, ntohl(msg_xid));
                ofpbuf_delete(*replyp);
            }
            *replyp = msg;
        } else {
            ofpbuf_delete(msg);
            if (msg_xid == barrier_xid) {
                return 0;
            } else {
                VLOG_DBG_RL(&bad_ofmsg_rl, "%s: reply with xid %08"PRIx32
                            " != expected %08"PRIx32" or %08"PRIx32,
                            vconn->name, ntohl(msg_xid),
                            ntohl(request_xid), ntohl(barrier_xid));
            }
        }
    }
}

/* vconn_transact_noreply() for a list of "struct ofpbuf"s, sent one by one.
 * All of the requests on 'requests' are always destroyed, regardless of the
 * return value. */
int
vconn_transact_multiple_noreply(struct vconn *vconn, struct list *requests,
                                struct ofpbuf **replyp)
{
    struct ofpbuf *request, *next;

    LIST_FOR_EACH_SAFE (request, next, list_node, requests) {
        int error;

        list_remove(&request->list_node);

        error = vconn_transact_noreply(vconn, request, replyp);
        if (error || *replyp) {
            ofpbuf_list_delete(requests);
            return error;
        }
    }

    *replyp = NULL;
    return 0;
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

/* Given 'name', a connection name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
pvconn_lookup_class(const char *name, struct pvconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
            struct pvconn_class *class = pvconn_classes[i];
            if (strlen(class->name) == prefix_len
                && !memcmp(class->name, name, prefix_len)) {
                *classp = class;
                return 0;
            }
        }
    }

    *classp = NULL;
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a connection name in the form "TYPE:ARGS" and TYPE is
 * a supported connection type, otherwise EAFNOSUPPORT.  */
int
pvconn_verify_name(const char *name)
{
    struct pvconn_class *class;
    return pvconn_lookup_class(name, &class);
}

/* Attempts to start listening for OpenFlow connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive vconn
 * class's name and ARGS are vconn class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pvconnp', otherwise a null
 * pointer.  */
int
pvconn_open(const char *name, struct pvconn **pvconnp, uint8_t dscp)
{
    struct pvconn_class *class;
    struct pvconn *pvconn;
    char *suffix_copy;
    int error;

    check_vconn_classes();

    /* Look up the class. */
    error = pvconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->listen(name, suffix_copy, &pvconn, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    *pvconnp = pvconn;
    return 0;

error:
    *pvconnp = NULL;
    return error;
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
 * no lower than 'min_version' and no higher than OFP10_VERSION.
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
    vconn->version = 0;
    vconn->min_version = 0;
    vconn->remote_ip = 0;
    vconn->remote_port = 0;
    vconn->local_ip = 0;
    vconn->local_port = 0;
    vconn->name = xstrdup(name);
    assert(vconn->state != VCS_CONNECTING || class->connect);
}

void
vconn_set_remote_ip(struct vconn *vconn, ovs_be32 ip)
{
    vconn->remote_ip = ip;
}

void
vconn_set_remote_port(struct vconn *vconn, ovs_be16 port)
{
    vconn->remote_port = port;
}

void
vconn_set_local_ip(struct vconn *vconn, ovs_be32 ip)
{
    vconn->local_ip = ip;
}

void
vconn_set_local_port(struct vconn *vconn, ovs_be16 port)
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
