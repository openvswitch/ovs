/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-bundle.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "random.h"
#include "util.h"
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

static const struct vconn_class *vconn_classes[] = {
    &tcp_vconn_class,
    &unix_vconn_class,
#ifdef HAVE_OPENSSL
    &ssl_vconn_class,
#endif
};

static const struct pvconn_class *pvconn_classes[] = {
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
        const struct vconn_class *class = vconn_classes[i];
        ovs_assert(class->name != NULL);
        ovs_assert(class->open != NULL);
        if (class->close || class->recv || class->send
            || class->run || class->run_wait || class->wait) {
            ovs_assert(class->close != NULL);
            ovs_assert(class->recv != NULL);
            ovs_assert(class->send != NULL);
            ovs_assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }

    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        const struct pvconn_class *class = pvconn_classes[i];
        ovs_assert(class->name != NULL);
        ovs_assert(class->listen != NULL);
        if (class->close || class->accept || class->wait) {
            ovs_assert(class->close != NULL);
            ovs_assert(class->accept != NULL);
            ovs_assert(class->wait != NULL);
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
               "PORT (default: %d) at remote IP\n", OFP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:IP[:PORT]           "
               "SSL PORT (default: %d) at remote IP\n", OFP_PORT);
#endif
        printf("  unix:FILE               Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive OpenFlow connection methods:\n");
        printf("  ptcp:[PORT][:IP]        "
               "listen to TCP PORT (default: %d) on IP\n",
               OFP_PORT);
#ifdef HAVE_OPENSSL
        printf("  pssl:[PORT][:IP]        "
               "listen for SSL on PORT (default: %d) on IP\n",
               OFP_PORT);
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
vconn_lookup_class(const char *name, const struct vconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
            const struct vconn_class *class = vconn_classes[i];
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
    const struct vconn_class *class;
    return vconn_lookup_class(name, &class);
}

/* Attempts to connect to an OpenFlow device.  'name' is a connection name in
 * the form "TYPE:ARGS", where TYPE is an active vconn class's name and ARGS
 * are vconn class-specific.
 *
 * The vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * one of those in the 'allowed_versions' bitmap: version 'x' is allowed if
 * allowed_versions & (1 << x) is nonzero.  If 'allowed_versions' is zero, then
 * OFPUTIL_DEFAULT_VERSIONS are allowed.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*vconnp', otherwise a null
 * pointer.  */
int
vconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
           struct vconn **vconnp)
{
    const struct vconn_class *class;
    struct vconn *vconn;
    char *suffix_copy;
    int error;

    COVERAGE_INC(vconn_open);
    check_vconn_classes();

    if (!allowed_versions) {
        allowed_versions = OFPUTIL_DEFAULT_VERSIONS;
    }

    /* Look up the class. */
    error = vconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->open(name, allowed_versions, suffix_copy, &vconn, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    ovs_assert(vconn->state != VCS_CONNECTING || vconn->vclass->connect);
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

    if (vconn->vclass->run) {
        (vconn->vclass->run)(vconn);
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

    if (vconn->vclass->run_wait) {
        (vconn->vclass->run_wait)(vconn);
    }
}

/* Returns 0 if 'vconn' is healthy (connecting or connected), a positive errno
 * value if the connection died abnormally (connection failed or aborted), or
 * EOF if the connection was closed in a normal way. */
int
vconn_get_status(const struct vconn *vconn)
{
    return vconn->error == EAGAIN ? 0 : vconn->error;
}

int
vconn_open_block(const char *name, uint32_t allowed_versions, uint8_t dscp,
                 struct vconn **vconnp)
{
    struct vconn *vconn;
    int error;

    fatal_signal_run();

    error = vconn_open(name, allowed_versions, dscp, &vconn);
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
        (vconn->vclass->close)(vconn);
        free(name);
    }
}

/* Returns the name of 'vconn', that is, the string passed to vconn_open(). */
const char *
vconn_get_name(const struct vconn *vconn)
{
    return vconn->name;
}

/* Returns the allowed_versions of 'vconn', that is,
 * the allowed_versions passed to vconn_open(). */
uint32_t
vconn_get_allowed_versions(const struct vconn *vconn)
{
    return vconn->allowed_versions;
}

/* Sets the allowed_versions of 'vconn', overriding
 * the allowed_versions passed to vconn_open(). */
void
vconn_set_allowed_versions(struct vconn *vconn, uint32_t allowed_versions)
{
    vconn->allowed_versions = allowed_versions;
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

/* By default, a vconn accepts only OpenFlow messages whose version matches the
 * one negotiated for the connection.  A message received with a different
 * version is an error that causes the vconn to drop the connection.
 *
 * This functions allows 'vconn' to accept messages with any OpenFlow version.
 * This is useful in the special case where 'vconn' is used as an rconn
 * "monitor" connection (see rconn_add_monitor()), that is, where 'vconn' is
 * used as a target for mirroring OpenFlow messages for debugging and
 * troubleshooting.
 *
 * This function should be called after a successful vconn_open() or
 * pvconn_accept() but before the connection completes, that is, before
 * vconn_connect() returns success.  Otherwise, messages that arrive on 'vconn'
 * beforehand with an unexpected version will the vconn to drop the
 * connection. */
void
vconn_set_recv_any_version(struct vconn *vconn)
{
    vconn->recv_any_version = true;
}

static void
vcs_connecting(struct vconn *vconn)
{
    int retval = (vconn->vclass->connect)(vconn);
    ovs_assert(retval != EINPROGRESS);
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

    b = ofputil_encode_hello(vconn->allowed_versions);
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

static char *
version_bitmap_to_string(uint32_t bitmap)
{
    struct ds s;

    ds_init(&s);
    if (!bitmap) {
        ds_put_cstr(&s, "no versions");
    } else if (is_pow2(bitmap)) {
        ds_put_cstr(&s, "version ");
        ofputil_format_version(&s, leftmost_1bit_idx(bitmap));
    } else if (is_pow2((bitmap >> 1) + 1)) {
        ds_put_cstr(&s, "version ");
        ofputil_format_version(&s, leftmost_1bit_idx(bitmap));
        ds_put_cstr(&s, " and earlier");
    } else {
        ds_put_cstr(&s, "versions ");
        ofputil_format_version_bitmap(&s, bitmap);
    }
    return ds_steal_cstr(&s);
}

static void
vcs_recv_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    retval = do_recv(vconn, &b);
    if (!retval) {
        enum ofptype type;
        enum ofperr error;

        error = ofptype_decode(&type, b->data);
        if (!error && type == OFPTYPE_HELLO) {
            char *peer_s, *local_s;
            uint32_t common_versions;

            if (!ofputil_decode_hello(b->data, &vconn->peer_versions)) {
                struct ds msg = DS_EMPTY_INITIALIZER;
                ds_put_format(&msg, "%s: unknown data in hello:\n",
                              vconn->name);
                ds_put_hex_dump(&msg, b->data, b->size, 0, true);
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s", ds_cstr(&msg));
                ds_destroy(&msg);
            }

            local_s = version_bitmap_to_string(vconn->allowed_versions);
            peer_s = version_bitmap_to_string(vconn->peer_versions);

            common_versions = vconn->peer_versions & vconn->allowed_versions;
            if (!common_versions) {
                vconn->version = leftmost_1bit_idx(vconn->peer_versions);
                VLOG_WARN_RL(&bad_ofmsg_rl,
                             "%s: version negotiation failed (we support "
                             "%s, peer supports %s)",
                             vconn->name, local_s, peer_s);
                vconn->state = VCS_SEND_ERROR;
            } else {
                vconn->version = leftmost_1bit_idx(common_versions);
                VLOG_DBG("%s: negotiated OpenFlow version 0x%02x "
                         "(we support %s, peer supports %s)", vconn->name,
                         vconn->version, local_s, peer_s);
                vconn->state = VCS_CONNECTED;
            }

            free(local_s);
            free(peer_s);

            ofpbuf_delete(b);
            return;
        } else {
            char *s = ofp_to_string(b->data, b->size, NULL, NULL, 1);
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
    char *local_s, *peer_s;

    local_s = version_bitmap_to_string(vconn->allowed_versions);
    peer_s = version_bitmap_to_string(vconn->peer_versions);
    snprintf(s, sizeof s, "We support %s, you support %s, no common versions.",
             local_s, peer_s);
    free(peer_s);
    free(local_s);

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
            ovs_assert(vconn->error != 0);
            return vconn->error;

        default:
            OVS_NOT_REACHED();
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
    if (!retval && !vconn->recv_any_version) {
        const struct ofp_header *oh = msg->data;
        if (oh->version != vconn->version) {
            enum ofptype type;

            if (ofptype_decode(&type, msg->data)
                || (type != OFPTYPE_HELLO &&
                    type != OFPTYPE_ERROR &&
                    type != OFPTYPE_ECHO_REQUEST &&
                    type != OFPTYPE_ECHO_REPLY)) {
                struct ofpbuf *reply;

                VLOG_ERR_RL(&bad_ofmsg_rl, "%s: received OpenFlow version "
                            "0x%02"PRIx8" != expected %02x",
                            vconn->name, oh->version, vconn->version);

                /* Send a "bad version" reply, if we can. */
                reply = ofperr_encode_reply(OFPERR_OFPBRC_BAD_VERSION, oh);
                retval = vconn_send(vconn, reply);
                if (retval) {
                    VLOG_INFO_RL(&bad_ofmsg_rl,
                                 "%s: failed to queue error reply (%s)",
                                 vconn->name, ovs_strerror(retval));
                    ofpbuf_delete(reply);
                }

                /* Suppress the received message, as if it had not arrived. */
                retval = EAGAIN;
                ofpbuf_delete(msg);
            }
        }
    }

    *msgp = retval ? NULL : msg;
    return retval;
}

static int
do_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval = (vconn->vclass->recv)(vconn, msgp);
    if (!retval) {
        COVERAGE_INC(vconn_received);
        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string((*msgp)->data, (*msgp)->size,
                                    NULL, NULL, 1);
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

    ovs_assert(msg->size >= sizeof(struct ofp_header));

    ofpmsg_update_length(msg);
    if (!VLOG_IS_DBG_ENABLED()) {
        COVERAGE_INC(vconn_sent);
        retval = (vconn->vclass->send)(vconn, msg);
    } else {
        char *s = ofp_to_string(msg->data, msg->size, NULL, NULL, 1);
        retval = (vconn->vclass->send)(vconn, msg);
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&ofmsg_rl, "%s: sent (%s): %s",
                        vconn->name, ovs_strerror(retval), s);
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
    ovs_assert(error != EINPROGRESS);

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

static int
vconn_recv_xid__(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp,
                 struct ovs_list *errors)
{
    for (;;) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;
        const struct ofp_header *oh;
        enum ofptype type;
        int error;

        error = vconn_recv_block(vconn, &reply);
        if (error) {
            *replyp = NULL;
            return error;
        }
        oh = reply->data;
        recv_xid = oh->xid;
        if (xid == recv_xid) {
            *replyp = reply;
            return 0;
        }

        error = ofptype_decode(&type, oh);
        if (!error && type == OFPTYPE_ERROR) {
            ovs_list_push_back(errors, &reply->list_node);
        } else {
            VLOG_DBG_RL(&bad_ofmsg_rl, "%s: received reply with xid %08"PRIx32
                        " != expected %08"PRIx32,
                        vconn->name, ntohl(recv_xid), ntohl(xid));
            ofpbuf_delete(reply);
        }
    }
}

/* Waits until a message with a transaction ID matching 'xid' is received on
 * 'vconn'.  Returns 0 if successful, in which case the reply is stored in
 * '*replyp' for the caller to examine and free.  Otherwise returns a positive
 * errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_recv_xid(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp)
{
    return vconn_recv_xid__(vconn, xid, replyp, NULL);
}

static int
vconn_transact__(struct vconn *vconn, struct ofpbuf *request,
                 struct ofpbuf **replyp, struct ovs_list *errors)
{
    ovs_be32 send_xid = ((struct ofp_header *) request->data)->xid;
    int error;

    *replyp = NULL;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
    }
    return error ? error : vconn_recv_xid__(vconn, send_xid, replyp, errors);
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
    return vconn_transact__(vconn, request, replyp, NULL);
}

static int
vconn_send_barrier(struct vconn *vconn, ovs_be32 *barrier_xid)
{
    struct ofpbuf *barrier;
    int error;

    /* Send barrier. */
    barrier = ofputil_encode_barrier_request(vconn_get_version(vconn));
    *barrier_xid = ((struct ofp_header *) barrier->data)->xid;
    error = vconn_send_block(vconn, barrier);
    if (error) {
        ofpbuf_delete(barrier);
    }
    return error;
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
    error = vconn_send_barrier(vconn, &barrier_xid);
    if (error) {
        return error;
    }

    for (;;) {
        struct ofpbuf *msg;
        ovs_be32 msg_xid;

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
vconn_transact_multiple_noreply(struct vconn *vconn, struct ovs_list *requests,
                                struct ofpbuf **replyp)
{
    struct ofpbuf *request;

    LIST_FOR_EACH_POP (request, list_node, requests) {
        int error;

        error = vconn_transact_noreply(vconn, request, replyp);
        if (error || *replyp) {
            ofpbuf_list_delete(requests);
            return error;
        }
    }

    *replyp = NULL;
    return 0;
}

static int
recv_flow_stats_reply(struct vconn *vconn, ovs_be32 send_xid,
                      struct ofpbuf **replyp,
                      struct ofputil_flow_stats *fs, struct ofpbuf *ofpacts)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct ofpbuf *reply = *replyp;

    for (;;) {
        int retval;
        bool more;

        /* Get a flow stats reply message, if we don't already have one. */
        if (!reply) {
            enum ofptype type;
            enum ofperr error;

            do {
                error = vconn_recv_block(vconn, &reply);
                if (error) {
                    return error;
                }
            } while (((struct ofp_header *) reply->data)->xid != send_xid);

            error = ofptype_decode(&type, reply->data);
            if (error || type != OFPTYPE_FLOW_STATS_REPLY) {
                VLOG_WARN_RL(&rl, "received bad reply: %s",
                             ofp_to_string(reply->data, reply->size,
                                           NULL, NULL, 1));
                return EPROTO;
            }
        }

        /* Pull an individual flow stats reply out of the message. */
        retval = ofputil_decode_flow_stats_reply(fs, reply, false, ofpacts);
        switch (retval) {
        case 0:
            *replyp = reply;
            return 0;

        case EOF:
            more = ofpmp_more(reply->header);
            ofpbuf_delete(reply);
            reply = NULL;
            if (!more) {
                *replyp = NULL;
                return EOF;
            }
            break;

        default:
            VLOG_WARN_RL(&rl, "parse error in reply (%s)",
                         ofperr_to_string(retval));
            return EPROTO;
        }
    }
}

/* Sends 'fsr' to 'vconn', encoding it with the given 'protocol', and then
 * waits for, parses, and accumulates all of the replies into '*fsesp' and
 * '*n_fsesp'.  The caller is responsible for freeing all of the flows.
 * Returns 0 if successful, otherwise a positive errno value. */
int
vconn_dump_flows(struct vconn *vconn,
                 const struct ofputil_flow_stats_request *fsr,
                 enum ofputil_protocol protocol,
                 struct ofputil_flow_stats **fsesp, size_t *n_fsesp)
{
    struct ofputil_flow_stats *fses = NULL;
    size_t n_fses = 0;
    size_t allocated_fses = 0;

    struct ofpbuf *request = ofputil_encode_flow_stats_request(fsr, protocol);
    const struct ofp_header *oh = request->data;
    ovs_be32 send_xid = oh->xid;
    int error = vconn_send_block(vconn, request);
    if (error) {
        goto exit;
    }

    struct ofpbuf *reply = NULL;
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);
    for (;;) {
        if (n_fses >= allocated_fses) {
            fses = x2nrealloc(fses, &allocated_fses, sizeof *fses);
        }

        struct ofputil_flow_stats *fs = &fses[n_fses];
        error = recv_flow_stats_reply(vconn, send_xid, &reply, fs, &ofpacts);
        if (error) {
            if (error == EOF) {
                error = 0;
            }
            break;
        }
        fs->ofpacts = xmemdup(fs->ofpacts, fs->ofpacts_len);
        n_fses++;
    }
    ofpbuf_uninit(&ofpacts);
    ofpbuf_delete(reply);

    if (error) {
        for (size_t i = 0; i < n_fses; i++) {
            free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
        }
        free(fses);

        fses = NULL;
        n_fses = 0;
    }

exit:
    *fsesp = fses;
    *n_fsesp = n_fses;
    return error;
}


static enum ofperr
vconn_bundle_reply_validate(struct ofpbuf *reply,
                            struct ofputil_bundle_ctrl_msg *request,
                            struct ovs_list *errors)
{
    const struct ofp_header *oh;
    enum ofptype type;
    enum ofperr error;
    struct ofputil_bundle_ctrl_msg rbc;

    oh = reply->data;
    error = ofptype_decode(&type, oh);
    if (error) {
        return error;
    }

    if (type == OFPTYPE_ERROR) {
        struct ofpbuf *copy = ofpbuf_clone(reply);
        ovs_list_push_back(errors, &copy->list_node);
        return ofperr_decode_msg(oh, NULL);
    }
    if (type != OFPTYPE_BUNDLE_CONTROL) {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    error = ofputil_decode_bundle_ctrl(oh, &rbc);
    if (error) {
        return error;
    }

    if (rbc.bundle_id != request->bundle_id) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    if (rbc.type != request->type + 1) {
        return OFPERR_OFPBFC_BAD_TYPE;
    }

    return 0;
}

/* Send bundle control message 'bc' of 'type' via 'vconn', and wait for either
 * an error or the corresponding bundle control message response.
 *
 * 'errors' is a list to which any OpenFlow errors relating to bundle
 * processing are appended.  Caller is responsible for releasing the memory of
 * each node in the list on return.
 *
 * Returns errno value, or 0 when successful. */
static int
vconn_bundle_control_transact(struct vconn *vconn,
                              struct ofputil_bundle_ctrl_msg *bc,
                              uint16_t type, struct ovs_list *errors)
{
    struct ofpbuf *request, *reply;
    int error;
    enum ofperr ofperr;

    bc->type = type;
    request = ofputil_encode_bundle_ctrl_request(vconn->version, bc);
    ofpmsg_update_length(request);
    error = vconn_transact__(vconn, request, &reply, errors);
    if (error) {
        return error;
    }

    ofperr = vconn_bundle_reply_validate(reply, bc, errors);
    ofpbuf_delete(reply);

    return ofperr ? EPROTO : 0;
}

/* Checks if error responses can be received on 'vconn'. */
static void
vconn_recv_error(struct vconn *vconn, struct ovs_list *errors)
{
    int error;

    do {
        struct ofpbuf *reply;

        error = vconn_recv(vconn, &reply);
        if (!error) {
            const struct ofp_header *oh;
            enum ofptype type;
            enum ofperr ofperr;

            oh = reply->data;
            ofperr = ofptype_decode(&type, oh);
            if (!ofperr && type == OFPTYPE_ERROR) {
                ovs_list_push_back(errors, &reply->list_node);
            } else {
                VLOG_DBG_RL(&bad_ofmsg_rl,
                            "%s: received unexpected reply with xid %08"PRIx32,
                            vconn->name, ntohl(oh->xid));
                ofpbuf_delete(reply);
            }
        }
    } while (!error);
}

/* Sends a barrier and waits for the barrier response and stores any errors
 * that are received before the barrier response. */
static int
vconn_bundle_barrier_transact(struct vconn *vconn, struct ovs_list *errors)
{
    struct ofpbuf *reply;
    ovs_be32 barrier_xid;
    int error;

    error = vconn_send_barrier(vconn, &barrier_xid);
    if (error) {
        return error;
    }

    error = vconn_recv_xid__(vconn, barrier_xid, &reply, errors);
    if (error) {
        return error;
    }
    ofpbuf_delete(reply);
    return 0;
}

static int
vconn_bundle_add_msg(struct vconn *vconn, struct ofputil_bundle_ctrl_msg *bc,
                     struct ofpbuf *msg,
                     struct ovs_list *errors)
{
    struct ofputil_bundle_add_msg bam;
    struct ofpbuf *request;
    int error;

    ofpmsg_update_length(msg);

    bam.bundle_id = bc->bundle_id;
    bam.flags = bc->flags;
    bam.msg = msg->data;

    request = ofputil_encode_bundle_add(vconn->version, &bam);

    error = vconn_send_block(vconn, request);
    if (!error) {
        /* Check for an error return, so that the socket buffer does not become
         * full of errors. */
        vconn_recv_error(vconn, errors);
    }
    return error;
}

/* Appends ofpbufs for received errors, if any, to 'errors'.  The caller must
 * free the received errors. */
int
vconn_bundle_transact(struct vconn *vconn, struct ovs_list *requests,
                      uint16_t flags, struct ovs_list *errors)
{
    struct ofputil_bundle_ctrl_msg bc;
    struct ofpbuf *request;
    int error;

    ovs_list_init(errors);

    memset(&bc, 0, sizeof bc);
    bc.flags = flags;
    error = vconn_bundle_control_transact(vconn, &bc, OFPBCT_OPEN_REQUEST,
                                          errors);
    if (error) {
        return error;
    }

    LIST_FOR_EACH (request, list_node, requests) {
        error = vconn_bundle_add_msg(vconn, &bc, request, errors);
        if (error) {
            break;
        }
    }

    if (!error) {
        /* A failing message does not invalidate the bundle, but the message is
         * simply not added to the bundle.  Since we do not want to commit if
         * any of the messages failed, we need to explicitly sync with barrier
         * before we issue the commit message. */
        error = vconn_bundle_barrier_transact(vconn, errors);
    }
    if (!error && !ovs_list_is_empty(errors)) {
        error = EPROTO;
    }

    /* Commit only if no errors are received. */
    if (!error) {
        error = vconn_bundle_control_transact(vconn, &bc,
                                              OFPBCT_COMMIT_REQUEST,
                                              errors);
    } else {
        vconn_bundle_control_transact(vconn, &bc, OFPBCT_DISCARD_REQUEST,
                                      errors);
    }
    return error;
}

void
vconn_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    ovs_assert(wait == WAIT_CONNECT || wait == WAIT_RECV || wait == WAIT_SEND);

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
    (vconn->vclass->wait)(vconn, wait);
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
pvconn_lookup_class(const char *name, const struct pvconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
            const struct pvconn_class *class = pvconn_classes[i];
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
    const struct pvconn_class *class;
    return pvconn_lookup_class(name, &class);
}

/* Attempts to start listening for OpenFlow connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive vconn
 * class's name and ARGS are vconn class-specific.
 *
 * vconns accepted by the pvconn will automatically negotiate an OpenFlow
 * protocol version acceptable to both peers on the connection.  The version
 * negotiated will be one of those in the 'allowed_versions' bitmap: version
 * 'x' is allowed if allowed_versions & (1 << x) is nonzero.  If
 * 'allowed_versions' is zero, then OFPUTIL_DEFAULT_VERSIONS are allowed.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pvconnp', otherwise a null
 * pointer.  */
int
pvconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
            struct pvconn **pvconnp)
{
    const struct pvconn_class *class;
    struct pvconn *pvconn;
    char *suffix_copy;
    int error;

    check_vconn_classes();

    if (!allowed_versions) {
        allowed_versions = OFPUTIL_DEFAULT_VERSIONS;
    }

    /* Look up the class. */
    error = pvconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->listen(name, allowed_versions, suffix_copy, &pvconn, dscp);
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
        (pvconn->pvclass->close)(pvconn);
        free(name);
    }
}

/* Tries to accept a new connection on 'pvconn'.  If successful, stores the new
 * connection in '*new_vconn' and returns 0.  Otherwise, returns a positive
 * errno value.
 *
 * The new vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than 'max_version'.
 *
 * pvconn_accept() will not block waiting for a connection.  If no connection
 * is ready to be accepted, it returns EAGAIN immediately. */
int
pvconn_accept(struct pvconn *pvconn, struct vconn **new_vconn)
{
    int retval = (pvconn->pvclass->accept)(pvconn, new_vconn);
    if (retval) {
        *new_vconn = NULL;
    } else {
        ovs_assert((*new_vconn)->state != VCS_CONNECTING
                   || (*new_vconn)->vclass->connect);
    }
    return retval;
}

void
pvconn_wait(struct pvconn *pvconn)
{
    (pvconn->pvclass->wait)(pvconn);
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
vconn_init(struct vconn *vconn, const struct vconn_class *class,
           int connect_status, const char *name, uint32_t allowed_versions)
{
    memset(vconn, 0, sizeof *vconn);
    vconn->vclass = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->allowed_versions = allowed_versions;
    vconn->name = xstrdup(name);
    ovs_assert(vconn->state != VCS_CONNECTING || class->connect);
}

void
pvconn_init(struct pvconn *pvconn, const struct pvconn_class *class,
            const char *name, uint32_t allowed_versions)
{
    pvconn->pvclass = class;
    pvconn->name = xstrdup(name);
    pvconn->allowed_versions = allowed_versions;
}
