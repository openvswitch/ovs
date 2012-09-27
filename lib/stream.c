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
#include "stream-provider.h"
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
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stream);

COVERAGE_DEFINE(pstream_open);
COVERAGE_DEFINE(stream_open);

/* State of an active stream.*/
enum stream_state {
    SCS_CONNECTING,             /* Underlying stream is not connected. */
    SCS_CONNECTED,              /* Connection established. */
    SCS_DISCONNECTED            /* Connection failed or connection closed. */
};

static const struct stream_class *stream_classes[] = {
    &tcp_stream_class,
    &unix_stream_class,
#ifdef HAVE_OPENSSL
    &ssl_stream_class,
#endif
};

static const struct pstream_class *pstream_classes[] = {
    &ptcp_pstream_class,
    &punix_pstream_class,
#ifdef HAVE_OPENSSL
    &pssl_pstream_class,
#endif
};

/* Check the validity of the stream class structures. */
static void
check_stream_classes(void)
{
#ifndef NDEBUG
    size_t i;

    for (i = 0; i < ARRAY_SIZE(stream_classes); i++) {
        const struct stream_class *class = stream_classes[i];
        assert(class->name != NULL);
        assert(class->open != NULL);
        if (class->close || class->recv || class->send || class->run
            || class->run_wait || class->wait) {
            assert(class->close != NULL);
            assert(class->recv != NULL);
            assert(class->send != NULL);
            assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }

    for (i = 0; i < ARRAY_SIZE(pstream_classes); i++) {
        const struct pstream_class *class = pstream_classes[i];
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
 * connection methods supported by the stream. */
void
stream_usage(const char *name, bool active, bool passive,
             bool bootstrap OVS_UNUSED)
{
    /* Really this should be implemented via callbacks into the stream
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */

    printf("\n");
    if (active) {
        printf("Active %s connection methods:\n", name);
        printf("  tcp:IP:PORT             "
               "PORT at remote IP\n");
#ifdef HAVE_OPENSSL
        printf("  ssl:IP:PORT             "
               "SSL PORT at remote IP\n");
#endif
        printf("  unix:FILE               "
               "Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive %s connection methods:\n", name);
        printf("  ptcp:PORT[:IP]          "
               "listen to TCP PORT on IP\n");
#ifdef HAVE_OPENSSL
        printf("  pssl:PORT[:IP]          "
               "listen for SSL on PORT on IP\n");
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

/* Given 'name', a stream name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
stream_lookup_class(const char *name, const struct stream_class **classp)
{
    size_t prefix_len;
    size_t i;

    check_stream_classes();

    *classp = NULL;
    prefix_len = strcspn(name, ":");
    if (name[prefix_len] == '\0') {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(stream_classes); i++) {
        const struct stream_class *class = stream_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            *classp = class;
            return 0;
        }
    }
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a stream name in the form "TYPE:ARGS" and TYPE is
 * a supported stream type, otherwise EAFNOSUPPORT.  */
int
stream_verify_name(const char *name)
{
    const struct stream_class *class;
    return stream_lookup_class(name, &class);
}

/* Attempts to connect a stream to a remote peer.  'name' is a connection name
 * in the form "TYPE:ARGS", where TYPE is an active stream class's name and
 * ARGS are stream class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*streamp', otherwise a null
 * pointer.  */
int
stream_open(const char *name, struct stream **streamp, uint8_t dscp)
{
    const struct stream_class *class;
    struct stream *stream;
    char *suffix_copy;
    int error;

    COVERAGE_INC(stream_open);

    /* Look up the class. */
    error = stream_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->open(name, suffix_copy, &stream, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    *streamp = stream;
    return 0;

error:
    *streamp = NULL;
    return error;
}

/* Blocks until a previously started stream connection attempt succeeds or
 * fails.  'error' should be the value returned by stream_open() and 'streamp'
 * should point to the stream pointer set by stream_open().  Returns 0 if
 * successful, otherwise a positive errno value other than EAGAIN or
 * EINPROGRESS.  If successful, leaves '*streamp' untouched; on error, closes
 * '*streamp' and sets '*streamp' to null.
 *
 * Typical usage:
 *   error = stream_open_block(stream_open("tcp:1.2.3.4:5", &stream), &stream);
 */
int
stream_open_block(int error, struct stream **streamp)
{
    struct stream *stream = *streamp;

    fatal_signal_run();

    if (!error) {
        while ((error = stream_connect(stream)) == EAGAIN) {
            stream_run(stream);
            stream_run_wait(stream);
            stream_connect_wait(stream);
            poll_block();
        }
        assert(error != EINPROGRESS);
    }

    if (error) {
        stream_close(stream);
        *streamp = NULL;
    } else {
        *streamp = stream;
    }
    return error;
}

/* Closes 'stream'. */
void
stream_close(struct stream *stream)
{
    if (stream != NULL) {
        char *name = stream->name;
        (stream->class->close)(stream);
        free(name);
    }
}

/* Returns the name of 'stream', that is, the string passed to
 * stream_open(). */
const char *
stream_get_name(const struct stream *stream)
{
    return stream ? stream->name : "(null)";
}

/* Returns the IP address of the peer, or 0 if the peer is not connected over
 * an IP-based protocol or if its IP address is not yet known. */
ovs_be32
stream_get_remote_ip(const struct stream *stream)
{
    return stream->remote_ip;
}

/* Returns the transport port of the peer, or 0 if the connection does not
 * contain a port or if the port is not yet known. */
ovs_be16
stream_get_remote_port(const struct stream *stream)
{
    return stream->remote_port;
}

/* Returns the IP address used to connect to the peer, or 0 if the connection
 * is not an IP-based protocol or if its IP address is not yet known. */
ovs_be32
stream_get_local_ip(const struct stream *stream)
{
    return stream->local_ip;
}

/* Returns the transport port used to connect to the peer, or 0 if the
 * connection does not contain a port or if the port is not yet known. */
ovs_be16
stream_get_local_port(const struct stream *stream)
{
    return stream->local_port;
}

static void
scs_connecting(struct stream *stream)
{
    int retval = (stream->class->connect)(stream);
    assert(retval != EINPROGRESS);
    if (!retval) {
        stream->state = SCS_CONNECTED;
    } else if (retval != EAGAIN) {
        stream->state = SCS_DISCONNECTED;
        stream->error = retval;
    }
}

/* Tries to complete the connection on 'stream'.  If 'stream''s connection is
 * complete, returns 0 if the connection was successful or a positive errno
 * value if it failed.  If the connection is still in progress, returns
 * EAGAIN. */
int
stream_connect(struct stream *stream)
{
    enum stream_state last_state;

    do {
        last_state = stream->state;
        switch (stream->state) {
        case SCS_CONNECTING:
            scs_connecting(stream);
            break;

        case SCS_CONNECTED:
            return 0;

        case SCS_DISCONNECTED:
            return stream->error;

        default:
            NOT_REACHED();
        }
    } while (stream->state != last_state);

    return EAGAIN;
}

/* Tries to receive up to 'n' bytes from 'stream' into 'buffer', and returns:
 *
 *     - If successful, the number of bytes received (between 1 and 'n').
 *
 *     - On error, a negative errno value.
 *
 *     - 0, if the connection has been closed in the normal fashion, or if 'n'
 *       is zero.
 *
 * The recv function will not block waiting for a packet to arrive.  If no
 * data have been received, it returns -EAGAIN immediately. */
int
stream_recv(struct stream *stream, void *buffer, size_t n)
{
    int retval = stream_connect(stream);
    return (retval ? -retval
            : n == 0 ? 0
            : (stream->class->recv)(stream, buffer, n));
}

/* Tries to send up to 'n' bytes of 'buffer' on 'stream', and returns:
 *
 *     - If successful, the number of bytes sent (between 1 and 'n').  0 is
 *       only a valid return value if 'n' is 0.
 *
 *     - On error, a negative errno value.
 *
 * The send function will not block.  If no bytes can be immediately accepted
 * for transmission, it returns -EAGAIN immediately. */
int
stream_send(struct stream *stream, const void *buffer, size_t n)
{
    int retval = stream_connect(stream);
    return (retval ? -retval
            : n == 0 ? 0
            : (stream->class->send)(stream, buffer, n));
}

/* Allows 'stream' to perform maintenance activities, such as flushing
 * output buffers. */
void
stream_run(struct stream *stream)
{
    if (stream->class->run) {
        (stream->class->run)(stream);
    }
}

/* Arranges for the poll loop to wake up when 'stream' needs to perform
 * maintenance activities. */
void
stream_run_wait(struct stream *stream)
{
    if (stream->class->run_wait) {
        (stream->class->run_wait)(stream);
    }
}

/* Arranges for the poll loop to wake up when 'stream' is ready to take an
 * action of the given 'type'. */
void
stream_wait(struct stream *stream, enum stream_wait_type wait)
{
    assert(wait == STREAM_CONNECT || wait == STREAM_RECV
           || wait == STREAM_SEND);

    switch (stream->state) {
    case SCS_CONNECTING:
        wait = STREAM_CONNECT;
        break;

    case SCS_DISCONNECTED:
        poll_immediate_wake();
        return;
    }
    (stream->class->wait)(stream, wait);
}

void
stream_connect_wait(struct stream *stream)
{
    stream_wait(stream, STREAM_CONNECT);
}

void
stream_recv_wait(struct stream *stream)
{
    stream_wait(stream, STREAM_RECV);
}

void
stream_send_wait(struct stream *stream)
{
    stream_wait(stream, STREAM_SEND);
}

/* Given 'name', a pstream name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
pstream_lookup_class(const char *name, const struct pstream_class **classp)
{
    size_t prefix_len;
    size_t i;

    check_stream_classes();

    *classp = NULL;
    prefix_len = strcspn(name, ":");
    if (name[prefix_len] == '\0') {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(pstream_classes); i++) {
        const struct pstream_class *class = pstream_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            *classp = class;
            return 0;
        }
    }
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a pstream name in the form "TYPE:ARGS" and TYPE is
 * a supported pstream type, otherwise EAFNOSUPPORT.  */
int
pstream_verify_name(const char *name)
{
    const struct pstream_class *class;
    return pstream_lookup_class(name, &class);
}

/* Returns 1 if the stream or pstream specified by 'name' needs periodic probes
 * to verify connectivity.  For [p]streams which need probes, it can take a
 * long time to notice the connection has been dropped.  Returns 0 if the
 * stream or pstream does not need probes, and -1 if 'name' is not valid. */
int
stream_or_pstream_needs_probes(const char *name)
{
    const struct pstream_class *pclass;
    const struct stream_class *class;

    if (!stream_lookup_class(name, &class)) {
        return class->needs_probes;
    } else if (!pstream_lookup_class(name, &pclass)) {
        return pclass->needs_probes;
    } else {
        return -1;
    }
}

/* Attempts to start listening for remote stream connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive stream
 * class's name and ARGS are stream class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pstreamp', otherwise a null
 * pointer.  */
int
pstream_open(const char *name, struct pstream **pstreamp, uint8_t dscp)
{
    const struct pstream_class *class;
    struct pstream *pstream;
    char *suffix_copy;
    int error;

    COVERAGE_INC(pstream_open);

    /* Look up the class. */
    error = pstream_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->listen(name, suffix_copy, &pstream, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    *pstreamp = pstream;
    return 0;

error:
    *pstreamp = NULL;
    return error;
}

/* Returns the name that was used to open 'pstream'.  The caller must not
 * modify or free the name. */
const char *
pstream_get_name(const struct pstream *pstream)
{
    return pstream->name;
}

/* Closes 'pstream'. */
void
pstream_close(struct pstream *pstream)
{
    if (pstream != NULL) {
        char *name = pstream->name;
        (pstream->class->close)(pstream);
        free(name);
    }
}

/* Tries to accept a new connection on 'pstream'.  If successful, stores the
 * new connection in '*new_stream' and returns 0.  Otherwise, returns a
 * positive errno value.
 *
 * pstream_accept() will not block waiting for a connection.  If no connection
 * is ready to be accepted, it returns EAGAIN immediately. */
int
pstream_accept(struct pstream *pstream, struct stream **new_stream)
{
    int retval = (pstream->class->accept)(pstream, new_stream);
    if (retval) {
        *new_stream = NULL;
    } else {
        assert((*new_stream)->state != SCS_CONNECTING
               || (*new_stream)->class->connect);
    }
    return retval;
}

/* Tries to accept a new connection on 'pstream'.  If successful, stores the
 * new connection in '*new_stream' and returns 0.  Otherwise, returns a
 * positive errno value.
 *
 * pstream_accept_block() blocks until a connection is ready or until an error
 * occurs.  It will not return EAGAIN. */
int
pstream_accept_block(struct pstream *pstream, struct stream **new_stream)
{
    int error;

    fatal_signal_run();
    while ((error = pstream_accept(pstream, new_stream)) == EAGAIN) {
        pstream_wait(pstream);
        poll_block();
    }
    if (error) {
        *new_stream = NULL;
    }
    return error;
}

void
pstream_wait(struct pstream *pstream)
{
    (pstream->class->wait)(pstream);
}

int
pstream_set_dscp(struct pstream *pstream, uint8_t dscp)
{
    if (pstream->class->set_dscp) {
        return pstream->class->set_dscp(pstream, dscp);
    }
    return 0;
}

/* Initializes 'stream' as a new stream named 'name', implemented via 'class'.
 * The initial connection status, supplied as 'connect_status', is interpreted
 * as follows:
 *
 *      - 0: 'stream' is connected.  Its 'send' and 'recv' functions may be
 *        called in the normal fashion.
 *
 *      - EAGAIN: 'stream' is trying to complete a connection.  Its 'connect'
 *        function should be called to complete the connection.
 *
 *      - Other positive errno values indicate that the connection failed with
 *        the specified error.
 *
 * After calling this function, stream_close() must be used to destroy
 * 'stream', otherwise resources will be leaked.
 *
 * The caller retains ownership of 'name'. */
void
stream_init(struct stream *stream, const struct stream_class *class,
            int connect_status, const char *name)
{
    memset(stream, 0, sizeof *stream);
    stream->class = class;
    stream->state = (connect_status == EAGAIN ? SCS_CONNECTING
                    : !connect_status ? SCS_CONNECTED
                    : SCS_DISCONNECTED);
    stream->error = connect_status;
    stream->name = xstrdup(name);
    assert(stream->state != SCS_CONNECTING || class->connect);
}

void
stream_set_remote_ip(struct stream *stream, ovs_be32 ip)
{
    stream->remote_ip = ip;
}

void
stream_set_remote_port(struct stream *stream, ovs_be16 port)
{
    stream->remote_port = port;
}

void
stream_set_local_ip(struct stream *stream, ovs_be32 ip)
{
    stream->local_ip = ip;
}

void
stream_set_local_port(struct stream *stream, ovs_be16 port)
{
    stream->local_port = port;
}

void
pstream_init(struct pstream *pstream, const struct pstream_class *class,
            const char *name)
{
    pstream->class = class;
    pstream->name = xstrdup(name);
}

static int
count_fields(const char *s_)
{
    char *s, *field, *save_ptr;
    int n = 0;

    save_ptr = NULL;
    s = xstrdup(s_);
    for (field = strtok_r(s, ":", &save_ptr); field != NULL;
         field = strtok_r(NULL, ":", &save_ptr)) {
        n++;
    }
    free(s);

    return n;
}

/* Like stream_open(), but for tcp streams the port defaults to
 * 'default_tcp_port' if no port number is given and for SSL streams the port
 * defaults to 'default_ssl_port' if no port number is given. */
int
stream_open_with_default_ports(const char *name_,
                               uint16_t default_tcp_port,
                               uint16_t default_ssl_port,
                               struct stream **streamp,
                               uint8_t dscp)
{
    char *name;
    int error;

    if (!strncmp(name_, "tcp:", 4) && count_fields(name_) < 3) {
        name = xasprintf("%s:%d", name_, default_tcp_port);
    } else if (!strncmp(name_, "ssl:", 4) && count_fields(name_) < 3) {
        name = xasprintf("%s:%d", name_, default_ssl_port);
    } else {
        name = xstrdup(name_);
    }
    error = stream_open(name, streamp, dscp);
    free(name);

    return error;
}

/* Like pstream_open(), but for ptcp streams the port defaults to
 * 'default_ptcp_port' if no port number is given and for passive SSL streams
 * the port defaults to 'default_pssl_port' if no port number is given. */
int
pstream_open_with_default_ports(const char *name_,
                                uint16_t default_ptcp_port,
                                uint16_t default_pssl_port,
                                struct pstream **pstreamp,
                                uint8_t dscp)
{
    char *name;
    int error;

    if (!strncmp(name_, "ptcp:", 5) && count_fields(name_) < 2) {
        name = xasprintf("%s%d", name_, default_ptcp_port);
    } else if (!strncmp(name_, "pssl:", 5) && count_fields(name_) < 2) {
        name = xasprintf("%s%d", name_, default_pssl_port);
    } else {
        name = xstrdup(name_);
    }
    error = pstream_open(name, pstreamp, dscp);
    free(name);

    return error;
}

/*
 * This function extracts IP address and port from the target string.
 *
 *     - On success, function returns true and fills *sin structure with port
 *       and IP address. If port was absent in target string then it will use
 *       corresponding default port value.
 *     - On error, function returns false and *sin contains garbage.
 */
bool
stream_parse_target_with_default_ports(const char *target,
                                       uint16_t default_tcp_port,
                                       uint16_t default_ssl_port,
                                       struct sockaddr_in *sin)
{
    return (!strncmp(target, "tcp:", 4)
             && inet_parse_active(target + 4, default_tcp_port, sin)) ||
            (!strncmp(target, "ssl:", 4)
             && inet_parse_active(target + 4, default_ssl_port, sin));
}

/* Attempts to guess the content type of a stream whose first few bytes were
 * the 'size' bytes of 'data'. */
static enum stream_content_type
stream_guess_content(const uint8_t *data, ssize_t size)
{
    if (size >= 2) {
#define PAIR(A, B) (((A) << 8) | (B))
        switch (PAIR(data[0], data[1])) {
        case PAIR(0x16, 0x03):  /* Handshake, version 3. */
            return STREAM_SSL;
        case PAIR('{', '"'):
            return STREAM_JSONRPC;
        case PAIR(OFP10_VERSION, 0 /* OFPT_HELLO */):
            return STREAM_OPENFLOW;
        }
    }

    return STREAM_UNKNOWN;
}

/* Returns a string represenation of 'type'. */
static const char *
stream_content_type_to_string(enum stream_content_type type)
{
    switch (type) {
    case STREAM_UNKNOWN:
    default:
        return "unknown";

    case STREAM_JSONRPC:
        return "JSON-RPC";

    case STREAM_OPENFLOW:
        return "OpenFlow";

    case STREAM_SSL:
        return "SSL";
    }
}

/* Attempts to guess the content type of a stream whose first few bytes were
 * the 'size' bytes of 'data'.  If this is done successfully, and the guessed
 * content type is other than 'expected_type', then log a message in vlog
 * module 'module', naming 'stream_name' as the source, explaining what
 * content was expected and what was actually received. */
void
stream_report_content(const void *data, ssize_t size,
                      enum stream_content_type expected_type,
                      struct vlog_module *module, const char *stream_name)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    enum stream_content_type actual_type;

    actual_type = stream_guess_content(data, size);
    if (actual_type != expected_type && actual_type != STREAM_UNKNOWN) {
        vlog_rate_limit(module, VLL_WARN, &rl,
                        "%s: received %s data on %s channel",
                        stream_name,
                        stream_content_type_to_string(actual_type),
                        stream_content_type_to_string(expected_type));
    }
}
