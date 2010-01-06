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
#include "flow.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "util.h"

#define THIS_MODULE VLM_stream
#include "vlog.h"

/* State of an active stream.*/
enum stream_state {
    SCS_CONNECTING,             /* Underlying stream is not connected. */
    SCS_CONNECTED,              /* Connection established. */
    SCS_DISCONNECTED            /* Connection failed or connection closed. */
};

static struct stream_class *stream_classes[] = {
    &tcp_stream_class,
    &unix_stream_class,
};

static struct pstream_class *pstream_classes[] = {
    &ptcp_pstream_class,
    &punix_pstream_class,
};

/* Check the validity of the stream class structures. */
static void
check_stream_classes(void)
{
#ifndef NDEBUG
    size_t i;

    for (i = 0; i < ARRAY_SIZE(stream_classes); i++) {
        struct stream_class *class = stream_classes[i];
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
        struct pstream_class *class = pstream_classes[i];
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
stream_usage(const char *name, bool active, bool passive)
{
    /* Really this should be implemented via callbacks into the stream
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */

    printf("\n");
    if (active) {
        printf("Active %s connection methods:\n", name);
        printf("  tcp:IP:PORT             "
               "PORT at remote IP\n");
        printf("  unix:FILE               "
               "Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive %s connection methods:\n", name);
        printf("  ptcp:PORT[:IP]          "
               "listen to TCP PORT on IP\n");
        printf("  punix:FILE              "
               "listen on Unix domain socket FILE\n");
    }
}

/* Attempts to connect a stream to a remote peer.  'name' is a connection name
 * in the form "TYPE:ARGS", where TYPE is an active stream class's name and
 * ARGS are stream class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*streamp', otherwise a null
 * pointer.  */
int
stream_open(const char *name, struct stream **streamp)
{
    size_t prefix_len;
    size_t i;

    COVERAGE_INC(stream_open);
    check_stream_classes();

    *streamp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(stream_classes); i++) {
        struct stream_class *class = stream_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            struct stream *stream;
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->open(name, suffix_copy, &stream);
            free(suffix_copy);
            if (!retval) {
                assert(stream->state != SCS_CONNECTING
                       || stream->class->connect);
                *streamp = stream;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
}

int
stream_open_block(const char *name, struct stream **streamp)
{
    struct stream *stream;
    int error;

    error = stream_open(name, &stream);
    while (error == EAGAIN) {
        stream_run(stream);
        stream_run_wait(stream);
        stream_connect_wait(stream);
        poll_block();
        error = stream_connect(stream);
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
uint32_t
stream_get_remote_ip(const struct stream *stream)
{
    return stream->remote_ip;
}

/* Returns the transport port of the peer, or 0 if the connection does not
 * contain a port or if the port is not yet known. */
uint16_t
stream_get_remote_port(const struct stream *stream)
{
    return stream->remote_port;
}

/* Returns the IP address used to connect to the peer, or 0 if the connection
 * is not an IP-based protocol or if its IP address is not yet known. */
uint32_t
stream_get_local_ip(const struct stream *stream)
{
    return stream->local_ip;
}

/* Returns the transport port used to connect to the peer, or 0 if the
 * connection does not contain a port or if the port is not yet known. */
uint16_t
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

/* Tries to complete the connection on 'stream', which must be an active
 * stream.  If 'stream''s connection is complete, returns 0 if the connection
 * was successful or a positive errno value if it failed.  If the
 * connection is still in progress, returns EAGAIN. */
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

/* Attempts to start listening for remote stream connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive stream
 * class's name and ARGS are stream class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pstreamp', otherwise a null
 * pointer.  */
int
pstream_open(const char *name, struct pstream **pstreamp)
{
    size_t prefix_len;
    size_t i;

    check_stream_classes();

    *pstreamp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(pstream_classes); i++) {
        struct pstream_class *class = pstream_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->listen(name, suffix_copy, pstreamp);
            free(suffix_copy);
            if (retval) {
                *pstreamp = NULL;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
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
stream_init(struct stream *stream, struct stream_class *class,
            int connect_status, const char *name)
{
    stream->class = class;
    stream->state = (connect_status == EAGAIN ? SCS_CONNECTING
                    : !connect_status ? SCS_CONNECTED
                    : SCS_DISCONNECTED);
    stream->error = connect_status;
    stream->name = xstrdup(name);
    assert(stream->state != SCS_CONNECTING || class->connect);
}

void
stream_set_remote_ip(struct stream *stream, uint32_t ip)
{
    stream->remote_ip = ip;
}

void
stream_set_remote_port(struct stream *stream, uint16_t port)
{
    stream->remote_port = port;
}

void
stream_set_local_ip(struct stream *stream, uint32_t ip)
{
    stream->local_ip = ip;
}

void
stream_set_local_port(struct stream *stream, uint16_t port)
{
    stream->local_port = port;
}

void
pstream_init(struct pstream *pstream, struct pstream_class *class,
            const char *name)
{
    pstream->class = class;
    pstream->name = xstrdup(name);
}
