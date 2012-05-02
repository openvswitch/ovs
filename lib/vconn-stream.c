/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "leak-checker.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "stream.h"
#include "util.h"
#include "vconn-provider.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vconn_stream);

/* Active stream socket vconn. */

struct vconn_stream
{
    struct vconn vconn;
    struct stream *stream;
    struct ofpbuf *rxbuf;
    struct ofpbuf *txbuf;
    int n_packets;
};

static struct vconn_class stream_vconn_class;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static void vconn_stream_clear_txbuf(struct vconn_stream *);

static struct vconn *
vconn_stream_new(struct stream *stream, int connect_status)
{
    struct vconn_stream *s;

    s = xmalloc(sizeof *s);
    vconn_init(&s->vconn, &stream_vconn_class, connect_status,
               stream_get_name(stream));
    s->stream = stream;
    s->txbuf = NULL;
    s->rxbuf = NULL;
    s->n_packets = 0;
    s->vconn.remote_ip = stream_get_remote_ip(stream);
    s->vconn.remote_port = stream_get_remote_port(stream);
    s->vconn.local_ip = stream_get_local_ip(stream);
    s->vconn.local_port = stream_get_local_port(stream);
    return &s->vconn;
}

/* Creates a new vconn that will send and receive data on a stream named 'name'
 * and stores a pointer to the vconn in '*vconnp'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
vconn_stream_open(const char *name, char *suffix OVS_UNUSED,
                  struct vconn **vconnp, uint8_t dscp)
{
    struct stream *stream;
    int error;

    error = stream_open_with_default_ports(name, OFP_TCP_PORT, OFP_SSL_PORT,
                                           &stream, dscp);
    if (!error) {
        error = stream_connect(stream);
        if (!error || error == EAGAIN) {
            *vconnp = vconn_stream_new(stream, error);
            return 0;
        }
    }

    stream_close(stream);
    return error;
}

static struct vconn_stream *
vconn_stream_cast(struct vconn *vconn)
{
    return CONTAINER_OF(vconn, struct vconn_stream, vconn);
}

static void
vconn_stream_close(struct vconn *vconn)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);

    if ((vconn->error == EPROTO || s->n_packets < 1) && s->rxbuf) {
        stream_report_content(s->rxbuf->data, s->rxbuf->size, STREAM_OPENFLOW,
                              THIS_MODULE, vconn_get_name(vconn));
    }

    stream_close(s->stream);
    vconn_stream_clear_txbuf(s);
    ofpbuf_delete(s->rxbuf);
    free(s);
}

static int
vconn_stream_connect(struct vconn *vconn)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);
    return stream_connect(s->stream);
}

static int
vconn_stream_recv__(struct vconn_stream *s, int rx_len)
{
    struct ofpbuf *rx = s->rxbuf;
    int want_bytes, retval;

    want_bytes = rx_len - rx->size;
    ofpbuf_prealloc_tailroom(rx, want_bytes);
    retval = stream_recv(s->stream, ofpbuf_tail(rx), want_bytes);
    if (retval > 0) {
        rx->size += retval;
        return retval == want_bytes ? 0 : EAGAIN;
    } else if (retval == 0) {
        if (rx->size) {
            VLOG_ERR_RL(&rl, "connection dropped mid-packet");
            return EPROTO;
        }
        return EOF;
    } else {
        return -retval;
    }
}

static int
vconn_stream_recv(struct vconn *vconn, struct ofpbuf **bufferp)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);
    const struct ofp_header *oh;
    int rx_len;

    /* Allocate new receive buffer if we don't have one. */
    if (s->rxbuf == NULL) {
        s->rxbuf = ofpbuf_new(1564);
    }

    /* Read ofp_header. */
    if (s->rxbuf->size < sizeof(struct ofp_header)) {
        int retval = vconn_stream_recv__(s, sizeof(struct ofp_header));
        if (retval) {
            return retval;
        }
    }

    /* Read payload. */
    oh = s->rxbuf->data;
    rx_len = ntohs(oh->length);
    if (rx_len < sizeof(struct ofp_header)) {
        VLOG_ERR_RL(&rl, "received too-short ofp_header (%d bytes)", rx_len);
        return EPROTO;
    } else if (s->rxbuf->size < rx_len) {
        int retval = vconn_stream_recv__(s, rx_len);
        if (retval) {
            return retval;
        }
    }

    s->n_packets++;
    *bufferp = s->rxbuf;
    s->rxbuf = NULL;
    return 0;
}

static void
vconn_stream_clear_txbuf(struct vconn_stream *s)
{
    ofpbuf_delete(s->txbuf);
    s->txbuf = NULL;
}

static int
vconn_stream_send(struct vconn *vconn, struct ofpbuf *buffer)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);
    ssize_t retval;

    if (s->txbuf) {
        return EAGAIN;
    }

    retval = stream_send(s->stream, buffer->data, buffer->size);
    if (retval == buffer->size) {
        ofpbuf_delete(buffer);
        return 0;
    } else if (retval >= 0 || retval == -EAGAIN) {
        leak_checker_claim(buffer);
        s->txbuf = buffer;
        if (retval > 0) {
            ofpbuf_pull(buffer, retval);
        }
        return 0;
    } else {
        return -retval;
    }
}

static void
vconn_stream_run(struct vconn *vconn)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);
    ssize_t retval;

    stream_run(s->stream);
    if (!s->txbuf) {
        return;
    }

    retval = stream_send(s->stream, s->txbuf->data, s->txbuf->size);
    if (retval < 0) {
        if (retval != -EAGAIN) {
            VLOG_ERR_RL(&rl, "send: %s", strerror(-retval));
            vconn_stream_clear_txbuf(s);
            return;
        }
    } else if (retval > 0) {
        ofpbuf_pull(s->txbuf, retval);
        if (!s->txbuf->size) {
            vconn_stream_clear_txbuf(s);
            return;
        }
    }
}

static void
vconn_stream_run_wait(struct vconn *vconn)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);

    stream_run_wait(s->stream);
    if (s->txbuf) {
        stream_send_wait(s->stream);
    }
}

static void
vconn_stream_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct vconn_stream *s = vconn_stream_cast(vconn);
    switch (wait) {
    case WAIT_CONNECT:
        stream_connect_wait(s->stream);
        break;

    case WAIT_SEND:
        if (!s->txbuf) {
            stream_send_wait(s->stream);
        } else {
            /* Nothing to do: need to drain txbuf first.
             * vconn_stream_run_wait() will arrange to wake up when there room
             * to send data, so there's no point in calling poll_fd_wait()
             * redundantly here. */
        }
        break;

    case WAIT_RECV:
        stream_recv_wait(s->stream);
        break;

    default:
        NOT_REACHED();
    }
}

/* Passive stream socket vconn. */

struct pvconn_pstream
{
    struct pvconn pvconn;
    struct pstream *pstream;
};

static struct pvconn_class pstream_pvconn_class;

static struct pvconn_pstream *
pvconn_pstream_cast(struct pvconn *pvconn)
{
    return CONTAINER_OF(pvconn, struct pvconn_pstream, pvconn);
}

/* Creates a new pvconn named 'name' that will accept new connections using
 * pstream_accept() and stores a pointer to the pvconn in '*pvconnp'.
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
static int
pvconn_pstream_listen(const char *name, char *suffix OVS_UNUSED,
                      struct pvconn **pvconnp, uint8_t dscp)
{
    struct pvconn_pstream *ps;
    struct pstream *pstream;
    int error;

    error = pstream_open_with_default_ports(name, OFP_TCP_PORT, OFP_SSL_PORT,
                                            &pstream, dscp);
    if (error) {
        return error;
    }

    ps = xmalloc(sizeof *ps);
    pvconn_init(&ps->pvconn, &pstream_pvconn_class, name);
    ps->pstream = pstream;
    *pvconnp = &ps->pvconn;
    return 0;
}

static void
pvconn_pstream_close(struct pvconn *pvconn)
{
    struct pvconn_pstream *ps = pvconn_pstream_cast(pvconn);
    pstream_close(ps->pstream);
    free(ps);
}

static int
pvconn_pstream_accept(struct pvconn *pvconn, struct vconn **new_vconnp)
{
    struct pvconn_pstream *ps = pvconn_pstream_cast(pvconn);
    struct stream *stream;
    int error;

    error = pstream_accept(ps->pstream, &stream);
    if (error) {
        if (error != EAGAIN) {
            VLOG_DBG_RL(&rl, "%s: accept: %s",
                        pstream_get_name(ps->pstream), strerror(error));
        }
        return error;
    }

    *new_vconnp = vconn_stream_new(stream, 0);
    return 0;
}

static void
pvconn_pstream_wait(struct pvconn *pvconn)
{
    struct pvconn_pstream *ps = pvconn_pstream_cast(pvconn);
    pstream_wait(ps->pstream);
}

/* Stream-based vconns and pvconns. */

#define STREAM_INIT(NAME)                           \
    {                                               \
            NAME,                                   \
            vconn_stream_open,                      \
            vconn_stream_close,                     \
            vconn_stream_connect,                   \
            vconn_stream_recv,                      \
            vconn_stream_send,                      \
            vconn_stream_run,                       \
            vconn_stream_run_wait,                  \
            vconn_stream_wait,                      \
    }

#define PSTREAM_INIT(NAME)                          \
    {                                               \
            NAME,                                   \
            pvconn_pstream_listen,                  \
            pvconn_pstream_close,                   \
            pvconn_pstream_accept,                  \
            pvconn_pstream_wait                     \
    }

static struct vconn_class stream_vconn_class = STREAM_INIT("stream");
static struct pvconn_class pstream_pvconn_class = PSTREAM_INIT("pstream");

struct vconn_class tcp_vconn_class = STREAM_INIT("tcp");
struct pvconn_class ptcp_pvconn_class = PSTREAM_INIT("ptcp");

struct vconn_class unix_vconn_class = STREAM_INIT("unix");
struct pvconn_class punix_pvconn_class = PSTREAM_INIT("punix");

#ifdef HAVE_OPENSSL
struct vconn_class ssl_vconn_class = STREAM_INIT("ssl");
struct pvconn_class pssl_pvconn_class = PSTREAM_INIT("pssl");
#endif
