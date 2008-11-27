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
#include "vconn-stream.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "vconn-provider.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_stream

/* Active stream socket vconn. */

struct stream_vconn
{
    struct vconn vconn;
    int fd;
    struct ofpbuf *rxbuf;
    struct ofpbuf *txbuf;
    struct poll_waiter *tx_waiter;
};

static struct vconn_class stream_vconn_class;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static void stream_clear_txbuf(struct stream_vconn *);

int
new_stream_vconn(const char *name, int fd, int connect_status,
                 uint32_t ip, struct vconn **vconnp)
{
    struct stream_vconn *s;

    s = xmalloc(sizeof *s);
    vconn_init(&s->vconn, &stream_vconn_class, connect_status, ip, name);
    s->fd = fd;
    s->txbuf = NULL;
    s->tx_waiter = NULL;
    s->rxbuf = NULL;
    *vconnp = &s->vconn;
    return 0;
}

static struct stream_vconn *
stream_vconn_cast(struct vconn *vconn)
{
    vconn_assert_class(vconn, &stream_vconn_class);
    return CONTAINER_OF(vconn, struct stream_vconn, vconn);
}

static void
stream_close(struct vconn *vconn)
{
    struct stream_vconn *s = stream_vconn_cast(vconn);
    poll_cancel(s->tx_waiter);
    stream_clear_txbuf(s);
    ofpbuf_delete(s->rxbuf);
    close(s->fd);
    free(s);
}

static int
stream_connect(struct vconn *vconn)
{
    struct stream_vconn *s = stream_vconn_cast(vconn);
    return check_connection_completion(s->fd);
}

static int
stream_recv(struct vconn *vconn, struct ofpbuf **bufferp)
{
    struct stream_vconn *s = stream_vconn_cast(vconn);
    struct ofpbuf *rx;
    size_t want_bytes;
    ssize_t retval;

    if (s->rxbuf == NULL) {
        s->rxbuf = ofpbuf_new(1564);
    }
    rx = s->rxbuf;

again:
    if (sizeof(struct ofp_header) > rx->size) {
        want_bytes = sizeof(struct ofp_header) - rx->size;
    } else {
        struct ofp_header *oh = rx->data;
        size_t length = ntohs(oh->length);
        if (length < sizeof(struct ofp_header)) {
            VLOG_ERR_RL(&rl, "received too-short ofp_header (%zu bytes)",
                        length);
            return EPROTO;
        }
        want_bytes = length - rx->size;
        if (!want_bytes) {
            *bufferp = rx;
            s->rxbuf = NULL;
            return 0;
        }
    }
    ofpbuf_prealloc_tailroom(rx, want_bytes);

    retval = read(s->fd, ofpbuf_tail(rx), want_bytes);
    if (retval > 0) {
        rx->size += retval;
        if (retval == want_bytes) {
            if (rx->size > sizeof(struct ofp_header)) {
                *bufferp = rx;
                s->rxbuf = NULL;
                return 0;
            } else {
                goto again;
            }
        }
        return EAGAIN;
    } else if (retval == 0) {
        if (rx->size) {
            VLOG_ERR_RL(&rl, "connection dropped mid-packet");
            return EPROTO;
        } else {
            return EOF;
        }
    } else {
        return errno;
    }
}

static void
stream_clear_txbuf(struct stream_vconn *s)
{
    ofpbuf_delete(s->txbuf);
    s->txbuf = NULL;
    s->tx_waiter = NULL;
}

static void
stream_do_tx(int fd UNUSED, short int revents UNUSED, void *vconn_)
{
    struct vconn *vconn = vconn_;
    struct stream_vconn *s = stream_vconn_cast(vconn);
    ssize_t n = write(s->fd, s->txbuf->data, s->txbuf->size);
    if (n < 0) {
        if (errno != EAGAIN) {
            VLOG_ERR_RL(&rl, "send: %s", strerror(errno));
            stream_clear_txbuf(s);
            return;
        }
    } else if (n > 0) {
        ofpbuf_pull(s->txbuf, n);
        if (!s->txbuf->size) {
            stream_clear_txbuf(s);
            return;
        }
    }
    s->tx_waiter = poll_fd_callback(s->fd, POLLOUT, stream_do_tx, vconn);
}

static int
stream_send(struct vconn *vconn, struct ofpbuf *buffer)
{
    struct stream_vconn *s = stream_vconn_cast(vconn);
    ssize_t retval;

    if (s->txbuf) {
        return EAGAIN;
    }

    retval = write(s->fd, buffer->data, buffer->size);
    if (retval == buffer->size) {
        ofpbuf_delete(buffer);
        return 0;
    } else if (retval >= 0 || errno == EAGAIN) {
        s->txbuf = buffer;
        if (retval > 0) {
            ofpbuf_pull(buffer, retval);
        }
        s->tx_waiter = poll_fd_callback(s->fd, POLLOUT, stream_do_tx, vconn);
        return 0;
    } else {
        return errno;
    }
}

static void
stream_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct stream_vconn *s = stream_vconn_cast(vconn);
    switch (wait) {
    case WAIT_CONNECT:
        poll_fd_wait(s->fd, POLLOUT);
        break;

    case WAIT_SEND:
        if (!s->txbuf) {
            poll_fd_wait(s->fd, POLLOUT);
        } else {
            /* Nothing to do: need to drain txbuf first. */
        }
        break;

    case WAIT_RECV:
        poll_fd_wait(s->fd, POLLIN);
        break;

    default:
        NOT_REACHED();
    }
}

static struct vconn_class stream_vconn_class = {
    "stream",                   /* name */
    NULL,                       /* open */
    stream_close,               /* close */
    stream_connect,             /* connect */
    stream_recv,                /* recv */
    stream_send,                /* send */
    stream_wait,                /* wait */
};

/* Passive stream socket vconn. */

struct pstream_pvconn
{
    struct pvconn pvconn;
    int fd;
    int (*accept_cb)(int fd, const struct sockaddr *, size_t sa_len,
                     struct vconn **);
};

static struct pvconn_class pstream_pvconn_class;

static struct pstream_pvconn *
pstream_pvconn_cast(struct pvconn *pvconn)
{
    pvconn_assert_class(pvconn, &pstream_pvconn_class);
    return CONTAINER_OF(pvconn, struct pstream_pvconn, pvconn);
}

int
new_pstream_pvconn(const char *name, int fd,
                  int (*accept_cb)(int fd, const struct sockaddr *,
                                   size_t sa_len, struct vconn **),
                  struct pvconn **pvconnp)
{
    struct pstream_pvconn *ps;
    int retval;

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    if (listen(fd, 10) < 0) {
        int error = errno;
        VLOG_ERR("%s: listen: %s", name, strerror(error));
        close(fd);
        return error;
    }

    ps = xmalloc(sizeof *ps);
    pvconn_init(&ps->pvconn, &pstream_pvconn_class, name);
    ps->fd = fd;
    ps->accept_cb = accept_cb;
    *pvconnp = &ps->pvconn;
    return 0;
}

static void
pstream_close(struct pvconn *pvconn)
{
    struct pstream_pvconn *ps = pstream_pvconn_cast(pvconn);
    close(ps->fd);
    free(ps);
}

static int
pstream_accept(struct pvconn *pvconn, struct vconn **new_vconnp)
{
    struct pstream_pvconn *ps = pstream_pvconn_cast(pvconn);
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    int new_fd;
    int retval;

    new_fd = accept(ps->fd, (struct sockaddr *) &ss, &ss_len);
    if (new_fd < 0) {
        int retval = errno;
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&rl, "accept: %s", strerror(retval));
        }
        return retval;
    }

    retval = set_nonblocking(new_fd);
    if (retval) {
        close(new_fd);
        return retval;
    }

    return ps->accept_cb(new_fd, (const struct sockaddr *) &ss, ss_len,
                         new_vconnp);
}

static void
pstream_wait(struct pvconn *pvconn)
{
    struct pstream_pvconn *ps = pstream_pvconn_cast(pvconn);
    poll_fd_wait(ps->fd, POLLIN);
}

static struct pvconn_class pstream_pvconn_class = {
    "pstream",
    NULL,
    pstream_close,
    pstream_accept,
    pstream_wait
};
