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

#include "vconn.h"
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "buffer.h"
#include "socket-util.h"
#include "util.h"
#include "openflow.h"
#include "ofp-print.h"
#include "poll-loop.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_tcp

/* Active TCP. */

struct tcp_vconn
{
    struct vconn vconn;
    int fd;
    struct buffer *rxbuf;
    struct buffer *txbuf;
    struct poll_waiter *tx_waiter;
};

static int
new_tcp_vconn(const char *name, int fd, int connect_status,
              struct vconn **vconnp)
{
    struct tcp_vconn *tcp;
    int on = 1;
    int retval;

    retval = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    if (retval) {
        VLOG_ERR("%s: setsockopt(TCP_NODELAY): %s", name, strerror(errno));
        close(fd);
        return errno;
    }

    tcp = xmalloc(sizeof *tcp);
    tcp->vconn.class = &tcp_vconn_class;
    tcp->vconn.connect_status = connect_status;
    tcp->fd = fd;
    tcp->txbuf = NULL;
    tcp->tx_waiter = NULL;
    tcp->rxbuf = NULL;
    *vconnp = &tcp->vconn;
    return 0;
}

static struct tcp_vconn *
tcp_vconn_cast(struct vconn *vconn)
{
    assert(vconn->class == &tcp_vconn_class);
    return CONTAINER_OF(vconn, struct tcp_vconn, vconn);
}


static int
tcp_open(const char *name, char *suffix, struct vconn **vconnp)
{
    char *save_ptr;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using "::" instead of the obvious ":" works around it. */
    host_name = strtok_r(suffix, "::", &save_ptr);
    port_string = strtok_r(NULL, "::", &save_ptr);
    if (!host_name) {
        fatal(0, "%s: bad peer name format", name);
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return ENOENT;
    }
    sin.sin_port = htons(port_string ? atoi(port_string) : OFP_TCP_PORT);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", name, strerror(errno));
        return errno;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        if (errno == EINPROGRESS) {
            return new_tcp_vconn(name, fd, EAGAIN, vconnp);
        } else {
            int error = errno;
            VLOG_ERR("%s: connect: %s", name, strerror(error));
            close(fd);
            return error;
        }
    } else {
        return new_tcp_vconn(name, fd, 0, vconnp);
    }
}

static void
tcp_close(struct vconn *vconn)
{
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    poll_cancel(tcp->tx_waiter);
    close(tcp->fd);
    free(tcp);
}

static int
tcp_connect(struct vconn *vconn)
{
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    return check_connection_completion(tcp->fd);
}

static int
tcp_recv(struct vconn *vconn, struct buffer **bufferp)
{
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    struct buffer *rx;
    size_t want_bytes;
    ssize_t retval;

    if (tcp->rxbuf == NULL) {
        tcp->rxbuf = buffer_new(1564);
    }
    rx = tcp->rxbuf;

again:
    if (sizeof(struct ofp_header) > rx->size) {
        want_bytes = sizeof(struct ofp_header) - rx->size;
    } else {
        struct ofp_header *oh = rx->data;
        size_t length = ntohs(oh->length);
        if (length < sizeof(struct ofp_header)) {
            VLOG_ERR("received too-short ofp_header (%zu bytes)", length);
            return EPROTO;
        }
        want_bytes = length - rx->size;
        if (!want_bytes) {
            *bufferp = rx;
            tcp->rxbuf = NULL;
            return 0;
        }
    }
    buffer_reserve_tailroom(rx, want_bytes);

    retval = read(tcp->fd, buffer_tail(rx), want_bytes);
    if (retval > 0) {
        rx->size += retval;
        if (retval == want_bytes) {
            if (rx->size > sizeof(struct ofp_header)) {
                *bufferp = rx;
                tcp->rxbuf = NULL;
                return 0;
            } else {
                goto again;
            }
        }
        return EAGAIN;
    } else if (retval == 0) {
        return rx->size ? EPROTO : EOF;
    } else {
        return retval ? errno : EAGAIN;
    }
}

static void
tcp_clear_txbuf(struct tcp_vconn *tcp)
{
    buffer_delete(tcp->txbuf);
    tcp->txbuf = NULL;
    tcp->tx_waiter = NULL;
}

static void
tcp_do_tx(int fd UNUSED, short int revents UNUSED, void *vconn_)
{
    struct vconn *vconn = vconn_;
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    ssize_t n = write(tcp->fd, tcp->txbuf->data, tcp->txbuf->size);
    if (n < 0) {
        if (errno != EAGAIN) {
            VLOG_ERR("send: %s", strerror(errno));
            tcp_clear_txbuf(tcp);
            return;
        }
    } else if (n > 0) {
        buffer_pull(tcp->txbuf, n);
        if (!tcp->txbuf->size) {
            tcp_clear_txbuf(tcp);
            return;
        }
    }
    tcp->tx_waiter = poll_fd_callback(tcp->fd, POLLOUT, tcp_do_tx, vconn);
}

static int
tcp_send(struct vconn *vconn, struct buffer *buffer)
{
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    ssize_t retval;

    if (tcp->txbuf) {
        return EAGAIN;
    }

    retval = write(tcp->fd, buffer->data, buffer->size);
    if (retval == buffer->size) {
        buffer_delete(buffer);
        return 0;
    } else if (retval >= 0 || errno == EAGAIN) {
        tcp->txbuf = buffer;
        if (retval > 0) {
            buffer_pull(buffer, retval);
        }
        tcp->tx_waiter = poll_fd_callback(tcp->fd, POLLOUT, tcp_do_tx, vconn);
        return 0;
    } else {
        return errno;
    }
}

static void
tcp_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct tcp_vconn *tcp = tcp_vconn_cast(vconn);
    switch (wait) {
    case WAIT_CONNECT:
        poll_fd_wait(tcp->fd, POLLOUT);
        break;

    case WAIT_SEND:
        if (!tcp->txbuf) {
            poll_fd_wait(tcp->fd, POLLOUT);
        } else {
            /* Nothing to do: need to drain txbuf first. */
        }
        break;

    case WAIT_RECV:
        poll_fd_wait(tcp->fd, POLLIN);
        break;

    default:
        NOT_REACHED();
    }
}

struct vconn_class tcp_vconn_class = {
    .name = "tcp",
    .open = tcp_open,
    .close = tcp_close,
    .connect = tcp_connect,
    .recv = tcp_recv,
    .send = tcp_send,
    .wait = tcp_wait,
};

/* Passive TCP. */

struct ptcp_vconn
{
    struct vconn vconn;
    int fd;
};

static struct ptcp_vconn *
ptcp_vconn_cast(struct vconn *vconn)
{
    assert(vconn->class == &ptcp_vconn_class);
    return CONTAINER_OF(vconn, struct ptcp_vconn, vconn);
}

static int
ptcp_open(const char *name, char *suffix, struct vconn **vconnp)
{
    struct sockaddr_in sin;
    struct ptcp_vconn *ptcp;
    int retval;
    int fd;
    unsigned int yes  = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", name, strerror(errno));
        return errno;
    }

    if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        VLOG_ERR("%s: setsockopt::SO_REUSEADDR: %s", name, strerror(errno));
        return errno;
    }


    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(atoi(suffix) ? atoi(suffix) : OFP_TCP_PORT);
    retval = bind(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: bind: %s", name, strerror(error));
        close(fd);
        return error;
    }

    retval = listen(fd, 10);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: listen: %s", name, strerror(error));
        close(fd);
        return error;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    ptcp = xmalloc(sizeof *ptcp);
    ptcp->vconn.class = &ptcp_vconn_class;
    ptcp->vconn.connect_status = 0;
    ptcp->fd = fd;
    *vconnp = &ptcp->vconn;
    return 0;
}

static void
ptcp_close(struct vconn *vconn)
{
    struct ptcp_vconn *ptcp = ptcp_vconn_cast(vconn);
    close(ptcp->fd);
    free(ptcp);
}

static int
ptcp_accept(struct vconn *vconn, struct vconn **new_vconnp)
{
    struct ptcp_vconn *ptcp = ptcp_vconn_cast(vconn);
    int new_fd;
    int error;

    new_fd = accept(ptcp->fd, NULL, NULL);
    if (new_fd < 0) {
        int error = errno;
        if (error != EAGAIN) {
            VLOG_DBG("accept: %s", strerror(error));
        }
        return error;
    }

    error = set_nonblocking(new_fd);
    if (error) {
        close(new_fd);
        return error;
    }

    return new_tcp_vconn("tcp" /* FIXME */, new_fd, 0, new_vconnp);
}

static void
ptcp_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct ptcp_vconn *ptcp = ptcp_vconn_cast(vconn);
    assert(wait == WAIT_ACCEPT);
    poll_fd_wait(ptcp->fd, POLLIN);
}

struct vconn_class ptcp_vconn_class = {
    .name = "ptcp",
    .open = ptcp_open,
    .close = ptcp_close,
    .accept = ptcp_accept,
    .wait = ptcp_wait
};

