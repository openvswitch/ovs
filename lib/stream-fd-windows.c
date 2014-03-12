/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "stream-fd.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <winsock2.h>
#include "fatal-signal.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "stream.h"
#include "stream-provider.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_fd_windows);

/* Active file descriptor stream. */

struct stream_fd
{
    struct stream stream;
    int fd;
    HANDLE wevent;
};

static const struct stream_class stream_fd_class;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

/* Creates a new stream named 'name' that will send and receive data on 'fd'
 * and stores a pointer to the stream in '*streamp'.  Initial connection status
 * 'connect_status' is interpreted as described for stream_init().
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
int
new_fd_stream(const char *name, int fd, int connect_status,
              struct stream **streamp)
{
    struct stream_fd *s;

    s = xmalloc(sizeof *s);
    stream_init(&s->stream, &stream_fd_class, connect_status, name);
    s->fd = fd;
    s->wevent = CreateEvent(NULL, FALSE, FALSE, NULL);
    *streamp = &s->stream;
    return 0;
}

static struct stream_fd *
stream_fd_cast(struct stream *stream)
{
    stream_assert_class(stream, &stream_fd_class);
    return CONTAINER_OF(stream, struct stream_fd, stream);
}

static void
fd_close(struct stream *stream)
{
    struct stream_fd *s = stream_fd_cast(stream);
    WSAEventSelect(s->fd, NULL, 0);
    CloseHandle(s->wevent);
    closesocket(s->fd);
    free(s);
}

static int
fd_connect(struct stream *stream)
{
    struct stream_fd *s = stream_fd_cast(stream);
    return check_connection_completion(s->fd);
}

static ssize_t
fd_recv(struct stream *stream, void *buffer, size_t n)
{
    struct stream_fd *s = stream_fd_cast(stream);
    ssize_t retval;

    retval = recv(s->fd, buffer, n, 0);
    if (retval < 0) {
        retval = -sock_errno();
    }
    if (retval == -WSAEWOULDBLOCK) {
        return -EAGAIN;
    }
    return retval;
}

static ssize_t
fd_send(struct stream *stream, const void *buffer, size_t n)
{
    struct stream_fd *s = stream_fd_cast(stream);
    ssize_t retval;

    retval = send(s->fd, buffer, n, 0);
    if (retval < 0) {
        retval = -sock_errno();
    }
    if (retval == -WSAEWOULDBLOCK) {
        return -EAGAIN;
    }

    return retval;
}

static void
fd_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct stream_fd *s = stream_fd_cast(stream);
    switch (wait) {
    case STREAM_CONNECT:
    case STREAM_SEND:
        poll_fd_wait_event(s->fd, s->wevent, POLLOUT);
        break;

    case STREAM_RECV:
        poll_fd_wait_event(s->fd, s->wevent, POLLIN);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static const struct stream_class stream_fd_class = {
    "fd",                       /* name */
    false,                      /* needs_probes */
    NULL,                       /* open */
    fd_close,                   /* close */
    fd_connect,                 /* connect */
    fd_recv,                    /* recv */
    fd_send,                    /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    fd_wait,                    /* wait */
};

/* Passive file descriptor stream. */

struct fd_pstream
{
    struct pstream pstream;
    int fd;
    HANDLE wevent;
    int (*accept_cb)(int fd, const struct sockaddr_storage *, size_t ss_len,
                     struct stream **);
    int (*set_dscp_cb)(int fd, uint8_t dscp);
    char *unlink_path;
};

static const struct pstream_class fd_pstream_class;

static struct fd_pstream *
fd_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &fd_pstream_class);
    return CONTAINER_OF(pstream, struct fd_pstream, pstream);
}

/* Creates a new pstream named 'name' that will accept new socket connections
 * on 'fd' and stores a pointer to the stream in '*pstreamp'.
 *
 * When a connection has been accepted, 'accept_cb' will be called with the new
 * socket fd 'fd' and the remote address of the connection 'sa' and 'sa_len'.
 * accept_cb must return 0 if the connection is successful, in which case it
 * must initialize '*streamp' to the new stream, or a positive errno value on
 * error.  In either case accept_cb takes ownership of the 'fd' passed in.
 *
 * When '*pstreamp' is closed, then 'unlink_path' (if nonnull) will be passed
 * to fatal_signal_unlink_file_now() and freed with free().
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
int
new_fd_pstream(const char *name, int fd,
               int (*accept_cb)(int fd, const struct sockaddr_storage *ss,
                                size_t ss_len, struct stream **streamp),
               int (*set_dscp_cb)(int fd, uint8_t dscp),
               char *unlink_path, struct pstream **pstreamp)
{
    struct fd_pstream *ps = xmalloc(sizeof *ps);
    pstream_init(&ps->pstream, &fd_pstream_class, name);
    ps->fd = fd;
    ps->wevent = CreateEvent(NULL, FALSE, FALSE, NULL);
    ps->accept_cb = accept_cb;
    ps->set_dscp_cb = set_dscp_cb;
    ps->unlink_path = unlink_path;
    *pstreamp = &ps->pstream;
    return 0;
}

static void
pfd_close(struct pstream *pstream)
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    WSAEventSelect(ps->fd, NULL, 0);
    CloseHandle(ps->wevent);
    closesocket(ps->fd);
    free(ps);
}

static int
pfd_accept(struct pstream *pstream, struct stream **new_streamp)
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    int new_fd;
    int retval;

    new_fd = accept(ps->fd, (struct sockaddr *) &ss, &ss_len);
    if (new_fd < 0) {
        retval = sock_errno();
        if (retval == WSAEWOULDBLOCK) {
            return EAGAIN;
        }
        return retval;
    }

    retval = set_nonblocking(new_fd);
    if (retval) {
        closesocket(new_fd);
        return retval;
    }

    return ps->accept_cb(new_fd, &ss, ss_len, new_streamp);
}

static void
pfd_wait(struct pstream *pstream)
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    poll_fd_wait_event(ps->fd, ps->wevent, POLLIN);
}

static int
pfd_set_dscp(struct pstream *pstream, uint8_t dscp)
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    if (ps->set_dscp_cb) {
        return ps->set_dscp_cb(ps->fd, dscp);
    }
    return 0;
}

static const struct pstream_class fd_pstream_class = {
    "pstream",
    false,
    NULL,
    pfd_close,
    pfd_accept,
    pfd_wait,
    pfd_set_dscp,
};
