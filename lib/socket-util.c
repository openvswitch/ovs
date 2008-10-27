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
#include "socket-util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_socket_util

/* Sets 'fd' to non-blocking mode.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1) {
            return 0;
        } else {
            VLOG_ERR("fcntl(F_SETFL) failed: %s", strerror(errno));
            return errno;
        }
    } else {
        VLOG_ERR("fcntl(F_GETFL) failed: %s", strerror(errno));
        return errno;
    }
}

/* Returns the maximum valid FD value, plus 1. */
int
get_max_fds(void)
{
    static int max_fds = -1;
    if (max_fds < 0) {
        struct rlimit r;
        if (!getrlimit(RLIMIT_NOFILE, &r)
            && r.rlim_cur != RLIM_INFINITY
            && r.rlim_cur != RLIM_SAVED_MAX
            && r.rlim_cur != RLIM_SAVED_CUR) {
            max_fds = r.rlim_cur;
        } else {
            VLOG_WARN("failed to obtain fd limit, defaulting to 1024");
            max_fds = 1024;
        }
    }
    return max_fds;
}

/* Translates 'host_name', which may be a DNS name or an IP address, into a
 * numeric IP address in '*addr'.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr) 
{
    if (!inet_aton(host_name, addr)) {
        struct hostent *he = gethostbyname(host_name);
        if (he == NULL) {
            struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_ERR_RL(&rl, "gethostbyname(%s): %s", host_name,
                        (h_errno == HOST_NOT_FOUND ? "host not found"
                         : h_errno == TRY_AGAIN ? "try again"
                         : h_errno == NO_RECOVERY ? "non-recoverable error"
                         : h_errno == NO_ADDRESS ? "no address"
                         : "unknown error"));
            return ENOENT;
        }
        addr->s_addr = *(uint32_t *) he->h_addr;
    }
    return 0;
}

/* Returns the error condition associated with socket 'fd' and resets the
 * socket's error status. */
int
get_socket_error(int fd) 
{
    int error;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
        error = errno;
        VLOG_ERR_RL(&rl, "getsockopt(SO_ERROR): %s", strerror(error));
    }
    return error;
}

int
check_connection_completion(int fd) 
{
    struct pollfd pfd;
    int retval;

    pfd.fd = fd;
    pfd.events = POLLOUT;
    do {
        retval = poll(&pfd, 1, 0);
    } while (retval < 0 && errno == EINTR);
    if (retval == 1) {
        return get_socket_error(fd);
    } else if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
        VLOG_ERR_RL(&rl, "poll: %s", strerror(errno));
        return errno;
    } else {
        return EAGAIN;
    }
}

/* Drain all the data currently in the receive queue of a datagram socket (and
 * possibly additional data).  There is no way to know how many packets are in
 * the receive queue, but we do know that the total number of bytes queued does
 * not exceed the receive buffer size, so we pull packets until none are left
 * or we've read that many bytes. */
int
drain_rcvbuf(int fd)
{
    socklen_t rcvbuf_len;
    size_t rcvbuf;

    rcvbuf_len = sizeof rcvbuf;
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbuf_len) < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
        VLOG_ERR_RL(&rl, "getsockopt(SO_RCVBUF) failed: %s", strerror(errno));
        return errno;
    }
    while (rcvbuf > 0) {
        /* In Linux, specifying MSG_TRUNC in the flags argument causes the
         * datagram length to be returned, even if that is longer than the
         * buffer provided.  Thus, we can use a 1-byte buffer to discard the
         * incoming datagram and still be able to account how many bytes were
         * removed from the receive buffer.
         *
         * On other Unix-like OSes, MSG_TRUNC has no effect in the flags
         * argument. */
#ifdef __linux__
#define BUFFER_SIZE 1
#else
#define BUFFER_SIZE 2048
#endif
        char buffer[BUFFER_SIZE];
        ssize_t n_bytes = recv(fd, buffer, sizeof buffer,
                               MSG_TRUNC | MSG_DONTWAIT);
        if (n_bytes <= 0 || n_bytes >= rcvbuf) {
            break;
        }
        rcvbuf -= n_bytes;
    }
    return 0;
}

/* Reads and discards up to 'n' datagrams from 'fd', stopping as soon as no
 * more data can be immediately read.  ('fd' should therefore be in
 * non-blocking mode.)*/
void
drain_fd(int fd, size_t n_packets)
{
    for (; n_packets > 0; n_packets--) {
        /* 'buffer' only needs to be 1 byte long in most circumstances.  This
         * size is defensive against the possibility that we someday want to
         * use a Linux tap device without TUN_NO_PI, in which case a buffer
         * smaller than sizeof(struct tun_pi) will give EINVAL on read. */
        char buffer[128];
        if (read(fd, buffer, sizeof buffer) <= 0) {
            break;
        }
    }
}

/* Stores in '*un' a sockaddr_un that refers to file 'name'.  Stores in
 * '*un_len' the size of the sockaddr_un. */
static void
make_sockaddr_un(const char *name, struct sockaddr_un* un, socklen_t *un_len)
{
    un->sun_family = AF_UNIX;
    strncpy(un->sun_path, name, sizeof un->sun_path);
    un->sun_path[sizeof un->sun_path - 1] = '\0';
    *un_len = (offsetof(struct sockaddr_un, sun_path)
                + strlen (un->sun_path) + 1);
}

/* Creates a Unix domain socket in the given 'style' (either SOCK_DGRAM or
 * SOCK_STREAM) that is bound to '*bind_path' (if 'bind_path' is non-null) and
 * connected to '*connect_path' (if 'connect_path' is non-null).  If 'nonblock'
 * is true, the socket is made non-blocking.  If 'passcred' is true, the socket
 * is configured to receive SCM_CREDENTIALS control messages.
 *
 * Returns the socket's fd if successful, otherwise a negative errno value. */
int
make_unix_socket(int style, bool nonblock, bool passcred UNUSED,
                 const char *bind_path, const char *connect_path)
{
    int error;
    int fd;

    fd = socket(PF_UNIX, style, 0);
    if (fd < 0) {
        return -errno;
    }

    /* Set nonblocking mode right away, if we want it.  This prevents blocking
     * in connect(), if connect_path != NULL.  (In turn, that's a corner case:
     * it will only happen if style is SOCK_STREAM or SOCK_SEQPACKET, and only
     * if a backlog of un-accepted connections has built up in the kernel.)  */
    if (nonblock) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            goto error;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            goto error;
        }
    }

    if (bind_path) {
        struct sockaddr_un un;
        socklen_t un_len;
        make_sockaddr_un(bind_path, &un, &un_len);
        if (unlink(un.sun_path) && errno != ENOENT) {
            VLOG_WARN("unlinking \"%s\": %s\n", un.sun_path, strerror(errno));
        }
        fatal_signal_add_file_to_unlink(bind_path);
        if (bind(fd, (struct sockaddr*) &un, un_len)
            || fchmod(fd, S_IRWXU)) {
            goto error;
        }
    }

    if (connect_path) {
        struct sockaddr_un un;
        socklen_t un_len;
        make_sockaddr_un(connect_path, &un, &un_len);
        if (connect(fd, (struct sockaddr*) &un, un_len)
            && errno != EINPROGRESS) {
            goto error;
        }
    }

#ifdef SCM_CREDENTIALS
    if (passcred) {
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable))) {
            goto error;
        }
    }
#endif

    return fd;

error:
    if (bind_path) {
        fatal_signal_remove_file_to_unlink(bind_path);
    }
    error = errno;
    close(fd);
    return -error;
}

int
get_unix_name_len(socklen_t sun_len)
{
    return (sun_len >= offsetof(struct sockaddr_un, sun_path)
            ? sun_len - offsetof(struct sockaddr_un, sun_path)
            : 0);
}
