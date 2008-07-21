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
#include <stdio.h>
#include <string.h>

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

/* Translates 'host_name', which may be a DNS name or an IP address, into a
 * numeric IP address in '*addr'.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr) 
{
    if (!inet_aton(host_name, addr)) {
        struct hostent *he = gethostbyname(host_name);
        if (he == NULL) {
            VLOG_ERR("gethostbyname(%s): %s", host_name,
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
        error = errno;
        VLOG_ERR("getsockopt(SO_ERROR): %s", strerror(error));
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
        VLOG_ERR("poll: %s", strerror(errno));
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
        VLOG_ERR("getsockopt(SO_RCVBUF) failed: %s", strerror(errno));
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
