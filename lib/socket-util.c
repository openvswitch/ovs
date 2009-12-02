/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "socket-util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Translates 'host_name', which must be a string representation of an IP
 * address, into a numeric IP address in '*addr'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr) 
{
    if (!inet_aton(host_name, addr)) {
        struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "\"%s\" is not a valid IP address", host_name);
        return ENOENT;
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

uint32_t
guess_netmask(uint32_t ip)
{
    ip = ntohl(ip);
    return ((ip >> 31) == 0 ? htonl(0xff000000)   /* Class A */
            : (ip >> 30) == 2 ? htonl(0xffff0000) /* Class B */
            : (ip >> 29) == 6 ? htonl(0xffffff00) /* Class C */
            : htonl(0));                          /* ??? */
}

/* Opens a non-blocking IPv4 socket of the specified 'style' and connects to
 * 'target', which should be a string in the format "<host>[:<port>]".  <host>
 * is required.  If 'default_port' is nonzero then <port> is optional and
 * defaults to 'default_port'.
 *
 * 'style' should be SOCK_STREAM (for TCP) or SOCK_DGRAM (for UDP).
 *
 * On success, returns 0 (indicating connection complete) or EAGAIN (indicating
 * connection in progress), in which case the new file descriptor is stored
 * into '*fdp'.  On failure, returns a positive errno value other than EAGAIN
 * and stores -1 into '*fdp'.
 *
 * If 'sinp' is non-null, then on success the target address is stored into
 * '*sinp'. */
int
inet_open_active(int style, const char *target_, uint16_t default_port,
                 struct sockaddr_in *sinp, int *fdp)
{
    char *target = xstrdup(target_);
    char *save_ptr = NULL;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int fd = -1;
    int error;

    /* Defaults. */
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(default_port);

    /* Tokenize. */
    host_name = strtok_r(target, ":", &save_ptr);
    port_string = strtok_r(NULL, ":", &save_ptr);
    if (!host_name) {
        ovs_error(0, "%s: bad peer name format", target_);
        error = EAFNOSUPPORT;
        goto exit;
    }

    /* Look up IP, port. */
    error = lookup_ip(host_name, &sin.sin_addr);
    if (error) {
        goto exit;
    }
    if (port_string && atoi(port_string)) {
        sin.sin_port = htons(atoi(port_string));
    } else if (!default_port) {
        VLOG_ERR("%s: port number must be specified", target_);
        error = EAFNOSUPPORT;
        goto exit;
    }

    /* Create non-blocking socket. */
    fd = socket(AF_INET, style, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", target_, strerror(errno));
        error = errno;
        goto exit;
    }
    error = set_nonblocking(fd);
    if (error) {
        goto exit_close;
    }

    /* Connect. */
    error = connect(fd, (struct sockaddr *) &sin, sizeof sin) == 0 ? 0 : errno;
    if (error == EINPROGRESS) {
        error = EAGAIN;
    } else if (error && error != EAGAIN) {
        goto exit_close;
    }

    /* Success: error is 0 or EAGAIN. */
    goto exit;

exit_close:
    close(fd);
exit:
    if (!error || error == EAGAIN) {
        if (sinp) {
            *sinp = sin;
        }
        *fdp = fd;
    } else {
        *fdp = -1;
    }
    free(target);
    return error;
}

/* Opens a non-blocking IPv4 socket of the specified 'style', binds to
 * 'target', and listens for incoming connections.  'target' should be a string
 * in the format "[<port>][:<ip>]".  <port> may be omitted if 'default_port' is
 * nonzero, in which case it defaults to 'default_port'.  If <ip> is omitted it
 * defaults to the wildcard IP address.
 *
 * 'style' should be SOCK_STREAM (for TCP) or SOCK_DGRAM (for UDP).
 *
 * For TCP, the socket will have SO_REUSEADDR turned on.
 *
 * On success, returns a non-negative file descriptor.  On failure, returns a
 * negative errno value. */
int
inet_open_passive(int style, const char *target_, uint16_t default_port)
{
    char *target = xstrdup(target_);
    char *string_ptr = target;
    struct sockaddr_in sin;
    const char *host_name;
    const char *port_string;
    int fd, error;
    unsigned int yes  = 1;

    /* Address defaults. */
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(default_port);

    /* Parse optional port number. */
    port_string = strsep(&string_ptr, ":");
    if (port_string && atoi(port_string)) {
        sin.sin_port = htons(atoi(port_string));
    } else if (!default_port) {
        VLOG_ERR("%s: port number must be specified", target_);
        error = EAFNOSUPPORT;
        goto exit;
    }

    /* Parse optional bind IP. */
    host_name = strsep(&string_ptr, ":");
    if (host_name && host_name[0]) {
        error = lookup_ip(host_name, &sin.sin_addr);
        if (error) {
            goto exit;
        }
    }

    /* Create non-blocking socket, set SO_REUSEADDR. */
    fd = socket(AF_INET, style, 0);
    if (fd < 0) {
        error = errno;
        VLOG_ERR("%s: socket: %s", target_, strerror(error));
        goto exit;
    }
    error = set_nonblocking(fd);
    if (error) {
        goto exit_close;
    }
    if (style == SOCK_STREAM
        && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        error = errno;
        VLOG_ERR("%s: setsockopt(SO_REUSEADDR): %s", target_, strerror(error));
        goto exit_close;
    }

    /* Bind. */
    if (bind(fd, (struct sockaddr *) &sin, sizeof sin) < 0) {
        error = errno;
        VLOG_ERR("%s: bind: %s", target_, strerror(error));
        goto exit_close;
    }

    /* Listen. */
    if (listen(fd, 10) < 0) {
        error = errno;
        VLOG_ERR("%s: listen: %s", target_, strerror(error));
        goto exit_close;
    }
    error = 0;
    goto exit;

exit_close:
    close(fd);
exit:
    free(target);
    return error ? -error : fd;
}

/* Returns a readable and writable fd for /dev/null, if successful, otherwise
 * a negative errno value.  The caller must not close the returned fd (because
 * the same fd will be handed out to subsequent callers). */
int
get_null_fd(void)
{
    static int null_fd = -1;
    if (null_fd < 0) {
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0) {
            int error = errno;
            VLOG_ERR("could not open /dev/null: %s", strerror(error));
            return -error;
        }
    }
    return null_fd;
}

int
read_fully(int fd, void *p_, size_t size, size_t *bytes_read)
{
    uint8_t *p = p_;

    *bytes_read = 0;
    while (size > 0) {
        ssize_t retval = read(fd, p, size);
        if (retval > 0) {
            *bytes_read += retval;
            size -= retval;
            p += retval;
        } else if (retval == 0) {
            return EOF;
        } else if (errno != EINTR) {
            return errno;
        }
    }
    return 0;
}

int
write_fully(int fd, const void *p_, size_t size, size_t *bytes_written)
{
    const uint8_t *p = p_;

    *bytes_written = 0;
    while (size > 0) {
        ssize_t retval = write(fd, p, size);
        if (retval > 0) {
            *bytes_written += retval;
            size -= retval;
            p += retval;
        } else if (retval == 0) {
            VLOG_WARN("write returned 0");
            return EPROTO;
        } else if (errno != EINTR) {
            return errno;
        }
    }
    return 0;
}
