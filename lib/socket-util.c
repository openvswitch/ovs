/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "ovs-thread.h"
#include "packets.h"
#include "poll-loop.h"
#include "util.h"
#include "vlog.h"
#ifdef __linux__
#include <linux/if_packet.h>
#endif
#ifdef HAVE_NETLINK
#include "netlink-protocol.h"
#include "netlink-socket.h"
#endif

VLOG_DEFINE_THIS_MODULE(socket_util);

/* #ifdefs make it a pain to maintain code: you have to try to build both ways.
 * Thus, this file compiles all of the code regardless of the target, by
 * writing "if (LINUX)" instead of "#ifdef __linux__". */
#ifdef __linux__
#define LINUX 1
#else
#define LINUX 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

/* Maximum length of the sun_path member in a struct sockaddr_un, excluding
 * space for a null terminator. */
#define MAX_UN_LEN (sizeof(((struct sockaddr_un *) 0)->sun_path) - 1)

static int getsockopt_int(int fd, int level, int option, const char *optname,
                          int *valuep);

/* Sets 'fd' to non-blocking mode.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
set_nonblocking(int fd)
{
#ifndef _WIN32
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1) {
            return 0;
        } else {
            VLOG_ERR("fcntl(F_SETFL) failed: %s", ovs_strerror(errno));
            return errno;
        }
    } else {
        VLOG_ERR("fcntl(F_GETFL) failed: %s", ovs_strerror(errno));
        return errno;
    }
#else
    unsigned long arg = 1;
    if (ioctlsocket(fd, FIONBIO, &arg)) {
        int error = sock_errno();
        VLOG_ERR("set_nonblocking failed: %s", sock_strerror(error));
        return error;
    }
    return 0;
#endif
}

void
xset_nonblocking(int fd)
{
    if (set_nonblocking(fd)) {
        exit(EXIT_FAILURE);
    }
}

int
set_dscp(int fd, uint8_t dscp)
{
    int val;
    bool success;

    if (dscp > 63) {
        return EINVAL;
    }

    /* Note: this function is used for both of IPv4 and IPv6 sockets */
    success = false;
    val = dscp << 2;
    if (setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof val)) {
#ifndef _WIN32
        if (sock_errno() != ENOPROTOOPT) {
#else
        if (sock_errno() != WSAENOPROTOOPT) {
#endif
            return sock_errno();
        }
    } else {
        success = true;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof val)) {
#ifndef _WIN32
        if (sock_errno() != ENOPROTOOPT) {
#else
        if (sock_errno() != WSAENOPROTOOPT) {
#endif
            return sock_errno();
        }
    } else {
        success = true;
    }
    if (!success) {
        return ENOPROTOOPT;
    }

    return 0;
}

/* Translates 'host_name', which must be a string representation of an IP
 * address, into a numeric IP address in '*addr'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr)
{
    if (!inet_pton(AF_INET, host_name, addr)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "\"%s\" is not a valid IP address", host_name);
        return ENOENT;
    }
    return 0;
}

/* Translates 'host_name', which must be a string representation of an IPv6
 * address, into a numeric IPv6 address in '*addr'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
lookup_ipv6(const char *host_name, struct in6_addr *addr)
{
    if (inet_pton(AF_INET6, host_name, addr) != 1) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "\"%s\" is not a valid IPv6 address", host_name);
        return ENOENT;
    }
    return 0;
}

/* Translates 'host_name', which must be a host name or a string representation
 * of an IP address, into a numeric IP address in '*addr'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Most Open vSwitch code should not use this because it causes deadlocks:
 * getaddrinfo() sends out a DNS request but that starts a new flow for which
 * OVS must set up a flow, but it can't because it's waiting for a DNS reply.
 * The synchronous lookup also delays other activity.  (Of course we can solve
 * this but it doesn't seem worthwhile quite yet.)  */
int
lookup_hostname(const char *host_name, struct in_addr *addr)
{
    struct addrinfo *result;
    struct addrinfo hints;

    if (inet_pton(AF_INET, host_name, addr)) {
        return 0;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;

    switch (getaddrinfo(host_name, NULL, &hints, &result)) {
    case 0:
        *addr = ALIGNED_CAST(struct sockaddr_in *,
                             result->ai_addr)->sin_addr;
        freeaddrinfo(result);
        return 0;

#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
#endif
    case EAI_NONAME:
    case EAI_SERVICE:
        return ENOENT;

    case EAI_AGAIN:
        return EAGAIN;

    case EAI_BADFLAGS:
    case EAI_FAMILY:
    case EAI_SOCKTYPE:
        return EINVAL;

    case EAI_FAIL:
        return EIO;

    case EAI_MEMORY:
        return ENOMEM;

#if defined (EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
        return ENXIO;
#endif

#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
        return sock_errno();
#endif

    default:
        return EPROTO;
    }
}

int
check_connection_completion(int fd)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
    struct pollfd pfd;
    int retval;

    pfd.fd = fd;
    pfd.events = POLLOUT;

#ifndef _WIN32
    do {
        retval = poll(&pfd, 1, 0);
    } while (retval < 0 && errno == EINTR);
#else
    retval = WSAPoll(&pfd, 1, 0);
#endif
    if (retval == 1) {
        if (pfd.revents & POLLERR) {
            ssize_t n = send(fd, "", 1, 0);
            if (n < 0) {
                return sock_errno();
            } else {
                VLOG_ERR_RL(&rl, "poll return POLLERR but send succeeded");
                return EPROTO;
            }
        }
        return 0;
    } else if (retval < 0) {
        VLOG_ERR_RL(&rl, "poll: %s", sock_strerror(sock_errno()));
        return errno;
    } else {
        return EAGAIN;
    }
}

#ifndef _WIN32
/* Drain all the data currently in the receive queue of a datagram socket (and
 * possibly additional data).  There is no way to know how many packets are in
 * the receive queue, but we do know that the total number of bytes queued does
 * not exceed the receive buffer size, so we pull packets until none are left
 * or we've read that many bytes. */
int
drain_rcvbuf(int fd)
{
    int rcvbuf;

    rcvbuf = get_socket_rcvbuf(fd);
    if (rcvbuf < 0) {
        return -rcvbuf;
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
        char buffer[LINUX ? 1 : 2048];
        ssize_t n_bytes = recv(fd, buffer, sizeof buffer,
                               MSG_TRUNC | MSG_DONTWAIT);
        if (n_bytes <= 0 || n_bytes >= rcvbuf) {
            break;
        }
        rcvbuf -= n_bytes;
    }
    return 0;
}
#endif

/* Returns the size of socket 'sock''s receive buffer (SO_RCVBUF), or a
 * negative errno value if an error occurs. */
int
get_socket_rcvbuf(int sock)
{
    int rcvbuf;
    int error;

    error = getsockopt_int(sock, SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF", &rcvbuf);
    return error ? -error : rcvbuf;
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

#ifndef _WIN32
/* Attempts to shorten 'name' by opening a file descriptor for the directory
 * part of the name and indirecting through /proc/self/fd/<dirfd>/<basename>.
 * On systems with Linux-like /proc, this works as long as <basename> isn't too
 * long.
 *
 * On success, returns 0 and stores the short name in 'short_name' and a
 * directory file descriptor to eventually be closed in '*dirfpd'. */
static int
shorten_name_via_proc(const char *name, char short_name[MAX_UN_LEN + 1],
                      int *dirfdp)
{
    char *dir, *base;
    int dirfd;
    int len;

    if (!LINUX) {
        return ENAMETOOLONG;
    }

    dir = dir_name(name);
    dirfd = open(dir, O_DIRECTORY | O_RDONLY);
    if (dirfd < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        int error = errno;

        VLOG_WARN_RL(&rl, "%s: open failed (%s)", dir, ovs_strerror(error));
        free(dir);

        return error;
    }
    free(dir);

    base = base_name(name);
    len = snprintf(short_name, MAX_UN_LEN + 1,
                   "/proc/self/fd/%d/%s", dirfd, base);
    free(base);

    if (len >= 0 && len <= MAX_UN_LEN) {
        *dirfdp = dirfd;
        return 0;
    } else {
        close(dirfd);
        return ENAMETOOLONG;
    }
}

/* Attempts to shorten 'name' by creating a symlink for the directory part of
 * the name and indirecting through <symlink>/<basename>.  This works on
 * systems that support symlinks, as long as <basename> isn't too long.
 *
 * On success, returns 0 and stores the short name in 'short_name' and the
 * symbolic link to eventually delete in 'linkname'. */
static int
shorten_name_via_symlink(const char *name, char short_name[MAX_UN_LEN + 1],
                         char linkname[MAX_UN_LEN + 1])
{
    char *abs, *dir, *base;
    const char *tmpdir;
    int error;
    int i;

    abs = abs_file_name(NULL, name);
    dir = dir_name(abs);
    base = base_name(abs);
    free(abs);

    tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL) {
        tmpdir = "/tmp";
    }

    for (i = 0; i < 1000; i++) {
        int len;

        len = snprintf(linkname, MAX_UN_LEN + 1,
                       "%s/ovs-un-c-%"PRIu32, tmpdir, random_uint32());
        error = (len < 0 || len > MAX_UN_LEN ? ENAMETOOLONG
                 : symlink(dir, linkname) ? errno
                 : 0);
        if (error != EEXIST) {
            break;
        }
    }

    if (!error) {
        int len;

        fatal_signal_add_file_to_unlink(linkname);

        len = snprintf(short_name, MAX_UN_LEN + 1, "%s/%s", linkname, base);
        if (len < 0 || len > MAX_UN_LEN) {
            fatal_signal_unlink_file_now(linkname);
            error = ENAMETOOLONG;
        }
    }

    if (error) {
        linkname[0] = '\0';
    }
    free(dir);
    free(base);

    return error;
}

/* Stores in '*un' a sockaddr_un that refers to file 'name'.  Stores in
 * '*un_len' the size of the sockaddr_un.
 *
 * Returns 0 on success, otherwise a positive errno value.
 *
 * Uses '*dirfdp' and 'linkname' to store references to data when the caller no
 * longer needs to use 'un'.  On success, freeing these references with
 * free_sockaddr_un() is mandatory to avoid a leak; on failure, freeing them is
 * unnecessary but harmless. */
static int
make_sockaddr_un(const char *name, struct sockaddr_un *un, socklen_t *un_len,
                 int *dirfdp, char linkname[MAX_UN_LEN + 1])
{
    char short_name[MAX_UN_LEN + 1];

    *dirfdp = -1;
    linkname[0] = '\0';
    if (strlen(name) > MAX_UN_LEN) {
        /* 'name' is too long to fit in a sockaddr_un.  Try a workaround. */
        int error = shorten_name_via_proc(name, short_name, dirfdp);
        if (error == ENAMETOOLONG) {
            error = shorten_name_via_symlink(name, short_name, linkname);
        }
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

            VLOG_WARN_RL(&rl, "Unix socket name %s is longer than maximum "
                         "%"PRIuSIZE" bytes", name, MAX_UN_LEN);
            return error;
        }

        name = short_name;
    }

    un->sun_family = AF_UNIX;
    ovs_strzcpy(un->sun_path, name, sizeof un->sun_path);
    *un_len = (offsetof(struct sockaddr_un, sun_path)
                + strlen (un->sun_path) + 1);
    return 0;
}

/* Clean up after make_sockaddr_un(). */
static void
free_sockaddr_un(int dirfd, const char *linkname)
{
    if (dirfd >= 0) {
        close(dirfd);
    }
    if (linkname[0]) {
        fatal_signal_unlink_file_now(linkname);
    }
}

/* Binds Unix domain socket 'fd' to a file with permissions 0700. */
static int
bind_unix_socket(int fd, struct sockaddr *sun, socklen_t sun_len)
{
    /* According to _Unix Network Programming_, umask should affect bind(). */
    mode_t old_umask = umask(0077);
    int error = bind(fd, sun, sun_len) ? errno : 0;
    umask(old_umask);
    return error;
}

/* Creates a Unix domain socket in the given 'style' (either SOCK_DGRAM or
 * SOCK_STREAM) that is bound to '*bind_path' (if 'bind_path' is non-null) and
 * connected to '*connect_path' (if 'connect_path' is non-null).  If 'nonblock'
 * is true, the socket is made non-blocking.
 *
 * Returns the socket's fd if successful, otherwise a negative errno value. */
int
make_unix_socket(int style, bool nonblock,
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
        error = set_nonblocking(fd);
        if (error) {
            goto error;
        }
    }

    if (bind_path) {
        char linkname[MAX_UN_LEN + 1];
        struct sockaddr_un un;
        socklen_t un_len;
        int dirfd;

        if (unlink(bind_path) && errno != ENOENT) {
            VLOG_WARN("unlinking \"%s\": %s\n",
                      bind_path, ovs_strerror(errno));
        }
        fatal_signal_add_file_to_unlink(bind_path);

        error = make_sockaddr_un(bind_path, &un, &un_len, &dirfd, linkname);
        if (!error) {
            error = bind_unix_socket(fd, (struct sockaddr *) &un, un_len);
        }
        free_sockaddr_un(dirfd, linkname);

        if (error) {
            goto error;
        }
    }

    if (connect_path) {
        char linkname[MAX_UN_LEN + 1];
        struct sockaddr_un un;
        socklen_t un_len;
        int dirfd;

        error = make_sockaddr_un(connect_path, &un, &un_len, &dirfd, linkname);
        if (!error
            && connect(fd, (struct sockaddr*) &un, un_len)
            && errno != EINPROGRESS) {
            error = errno;
        }
        free_sockaddr_un(dirfd, linkname);

        if (error) {
            goto error;
        }
    }

    return fd;

error:
    if (error == EAGAIN) {
        error = EPROTO;
    }
    if (bind_path) {
        fatal_signal_unlink_file_now(bind_path);
    }
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
#endif /* _WIN32 */

ovs_be32
guess_netmask(ovs_be32 ip_)
{
    uint32_t ip = ntohl(ip_);
    return ((ip >> 31) == 0 ? htonl(0xff000000)   /* Class A */
            : (ip >> 30) == 2 ? htonl(0xffff0000) /* Class B */
            : (ip >> 29) == 6 ? htonl(0xffffff00) /* Class C */
            : htonl(0));                          /* ??? */
}

/* This is like strsep() except:
 *
 *    - The separator string is ":".
 *
 *    - Square brackets [] quote ":" separators and are removed from the
 *      tokens. */
static char *
parse_bracketed_token(char **pp)
{
    char *p = *pp;

    if (p == NULL) {
        return NULL;
    } else if (*p == '\0') {
        *pp = NULL;
        return p;
    } else if (*p == '[') {
        char *start = p + 1;
        char *end = start + strcspn(start, "]");
        *pp = (*end == '\0' ? NULL
               : end[1] == ':' ? end + 2
               : end + 1);
        *end = '\0';
        return start;
    } else {
        char *start = p;
        char *end = start + strcspn(start, ":");
        *pp = *end == '\0' ? NULL : end + 1;
        *end = '\0';
        return start;
    }
}

static bool
parse_sockaddr_components(struct sockaddr_storage *ss,
                          const char *host_s,
                          const char *port_s, uint16_t default_port,
                          const char *s)
{
    struct sockaddr_in *sin = ALIGNED_CAST(struct sockaddr_in *, ss);
    int port;

    if (port_s && port_s[0]) {
        if (!str_to_int(port_s, 10, &port) || port < 0 || port > 65535) {
            VLOG_ERR("%s: bad port number \"%s\"", s, port_s);
        }
    } else {
        port = default_port;
    }

    memset(ss, 0, sizeof *ss);
    if (strchr(host_s, ':')) {
        struct sockaddr_in6 *sin6
            = ALIGNED_CAST(struct sockaddr_in6 *, ss);

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        if (!inet_pton(AF_INET6, host_s, sin6->sin6_addr.s6_addr)) {
            VLOG_ERR("%s: bad IPv6 address \"%s\"", s, host_s);
            goto exit;
        }
    } else {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        if (!inet_pton(AF_INET, host_s, &sin->sin_addr.s_addr)) {
            VLOG_ERR("%s: bad IPv4 address \"%s\"", s, host_s);
            goto exit;
        }
    }

    return true;

exit:
    memset(ss, 0, sizeof *ss);
    return false;
}

/* Parses 'target', which should be a string in the format "<host>[:<port>]".
 * <host>, which is required, may be an IPv4 address or an IPv6 address
 * enclosed in square brackets.  If 'default_port' is nonzero then <port> is
 * optional and defaults to 'default_port'.
 *
 * On success, returns true and stores the parsed remote address into '*ss'.
 * On failure, logs an error, stores zeros into '*ss', and returns false. */
bool
inet_parse_active(const char *target_, uint16_t default_port,
                  struct sockaddr_storage *ss)
{
    char *target = xstrdup(target_);
    const char *port;
    const char *host;
    char *p;
    bool ok;

    p = target;
    host = parse_bracketed_token(&p);
    port = parse_bracketed_token(&p);
    if (!host) {
        VLOG_ERR("%s: host must be specified", target_);
        ok = false;
    } else if (!port && !default_port) {
        VLOG_ERR("%s: port must be specified", target_);
        ok = false;
    } else {
        ok = parse_sockaddr_components(ss, host, port, default_port, target_);
    }
    if (!ok) {
        memset(ss, 0, sizeof *ss);
    }
    free(target);
    return ok;
}


/* Opens a non-blocking IPv4 or IPv6 socket of the specified 'style' and
 * connects to 'target', which should be a string in the format
 * "<host>[:<port>]".  <host>, which is required, may be an IPv4 address or an
 * IPv6 address enclosed in square brackets.  If 'default_port' is nonzero then
 * <port> is optional and defaults to 'default_port'.
 *
 * 'style' should be SOCK_STREAM (for TCP) or SOCK_DGRAM (for UDP).
 *
 * On success, returns 0 (indicating connection complete) or EAGAIN (indicating
 * connection in progress), in which case the new file descriptor is stored
 * into '*fdp'.  On failure, returns a positive errno value other than EAGAIN
 * and stores -1 into '*fdp'.
 *
 * If 'ss' is non-null, then on success stores the target address into '*ss'.
 *
 * 'dscp' becomes the DSCP bits in the IP headers for the new connection.  It
 * should be in the range [0, 63] and will automatically be shifted to the
 * appropriately place in the IP tos field. */
int
inet_open_active(int style, const char *target, uint16_t default_port,
                 struct sockaddr_storage *ssp, int *fdp, uint8_t dscp)
{
    struct sockaddr_storage ss;
    int fd = -1;
    int error;

    /* Parse. */
    if (!inet_parse_active(target, default_port, &ss)) {
        error = EAFNOSUPPORT;
        goto exit;
    }

    /* Create non-blocking socket. */
    fd = socket(ss.ss_family, style, 0);
    if (fd < 0) {
        error = sock_errno();
        VLOG_ERR("%s: socket: %s", target, sock_strerror(error));
        goto exit;
    }
    error = set_nonblocking(fd);
    if (error) {
        goto exit;
    }

    /* The dscp bits must be configured before connect() to ensure that the
     * TOS field is set during the connection establishment.  If set after
     * connect(), the handshake SYN frames will be sent with a TOS of 0. */
    error = set_dscp(fd, dscp);
    if (error) {
        VLOG_ERR("%s: set_dscp: %s", target, sock_strerror(error));
        goto exit;
    }

    /* Connect. */
    error = connect(fd, (struct sockaddr *) &ss, ss_length(&ss)) == 0
                    ? 0
                    : sock_errno();
    if (error == EINPROGRESS
#ifdef _WIN32
        || error == WSAEALREADY || error == WSAEWOULDBLOCK
#endif
        ) {
        error = EAGAIN;
    }

exit:
    if (error && error != EAGAIN) {
        if (ssp) {
            memset(ssp, 0, sizeof *ssp);
        }
        if (fd >= 0) {
            closesocket(fd);
            fd = -1;
        }
    } else {
        if (ssp) {
            *ssp = ss;
        }
    }
    *fdp = fd;
    return error;
}

/* Parses 'target', which should be a string in the format "[<port>][:<host>]":
 *
 *      - If 'default_port' is -1, then <port> is required.  Otherwise, if
 *        <port> is omitted, then 'default_port' is used instead.
 *
 *      - If <port> (or 'default_port', if used) is 0, then no port is bound
 *        and the TCP/IP stack will select a port.
 *
 *      - <host> is optional.  If supplied, it may be an IPv4 address or an
 *        IPv6 address enclosed in square brackets.  If omitted, the IP address
 *        is wildcarded.
 *
 * If successful, stores the address into '*ss' and returns true; otherwise
 * zeros '*ss' and returns false. */
bool
inet_parse_passive(const char *target_, int default_port,
                   struct sockaddr_storage *ss)
{
    char *target = xstrdup(target_);
    const char *port;
    const char *host;
    char *p;
    bool ok;

    p = target;
    port = parse_bracketed_token(&p);
    host = parse_bracketed_token(&p);
    if (!port && default_port < 0) {
        VLOG_ERR("%s: port must be specified", target_);
        ok = false;
    } else {
        ok = parse_sockaddr_components(ss, host ? host : "0.0.0.0",
                                       port, default_port, target_);
    }
    if (!ok) {
        memset(ss, 0, sizeof *ss);
    }
    free(target);
    return ok;
}


/* Opens a non-blocking IPv4 or IPv6 socket of the specified 'style', binds to
 * 'target', and listens for incoming connections.  Parses 'target' in the same
 * way was inet_parse_passive().
 *
 * 'style' should be SOCK_STREAM (for TCP) or SOCK_DGRAM (for UDP).
 *
 * For TCP, the socket will have SO_REUSEADDR turned on.
 *
 * On success, returns a non-negative file descriptor.  On failure, returns a
 * negative errno value.
 *
 * If 'ss' is non-null, then on success stores the bound address into '*ss'.
 *
 * 'dscp' becomes the DSCP bits in the IP headers for the new connection.  It
 * should be in the range [0, 63] and will automatically be shifted to the
 * appropriately place in the IP tos field. */
int
inet_open_passive(int style, const char *target, int default_port,
                  struct sockaddr_storage *ssp, uint8_t dscp)
{
    bool kernel_chooses_port;
    struct sockaddr_storage ss;
    int fd = 0, error;
    unsigned int yes = 1;

    if (!inet_parse_passive(target, default_port, &ss)) {
        return -EAFNOSUPPORT;
    }
    kernel_chooses_port = ss_get_port(&ss) == 0;

    /* Create non-blocking socket, set SO_REUSEADDR. */
    fd = socket(ss.ss_family, style, 0);
    if (fd < 0) {
        error = sock_errno();
        VLOG_ERR("%s: socket: %s", target, sock_strerror(error));
        return -error;
    }
    error = set_nonblocking(fd);
    if (error) {
        goto error;
    }
    if (style == SOCK_STREAM
        && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        error = sock_errno();
        VLOG_ERR("%s: setsockopt(SO_REUSEADDR): %s",
                 target, sock_strerror(error));
        goto error;
    }

    /* Bind. */
    if (bind(fd, (struct sockaddr *) &ss, ss_length(&ss)) < 0) {
        error = sock_errno();
        VLOG_ERR("%s: bind: %s", target, sock_strerror(error));
        goto error;
    }

    /* The dscp bits must be configured before connect() to ensure that the TOS
     * field is set during the connection establishment.  If set after
     * connect(), the handshake SYN frames will be sent with a TOS of 0. */
    error = set_dscp(fd, dscp);
    if (error) {
        VLOG_ERR("%s: set_dscp: %s", target, sock_strerror(error));
        goto error;
    }

    /* Listen. */
    if (style == SOCK_STREAM && listen(fd, 10) < 0) {
        error = sock_errno();
        VLOG_ERR("%s: listen: %s", target, sock_strerror(error));
        goto error;
    }

    if (ssp || kernel_chooses_port) {
        socklen_t ss_len = sizeof ss;
        if (getsockname(fd, (struct sockaddr *) &ss, &ss_len) < 0) {
            error = sock_errno();
            VLOG_ERR("%s: getsockname: %s", target, sock_strerror(error));
            goto error;
        }
        if (kernel_chooses_port) {
            VLOG_INFO("%s: listening on port %"PRIu16,
                      target, ss_get_port(&ss));
        }
        if (ssp) {
            *ssp = ss;
        }
    }

    return fd;

error:
    if (ssp) {
        memset(ssp, 0, sizeof *ssp);
    }
    closesocket(fd);
    return -error;
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

/* Given file name 'file_name', fsyncs the directory in which it is contained.
 * Returns 0 if successful, otherwise a positive errno value. */
int
fsync_parent_dir(const char *file_name)
{
    int error = 0;
#ifndef _WIN32
    char *dir;
    int fd;

    dir = dir_name(file_name);
    fd = open(dir, O_RDONLY);
    if (fd >= 0) {
        if (fsync(fd)) {
            if (errno == EINVAL || errno == EROFS) {
                /* This directory does not support synchronization.  Not
                 * really an error. */
            } else {
                error = errno;
                VLOG_ERR("%s: fsync failed (%s)", dir, ovs_strerror(error));
            }
        }
        close(fd);
    } else {
        error = errno;
        VLOG_ERR("%s: open failed (%s)", dir, ovs_strerror(error));
    }
    free(dir);
#endif

    return error;
}

/* Obtains the modification time of the file named 'file_name' to the greatest
 * supported precision.  If successful, stores the mtime in '*mtime' and
 * returns 0.  On error, returns a positive errno value and stores zeros in
 * '*mtime'. */
int
get_mtime(const char *file_name, struct timespec *mtime)
{
    struct stat s;

    if (!stat(file_name, &s)) {
        mtime->tv_sec = s.st_mtime;

#if HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
        mtime->tv_nsec = s.st_mtim.tv_nsec;
#elif HAVE_STRUCT_STAT_ST_MTIMENSEC
        mtime->tv_nsec = s.st_mtimensec;
#else
        mtime->tv_nsec = 0;
#endif

        return 0;
    } else {
        mtime->tv_sec = mtime->tv_nsec = 0;
        return errno;
    }
}

#ifndef _WIN32
void
xpipe(int fds[2])
{
    if (pipe(fds)) {
        VLOG_FATAL("failed to create pipe (%s)", ovs_strerror(errno));
    }
}

void
xpipe_nonblocking(int fds[2])
{
    xpipe(fds);
    xset_nonblocking(fds[0]);
    xset_nonblocking(fds[1]);
}
#endif

static int
getsockopt_int(int fd, int level, int option, const char *optname, int *valuep)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
    socklen_t len;
    int value;
    int error;

    len = sizeof value;
    if (getsockopt(fd, level, option, &value, &len)) {
        error = sock_errno();
        VLOG_ERR_RL(&rl, "getsockopt(%s): %s", optname, sock_strerror(error));
    } else if (len != sizeof value) {
        error = EINVAL;
        VLOG_ERR_RL(&rl, "getsockopt(%s): value is %u bytes (expected %"PRIuSIZE")",
                    optname, (unsigned int) len, sizeof value);
    } else {
        error = 0;
    }

    *valuep = error ? 0 : value;
    return error;
}

static void
describe_sockaddr(struct ds *string, int fd,
                  int (*getaddr)(int, struct sockaddr *, socklen_t *))
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;

    if (!getaddr(fd, (struct sockaddr *) &ss, &len)) {
        if (ss.ss_family == AF_INET || ss.ss_family == AF_INET6) {
            char addrbuf[SS_NTOP_BUFSIZE];

            ds_put_format(string, "%s:%"PRIu16,
                          ss_format_address(&ss, addrbuf, sizeof addrbuf),
                          ss_get_port(&ss));
#ifndef _WIN32
        } else if (ss.ss_family == AF_UNIX) {
            struct sockaddr_un sun;
            const char *null;
            size_t maxlen;

            memcpy(&sun, &ss, sizeof sun);
            maxlen = len - offsetof(struct sockaddr_un, sun_path);
            null = memchr(sun.sun_path, '\0', maxlen);
            ds_put_buffer(string, sun.sun_path,
                          null ? null - sun.sun_path : maxlen);
#endif
        }
#ifdef HAVE_NETLINK
        else if (ss.ss_family == AF_NETLINK) {
            int protocol;

/* SO_PROTOCOL was introduced in 2.6.32.  Support it regardless of the version
 * of the Linux kernel headers in use at build time. */
#ifndef SO_PROTOCOL
#define SO_PROTOCOL 38
#endif

            if (!getsockopt_int(fd, SOL_SOCKET, SO_PROTOCOL, "SO_PROTOCOL",
                                &protocol)) {
                switch (protocol) {
                case NETLINK_ROUTE:
                    ds_put_cstr(string, "NETLINK_ROUTE");
                    break;

                case NETLINK_GENERIC:
                    ds_put_cstr(string, "NETLINK_GENERIC");
                    break;

                default:
                    ds_put_format(string, "AF_NETLINK family %d", protocol);
                    break;
                }
            } else {
                ds_put_cstr(string, "AF_NETLINK");
            }
        }
#endif
#if __linux__
        else if (ss.ss_family == AF_PACKET) {
            struct sockaddr_ll sll;

            memcpy(&sll, &ss, sizeof sll);
            ds_put_cstr(string, "AF_PACKET");
            if (sll.sll_ifindex) {
                char name[IFNAMSIZ];

                if (if_indextoname(sll.sll_ifindex, name)) {
                    ds_put_format(string, "(%s)", name);
                } else {
                    ds_put_format(string, "(ifindex=%d)", sll.sll_ifindex);
                }
            }
            if (sll.sll_protocol) {
                ds_put_format(string, "(protocol=0x%"PRIu16")",
                              ntohs(sll.sll_protocol));
            }
        }
#endif
        else if (ss.ss_family == AF_UNSPEC) {
            ds_put_cstr(string, "AF_UNSPEC");
        } else {
            ds_put_format(string, "AF_%d", (int) ss.ss_family);
        }
    }
}


#ifdef __linux__
static void
put_fd_filename(struct ds *string, int fd)
{
    char buf[1024];
    char *linkname;
    int n;

    linkname = xasprintf("/proc/self/fd/%d", fd);
    n = readlink(linkname, buf, sizeof buf);
    if (n > 0) {
        ds_put_char(string, ' ');
        ds_put_buffer(string, buf, n);
        if (n > sizeof buf) {
            ds_put_cstr(string, "...");
        }
    }
    free(linkname);
}
#endif

/* Returns a malloc()'d string describing 'fd', for use in logging. */
char *
describe_fd(int fd)
{
    struct ds string;
    struct stat s;

    ds_init(&string);
#ifndef _WIN32
    if (fstat(fd, &s)) {
        ds_put_format(&string, "fstat failed (%s)", ovs_strerror(errno));
    } else if (S_ISSOCK(s.st_mode)) {
        describe_sockaddr(&string, fd, getsockname);
        ds_put_cstr(&string, "<->");
        describe_sockaddr(&string, fd, getpeername);
    } else {
        ds_put_cstr(&string, (isatty(fd) ? "tty"
                              : S_ISDIR(s.st_mode) ? "directory"
                              : S_ISCHR(s.st_mode) ? "character device"
                              : S_ISBLK(s.st_mode) ? "block device"
                              : S_ISREG(s.st_mode) ? "file"
                              : S_ISFIFO(s.st_mode) ? "FIFO"
                              : S_ISLNK(s.st_mode) ? "symbolic link"
                              : "unknown"));
#ifdef __linux__
        put_fd_filename(&string, fd);
#endif
    }
#else
    ds_put_format(&string,"file descriptor");
#endif /* _WIN32 */
    return ds_steal_cstr(&string);
}

#ifndef _WIN32
/* Calls ioctl() on an AF_INET sock, passing the specified 'command' and
 * 'arg'.  Returns 0 if successful, otherwise a positive errno value. */
int
af_inet_ioctl(unsigned long int command, const void *arg)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int sock;

    if (ovsthread_once_start(&once)) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            int error = sock_errno();
            VLOG_ERR("failed to create inet socket: %s", sock_strerror(error));
            sock = -error;
        }
        ovsthread_once_done(&once);
    }

    return (sock < 0 ? -sock
            : ioctl(sock, command, arg) == -1 ? errno
            : 0);
}

int
af_inet_ifreq_ioctl(const char *name, struct ifreq *ifr, unsigned long int cmd,
                    const char *cmd_name)
{
    int error;

    ovs_strzcpy(ifr->ifr_name, name, sizeof ifr->ifr_name);
    error = af_inet_ioctl(cmd, ifr);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_DBG_RL(&rl, "%s: ioctl(%s) failed: %s", name, cmd_name,
                    ovs_strerror(error));
    }
    return error;
}
#endif

/* sockaddr_storage helpers. */

/* Returns the IPv4 or IPv6 port in 'ss'. */
uint16_t
ss_get_port(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin
            = ALIGNED_CAST(const struct sockaddr_in *, ss);
        return ntohs(sin->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6
            = ALIGNED_CAST(const struct sockaddr_in6 *, ss);
        return ntohs(sin6->sin6_port);
    } else {
        OVS_NOT_REACHED();
    }
}

/* Formats the IPv4 or IPv6 address in 'ss' into the 'bufsize' bytes in 'buf'.
 * If 'ss' is an IPv6 address, puts square brackets around the address.
 * 'bufsize' should be at least SS_NTOP_BUFSIZE.
 *
 * Returns 'buf'. */
char *
ss_format_address(const struct sockaddr_storage *ss,
                  char *buf, size_t bufsize)
{
    ovs_assert(bufsize >= SS_NTOP_BUFSIZE);
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin
            = ALIGNED_CAST(const struct sockaddr_in *, ss);

        snprintf(buf, bufsize, IP_FMT, IP_ARGS(sin->sin_addr.s_addr));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6
            = ALIGNED_CAST(const struct sockaddr_in6 *, ss);

        buf[0] = '[';
        inet_ntop(AF_INET6, sin6->sin6_addr.s6_addr, buf + 1, bufsize - 1);
        strcpy(strchr(buf, '\0'), "]");
    } else {
        OVS_NOT_REACHED();
    }

    return buf;
}

size_t
ss_length(const struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);

    case AF_INET6:
        return sizeof(struct sockaddr_in6);

    default:
        OVS_NOT_REACHED();
    }
}

/* For Windows socket calls, 'errno' is not set.  One has to call
 * WSAGetLastError() to get the error number and then pass it to
 * this function to get the correct error string.
 *
 * ovs_strerror() calls strerror_r() and would not get the correct error
 * string for Windows sockets, but is good for POSIX. */
const char *
sock_strerror(int error)
{
#ifdef _WIN32
    return ovs_format_message(error);
#else
    return ovs_strerror(error);
#endif
}
