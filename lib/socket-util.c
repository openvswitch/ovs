/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include "openvswitch/dynamic-string.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "util.h"
#include "openvswitch/vlog.h"
#ifdef __linux__
#include <linux/if_packet.h>
#endif
#ifdef HAVE_NETLINK
#include "netlink-protocol.h"
#include "netlink-socket.h"
#endif
#include "dns-resolve.h"

VLOG_DEFINE_THIS_MODULE(socket_util);

static int getsockopt_int(int fd, int level, int option, const char *optname,
                          int *valuep);
static struct sockaddr_in *sin_cast(const struct sockaddr *);
static struct sockaddr_in6 *sin6_cast(const struct sockaddr *);
static const struct sockaddr *sa_cast(const struct sockaddr_storage *);
static bool parse_sockaddr_components(struct sockaddr_storage *ss,
                                      char *host_s,
                                      const char *port_s,
                                      uint16_t default_port,
                                      const char *s,
                                      bool resolve_host);

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

void
setsockopt_tcp_nodelay(int fd)
{
    int on = 1;
    int retval;

    retval = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    if (retval) {
        retval = sock_errno();
        VLOG_ERR("setsockopt(TCP_NODELAY): %s", sock_strerror(retval));
    }
}

/* Sets the DSCP value of socket 'fd' to 'dscp', which must be 63 or less.
 * 'family' must indicate the socket's address family (AF_INET or AF_INET6, to
 * do anything useful). */
int
set_dscp(int fd, int family, uint8_t dscp)
{
    int retval;
    int val;

#ifdef _WIN32
    /* XXX: Consider using QoS2 APIs for Windows to set dscp. */
    return 0;
#endif

    if (dscp > 63) {
        return EINVAL;
    }
    val = dscp << 2;

    switch (family) {
    case AF_INET:
        retval = setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof val);
        break;

    case AF_INET6:
        retval = setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof val);
        break;

    default:
        return ENOPROTOOPT;
    }

    return retval ? sock_errno() : 0;
}

/* Checks whether 'host_name' is an IPv4 or IPv6 address.  It is assumed
 * that 'host_name' is valid.  Returns false if it is IPv4 address, true if
 * it is IPv6 address. */
bool
addr_is_ipv6(const char *host_name)
{
    return strchr(host_name, ':') != NULL;
}

/* Translates 'host_name', which must be a string representation of an IP
 * address, into a numeric IP address in '*addr'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr)
{
    if (!ip_parse(host_name, &addr->s_addr)) {
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
    if (!ipv6_parse(host_name, addr)) {
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

    if (ip_parse(host_name, &addr->s_addr)) {
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
    fd_set wrset, exset;
    FD_ZERO(&wrset);
    FD_ZERO(&exset);
    FD_SET(fd, &exset);
    FD_SET(fd, &wrset);
    pfd.revents = 0;
    struct timeval tv = { 0, 0 };
    /* WSAPoll is broken on Windows, instead do a select */
    retval = select(0, NULL, &wrset, &exset, &tv);
    if (retval == 1) {
        if (FD_ISSET(fd, &wrset)) {
            pfd.revents |= pfd.events;
        }
        if (FD_ISSET(fd, &exset)) {
            pfd.revents |= POLLERR;
        }
    }
#endif
    if (retval == 1) {
        if (pfd.revents & (POLLERR | POLLHUP)) {
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

ovs_be32
guess_netmask(ovs_be32 ip_)
{
    uint32_t ip = ntohl(ip_);
    return ((ip >> 31) == 0 ? htonl(0xff000000)   /* Class A */
            : (ip >> 30) == 2 ? htonl(0xffff0000) /* Class B */
            : (ip >> 29) == 6 ? htonl(0xffffff00) /* Class C */
            : htonl(0));                          /* ??? */
}

static char *
unbracket(char *s)
{
    if (*s == '[') {
        s++;

        char *end = strchr(s, '\0');
        if (end[-1] == ']') {
            end[-1] = '\0';
        }
    }
    return s;
}

/* 'host_index' is 0 if the host precedes the port within 's', 1 otherwise. */
static void
inet_parse_tokens__(char *s, int host_index, char **hostp, char **portp)
{
    char *colon = NULL;
    bool in_brackets = false;
    int n_colons = 0;
    for (char *p = s; *p; p++) {
        if (*p == '[') {
            in_brackets = true;
        } else if (*p == ']') {
            in_brackets = false;
        } else if (*p == ':' && !in_brackets) {
            n_colons++;
            colon = p;
        }
    }

    *hostp = *portp = NULL;
    if (n_colons > 1) {
        *hostp = s;
    } else {
        char **tokens[2];
        tokens[host_index] = hostp;
        tokens[!host_index] = portp;

        if (colon) {
            *colon = '\0';
            *tokens[1] = unbracket(colon + 1);
        }
        *tokens[0] = unbracket(s);
    }
}

/* Parses 's', a string in the form "<host>[:<port>]", into its (required) host
 * and (optional) port components, and stores pointers to them in '*hostp' and
 * '*portp' respectively.  Always sets '*hostp' nonnull, although possibly to
 * an empty string.  Can set '*portp' to the null string.
 *
 * Supports both IPv4 and IPv6.  IPv6 addresses may be quoted with square
 * brackets.  Resolves ambiguous cases that might represent an IPv6 address or
 * an IPv6 address and a port as representing just a host, e.g. "::1:2:3:4:80"
 * is a host but "[::1:2:3:4]:80" is a host and a port.
 *
 * Modifies 's' and points '*hostp' and '*portp' (if nonnull) into it.
 */
void
inet_parse_host_port_tokens(char *s, char **hostp, char **portp)
{
    inet_parse_tokens__(s, 0, hostp, portp);
}

/* Parses 's', a string in the form "<port>[:<host>]", into its port and host
 * components, and stores pointers to them in '*portp' and '*hostp'
 * respectively.  Either '*portp' and '*hostp' (but not both) can end up null.
 *
 * Supports both IPv4 and IPv6.  IPv6 addresses may be quoted with square
 * brackets.  Resolves ambiguous cases that might represent an IPv6 address or
 * an IPv6 address and a port as representing just a host, e.g. "::1:2:3:4:80"
 * is a host but "[::1:2:3:4]:80" is a host and a port.
 *
 * Modifies 's' and points '*hostp' and '*portp' (if nonnull) into it.
 */
void
inet_parse_port_host_tokens(char *s, char **portp, char **hostp)
{
    inet_parse_tokens__(s, 1, hostp, portp);
}

static bool
parse_sockaddr_components_dns(struct sockaddr_storage *ss OVS_UNUSED,
                              char *host_s,
                              const char *port_s OVS_UNUSED,
                              uint16_t default_port OVS_UNUSED,
                              const char *s OVS_UNUSED)
{
    char *tmp_host_s;

    dns_resolve(host_s, &tmp_host_s);
    if (tmp_host_s != NULL) {
        parse_sockaddr_components(ss, tmp_host_s, port_s,
                                  default_port, s, false);
        free(tmp_host_s);
        return true;
    }
    return false;
}

static bool
parse_sockaddr_components(struct sockaddr_storage *ss,
                          char *host_s,
                          const char *port_s, uint16_t default_port,
                          const char *s,
                          bool resolve_host)
{
    struct sockaddr_in *sin = sin_cast(sa_cast(ss));
    int port;

    if (port_s && port_s[0]) {
        if (!str_to_int(port_s, 10, &port) || port < 0 || port > 65535) {
            VLOG_ERR("%s: bad port number \"%s\"", s, port_s);
            goto exit;
        }
    } else {
        port = default_port;
    }

    memset(ss, 0, sizeof *ss);
    if (host_s && strchr(host_s, ':')) {
        struct sockaddr_in6 *sin6 = sin6_cast(sa_cast(ss));
        char *addr = strsep(&host_s, "%");

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        if (!addr || !*addr || !ipv6_parse(addr, &sin6->sin6_addr)) {
            goto exit;
        }

#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
        char *scope = strsep(&host_s, "%");
        if (scope && *scope) {
            if (!scope[strspn(scope, "0123456789")]) {
                sin6->sin6_scope_id = atoi(scope);
            } else {
                sin6->sin6_scope_id = if_nametoindex(scope);
                if (!sin6->sin6_scope_id) {
                    VLOG_ERR("%s: bad IPv6 scope \"%s\" (%s)",
                             s, scope, ovs_strerror(errno));
                    goto exit;
                }
            }
        }
#endif
    } else {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        if (host_s && !ip_parse(host_s, &sin->sin_addr.s_addr)) {
            goto resolve;
        }
    }

    return true;

resolve:
    if (resolve_host && parse_sockaddr_components_dns(ss, host_s, port_s,
                                                      default_port, s)) {
        return true;
    } else if (!resolve_host) {
        VLOG_ERR("%s: bad IP address \"%s\"", s, host_s);
    }
exit:
    memset(ss, 0, sizeof *ss);
    return false;
}

/* Parses 'target', which should be a string in the format "<host>[:<port>]".
 * <host>, which is required, may be an IPv4 address or an IPv6 address
 * enclosed in square brackets.  If 'default_port' is nonnegative then <port>
 * is optional and defaults to 'default_port' (use 0 to make the kernel choose
 * an available port, although this isn't usually appropriate for active
 * connections).  If 'default_port' is negative, then <port> is required.
 * It resolves the host if 'resolve_host' is true.
 *
 * On success, returns true and stores the parsed remote address into '*ss'.
 * On failure, logs an error, stores zeros into '*ss', and returns false. */
bool
inet_parse_active(const char *target_, int default_port,
                  struct sockaddr_storage *ss, bool resolve_host)
{
    char *target = xstrdup(target_);
    char *port, *host;
    bool ok;

    inet_parse_host_port_tokens(target, &host, &port);
    if (!host) {
        VLOG_ERR("%s: host must be specified", target_);
        ok = false;
    } else if (!port && default_port < 0) {
        VLOG_ERR("%s: port must be specified", target_);
        ok = false;
    } else {
        ok = parse_sockaddr_components(ss, host, port, default_port,
                                       target_, resolve_host);
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
 * IPv6 address enclosed in square brackets.  If 'default_port' is nonnegative
 * then <port> is optional and defaults to 'default_port'.
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
inet_open_active(int style, const char *target, int default_port,
                 struct sockaddr_storage *ssp, int *fdp, uint8_t dscp)
{
    struct sockaddr_storage ss;
    int fd = -1;
    int error;

    /* Parse. */
    if (!inet_parse_active(target, default_port, &ss, true)) {
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
    error = set_dscp(fd, ss.ss_family, dscp);
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
    char *port, *host;
    bool ok;

    inet_parse_port_host_tokens(target, &port, &host);
    if (!port && default_port < 0) {
        VLOG_ERR("%s: port must be specified", target_);
        ok = false;
    } else {
        ok = parse_sockaddr_components(ss, host, port, default_port,
                                       target_, true);
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
 * appropriately place in the IP tos field.
 *
 * If 'kernel_print_port' is true and the port is dynamically assigned by
 * the kernel, print the chosen port. */
int
inet_open_passive(int style, const char *target, int default_port,
                  struct sockaddr_storage *ssp, uint8_t dscp,
                  bool kernel_print_port)
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
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "%s: bind: %s", target, sock_strerror(error));
        goto error;
    }

    /* The dscp bits must be configured before connect() to ensure that the TOS
     * field is set during the connection establishment.  If set after
     * connect(), the handshake SYN frames will be sent with a TOS of 0. */
    error = set_dscp(fd, ss.ss_family, dscp);
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
        if (kernel_chooses_port && kernel_print_port) {
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

/* Parses 'target', which may be an IPv4 address or an IPv6 address
 * enclosed in square brackets.
 *
 * On success, returns true and stores the parsed remote address into '*ss'.
 * On failure, logs an error, stores zeros into '*ss', and returns false. */
bool
inet_parse_address(const char *target_, struct sockaddr_storage *ss)
{
    char *target = xstrdup(target_);
    char *host = unbracket(target);
    bool ok = parse_sockaddr_components(ss, host, NULL, 0, target_, false);
    if (!ok) {
        memset(ss, 0, sizeof *ss);
    }
    free(target);
    return ok;
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
            ss_format_address(&ss, string);
            ds_put_format(string, ":%"PRIu16, ss_get_port(&ss));
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

/* sockaddr helpers. */

static struct sockaddr_in *
sin_cast(const struct sockaddr *sa)
{
    return ALIGNED_CAST(struct sockaddr_in *, sa);
}

static struct sockaddr_in6 *
sin6_cast(const struct sockaddr *sa)
{
    return ALIGNED_CAST(struct sockaddr_in6 *, sa);
}

/* Returns true if 'sa' represents an IPv4 or IPv6 address, false otherwise. */
bool
sa_is_ip(const struct sockaddr *sa)
{
    return sa->sa_family == AF_INET || sa->sa_family == AF_INET6;
}

/* Returns the IPv4 or IPv6 address in 'sa'.  Returns IPv4 addresses as
 * v6-mapped. */
struct in6_addr
sa_get_address(const struct sockaddr *sa)
{
    ovs_assert(sa_is_ip(sa));
    return (sa->sa_family == AF_INET
            ? in6_addr_mapped_ipv4(sin_cast(sa)->sin_addr.s_addr)
            : sin6_cast(sa)->sin6_addr);
}

/* Returns the IPv4 or IPv6 port in 'sa'. */
uint16_t
sa_get_port(const struct sockaddr *sa)
{
    ovs_assert(sa_is_ip(sa));
    return ntohs(sa->sa_family == AF_INET
                 ? sin_cast(sa)->sin_port
                 : sin6_cast(sa)->sin6_port);
}

/* Returns true if 'name' is safe to include inside a network address field.
 * We want to avoid names that include confusing punctuation, etc. */
static bool OVS_UNUSED
is_safe_name(const char *name)
{
    if (!name[0] || isdigit((unsigned char) name[0])) {
        return false;
    }
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char) *p) && *p != '-' && *p != '_') {
            return false;
        }
    }
    return true;
}

static void
sa_format_address__(const struct sockaddr *sa,
                    const char *lbrack, const char *rbrack,
                    struct ds *s)
{
    ovs_assert(sa_is_ip(sa));
    if (sa->sa_family == AF_INET) {
        ds_put_format(s, IP_FMT, IP_ARGS(sin_cast(sa)->sin_addr.s_addr));
    } else {
        const struct sockaddr_in6 *sin6 = sin6_cast(sa);

        ds_put_cstr(s, lbrack);
        ds_reserve(s, s->length + INET6_ADDRSTRLEN);
        char *tail = &s->string[s->length];
        inet_ntop(AF_INET6, sin6->sin6_addr.s6_addr, tail, INET6_ADDRSTRLEN);
        s->length += strlen(tail);

#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
        uint32_t scope = sin6->sin6_scope_id;
        if (scope) {
            char namebuf[IF_NAMESIZE];
            char *name = if_indextoname(scope, namebuf);
            ds_put_char(s, '%');
            if (name && is_safe_name(name)) {
                ds_put_cstr(s, name);
            } else {
                ds_put_format(s, "%"PRIu32, scope);
            }
        }
#endif

        ds_put_cstr(s, rbrack);
    }
}

/* Formats the IPv4 or IPv6 address in 'sa' into 's'.  If 'sa' is an IPv6
 * address, puts square brackets around the address. */
void
sa_format_address(const struct sockaddr *sa, struct ds *s)
{
    sa_format_address__(sa, "[", "]", s);
}

/* Formats the IPv4 or IPv6 address in 'sa' into 's'.  Does not add square
 * brackets around IPv6 addresses. */
void
sa_format_address_nobracks(const struct sockaddr *sa, struct ds *s)
{
    sa_format_address__(sa, "", "", s);
}

size_t
sa_length(const struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);

    case AF_INET6:
        return sizeof(struct sockaddr_in6);

    default:
        OVS_NOT_REACHED();
    }
}

/* sockaddr_storage helpers.  */

static const struct sockaddr *
sa_cast(const struct sockaddr_storage *ss)
{
    return ALIGNED_CAST(const struct sockaddr *, ss);
}

bool
ss_is_ip(const struct sockaddr_storage *ss)
{
    return sa_is_ip(sa_cast(ss));
}

uint16_t
ss_get_port(const struct sockaddr_storage *ss)
{
    return sa_get_port(sa_cast(ss));
}

struct in6_addr
ss_get_address(const struct sockaddr_storage *ss)
{
    return sa_get_address(sa_cast(ss));
}

void
ss_format_address(const struct sockaddr_storage *ss, struct ds *s)
{
    sa_format_address(sa_cast(ss), s);
}

void
ss_format_address_nobracks(const struct sockaddr_storage *ss, struct ds *s)
{
    sa_format_address_nobracks(sa_cast(ss), s);
}

size_t
ss_length(const struct sockaddr_storage *ss)
{
    return sa_length(sa_cast(ss));
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

#ifdef __linux__
static int
emulate_sendmmsg(int fd, struct mmsghdr *msgs, unsigned int n,
                 unsigned int flags)
{
    for (unsigned int i = 0; i < n; i++) {
        ssize_t retval = sendmsg(fd, &msgs[i].msg_hdr, flags);
        if (retval < 0) {
            return i ? i : retval;
        }
        msgs[i].msg_len = retval;
    }
    return n;
}

#ifndef HAVE_SENDMMSG
int
sendmmsg(int fd, struct mmsghdr *msgs, unsigned int n, unsigned int flags)
{
    return emulate_sendmmsg(fd, msgs, n, flags);
}
#else
/* sendmmsg was redefined in lib/socket-util.c, should undef sendmmsg here
 * to avoid recursion */
#undef sendmmsg
int
wrap_sendmmsg(int fd, struct mmsghdr *msgs, unsigned int n, unsigned int flags)
{
    static bool sendmmsg_broken = false;
    if (!sendmmsg_broken) {
        int save_errno = errno;
        int retval = sendmmsg(fd, msgs, n, flags);
        if (retval >= 0 || errno != ENOSYS) {
            return retval;
        }
        sendmmsg_broken = true;
        errno = save_errno;
    }
    return emulate_sendmmsg(fd, msgs, n, flags);
}
#endif

static int
emulate_recvmmsg(int fd, struct mmsghdr *msgs, unsigned int n,
                 int flags, struct timespec *timeout OVS_UNUSED)
{
    ovs_assert(!timeout);       /* XXX not emulated */

    bool waitforone = flags & MSG_WAITFORONE;
    flags &= ~MSG_WAITFORONE;

    for (unsigned int i = 0; i < n; i++) {
        ssize_t retval = recvmsg(fd, &msgs[i].msg_hdr, flags);
        if (retval < 0) {
            return i ? i : retval;
        }
        msgs[i].msg_len = retval;

        if (waitforone) {
            flags |= MSG_DONTWAIT;
        }
    }
    return n;
}

#ifndef HAVE_SENDMMSG
int
recvmmsg(int fd, struct mmsghdr *msgs, unsigned int n,
         int flags, struct timespec *timeout)
{
    return emulate_recvmmsg(fd, msgs, n, flags, timeout);
}
#else
/* recvmmsg was redefined in lib/socket-util.c, should undef recvmmsg here
 * to avoid recursion */
#undef recvmmsg
int
wrap_recvmmsg(int fd, struct mmsghdr *msgs, unsigned int n,
              int flags, struct timespec *timeout)
{
    ovs_assert(!timeout);       /* XXX not emulated */

    static bool recvmmsg_broken = false;
    if (!recvmmsg_broken) {
        int save_errno = errno;
        int retval = recvmmsg(fd, msgs, n, flags, timeout);
        if (retval >= 0 || errno != ENOSYS) {
            return retval;
        }
        recvmmsg_broken = true;
        errno = save_errno;
    }
    return emulate_recvmmsg(fd, msgs, n, flags, timeout);
}
#endif
#endif /* __linux__ */
