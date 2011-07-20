/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#ifndef NETLINK_SOCKET_H
#define NETLINK_SOCKET_H 1

/* Netlink socket definitions.
 *
 * Netlink is a datagram-based network protocol primarily for communication
 * between user processes and the kernel, and mainly on Linux.  Netlink is
 * specified in RFC 3549, "Linux Netlink as an IP Services Protocol".
 *
 * Netlink is not suitable for use in physical networks of heterogeneous
 * machines because host byte order is used throughout.
 *
 * This header file defines functions for working with Netlink sockets, which
 * are Linux-specific.  For Netlink protocol definitions, see
 * netlink-protocol.h.  For helper functions for working with Netlink messages,
 * see netlink.h.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ofpbuf;
struct nl_sock;

#ifndef HAVE_NETLINK
#error "netlink-socket.h is only for hosts that support Netlink sockets"
#endif

/* Netlink sockets. */
int nl_sock_create(int protocol, struct nl_sock **);
int nl_sock_clone(const struct nl_sock *, struct nl_sock **);
void nl_sock_destroy(struct nl_sock *);

int nl_sock_join_mcgroup(struct nl_sock *, unsigned int multicast_group);
int nl_sock_leave_mcgroup(struct nl_sock *, unsigned int multicast_group);

int nl_sock_send(struct nl_sock *, const struct ofpbuf *, bool wait);
int nl_sock_recv(struct nl_sock *, struct ofpbuf **, bool wait);
int nl_sock_transact(struct nl_sock *, const struct ofpbuf *request,
                     struct ofpbuf **reply);

int nl_sock_drain(struct nl_sock *);

void nl_sock_wait(const struct nl_sock *, short int events);

/* Table dumping. */
struct nl_dump {
    struct nl_sock *sock;       /* Socket being dumped. */
    uint32_t seq;               /* Expected nlmsg_seq for replies. */
    struct ofpbuf *buffer;      /* Receive buffer currently being iterated. */
    int status;                 /* 0=OK, EOF=done, or positive errno value. */
};

void nl_dump_start(struct nl_dump *, struct nl_sock *,
                   const struct ofpbuf *request);
bool nl_dump_next(struct nl_dump *, struct ofpbuf *reply);
int nl_dump_done(struct nl_dump *);

/* Miscellaneous */
int nl_lookup_genl_family(const char *name, int *number);

#endif /* netlink-socket.h */
