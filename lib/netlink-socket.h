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
 *
 *
 * Thread-safety
 * =============
 *
 * Most of the netlink functions are not fully thread-safe: Only a single
 * thread may use a given nl_sock or nl_dump at one time. The exceptions are:
 *
 *    - nl_sock_recv() is conditionally thread-safe: it may be called from
 *      different threads with the same nl_sock, but each caller must provide
 *      an independent receive buffer.
 *
 *    - nl_dump_next() is conditionally thread-safe: it may be called from
 *      different threads with the same nl_dump, but each caller must provide
 *      independent buffers.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ofpbuf.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"

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
int nl_sock_send_seq(struct nl_sock *, const struct ofpbuf *,
                     uint32_t nlmsg_seq, bool wait);
int nl_sock_recv(struct nl_sock *, struct ofpbuf *, bool wait);
int nl_sock_transact(struct nl_sock *, const struct ofpbuf *request,
                     struct ofpbuf **replyp);

int nl_sock_drain(struct nl_sock *);

void nl_sock_wait(const struct nl_sock *, short int events);
int nl_sock_fd(const struct nl_sock *);

uint32_t nl_sock_pid(const struct nl_sock *);

/* Batching transactions. */
struct nl_transaction {
    /* Filled in by client. */
    struct ofpbuf *request;     /* Request to send. */

    /* The client must initialize 'reply' to one of:
     *
     *   - NULL, if it does not care to examine the reply.
     *
     *   - Otherwise, to an ofpbuf with a memory allocation of at least
     *     NLMSG_HDRLEN bytes.
     */
    struct ofpbuf *reply;       /* Reply (empty if reply was an error code). */
    int error;                  /* Positive errno value, 0 if no error. */
};

void nl_sock_transact_multiple(struct nl_sock *,
                               struct nl_transaction **, size_t n);

/* Transactions without an allocated socket. */
int nl_transact(int protocol, const struct ofpbuf *request,
                struct ofpbuf **replyp);
void nl_transact_multiple(int protocol, struct nl_transaction **, size_t n);

/* Table dumping. */
#define NL_DUMP_BUFSIZE         4096

struct nl_dump {
    struct nl_sock *sock;       /* Socket being dumped. */
    uint32_t nl_seq;            /* Expected nlmsg_seq for replies. */
    atomic_uint status;         /* Low bit set if we read final message.
                                 * Other bits hold an errno (0 for success). */
    struct seq *status_seq;     /* Tracks changes to the above 'status'. */
    struct ovs_mutex mutex;
};

void nl_dump_start(struct nl_dump *, int protocol,
                   const struct ofpbuf *request);
bool nl_dump_next(struct nl_dump *, struct ofpbuf *reply, struct ofpbuf *buf);
bool nl_dump_peek(struct ofpbuf *reply, struct ofpbuf *buf);
int nl_dump_done(struct nl_dump *);

/* Miscellaneous */
int nl_lookup_genl_family(const char *name, int *number);
int nl_lookup_genl_mcgroup(const char *family_name, const char *group_name,
                           unsigned int *multicast_group);

#endif /* netlink-socket.h */
