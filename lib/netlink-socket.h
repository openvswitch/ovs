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
 * This header file defines functions for working with Netlink sockets.  Only
 * Linux natively supports Netlink sockets, but Netlink is well suited as a
 * basis for extensible low-level protocols, so it can make sense to implement
 * a Netlink layer on other systems.  This doesn't have to be done in exactly
 * the same way as on Linux, as long as the implementation can support the
 * semantics that are important to Open vSwitch.  See "Usage concepts" below
 * for more information.
 *
 * For Netlink protocol definitions, see netlink-protocol.h.  For helper
 * functions for working with Netlink messages, see netlink.h.
 *
 *
 * Usage concepts
 * ==============
 *
 * Netlink is a datagram-based network protocol primarily for communication
 * between user processes and the kernel.  Netlink is specified in RFC 3549,
 * "Linux Netlink as an IP Services Protocol".
 *
 * Netlink is not suitable for use in physical networks of heterogeneous
 * machines because host byte order is used throughout.
 *
 * The AF_NETLINK socket namespace is subdivided into statically numbered
 * protocols, e.g. NETLINK_ROUTE, NETLINK_NETFILTER, provided as the third
 * argument to the socket() function.  Maintaining the assigned numbers became
 * a bit of a problem, so the "Generic Netlink" NETLINK_GENERIC protocol was
 * introduced to map between human-readable names and dynamically assigned
 * numbers.  All recently introduced Netlink protocol messages in Linux
 * (including all of the Open vSwitch specific messages) fall under
 * NETLINK_GENERIC.  The Netlink library provides the nl_lookup_genl_family()
 * function for translating a Generic Netlink name to a number.  On Linux, this
 * queries the kernel Generic Netlink implementation, but on other systems it
 * might be easier to statically assign each of the names used by Open vSwitch
 * and then implement this function entirely in userspace.
 *
 * Each Netlink socket is distinguished by its Netlink PID, a 32-bit integer
 * that is analogous to a TCP or UDP port number.  The kernel has PID 0.
 *
 * Most Netlink messages manage a kernel table of some kind, e.g. the kernel
 * routing table, ARP table, etc.  Open vSwitch specific messages manage tables
 * of datapaths, ports within datapaths ("vports"), and flows within
 * datapaths.  Open vSwitch also has messages related to network packets
 * received on vports, which aren't really a table.
 *
 * Datagram protocols over a physical network are typically unreliable: in UDP,
 * for example, messages can be dropped, delivered more than once, or delivered
 * out of order.  In Linux, Netlink does not deliver messages out of order or
 * multiple times.  In some cases it can drop messages, but the kernel
 * indicates when a message has been dropped.  The description below of each
 * way Open vSwitch uses Netlink also explains how to work around dropped
 * messages.
 *
 * Open vSwitch uses Netlink in four characteristic ways:
 *
 *    1. Transactions.  A transaction is analogous to a system call, an ioctl,
 *       or an RPC: userspace sends a request to the kernel, which processes
 *       the request synchronously and returns a reply to userspace.
 *       (Sometimes there is no explicit reply, but even in that case userspace
 *       will receive an immediate reply if there is an error.)
 *
 *       nl_transact() is the primary interface for transactions over Netlink.
 *       This function doesn't take a socket as a parameter because sockets do
 *       not have any state related to transactions.
 *
 *       Netlink uses 16-bit "length" fields extensively, which effectively
 *       limits requests and replies to 64 kB.  "Dumps" (see below) are one way
 *       to work around this limit for replies.
 *
 *       In the Linux implementation of Netlink transactions, replies can
 *       sometimes be lost.  When this happens, nl_transact() automatically
 *       executes the transaction again.  This means that it is important that
 *       transactions be idempotent, or that the client be prepared to tolerate
 *       that a transaction might actually execute more than once.
 *
 *       The Linux implementation can execute several transactions at the same
 *       time more efficiently than individually.  nl_transact_multiple()
 *       allows for this.  The semantics are no different from executing each
 *       of the transactions individually with nl_transact().
 *
 *    2. Dumps.  A dump asks the kernel to provide all of the information in a
 *       table.  It consists of a request and a reply, where the reply consists
 *       of an arbitrary number of messages.  Each message in the reply is
 *       limited to 64 kB, as is the request, but the total size of the reply
 *       can be many times larger.
 *
 *       The reply to a dump is usually generated piece by piece, not
 *       atomically.  The reply can represent an inconsistent snapshot of the
 *       table.  This is especially likely if entries in the table were being
 *       added or deleted or changing during the dump.
 *
 *       nl_dump_start() begins a dump based on the caller-provided request and
 *       initializes a "struct nl_dump" to identify the dump.  Subsequent calls
 *       to nl_dump_next() then obtain the reply, one message at a time.
 *       Usually, each message gives information about some entry in a table,
 *       e.g. one flow in the Open vSwitch flow table, or one route in a
 *       routing table.  nl_dump_done() ends the dump.
 *
 *       Linux implements dumps so that messages in a reply do not get lost.
 *
 *    3. Multicast subscriptions.  Most kernel Netlink implementations allow a
 *       process to monitor changes to its table, by subscribing to a Netlink
 *       multicast group dedicated to that table.  Whenever the table's content
 *       changes (e.g. an entry is added or deleted or modified), the Netlink
 *       implementation sends a message to all sockets that subscribe to its
 *       multicast group notifying it of details of the change.  (This doesn't
 *       require much extra work by the Netlink implementer because the message
 *       is generally identical to the one sent as a reply to the request that
 *       changed the table.)
 *
 *       nl_sock_join_mcgroup() subscribes a socket to a multicast group, and
 *       nl_sock_recv() reads notifications.
 *
 *       If userspace doesn't read messages from a socket subscribed to a
 *       multicast group quickly enough, then notification messages can pile up
 *       in the socket's receive buffer.  If this continues long enough, the
 *       receive buffer will fill up and notifications will be lost.  In that
 *       case, nl_sock_recv() will return ENOBUFS.  The client can then use a
 *       dump to resynchronize with the table state.  (A simple implementation
 *       of multicast groups might take advantage of this by simply returning
 *       ENOBUFS whenever a table changes, without implementing actual
 *       notifications.  This would cause lots of extra dumps, so it may not be
 *       suitable as a production implementation.)
 *
 *    4. Unicast subscriptions (Open vSwitch specific).  Userspace can assign
 *       one or more Netlink PIDs to a vport as "upcall PIDs".  When a packet
 *       received on the vport does not match any flow in its datapath's flow
 *       table, the kernel hashes some of the packet's headers, uses the hash
 *       to select one of the PIDs, and sends the packet (encapsulated in an
 *       Open vSwitch Netlink message) to the socket with the selected PID.
 *
 *       nl_sock_recv() reads notifications sent this way.
 *
 *       Specifically on Windows platform, the datapath needs to allocate a
 *       queue for packets, and it does so only when userspace "subscribe"'s to
 *       packets on that netlink socket.  Before closing the netlink socket,
 *       userspace needs to "unsubscribe" packets on that netlink socket.
 *
 *       nl_sock_subscribe_packets() and nl_sock_unsubscribe_packets() are
 *       Windows specific.
 *
 *       Messages received this way can overflow, just like multicast
 *       subscription messages, and they are reported the same way.  Because
 *       packet notification messages do not report the state of a table, there
 *       is no way to recover the dropped packets; they are simply lost.
 *
 *       The main reason to support multiple PIDs per vport is to increase
 *       fairness, that is, to make it harder for a single high-flow-rate
 *       sender to drown out lower rate sources.  Multiple PIDs per vport might
 *       also improve packet handling latency or flow setup rate, but that is
 *       not the main goal.
 *
 *       Old versions of the Linux kernel module supported only one PID per
 *       vport, and userspace still copes with this, so a simple or early
 *       implementation might only support one PID per vport too.
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
#include "openvswitch/ofpbuf.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"

struct nl_sock;

#ifndef HAVE_NETLINK
#ifndef _WIN32
#error "netlink-socket.h is only for hosts that support Netlink sockets"
#endif
#endif

/* Netlink sockets. */
int nl_sock_create(int protocol, struct nl_sock **);
int nl_sock_clone(const struct nl_sock *, struct nl_sock **);
void nl_sock_destroy(struct nl_sock *);

int nl_sock_join_mcgroup(struct nl_sock *, unsigned int multicast_group);
int nl_sock_leave_mcgroup(struct nl_sock *, unsigned int multicast_group);

#ifdef _WIN32
int nl_sock_subscribe_packets(struct nl_sock *sock);
int nl_sock_unsubscribe_packets(struct nl_sock *sock);
#endif

int nl_sock_send(struct nl_sock *, const struct ofpbuf *, bool wait);
int nl_sock_send_seq(struct nl_sock *, const struct ofpbuf *,
                     uint32_t nlmsg_seq, bool wait);
int nl_sock_recv(struct nl_sock *, struct ofpbuf *, bool wait);

int nl_sock_drain(struct nl_sock *);

void nl_sock_wait(const struct nl_sock *, short int events);
#ifndef _WIN32
int nl_sock_fd(const struct nl_sock *);
#endif

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

/* Transactions without an allocated socket. */
int nl_transact(int protocol, const struct ofpbuf *request,
                struct ofpbuf **replyp);
void nl_transact_multiple(int protocol, struct nl_transaction **, size_t n);

/* Table dumping. */
#define NL_DUMP_BUFSIZE         4096

struct nl_dump {
    /* These members are immutable during the lifetime of the nl_dump. */
    struct nl_sock *sock;       /* Socket being dumped. */
    uint32_t nl_seq;            /* Expected nlmsg_seq for replies. */
    int status OVS_GUARDED;     /* 0: dump in progress,
                                 * positive errno: dump completed with error,
                                 * EOF: dump completed successfully. */

    /* 'mutex' protects 'status' and serializes access to 'sock'. */
    struct ovs_mutex mutex;     /* Protects 'status', synchronizes recv(). */
};

void nl_dump_start(struct nl_dump *, int protocol,
                   const struct ofpbuf *request);
bool nl_dump_next(struct nl_dump *, struct ofpbuf *reply, struct ofpbuf *buf);
int nl_dump_done(struct nl_dump *);

/* Miscellaneous */
int nl_lookup_genl_family(const char *name, int *number);
int nl_lookup_genl_mcgroup(const char *family_name, const char *group_name,
                           unsigned int *multicast_group);

#endif /* netlink-socket.h */
