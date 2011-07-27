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

#include <config.h>
#include "netlink-socket.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "netlink.h"
#include "netlink-protocol.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "stress.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netlink_socket);

COVERAGE_DEFINE(netlink_overflow);
COVERAGE_DEFINE(netlink_received);
COVERAGE_DEFINE(netlink_recv_jumbo);
COVERAGE_DEFINE(netlink_send);
COVERAGE_DEFINE(netlink_sent);

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* A single (bad) Netlink message can in theory dump out many, many log
 * messages, so the burst size is set quite high here to avoid missing useful
 * information.  Also, at high logging levels we log *all* Netlink messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 600);

static void log_nlmsg(const char *function, int error,
                      const void *message, size_t size, int protocol);

/* Netlink sockets. */

struct nl_sock
{
    int fd;
    uint32_t pid;
    int protocol;
    bool any_groups;
    struct nl_dump *dump;
};

static int alloc_pid(uint32_t *);
static void free_pid(uint32_t);
static int nl_sock_cow__(struct nl_sock *);

/* Creates a new netlink socket for the given netlink 'protocol'
 * (NETLINK_ROUTE, NETLINK_GENERIC, ...).  Returns 0 and sets '*sockp' to the
 * new socket if successful, otherwise returns a positive errno value.  */
int
nl_sock_create(int protocol, struct nl_sock **sockp)
{
    struct nl_sock *sock;
    struct sockaddr_nl local, remote;
    int retval = 0;

    *sockp = NULL;
    sock = malloc(sizeof *sock);
    if (sock == NULL) {
        return ENOMEM;
    }

    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (sock->fd < 0) {
        VLOG_ERR("fcntl: %s", strerror(errno));
        goto error;
    }
    sock->protocol = protocol;
    sock->any_groups = false;
    sock->dump = NULL;

    retval = alloc_pid(&sock->pid);
    if (retval) {
        goto error;
    }

    /* Bind local address as our selected pid. */
    memset(&local, 0, sizeof local);
    local.nl_family = AF_NETLINK;
    local.nl_pid = sock->pid;
    if (bind(sock->fd, (struct sockaddr *) &local, sizeof local) < 0) {
        VLOG_ERR("bind(%"PRIu32"): %s", sock->pid, strerror(errno));
        goto error_free_pid;
    }

    /* Bind remote address as the kernel (pid 0). */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
        VLOG_ERR("connect(0): %s", strerror(errno));
        goto error_free_pid;
    }

    *sockp = sock;
    return 0;

error_free_pid:
    free_pid(sock->pid);
error:
    if (retval == 0) {
        retval = errno;
        if (retval == 0) {
            retval = EINVAL;
        }
    }
    if (sock->fd >= 0) {
        close(sock->fd);
    }
    free(sock);
    return retval;
}

/* Creates a new netlink socket for the same protocol as 'src'.  Returns 0 and
 * sets '*sockp' to the new socket if successful, otherwise returns a positive
 * errno value.  */
int
nl_sock_clone(const struct nl_sock *src, struct nl_sock **sockp)
{
    return nl_sock_create(src->protocol, sockp);
}

/* Destroys netlink socket 'sock'. */
void
nl_sock_destroy(struct nl_sock *sock)
{
    if (sock) {
        if (sock->dump) {
            sock->dump = NULL;
        } else {
            close(sock->fd);
            free_pid(sock->pid);
            free(sock);
        }
    }
}

/* Tries to add 'sock' as a listener for 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to join a multicast group to which a socket
 * already belongs. */
int
nl_sock_join_mcgroup(struct nl_sock *sock, unsigned int multicast_group)
{
    int error = nl_sock_cow__(sock);
    if (error) {
        return error;
    }
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        VLOG_WARN("could not join multicast group %u (%s)",
                  multicast_group, strerror(errno));
        return errno;
    }
    sock->any_groups = true;
    return 0;
}

/* Tries to make 'sock' stop listening to 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to leave a multicast group to which a socket
 * does not belong.
 *
 * On success, reading from 'sock' will still return any messages that were
 * received on 'multicast_group' before the group was left. */
int
nl_sock_leave_mcgroup(struct nl_sock *sock, unsigned int multicast_group)
{
    assert(!sock->dump);
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        VLOG_WARN("could not leave multicast group %u (%s)",
                  multicast_group, strerror(errno));
        return errno;
    }
    return 0;
}

static int
nl_sock_send__(struct nl_sock *sock, const struct ofpbuf *msg, bool wait)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(msg);
    int error;

    nlmsg->nlmsg_len = msg->size;
    nlmsg->nlmsg_pid = sock->pid;
    do {
        int retval;
        retval = send(sock->fd, msg->data, msg->size, wait ? 0 : MSG_DONTWAIT);
        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
    log_nlmsg(__func__, error, msg->data, msg->size, sock->protocol);
    if (!error) {
        COVERAGE_INC(netlink_sent);
    }
    return error;
}

/* Tries to send 'msg', which must contain a Netlink message, to the kernel on
 * 'sock'.  nlmsg_len in 'msg' will be finalized to match msg->size, and
 * nlmsg_pid will be set to 'sock''s pid, before the message is sent.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full. */
int
nl_sock_send(struct nl_sock *sock, const struct ofpbuf *msg, bool wait)
{
    int error = nl_sock_cow__(sock);
    if (error) {
        return error;
    }
    return nl_sock_send__(sock, msg, wait);
}

/* This stress option is useful for testing that OVS properly tolerates
 * -ENOBUFS on NetLink sockets.  Such errors are unavoidable because they can
 * occur if the kernel cannot temporarily allocate enough GFP_ATOMIC memory to
 * reply to a request.  They can also occur if messages arrive on a multicast
 * channel faster than OVS can process them. */
STRESS_OPTION(
    netlink_overflow, "simulate netlink socket receive buffer overflow",
    5, 1, -1, 100);

static int
nl_sock_recv__(struct nl_sock *sock, struct ofpbuf **bufp, bool wait)
{
    /* We can't accurately predict the size of the data to be received.  Most
     * received data will fit in a 2 kB buffer, so we allocate that much space.
     * In case the data is actually bigger than that, we make available enough
     * additional space to allow Netlink messages to be up to 64 kB long (a
     * reasonable figure since that's the maximum length of a Netlink
     * attribute). */
    enum { MAX_SIZE = 65536 };
    enum { HEAD_SIZE = 2048 };
    enum { TAIL_SIZE = MAX_SIZE - HEAD_SIZE };

    struct nlmsghdr *nlmsghdr;
    uint8_t tail[TAIL_SIZE];
    struct iovec iov[2];
    struct ofpbuf *buf;
    struct msghdr msg;
    ssize_t retval;

    *bufp = NULL;

    buf = ofpbuf_new(HEAD_SIZE);
    iov[0].iov_base = buf->data;
    iov[0].iov_len = HEAD_SIZE;
    iov[1].iov_base = tail;
    iov[1].iov_len = TAIL_SIZE;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    do {
        retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);
    } while (retval < 0 && errno == EINTR);

    if (retval < 0) {
        int error = errno;
        if (error == ENOBUFS) {
            /* Socket receive buffer overflow dropped one or more messages that
             * the kernel tried to send to us. */
            COVERAGE_INC(netlink_overflow);
        }
        ofpbuf_delete(buf);
        return error;
    }

    if (msg.msg_flags & MSG_TRUNC) {
        VLOG_ERR_RL(&rl, "truncated message (longer than %d bytes)", MAX_SIZE);
        ofpbuf_delete(buf);
        return E2BIG;
    }

    ofpbuf_put_uninit(buf, MIN(retval, HEAD_SIZE));
    if (retval > HEAD_SIZE) {
        COVERAGE_INC(netlink_recv_jumbo);
        ofpbuf_put(buf, tail, retval - HEAD_SIZE);
    }

    nlmsghdr = buf->data;
    if (retval < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len > retval) {
        VLOG_ERR_RL(&rl, "received invalid nlmsg (%zd bytes < %d)",
                    retval, NLMSG_HDRLEN);
        ofpbuf_delete(buf);
        return EPROTO;
    }

    if (STRESS(netlink_overflow)) {
        ofpbuf_delete(buf);
        return ENOBUFS;
    }

    *bufp = buf;
    log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
    COVERAGE_INC(netlink_received);

    return 0;
}

/* Tries to receive a netlink message from the kernel on 'sock'.  If
 * successful, stores the received message into '*bufp' and returns 0.  The
 * caller is responsible for destroying the message with ofpbuf_delete().  On
 * failure, returns a positive errno value and stores a null pointer into
 * '*bufp'.
 *
 * If 'wait' is true, nl_sock_recv waits for a message to be ready; otherwise,
 * returns EAGAIN if the 'sock' receive buffer is empty. */
int
nl_sock_recv(struct nl_sock *sock, struct ofpbuf **bufp, bool wait)
{
    int error = nl_sock_cow__(sock);
    if (error) {
        return error;
    }
    return nl_sock_recv__(sock, bufp, wait);
}

/* Sends 'request' to the kernel via 'sock' and waits for a response.  If
 * successful, returns 0.  On failure, returns a positive errno value.
 *
 * If 'replyp' is nonnull, then on success '*replyp' is set to the kernel's
 * reply, which the caller is responsible for freeing with ofpbuf_delete(), and
 * on failure '*replyp' is set to NULL.  If 'replyp' is null, then the kernel's
 * reply, if any, is discarded.
 *
 * nlmsg_len in 'msg' will be finalized to match msg->size, and nlmsg_pid will
 * be set to 'sock''s pid, before the message is sent.  NLM_F_ACK will be set
 * in nlmsg_flags.
 *
 * The caller is responsible for destroying 'request'.
 *
 * Bare Netlink is an unreliable transport protocol.  This function layers
 * reliable delivery and reply semantics on top of bare Netlink.
 *
 * In Netlink, sending a request to the kernel is reliable enough, because the
 * kernel will tell us if the message cannot be queued (and we will in that
 * case put it on the transmit queue and wait until it can be delivered).
 *
 * Receiving the reply is the real problem: if the socket buffer is full when
 * the kernel tries to send the reply, the reply will be dropped.  However, the
 * kernel sets a flag that a reply has been dropped.  The next call to recv
 * then returns ENOBUFS.  We can then re-send the request.
 *
 * Caveats:
 *
 *      1. Netlink depends on sequence numbers to match up requests and
 *         replies.  The sender of a request supplies a sequence number, and
 *         the reply echos back that sequence number.
 *
 *         This is fine, but (1) some kernel netlink implementations are
 *         broken, in that they fail to echo sequence numbers and (2) this
 *         function will drop packets with non-matching sequence numbers, so
 *         that only a single request can be usefully transacted at a time.
 *
 *      2. Resending the request causes it to be re-executed, so the request
 *         needs to be idempotent.
 */
int
nl_sock_transact(struct nl_sock *sock,
                 const struct ofpbuf *request, struct ofpbuf **replyp)
{
    uint32_t seq = nl_msg_nlmsghdr(request)->nlmsg_seq;
    struct nlmsghdr *nlmsghdr;
    struct ofpbuf *reply;
    int retval;

    if (replyp) {
        *replyp = NULL;
    }

    /* Ensure that we get a reply even if this message doesn't ordinarily call
     * for one. */
    nl_msg_nlmsghdr(request)->nlmsg_flags |= NLM_F_ACK;

send:
    retval = nl_sock_send(sock, request, true);
    if (retval) {
        return retval;
    }

recv:
    retval = nl_sock_recv(sock, &reply, true);
    if (retval) {
        if (retval == ENOBUFS) {
            COVERAGE_INC(netlink_overflow);
            VLOG_DBG_RL(&rl, "receive buffer overflow, resending request");
            goto send;
        } else {
            return retval;
        }
    }
    nlmsghdr = nl_msg_nlmsghdr(reply);
    if (seq != nlmsghdr->nlmsg_seq) {
        VLOG_DBG_RL(&rl, "ignoring seq %#"PRIx32" != expected %#"PRIx32,
                    nl_msg_nlmsghdr(reply)->nlmsg_seq, seq);
        ofpbuf_delete(reply);
        goto recv;
    }

    /* If the reply is an error, discard the reply and return the error code.
     *
     * Except: if the reply is just an acknowledgement (error code of 0), and
     * the caller is interested in the reply (replyp != NULL), pass the reply
     * up to the caller.  Otherwise the caller will get a return value of 0
     * and null '*replyp', which makes unwary callers likely to segfault. */
    if (nl_msg_nlmsgerr(reply, &retval) && (retval || !replyp)) {
        ofpbuf_delete(reply);
        if (retval) {
            VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                        retval, strerror(retval));
        }
        return retval != EAGAIN ? retval : EPROTO;
    }

    if (replyp) {
        *replyp = reply;
    } else {
        ofpbuf_delete(reply);
    }
    return 0;
}

/* Drain all the messages currently in 'sock''s receive queue. */
int
nl_sock_drain(struct nl_sock *sock)
{
    int error = nl_sock_cow__(sock);
    if (error) {
        return error;
    }
    return drain_rcvbuf(sock->fd);
}

/* The client is attempting some operation on 'sock'.  If 'sock' has an ongoing
 * dump operation, then replace 'sock''s fd with a new socket and hand 'sock''s
 * old fd over to the dump. */
static int
nl_sock_cow__(struct nl_sock *sock)
{
    struct nl_sock *copy;
    uint32_t tmp_pid;
    int tmp_fd;
    int error;

    if (!sock->dump) {
        return 0;
    }

    error = nl_sock_clone(sock, &copy);
    if (error) {
        return error;
    }

    tmp_fd = sock->fd;
    sock->fd = copy->fd;
    copy->fd = tmp_fd;

    tmp_pid = sock->pid;
    sock->pid = copy->pid;
    copy->pid = tmp_pid;

    sock->dump->sock = copy;
    sock->dump = NULL;

    return 0;
}

/* Starts a Netlink "dump" operation, by sending 'request' to the kernel via
 * 'sock', and initializes 'dump' to reflect the state of the operation.
 *
 * nlmsg_len in 'msg' will be finalized to match msg->size, and nlmsg_pid will
 * be set to 'sock''s pid, before the message is sent.  NLM_F_DUMP and
 * NLM_F_ACK will be set in nlmsg_flags.
 *
 * This Netlink socket library is designed to ensure that the dump is reliable
 * and that it will not interfere with other operations on 'sock', including
 * destroying or sending and receiving messages on 'sock'.  One corner case is
 * not handled:
 *
 *   - If 'sock' has been used to send a request (e.g. with nl_sock_send())
 *     whose response has not yet been received (e.g. with nl_sock_recv()).
 *     This is unusual: usually nl_sock_transact() is used to send a message
 *     and receive its reply all in one go.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling nl_dump_done().
 *
 * The caller is responsible for destroying 'request'.
 *
 * The new 'dump' is independent of 'sock'.  'sock' and 'dump' may be destroyed
 * in either order.
 */
void
nl_dump_start(struct nl_dump *dump,
              struct nl_sock *sock, const struct ofpbuf *request)
{
    struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(request);
    nlmsghdr->nlmsg_flags |= NLM_F_DUMP | NLM_F_ACK;
    dump->seq = nlmsghdr->nlmsg_seq;
    dump->buffer = NULL;
    if (sock->any_groups || sock->dump) {
        /* 'sock' might belong to some multicast group, or it already has an
         * onoging dump.  Clone the socket to avoid possibly intermixing
         * multicast messages or previous dump results with our results. */
        dump->status = nl_sock_clone(sock, &dump->sock);
        if (dump->status) {
            return;
        }
    } else {
        sock->dump = dump;
        dump->sock = sock;
        dump->status = 0;
    }
    dump->status = nl_sock_send__(sock, request, true);
}

/* Helper function for nl_dump_next(). */
static int
nl_dump_recv(struct nl_dump *dump, struct ofpbuf **bufferp)
{
    struct nlmsghdr *nlmsghdr;
    struct ofpbuf *buffer;
    int retval;

    retval = nl_sock_recv__(dump->sock, bufferp, true);
    if (retval) {
        return retval == EINTR ? EAGAIN : retval;
    }
    buffer = *bufferp;

    nlmsghdr = nl_msg_nlmsghdr(buffer);
    if (dump->seq != nlmsghdr->nlmsg_seq) {
        VLOG_DBG_RL(&rl, "ignoring seq %#"PRIx32" != expected %#"PRIx32,
                    nlmsghdr->nlmsg_seq, dump->seq);
        return EAGAIN;
    }

    if (nl_msg_nlmsgerr(buffer, &retval)) {
        VLOG_INFO_RL(&rl, "netlink dump request error (%s)",
                     strerror(retval));
        return retval && retval != EAGAIN ? retval : EPROTO;
    }

    return 0;
}

/* Attempts to retrieve another reply from 'dump', which must have been
 * initialized with nl_dump_start().
 *
 * If successful, returns true and points 'reply->data' and 'reply->size' to
 * the message that was retrieved.  The caller must not modify 'reply' (because
 * it points into the middle of a larger buffer).
 *
 * On failure, returns false and sets 'reply->data' to NULL and 'reply->size'
 * to 0.  Failure might indicate an actual error or merely the end of replies.
 * An error status for the entire dump operation is provided when it is
 * completed by calling nl_dump_done().
 */
bool
nl_dump_next(struct nl_dump *dump, struct ofpbuf *reply)
{
    struct nlmsghdr *nlmsghdr;

    reply->data = NULL;
    reply->size = 0;
    if (dump->status) {
        return false;
    }

    if (dump->buffer && !dump->buffer->size) {
        ofpbuf_delete(dump->buffer);
        dump->buffer = NULL;
    }
    while (!dump->buffer) {
        int retval = nl_dump_recv(dump, &dump->buffer);
        if (retval) {
            ofpbuf_delete(dump->buffer);
            dump->buffer = NULL;
            if (retval != EAGAIN) {
                dump->status = retval;
                return false;
            }
        }
    }

    nlmsghdr = nl_msg_next(dump->buffer, reply);
    if (!nlmsghdr) {
        VLOG_WARN_RL(&rl, "netlink dump reply contains message fragment");
        dump->status = EPROTO;
        return false;
    } else if (nlmsghdr->nlmsg_type == NLMSG_DONE) {
        dump->status = EOF;
        return false;
    }

    return true;
}

/* Completes Netlink dump operation 'dump', which must have been initialized
 * with nl_dump_start().  Returns 0 if the dump operation was error-free,
 * otherwise a positive errno value describing the problem. */
int
nl_dump_done(struct nl_dump *dump)
{
    /* Drain any remaining messages that the client didn't read.  Otherwise the
     * kernel will continue to queue them up and waste buffer space. */
    while (!dump->status) {
        struct ofpbuf reply;
        if (!nl_dump_next(dump, &reply)) {
            assert(dump->status);
        }
    }

    if (dump->sock) {
        if (dump->sock->dump) {
            dump->sock->dump = NULL;
        } else {
            nl_sock_destroy(dump->sock);
        }
    }
    ofpbuf_delete(dump->buffer);
    return dump->status == EOF ? 0 : dump->status;
}

/* Causes poll_block() to wake up when any of the specified 'events' (which is
 * a OR'd combination of POLLIN, POLLOUT, etc.) occur on 'sock'. */
void
nl_sock_wait(const struct nl_sock *sock, short int events)
{
    poll_fd_wait(sock->fd, events);
}

/* Miscellaneous.  */

struct genl_family {
    struct hmap_node hmap_node;
    uint16_t id;
    char *name;
};

static struct hmap genl_families = HMAP_INITIALIZER(&genl_families);

static const struct nl_policy family_policy[CTRL_ATTR_MAX + 1] = {
    [CTRL_ATTR_FAMILY_ID] = {.type = NL_A_U16},
};

static struct genl_family *
find_genl_family_by_id(uint16_t id)
{
    struct genl_family *family;

    HMAP_FOR_EACH_IN_BUCKET (family, hmap_node, hash_int(id, 0),
                             &genl_families) {
        if (family->id == id) {
            return family;
        }
    }
    return NULL;
}

static void
define_genl_family(uint16_t id, const char *name)
{
    struct genl_family *family = find_genl_family_by_id(id);

    if (family) {
        if (!strcmp(family->name, name)) {
            return;
        }
        free(family->name);
    } else {
        family = xmalloc(sizeof *family);
        family->id = id;
        hmap_insert(&genl_families, &family->hmap_node, hash_int(id, 0));
    }
    family->name = xstrdup(name);
}

static const char *
genl_family_to_name(uint16_t id)
{
    if (id == GENL_ID_CTRL) {
        return "control";
    } else {
        struct genl_family *family = find_genl_family_by_id(id);
        return family ? family->name : "unknown";
    }
}

static int do_lookup_genl_family(const char *name)
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    struct nlattr *attrs[ARRAY_SIZE(family_policy)];
    int retval;

    retval = nl_sock_create(NETLINK_GENERIC, &sock);
    if (retval) {
        return -retval;
    }

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, GENL_ID_CTRL, NLM_F_REQUEST,
                          CTRL_CMD_GETFAMILY, 1);
    nl_msg_put_string(&request, CTRL_ATTR_FAMILY_NAME, name);
    retval = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (retval) {
        nl_sock_destroy(sock);
        return -retval;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         family_policy, attrs, ARRAY_SIZE(family_policy))) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return -EPROTO;
    }

    retval = nl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
    if (retval == 0) {
        retval = -EPROTO;
    } else {
        define_genl_family(retval, name);
    }
    nl_sock_destroy(sock);
    ofpbuf_delete(reply);

    return retval;
}

/* If '*number' is 0, translates the given Generic Netlink family 'name' to a
 * number and stores it in '*number'.  If successful, returns 0 and the caller
 * may use '*number' as the family number.  On failure, returns a positive
 * errno value and '*number' caches the errno value. */
int
nl_lookup_genl_family(const char *name, int *number)
{
    if (*number == 0) {
        *number = do_lookup_genl_family(name);
        assert(*number != 0);
    }
    return *number > 0 ? 0 : -*number;
}

/* Netlink PID.
 *
 * Every Netlink socket must be bound to a unique 32-bit PID.  By convention,
 * programs that have a single Netlink socket use their Unix process ID as PID,
 * and programs with multiple Netlink sockets add a unique per-socket
 * identifier in the bits above the Unix process ID.
 *
 * The kernel has Netlink PID 0.
 */

/* Parameters for how many bits in the PID should come from the Unix process ID
 * and how many unique per-socket. */
#define SOCKET_BITS 10
#define MAX_SOCKETS (1u << SOCKET_BITS)

#define PROCESS_BITS (32 - SOCKET_BITS)
#define MAX_PROCESSES (1u << PROCESS_BITS)
#define PROCESS_MASK ((uint32_t) (MAX_PROCESSES - 1))

/* Bit vector of unused socket identifiers. */
static uint32_t avail_sockets[ROUND_UP(MAX_SOCKETS, 32)];

/* Allocates and returns a new Netlink PID. */
static int
alloc_pid(uint32_t *pid)
{
    int i;

    for (i = 0; i < MAX_SOCKETS; i++) {
        if ((avail_sockets[i / 32] & (1u << (i % 32))) == 0) {
            avail_sockets[i / 32] |= 1u << (i % 32);
            *pid = (getpid() & PROCESS_MASK) | (i << PROCESS_BITS);
            return 0;
        }
    }
    VLOG_ERR("netlink pid space exhausted");
    return ENOBUFS;
}

/* Makes the specified 'pid' available for reuse. */
static void
free_pid(uint32_t pid)
{
    int sock = pid >> PROCESS_BITS;
    assert(avail_sockets[sock / 32] & (1u << (sock % 32)));
    avail_sockets[sock / 32] &= ~(1u << (sock % 32));
}

static void
nlmsghdr_to_string(const struct nlmsghdr *h, int protocol, struct ds *ds)
{
    struct nlmsg_flag {
        unsigned int bits;
        const char *name;
    };
    static const struct nlmsg_flag flags[] = {
        { NLM_F_REQUEST, "REQUEST" },
        { NLM_F_MULTI, "MULTI" },
        { NLM_F_ACK, "ACK" },
        { NLM_F_ECHO, "ECHO" },
        { NLM_F_DUMP, "DUMP" },
        { NLM_F_ROOT, "ROOT" },
        { NLM_F_MATCH, "MATCH" },
        { NLM_F_ATOMIC, "ATOMIC" },
    };
    const struct nlmsg_flag *flag;
    uint16_t flags_left;

    ds_put_format(ds, "nl(len:%"PRIu32", type=%"PRIu16,
                  h->nlmsg_len, h->nlmsg_type);
    if (h->nlmsg_type == NLMSG_NOOP) {
        ds_put_cstr(ds, "(no-op)");
    } else if (h->nlmsg_type == NLMSG_ERROR) {
        ds_put_cstr(ds, "(error)");
    } else if (h->nlmsg_type == NLMSG_DONE) {
        ds_put_cstr(ds, "(done)");
    } else if (h->nlmsg_type == NLMSG_OVERRUN) {
        ds_put_cstr(ds, "(overrun)");
    } else if (h->nlmsg_type < NLMSG_MIN_TYPE) {
        ds_put_cstr(ds, "(reserved)");
    } else if (protocol == NETLINK_GENERIC) {
        ds_put_format(ds, "(%s)", genl_family_to_name(h->nlmsg_type));
    } else {
        ds_put_cstr(ds, "(family-defined)");
    }
    ds_put_format(ds, ", flags=%"PRIx16, h->nlmsg_flags);
    flags_left = h->nlmsg_flags;
    for (flag = flags; flag < &flags[ARRAY_SIZE(flags)]; flag++) {
        if ((flags_left & flag->bits) == flag->bits) {
            ds_put_format(ds, "[%s]", flag->name);
            flags_left &= ~flag->bits;
        }
    }
    if (flags_left) {
        ds_put_format(ds, "[OTHER:%"PRIx16"]", flags_left);
    }
    ds_put_format(ds, ", seq=%"PRIx32", pid=%"PRIu32"(%d:%d))",
                  h->nlmsg_seq, h->nlmsg_pid,
                  (int) (h->nlmsg_pid & PROCESS_MASK),
                  (int) (h->nlmsg_pid >> PROCESS_BITS));
}

static char *
nlmsg_to_string(const struct ofpbuf *buffer, int protocol)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct nlmsghdr *h = ofpbuf_at(buffer, 0, NLMSG_HDRLEN);
    if (h) {
        nlmsghdr_to_string(h, protocol, &ds);
        if (h->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *e;
            e = ofpbuf_at(buffer, NLMSG_HDRLEN,
                          NLMSG_ALIGN(sizeof(struct nlmsgerr)));
            if (e) {
                ds_put_format(&ds, " error(%d", e->error);
                if (e->error < 0) {
                    ds_put_format(&ds, "(%s)", strerror(-e->error));
                }
                ds_put_cstr(&ds, ", in-reply-to(");
                nlmsghdr_to_string(&e->msg, protocol, &ds);
                ds_put_cstr(&ds, "))");
            } else {
                ds_put_cstr(&ds, " error(truncated)");
            }
        } else if (h->nlmsg_type == NLMSG_DONE) {
            int *error = ofpbuf_at(buffer, NLMSG_HDRLEN, sizeof *error);
            if (error) {
                ds_put_format(&ds, " done(%d", *error);
                if (*error < 0) {
                    ds_put_format(&ds, "(%s)", strerror(-*error));
                }
                ds_put_cstr(&ds, ")");
            } else {
                ds_put_cstr(&ds, " done(truncated)");
            }
        } else if (protocol == NETLINK_GENERIC) {
            struct genlmsghdr *genl = nl_msg_genlmsghdr(buffer);
            if (genl) {
                ds_put_format(&ds, ",genl(cmd=%"PRIu8",version=%"PRIu8")",
                              genl->cmd, genl->version);
            }
        }
    } else {
        ds_put_cstr(&ds, "nl(truncated)");
    }
    return ds.string;
}

static void
log_nlmsg(const char *function, int error,
          const void *message, size_t size, int protocol)
{
    struct ofpbuf buffer;
    char *nlmsg;

    if (!VLOG_IS_DBG_ENABLED()) {
        return;
    }

    ofpbuf_use_const(&buffer, message, size);
    nlmsg = nlmsg_to_string(&buffer, protocol);
    VLOG_DBG_RL(&rl, "%s (%s): %s", function, strerror(error), nlmsg);
    free(nlmsg);
}


