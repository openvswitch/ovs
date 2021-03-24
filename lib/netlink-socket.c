/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netlink.h"
#include "netlink-protocol.h"
#include "netnsid.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netlink_socket);

COVERAGE_DEFINE(netlink_overflow);
COVERAGE_DEFINE(netlink_received);
COVERAGE_DEFINE(netlink_recv_jumbo);
COVERAGE_DEFINE(netlink_sent);

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* A single (bad) Netlink message can in theory dump out many, many log
 * messages, so the burst size is set quite high here to avoid missing useful
 * information.  Also, at high logging levels we log *all* Netlink messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 600);

static uint32_t nl_sock_allocate_seq(struct nl_sock *, unsigned int n);
static void log_nlmsg(const char *function, int error,
                      const void *message, size_t size, int protocol);
#ifdef _WIN32
static int get_sock_pid_from_kernel(struct nl_sock *sock);
static int set_sock_property(struct nl_sock *sock);
static int nl_sock_transact(struct nl_sock *sock, const struct ofpbuf *request,
                            struct ofpbuf **replyp);

/* In the case DeviceIoControl failed and GetLastError returns with
 * ERROR_NOT_FOUND means we lost communication with the kernel device.
 * CloseHandle will fail because the handle in 'theory' does not exist.
 * The only remaining option is to crash and allow the service to be restarted
 * via service manager.  This is the only way to close the handle from both
 * userspace and kernel. */
void
lost_communication(DWORD last_err)
{
    if (last_err == ERROR_NOT_FOUND) {
        ovs_abort(0, "lost communication with the kernel device");
    }
}
#endif

/* Netlink sockets. */

struct nl_sock {
#ifdef _WIN32
    HANDLE handle;
    OVERLAPPED overlapped;
    DWORD read_ioctl;
#else
    int fd;
#endif
    uint32_t next_seq;
    uint32_t pid;
    int protocol;
    unsigned int rcvbuf;        /* Receive buffer size (SO_RCVBUF). */
};

/* Compile-time limit on iovecs, so that we can allocate a maximum-size array
 * of iovecs on the stack. */
#define MAX_IOVS 128

/* Maximum number of iovecs that may be passed to sendmsg, capped at a
 * minimum of _XOPEN_IOV_MAX (16) and a maximum of MAX_IOVS.
 *
 * Initialized by nl_sock_create(). */
static int max_iovs;

static int nl_pool_alloc(int protocol, struct nl_sock **sockp);
static void nl_pool_release(struct nl_sock *);

/* Creates a new netlink socket for the given netlink 'protocol'
 * (NETLINK_ROUTE, NETLINK_GENERIC, ...).  Returns 0 and sets '*sockp' to the
 * new socket if successful, otherwise returns a positive errno value. */
int
nl_sock_create(int protocol, struct nl_sock **sockp)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct nl_sock *sock;
#ifndef _WIN32
    struct sockaddr_nl local, remote;
#endif
    socklen_t local_size;
    int rcvbuf;
    int retval = 0;

    if (ovsthread_once_start(&once)) {
        int save_errno = errno;
        errno = 0;

        max_iovs = sysconf(_SC_UIO_MAXIOV);
        if (max_iovs < _XOPEN_IOV_MAX) {
            if (max_iovs == -1 && errno) {
                VLOG_WARN("sysconf(_SC_UIO_MAXIOV): %s", ovs_strerror(errno));
            }
            max_iovs = _XOPEN_IOV_MAX;
        } else if (max_iovs > MAX_IOVS) {
            max_iovs = MAX_IOVS;
        }

        errno = save_errno;
        ovsthread_once_done(&once);
    }

    *sockp = NULL;
    sock = xmalloc(sizeof *sock);

#ifdef _WIN32
    sock->overlapped.hEvent = NULL;
    sock->handle = CreateFile(OVS_DEVICE_NAME_USER,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, NULL);

    if (sock->handle == INVALID_HANDLE_VALUE) {
        VLOG_ERR("fcntl: %s", ovs_lasterror_to_string());
        goto error;
    }

    memset(&sock->overlapped, 0, sizeof sock->overlapped);
    sock->overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (sock->overlapped.hEvent == NULL) {
        VLOG_ERR("fcntl: %s", ovs_lasterror_to_string());
        goto error;
    }
    /* Initialize the type/ioctl to Generic */
    sock->read_ioctl = OVS_IOCTL_READ;
#else
    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (sock->fd < 0) {
        VLOG_ERR("fcntl: %s", ovs_strerror(errno));
        goto error;
    }
#endif

    sock->protocol = protocol;
    sock->next_seq = 1;

    rcvbuf = 1024 * 1024 * 4;
#ifdef _WIN32
    sock->rcvbuf = rcvbuf;
    retval = get_sock_pid_from_kernel(sock);
    if (retval != 0) {
        goto error;
    }
    retval = set_sock_property(sock);
    if (retval != 0) {
        goto error;
    }
#else
    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof rcvbuf)) {
        /* Only root can use SO_RCVBUFFORCE.  Everyone else gets EPERM.
         * Warn only if the failure is therefore unexpected. */
        if (errno != EPERM) {
            VLOG_WARN_RL(&rl, "setting %d-byte socket receive buffer failed "
                         "(%s)", rcvbuf, ovs_strerror(errno));
        }
    }

    retval = get_socket_rcvbuf(sock->fd);
    if (retval < 0) {
        retval = -retval;
        goto error;
    }
    sock->rcvbuf = retval;
    retval = 0;

    /* Connect to kernel (pid 0) as remote address. */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
        VLOG_ERR("connect(0): %s", ovs_strerror(errno));
        goto error;
    }

    /* Obtain pid assigned by kernel. */
    local_size = sizeof local;
    if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
        VLOG_ERR("getsockname: %s", ovs_strerror(errno));
        goto error;
    }
    if (local_size < sizeof local || local.nl_family != AF_NETLINK) {
        VLOG_ERR("getsockname returned bad Netlink name");
        retval = EINVAL;
        goto error;
    }
    sock->pid = local.nl_pid;
#endif

    *sockp = sock;
    return 0;

error:
    if (retval == 0) {
        retval = errno;
        if (retval == 0) {
            retval = EINVAL;
        }
    }
#ifdef _WIN32
    if (sock->overlapped.hEvent) {
        CloseHandle(sock->overlapped.hEvent);
    }
    if (sock->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(sock->handle);
    }
#else
    if (sock->fd >= 0) {
        close(sock->fd);
    }
#endif
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
#ifdef _WIN32
        if (sock->overlapped.hEvent) {
            CloseHandle(sock->overlapped.hEvent);
        }
        CloseHandle(sock->handle);
#else
        close(sock->fd);
#endif
        free(sock);
    }
}

#ifdef _WIN32
/* Reads the pid for 'sock' generated in the kernel datapath. The function
 * uses a separate IOCTL instead of a transaction semantic to avoid unnecessary
 * message overhead. */
static int
get_sock_pid_from_kernel(struct nl_sock *sock)
{
    uint32_t pid = 0;
    int retval = 0;
    DWORD bytes = 0;

    if (!DeviceIoControl(sock->handle, OVS_IOCTL_GET_PID,
                         NULL, 0, &pid, sizeof(pid),
                         &bytes, NULL)) {
        lost_communication(GetLastError());
        retval = EINVAL;
    } else {
        if (bytes < sizeof(pid)) {
            retval = EINVAL;
        } else {
            sock->pid = pid;
        }
    }

    return retval;
}

/* Used for setting and managing socket properties in userspace and kernel.
 * Currently two attributes are tracked - pid and protocol
 * protocol - supplied by userspace based on the netlink family. Windows uses
 *            this property to set the value in kernel datapath.
 *            eg: (NETLINK_GENERIC/ NETLINK_NETFILTER)
 * pid -      generated by windows kernel and set in userspace. The property
 *            is not modified.
 * Also verify if Protocol and PID in Kernel reflects the values in userspace
 * */
static int
set_sock_property(struct nl_sock *sock)
{
    static const struct nl_policy ovs_socket_policy[] = {
        [OVS_NL_ATTR_SOCK_PROTO] = { .type = NL_A_BE32, .optional = true },
        [OVS_NL_ATTR_SOCK_PID] = { .type = NL_A_BE32, .optional = true }
    };

    struct ofpbuf request, *reply;
    struct ovs_header *ovs_header;
    struct nlattr *attrs[ARRAY_SIZE(ovs_socket_policy)];
    int retval = 0;
    int error;

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                          OVS_CTRL_CMD_SOCK_PROP, OVS_WIN_CONTROL_VERSION);
    ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    nl_msg_put_be32(&request, OVS_NL_ATTR_SOCK_PROTO, sock->protocol);
    /* pid is already set as part of get_sock_pid_from_kernel()
     * This is added to maintain consistency
     */
    nl_msg_put_be32(&request, OVS_NL_ATTR_SOCK_PID, sock->pid);

    error = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (error) {
        retval = EINVAL;
    }

    if (!nl_policy_parse(reply,
                         NLMSG_HDRLEN + GENL_HDRLEN + sizeof *ovs_header,
                         ovs_socket_policy, attrs,
                         ARRAY_SIZE(ovs_socket_policy))) {
        ofpbuf_delete(reply);
        retval = EINVAL;
    }
    /* Verify if the properties are setup properly */
    if (attrs[OVS_NL_ATTR_SOCK_PROTO]) {
        int protocol = nl_attr_get_be32(attrs[OVS_NL_ATTR_SOCK_PROTO]);
        if (protocol != sock->protocol) {
            VLOG_ERR("Invalid protocol returned:%d expected:%d",
                     protocol, sock->protocol);
            retval = EINVAL;
        }
    }

    if (attrs[OVS_NL_ATTR_SOCK_PID]) {
        int pid = nl_attr_get_be32(attrs[OVS_NL_ATTR_SOCK_PID]);
        if (pid != sock->pid) {
            VLOG_ERR("Invalid pid returned:%d expected:%d",
                     pid, sock->pid);
            retval = EINVAL;
        }
    }

    return retval;
}
#endif  /* _WIN32 */

#ifdef _WIN32
static int __inline
nl_sock_mcgroup(struct nl_sock *sock, unsigned int multicast_group, bool join)
{
    struct ofpbuf request;
    uint64_t request_stub[128];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    int error;

    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                          OVS_CTRL_CMD_MC_SUBSCRIBE_REQ,
                          OVS_WIN_CONTROL_VERSION);

    ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;

    nl_msg_put_u32(&request, OVS_NL_ATTR_MCAST_GRP, multicast_group);
    nl_msg_put_u8(&request, OVS_NL_ATTR_MCAST_JOIN, join ? 1 : 0);

    error = nl_sock_send(sock, &request, true);
    ofpbuf_uninit(&request);
    return error;
}
#endif
/* Tries to add 'sock' as a listener for 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * A socket that is subscribed to a multicast group that receives asynchronous
 * notifications must not be used for Netlink transactions or dumps, because
 * transactions and dumps can cause notifications to be lost.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to join a multicast group to which a socket
 * already belongs. */
int
nl_sock_join_mcgroup(struct nl_sock *sock, unsigned int multicast_group)
{
#ifdef _WIN32
    /* Set the socket type as a "multicast" socket */
    sock->read_ioctl = OVS_IOCTL_READ_EVENT;
    int error = nl_sock_mcgroup(sock, multicast_group, true);
    if (error) {
        sock->read_ioctl = OVS_IOCTL_READ;
        VLOG_WARN("could not join multicast group %u (%s)",
                  multicast_group, ovs_strerror(error));
        return error;
    }
#else
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        VLOG_WARN("could not join multicast group %u (%s)",
                  multicast_group, ovs_strerror(errno));
        return errno;
    }
#endif
    return 0;
}

/* When 'enable' is true, it tries to enable 'sock' to receive netlink
 * notifications form all network namespaces that have an nsid assigned
 * into the network namespace where the socket has been opened. The
 * running kernel needs to provide support for that. When 'enable' is
 * false, it will receive netlink notifications only from the network
 * namespace where the socket has been opened.
 *
 * Returns 0 if successful, otherwise a positive errno.  */
int
nl_sock_listen_all_nsid(struct nl_sock *sock, bool enable)
{
    int error;
    int val = enable ? 1 : 0;

#ifndef _WIN32
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &val,
                   sizeof val) < 0) {
        error = errno;
        VLOG_INFO("netlink: could not %s listening to all nsid (%s)",
                  enable ? "enable" : "disable", ovs_strerror(error));
        return errno;
    }
#endif

    return 0;
}

#ifdef _WIN32
int
nl_sock_subscribe_packet__(struct nl_sock *sock, bool subscribe)
{
    struct ofpbuf request;
    uint64_t request_stub[128];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    int error;

    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);
    nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                          OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ,
                          OVS_WIN_CONTROL_VERSION);

    ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;
    nl_msg_put_u8(&request, OVS_NL_ATTR_PACKET_SUBSCRIBE, subscribe ? 1 : 0);
    nl_msg_put_u32(&request, OVS_NL_ATTR_PACKET_PID, sock->pid);

    error = nl_sock_send(sock, &request, true);
    ofpbuf_uninit(&request);
    return error;
}

int
nl_sock_subscribe_packets(struct nl_sock *sock)
{
    int error;

    if (sock->read_ioctl != OVS_IOCTL_READ) {
        return EINVAL;
    }

    error = nl_sock_subscribe_packet__(sock, true);
    if (error) {
        VLOG_WARN("could not subscribe packets (%s)",
                  ovs_strerror(error));
        return error;
    }
    sock->read_ioctl = OVS_IOCTL_READ_PACKET;

    return 0;
}

int
nl_sock_unsubscribe_packets(struct nl_sock *sock)
{
    ovs_assert(sock->read_ioctl == OVS_IOCTL_READ_PACKET);

    int error = nl_sock_subscribe_packet__(sock, false);
    if (error) {
        VLOG_WARN("could not unsubscribe to packets (%s)",
                  ovs_strerror(error));
        return error;
    }

    sock->read_ioctl = OVS_IOCTL_READ;
    return 0;
}
#endif

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
#ifdef _WIN32
    int error = nl_sock_mcgroup(sock, multicast_group, false);
    if (error) {
        VLOG_WARN("could not leave multicast group %u (%s)",
                   multicast_group, ovs_strerror(error));
        return error;
    }
    sock->read_ioctl = OVS_IOCTL_READ;
#else
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        VLOG_WARN("could not leave multicast group %u (%s)",
                  multicast_group, ovs_strerror(errno));
        return errno;
    }
#endif
    return 0;
}

static int
nl_sock_send__(struct nl_sock *sock, const struct ofpbuf *msg,
               uint32_t nlmsg_seq, bool wait)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(msg);
    int error;

    nlmsg->nlmsg_len = msg->size;
    nlmsg->nlmsg_seq = nlmsg_seq;
    nlmsg->nlmsg_pid = sock->pid;
    do {
        int retval;
#ifdef _WIN32
        DWORD bytes;

        if (!DeviceIoControl(sock->handle, OVS_IOCTL_WRITE,
                             msg->data, msg->size, NULL, 0,
                             &bytes, NULL)) {
            lost_communication(GetLastError());
            retval = -1;
            /* XXX: Map to a more appropriate error based on GetLastError(). */
            errno = EINVAL;
            VLOG_DBG_RL(&rl, "fatal driver failure in write: %s",
                        ovs_lasterror_to_string());
        } else {
            retval = msg->size;
        }
#else
        retval = send(sock->fd, msg->data, msg->size,
                      wait ? 0 : MSG_DONTWAIT);
#endif
        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
    log_nlmsg(__func__, error, msg->data, msg->size, sock->protocol);
    if (!error) {
        COVERAGE_INC(netlink_sent);
    }
    return error;
}

/* Tries to send 'msg', which must contain a Netlink message, to the kernel on
 * 'sock'.  nlmsg_len in 'msg' will be finalized to match msg->size, nlmsg_pid
 * will be set to 'sock''s pid, and nlmsg_seq will be initialized to a fresh
 * sequence number, before the message is sent.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full. */
int
nl_sock_send(struct nl_sock *sock, const struct ofpbuf *msg, bool wait)
{
    return nl_sock_send_seq(sock, msg, nl_sock_allocate_seq(sock, 1), wait);
}

/* Tries to send 'msg', which must contain a Netlink message, to the kernel on
 * 'sock'.  nlmsg_len in 'msg' will be finalized to match msg->size, nlmsg_pid
 * will be set to 'sock''s pid, and nlmsg_seq will be initialized to
 * 'nlmsg_seq', before the message is sent.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full.
 *
 * This function is suitable for sending a reply to a request that was received
 * with sequence number 'nlmsg_seq'.  Otherwise, use nl_sock_send() instead. */
int
nl_sock_send_seq(struct nl_sock *sock, const struct ofpbuf *msg,
                 uint32_t nlmsg_seq, bool wait)
{
    return nl_sock_send__(sock, msg, nlmsg_seq, wait);
}

static int
nl_sock_recv__(struct nl_sock *sock, struct ofpbuf *buf, int *nsid, bool wait)
{
    /* We can't accurately predict the size of the data to be received.  The
     * caller is supposed to have allocated enough space in 'buf' to handle the
     * "typical" case.  To handle exceptions, we make available enough space in
     * 'tail' to allow Netlink messages to be up to 64 kB long (a reasonable
     * figure since that's the maximum length of a Netlink attribute). */
    struct nlmsghdr *nlmsghdr;
    uint8_t tail[65536];
    struct iovec iov[2];
    struct msghdr msg;
    uint8_t msgctrl[64];
    struct cmsghdr *cmsg;
    ssize_t retval;
    int *ptr;
    int error;

    ovs_assert(buf->allocated >= sizeof *nlmsghdr);
    ofpbuf_clear(buf);

    iov[0].iov_base = buf->base;
    iov[0].iov_len = buf->allocated;
    iov[1].iov_base = tail;
    iov[1].iov_len = sizeof tail;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = msgctrl;
    msg.msg_controllen = sizeof msgctrl;

    /* Receive a Netlink message from the kernel.
     *
     * This works around a kernel bug in which the kernel returns an error code
     * as if it were the number of bytes read.  It doesn't actually modify
     * anything in the receive buffer in that case, so we can initialize the
     * Netlink header with an impossible message length and then, upon success,
     * check whether it changed. */
    nlmsghdr = buf->base;
    do {
        nlmsghdr->nlmsg_len = UINT32_MAX;
#ifdef _WIN32
        DWORD bytes;
        if (!DeviceIoControl(sock->handle, sock->read_ioctl,
                             NULL, 0, tail, sizeof tail, &bytes, NULL)) {
            lost_communication(GetLastError());
            VLOG_DBG_RL(&rl, "fatal driver failure in transact: %s",
                        ovs_lasterror_to_string());
            retval = -1;
            /* XXX: Map to a more appropriate error. */
            errno = EINVAL;
        } else {
            retval = bytes;
            if (retval == 0) {
                retval = -1;
                errno = EAGAIN;
            } else {
                if (retval >= buf->allocated) {
                    ofpbuf_reinit(buf, retval);
                    nlmsghdr = buf->base;
                    nlmsghdr->nlmsg_len = UINT32_MAX;
                }
                memcpy(buf->data, tail, retval);
                buf->size = retval;
            }
        }
#else
        retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);
#endif
        error = (retval < 0 ? errno
                 : retval == 0 ? ECONNRESET /* not possible? */
                 : nlmsghdr->nlmsg_len != UINT32_MAX ? 0
                 : retval);
    } while (error == EINTR);
    if (error) {
        if (error == ENOBUFS) {
            /* Socket receive buffer overflow dropped one or more messages that
             * the kernel tried to send to us. */
            COVERAGE_INC(netlink_overflow);
        }
        return error;
    }

    if (msg.msg_flags & MSG_TRUNC) {
        VLOG_ERR_RL(&rl, "truncated message (longer than %"PRIuSIZE" bytes)",
                    sizeof tail);
        return E2BIG;
    }

    if (retval < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len > retval) {
        VLOG_ERR_RL(&rl, "received invalid nlmsg (%"PRIuSIZE" bytes < %"PRIuSIZE")",
                    retval, sizeof *nlmsghdr);
        return EPROTO;
    }
#ifndef _WIN32
    buf->size = MIN(retval, buf->allocated);
    if (retval > buf->allocated) {
        COVERAGE_INC(netlink_recv_jumbo);
        ofpbuf_put(buf, tail, retval - buf->allocated);
    }
#endif

    if (nsid) {
        /* The network namespace id from which the message was sent comes
         * as ancillary data. For older kernels, this data is either not
         * available or it might be -1, so it falls back to local network
         * namespace (no id). Latest kernels return a valid ID only if
         * available or nothing. */
        netnsid_set_local(nsid);
#ifndef _WIN32
        cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != NULL) {
            if (cmsg->cmsg_level == SOL_NETLINK
                && cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID) {
                ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
                netnsid_set(nsid, *ptr);
            }
            if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS) {
                /* This is unexpected and unwanted, close all fds */
                int nfds;
                int i;
                nfds = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)))
                       / sizeof(int);
                ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
                for (i = 0; i < nfds; i++) {
                    VLOG_ERR_RL(&rl, "closing unexpected received fd (%d).",
                                ptr[i]);
                    close(ptr[i]);
                }
            }

            cmsg = CMSG_NXTHDR(&msg, cmsg);
        }
#endif
    }

    log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
    COVERAGE_INC(netlink_received);

    return 0;
}

/* Tries to receive a Netlink message from the kernel on 'sock' into 'buf'.  If
 * 'wait' is true, waits for a message to be ready.  Otherwise, fails with
 * EAGAIN if the 'sock' receive buffer is empty.  If 'nsid' is provided, the
 * network namespace id from which the message was sent will be provided.
 *
 * The caller must have initialized 'buf' with an allocation of at least
 * NLMSG_HDRLEN bytes.  For best performance, the caller should allocate enough
 * space for a "typical" message.
 *
 * On success, returns 0 and replaces 'buf''s previous content by the received
 * message.  This function expands 'buf''s allocated memory, as necessary, to
 * hold the actual size of the received message.
 *
 * On failure, returns a positive errno value and clears 'buf' to zero length.
 * 'buf' retains its previous memory allocation.
 *
 * Regardless of success or failure, this function resets 'buf''s headroom to
 * 0. */
int
nl_sock_recv(struct nl_sock *sock, struct ofpbuf *buf, int *nsid, bool wait)
{
    return nl_sock_recv__(sock, buf, nsid, wait);
}

static void
nl_sock_record_errors__(struct nl_transaction **transactions, size_t n,
                        int error)
{
    size_t i;

    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        txn->error = error;
        if (txn->reply) {
            ofpbuf_clear(txn->reply);
        }
    }
}

static int
nl_sock_transact_multiple__(struct nl_sock *sock,
                            struct nl_transaction **transactions, size_t n,
                            size_t *done)
{
    uint64_t tmp_reply_stub[1024 / 8];
    struct nl_transaction tmp_txn;
    struct ofpbuf tmp_reply;

    uint32_t base_seq;
    struct iovec iovs[MAX_IOVS];
    struct msghdr msg;
    int error;
    int i;

    base_seq = nl_sock_allocate_seq(sock, n);
    *done = 0;
    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(txn->request);

        nlmsg->nlmsg_len = txn->request->size;
        nlmsg->nlmsg_seq = base_seq + i;
        nlmsg->nlmsg_pid = sock->pid;

        iovs[i].iov_base = txn->request->data;
        iovs[i].iov_len = txn->request->size;
    }

#ifndef _WIN32
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iovs;
    msg.msg_iovlen = n;
    do {
        error = sendmsg(sock->fd, &msg, 0) < 0 ? errno : 0;
    } while (error == EINTR);

    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        log_nlmsg(__func__, error, txn->request->data,
                  txn->request->size, sock->protocol);
    }
    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }

    if (error) {
        return error;
    }

    ofpbuf_use_stub(&tmp_reply, tmp_reply_stub, sizeof tmp_reply_stub);
    tmp_txn.request = NULL;
    tmp_txn.reply = &tmp_reply;
    tmp_txn.error = 0;
    while (n > 0) {
        struct nl_transaction *buf_txn, *txn;
        uint32_t seq;

        /* Find a transaction whose buffer we can use for receiving a reply.
         * If no such transaction is left, use tmp_txn. */
        buf_txn = &tmp_txn;
        for (i = 0; i < n; i++) {
            if (transactions[i]->reply) {
                buf_txn = transactions[i];
                break;
            }
        }

        /* Receive a reply. */
        error = nl_sock_recv__(sock, buf_txn->reply, NULL, false);
        if (error) {
            if (error == EAGAIN) {
                nl_sock_record_errors__(transactions, n, 0);
                *done += n;
                error = 0;
            }
            break;
        }

        /* Match the reply up with a transaction. */
        seq = nl_msg_nlmsghdr(buf_txn->reply)->nlmsg_seq;
        if (seq < base_seq || seq >= base_seq + n) {
            VLOG_DBG_RL(&rl, "ignoring unexpected seq %#"PRIx32, seq);
            continue;
        }
        i = seq - base_seq;
        txn = transactions[i];

        /* Fill in the results for 'txn'. */
        if (nl_msg_nlmsgerr(buf_txn->reply, &txn->error)) {
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
            if (txn->error) {
                VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                            error, ovs_strerror(txn->error));
            }
        } else {
            txn->error = 0;
            if (txn->reply && txn != buf_txn) {
                /* Swap buffers. */
                struct ofpbuf *reply = buf_txn->reply;
                buf_txn->reply = txn->reply;
                txn->reply = reply;
            }
        }

        /* Fill in the results for transactions before 'txn'.  (We have to do
         * this after the results for 'txn' itself because of the buffer swap
         * above.) */
        nl_sock_record_errors__(transactions, i, 0);

        /* Advance. */
        *done += i + 1;
        transactions += i + 1;
        n -= i + 1;
        base_seq += i + 1;
    }
    ofpbuf_uninit(&tmp_reply);
#else
    error = 0;
    uint8_t reply_buf[65536];
    for (i = 0; i < n; i++) {
        DWORD reply_len;
        bool ret;
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *request_nlmsg, *reply_nlmsg;

        ret = DeviceIoControl(sock->handle, OVS_IOCTL_TRANSACT,
                              txn->request->data,
                              txn->request->size,
                              reply_buf, sizeof reply_buf,
                              &reply_len, NULL);

        if (ret && reply_len == 0) {
            /*
             * The current transaction did not produce any data to read and that
             * is not an error as such. Continue with the remainder of the
             * transactions.
             */
            txn->error = 0;
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
        } else if (!ret) {
            /* XXX: Map to a more appropriate error. */
            lost_communication(GetLastError());
            error = EINVAL;
            VLOG_DBG_RL(&rl, "fatal driver failure: %s",
                ovs_lasterror_to_string());
            break;
        }

        if (reply_len != 0) {
            request_nlmsg = nl_msg_nlmsghdr(txn->request);

            if (reply_len < sizeof *reply_nlmsg) {
                nl_sock_record_errors__(transactions, n, 0);
                VLOG_DBG_RL(&rl, "insufficient length of reply %#"PRIu32
                    " for seq: %#"PRIx32, reply_len, request_nlmsg->nlmsg_seq);
                break;
            }

            /* Validate the sequence number in the reply. */
            reply_nlmsg = (struct nlmsghdr *)reply_buf;

            if (request_nlmsg->nlmsg_seq != reply_nlmsg->nlmsg_seq) {
                ovs_assert(request_nlmsg->nlmsg_seq == reply_nlmsg->nlmsg_seq);
                VLOG_DBG_RL(&rl, "mismatched seq request %#"PRIx32
                    ", reply %#"PRIx32, request_nlmsg->nlmsg_seq,
                    reply_nlmsg->nlmsg_seq);
                break;
            }

            /* Handle errors embedded within the netlink message. */
            ofpbuf_use_stub(&tmp_reply, reply_buf, sizeof reply_buf);
            tmp_reply.size = sizeof reply_buf;
            if (nl_msg_nlmsgerr(&tmp_reply, &txn->error)) {
                if (txn->reply) {
                    ofpbuf_clear(txn->reply);
                }
                if (txn->error) {
                    VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                                error, ovs_strerror(txn->error));
                }
            } else {
                txn->error = 0;
                if (txn->reply) {
                    /* Copy the reply to the buffer specified by the caller. */
                    if (reply_len > txn->reply->allocated) {
                        ofpbuf_reinit(txn->reply, reply_len);
                    }
                    memcpy(txn->reply->data, reply_buf, reply_len);
                    txn->reply->size = reply_len;
                }
            }
            ofpbuf_uninit(&tmp_reply);
        }

        /* Count the number of successful transactions. */
        (*done)++;

    }

    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }
#endif

    return error;
}

static void
nl_sock_transact_multiple(struct nl_sock *sock,
                          struct nl_transaction **transactions, size_t n)
{
    int max_batch_count;
    int error;

    if (!n) {
        return;
    }

    /* In theory, every request could have a 64 kB reply.  But the default and
     * maximum socket rcvbuf size with typical Dom0 memory sizes both tend to
     * be a bit below 128 kB, so that would only allow a single message in a
     * "batch".  So we assume that replies average (at most) 4 kB, which allows
     * a good deal of batching.
     *
     * In practice, most of the requests that we batch either have no reply at
     * all or a brief reply. */
    max_batch_count = MAX(sock->rcvbuf / 4096, 1);
    max_batch_count = MIN(max_batch_count, max_iovs);

    while (n > 0) {
        size_t count, bytes;
        size_t done;

        /* Batch up to 'max_batch_count' transactions.  But cap it at about a
         * page of requests total because big skbuffs are expensive to
         * allocate in the kernel.  */
#if defined(PAGESIZE)
        enum { MAX_BATCH_BYTES = MAX(1, PAGESIZE - 512) };
#else
        enum { MAX_BATCH_BYTES = 4096 - 512 };
#endif
        bytes = transactions[0]->request->size;
        for (count = 1; count < n && count < max_batch_count; count++) {
            if (bytes + transactions[count]->request->size > MAX_BATCH_BYTES) {
                break;
            }
            bytes += transactions[count]->request->size;
        }

        error = nl_sock_transact_multiple__(sock, transactions, count, &done);
        transactions += done;
        n -= done;

        if (error == ENOBUFS) {
            VLOG_DBG_RL(&rl, "receive buffer overflow, resending request");
        } else if (error) {
            VLOG_ERR_RL(&rl, "transaction error (%s)", ovs_strerror(error));
            nl_sock_record_errors__(transactions, n, error);
            if (error != EAGAIN) {
                /* A fatal error has occurred.  Abort the rest of
                 * transactions. */
                break;
            }
        }
    }
}

static int
nl_sock_transact(struct nl_sock *sock, const struct ofpbuf *request,
                 struct ofpbuf **replyp)
{
    struct nl_transaction *transactionp;
    struct nl_transaction transaction;

    transaction.request = CONST_CAST(struct ofpbuf *, request);
    transaction.reply = replyp ? ofpbuf_new(1024) : NULL;
    transactionp = &transaction;

    nl_sock_transact_multiple(sock, &transactionp, 1);

    if (replyp) {
        if (transaction.error) {
            ofpbuf_delete(transaction.reply);
            *replyp = NULL;
        } else {
            *replyp = transaction.reply;
        }
    }

    return transaction.error;
}

/* Drain all the messages currently in 'sock''s receive queue. */
int
nl_sock_drain(struct nl_sock *sock)
{
#ifdef _WIN32
    return 0;
#else
    return drain_rcvbuf(sock->fd);
#endif
}

/* Starts a Netlink "dump" operation, by sending 'request' to the kernel on a
 * Netlink socket created with the given 'protocol', and initializes 'dump' to
 * reflect the state of the operation.
 *
 * 'request' must contain a Netlink message.  Before sending the message,
 * nlmsg_len will be finalized to match request->size, and nlmsg_pid will be
 * set to the Netlink socket's pid.  NLM_F_DUMP and NLM_F_ACK will be set in
 * nlmsg_flags.
 *
 * The design of this Netlink socket library ensures that the dump is reliable.
 *
 * This function provides no status indication.  nl_dump_done() provides an
 * error status for the entire dump operation.
 *
 * The caller must eventually destroy 'request'.
 */
void
nl_dump_start(struct nl_dump *dump, int protocol, const struct ofpbuf *request)
{
    nl_msg_nlmsghdr(request)->nlmsg_flags |= NLM_F_DUMP | NLM_F_ACK;

    ovs_mutex_init(&dump->mutex);
    ovs_mutex_lock(&dump->mutex);
    dump->status = nl_pool_alloc(protocol, &dump->sock);
    if (!dump->status) {
        dump->status = nl_sock_send__(dump->sock, request,
                                      nl_sock_allocate_seq(dump->sock, 1),
                                      true);
    }
    dump->nl_seq = nl_msg_nlmsghdr(request)->nlmsg_seq;
    ovs_mutex_unlock(&dump->mutex);
}

static int
nl_dump_refill(struct nl_dump *dump, struct ofpbuf *buffer)
    OVS_REQUIRES(dump->mutex)
{
    struct nlmsghdr *nlmsghdr;
    int error;

    while (!buffer->size) {
        error = nl_sock_recv__(dump->sock, buffer, NULL, false);
        if (error) {
            /* The kernel never blocks providing the results of a dump, so
             * error == EAGAIN means that we've read the whole thing, and
             * therefore transform it into EOF.  (The kernel always provides
             * NLMSG_DONE as a sentinel.  Some other thread must have received
             * that already but not yet signaled it in 'status'.)
             *
             * Any other error is just an error. */
            return error == EAGAIN ? EOF : error;
        }

        nlmsghdr = nl_msg_nlmsghdr(buffer);
        if (dump->nl_seq != nlmsghdr->nlmsg_seq) {
            VLOG_DBG_RL(&rl, "ignoring seq %#"PRIx32" != expected %#"PRIx32,
                        nlmsghdr->nlmsg_seq, dump->nl_seq);
            ofpbuf_clear(buffer);
        }
    }

    if (nl_msg_nlmsgerr(buffer, &error) && error) {
        VLOG_INFO_RL(&rl, "netlink dump request error (%s)",
                     ovs_strerror(error));
        ofpbuf_clear(buffer);
        return error;
    }

    return 0;
}

static int
nl_dump_next__(struct ofpbuf *reply, struct ofpbuf *buffer)
{
    struct nlmsghdr *nlmsghdr = nl_msg_next(buffer, reply);
    if (!nlmsghdr) {
        VLOG_WARN_RL(&rl, "netlink dump contains message fragment");
        return EPROTO;
    } else if (nlmsghdr->nlmsg_type == NLMSG_DONE) {
        return EOF;
    } else {
        return 0;
    }
}

/* Attempts to retrieve another reply from 'dump' into 'buffer'. 'dump' must
 * have been initialized with nl_dump_start(), and 'buffer' must have been
 * initialized. 'buffer' should be at least NL_DUMP_BUFSIZE bytes long.
 *
 * If successful, returns true and points 'reply->data' and
 * 'reply->size' to the message that was retrieved. The caller must not
 * modify 'reply' (because it points within 'buffer', which will be used by
 * future calls to this function).
 *
 * On failure, returns false and sets 'reply->data' to NULL and
 * 'reply->size' to 0.  Failure might indicate an actual error or merely
 * the end of replies.  An error status for the entire dump operation is
 * provided when it is completed by calling nl_dump_done().
 *
 * Multiple threads may call this function, passing the same nl_dump, however
 * each must provide independent buffers. This function may cache multiple
 * replies in the buffer, and these will be processed before more replies are
 * fetched. When this function returns false, other threads may continue to
 * process replies in their buffers, but they will not fetch more replies.
 */
bool
nl_dump_next(struct nl_dump *dump, struct ofpbuf *reply, struct ofpbuf *buffer)
{
    int retval = 0;

    /* If the buffer is empty, refill it.
     *
     * If the buffer is not empty, we don't check the dump's status.
     * Otherwise, we could end up skipping some of the dump results if thread A
     * hits EOF while thread B is in the midst of processing a batch. */
    if (!buffer->size) {
        ovs_mutex_lock(&dump->mutex);
        if (!dump->status) {
            /* Take the mutex here to avoid an in-kernel race.  If two threads
             * try to read from a Netlink dump socket at once, then the socket
             * error can be set to EINVAL, which will be encountered on the
             * next recv on that socket, which could be anywhere due to the way
             * that we pool Netlink sockets.  Serializing the recv calls avoids
             * the issue. */
            dump->status = nl_dump_refill(dump, buffer);
        }
        retval = dump->status;
        ovs_mutex_unlock(&dump->mutex);
    }

    /* Fetch the next message from the buffer. */
    if (!retval) {
        retval = nl_dump_next__(reply, buffer);
        if (retval) {
            /* Record 'retval' as the dump status, but don't overwrite an error
             * with EOF.  */
            ovs_mutex_lock(&dump->mutex);
            if (dump->status <= 0) {
                dump->status = retval;
            }
            ovs_mutex_unlock(&dump->mutex);
        }
    }

    if (retval) {
        reply->data = NULL;
        reply->size = 0;
    }
    return !retval;
}

/* Completes Netlink dump operation 'dump', which must have been initialized
 * with nl_dump_start().  Returns 0 if the dump operation was error-free,
 * otherwise a positive errno value describing the problem. */
int
nl_dump_done(struct nl_dump *dump)
{
    int status;

    ovs_mutex_lock(&dump->mutex);
    status = dump->status;
    ovs_mutex_unlock(&dump->mutex);

    /* Drain any remaining messages that the client didn't read.  Otherwise the
     * kernel will continue to queue them up and waste buffer space.
     *
     * XXX We could just destroy and discard the socket in this case. */
    if (!status) {
        uint64_t tmp_reply_stub[NL_DUMP_BUFSIZE / 8];
        struct ofpbuf reply, buf;

        ofpbuf_use_stub(&buf, tmp_reply_stub, sizeof tmp_reply_stub);
        while (nl_dump_next(dump, &reply, &buf)) {
            /* Nothing to do. */
        }
        ofpbuf_uninit(&buf);

        ovs_mutex_lock(&dump->mutex);
        status = dump->status;
        ovs_mutex_unlock(&dump->mutex);
        ovs_assert(status);
    }

    nl_pool_release(dump->sock);
    ovs_mutex_destroy(&dump->mutex);

    return status == EOF ? 0 : status;
}

#ifdef _WIN32
/* Pend an I/O request in the driver. The driver completes the I/O whenever
 * an event or a packet is ready to be read. Once the I/O is completed
 * the overlapped structure event associated with the pending I/O will be set
 */
static int
pend_io_request(struct nl_sock *sock)
{
    struct ofpbuf request;
    uint64_t request_stub[128];
    struct ovs_header *ovs_header;
    struct nlmsghdr *nlmsg;
    uint32_t seq;
    int retval = 0;
    int error;
    DWORD bytes;
    OVERLAPPED *overlapped = CONST_CAST(OVERLAPPED *, &sock->overlapped);
    uint16_t cmd = OVS_CTRL_CMD_WIN_PEND_PACKET_REQ;

    ovs_assert(sock->read_ioctl == OVS_IOCTL_READ_PACKET ||
               sock->read_ioctl  == OVS_IOCTL_READ_EVENT);
    if (sock->read_ioctl == OVS_IOCTL_READ_EVENT) {
        cmd = OVS_CTRL_CMD_WIN_PEND_REQ;
    }

    int ovs_msg_size = sizeof (struct nlmsghdr) + sizeof (struct genlmsghdr) +
                               sizeof (struct ovs_header);

    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    seq = nl_sock_allocate_seq(sock, 1);
    nl_msg_put_genlmsghdr(&request, 0, OVS_WIN_NL_CTRL_FAMILY_ID, 0,
                          cmd, OVS_WIN_CONTROL_VERSION);
    nlmsg = nl_msg_nlmsghdr(&request);
    nlmsg->nlmsg_seq = seq;
    nlmsg->nlmsg_pid = sock->pid;

    ovs_header = ofpbuf_put_uninit(&request, sizeof *ovs_header);
    ovs_header->dp_ifindex = 0;
    nlmsg->nlmsg_len = request.size;

    if (!DeviceIoControl(sock->handle, OVS_IOCTL_WRITE,
                         request.data, request.size,
                         NULL, 0, &bytes, overlapped)) {
        error = GetLastError();
        /* Check if the I/O got pended */
        if (error != ERROR_IO_INCOMPLETE && error != ERROR_IO_PENDING) {
            lost_communication(error);
            VLOG_ERR("nl_sock_wait failed - %s\n", ovs_format_message(error));
            retval = EINVAL;
        }
    } else {
        retval = EAGAIN;
    }

done:
    ofpbuf_uninit(&request);
    return retval;
}
#endif  /* _WIN32 */

/* Causes poll_block() to wake up when any of the specified 'events' (which is
 * a OR'd combination of POLLIN, POLLOUT, etc.) occur on 'sock'.
 * On Windows, 'sock' is not treated as const, and may be modified. */
void
nl_sock_wait(const struct nl_sock *sock, short int events)
{
#ifdef _WIN32
    if (sock->overlapped.Internal != STATUS_PENDING) {
        int ret = pend_io_request(CONST_CAST(struct nl_sock *, sock));
        if (ret == 0) {
            poll_wevent_wait(sock->overlapped.hEvent);
        } else {
            poll_immediate_wake();
        }
    } else {
        poll_wevent_wait(sock->overlapped.hEvent);
    }
#else
    poll_fd_wait(sock->fd, events);
#endif
}

#ifndef _WIN32
/* Returns the underlying fd for 'sock', for use in "poll()"-like operations
 * that can't use nl_sock_wait().
 *
 * It's a little tricky to use the returned fd correctly, because nl_sock does
 * "copy on write" to allow a single nl_sock to be used for notifications,
 * transactions, and dumps.  If 'sock' is used only for notifications and
 * transactions (and never for dump) then the usage is safe. */
int
nl_sock_fd(const struct nl_sock *sock)
{
    return sock->fd;
}
#endif

/* Returns the PID associated with this socket. */
uint32_t
nl_sock_pid(const struct nl_sock *sock)
{
    return sock->pid;
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
    [CTRL_ATTR_MCAST_GROUPS] = {.type = NL_A_NESTED, .optional = true},
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

#ifndef _WIN32
static int
do_lookup_genl_family(const char *name, struct nlattr **attrs,
                      struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    int error;

    *replyp = NULL;
    error = nl_sock_create(NETLINK_GENERIC, &sock);
    if (error) {
        return error;
    }

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, GENL_ID_CTRL, NLM_F_REQUEST,
                          CTRL_CMD_GETFAMILY, 1);
    nl_msg_put_string(&request, CTRL_ATTR_FAMILY_NAME, name);
    error = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (error) {
        nl_sock_destroy(sock);
        return error;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         family_policy, attrs, ARRAY_SIZE(family_policy))
        || nl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]) == 0) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return EPROTO;
    }

    nl_sock_destroy(sock);
    *replyp = reply;
    return 0;
}
#else
static int
do_lookup_genl_family(const char *name, struct nlattr **attrs,
                      struct ofpbuf **replyp)
{
    struct nlmsghdr *nlmsg;
    struct ofpbuf *reply;
    int error;
    uint16_t family_id;
    const char *family_name;
    uint32_t family_version;
    uint32_t family_attrmax;
    uint32_t mcgrp_id = OVS_WIN_NL_INVALID_MCGRP_ID;
    const char *mcgrp_name = NULL;

    *replyp = NULL;
    reply = ofpbuf_new(1024);

    /* CTRL_ATTR_MCAST_GROUPS is supported only for VPORT family. */
    if (!strcmp(name, OVS_WIN_CONTROL_FAMILY)) {
        family_id = OVS_WIN_NL_CTRL_FAMILY_ID;
        family_name = OVS_WIN_CONTROL_FAMILY;
        family_version = OVS_WIN_CONTROL_VERSION;
        family_attrmax = OVS_WIN_CONTROL_ATTR_MAX;
    } else if (!strcmp(name, OVS_DATAPATH_FAMILY)) {
        family_id = OVS_WIN_NL_DATAPATH_FAMILY_ID;
        family_name = OVS_DATAPATH_FAMILY;
        family_version = OVS_DATAPATH_VERSION;
        family_attrmax = OVS_DP_ATTR_MAX;
    } else if (!strcmp(name, OVS_PACKET_FAMILY)) {
        family_id = OVS_WIN_NL_PACKET_FAMILY_ID;
        family_name = OVS_PACKET_FAMILY;
        family_version = OVS_PACKET_VERSION;
        family_attrmax = OVS_PACKET_ATTR_MAX;
    } else if (!strcmp(name, OVS_VPORT_FAMILY)) {
        family_id = OVS_WIN_NL_VPORT_FAMILY_ID;
        family_name = OVS_VPORT_FAMILY;
        family_version = OVS_VPORT_VERSION;
        family_attrmax = OVS_VPORT_ATTR_MAX;
        mcgrp_id = OVS_WIN_NL_VPORT_MCGRP_ID;
        mcgrp_name = OVS_VPORT_MCGROUP;
    } else if (!strcmp(name, OVS_FLOW_FAMILY)) {
        family_id = OVS_WIN_NL_FLOW_FAMILY_ID;
        family_name = OVS_FLOW_FAMILY;
        family_version = OVS_FLOW_VERSION;
        family_attrmax = OVS_FLOW_ATTR_MAX;
    } else if (!strcmp(name, OVS_WIN_NETDEV_FAMILY)) {
        family_id = OVS_WIN_NL_NETDEV_FAMILY_ID;
        family_name = OVS_WIN_NETDEV_FAMILY;
        family_version = OVS_WIN_NETDEV_VERSION;
        family_attrmax = OVS_WIN_NETDEV_ATTR_MAX;
    } else if (!strcmp(name, OVS_CT_LIMIT_FAMILY)) {
        family_id = OVS_WIN_NL_CTLIMIT_FAMILY_ID;
        family_name = OVS_CT_LIMIT_FAMILY;
        family_version = OVS_CT_LIMIT_VERSION;
        family_attrmax = OVS_CT_LIMIT_ATTR_MAX;
    } else {
        ofpbuf_delete(reply);
        return EINVAL;
    }

    nl_msg_put_genlmsghdr(reply, 0, GENL_ID_CTRL, 0,
                          CTRL_CMD_NEWFAMILY, family_version);
    /* CTRL_ATTR_HDRSIZE and CTRL_ATTR_OPS are not populated, but the
     * callers do not seem to need them. */
    nl_msg_put_u16(reply, CTRL_ATTR_FAMILY_ID, family_id);
    nl_msg_put_string(reply, CTRL_ATTR_FAMILY_NAME, family_name);
    nl_msg_put_u32(reply, CTRL_ATTR_VERSION, family_version);
    nl_msg_put_u32(reply, CTRL_ATTR_MAXATTR, family_attrmax);

    if (mcgrp_id != OVS_WIN_NL_INVALID_MCGRP_ID) {
        size_t mcgrp_ofs1 = nl_msg_start_nested(reply, CTRL_ATTR_MCAST_GROUPS);
        size_t mcgrp_ofs2= nl_msg_start_nested(reply,
            OVS_WIN_NL_VPORT_MCGRP_ID - OVS_WIN_NL_MCGRP_START_ID);
        nl_msg_put_u32(reply, CTRL_ATTR_MCAST_GRP_ID, mcgrp_id);
        ovs_assert(mcgrp_name != NULL);
        nl_msg_put_string(reply, CTRL_ATTR_MCAST_GRP_NAME, mcgrp_name);
        nl_msg_end_nested(reply, mcgrp_ofs2);
        nl_msg_end_nested(reply, mcgrp_ofs1);
    }

    /* Set the total length of the netlink message. */
    nlmsg = nl_msg_nlmsghdr(reply);
    nlmsg->nlmsg_len = reply->size;

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         family_policy, attrs, ARRAY_SIZE(family_policy))
        || nl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]) == 0) {
        ofpbuf_delete(reply);
        return EPROTO;
    }

    *replyp = reply;
    return 0;
}
#endif

/* Finds the multicast group called 'group_name' in genl family 'family_name'.
 * When successful, writes its result to 'multicast_group' and returns 0.
 * Otherwise, clears 'multicast_group' and returns a positive error code.
 */
int
nl_lookup_genl_mcgroup(const char *family_name, const char *group_name,
                       unsigned int *multicast_group)
{
    struct nlattr *family_attrs[ARRAY_SIZE(family_policy)];
    const struct nlattr *mc;
    struct ofpbuf *reply;
    unsigned int left;
    int error;

    *multicast_group = 0;
    error = do_lookup_genl_family(family_name, family_attrs, &reply);
    if (error) {
        return error;
    }

    if (!family_attrs[CTRL_ATTR_MCAST_GROUPS]) {
        error = EPROTO;
        goto exit;
    }

    NL_NESTED_FOR_EACH (mc, left, family_attrs[CTRL_ATTR_MCAST_GROUPS]) {
        static const struct nl_policy mc_policy[] = {
            [CTRL_ATTR_MCAST_GRP_ID] = {.type = NL_A_U32},
            [CTRL_ATTR_MCAST_GRP_NAME] = {.type = NL_A_STRING},
        };

        struct nlattr *mc_attrs[ARRAY_SIZE(mc_policy)];
        const char *mc_name;

        if (!nl_parse_nested(mc, mc_policy, mc_attrs, ARRAY_SIZE(mc_policy))) {
            error = EPROTO;
            goto exit;
        }

        mc_name = nl_attr_get_string(mc_attrs[CTRL_ATTR_MCAST_GRP_NAME]);
        if (!strcmp(group_name, mc_name)) {
            *multicast_group =
                nl_attr_get_u32(mc_attrs[CTRL_ATTR_MCAST_GRP_ID]);
            error = 0;
            goto exit;
        }
    }
    error = EPROTO;

exit:
    ofpbuf_delete(reply);
    return error;
}

/* If '*number' is 0, translates the given Generic Netlink family 'name' to a
 * number and stores it in '*number'.  If successful, returns 0 and the caller
 * may use '*number' as the family number.  On failure, returns a positive
 * errno value and '*number' caches the errno value. */
int
nl_lookup_genl_family(const char *name, int *number)
{
    if (*number == 0) {
        struct nlattr *attrs[ARRAY_SIZE(family_policy)];
        struct ofpbuf *reply;
        int error;

        error = do_lookup_genl_family(name, attrs, &reply);
        if (!error) {
            *number = nl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
            define_genl_family(*number, name);
        } else {
            *number = -error;
        }
        ofpbuf_delete(reply);

        ovs_assert(*number != 0);
    }
    return *number > 0 ? 0 : -*number;
}

struct nl_pool {
    struct nl_sock *socks[16];
    int n;
};

static struct ovs_mutex pool_mutex = OVS_MUTEX_INITIALIZER;
static struct nl_pool pools[MAX_LINKS] OVS_GUARDED_BY(pool_mutex);

static int
nl_pool_alloc(int protocol, struct nl_sock **sockp)
{
    struct nl_sock *sock = NULL;
    struct nl_pool *pool;

    ovs_assert(protocol >= 0 && protocol < ARRAY_SIZE(pools));

    ovs_mutex_lock(&pool_mutex);
    pool = &pools[protocol];
    if (pool->n > 0) {
        sock = pool->socks[--pool->n];
    }
    ovs_mutex_unlock(&pool_mutex);

    if (sock) {
        *sockp = sock;
        return 0;
    } else {
        return nl_sock_create(protocol, sockp);
    }
}

static void
nl_pool_release(struct nl_sock *sock)
{
    if (sock) {
        struct nl_pool *pool = &pools[sock->protocol];

        ovs_mutex_lock(&pool_mutex);
        if (pool->n < ARRAY_SIZE(pool->socks)) {
            pool->socks[pool->n++] = sock;
            sock = NULL;
        }
        ovs_mutex_unlock(&pool_mutex);

        nl_sock_destroy(sock);
    }
}

/* Sends 'request' to the kernel on a Netlink socket for the given 'protocol'
 * (e.g. NETLINK_ROUTE or NETLINK_GENERIC) and waits for a response.  If
 * successful, returns 0.  On failure, returns a positive errno value.
 *
 * If 'replyp' is nonnull, then on success '*replyp' is set to the kernel's
 * reply, which the caller is responsible for freeing with ofpbuf_delete(), and
 * on failure '*replyp' is set to NULL.  If 'replyp' is null, then the kernel's
 * reply, if any, is discarded.
 *
 * Before the message is sent, nlmsg_len in 'request' will be finalized to
 * match msg->size, nlmsg_pid will be set to the pid of the socket used
 * for sending the request, and nlmsg_seq will be initialized.
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
nl_transact(int protocol, const struct ofpbuf *request,
            struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    int error;

    error = nl_pool_alloc(protocol, &sock);
    if (error) {
        if (replyp) {
            *replyp = NULL;
        }
        return error;
    }

    error = nl_sock_transact(sock, request, replyp);

    nl_pool_release(sock);
    return error;
}

/* Sends the 'request' member of the 'n' transactions in 'transactions' on a
 * Netlink socket for the given 'protocol' (e.g. NETLINK_ROUTE or
 * NETLINK_GENERIC), in order, and receives responses to all of them.  Fills in
 * the 'error' member of each transaction with 0 if it was successful,
 * otherwise with a positive errno value.  If 'reply' is nonnull, then it will
 * be filled with the reply if the message receives a detailed reply.  In other
 * cases, i.e. where the request failed or had no reply beyond an indication of
 * success, 'reply' will be cleared if it is nonnull.
 *
 * The caller is responsible for destroying each request and reply, and the
 * transactions array itself.
 *
 * Before sending each message, this function will finalize nlmsg_len in each
 * 'request' to match the ofpbuf's size, set nlmsg_pid to the pid of the socket
 * used for the transaction, and initialize nlmsg_seq.
 *
 * Bare Netlink is an unreliable transport protocol.  This function layers
 * reliable delivery and reply semantics on top of bare Netlink.  See
 * nl_transact() for some caveats.
 */
void
nl_transact_multiple(int protocol,
                     struct nl_transaction **transactions, size_t n)
{
    struct nl_sock *sock;
    int error;

    error = nl_pool_alloc(protocol, &sock);
    if (!error) {
        nl_sock_transact_multiple(sock, transactions, n);
        nl_pool_release(sock);
    } else {
        nl_sock_record_errors__(transactions, n, error);
    }
}


static uint32_t
nl_sock_allocate_seq(struct nl_sock *sock, unsigned int n)
{
    uint32_t seq = sock->next_seq;

    sock->next_seq += n;

    /* Make it impossible for the next request for sequence numbers to wrap
     * around to 0.  Start over with 1 to avoid ever using a sequence number of
     * 0, because the kernel uses sequence number 0 for notifications. */
    if (sock->next_seq >= UINT32_MAX / 2) {
        sock->next_seq = 1;
    }

    return seq;
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
    ds_put_format(ds, ", seq=%"PRIx32", pid=%"PRIu32,
                  h->nlmsg_seq, h->nlmsg_pid);
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
                    ds_put_format(&ds, "(%s)", ovs_strerror(-e->error));
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
                    ds_put_format(&ds, "(%s)", ovs_strerror(-*error));
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
    if (!VLOG_IS_DBG_ENABLED()) {
        return;
    }

    struct ofpbuf buffer = ofpbuf_const_initializer(message, size);
    char *nlmsg = nlmsg_to_string(&buffer, protocol);
    VLOG_DBG_RL(&rl, "%s (%s): %s", function, ovs_strerror(error), nlmsg);
    free(nlmsg);
}
