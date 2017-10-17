/*
 * Copyright (c) 2011, 2012, 2013 Nicira, Inc.
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

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#ifndef __SYS_SOCKET_SPARSE
#define __SYS_SOCKET_SPARSE 1

#include "openvswitch/types.h"
#include <sys/uio.h>
#include <stddef.h>

typedef unsigned short int sa_family_t;
typedef __socklen_t socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[64];
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char sa_data[64];
};

struct msghdr {
    void *msg_name;
    socklen_t      msg_namelen;
    struct iovec  *msg_iov;
    int            msg_iovlen;
    void          *msg_control;
    socklen_t      msg_controllen;
    int            msg_flags;
};

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
    unsigned char cmsg_data[];
};

#define __CMSG_ALIGNTO sizeof(size_t)
#define CMSG_ALIGN(LEN) \
        (((LEN) + __CMSG_ALIGNTO - 1) / __CMSG_ALIGNTO * __CMSG_ALIGNTO)
#define CMSG_DATA(CMSG) ((CMSG)->cmsg_data)
#define CMSG_LEN(LEN) (sizeof(struct cmsghdr) + (LEN))
#define CMSG_SPACE(LEN) CMSG_ALIGN(CMSG_LEN(LEN))
#define CMSG_FIRSTHDR(MSG) \
    ((MSG)->msg_controllen ? (struct cmsghdr *) (MSG)->msg_control : NULL)
#define CMSG_NXTHDR(MSG, CMSG) __cmsg_nxthdr(MSG, CMSG)

static inline struct cmsghdr *
__cmsg_nxthdr(struct msghdr *msg, struct cmsghdr *cmsg)
{
    size_t ofs = (char *) cmsg - (char *) msg->msg_control;
    size_t next_ofs = ofs + CMSG_ALIGN(cmsg->cmsg_len);
    return (next_ofs < msg->msg_controllen
            ? (void *) ((char *) msg->msg_control + next_ofs)
            : NULL);
}

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

enum {
    SCM_RIGHTS = 1
};

enum {
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_SEQPACKET,
    SOCK_STREAM
};

enum {
    SOL_PACKET,
    SOL_SOCKET
};

enum {
    SO_ACCEPTCONN,
    SO_BROADCAST,
    SO_DEBUG,
    SO_DONTROUTE,
    SO_ERROR,
    SO_KEEPALIVE,
    SO_LINGER,
    SO_OOBINLINE,
    SO_RCVBUF,
    SO_RCVLOWAT,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_SNDBUF,
    SO_SNDLOWAT,
    SO_SNDTIMEO,
    SO_TYPE,
    SO_RCVBUFFORCE,
    SO_ATTACH_FILTER
};

enum {
    MSG_CTRUNC,
    MSG_DONTROUTE,
    MSG_EOR,
    MSG_OOB,
    MSG_NOSIGNAL,
    MSG_PEEK,
    MSG_TRUNC,
    MSG_WAITALL,
    MSG_DONTWAIT
};

enum {
    AF_UNSPEC,
    PF_UNSPEC = AF_UNSPEC,
    AF_INET,
    PF_INET = AF_INET,
    AF_INET6,
    PF_INET6 = AF_INET6,
    AF_UNIX,
    PF_UNIX = AF_UNIX,
    AF_NETLINK,
    PF_NETLINK = AF_NETLINK,
    AF_PACKET,
    PF_PACKET = AF_PACKET
};

enum {
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR
};

int accept(int, struct sockaddr *, socklen_t *);
int bind(int, const struct sockaddr *, socklen_t);
int connect(int, const struct sockaddr *, socklen_t);
int getpeername(int, struct sockaddr *, socklen_t *);
int getsockname(int, struct sockaddr *, socklen_t *);
int getsockopt(int, int, int, void *, socklen_t *);
int listen(int, int);
ssize_t recv(int, void *, size_t, int);
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t recvmsg(int, struct msghdr *, int);
ssize_t send(int, const void *, size_t, int);
ssize_t sendmsg(int, const struct msghdr *, int);
int sendmmsg(int, struct mmsghdr *, unsigned int, unsigned int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *,
               socklen_t);
int setsockopt(int, int, int, const void *, socklen_t);
int shutdown(int, int);
int sockatmark(int);
int socket(int, int, int);
int socketpair(int, int, int, int[2]);

#endif /* <sys/socket.h> for sparse */
