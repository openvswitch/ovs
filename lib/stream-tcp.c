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
#include "stream.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packets.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream-fd.h"

#include "vlog.h"
#define THIS_MODULE VLM_stream_tcp

/* Active TCP. */

static int
new_tcp_stream(const char *name, int fd, int connect_status,
              const struct sockaddr_in *remote, struct stream **streamp)
{
    struct sockaddr_in local;
    socklen_t local_len = sizeof local;
    int on = 1;
    int retval;

    /* Get the local IP and port information */
    retval = getsockname(fd, (struct sockaddr *)&local, &local_len);
    if (retval) {
        memset(&local, 0, sizeof local);
    }

    retval = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    if (retval) {
        VLOG_ERR("%s: setsockopt(TCP_NODELAY): %s", name, strerror(errno));
        close(fd);
        return errno;
    }

    retval = new_fd_stream(name, fd, connect_status, NULL, streamp);
    if (!retval) {
        struct stream *stream = *streamp;
        stream_set_remote_ip(stream, remote->sin_addr.s_addr);
        stream_set_remote_port(stream, remote->sin_port);
        stream_set_local_ip(stream, local.sin_addr.s_addr);
        stream_set_local_port(stream, local.sin_port);
    }
    return retval;
}

static int
tcp_open(const char *name, char *suffix, struct stream **streamp)
{
    struct sockaddr_in sin;
    int fd, error;

    error = inet_open_active(SOCK_STREAM, suffix, 0, &sin, &fd);
    if (fd >= 0) {
        return new_tcp_stream(name, fd, error, &sin, streamp);
    } else {
        VLOG_ERR("%s: connect: %s", name, strerror(error));
        return error;
    }
}

struct stream_class tcp_stream_class = {
    "tcp",                      /* name */
    tcp_open,                   /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* wait */
};

/* Passive TCP. */

static int ptcp_accept(int fd, const struct sockaddr *sa, size_t sa_len,
                       struct stream **streamp);

static int
ptcp_open(const char *name UNUSED, char *suffix, struct pstream **pstreamp)
{
    int fd;

    fd = inet_open_passive(SOCK_STREAM, suffix, 0);
    if (fd < 0) {
        return -fd;
    } else {
        return new_fd_pstream("ptcp", fd, ptcp_accept, NULL, pstreamp);
    }
}

static int
ptcp_accept(int fd, const struct sockaddr *sa, size_t sa_len,
            struct stream **streamp)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
    char name[128];

    if (sa_len == sizeof(struct sockaddr_in) && sin->sin_family == AF_INET) {
        sprintf(name, "tcp:"IP_FMT, IP_ARGS(&sin->sin_addr));
        sprintf(strchr(name, '\0'), ":%"PRIu16, ntohs(sin->sin_port));
    } else {
        strcpy(name, "tcp");
    }
    return new_tcp_stream(name, fd, 0, sin, streamp);
}

struct pstream_class ptcp_pstream_class = {
    "ptcp",
    ptcp_open,
    NULL,
    NULL,
    NULL
};

