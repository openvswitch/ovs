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
#include "vconn.h"
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
#include "openflow/openflow.h"
#include "vconn-provider.h"
#include "vconn-stream.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_tcp

/* Active TCP. */

static int
new_tcp_vconn(const char *name, int fd, int connect_status,
              const struct sockaddr_in *remote, struct vconn **vconnp)
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

    retval = new_stream_vconn(name, fd, connect_status, true, vconnp);
    if (!retval) {
        struct vconn *vconn = *vconnp;
        vconn_set_remote_ip(vconn, remote->sin_addr.s_addr);
        vconn_set_remote_port(vconn, remote->sin_port);
        vconn_set_local_ip(vconn, local.sin_addr.s_addr);
        vconn_set_local_port(vconn, local.sin_port);
    }
    return retval;
}

static int
tcp_open(const char *name, char *suffix, struct vconn **vconnp)
{
    char *save_ptr;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    host_name = strtok_r(suffix, ":", &save_ptr);
    port_string = strtok_r(NULL, ":", &save_ptr);
    if (!host_name) {
        ovs_error(0, "%s: bad peer name format", name);
        return EAFNOSUPPORT;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return ENOENT;
    }
    sin.sin_port = htons(port_string ? atoi(port_string) : OFP_TCP_PORT);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", name, strerror(errno));
        return errno;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        if (errno == EINPROGRESS) {
            return new_tcp_vconn(name, fd, EAGAIN, &sin, vconnp);
        } else {
            int error = errno;
            VLOG_ERR("%s: connect: %s", name, strerror(error));
            close(fd);
            return error;
        }
    } else {
        return new_tcp_vconn(name, fd, 0, &sin, vconnp);
    }
}

struct vconn_class tcp_vconn_class = {
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
                       struct vconn **vconnp);

static int
ptcp_open(const char *name, char *suffix, struct pvconn **pvconnp)
{
    struct sockaddr_in sin;
    int retval;
    int fd;
    unsigned int yes  = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", name, strerror(errno));
        return errno;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        VLOG_ERR("%s: setsockopt(SO_REUSEADDR): %s", name, strerror(errno));
        return errno;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(atoi(suffix) ? atoi(suffix) : OFP_TCP_PORT);
    retval = bind(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: bind: %s", name, strerror(error));
        close(fd);
        return error;
    }

    return new_pstream_pvconn("ptcp", fd, ptcp_accept, pvconnp);
}

static int
ptcp_accept(int fd, const struct sockaddr *sa, size_t sa_len,
            struct vconn **vconnp)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
    char name[128];

    if (sa_len == sizeof(struct sockaddr_in) && sin->sin_family == AF_INET) {
        sprintf(name, "tcp:"IP_FMT, IP_ARGS(&sin->sin_addr));
        if (sin->sin_port != htons(OFP_TCP_PORT)) {
            sprintf(strchr(name, '\0'), ":%"PRIu16, ntohs(sin->sin_port));
        }
    } else {
        strcpy(name, "tcp");
    }
    return new_tcp_vconn(name, fd, 0, sin, vconnp);
}

struct pvconn_class ptcp_pvconn_class = {
    "ptcp",
    ptcp_open,
    NULL,
    NULL,
    NULL
};

