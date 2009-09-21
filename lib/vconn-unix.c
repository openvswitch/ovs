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
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "vconn-provider.h"
#include "vconn-stream.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_unix

/* Active UNIX socket. */

/* Number of unix sockets created so far, to ensure binding path uniqueness. */
static int n_unix_sockets;

static int
unix_open(const char *name, char *suffix, struct vconn **vconnp)
{
    const char *connect_path = suffix;
    char *bind_path;
    int fd;

    bind_path = xasprintf("/tmp/vconn-unix.%ld.%d",
                          (long int) getpid(), n_unix_sockets++);
    fd = make_unix_socket(SOCK_STREAM, true, false, bind_path, connect_path);
    if (fd < 0) {
        VLOG_ERR("%s: connection to %s failed: %s",
                 bind_path, connect_path, strerror(-fd));
        free(bind_path);
        return -fd;
    }

    return new_stream_vconn(name, fd, check_connection_completion(fd),
                            bind_path, vconnp);
}

struct vconn_class unix_vconn_class = {
    "unix",                     /* name */
    unix_open,                  /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* wait */
};

/* Passive UNIX socket. */

static int punix_accept(int fd, const struct sockaddr *sa, size_t sa_len,
                        struct vconn **vconnp);

static int
punix_open(const char *name UNUSED, char *suffix, struct pvconn **pvconnp)
{
    int fd, error;

    fd = make_unix_socket(SOCK_STREAM, true, true, suffix, NULL);
    if (fd < 0) {
        VLOG_ERR("%s: binding failed: %s", suffix, strerror(errno));
        return errno;
    }

    error = set_nonblocking(fd);
    if (error) {
        close(fd);
        return error;
    }

    if (listen(fd, 10) < 0) {
        error = errno;
        VLOG_ERR("%s: listen: %s", name, strerror(error));
        close(fd);
        return error;
    }

    return new_pstream_pvconn("punix", fd, punix_accept,
                              xstrdup(suffix), pvconnp);
}

static int
punix_accept(int fd, const struct sockaddr *sa, size_t sa_len,
             struct vconn **vconnp)
{
    const struct sockaddr_un *sun = (const struct sockaddr_un *) sa;
    int name_len = get_unix_name_len(sa_len);
    char name[128];

    if (name_len > 0) {
        snprintf(name, sizeof name, "unix:%.*s", name_len, sun->sun_path);
    } else {
        strcpy(name, "unix");
    }
    return new_stream_vconn(name, fd, 0, NULL, vconnp);
}

struct pvconn_class punix_pvconn_class = {
    "punix",
    punix_open,
    NULL,
    NULL,
    NULL
};

