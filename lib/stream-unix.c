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
#include "stream.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream-fd.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_unix);

/* Active UNIX socket. */

/* Number of unix sockets created so far, to ensure binding path uniqueness. */
static int n_unix_sockets;

static int
unix_open(const char *name, char *suffix, struct stream **streamp)
{
    const char *connect_path = suffix;
    char *bind_path;
    int fd;

    bind_path = xasprintf("/tmp/stream-unix.%ld.%d",
                          (long int) getpid(), n_unix_sockets++);
    fd = make_unix_socket(SOCK_STREAM, true, false, bind_path, connect_path);
    if (fd < 0) {
        VLOG_ERR("%s: connection to %s failed: %s",
                 bind_path, connect_path, strerror(-fd));
        free(bind_path);
        return -fd;
    }

    return new_fd_stream(name, fd, check_connection_completion(fd),
                         bind_path, streamp);
}

struct stream_class unix_stream_class = {
    "unix",                     /* name */
    unix_open,                  /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    NULL,                       /* wait */
};

/* Passive UNIX socket. */

static int punix_accept(int fd, const struct sockaddr *sa, size_t sa_len,
                        struct stream **streamp);

static int
punix_open(const char *name OVS_UNUSED, char *suffix,
           struct pstream **pstreamp)
{
    int fd, error;

    fd = make_unix_socket(SOCK_STREAM, true, true, suffix, NULL);
    if (fd < 0) {
        VLOG_ERR("%s: binding failed: %s", suffix, strerror(errno));
        return errno;
    }

    if (listen(fd, 10) < 0) {
        error = errno;
        VLOG_ERR("%s: listen: %s", name, strerror(error));
        close(fd);
        return error;
    }

    return new_fd_pstream(name, fd, punix_accept,
                          xstrdup(suffix), pstreamp);
}

static int
punix_accept(int fd, const struct sockaddr *sa, size_t sa_len,
             struct stream **streamp)
{
    const struct sockaddr_un *sun = (const struct sockaddr_un *) sa;
    int name_len = get_unix_name_len(sa_len);
    char name[128];

    if (name_len > 0) {
        snprintf(name, sizeof name, "unix:%.*s", name_len, sun->sun_path);
    } else {
        strcpy(name, "unix");
    }
    return new_fd_stream(name, fd, 0, NULL, streamp);
}

struct pstream_class punix_pstream_class = {
    "punix",
    punix_open,
    NULL,
    NULL,
    NULL
};

