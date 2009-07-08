/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
    char bind_path[128];
    int fd;

    sprintf(bind_path, "/tmp/vconn-unix.%ld.%d",
            (long int) getpid(), n_unix_sockets++);
    fd = make_unix_socket(SOCK_STREAM, true, false, bind_path, connect_path);
    if (fd < 0) {
        VLOG_ERR("%s: connection to %s failed: %s",
                 bind_path, connect_path, strerror(-fd));
        return -fd;
    }

    return new_stream_vconn(name, fd, check_connection_completion(fd),
                            0, true, vconnp);
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
    int fd;

    fd = make_unix_socket(SOCK_STREAM, true, true, suffix, NULL);
    if (fd < 0) {
        VLOG_ERR("%s: binding failed: %s", suffix, strerror(errno));
        return errno;
    }

    return new_pstream_pvconn("punix", fd, punix_accept, pvconnp);
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
    return new_stream_vconn(name, fd, 0, 0, true, vconnp);
}

struct pvconn_class punix_pvconn_class = {
    "punix",
    punix_open,
    NULL,
    NULL,
    NULL
};

