/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
                            0, vconnp);
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
punix_open(const char *name, char *suffix, struct pvconn **pvconnp)
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
    return new_stream_vconn(name, fd, 0, 0, vconnp);
}

struct pvconn_class punix_pvconn_class = {
    "punix",
    punix_open,
};

