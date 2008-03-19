/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "vconn.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openflow-netlink.h"
#include "buffer.h"
#include "dpif.h"
#include "netlink.h"
#include "socket-util.h"
#include "util.h"
#include "openflow.h"

#include "vlog.h"
#define THIS_MODULE VLM_VCONN_NETLINK

struct netlink_vconn
{
    struct vconn vconn;
    struct dpif dp;
};

static struct netlink_vconn *
netlink_vconn_cast(struct vconn *vconn) 
{
    assert(vconn->class == &netlink_vconn_class);
    return CONTAINER_OF(vconn, struct netlink_vconn, vconn); 
}

static int
netlink_open(const char *name, char *suffix, struct vconn **vconnp)
{
    struct netlink_vconn *netlink;
    int dp_idx;
    int retval;

    if (sscanf(suffix, "%d", &dp_idx) != 1) {
        fatal(0, "%s: bad peer name format", name);
    }

    netlink = xmalloc(sizeof *netlink);
    netlink->vconn.class = &netlink_vconn_class;
    retval = dpif_open(dp_idx, true, &netlink->dp);
    if (retval) {
        free(netlink);
        *vconnp = NULL;
        return retval;
    }
    *vconnp = &netlink->vconn;
    return 0;
}

static void
netlink_close(struct vconn *vconn) 
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    dpif_close(&netlink->dp);
    free(netlink);
}

static bool
netlink_prepoll(struct vconn *vconn, int want, struct pollfd *pfd) 
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    pfd->fd = nl_sock_fd(netlink->dp.sock);
    if (want & WANT_RECV) {
        pfd->events |= POLLIN;
    }
    if (want & WANT_SEND) {
        pfd->events |= POLLOUT;
    }
    return false;
}

static int
netlink_recv(struct vconn *vconn, struct buffer **bufferp)
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    return dpif_recv_openflow(&netlink->dp, bufferp, false);
}

static int
netlink_send(struct vconn *vconn, struct buffer *buffer) 
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    int retval = dpif_send_openflow(&netlink->dp, buffer, false);
    if (!retval) {
        buffer_delete(buffer);
    }
    return retval;
}

struct vconn_class netlink_vconn_class = {
    .name = "nl",
    .open = netlink_open,
    .close = netlink_close,
    .prepoll = netlink_prepoll,
    .recv = netlink_recv,
    .send = netlink_send,
};
