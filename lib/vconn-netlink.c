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
#include "dpif.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow-netlink.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "vconn-provider.h"

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
    vconn_assert_class(vconn, &netlink_vconn_class);
    return CONTAINER_OF(vconn, struct netlink_vconn, vconn); 
}

static int
netlink_open(const char *name, char *suffix, struct vconn **vconnp)
{
    struct netlink_vconn *netlink;
    int dp_idx;
    int subscribe;
    int retval;

    subscribe = 1;
    if (sscanf(suffix, "%d:%d", &dp_idx, &subscribe) < 1) {
        ofp_error(0, "%s: syntax error", name);
        return EAFNOSUPPORT;
    }

    netlink = xmalloc(sizeof *netlink);
    vconn_init(&netlink->vconn, &netlink_vconn_class, 0, 0, name);
    retval = dpif_open(dp_idx, subscribe, &netlink->dp);
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

static int
netlink_recv(struct vconn *vconn, struct ofpbuf **bufferp)
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    return dpif_recv_openflow(&netlink->dp, bufferp, false);
}

static int
netlink_send(struct vconn *vconn, struct ofpbuf *buffer) 
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    int retval = dpif_send_openflow(&netlink->dp, buffer, false);
    if (!retval) {
        ofpbuf_delete(buffer);
    }
    return retval;
}

static void
netlink_wait(struct vconn *vconn, enum vconn_wait_type wait) 
{
    struct netlink_vconn *netlink = netlink_vconn_cast(vconn);
    short int events = 0;
    switch (wait) {
    case WAIT_RECV:
        events = POLLIN;
        break;

    case WAIT_SEND:
        events = 0;
        break;

    default:
        NOT_REACHED();
    }
    poll_fd_wait(nl_sock_fd(netlink->dp.sock), events);
}

struct vconn_class netlink_vconn_class = {
    "nl",                       /* name */
    netlink_open,               /* open */
    netlink_close,              /* close */
    NULL,                       /* connect */
    netlink_recv,               /* recv */
    netlink_send,               /* send */
    netlink_wait,               /* wait */
};
