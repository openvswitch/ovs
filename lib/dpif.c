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
#include "dpif.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "netlink.h"
#include "netlink-protocol.h"
#include "ofpbuf.h"
#include "openflow/openflow-netlink.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "util.h"
#include "xtoxll.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpif

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 60);

/* The Generic Netlink family number used for OpenFlow. */
static int openflow_family;

static int lookup_openflow_multicast_group(int dp_idx, int *multicast_group);
static int send_mgmt_command(struct dpif *, int command,
                             const char *netdev);

/* Opens the local datapath numbered 'dp_idx', initializing 'dp'.  If
 * 'subscribe' is true, listens for asynchronous messages (packet-in, etc.)
 * from the datapath; otherwise, 'dp' will receive only replies to explicitly
 * initiated requests. */
int
dpif_open(int dp_idx, bool subscribe, struct dpif *dp)
{
    struct nl_sock *sock;
    int multicast_group = 0;
    int retval;

    retval = nl_lookup_genl_family(DP_GENL_FAMILY_NAME, &openflow_family);
    if (retval) {
        return retval;
    }

    if (subscribe) {
        retval = lookup_openflow_multicast_group(dp_idx, &multicast_group);
        if (retval) {
            return retval;
        }
    }

    /* Specify a large so_rcvbuf size because we occasionally need to be able
     * to retrieve large collections of flow records. */
    retval = nl_sock_create(NETLINK_GENERIC, multicast_group, 0,
                            4 * 1024u * 1024, &sock);
    if (retval) {
        return retval;
    }

    dp->dp_idx = dp_idx;
    dp->sock = sock;
    return 0;
}

/* Closes 'dp'. */
void
dpif_close(struct dpif *dp) 
{
    if (dp) {
        nl_sock_destroy(dp->sock);
    }
}

static const struct nl_policy openflow_policy[] = {
    [DP_GENL_A_DP_IDX] = { .type = NL_A_U32 },
    [DP_GENL_A_OPENFLOW] = { .type = NL_A_UNSPEC,
                              .min_len = sizeof(struct ofp_header),
                              .max_len = 65535 },
};

/* Tries to receive an openflow message from the kernel on 'sock'.  If
 * successful, stores the received message into '*msgp' and returns 0.  The
 * caller is responsible for destroying the message with ofpbuf_delete().  On
 * failure, returns a positive errno value and stores a null pointer into
 * '*msgp'.
 *
 * Only Netlink messages with embedded OpenFlow messages are accepted.  Other
 * Netlink messages provoke errors.
 *
 * If 'wait' is true, dpif_recv_openflow waits for a message to be ready;
 * otherwise, returns EAGAIN if the 'sock' receive buffer is empty. */
int
dpif_recv_openflow(struct dpif *dp, struct ofpbuf **bufferp,
                        bool wait) 
{
    struct nlattr *attrs[ARRAY_SIZE(openflow_policy)];
    struct ofpbuf *buffer;
    struct ofp_header *oh;
    uint16_t ofp_len;
    int retval;

    buffer = *bufferp = NULL;
    do {
        ofpbuf_delete(buffer);
        retval = nl_sock_recv(dp->sock, &buffer, wait);
    } while (retval == ENOBUFS
             || (!retval
                 && (nl_msg_nlmsgerr(buffer, NULL)
                     || nl_msg_nlmsghdr(buffer)->nlmsg_type == NLMSG_DONE)));
    if (retval) {
        if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "dpif_recv_openflow: %s", strerror(retval)); 
        }
        return retval;
    }

    if (nl_msg_genlmsghdr(buffer) == NULL) {
        VLOG_DBG_RL(&rl, "received packet too short for Generic Netlink");
        goto error;
    }
    if (nl_msg_nlmsghdr(buffer)->nlmsg_type != openflow_family) {
        VLOG_DBG_RL(&rl, "received type (%"PRIu16") != openflow family (%d)",
                    nl_msg_nlmsghdr(buffer)->nlmsg_type, openflow_family);
        goto error;
    }

    if (!nl_policy_parse(buffer, openflow_policy, attrs,
                         ARRAY_SIZE(openflow_policy))) {
        goto error;
    }
    if (nl_attr_get_u32(attrs[DP_GENL_A_DP_IDX]) != dp->dp_idx) {
        VLOG_WARN_RL(&rl, "received dp_idx (%"PRIu32") differs from expected "
                     "(%d)", nl_attr_get_u32(attrs[DP_GENL_A_DP_IDX]),
                     dp->dp_idx);
        goto error;
    }

    oh = buffer->data = (void *) nl_attr_get(attrs[DP_GENL_A_OPENFLOW]);
    buffer->size = nl_attr_get_size(attrs[DP_GENL_A_OPENFLOW]);
    ofp_len = ntohs(oh->length);
    if (ofp_len != buffer->size) {
        VLOG_WARN_RL(&rl,
                     "ofp_header.length %"PRIu16" != attribute length %zu\n",
                     ofp_len, buffer->size);
        buffer->size = MIN(ofp_len, buffer->size);
    }
    *bufferp = buffer;
    return 0;

error:
    ofpbuf_delete(buffer);
    return EPROTO;
}

/* Encapsulates 'msg', which must contain an OpenFlow message, in a Netlink
 * message, and sends it to the OpenFlow kernel module via 'sock'.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full.
 *
 * If the send is successful, then the kernel module will receive it, but there
 * is no guarantee that any reply will not be dropped (see nl_sock_transact()
 * for details). 
 */
int
dpif_send_openflow(struct dpif *dp, struct ofpbuf *buffer, bool wait) 
{
    struct ofp_header *oh;
    unsigned int dump_flag;
    struct ofpbuf hdr;
    struct nlattr *nla;
    uint32_t fixed_buffer[64 / 4];
    struct iovec iov[3];
    int pad_bytes;
    int n_iov;
    int retval;

    /* The reply to OFPT_STATS_REQUEST may be multiple segments long, so we
     * need to specify NLM_F_DUMP in the request. */
    oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    dump_flag = oh->type == OFPT_STATS_REQUEST ? NLM_F_DUMP : 0;

    ofpbuf_use(&hdr, fixed_buffer, sizeof fixed_buffer);
    nl_msg_put_genlmsghdr(&hdr, dp->sock, 32, openflow_family,
                          NLM_F_REQUEST | dump_flag, DP_GENL_C_OPENFLOW, 1);
    nl_msg_put_u32(&hdr, DP_GENL_A_DP_IDX, dp->dp_idx);
    nla = ofpbuf_put_uninit(&hdr, sizeof *nla);
    nla->nla_len = sizeof *nla + buffer->size;
    nla->nla_type = DP_GENL_A_OPENFLOW;
    pad_bytes = NLA_ALIGN(nla->nla_len) - nla->nla_len;
    nl_msg_nlmsghdr(&hdr)->nlmsg_len = hdr.size + buffer->size + pad_bytes;
    n_iov = 2;
    iov[0].iov_base = hdr.data;
    iov[0].iov_len = hdr.size;
    iov[1].iov_base = buffer->data;
    iov[1].iov_len = buffer->size;
    if (pad_bytes) {
        static char zeros[NLA_ALIGNTO];
        n_iov++;
        iov[2].iov_base = zeros;
        iov[2].iov_len = pad_bytes; 
    }
    retval = nl_sock_sendv(dp->sock, iov, n_iov, false);
    if (retval && retval != EAGAIN) {
        VLOG_WARN_RL(&rl, "dpif_send_openflow: %s", strerror(retval));
    }
    return retval;
}

/* Creates the datapath represented by 'dp'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_add_dp(struct dpif *dp)
{
    return send_mgmt_command(dp, DP_GENL_C_ADD_DP, NULL);
}

/* Destroys the datapath represented by 'dp'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
dpif_del_dp(struct dpif *dp) 
{
    return send_mgmt_command(dp, DP_GENL_C_DEL_DP, NULL);
}

/* Adds the Ethernet device named 'netdev' to this datapath.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
dpif_add_port(struct dpif *dp, const char *netdev)
{
    return send_mgmt_command(dp, DP_GENL_C_ADD_PORT, netdev);
}

/* Removes the Ethernet device named 'netdev' from this datapath.  Returns 0
 * if successful, otherwise a positive errno value. */
int
dpif_del_port(struct dpif *dp, const char *netdev)
{
    return send_mgmt_command(dp, DP_GENL_C_DEL_PORT, netdev);
}

static const struct nl_policy openflow_multicast_policy[] = {
    [DP_GENL_A_DP_IDX] = { .type = NL_A_U32 },
    [DP_GENL_A_MC_GROUP] = { .type = NL_A_U32 },
};

/* Looks up the Netlink multicast group used by datapath 'dp_idx'.  If
 * successful, stores the multicast group in '*multicast_group' and returns 0.
 * Otherwise, returns a positve errno value. */
static int
lookup_openflow_multicast_group(int dp_idx, int *multicast_group) 
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    struct nlattr *attrs[ARRAY_SIZE(openflow_multicast_policy)];
    int retval;

    retval = nl_sock_create(NETLINK_GENERIC, 0, 0, 0, &sock);
    if (retval) {
        return retval;
    }
    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, sock, 0, openflow_family, NLM_F_REQUEST,
                          DP_GENL_C_QUERY_DP, 1);
    nl_msg_put_u32(&request, DP_GENL_A_DP_IDX, dp_idx);
    retval = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (retval) {
        nl_sock_destroy(sock);
        return retval;
    }
    if (!nl_policy_parse(reply, openflow_multicast_policy, attrs,
                         ARRAY_SIZE(openflow_multicast_policy))) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return EPROTO;
    }
    *multicast_group = nl_attr_get_u32(attrs[DP_GENL_A_MC_GROUP]);
    nl_sock_destroy(sock);
    ofpbuf_delete(reply);

    return 0;
}

/* Sends the given 'command' to datapath 'dp'.  If 'netdev' is nonnull, adds it
 * to the command as the port name attribute.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
send_mgmt_command(struct dpif *dp, int command, const char *netdev) 
{
    struct ofpbuf request, *reply;
    int retval;

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, dp->sock, 32, openflow_family,
                          NLM_F_REQUEST | NLM_F_ACK, command, 1);
    nl_msg_put_u32(&request, DP_GENL_A_DP_IDX, dp->dp_idx);
    if (netdev) {
        nl_msg_put_string(&request, DP_GENL_A_PORTNAME, netdev);
    }
    retval = nl_sock_transact(dp->sock, &request, &reply);
    ofpbuf_uninit(&request);
    ofpbuf_delete(reply);

    return retval;
}
