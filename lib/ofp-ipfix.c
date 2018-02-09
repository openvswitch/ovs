/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include "openvswitch/ofp-ipfix.h"
#include <stdlib.h>
#include "byte-order.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofpbuf.h"
#include "util.h"

static void
ofputil_ipfix_stats_to_reply(const struct ofputil_ipfix_stats *ois,
                            struct nx_ipfix_stats_reply *reply)
{
    reply->collector_set_id = htonl(ois->collector_set_id);
    reply->total_flows = htonll(ois->total_flows);
    reply->current_flows = htonll(ois->current_flows);
    reply->pkts = htonll(ois->pkts);
    reply->ipv4_pkts = htonll(ois->ipv4_pkts);
    reply->ipv6_pkts = htonll(ois->ipv6_pkts);
    reply->error_pkts = htonll(ois->error_pkts);
    reply->ipv4_error_pkts = htonll(ois->ipv4_error_pkts);
    reply->ipv6_error_pkts = htonll(ois->ipv6_error_pkts);
    reply->tx_pkts = htonll(ois->tx_pkts);
    reply->tx_errors = htonll(ois->tx_errors);
    memset(reply->pad, 0, sizeof reply->pad);
}

/* Encode a ipfix stat for 'ois' and append it to 'replies'. */
void
ofputil_append_ipfix_stat(struct ovs_list *replies,
                         const struct ofputil_ipfix_stats *ois)
{
    struct nx_ipfix_stats_reply *reply = ofpmp_append(replies, sizeof *reply);
    ofputil_ipfix_stats_to_reply(ois, reply);
}

static enum ofperr
ofputil_ipfix_stats_from_nx(struct ofputil_ipfix_stats *is,
                            const struct nx_ipfix_stats_reply *reply)
{
    is->collector_set_id = ntohl(reply->collector_set_id);
    is->total_flows = ntohll(reply->total_flows);
    is->current_flows = ntohll(reply->current_flows);
    is->pkts = ntohll(reply->pkts);
    is->ipv4_pkts = ntohll(reply->ipv4_pkts);
    is->ipv6_pkts = ntohll(reply->ipv6_pkts);
    is->error_pkts = ntohll(reply->error_pkts);
    is->ipv4_error_pkts = ntohll(reply->ipv4_error_pkts);
    is->ipv6_error_pkts = ntohll(reply->ipv6_error_pkts);
    is->tx_pkts = ntohll(reply->tx_pkts);
    is->tx_errors = ntohll(reply->tx_errors);

    return 0;
}

int
ofputil_pull_ipfix_stats(struct ofputil_ipfix_stats *is, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    memset(is, 0xFF, sizeof (*is));

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_NXST_IPFIX_BRIDGE_REPLY ||
               raw == OFPRAW_NXST_IPFIX_FLOW_REPLY) {
        struct nx_ipfix_stats_reply *reply;

        reply = ofpbuf_try_pull(msg, sizeof *reply);
        return ofputil_ipfix_stats_from_nx(is, reply);
    } else {
        OVS_NOT_REACHED();
    }
}


/* Returns the number of ipfix stats elements in
 * OFPTYPE_IPFIX_BRIDGE_STATS_REPLY or OFPTYPE_IPFIX_FLOW_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_ipfix_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    return b.size / sizeof(struct ofputil_ipfix_stats);
}
