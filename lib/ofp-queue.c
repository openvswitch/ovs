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
#include "openvswitch/ofp-queue.h"
#include "byte-order.h"
#include "flow.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_queue);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static void
ofp_print_queue_name(struct ds *string, uint32_t queue_id)
{
    if (queue_id == OFPQ_ALL) {
        ds_put_cstr(string, "ALL");
    } else {
        ds_put_format(string, "%"PRIu32, queue_id);
    }
}

/* OFPT_QUEUE_GET_CONFIG request and reply. */

/* Constructs and returns an OFPT_QUEUE_GET_CONFIG request for the specified
 * 'port' and 'queue', suitable for OpenFlow version 'version'.
 *
 * 'queue' is honored only for OpenFlow 1.4 and later; older versions always
 * request all queues. */
struct ofpbuf *
ofputil_encode_queue_get_config_request(enum ofp_version version,
                                        ofp_port_t port,
                                        uint32_t queue)
{
    struct ofpbuf *request;

    if (version == OFP10_VERSION) {
        struct ofp10_queue_get_config_request *qgcr10;

        request = ofpraw_alloc(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr10 = ofpbuf_put_zeros(request, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
    } else if (version < OFP14_VERSION) {
        struct ofp11_queue_get_config_request *qgcr11;

        request = ofpraw_alloc(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST,
                               version, 0);
        qgcr11 = ofpbuf_put_zeros(request, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
    } else {
        struct ofp14_queue_desc_request *qdr14;

        request = ofpraw_alloc(OFPRAW_OFPST14_QUEUE_DESC_REQUEST,
                               version, 0);
        qdr14 = ofpbuf_put_zeros(request, sizeof *qdr14);
        qdr14->port = ofputil_port_to_ofp11(port);
        qdr14->queue = htonl(queue);
    }

    return request;
}

/* Parses OFPT_QUEUE_GET_CONFIG request 'oh', storing the port specified by the
 * request into '*port'.  Returns 0 if successful, otherwise an OpenFlow error
 * code. */
enum ofperr
ofputil_decode_queue_get_config_request(const struct ofp_header *oh,
                                        ofp_port_t *port, uint32_t *queue)
{
    const struct ofp10_queue_get_config_request *qgcr10;
    const struct ofp11_queue_get_config_request *qgcr11;
    const struct ofp14_queue_desc_request *qdr14;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);

    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        qgcr10 = b.data;
        *port = u16_to_ofp(ntohs(qgcr10->port));
        *queue = OFPQ_ALL;
        break;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        qgcr11 = b.data;
        *queue = OFPQ_ALL;
        enum ofperr error = ofputil_port_from_ofp11(qgcr11->port, port);
        if (error || *port == OFPP_ANY) {
            return error;
        }
        break;

    case OFPRAW_OFPST14_QUEUE_DESC_REQUEST:
        qdr14 = b.data;
        *queue = ntohl(qdr14->queue);
        return ofputil_port_from_ofp11(qdr14->port, port);

    default:
        OVS_NOT_REACHED();
    }

    return (ofp_to_u16(*port) < ofp_to_u16(OFPP_MAX)
            ? 0
            : OFPERR_OFPQOFC_BAD_PORT);
}

enum ofperr
ofputil_queue_get_config_request_format(
    struct ds *string, const struct ofp_header *oh,
    const struct ofputil_port_map *port_map)
{
    enum ofperr error;
    ofp_port_t port;
    uint32_t queue;

    error = ofputil_decode_queue_get_config_request(oh, &port, &queue);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port=");
    ofputil_format_port(port, port_map, string);

    if (queue != OFPQ_ALL) {
        ds_put_cstr(string, " queue=");
        ofp_print_queue_name(string, queue);
    }

    return 0;
}

/* Constructs and returns the beginning of a reply to
 * OFPT_QUEUE_GET_CONFIG_REQUEST or OFPMP_QUEUE_DESC request 'oh'.  The caller
 * may append information about individual queues with
 * ofputil_append_queue_get_config_reply(). */
void
ofputil_start_queue_get_config_reply(const struct ofp_header *request,
                                     struct ovs_list *replies)
{
    struct ofpbuf *reply;
    ofp_port_t port;
    uint32_t queue;

    ovs_assert(!ofputil_decode_queue_get_config_request(request, &port,
                                                        &queue));

    enum ofpraw raw = ofpraw_decode_assert(request);
    switch ((int) raw) {
    case OFPRAW_OFPT10_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY,
                                   request, 0);
        struct ofp10_queue_get_config_reply *qgcr10
            = ofpbuf_put_zeros(reply, sizeof *qgcr10);
        qgcr10->port = htons(ofp_to_u16(port));
        break;

    case OFPRAW_OFPT11_QUEUE_GET_CONFIG_REQUEST:
        reply = ofpraw_alloc_reply(OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY,
                                   request, 0);
        struct ofp11_queue_get_config_reply *qgcr11
            = ofpbuf_put_zeros(reply, sizeof *qgcr11);
        qgcr11->port = ofputil_port_to_ofp11(port);
        break;

    case OFPRAW_OFPST14_QUEUE_DESC_REQUEST:
        reply = ofpraw_alloc_stats_reply(request, 0);
        break;

    default:
        OVS_NOT_REACHED();
    }

    ovs_list_init(replies);
    ovs_list_push_back(replies, &reply->list_node);
}

static void
put_ofp10_queue_rate(struct ofpbuf *reply,
                     enum ofp10_queue_properties property, uint16_t rate)
{
    if (rate != UINT16_MAX) {
        struct ofp10_queue_prop_rate *oqpr;

        oqpr = ofpbuf_put_zeros(reply, sizeof *oqpr);
        oqpr->prop_header.property = htons(property);
        oqpr->prop_header.len = htons(sizeof *oqpr);
        oqpr->rate = htons(rate);
    }
}

static void
put_ofp14_queue_rate(struct ofpbuf *reply,
                     enum ofp14_queue_desc_prop_type type, uint16_t rate)
{
    if (rate != UINT16_MAX) {
        ofpprop_put_u16(reply, type, rate);
    }
}

void
ofputil_append_queue_get_config_reply(const struct ofputil_queue_config *qc,
                                      struct ovs_list *replies)
{
    enum ofp_version ofp_version = ofpmp_version(replies);
    struct ofpbuf *reply = ofpbuf_from_list(ovs_list_back(replies));
    size_t start_ofs = reply->size;
    size_t len_ofs;
    ovs_be16 *len;

    if (ofp_version < OFP14_VERSION) {
        if (ofp_version < OFP12_VERSION) {
            struct ofp10_packet_queue *opq10;

            opq10 = ofpbuf_put_zeros(reply, sizeof *opq10);
            opq10->queue_id = htonl(qc->queue);
            len_ofs = (char *) &opq10->len - (char *) reply->data;
        } else {
            struct ofp12_packet_queue *opq12;

            opq12 = ofpbuf_put_zeros(reply, sizeof *opq12);
            opq12->port = ofputil_port_to_ofp11(qc->port);
            opq12->queue_id = htonl(qc->queue);
            len_ofs = (char *) &opq12->len - (char *) reply->data;
        }

        put_ofp10_queue_rate(reply, OFPQT10_MIN_RATE, qc->min_rate);
        put_ofp10_queue_rate(reply, OFPQT11_MAX_RATE, qc->max_rate);
    } else {
        struct ofp14_queue_desc *oqd = ofpbuf_put_zeros(reply, sizeof *oqd);
        oqd->port_no = ofputil_port_to_ofp11(qc->port);
        oqd->queue_id = htonl(qc->queue);
        len_ofs = (char *) &oqd->len - (char *) reply->data;
        put_ofp14_queue_rate(reply, OFPQDPT14_MIN_RATE, qc->min_rate);
        put_ofp14_queue_rate(reply, OFPQDPT14_MAX_RATE, qc->max_rate);
    }

    len = ofpbuf_at(reply, len_ofs, sizeof *len);
    *len = htons(reply->size - start_ofs);

    if (ofp_version >= OFP14_VERSION) {
        ofpmp_postappend(replies, start_ofs);
    }
}

static enum ofperr
parse_ofp10_queue_rate(const struct ofp10_queue_prop_header *hdr,
                       uint16_t *rate)
{
    const struct ofp10_queue_prop_rate *oqpr;

    if (hdr->len == htons(sizeof *oqpr)) {
        oqpr = (const struct ofp10_queue_prop_rate *) hdr;
        *rate = ntohs(oqpr->rate);
        return 0;
    } else {
        return OFPERR_OFPBRC_BAD_LEN;
    }
}

static int
ofputil_pull_queue_get_config_reply10(struct ofpbuf *msg,
                                      struct ofputil_queue_config *queue)
{
    const struct ofp_header *oh = msg->header;
    unsigned int opq_len;       /* Length of protocol-specific queue header. */
    unsigned int len;           /* Total length of queue + properties. */

    /* Obtain the port number from the message header. */
    if (oh->version == OFP10_VERSION) {
        const struct ofp10_queue_get_config_reply *oqgcr10 = msg->msg;
        queue->port = u16_to_ofp(ntohs(oqgcr10->port));
    } else {
        const struct ofp11_queue_get_config_reply *oqgcr11 = msg->msg;
        enum ofperr error = ofputil_port_from_ofp11(oqgcr11->port,
                                                    &queue->port);
        if (error) {
            return error;
        }
    }

    /* Pull off the queue header and get the queue number and length. */
    if (oh->version < OFP12_VERSION) {
        const struct ofp10_packet_queue *opq10;
        opq10 = ofpbuf_try_pull(msg, sizeof *opq10);
        if (!opq10) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue = ntohl(opq10->queue_id);
        len = ntohs(opq10->len);
        opq_len = sizeof *opq10;
    } else {
        const struct ofp12_packet_queue *opq12;
        opq12 = ofpbuf_try_pull(msg, sizeof *opq12);
        if (!opq12) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        queue->queue = ntohl(opq12->queue_id);
        len = ntohs(opq12->len);
        opq_len = sizeof *opq12;
    }

    /* Length check. */
    if (len < opq_len || len > msg->size + opq_len || len % 8) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= opq_len;

    /* Pull properties.  The format of these properties differs from used in
     * OF1.4+ so we can't use the common property functions. */
    while (len > 0) {
        const struct ofp10_queue_prop_header *hdr;
        unsigned int property;
        unsigned int prop_len;
        enum ofperr error = 0;

        hdr = ofpbuf_at_assert(msg, 0, sizeof *hdr);
        prop_len = ntohs(hdr->len);
        if (prop_len < sizeof *hdr || prop_len > len || prop_len % 8) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        property = ntohs(hdr->property);
        switch (property) {
        case OFPQT10_MIN_RATE:
            error = parse_ofp10_queue_rate(hdr, &queue->min_rate);
            break;

        case OFPQT11_MAX_RATE:
            error = parse_ofp10_queue_rate(hdr, &queue->max_rate);
            break;

        default:
            VLOG_INFO_RL(&rl, "unknown queue property %u", property);
            break;
        }
        if (error) {
            return error;
        }

        ofpbuf_pull(msg, prop_len);
        len -= prop_len;
    }
    return 0;
}

static int
ofputil_pull_queue_get_config_reply14(struct ofpbuf *msg,
                                      struct ofputil_queue_config *queue)
{
    struct ofp14_queue_desc *oqd14 = ofpbuf_try_pull(msg, sizeof *oqd14);
    if (!oqd14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    enum ofperr error = ofputil_port_from_ofp11(oqd14->port_no, &queue->port);
    if (error) {
        return error;
    }
    queue->queue = ntohl(oqd14->queue_id);

    /* Length check. */
    unsigned int len = ntohs(oqd14->len);
    if (len < sizeof *oqd14 || len > msg->size + sizeof *oqd14 || len % 8) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    len -= sizeof *oqd14;

    struct ofpbuf properties = ofpbuf_const_initializer(ofpbuf_pull(msg, len),
                                                        len);
    while (properties.size > 0) {
        struct ofpbuf payload;
        uint64_t type;

        error = ofpprop_pull(&properties, &payload, &type);
        if (error) {
            return error;
        }

        switch (type) {
        case OFPQDPT14_MIN_RATE:
            error = ofpprop_parse_u16(&payload, &queue->min_rate);
            break;

        case OFPQDPT14_MAX_RATE:
            error = ofpprop_parse_u16(&payload, &queue->max_rate);
            break;

        default:
            error = OFPPROP_UNKNOWN(true, "queue desc", type);
            break;
        }

        if (error) {
            return error;
        }
    }

    return 0;
}

/* Decodes information about a queue from the OFPT_QUEUE_GET_CONFIG_REPLY in
 * 'reply' and stores it in '*queue'.  ofputil_decode_queue_get_config_reply()
 * must already have pulled off the main header.
 *
 * This function returns EOF if the last queue has already been decoded, 0 if a
 * queue was successfully decoded into '*queue', or an ofperr if there was a
 * problem decoding 'reply'. */
int
ofputil_pull_queue_get_config_reply(struct ofpbuf *msg,
                                    struct ofputil_queue_config *queue)
{
    enum ofpraw raw;
    if (!msg->header) {
        /* Pull OpenFlow header. */
        raw = ofpraw_pull_assert(msg);

        /* Pull protocol-specific ofp_queue_get_config_reply header (OF1.4
         * doesn't have one at all). */
        if (raw == OFPRAW_OFPT10_QUEUE_GET_CONFIG_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp10_queue_get_config_reply));
        } else if (raw == OFPRAW_OFPT11_QUEUE_GET_CONFIG_REPLY) {
            ofpbuf_pull(msg, sizeof(struct ofp11_queue_get_config_reply));
        } else {
            ovs_assert(raw == OFPRAW_OFPST14_QUEUE_DESC_REPLY);
        }
    } else {
        raw = ofpraw_decode_assert(msg->header);
    }

    queue->min_rate = UINT16_MAX;
    queue->max_rate = UINT16_MAX;

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_QUEUE_DESC_REPLY) {
        return ofputil_pull_queue_get_config_reply14(msg, queue);
    } else {
        return ofputil_pull_queue_get_config_reply10(msg, queue);
    }
}

static void
print_queue_rate(struct ds *string, const char *name, unsigned int rate)
{
    if (rate <= 1000) {
        ds_put_format(string, " %s:%u.%u%%", name, rate / 10, rate % 10);
    } else if (rate < UINT16_MAX) {
        ds_put_format(string, " %s:(disabled)", name);
    }
}

/* qsort comparison function. */
static int
compare_queues(const void *a_, const void *b_)
{
    const struct ofputil_queue_config *a = a_;
    const struct ofputil_queue_config *b = b_;

    uint16_t ap = ofp_to_u16(a->port);
    uint16_t bp = ofp_to_u16(b->port);
    if (ap != bp) {
        return ap < bp ? -1 : 1;
    }

    uint32_t aq = a->queue;
    uint32_t bq = b->queue;
    return aq < bq ? -1 : aq > bq;
}

enum ofperr
ofputil_queue_get_config_reply_format(struct ds *string,
                                      const struct ofp_header *oh,
                                      const struct ofputil_port_map *port_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    struct ofputil_queue_config *queues = NULL;
    size_t allocated_queues = 0;
    size_t n = 0;

    int retval = 0;
    for (;;) {
        if (n >= allocated_queues) {
            queues = x2nrealloc(queues, &allocated_queues, sizeof *queues);
        }
        retval = ofputil_pull_queue_get_config_reply(&b, &queues[n]);
        if (retval) {
            break;
        }
        n++;
    }

    qsort(queues, n, sizeof *queues, compare_queues);

    ds_put_char(string, ' ');

    ofp_port_t port = 0;
    for (const struct ofputil_queue_config *q = queues; q < &queues[n]; q++) {
        if (q->port != port) {
            port = q->port;

            ds_put_cstr(string, "port=");
            ofputil_format_port(port, port_map, string);
            ds_put_char(string, '\n');
        }

        ds_put_format(string, "queue %"PRIu32":", q->queue);
        print_queue_rate(string, "min_rate", q->min_rate);
        print_queue_rate(string, "max_rate", q->max_rate);
        ds_put_char(string, '\n');
    }

    ds_chomp(string, ' ');
    free(queues);

    return retval != EOF ? retval : 0;
}

/* Parse a queue status request message into 'oqsr'.
 * Returns 0 if successful, otherwise an OFPERR_* number. */
enum ofperr
ofputil_decode_queue_stats_request(const struct ofp_header *request,
                                   struct ofputil_queue_stats_request *oqsr)
{
    switch ((enum ofp_version)request->version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION: {
        const struct ofp11_queue_stats_request *qsr11 = ofpmsg_body(request);
        oqsr->queue_id = ntohl(qsr11->queue_id);
        return ofputil_port_from_ofp11(qsr11->port_no, &oqsr->port_no);
    }

    case OFP10_VERSION: {
        const struct ofp10_queue_stats_request *qsr10 = ofpmsg_body(request);
        oqsr->queue_id = ntohl(qsr10->queue_id);
        oqsr->port_no = u16_to_ofp(ntohs(qsr10->port_no));
        /* OF 1.0 uses OFPP_ALL for OFPP_ANY */
        if (oqsr->port_no == OFPP_ALL) {
            oqsr->port_no = OFPP_ANY;
        }
        return 0;
    }

    default:
        OVS_NOT_REACHED();
    }
}

/* Encode a queue stats request for 'oqsr', the encoded message
 * will be for OpenFlow version 'ofp_version'. Returns message
 * as a struct ofpbuf. Returns encoded message on success, NULL on error. */
struct ofpbuf *
ofputil_encode_queue_stats_request(
    enum ofp_version ofp_version,
    const struct ofputil_queue_stats_request *oqsr)
{
    struct ofpbuf *request;

    switch (ofp_version) {
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp11_queue_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST11_QUEUE_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        req->port_no = ofputil_port_to_ofp11(oqsr->port_no);
        req->queue_id = htonl(oqsr->queue_id);
        break;
    }
    case OFP10_VERSION: {
        struct ofp10_queue_stats_request *req;
        request = ofpraw_alloc(OFPRAW_OFPST10_QUEUE_REQUEST, ofp_version, 0);
        req = ofpbuf_put_zeros(request, sizeof *req);
        /* OpenFlow 1.0 needs OFPP_ALL instead of OFPP_ANY */
        req->port_no = htons(ofp_to_u16(oqsr->port_no == OFPP_ANY
                                        ? OFPP_ALL : oqsr->port_no));
        req->queue_id = htonl(oqsr->queue_id);
        break;
    }
    default:
        OVS_NOT_REACHED();
    }

    return request;
}

enum ofperr
ofputil_queue_stats_request_format(struct ds *string,
                                   const struct ofp_header *oh,
                                   const struct ofputil_port_map *port_map)
{
    struct ofputil_queue_stats_request oqsr;
    enum ofperr error;

    error = ofputil_decode_queue_stats_request(oh, &oqsr);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port=");
    ofputil_format_port(oqsr.port_no, port_map, string);

    ds_put_cstr(string, " queue=");
    ofp_print_queue_name(string, oqsr.queue_id);

    return 0;
}

/* Returns the number of queue stats elements in OFPTYPE_QUEUE_STATS_REPLY
 * message 'oh'. */
size_t
ofputil_count_queue_stats(const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    for (size_t n = 0; ; n++) {
        struct ofputil_queue_stats qs;
        if (ofputil_decode_queue_stats(&qs, &b)) {
            return n;
        }
    }
}

static enum ofperr
ofputil_queue_stats_from_ofp10(struct ofputil_queue_stats *oqs,
                               const struct ofp10_queue_stats *qs10)
{
    oqs->port_no = u16_to_ofp(ntohs(qs10->port_no));
    oqs->queue_id = ntohl(qs10->queue_id);
    oqs->tx_bytes = ntohll(get_32aligned_be64(&qs10->tx_bytes));
    oqs->tx_packets = ntohll(get_32aligned_be64(&qs10->tx_packets));
    oqs->tx_errors = ntohll(get_32aligned_be64(&qs10->tx_errors));
    oqs->duration_sec = oqs->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_queue_stats_from_ofp11(struct ofputil_queue_stats *oqs,
                               const struct ofp11_queue_stats *qs11)
{
    enum ofperr error;

    error = ofputil_port_from_ofp11(qs11->port_no, &oqs->port_no);
    if (error) {
        return error;
    }

    oqs->queue_id = ntohl(qs11->queue_id);
    oqs->tx_bytes = ntohll(qs11->tx_bytes);
    oqs->tx_packets = ntohll(qs11->tx_packets);
    oqs->tx_errors = ntohll(qs11->tx_errors);
    oqs->duration_sec = oqs->duration_nsec = UINT32_MAX;

    return 0;
}

static enum ofperr
ofputil_queue_stats_from_ofp13(struct ofputil_queue_stats *oqs,
                               const struct ofp13_queue_stats *qs13)
{
    enum ofperr error = ofputil_queue_stats_from_ofp11(oqs, &qs13->qs);
    if (!error) {
        oqs->duration_sec = ntohl(qs13->duration_sec);
        oqs->duration_nsec = ntohl(qs13->duration_nsec);
    }

    return error;
}

static enum ofperr
ofputil_pull_ofp14_queue_stats(struct ofputil_queue_stats *oqs,
                               struct ofpbuf *msg)
{
    const struct ofp14_queue_stats *qs14;
    size_t len;

    qs14 = ofpbuf_try_pull(msg, sizeof *qs14);
    if (!qs14) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    len = ntohs(qs14->length);
    if (len < sizeof *qs14 || len - sizeof *qs14 > msg->size) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    ofpbuf_pull(msg, len - sizeof *qs14);

    /* No properties yet defined, so ignore them for now. */

    return ofputil_queue_stats_from_ofp13(oqs, &qs14->qs);
}

/* Converts an OFPST_QUEUE_STATS reply in 'msg' into an abstract
 * ofputil_queue_stats in 'qs'.
 *
 * Multiple OFPST_QUEUE_STATS replies can be packed into a single OpenFlow
 * message.  Calling this function multiple times for a single 'msg' iterates
 * through the replies.  The caller must initially leave 'msg''s layer pointers
 * null and not modify them between calls.
 *
 * Returns 0 if successful, EOF if no replies were left in this 'msg',
 * otherwise a positive errno value. */
int
ofputil_decode_queue_stats(struct ofputil_queue_stats *qs, struct ofpbuf *msg)
{
    enum ofperr error;
    enum ofpraw raw;

    error = (msg->header ? ofpraw_decode(&raw, msg->header)
             : ofpraw_pull(&raw, msg));
    if (error) {
        return error;
    }

    if (!msg->size) {
        return EOF;
    } else if (raw == OFPRAW_OFPST14_QUEUE_REPLY) {
        return ofputil_pull_ofp14_queue_stats(qs, msg);
    } else if (raw == OFPRAW_OFPST13_QUEUE_REPLY) {
        const struct ofp13_queue_stats *qs13;

        qs13 = ofpbuf_try_pull(msg, sizeof *qs13);
        if (!qs13) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp13(qs, qs13);
    } else if (raw == OFPRAW_OFPST11_QUEUE_REPLY) {
        const struct ofp11_queue_stats *qs11;

        qs11 = ofpbuf_try_pull(msg, sizeof *qs11);
        if (!qs11) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp11(qs, qs11);
    } else if (raw == OFPRAW_OFPST10_QUEUE_REPLY) {
        const struct ofp10_queue_stats *qs10;

        qs10 = ofpbuf_try_pull(msg, sizeof *qs10);
        if (!qs10) {
            goto bad_len;
        }
        return ofputil_queue_stats_from_ofp10(qs, qs10);
    } else {
        OVS_NOT_REACHED();
    }

 bad_len:
    VLOG_WARN_RL(&rl, "OFPST_QUEUE reply has %"PRIu32" leftover "
                 "bytes at end", msg->size);
    return OFPERR_OFPBRC_BAD_LEN;
}

static void
ofputil_queue_stats_to_ofp10(const struct ofputil_queue_stats *oqs,
                             struct ofp10_queue_stats *qs10)
{
    qs10->port_no = htons(ofp_to_u16(oqs->port_no));
    memset(qs10->pad, 0, sizeof qs10->pad);
    qs10->queue_id = htonl(oqs->queue_id);
    put_32aligned_be64(&qs10->tx_bytes, htonll(oqs->tx_bytes));
    put_32aligned_be64(&qs10->tx_packets, htonll(oqs->tx_packets));
    put_32aligned_be64(&qs10->tx_errors, htonll(oqs->tx_errors));
}

static void
ofputil_queue_stats_to_ofp11(const struct ofputil_queue_stats *oqs,
                             struct ofp11_queue_stats *qs11)
{
    qs11->port_no = ofputil_port_to_ofp11(oqs->port_no);
    qs11->queue_id = htonl(oqs->queue_id);
    qs11->tx_bytes = htonll(oqs->tx_bytes);
    qs11->tx_packets = htonll(oqs->tx_packets);
    qs11->tx_errors = htonll(oqs->tx_errors);
}

static void
ofputil_queue_stats_to_ofp13(const struct ofputil_queue_stats *oqs,
                             struct ofp13_queue_stats *qs13)
{
    ofputil_queue_stats_to_ofp11(oqs, &qs13->qs);
    if (oqs->duration_sec != UINT32_MAX) {
        qs13->duration_sec = htonl(oqs->duration_sec);
        qs13->duration_nsec = htonl(oqs->duration_nsec);
    } else {
        qs13->duration_sec = OVS_BE32_MAX;
        qs13->duration_nsec = OVS_BE32_MAX;
    }
}

static void
ofputil_queue_stats_to_ofp14(const struct ofputil_queue_stats *oqs,
                             struct ofp14_queue_stats *qs14)
{
    qs14->length = htons(sizeof *qs14);
    memset(qs14->pad, 0, sizeof qs14->pad);
    ofputil_queue_stats_to_ofp13(oqs, &qs14->qs);
}


/* Encode a queue stat for 'oqs' and append it to 'replies'. */
void
ofputil_append_queue_stat(struct ovs_list *replies,
                          const struct ofputil_queue_stats *oqs)
{
    switch (ofpmp_version(replies)) {
    case OFP13_VERSION: {
        struct ofp13_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp13(oqs, reply);
        break;
    }

    case OFP12_VERSION:
    case OFP11_VERSION: {
        struct ofp11_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp11(oqs, reply);
        break;
    }

    case OFP10_VERSION: {
        struct ofp10_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp10(oqs, reply);
        break;
    }

    case OFP14_VERSION:
    case OFP15_VERSION:
    case OFP16_VERSION: {
        struct ofp14_queue_stats *reply = ofpmp_append(replies, sizeof *reply);
        ofputil_queue_stats_to_ofp14(oqs, reply);
        break;
    }

    default:
        OVS_NOT_REACHED();
    }
}

static void
print_queue_stat(struct ds *string, const char *leader, uint64_t stat,
                 int more)
{
    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, stat);
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

enum ofperr
ofputil_queue_stats_reply_format(struct ds *string,
                                 const struct ofp_header *oh,
                                 const struct ofputil_port_map *port_map,
                                 int verbosity)
{
    ds_put_format(string, " %"PRIuSIZE" queues\n",
                  ofputil_count_queue_stats(oh));
    if (verbosity < 1) {
        return 0;
    }

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_queue_stats qs;
        int retval;

        retval = ofputil_decode_queue_stats(&qs, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_cstr(string, "  port ");
        ofputil_format_port(qs.port_no, port_map, string);
        ds_put_cstr(string, " queue ");
        ofp_print_queue_name(string, qs.queue_id);
        ds_put_cstr(string, ": ");

        print_queue_stat(string, "bytes=", qs.tx_bytes, 1);
        print_queue_stat(string, "pkts=", qs.tx_packets, 1);
        print_queue_stat(string, "errors=", qs.tx_errors, 1);

        ds_put_cstr(string, "duration=");
        if (qs.duration_sec != UINT32_MAX) {
            ofp_print_duration(string, qs.duration_sec, qs.duration_nsec);
        } else {
            ds_put_char(string, '?');
        }
        ds_put_char(string, '\n');
    }
}

