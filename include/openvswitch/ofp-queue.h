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

#ifndef OPENVSWITCH_OFP_QUEUE_H
#define OPENVSWITCH_OFP_QUEUE_H 1

#include "openflow/openflow.h"

struct ofpbuf;
struct ovs_list;

#ifdef __cplusplus
extern "C" {
#endif

/* Queue configuration reply. */
struct ofputil_queue_config {
    ofp_port_t port;
    uint32_t queue;

    /* Each of these optional values is expressed in tenths of a percent.
     * Values greater than 1000 indicate that the feature is disabled.
     * UINT16_MAX indicates that the value is omitted. */
    uint16_t min_rate;
    uint16_t max_rate;
};

void ofputil_start_queue_get_config_reply(const struct ofp_header *request,
                                          struct ovs_list *replies);
void ofputil_append_queue_get_config_reply(
    const struct ofputil_queue_config *, struct ovs_list *replies);

int ofputil_pull_queue_get_config_reply(struct ofpbuf *reply,
                                        struct ofputil_queue_config *);

struct ofputil_queue_stats_request {
    ofp_port_t port_no;           /* OFPP_ANY means "all ports". */
    uint32_t queue_id;
};

enum ofperr ofputil_decode_queue_stats_request(
    const struct ofp_header *, struct ofputil_queue_stats_request *);
struct ofpbuf *ofputil_encode_queue_stats_request(
    enum ofp_version, const struct ofputil_queue_stats_request *);

struct ofputil_queue_stats {
    ofp_port_t port_no;
    uint32_t queue_id;

    /* Values of unsupported statistics are set to all-1-bits (UINT64_MAX). */
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;

    /* UINT32_MAX if unknown. */
    uint32_t duration_sec;
    uint32_t duration_nsec;
};

size_t ofputil_count_queue_stats(const struct ofp_header *);
int ofputil_decode_queue_stats(struct ofputil_queue_stats *, struct ofpbuf *);
void ofputil_append_queue_stat(struct ovs_list *replies,
                               const struct ofputil_queue_stats *);

/* Queue configuration request. */
struct ofpbuf *ofputil_encode_queue_get_config_request(enum ofp_version,
                                                       ofp_port_t port,
                                                       uint32_t queue);
enum ofperr ofputil_decode_queue_get_config_request(const struct ofp_header *,
                                                    ofp_port_t *port,
                                                    uint32_t *queue);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-queue.h */
