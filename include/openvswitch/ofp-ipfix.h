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

#ifndef OPENVSWITCH_OFP_IPFIX_H
#define OPENVSWITCH_OFP_IPFIX_H 1

#include "openflow/openflow.h"

struct ofpbuf;
struct ovs_list;

#ifdef __cplusplus
extern "C" {
#endif

struct ofputil_ipfix_stats {
    uint32_t collector_set_id;  /* Used only for flow-based IPFIX statistics. */
    uint64_t total_flows;  /* Totabl flows of this IPFIX exporter. */
    uint64_t current_flows;  /* Current flows of this IPFIX exporter. */
    uint64_t pkts;  /* Successfully sampled packets. */
    uint64_t ipv4_pkts;  /* Successfully sampled IPV4 packets. */
    uint64_t ipv6_pkts;  /* Successfully sampled IPV6 packets. */
    uint64_t error_pkts;  /* Error packets when sampling. */
    uint64_t ipv4_error_pkts;  /* Error IPV4 packets when sampling. */
    uint64_t ipv6_error_pkts;  /* Error IPV6 packets when sampling. */
    uint64_t tx_pkts;  /* TX IPFIX packets. */
    uint64_t tx_errors;  /* IPFIX packets TX errors. */
};

void ofputil_append_ipfix_stat(struct ovs_list *replies,
                              const struct ofputil_ipfix_stats *);
size_t ofputil_count_ipfix_stats(const struct ofp_header *);
int ofputil_pull_ipfix_stats(struct ofputil_ipfix_stats *, struct ofpbuf *msg);

#ifdef __cplusplus
}
#endif

#endif  /* ofp-ipfix.h */
