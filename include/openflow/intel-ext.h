/*
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
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

#ifndef OPENFLOW_INTEL_EXT_H
#define OPENFLOW_INTEL_EXT_H

/* This file presents Intel vendor extension. It is not anyhow
 * standardized, so all those definitions are not part of
 * official openflow headers (openflow.h).  Nevertheless below
 * features introduces real value so it could be suitable for
 * standardization */

/* Intel extended statistics type */

enum intel_port_stats_subtype {
    INTEL_PORT_STATS_RFC2819 = 1,
    INTEL_PORT_STATS_CUSTOM
};

#define INTEL_PORT_STATS_RFC2819_SIZE 184
#define INTEL_PORT_STATS_CUSTOM_SIZE 16

/* Struct implements custom property type based on
 * 'ofp_prop_experimenter'. */
struct intel_port_stats_rfc2819 {
    ovs_be16 type;              /* OFPPSPT14_EXPERIMENTER. */
    ovs_be16 length;            /* Length in bytes of this property excluding
                                 * trailing padding. */
    ovs_be32 experimenter;      /* INTEL_VENDOR_ID. */
    ovs_be32 exp_type;          /* INTEL_PORT_STATS_*. */

    uint8_t pad[4];

    ovs_be64 rx_1_to_64_packets;
    ovs_be64 rx_65_to_127_packets;
    ovs_be64 rx_128_to_255_packets;
    ovs_be64 rx_256_to_511_packets;
    ovs_be64 rx_512_to_1023_packets;
    ovs_be64 rx_1024_to_1522_packets;
    ovs_be64 rx_1523_to_max_packets;

    ovs_be64 tx_1_to_64_packets;
    ovs_be64 tx_65_to_127_packets;
    ovs_be64 tx_128_to_255_packets;
    ovs_be64 tx_256_to_511_packets;
    ovs_be64 tx_512_to_1023_packets;
    ovs_be64 tx_1024_to_1522_packets;
    ovs_be64 tx_1523_to_max_packets;

    ovs_be64 tx_multicast_packets;
    ovs_be64 rx_broadcast_packets;
    ovs_be64 tx_broadcast_packets;
    ovs_be64 rx_undersized_errors;
    ovs_be64 rx_oversize_errors;
    ovs_be64 rx_fragmented_errors;
    ovs_be64 rx_jabber_errors;

};
OFP_ASSERT(sizeof (struct intel_port_stats_rfc2819) ==
           INTEL_PORT_STATS_RFC2819_SIZE);

/* Structure implements custom property type based on
 * 'ofp_prop_experimenter'. It contains custom
 * statistics in dictionary format */
struct intel_port_custom_stats {
    ovs_be16 type;              /* OFPPSPT14_EXPERIMENTER. */
    ovs_be16 length;            /* Length in bytes of this property excluding
                                 * trailing padding. */
    ovs_be32 experimenter;      /* INTEL_VENDOR_ID. */
    ovs_be32 exp_type;          /* INTEL_PORT_STATS_*. */

    uint8_t pad[2];
    ovs_be16 stats_array_size;  /* number of counters. */

    /* Followed by:
     *   - Exactly 'stats_array_size' array elements of
     *     dynamic structure which contains:
     *     - "NAME SIZE" - counter name size (number of characters)
     *     - "COUNTER NAME" - Exact number of characters
     *       defined by "NAME SIZE".
     *     - "COUNTER VALUE" -  ovs_be64 counter value,
     *   - Zero or more bytes to fill out the
     *     overall length in header.length. */
};
OFP_ASSERT(sizeof(struct intel_port_custom_stats) ==
                                  INTEL_PORT_STATS_CUSTOM_SIZE);

#endif /* openflow/intel-ext.h */
