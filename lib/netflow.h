/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#ifndef NETFLOW_H
#define NETFLOW_H 1

/* NetFlow v5 protocol definitions. */

#include <stdint.h>
#include "openvswitch/types.h"
#include "util.h"

#define NETFLOW_V5_VERSION 5

/* Every NetFlow v5 message contains the header that follows.  This is
 * followed by up to thirty records that describe a terminating flow.
 * We only send a single record per NetFlow message.
 */
struct netflow_v5_header {
    ovs_be16 version;              /* NetFlow version is 5. */
    ovs_be16 count;                /* Number of records in this message. */
    ovs_be32 sysuptime;            /* System uptime in milliseconds. */
    ovs_be32 unix_secs;            /* Number of seconds since Unix epoch. */
    ovs_be32 unix_nsecs;           /* Number of residual nanoseconds
                                      after epoch seconds. */
    ovs_be32 flow_seq;             /* Number of flows since sending
                                      messages began. */
    uint8_t  engine_type;          /* Engine type. */
    uint8_t  engine_id;            /* Engine id. */
    ovs_be16 sampling_interval;    /* Set to zero. */
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_header) == 24);

/* A NetFlow v5 description of a terminating flow.  It is preceded by a
 * NetFlow v5 header.
 */
struct netflow_v5_record {
    ovs_be32 src_addr;             /* Source IP address. */
    ovs_be32 dst_addr;             /* Destination IP address. */
    ovs_be32 nexthop;              /* IP address of next hop.  Set to 0. */
    ovs_be16 input;                /* Input interface index. */
    ovs_be16 output;               /* Output interface index. */
    ovs_be32 packet_count;         /* Number of packets. */
    ovs_be32 byte_count;           /* Number of bytes. */
    ovs_be32 init_time;            /* Value of sysuptime on first packet. */
    ovs_be32 used_time;            /* Value of sysuptime on last packet. */

    /* The 'src_port' and 'dst_port' identify the source and destination
     * port, respectively, for TCP and UDP.  For ICMP, the high-order
     * byte identifies the type and low-order byte identifies the code
     * in the 'dst_port' field. */
    ovs_be16 src_port;
    ovs_be16 dst_port;

    uint8_t  pad1;
    uint8_t  tcp_flags;            /* Union of seen TCP flags. */
    uint8_t  ip_proto;             /* IP protocol. */
    uint8_t  ip_tos;               /* IP TOS value. */
    ovs_be16 src_as;               /* Source AS ID.  Set to 0. */
    ovs_be16 dst_as;               /* Destination AS ID.  Set to 0. */
    uint8_t  src_mask;             /* Source mask bits.  Set to 0. */
    uint8_t  dst_mask;             /* Destination mask bits.  Set to 0. */
    uint8_t  pad[2];
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_record) == 48);

#endif /* lib/netflow.h */
