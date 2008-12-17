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

#ifndef NETFLOW_H
#define NETFLOW_H 1

#include <util.h>


#define NETFLOW_V5_VERSION 5

/* Every NetFlow v5 message contains the header that follows.  This is
 * followed by up to thirty records that describe a terminating flow.
 * We only send a single record per NetFlow message.
 */
struct netflow_v5_header {
    uint16_t version;              /* NetFlow version is 5. */
    uint16_t count;                /* Number of records in this message. */
    uint32_t sysuptime;            /* System uptime in milliseconds. */
    uint32_t unix_secs;            /* Number of seconds since Unix epoch. */
    uint32_t unix_nsecs;           /* Number of residual nanoseconds 
                                      after epoch seconds. */
    uint32_t flow_seq;             /* Number of flows since sending 
                                      messages began. */
    uint8_t  engine_type;          /* Set to zero. */
    uint8_t  engine_id;            /* Set to zero. */
    uint16_t sampling_interval;    /* Set to zero. */
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_header) == 24);

/* A NetFlow v5 description of a terminating flow.  It is preceded by a 
 * NetFlow v5 header. 
 */
struct netflow_v5_record {
    uint32_t src_addr;             /* Source IP address. */
    uint32_t dst_addr;             /* Destination IP address. */
    uint32_t nexthop;              /* IP address of next hop.  Set to 0. */
    uint16_t input;                /* Input interface index. */
    uint16_t output;               /* Output interface index. */
    uint32_t packet_count;         /* Number of packets. */
    uint32_t byte_count;           /* Number of bytes. */
    uint32_t init_time;            /* Value of sysuptime on first packet. */
    uint32_t used_time;            /* Value of sysuptime on last packet. */

    /* The 'src_port' and 'dst_port' identify the source and destination
     * port, respectively, for TCP and UDP.  For ICMP, the high-order
     * byte identifies the type and low-order byte identifies the code
     * in the 'dst_port' field. */
    uint16_t src_port;             
    uint16_t dst_port;            

    uint8_t  pad1;
    uint8_t  tcp_flags;            /* Union of seen TCP flags. */
    uint8_t  ip_proto;             /* IP protocol. */
    uint8_t  ip_tos;               /* IP TOS value. */
    uint16_t src_as;               /* Source AS ID.  Set to 0. */
    uint16_t dst_as;               /* Destination AS ID.  Set to 0. */
    uint8_t  src_mask;             /* Source mask bits.  Set to 0. */
    uint8_t  dst_mask;             /* Destination mask bits.  Set to 0. */
    uint8_t  pad[2];
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_record) == 48);

#endif /* netflow.h */
