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

#ifndef OPENFLOW_NETLINK_H
#define OPENFLOW_NETLINK_H 1

#include <linux/netlink.h>

#define DP_GENL_FAMILY_NAME "OpenFlow"

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
	DP_GENL_A_UNSPEC,
    DP_GENL_A_OFPHEADER, /* OFP header information */
	DP_GENL_A_DP_IDX,	 /* Datapath Ethernet device name. */
	DP_GENL_A_PORTNAME,	 /* Device name for datapath port. */
	DP_GENL_A_MC_GROUP,	 /* Generic netlink multicast group. */
	DP_GENL_A_OPENFLOW,  /* OpenFlow packet. */

    DP_GENL_A_DP_INFO,   /* OpenFlow datapath information */

    DP_GENL_A_FLOW,      /* OpenFlow flow entry */
    DP_GENL_A_NUMFLOWS,  /* Number of flows  */
    DP_GENL_A_TABLEIDX,  /* Flow table index */

    DP_GENL_A_TABLE,     /* OpenFlow table entry */
    DP_GENL_A_NUMTABLES, /* Number of tables in a table query */

    DP_GENL_A_NPACKETS,  /* Number of packets to send up netlink */
    DP_GENL_A_PSIZE,     /* Size of packets to send up netlink */

	__DP_GENL_A_MAX,
	DP_GENL_A_MAX = __DP_GENL_A_MAX - 1
};

/* Commands that can be executed on the datapath's netlink interface. */
enum dp_genl_command {
	DP_GENL_C_UNSPEC,
	DP_GENL_C_ADD_DP,	 /* Create datapath. */
	DP_GENL_C_DEL_DP,	 /* Destroy datapath. */
	DP_GENL_C_QUERY_DP,	 /* Get multicast group for datapath. */
	DP_GENL_C_SHOW_DP,	 /* Show information about datapath. */
	DP_GENL_C_ADD_PORT,	 /* Add port to datapath. */
	DP_GENL_C_DEL_PORT,	 /* Remove port from datapath. */
	DP_GENL_C_OPENFLOW,  /* Encapsulated OpenFlow protocol. */

    DP_GENL_C_QUERY_FLOW,  /* Request flow entries. */
    DP_GENL_C_QUERY_TABLE, /* Request table entries. */

    DP_GENL_C_BENCHMARK_NL, /* Benchmark netlink connection */

	__DP_GENL_C_MAX,
	DP_GENL_C_MAX = __DP_GENL_C_MAX - 1
};

/* Table */
enum {
    TBL_MACONLY,
    TBL_HASH,
    TBL_LINEAR,
     __TBL_MAX,
     TBL_MAX = __TBL_MAX - 1
};

#endif /* openflow_netlink_h */
