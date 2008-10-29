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

#ifndef OPENFLOW_OPENFLOW_NETLINK_H
#define OPENFLOW_OPENFLOW_NETLINK_H 1

#define DP_GENL_FAMILY_NAME "OpenFlow"

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
	DP_GENL_A_UNSPEC,
	DP_GENL_A_DP_IDX,	 /* Datapath Ethernet device name. */
	DP_GENL_A_PORTNAME,	 /* Device name for datapath port. */
	DP_GENL_A_MC_GROUP,	 /* Generic netlink multicast group. */
	DP_GENL_A_OPENFLOW,  /* OpenFlow packet. */

	__DP_GENL_A_MAX,
	DP_GENL_A_MAX = __DP_GENL_A_MAX - 1
};

/* Commands that can be executed on the datapath's netlink interface. */
enum dp_genl_command {
	DP_GENL_C_UNSPEC,
	DP_GENL_C_ADD_DP,	 /* Create datapath. */
	DP_GENL_C_DEL_DP,	 /* Destroy datapath. */
	DP_GENL_C_QUERY_DP,	 /* Get multicast group for datapath. */
	DP_GENL_C_ADD_PORT,	 /* Add port to datapath. */
	DP_GENL_C_DEL_PORT,	 /* Remove port from datapath. */
	DP_GENL_C_OPENFLOW,  /* Encapsulated OpenFlow protocol. */

	__DP_GENL_C_MAX,
	DP_GENL_C_MAX = __DP_GENL_C_MAX - 1
};

#endif /* openflow/openflow-netlink.h */
