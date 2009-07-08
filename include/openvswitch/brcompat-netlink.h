/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OPENVSWITCH_BRCOMPAT_NETLINK_H
#define OPENVSWITCH_BRCOMPAT_NETLINK_H 1

#define BRC_GENL_FAMILY_NAME "brcompat"

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
	BRC_GENL_A_UNSPEC,
	BRC_GENL_A_DP_NAME,	    /* Datapath name. */
	BRC_GENL_A_PORT_NAME,   /* Interface name. */
	BRC_GENL_A_ERR_CODE,    /* Positive error code. */
	BRC_GENL_A_MC_GROUP,    /* Generic netlink multicast group. */
	BRC_GENL_A_PROC_DIR,    /* Name of subdirectory in /proc. */
	BRC_GENL_A_PROC_NAME,   /* Name of file in /proc. */
	BRC_GENL_A_PROC_DATA,   /* Contents of file in /proc. */

	__BRC_GENL_A_MAX,
	BRC_GENL_A_MAX = __BRC_GENL_A_MAX - 1
};

/* Commands that can be executed on the datapath's netlink interface. */
enum brc_genl_command {
	BRC_GENL_C_UNSPEC,

	/*
	 * "K:" messages are sent by the kernel to userspace.
	 * "U:" messages are sent by userspace to the kernel.
	 */
	BRC_GENL_C_DP_ADD,      /* K: Datapath created. */
	BRC_GENL_C_DP_DEL,      /* K: Datapath destroyed. */
	BRC_GENL_C_DP_RESULT,   /* U: Return code from ovs-brcompatd. */
	BRC_GENL_C_PORT_ADD,    /* K: Port added to datapath. */
	BRC_GENL_C_PORT_DEL,    /* K: Port removed from datapath. */
	BRC_GENL_C_QUERY_MC,    /* U: Get multicast group for brcompat. */
	BRC_GENL_C_SET_PROC,    /* U: Set contents of file in /proc. */

	__BRC_GENL_C_MAX,
	BRC_GENL_C_MAX = __BRC_GENL_C_MAX - 1
};
#endif /* openvswitch/brcompat-netlink.h */
