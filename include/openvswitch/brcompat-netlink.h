/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * ----------------------------------------------------------------------
 */

#ifndef OPENVSWITCH_BRCOMPAT_NETLINK_H
#define OPENVSWITCH_BRCOMPAT_NETLINK_H 1

#define BRC_GENL_FAMILY_NAME "brcompat"

/* Attributes that can be attached to the datapath's netlink messages. */
enum {
	BRC_GENL_A_UNSPEC,

	/*
	 * "K:" attributes appear in messages from the kernel to userspace.
	 * "U:" attributes appear in messages from userspace to the kernel.
	 */

	/* BRC_GENL_C_DP_ADD, BRC_GENL_C_DP_DEL. */
	BRC_GENL_A_DP_NAME,		/* K: Datapath name. */

	/* BRC_GENL_C_DP_ADD, BRC_GENL_C_DP_DEL,
	   BRC_GENL_C_PORT_ADD, BRC_GENL_C_PORT_DEL. */
	BRC_GENL_A_PORT_NAME,	/* K: Interface name. */

	/* BRC_GENL_C_DP_RESULT. */
	BRC_GENL_A_ERR_CODE,	/* U: Positive error code. */

	/* BRC_GENL_C_QUERY_MC. */
	BRC_GENL_A_MC_GROUP,	/* K: Generic netlink multicast group. */

	/* BRC_GENL_C_FDB_QUERY. */
	BRC_GENL_A_FDB_COUNT,	/* K: Number of FDB entries to read. */
	BRC_GENL_A_FDB_SKIP,	/* K: Record offset into FDB to start reading. */

	/* BRC_GENL_C_DP_RESULT. */
	BRC_GENL_A_FDB_DATA,    /* U: FDB records. */
	BRC_GENL_A_IFINDEXES,   /* U: "int" ifindexes of bridges or ports. */

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
	BRC_GENL_C_DP_ADD,		/* K: Datapath created. */
	BRC_GENL_C_DP_DEL,		/* K: Datapath destroyed. */
	BRC_GENL_C_DP_RESULT,	/* U: Return code from ovs-brcompatd. */
	BRC_GENL_C_PORT_ADD,	/* K: Port added to datapath. */
	BRC_GENL_C_PORT_DEL,	/* K: Port removed from datapath. */
	BRC_GENL_C_QUERY_MC,	/* U: Get multicast group for brcompat. */
	BRC_GENL_C_FDB_QUERY,	/* K: Read records from forwarding database. */
	BRC_GENL_C_GET_BRIDGES, /* K: Get ifindexes of all bridges. */
	BRC_GENL_C_GET_PORTS,   /* K: Get ifindexes of all ports on a bridge. */

	__BRC_GENL_C_MAX,
	BRC_GENL_C_MAX = __BRC_GENL_C_MAX - 1
};
#endif /* openvswitch/brcompat-netlink.h */
