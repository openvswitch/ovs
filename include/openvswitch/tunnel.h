/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#ifndef OPENVSWITCH_TUNNEL_H
#define OPENVSWITCH_TUNNEL_H 1

#include <linux/types.h>

#define TNL_F_CSUM		(1 << 1) /* Checksum packets. */
#define TNL_F_IN_KEY_MATCH	(1 << 2) /* Store the key in tun_id to match in flow table. */
#define TNL_F_OUT_KEY_ACTION	(1 << 3) /* Get the key from a SET_TUNNEL action. */
#define TNL_F_TOS_INHERIT	(1 << 4) /* Inherit the ToS from the inner packet. */
#define TNL_F_TTL_INHERIT	(1 << 5) /* Inherit the TTL from the inner packet. */
#define TNL_F_PMTUD		(1 << 6) /* Enable path MTU discovery. */

struct tnl_port_config {
	__u32	flags;
	__be32	saddr;
	__be32	daddr;
	__be32	in_key;
	__be32	out_key;
	__u8	tos;
	__u8	ttl;
};

#endif /* openvswitch/tunnel.h */
