/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
#include <linux/openvswitch.h>

/* OVS_VPORT_ATTR_OPTIONS attributes for tunnels.
 *
 * OVS_TUNNEL_ATTR_DST_IPV4 is required for kernel tunnel ports, all other
 * attributes are optional.
 * For flow-based tunnels, none of the options apply.
 */
enum {
	OVS_TUNNEL_ATTR_UNSPEC,
	OVS_TUNNEL_ATTR_FLAGS,    /* 32-bit TNL_F_*. */
	OVS_TUNNEL_ATTR_DST_IPV4, /* Remote IPv4 address. */
	OVS_TUNNEL_ATTR_SRC_IPV4, /* Local IPv4 address. */
	OVS_TUNNEL_ATTR_OUT_KEY,  /* __be64 key to use on output. */
	OVS_TUNNEL_ATTR_IN_KEY,   /* __be64 key to match on input. */
	OVS_TUNNEL_ATTR_TOS,      /* 8-bit TOS value. */
	OVS_TUNNEL_ATTR_TTL,      /* 8-bit TTL value. */
	__OVS_TUNNEL_ATTR_MAX
};

#define OVS_TUNNEL_ATTR_MAX (__OVS_TUNNEL_ATTR_MAX - 1)

#define TNL_F_CSUM		(1 << 0) /* Checksum packets. */
#define TNL_F_TOS_INHERIT	(1 << 1) /* Inherit ToS from inner packet. */
#define TNL_F_TTL_INHERIT	(1 << 2) /* Inherit TTL from inner packet. */
#define TNL_F_DF_INHERIT	(1 << 3) /* Inherit DF bit from inner packet. */
#define TNL_F_DF_DEFAULT	(1 << 4) /* Set DF bit if inherit off or
					  * not IP. */
/* Bit 6 is reserved since it was previously used for Tunnel header caching. */
#define TNL_F_PMTUD		(1 << 5) /* Enable path MTU discovery. */
#define TNL_F_IPSEC		(1 << 7) /* Traffic is IPsec encrypted. */

#endif /* openvswitch/tunnel.h */
