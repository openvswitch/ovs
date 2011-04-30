/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include "openvswitch/datapath-protocol.h"

/* ODP_VPORT_ATTR_OPTIONS attributes for tunnels.
 *
 * ODP_TUNNEL_ATTR_FLAGS and ODP_TUNNEL_ATTR_DST_IPV4 are required.  All other
 * attributes are optional.
 */
enum {
	ODP_TUNNEL_ATTR_UNSPEC,
	ODP_TUNNEL_ATTR_FLAGS,    /* 32-bit TNL_F_*. */
	ODP_TUNNEL_ATTR_DST_IPV4, /* IPv4 destination address. */
	ODP_TUNNEL_ATTR_SRC_IPV4, /* IPv4 source address. */
	ODP_TUNNEL_ATTR_OUT_KEY,  /* __be64 key to use on output. */
	ODP_TUNNEL_ATTR_IN_KEY,   /* __be64 key to match on input. */
	ODP_TUNNEL_ATTR_TOS,      /* 8-bit TOS value. */
	ODP_TUNNEL_ATTR_TTL,      /* 8-bit TTL value. */
	__ODP_TUNNEL_ATTR_MAX
};

#define ODP_TUNNEL_ATTR_MAX (__ODP_TUNNEL_ATTR_MAX - 1)

#define TNL_F_CSUM		(1 << 0) /* Checksum packets. */
#define TNL_F_TOS_INHERIT	(1 << 1) /* Inherit the ToS from the inner packet. */
#define TNL_F_TTL_INHERIT	(1 << 2) /* Inherit the TTL from the inner packet. */
#define TNL_F_DF_INHERIT	(1 << 3) /* Inherit the DF bit from the inner packet. */
#define TNL_F_DF_DEFAULT	(1 << 4) /* Set the DF bit if inherit off or not IP. */
#define TNL_F_PMTUD		(1 << 5) /* Enable path MTU discovery. */
#define TNL_F_HDR_CACHE		(1 << 6) /* Enable tunnel header caching. */
#define TNL_F_IPSEC		(1 << 7) /* Traffic is IPsec encrypted. */

#endif /* openvswitch/tunnel.h */
