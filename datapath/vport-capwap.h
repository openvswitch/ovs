/*
 * Copyright (c) 2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef VPORT_CAPWAP_H
#define VPORT_CAPWAP_H 1

#include <linux/net.h>

struct capwap_net {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	struct socket *capwap_rcv_socket;
	struct netns_frags frag_state;
	int n_tunnels;
#endif
};

#endif /* vport-capwap.h */
