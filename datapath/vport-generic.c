/*
 * Copyright (c) 2007-2011 Nicira, Inc.
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

#include <linux/etherdevice.h>

#include "vport-generic.h"

unsigned ovs_vport_gen_get_dev_flags(const struct vport *vport)
{
	return IFF_UP | IFF_RUNNING | IFF_LOWER_UP;
}

int ovs_vport_gen_is_running(const struct vport *vport)
{
	return 1;
}

unsigned char ovs_vport_gen_get_operstate(const struct vport *vport)
{
	return IF_OPER_UP;
}
