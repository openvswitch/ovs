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

#ifndef VPORT_GENERIC_H
#define VPORT_GENERIC_H 1

#include "vport.h"

unsigned ovs_vport_gen_get_dev_flags(const struct vport *);
int ovs_vport_gen_is_running(const struct vport *);
unsigned char ovs_vport_gen_get_operstate(const struct vport *);

#endif /* vport-generic.h */
