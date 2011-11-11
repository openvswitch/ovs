/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/etherdevice.h>

#include "vport-generic.h"

unsigned vport_gen_get_dev_flags(const struct vport *vport)
{
	return IFF_UP | IFF_RUNNING | IFF_LOWER_UP;
}

int vport_gen_is_running(const struct vport *vport)
{
	return 1;
}

unsigned char vport_gen_get_operstate(const struct vport *vport)
{
	return IF_OPER_UP;
}
