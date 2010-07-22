/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/etherdevice.h>

#include "vport-generic.h"

void vport_gen_rand_ether_addr(u8 *addr)
{
	random_ether_addr(addr);

	/* Set the OUI to the Nicira one. */
	addr[0] = 0x00;
	addr[1] = 0x23;
	addr[2] = 0x20;

	/* Set the top bit to indicate random address. */
	addr[3] |= 0x80;
}

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
