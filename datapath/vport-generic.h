/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef VPORT_GENERIC_H
#define VPORT_GENERIC_H 1

#include "vport.h"

void vport_gen_rand_ether_addr(u8 *addr);
unsigned vport_gen_get_dev_flags(const struct vport *);
int vport_gen_is_running(const struct vport *);
unsigned char vport_gen_get_operstate(const struct vport *);

#endif /* vport-generic.h */
