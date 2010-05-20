/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef VPORT_INTERNAL_DEV_H
#define VPORT_INTERNAL_DEV_H 1

#include "datapath.h"
#include "vport.h"

int is_internal_vport(const struct vport *);

int is_internal_dev(const struct net_device *);
struct vport *internal_dev_get_vport(struct net_device *);

#endif /* vport-internal_dev.h */
