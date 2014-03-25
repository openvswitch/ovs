#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#ifdef DPDK_NETDEV
#include <config.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_launch.h>
#include <rte_malloc.h>

#include "ofpbuf.h"

int dpdk_init(int argc, char **argv);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct ofpbuf *);

#else

#define dpdk_init(arg1, arg2) (0)
#define netdev_dpdk_register()
#define free_dpdk_buf(arg)

#endif /* DPDK_NETDEV */
#endif
