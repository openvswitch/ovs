#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>
#include "ofpbuf.h"

#ifdef DPDK_NETDEV

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

int dpdk_init(int argc, char **argv);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct ofpbuf *);
int pmd_thread_setaffinity_cpu(int cpu);

#else

static inline int
dpdk_init(int arg1 OVS_UNUSED, char **arg2 OVS_UNUSED)
{
    return 0;
}

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}

static inline void
free_dpdk_buf(struct ofpbuf *buf OVS_UNUSED)
{
    /* Nothing */
}

static inline int
pmd_thread_setaffinity_cpu(int cpu OVS_UNUSED)
{
    return 0;
}

#endif /* DPDK_NETDEV */
#endif
