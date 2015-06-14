#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

struct dp_packet;

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_errno.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_launch.h>
#include <rte_malloc.h>

#define NON_PMD_CORE_ID LCORE_ID_ANY

int dpdk_init(int argc, char **argv);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);
int pmd_thread_setaffinity_cpu(unsigned cpu);

#else

#define NON_PMD_CORE_ID UINT32_MAX

#include "util.h"

static inline int
dpdk_init(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--dpdk")) {
        ovs_fatal(0, "DPDK support not built into this copy of Open vSwitch.");
    }
    return 0;
}

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}

static inline void
free_dpdk_buf(struct dp_packet *buf OVS_UNUSED)
{
    /* Nothing */
}

static inline int
pmd_thread_setaffinity_cpu(unsigned cpu OVS_UNUSED)
{
    return 0;
}

#endif /* DPDK_NETDEV */
#endif
