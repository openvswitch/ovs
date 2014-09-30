#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

struct dpif_packet;

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

int dpdk_init(int argc, char **argv);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct dpif_packet *);
int pmd_thread_setaffinity_cpu(int cpu);
void thread_set_nonpmd(void);

#else

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
free_dpdk_buf(struct dpif_packet *buf OVS_UNUSED)
{
    /* Nothing */
}

static inline int
pmd_thread_setaffinity_cpu(int cpu OVS_UNUSED)
{
    return 0;
}

static inline void
thread_set_nonpmd(void)
{
    /* Nothing */
}

#endif /* DPDK_NETDEV */
#endif
