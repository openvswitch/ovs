#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

struct dp_packet;
struct smap;

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

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);
void dpdk_set_lcore_id(unsigned cpu);

#else

#define NON_PMD_CORE_ID UINT32_MAX

#include "util.h"

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

static inline void
dpdk_set_lcore_id(unsigned cpu OVS_UNUSED)
{
    /* Nothing */
}

#endif /* DPDK_NETDEV */

void dpdk_init(const struct smap *ovs_other_config);

#endif
