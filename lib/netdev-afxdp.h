/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETDEV_AFXDP_H
#define NETDEV_AFXDP_H 1

#ifdef HAVE_AF_XDP

#include <stdint.h>
#include <stdbool.h>

/* These functions are Linux AF_XDP specific, so they should be used directly
 * only by Linux-specific code. */

enum afxdp_mode {
    OVS_AF_XDP_MODE_UNSPEC,
    OVS_AF_XDP_MODE_BEST_EFFORT,
    OVS_AF_XDP_MODE_NATIVE_ZC,
    OVS_AF_XDP_MODE_NATIVE,
    OVS_AF_XDP_MODE_GENERIC,
    OVS_AF_XDP_MODE_MAX,
};

struct dp_packet;
struct dp_packet_batch;
struct netdev;
struct netdev_afxdp_tx_lock;
struct netdev_custom_stats;
struct netdev_rxq;
struct netdev_stats;
struct smap;
struct xdp_umem;
struct xsk_socket_info;

int netdev_afxdp_rxq_construct(struct netdev_rxq *rxq_);
void netdev_afxdp_rxq_destruct(struct netdev_rxq *rxq_);
int netdev_afxdp_init(void);
int netdev_afxdp_construct(struct netdev *netdev_);
void netdev_afxdp_destruct(struct netdev *netdev_);
int netdev_afxdp_verify_mtu_size(const struct netdev *netdev, int mtu);

int netdev_afxdp_rxq_recv(struct netdev_rxq *rxq_,
                          struct dp_packet_batch *batch,
                          int *qfill);
int netdev_afxdp_batch_send(struct netdev *netdev_, int qid,
                            struct dp_packet_batch *batch,
                            bool concurrent_txq);
int netdev_afxdp_set_config(struct netdev *netdev, const struct smap *args,
                            char **errp);
int netdev_afxdp_get_config(const struct netdev *netdev, struct smap *args);
int netdev_afxdp_get_stats(const struct netdev *netdev_,
                           struct netdev_stats *stats);
int netdev_afxdp_get_custom_stats(const struct netdev *netdev,
                                  struct netdev_custom_stats *custom_stats);


void free_afxdp_buf(struct dp_packet *p);
int netdev_afxdp_reconfigure(struct netdev *netdev);
void signal_remove_xdp(struct netdev *netdev);

#else /* !HAVE_AF_XDP */

#include "openvswitch/compiler.h"

struct dp_packet;

static inline void
free_afxdp_buf(struct dp_packet *p OVS_UNUSED)
{
    /* Nothing. */
}

#endif /* HAVE_AF_XDP */
#endif /* netdev-afxdp.h */
