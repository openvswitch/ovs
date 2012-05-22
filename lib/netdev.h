/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#ifndef NETDEV_H
#define NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openvswitch/types.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Generic interface to network devices.
 *
 * Currently, there is a single implementation of this interface that supports
 * Linux.  The interface should be generic enough to be implementable on other
 * operating systems as well. */

struct ofpbuf;
struct in_addr;
struct in6_addr;
struct smap;
struct sset;

enum netdev_flags {
    NETDEV_UP = 0x0001,         /* Device enabled? */
    NETDEV_PROMISC = 0x0002,    /* Promiscuous mode? */
    NETDEV_LOOPBACK = 0x0004    /* This is a loopback device. */
};

/* Network device statistics.
 *
 * Values of unsupported statistics are set to all-1-bits (UINT64_MAX). */
struct netdev_stats {
    uint64_t rx_packets;        /* Total packets received. */
    uint64_t tx_packets;        /* Total packets transmitted. */
    uint64_t rx_bytes;          /* Total bytes received. */
    uint64_t tx_bytes;          /* Total bytes transmitted. */
    uint64_t rx_errors;         /* Bad packets received. */
    uint64_t tx_errors;         /* Packet transmit problems. */
    uint64_t rx_dropped;        /* No buffer space. */
    uint64_t tx_dropped;        /* No buffer space. */
    uint64_t multicast;         /* Multicast packets received. */
    uint64_t collisions;

    /* Detailed receive errors. */
    uint64_t rx_length_errors;
    uint64_t rx_over_errors;    /* Receiver ring buff overflow. */
    uint64_t rx_crc_errors;     /* Recved pkt with crc error. */
    uint64_t rx_frame_errors;   /* Recv'd frame alignment error. */
    uint64_t rx_fifo_errors;    /* Recv'r fifo overrun . */
    uint64_t rx_missed_errors;  /* Receiver missed packet. */

    /* Detailed transmit errors. */
    uint64_t tx_aborted_errors;
    uint64_t tx_carrier_errors;
    uint64_t tx_fifo_errors;
    uint64_t tx_heartbeat_errors;
    uint64_t tx_window_errors;
};

struct netdev;
struct netdev_class;

void netdev_run(void);
void netdev_wait(void);

void netdev_enumerate_types(struct sset *types);

/* Open and close. */
int netdev_open(const char *name, const char *type, struct netdev **);
void netdev_close(struct netdev *);

bool netdev_exists(const char *name);
bool netdev_is_open(const char *name);

void netdev_parse_name(const char *netdev_name, char **name, char **type);

/* Options. */
int netdev_set_config(struct netdev *, const struct smap *args);
int netdev_get_config(const struct netdev *, struct smap *);

/* Basic properties. */
const char *netdev_get_name(const struct netdev *);
const char *netdev_get_type(const struct netdev *);
int netdev_get_mtu(const struct netdev *, int *mtup);
int netdev_set_mtu(const struct netdev *, int mtu);
int netdev_get_ifindex(const struct netdev *);

/* Packet send and receive. */
int netdev_listen(struct netdev *);
int netdev_recv(struct netdev *, struct ofpbuf *);
void netdev_recv_wait(struct netdev *);
int netdev_drain(struct netdev *);

int netdev_send(struct netdev *, const struct ofpbuf *);
void netdev_send_wait(struct netdev *);

/* Hardware address. */
int netdev_set_etheraddr(struct netdev *, const uint8_t mac[6]);
int netdev_get_etheraddr(const struct netdev *, uint8_t mac[6]);

/* PHY interface. */
bool netdev_get_carrier(const struct netdev *);
long long int netdev_get_carrier_resets(const struct netdev *);
int netdev_set_miimon_interval(struct netdev *, long long int interval);

/* Features. */
enum netdev_features {
    NETDEV_F_10MB_HD =    1 << 0,  /* 10 Mb half-duplex rate support. */
    NETDEV_F_10MB_FD =    1 << 1,  /* 10 Mb full-duplex rate support. */
    NETDEV_F_100MB_HD =   1 << 2,  /* 100 Mb half-duplex rate support. */
    NETDEV_F_100MB_FD =   1 << 3,  /* 100 Mb full-duplex rate support. */
    NETDEV_F_1GB_HD =     1 << 4,  /* 1 Gb half-duplex rate support. */
    NETDEV_F_1GB_FD =     1 << 5,  /* 1 Gb full-duplex rate support. */
    NETDEV_F_10GB_FD =    1 << 6,  /* 10 Gb full-duplex rate support. */
    NETDEV_F_40GB_FD =    1 << 7,  /* 40 Gb full-duplex rate support. */
    NETDEV_F_100GB_FD =   1 << 8,  /* 100 Gb full-duplex rate support. */
    NETDEV_F_1TB_FD =     1 << 9,  /* 1 Tb full-duplex rate support. */
    NETDEV_F_OTHER =      1 << 10, /* Other rate, not in the list. */
    NETDEV_F_COPPER =     1 << 11, /* Copper medium. */
    NETDEV_F_FIBER =      1 << 12, /* Fiber medium. */
    NETDEV_F_AUTONEG =    1 << 13, /* Auto-negotiation. */
    NETDEV_F_PAUSE =      1 << 14, /* Pause. */
    NETDEV_F_PAUSE_ASYM = 1 << 15, /* Asymmetric pause. */
};

int netdev_get_features(const struct netdev *,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);
uint64_t netdev_features_to_bps(enum netdev_features features);
bool netdev_features_is_full_duplex(enum netdev_features features);
int netdev_set_advertisements(struct netdev *, enum netdev_features advertise);

/* TCP/IP stack interface. */
int netdev_get_in4(const struct netdev *, struct in_addr *address,
                   struct in_addr *netmask);
int netdev_set_in4(struct netdev *, struct in_addr addr, struct in_addr mask);
int netdev_get_in4_by_name(const char *device_name, struct in_addr *in4);
int netdev_get_in6(const struct netdev *, struct in6_addr *);
int netdev_add_router(struct netdev *, struct in_addr router);
int netdev_get_next_hop(const struct netdev *, const struct in_addr *host,
                        struct in_addr *next_hop, char **);
int netdev_get_drv_info(const struct netdev *, struct smap *);
int netdev_arp_lookup(const struct netdev *, ovs_be32 ip, uint8_t mac[6]);

int netdev_get_flags(const struct netdev *, enum netdev_flags *);
int netdev_set_flags(struct netdev *, enum netdev_flags, bool permanent);
int netdev_turn_flags_on(struct netdev *, enum netdev_flags, bool permanent);
int netdev_turn_flags_off(struct netdev *, enum netdev_flags, bool permanent);
struct netdev *netdev_find_dev_by_in4(const struct in_addr *);

/* Statistics. */
int netdev_get_stats(const struct netdev *, struct netdev_stats *);
int netdev_set_stats(struct netdev *, const struct netdev_stats *);

/* Quality of service. */
struct netdev_qos_capabilities {
    unsigned int n_queues;
};

struct netdev_queue_stats {
    /* Values of unsupported statistics are set to all-1-bits (UINT64_MAX). */
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;
};

int netdev_set_policing(struct netdev *, uint32_t kbits_rate,
                        uint32_t kbits_burst);

int netdev_get_qos_types(const struct netdev *, struct sset *types);
int netdev_get_qos_capabilities(const struct netdev *,
                                const char *type,
                                struct netdev_qos_capabilities *);
int netdev_get_n_queues(const struct netdev *,
                        const char *type, unsigned int *n_queuesp);

int netdev_get_qos(const struct netdev *,
                   const char **typep, struct smap *details);
int netdev_set_qos(struct netdev *,
                   const char *type, const struct smap *details);

int netdev_get_queue(const struct netdev *,
                     unsigned int queue_id, struct smap *details);
int netdev_set_queue(struct netdev *,
                     unsigned int queue_id, const struct smap *details);
int netdev_delete_queue(struct netdev *, unsigned int queue_id);
int netdev_get_queue_stats(const struct netdev *, unsigned int queue_id,
                           struct netdev_queue_stats *);

typedef void netdev_dump_queues_cb(unsigned int queue_id,
                                   const struct smap *details, void *aux);
int netdev_dump_queues(const struct netdev *,
                       netdev_dump_queues_cb *, void *aux);

typedef void netdev_dump_queue_stats_cb(unsigned int queue_id,
                                        struct netdev_queue_stats *,
                                        void *aux);
int netdev_dump_queue_stats(const struct netdev *,
                            netdev_dump_queue_stats_cb *, void *aux);

unsigned int netdev_change_seq(const struct netdev *netdev);

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
