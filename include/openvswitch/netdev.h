/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef OPENVSWITCH_NETDEV_H
#define OPENVSWITCH_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct netdev;
struct ds;

/* Maximum name length for custom statistics counters */
#define NETDEV_CUSTOM_STATS_NAME_SIZE 64

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

    /* Extended statistics based on RFC2819. */
    uint64_t rx_1_to_64_packets;
    uint64_t rx_65_to_127_packets;
    uint64_t rx_128_to_255_packets;
    uint64_t rx_256_to_511_packets;
    uint64_t rx_512_to_1023_packets;
    uint64_t rx_1024_to_1522_packets;
    uint64_t rx_1523_to_max_packets;

    uint64_t tx_1_to_64_packets;
    uint64_t tx_65_to_127_packets;
    uint64_t tx_128_to_255_packets;
    uint64_t tx_256_to_511_packets;
    uint64_t tx_512_to_1023_packets;
    uint64_t tx_1024_to_1522_packets;
    uint64_t tx_1523_to_max_packets;

    uint64_t tx_multicast_packets;

    uint64_t rx_broadcast_packets;
    uint64_t tx_broadcast_packets;

    uint64_t rx_undersized_errors;
    uint64_t rx_oversize_errors;
    uint64_t rx_fragmented_errors;
    uint64_t rx_jabber_errors;

    /* Datapath upcall statistics. */
    uint64_t upcall_packets; /* Rx packets forwarded to userspace. */
    uint64_t upcall_errors;  /* Rx packets failed forwarding to userspace. */
};

/* Structure representation of custom statistics counter */
struct netdev_custom_counter {
    uint64_t value;
    char name[NETDEV_CUSTOM_STATS_NAME_SIZE];
};

/* Structure representation of custom statistics */
struct netdev_custom_stats {
    uint16_t size;
    struct netdev_custom_counter *counters;
};

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

#define NETDEV_DEFAULT_BPS UINT64_C(10 * 1000 * 1000 * 1000)

int netdev_get_features(const struct netdev *,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);
int netdev_get_speed(const struct netdev *, uint32_t *current, uint32_t *max);
uint64_t netdev_features_to_bps(enum netdev_features features,
                                uint64_t default_bps);
bool netdev_features_is_full_duplex(enum netdev_features features);
int netdev_get_duplex(const struct netdev *, bool *full_duplex);
int netdev_set_advertisements(struct netdev *, enum netdev_features advertise);
void netdev_features_format(struct ds *, enum netdev_features);

void netdev_free_custom_stats_counters(struct netdev_custom_stats *);

#ifdef __cplusplus
}
#endif

#endif /* netdev.h */
