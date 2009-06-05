/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef NETDEV_H
#define NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Generic interface to network devices.
 *
 * Currently, there is a single implementation of this interface that supports
 * Linux.  The interface should be generic enough to be implementable on other
 * operating systems as well. */

struct ofpbuf;
struct in_addr;
struct in6_addr;
struct svec;

enum netdev_flags {
    NETDEV_UP = 0x0001,         /* Device enabled? */
    NETDEV_PROMISC = 0x0002     /* Promiscuous mode? */
};

enum netdev_pseudo_ethertype {
    NETDEV_ETH_TYPE_NONE = -128, /* Receive no frames. */
    NETDEV_ETH_TYPE_ANY,         /* Receive all frames. */
    NETDEV_ETH_TYPE_802_2        /* Receive all IEEE 802.2 frames. */
};

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

int netdev_open(const char *name, int ethertype, struct netdev **);
int netdev_open_tap(const char *name, struct netdev **);
void netdev_close(struct netdev *);

int netdev_recv(struct netdev *, struct ofpbuf *);
void netdev_recv_wait(struct netdev *);
int netdev_drain(struct netdev *);
int netdev_send(struct netdev *, const struct ofpbuf *);
void netdev_send_wait(struct netdev *);
int netdev_set_etheraddr(struct netdev *, const uint8_t mac[6]);
const uint8_t *netdev_get_etheraddr(const struct netdev *);
const char *netdev_get_name(const struct netdev *);
int netdev_get_mtu(const struct netdev *);
int netdev_get_features(struct netdev *,
                        uint32_t *current, uint32_t *advertised,
                        uint32_t *supported, uint32_t *peer);
int netdev_set_advertisements(struct netdev *, uint32_t advertise);
bool netdev_get_in4(const struct netdev *, struct in_addr *);
int netdev_set_in4(struct netdev *, struct in_addr addr, struct in_addr mask);
int netdev_add_router(struct in_addr router);
bool netdev_get_in6(const struct netdev *, struct in6_addr *);
int netdev_get_flags(const struct netdev *, enum netdev_flags *);
int netdev_set_flags(struct netdev *, enum netdev_flags, bool permanent);
int netdev_turn_flags_on(struct netdev *, enum netdev_flags, bool permanent);
int netdev_turn_flags_off(struct netdev *, enum netdev_flags, bool permanent);
int netdev_arp_lookup(const struct netdev *, uint32_t ip, uint8_t mac[6]);
int netdev_get_carrier(const struct netdev *, bool *carrier);
int netdev_get_stats(const struct netdev *, struct netdev_stats *);
int netdev_set_policing(struct netdev *, uint32_t kbits_rate, 
                        uint32_t kbits_burst);

void netdev_enumerate(struct svec *);
int netdev_nodev_get_flags(const char *netdev_name, enum netdev_flags *);
int netdev_nodev_set_etheraddr(const char *name, const uint8_t mac[6]);
int netdev_nodev_get_etheraddr(const char *netdev_name, uint8_t mac[6]);
int netdev_nodev_set_policing(const char *netdev_name, uint32_t kbits_rate, 
                              uint32_t kbits_burst);
int netdev_nodev_get_carrier(const char *netdev_name, bool *carrier);

int netdev_get_vlan_vid(const char *netdev_name, int *vlan_vid);

#endif /* netdev.h */
