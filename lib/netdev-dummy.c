/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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

#include <config.h>

#include "dummy.h"

#include <errno.h>

#include "connectivity.h"
#include "flow.h"
#include "list.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "packets.h"
#include "pcap-file.h"
#include "poll-loop.h"
#include "seq.h"
#include "shash.h"
#include "sset.h"
#include "stream.h"
#include "unaligned.h"
#include "timeval.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dummy);

struct dummy_stream {
    struct stream *stream;
    struct ofpbuf rxbuf;
    struct list txq;
};

/* Protects 'dummy_list'. */
static struct ovs_mutex dummy_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dummy_dev's. */
static struct list dummy_list OVS_GUARDED_BY(dummy_list_mutex)
    = LIST_INITIALIZER(&dummy_list);

struct netdev_dummy {
    struct netdev up;

    /* In dummy_list. */
    struct list list_node OVS_GUARDED_BY(dummy_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(dummy_list_mutex);

    uint8_t hwaddr[ETH_ADDR_LEN] OVS_GUARDED;
    int mtu OVS_GUARDED;
    struct netdev_stats stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;
    int ifindex OVS_GUARDED;

    struct pstream *pstream OVS_GUARDED;
    struct dummy_stream *streams OVS_GUARDED;
    size_t n_streams OVS_GUARDED;

    FILE *tx_pcap, *rx_pcap OVS_GUARDED;

    struct list rxes OVS_GUARDED; /* List of child "netdev_rx_dummy"s. */
};

/* Max 'recv_queue_len' in struct netdev_dummy. */
#define NETDEV_DUMMY_MAX_QUEUE 100

struct netdev_rx_dummy {
    struct netdev_rx up;
    struct list node;           /* In netdev_dummy's "rxes" list. */
    struct list recv_queue;
    int recv_queue_len;         /* list_size(&recv_queue). */
    bool listening;
};

static unixctl_cb_func netdev_dummy_set_admin_state;
static int netdev_dummy_construct(struct netdev *);
static void netdev_dummy_queue_packet(struct netdev_dummy *, struct ofpbuf *);

static void dummy_stream_close(struct dummy_stream *);

static bool
is_dummy_class(const struct netdev_class *class)
{
    return class->construct == netdev_dummy_construct;
}

static struct netdev_dummy *
netdev_dummy_cast(const struct netdev *netdev)
{
    ovs_assert(is_dummy_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_dummy, up);
}

static struct netdev_rx_dummy *
netdev_rx_dummy_cast(const struct netdev_rx *rx)
{
    ovs_assert(is_dummy_class(netdev_get_class(rx->netdev)));
    return CONTAINER_OF(rx, struct netdev_rx_dummy, up);
}

static void
netdev_dummy_run(void)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        size_t i;

        ovs_mutex_lock(&dev->mutex);

        if (dev->pstream) {
            struct stream *new_stream;
            int error;

            error = pstream_accept(dev->pstream, &new_stream);
            if (!error) {
                struct dummy_stream *s;

                dev->streams = xrealloc(dev->streams,
                                        ((dev->n_streams + 1)
                                         * sizeof *dev->streams));
                s = &dev->streams[dev->n_streams++];
                s->stream = new_stream;
                ofpbuf_init(&s->rxbuf, 2048);
                list_init(&s->txq);
            } else if (error != EAGAIN) {
                VLOG_WARN("%s: accept failed (%s)",
                          pstream_get_name(dev->pstream), ovs_strerror(error));
                pstream_close(dev->pstream);
                dev->pstream = NULL;
            }
        }

        for (i = 0; i < dev->n_streams; i++) {
            struct dummy_stream *s = &dev->streams[i];
            int error = 0;
            size_t n;

            stream_run(s->stream);

            if (!list_is_empty(&s->txq)) {
                struct ofpbuf *txbuf;
                int retval;

                txbuf = ofpbuf_from_list(list_front(&s->txq));
                retval = stream_send(s->stream, txbuf->data, txbuf->size);
                if (retval > 0) {
                    ofpbuf_pull(txbuf, retval);
                    if (!txbuf->size) {
                        list_remove(&txbuf->list_node);
                        ofpbuf_delete(txbuf);
                    }
                } else if (retval != -EAGAIN) {
                    error = -retval;
                }
            }

            if (!error) {
                if (s->rxbuf.size < 2) {
                    n = 2 - s->rxbuf.size;
                } else {
                    uint16_t frame_len;

                    frame_len = ntohs(get_unaligned_be16(s->rxbuf.data));
                    if (frame_len < ETH_HEADER_LEN) {
                        error = EPROTO;
                        n = 0;
                    } else {
                        n = (2 + frame_len) - s->rxbuf.size;
                    }
                }
            }
            if (!error) {
                int retval;

                ofpbuf_prealloc_tailroom(&s->rxbuf, n);
                retval = stream_recv(s->stream, ofpbuf_tail(&s->rxbuf), n);
                if (retval > 0) {
                    s->rxbuf.size += retval;
                    if (retval == n && s->rxbuf.size > 2) {
                        ofpbuf_pull(&s->rxbuf, 2);
                        netdev_dummy_queue_packet(dev,
                                                  ofpbuf_clone(&s->rxbuf));
                        ofpbuf_clear(&s->rxbuf);
                    }
                } else if (retval != -EAGAIN) {
                    error = (retval < 0 ? -retval
                             : s->rxbuf.size ? EPROTO
                             : EOF);
                }
            }

            if (error) {
                VLOG_DBG("%s: closing connection (%s)",
                         stream_get_name(s->stream),
                         ovs_retval_to_string(error));
                dummy_stream_close(&dev->streams[i]);
                dev->streams[i] = dev->streams[--dev->n_streams];
            }
        }

        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dummy_list_mutex);
}

static void
dummy_stream_close(struct dummy_stream *s)
{
    stream_close(s->stream);
    ofpbuf_uninit(&s->rxbuf);
    ofpbuf_list_delete(&s->txq);
}

static void
netdev_dummy_wait(void)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        size_t i;

        ovs_mutex_lock(&dev->mutex);
        if (dev->pstream) {
            pstream_wait(dev->pstream);
        }
        for (i = 0; i < dev->n_streams; i++) {
            struct dummy_stream *s = &dev->streams[i];

            stream_run_wait(s->stream);
            if (!list_is_empty(&s->txq)) {
                stream_send_wait(s->stream);
            }
            stream_recv_wait(s->stream);
        }
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dummy_list_mutex);
}

static struct netdev *
netdev_dummy_alloc(void)
{
    struct netdev_dummy *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_dummy_construct(struct netdev *netdev_)
{
    static atomic_uint next_n = ATOMIC_VAR_INIT(0xaa550000);
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    unsigned int n;

    atomic_add(&next_n, 1, &n);

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);
    netdev->hwaddr[0] = 0xaa;
    netdev->hwaddr[1] = 0x55;
    netdev->hwaddr[2] = n >> 24;
    netdev->hwaddr[3] = n >> 16;
    netdev->hwaddr[4] = n >> 8;
    netdev->hwaddr[5] = n;
    netdev->mtu = 1500;
    netdev->flags = 0;
    netdev->ifindex = -EOPNOTSUPP;

    netdev->pstream = NULL;
    netdev->streams = NULL;
    netdev->n_streams = 0;

    list_init(&netdev->rxes);
    ovs_mutex_unlock(&netdev->mutex);

    ovs_mutex_lock(&dummy_list_mutex);
    list_push_back(&dummy_list, &netdev->list_node);
    ovs_mutex_unlock(&dummy_list_mutex);

    return 0;
}

static void
netdev_dummy_destruct(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    size_t i;

    ovs_mutex_lock(&dummy_list_mutex);
    list_remove(&netdev->list_node);
    ovs_mutex_unlock(&dummy_list_mutex);

    ovs_mutex_lock(&netdev->mutex);
    pstream_close(netdev->pstream);
    for (i = 0; i < netdev->n_streams; i++) {
        dummy_stream_close(&netdev->streams[i]);
    }
    free(netdev->streams);
    ovs_mutex_unlock(&netdev->mutex);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_dummy_dealloc(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    free(netdev);
}

static int
netdev_dummy_get_config(const struct netdev *netdev_, struct smap *args)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->ifindex >= 0) {
        smap_add_format(args, "ifindex", "%d", netdev->ifindex);
    }

    if (netdev->pstream) {
        smap_add(args, "pstream", pstream_get_name(netdev->pstream));
    }

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_dummy_set_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    const char *pstream;
    const char *pcap;

    ovs_mutex_lock(&netdev->mutex);
    netdev->ifindex = smap_get_int(args, "ifindex", -EOPNOTSUPP);

    pstream = smap_get(args, "pstream");
    if (!pstream
        || !netdev->pstream
        || strcmp(pstream_get_name(netdev->pstream), pstream)) {
        pstream_close(netdev->pstream);
        netdev->pstream = NULL;

        if (pstream) {
            int error;

            error = pstream_open(pstream, &netdev->pstream, DSCP_DEFAULT);
            if (error) {
                VLOG_WARN("%s: open failed (%s)",
                          pstream, ovs_strerror(error));
            }
        }
    }

    if (netdev->rx_pcap) {
        fclose(netdev->rx_pcap);
    }
    if (netdev->tx_pcap && netdev->tx_pcap != netdev->rx_pcap) {
        fclose(netdev->tx_pcap);
    }
    netdev->rx_pcap = netdev->tx_pcap = NULL;
    pcap = smap_get(args, "pcap");
    if (pcap) {
        netdev->rx_pcap = netdev->tx_pcap = pcap_open(pcap, "ab");
    } else {
        const char *rx_pcap = smap_get(args, "rx_pcap");
        const char *tx_pcap = smap_get(args, "tx_pcap");

        if (rx_pcap) {
            netdev->rx_pcap = pcap_open(rx_pcap, "ab");
        }
        if (tx_pcap) {
            netdev->tx_pcap = pcap_open(tx_pcap, "ab");
        }
    }

    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static struct netdev_rx *
netdev_dummy_rx_alloc(void)
{
    struct netdev_rx_dummy *rx = xzalloc(sizeof *rx);
    return &rx->up;
}

static int
netdev_dummy_rx_construct(struct netdev_rx *rx_)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    list_push_back(&netdev->rxes, &rx->node);
    list_init(&rx->recv_queue);
    rx->recv_queue_len = 0;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static void
netdev_dummy_rx_destruct(struct netdev_rx *rx_)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    list_remove(&rx->node);
    ofpbuf_list_delete(&rx->recv_queue);
    ovs_mutex_unlock(&netdev->mutex);
}

static void
netdev_dummy_rx_dealloc(struct netdev_rx *rx_)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);

    free(rx);
}

static int
netdev_dummy_rx_recv(struct netdev_rx *rx_, void *buffer, size_t size)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);
    struct ofpbuf *packet;
    int retval;

    ovs_mutex_lock(&netdev->mutex);
    if (!list_is_empty(&rx->recv_queue)) {
        packet = ofpbuf_from_list(list_pop_front(&rx->recv_queue));
        rx->recv_queue_len--;
    } else {
        packet = NULL;
    }
    ovs_mutex_unlock(&netdev->mutex);

    if (!packet) {
        return -EAGAIN;
    }

    if (packet->size <= size) {
        memcpy(buffer, packet->data, packet->size);
        retval = packet->size;

        ovs_mutex_lock(&netdev->mutex);
        netdev->stats.rx_packets++;
        netdev->stats.rx_bytes += packet->size;
        ovs_mutex_unlock(&netdev->mutex);
    } else {
        retval = -EMSGSIZE;
    }
    ofpbuf_delete(packet);

    return retval;
}

static void
netdev_dummy_rx_wait(struct netdev_rx *rx_)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    if (!list_is_empty(&rx->recv_queue)) {
        poll_immediate_wake();
    }
    ovs_mutex_unlock(&netdev->mutex);
}

static int
netdev_dummy_rx_drain(struct netdev_rx *rx_)
{
    struct netdev_rx_dummy *rx = netdev_rx_dummy_cast(rx_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    ofpbuf_list_delete(&rx->recv_queue);
    rx->recv_queue_len = 0;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_dummy_send(struct netdev *netdev, const void *buffer, size_t size)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    size_t i;

    if (size < ETH_HEADER_LEN) {
        return EMSGSIZE;
    } else {
        const struct eth_header *eth = buffer;
        int max_size;

        ovs_mutex_lock(&dev->mutex);
        max_size = dev->mtu + ETH_HEADER_LEN;
        ovs_mutex_unlock(&dev->mutex);

        if (eth->eth_type == htons(ETH_TYPE_VLAN)) {
            max_size += VLAN_HEADER_LEN;
        }
        if (size > max_size) {
            return EMSGSIZE;
        }
    }

    ovs_mutex_lock(&dev->mutex);
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += size;

    if (dev->tx_pcap) {
        struct ofpbuf packet;

        ofpbuf_use_const(&packet, buffer, size);
        pcap_write(dev->tx_pcap, &packet);
        fflush(dev->tx_pcap);
    }

    for (i = 0; i < dev->n_streams; i++) {
        struct dummy_stream *s = &dev->streams[i];

        if (list_size(&s->txq) < NETDEV_DUMMY_MAX_QUEUE) {
            struct ofpbuf *b;

            b = ofpbuf_clone_data_with_headroom(buffer, size, 2);
            put_unaligned_be16(ofpbuf_push_uninit(b, 2), htons(size));
            list_push_back(&s->txq, &b->list_node);
        }
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        seq_change(connectivity_seq_get());
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac, dev->hwaddr, ETH_ADDR_LEN);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mtup = dev->mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_set_mtu(const struct netdev *netdev, int mtu)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dev->mtu = mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *stats = dev->stats;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_set_stats(struct netdev *netdev, const struct netdev_stats *stats)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    dev->stats = *stats;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_ifindex(const struct netdev *netdev)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    int ifindex;

    ovs_mutex_lock(&dev->mutex);
    ifindex = dev->ifindex;
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static int
netdev_dummy_update_flags__(struct netdev_dummy *netdev,
                            enum netdev_flags off, enum netdev_flags on,
                            enum netdev_flags *old_flagsp)
    OVS_REQUIRES(netdev->mutex)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = netdev->flags;
    netdev->flags |= on;
    netdev->flags &= ~off;
    if (*old_flagsp != netdev->flags) {
        seq_change(connectivity_seq_get());
    }

    return 0;
}

static int
netdev_dummy_update_flags(struct netdev *netdev_,
                          enum netdev_flags off, enum netdev_flags on,
                          enum netdev_flags *old_flagsp)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_dummy_update_flags__(netdev, off, on, old_flagsp);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/* Helper functions. */

static const struct netdev_class dummy_class = {
    "dummy",
    NULL,                       /* init */
    netdev_dummy_run,
    netdev_dummy_wait,

    netdev_dummy_alloc,
    netdev_dummy_construct,
    netdev_dummy_destruct,
    netdev_dummy_dealloc,
    netdev_dummy_get_config,
    netdev_dummy_set_config,
    NULL,                       /* get_tunnel_config */

    netdev_dummy_send,          /* send */
    NULL,                       /* send_wait */

    netdev_dummy_set_etheraddr,
    netdev_dummy_get_etheraddr,
    netdev_dummy_get_mtu,
    netdev_dummy_set_mtu,
    netdev_dummy_get_ifindex,
    NULL,                       /* get_carrier */
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    netdev_dummy_get_stats,
    netdev_dummy_set_stats,

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_dummy_update_flags,

    netdev_dummy_rx_alloc,
    netdev_dummy_rx_construct,
    netdev_dummy_rx_destruct,
    netdev_dummy_rx_dealloc,
    netdev_dummy_rx_recv,
    netdev_dummy_rx_wait,
    netdev_dummy_rx_drain,
};

static struct ofpbuf *
eth_from_packet_or_flow(const char *s)
{
    enum odp_key_fitness fitness;
    struct ofpbuf *packet;
    struct ofpbuf odp_key;
    struct flow flow;
    int error;

    if (!eth_from_hex(s, &packet)) {
        return packet;
    }

    /* Convert string to datapath key.
     *
     * It would actually be nicer to parse an OpenFlow-like flow key here, but
     * the code for that currently calls exit() on parse error.  We have to
     * settle for parsing a datapath key for now.
     */
    ofpbuf_init(&odp_key, 0);
    error = odp_flow_from_string(s, NULL, &odp_key, NULL);
    if (error) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    /* Convert odp_key to flow. */
    fitness = odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
    if (fitness == ODP_FIT_ERROR) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    packet = ofpbuf_new(0);
    flow_compose(packet, &flow);

    ofpbuf_uninit(&odp_key);
    return packet;
}

static void
netdev_dummy_queue_packet__(struct netdev_rx_dummy *rx, struct ofpbuf *packet)
{
    list_push_back(&rx->recv_queue, &packet->list_node);
    rx->recv_queue_len++;
}

static void
netdev_dummy_queue_packet(struct netdev_dummy *dummy, struct ofpbuf *packet)
    OVS_REQUIRES(dummy->mutex)
{
    struct netdev_rx_dummy *rx, *prev;

    if (dummy->rx_pcap) {
        pcap_write(dummy->rx_pcap, packet);
        fflush(dummy->rx_pcap);
    }
    prev = NULL;
    LIST_FOR_EACH (rx, node, &dummy->rxes) {
        if (rx->recv_queue_len < NETDEV_DUMMY_MAX_QUEUE) {
            if (prev) {
                netdev_dummy_queue_packet__(prev, ofpbuf_clone(packet));
            }
            prev = rx;
        }
    }
    if (prev) {
        netdev_dummy_queue_packet__(prev, packet);
    } else {
        ofpbuf_delete(packet);
    }
}

static void
netdev_dummy_receive(struct unixctl_conn *conn,
                     int argc, const char *argv[], void *aux OVS_UNUSED)
{
    struct netdev_dummy *dummy_dev;
    struct netdev *netdev;
    int i;

    netdev = netdev_from_name(argv[1]);
    if (!netdev || !is_dummy_class(netdev->netdev_class)) {
        unixctl_command_reply_error(conn, "no such dummy netdev");
        goto exit;
    }
    dummy_dev = netdev_dummy_cast(netdev);

    for (i = 2; i < argc; i++) {
        struct ofpbuf *packet;

        packet = eth_from_packet_or_flow(argv[i]);
        if (!packet) {
            unixctl_command_reply_error(conn, "bad packet syntax");
            goto exit;
        }

        ovs_mutex_lock(&dummy_dev->mutex);
        netdev_dummy_queue_packet(dummy_dev, packet);
        ovs_mutex_unlock(&dummy_dev->mutex);
    }

    unixctl_command_reply(conn, NULL);

exit:
    netdev_close(netdev);
}

static void
netdev_dummy_set_admin_state__(struct netdev_dummy *dev, bool admin_state)
    OVS_REQUIRES(dev->mutex)
{
    enum netdev_flags old_flags;

    if (admin_state) {
        netdev_dummy_update_flags__(dev, 0, NETDEV_UP, &old_flags);
    } else {
        netdev_dummy_update_flags__(dev, NETDEV_UP, 0, &old_flags);
    }
}

static void
netdev_dummy_set_admin_state(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    bool up;

    if (!strcasecmp(argv[argc - 1], "up")) {
        up = true;
    } else if ( !strcasecmp(argv[argc - 1], "down")) {
        up = false;
    } else {
        unixctl_command_reply_error(conn, "Invalid Admin State");
        return;
    }

    if (argc > 2) {
        struct netdev *netdev = netdev_from_name(argv[1]);
        if (netdev && is_dummy_class(netdev->netdev_class)) {
            struct netdev_dummy *dummy_dev = netdev_dummy_cast(netdev);

            ovs_mutex_lock(&dummy_dev->mutex);
            netdev_dummy_set_admin_state__(dummy_dev, up);
            ovs_mutex_unlock(&dummy_dev->mutex);

            netdev_close(netdev);
        } else {
            unixctl_command_reply_error(conn, "Unknown Dummy Interface");
            netdev_close(netdev);
            return;
        }
    } else {
        struct netdev_dummy *netdev;

        ovs_mutex_lock(&dummy_list_mutex);
        LIST_FOR_EACH (netdev, list_node, &dummy_list) {
            ovs_mutex_lock(&netdev->mutex);
            netdev_dummy_set_admin_state__(netdev, up);
            ovs_mutex_unlock(&netdev->mutex);
        }
        ovs_mutex_unlock(&dummy_list_mutex);
    }
    unixctl_command_reply(conn, "OK");
}

void
netdev_dummy_register(bool override)
{
    unixctl_command_register("netdev-dummy/receive", "NAME PACKET|FLOW...",
                             2, INT_MAX, netdev_dummy_receive, NULL);
    unixctl_command_register("netdev-dummy/set-admin-state",
                             "[netdev] up|down", 1, 2,
                             netdev_dummy_set_admin_state, NULL);

    if (override) {
        struct sset types;
        const char *type;

        sset_init(&types);
        netdev_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (!strcmp(type, "patch")) {
                continue;
            }
            if (!netdev_unregister_provider(type)) {
                struct netdev_class *class;
                int error;

                class = xmemdup(&dummy_class, sizeof dummy_class);
                class->type = xstrdup(type);
                error = netdev_register_provider(class);
                if (error) {
                    VLOG_ERR("%s: failed to register netdev provider (%s)",
                             type, ovs_strerror(error));
                    free(CONST_CAST(char *, class->type));
                    free(class);
                }
            }
        }
        sset_destroy(&types);
    }
    netdev_register_provider(&dummy_class);

    netdev_vport_tunnel_register();
}
