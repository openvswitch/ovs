/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#include "dp-packet.h"
#include "dpif-netdev.h"
#include "dynamic-string.h"
#include "flow.h"
#include "list.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "pcap-file.h"
#include "poll-loop.h"
#include "shash.h"
#include "sset.h"
#include "stream.h"
#include "unaligned.h"
#include "timeval.h"
#include "unixctl.h"
#include "reconnect.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dummy);

struct reconnect;

struct dummy_packet_stream {
    struct stream *stream;
    struct dp_packet rxbuf;
    struct ovs_list txq;
};

enum dummy_packet_conn_type {
    NONE,       /* No connection is configured. */
    PASSIVE,    /* Listener. */
    ACTIVE      /* Connect to listener. */
};

enum dummy_netdev_conn_state {
    CONN_STATE_CONNECTED,      /* Listener connected. */
    CONN_STATE_NOT_CONNECTED,  /* Listener not connected.  */
    CONN_STATE_UNKNOWN,        /* No relavent information.  */
};

struct dummy_packet_pconn {
    struct pstream *pstream;
    struct dummy_packet_stream *streams;
    size_t n_streams;
};

struct dummy_packet_rconn {
    struct dummy_packet_stream *rstream;
    struct reconnect *reconnect;
};

struct dummy_packet_conn {
    enum dummy_packet_conn_type type;
    union {
        struct dummy_packet_pconn pconn;
        struct dummy_packet_rconn rconn;
    } u;
};

struct pkt_list_node {
    struct dp_packet *pkt;
    struct ovs_list list_node;
};

/* Protects 'dummy_list'. */
static struct ovs_mutex dummy_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dummy_dev's. */
static struct ovs_list dummy_list OVS_GUARDED_BY(dummy_list_mutex)
    = OVS_LIST_INITIALIZER(&dummy_list);

struct netdev_dummy {
    struct netdev up;

    /* In dummy_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dummy_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(dummy_list_mutex);

    uint8_t hwaddr[ETH_ADDR_LEN] OVS_GUARDED;
    int mtu OVS_GUARDED;
    struct netdev_stats stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;
    int ifindex OVS_GUARDED;

    struct dummy_packet_conn conn OVS_GUARDED;

    FILE *tx_pcap, *rxq_pcap OVS_GUARDED;

    struct in_addr address, netmask;
    struct ovs_list rxes OVS_GUARDED; /* List of child "netdev_rxq_dummy"s. */
};

/* Max 'recv_queue_len' in struct netdev_dummy. */
#define NETDEV_DUMMY_MAX_QUEUE 100

struct netdev_rxq_dummy {
    struct netdev_rxq up;
    struct ovs_list node;       /* In netdev_dummy's "rxes" list. */
    struct ovs_list recv_queue;
    int recv_queue_len;         /* list_size(&recv_queue). */
    struct seq *seq;            /* Reports newly queued packets. */
};

static unixctl_cb_func netdev_dummy_set_admin_state;
static int netdev_dummy_construct(struct netdev *);
static void netdev_dummy_queue_packet(struct netdev_dummy *, struct dp_packet *);

static void dummy_packet_stream_close(struct dummy_packet_stream *);

static void pkt_list_delete(struct ovs_list *);

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

static struct netdev_rxq_dummy *
netdev_rxq_dummy_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_dummy_class(netdev_get_class(rx->netdev)));
    return CONTAINER_OF(rx, struct netdev_rxq_dummy, up);
}

static void
dummy_packet_stream_init(struct dummy_packet_stream *s, struct stream *stream)
{
    int rxbuf_size = stream ? 2048 : 0;
    s->stream = stream;
    dp_packet_init(&s->rxbuf, rxbuf_size);
    list_init(&s->txq);
}

static struct dummy_packet_stream *
dummy_packet_stream_create(struct stream *stream)
{
    struct dummy_packet_stream *s;

    s = xzalloc(sizeof *s);
    dummy_packet_stream_init(s, stream);

    return s;
}

static void
dummy_packet_stream_wait(struct dummy_packet_stream *s)
{
    stream_run_wait(s->stream);
    if (!list_is_empty(&s->txq)) {
        stream_send_wait(s->stream);
    }
    stream_recv_wait(s->stream);
}

static void
dummy_packet_stream_send(struct dummy_packet_stream *s, const void *buffer, size_t size)
{
    if (list_size(&s->txq) < NETDEV_DUMMY_MAX_QUEUE) {
        struct dp_packet *b;
        struct pkt_list_node *node;

        b = dp_packet_clone_data_with_headroom(buffer, size, 2);
        put_unaligned_be16(dp_packet_push_uninit(b, 2), htons(size));

        node = xmalloc(sizeof *node);
        node->pkt = b;
        list_push_back(&s->txq, &node->list_node);
    }
}

static int
dummy_packet_stream_run(struct netdev_dummy *dev, struct dummy_packet_stream *s)
{
    int error = 0;
    size_t n;

    stream_run(s->stream);

    if (!list_is_empty(&s->txq)) {
        struct pkt_list_node *txbuf_node;
        struct dp_packet *txbuf;
        int retval;

        ASSIGN_CONTAINER(txbuf_node, list_front(&s->txq), list_node);
        txbuf = txbuf_node->pkt;
        retval = stream_send(s->stream, dp_packet_data(txbuf), dp_packet_size(txbuf));

        if (retval > 0) {
            dp_packet_pull(txbuf, retval);
            if (!dp_packet_size(txbuf)) {
                list_remove(&txbuf_node->list_node);
                free(txbuf_node);
                dp_packet_delete(txbuf);
            }
        } else if (retval != -EAGAIN) {
            error = -retval;
        }
    }

    if (!error) {
        if (dp_packet_size(&s->rxbuf) < 2) {
            n = 2 - dp_packet_size(&s->rxbuf);
        } else {
            uint16_t frame_len;

            frame_len = ntohs(get_unaligned_be16(dp_packet_data(&s->rxbuf)));
            if (frame_len < ETH_HEADER_LEN) {
                error = EPROTO;
                n = 0;
            } else {
                n = (2 + frame_len) - dp_packet_size(&s->rxbuf);
            }
        }
    }
    if (!error) {
        int retval;

        dp_packet_prealloc_tailroom(&s->rxbuf, n);
        retval = stream_recv(s->stream, dp_packet_tail(&s->rxbuf), n);

        if (retval > 0) {
            dp_packet_set_size(&s->rxbuf, dp_packet_size(&s->rxbuf) + retval);
            if (retval == n && dp_packet_size(&s->rxbuf) > 2) {
                dp_packet_pull(&s->rxbuf, 2);
                netdev_dummy_queue_packet(dev,
                                          dp_packet_clone(&s->rxbuf));
                dp_packet_clear(&s->rxbuf);
            }
        } else if (retval != -EAGAIN) {
            error = (retval < 0 ? -retval
                     : dp_packet_size(&s->rxbuf) ? EPROTO
                     : EOF);
        }
    }

    return error;
}

static void
dummy_packet_stream_close(struct dummy_packet_stream *s)
{
    stream_close(s->stream);
    dp_packet_uninit(&s->rxbuf);
    pkt_list_delete(&s->txq);
}

static void
dummy_packet_conn_init(struct dummy_packet_conn *conn)
{
    memset(conn, 0, sizeof *conn);
    conn->type = NONE;
}

static void
dummy_packet_conn_get_config(struct dummy_packet_conn *conn, struct smap *args)
{

    switch (conn->type) {
    case PASSIVE:
        smap_add(args, "pstream", pstream_get_name(conn->u.pconn.pstream));
        break;

    case ACTIVE:
        smap_add(args, "stream", stream_get_name(conn->u.rconn.rstream->stream));
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_close(struct dummy_packet_conn *conn)
{
    int i;
    struct dummy_packet_pconn *pconn = &conn->u.pconn;
    struct dummy_packet_rconn *rconn = &conn->u.rconn;

    switch (conn->type) {
    case PASSIVE:
        pstream_close(pconn->pstream);
        for (i = 0; i < pconn->n_streams; i++) {
            dummy_packet_stream_close(&pconn->streams[i]);
        }
        free(pconn->streams);
        pconn->pstream = NULL;
        pconn->streams = NULL;
        break;

    case ACTIVE:
        dummy_packet_stream_close(rconn->rstream);
        free(rconn->rstream);
        rconn->rstream = NULL;
        reconnect_destroy(rconn->reconnect);
        rconn->reconnect = NULL;
        break;

    case NONE:
    default:
        break;
    }

    conn->type = NONE;
    memset(conn, 0, sizeof *conn);
}

static void
dummy_packet_conn_set_config(struct dummy_packet_conn *conn,
                             const struct smap *args)
{
    const char *pstream = smap_get(args, "pstream");
    const char *stream = smap_get(args, "stream");

    if (pstream && stream) {
         VLOG_WARN("Open failed: both %s and %s are configured",
                   pstream, stream);
         return;
    }

    switch (conn->type) {
    case PASSIVE:
        if (pstream &&
            !strcmp(pstream_get_name(conn->u.pconn.pstream), pstream)) {
            return;
        }
        dummy_packet_conn_close(conn);
        break;
    case ACTIVE:
        if (stream &&
            !strcmp(stream_get_name(conn->u.rconn.rstream->stream), stream)) {
            return;
        }
        dummy_packet_conn_close(conn);
        break;
    case NONE:
    default:
        break;
    }

    if (pstream) {
        int error;

        error = pstream_open(pstream, &conn->u.pconn.pstream, DSCP_DEFAULT);
        if (error) {
            VLOG_WARN("%s: open failed (%s)", pstream, ovs_strerror(error));
        } else {
            conn->type = PASSIVE;
        }
    }

    if (stream) {
        int error;
        struct stream *active_stream;
        struct reconnect *reconnect;;

        reconnect = reconnect_create(time_msec());
        reconnect_set_name(reconnect, stream);
        reconnect_set_passive(reconnect, false, time_msec());
        reconnect_enable(reconnect, time_msec());
        reconnect_set_backoff(reconnect, 100, INT_MAX);
        reconnect_set_probe_interval(reconnect, 0);
        conn->u.rconn.reconnect = reconnect;
        conn->type = ACTIVE;

        error = stream_open(stream, &active_stream, DSCP_DEFAULT);
        conn->u.rconn.rstream = dummy_packet_stream_create(active_stream);

        switch (error) {
        case 0:
            reconnect_connected(reconnect, time_msec());
            break;

        case EAGAIN:
            reconnect_connecting(reconnect, time_msec());
            break;

        default:
            reconnect_connect_failed(reconnect, time_msec(), error);
            stream_close(active_stream);
            conn->u.rconn.rstream->stream = NULL;
            break;
        }
    }
}

static void
dummy_pconn_run(struct netdev_dummy *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct stream *new_stream;
    struct dummy_packet_pconn *pconn = &dev->conn.u.pconn;
    int error;
    size_t i;

    error = pstream_accept(pconn->pstream, &new_stream);
    if (!error) {
        struct dummy_packet_stream *s;

        pconn->streams = xrealloc(pconn->streams,
                                ((pconn->n_streams + 1)
                                 * sizeof *s));
        s = &pconn->streams[pconn->n_streams++];
        dummy_packet_stream_init(s, new_stream);
    } else if (error != EAGAIN) {
        VLOG_WARN("%s: accept failed (%s)",
                  pstream_get_name(pconn->pstream), ovs_strerror(error));
        pstream_close(pconn->pstream);
        pconn->pstream = NULL;
        dev->conn.type = NONE;
    }

    for (i = 0; i < pconn->n_streams; i++) {
        struct dummy_packet_stream *s = &pconn->streams[i];

        error = dummy_packet_stream_run(dev, s);
        if (error) {
            VLOG_DBG("%s: closing connection (%s)",
                     stream_get_name(s->stream),
                     ovs_retval_to_string(error));
            dummy_packet_stream_close(s);
            pconn->streams[i] = pconn->streams[--pconn->n_streams];
        }
    }
}

static void
dummy_rconn_run(struct netdev_dummy *dev)
OVS_REQUIRES(dev->mutex)
{
    struct dummy_packet_rconn *rconn = &dev->conn.u.rconn;

    switch (reconnect_run(rconn->reconnect, time_msec())) {
    case RECONNECT_CONNECT:
        {
            int error;

            if (rconn->rstream->stream) {
                error = stream_connect(rconn->rstream->stream);
            } else {
                error = stream_open(reconnect_get_name(rconn->reconnect),
                                    &rconn->rstream->stream, DSCP_DEFAULT);
            }

            switch (error) {
            case 0:
                reconnect_connected(rconn->reconnect, time_msec());
                break;

            case EAGAIN:
                reconnect_connecting(rconn->reconnect, time_msec());
                break;

            default:
                reconnect_connect_failed(rconn->reconnect, time_msec(), error);
                stream_close(rconn->rstream->stream);
                rconn->rstream->stream = NULL;
                break;
            }
        }
        break;

    case RECONNECT_DISCONNECT:
    case RECONNECT_PROBE:
    default:
        break;
    }

    if (reconnect_is_connected(rconn->reconnect)) {
        int err;

        err = dummy_packet_stream_run(dev, rconn->rstream);

        if (err) {
            reconnect_disconnected(rconn->reconnect, time_msec(), err);
            stream_close(rconn->rstream->stream);
            rconn->rstream->stream = NULL;
        }
    }
}

static void
dummy_packet_conn_run(struct netdev_dummy *dev)
    OVS_REQUIRES(dev->mutex)
{
    switch (dev->conn.type) {
    case PASSIVE:
        dummy_pconn_run(dev);
        break;

    case ACTIVE:
        dummy_rconn_run(dev);
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_wait(struct dummy_packet_conn *conn)
{
    int i;
    switch (conn->type) {
    case PASSIVE:
        pstream_wait(conn->u.pconn.pstream);
        for (i = 0; i < conn->u.pconn.n_streams; i++) {
            struct dummy_packet_stream *s = &conn->u.pconn.streams[i];
            dummy_packet_stream_wait(s);
        }
        break;
    case ACTIVE:
        if (reconnect_is_connected(conn->u.rconn.reconnect)) {
            dummy_packet_stream_wait(conn->u.rconn.rstream);
        }
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_send(struct dummy_packet_conn *conn,
                       const void *buffer, size_t size)
{
    int i;

    switch (conn->type) {
    case PASSIVE:
        for (i = 0; i < conn->u.pconn.n_streams; i++) {
            struct dummy_packet_stream *s = &conn->u.pconn.streams[i];

            dummy_packet_stream_send(s, buffer, size);
            pstream_wait(conn->u.pconn.pstream);
        }
        break;

    case ACTIVE:
        if (reconnect_is_connected(conn->u.rconn.reconnect)) {
            dummy_packet_stream_send(conn->u.rconn.rstream, buffer, size);
            dummy_packet_stream_wait(conn->u.rconn.rstream);
        }
        break;

    case NONE:
    default:
        break;
    }
}

static enum dummy_netdev_conn_state
dummy_netdev_get_conn_state(struct dummy_packet_conn *conn)
{
    enum dummy_netdev_conn_state state;

    if (conn->type == ACTIVE) {
        if (reconnect_is_connected(conn->u.rconn.reconnect)) {
            state = CONN_STATE_CONNECTED;
        } else {
            state = CONN_STATE_NOT_CONNECTED;
        }
    } else {
        state = CONN_STATE_UNKNOWN;
    }

    return state;
}

static void
netdev_dummy_run(void)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        ovs_mutex_lock(&dev->mutex);
        dummy_packet_conn_run(dev);
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dummy_list_mutex);
}

static void
netdev_dummy_wait(void)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        ovs_mutex_lock(&dev->mutex);
        dummy_packet_conn_wait(&dev->conn);
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
    static atomic_count next_n = ATOMIC_COUNT_INIT(0xaa550000);
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    unsigned int n;

    n = atomic_count_inc(&next_n);

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

    dummy_packet_conn_init(&netdev->conn);

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

    ovs_mutex_lock(&dummy_list_mutex);
    list_remove(&netdev->list_node);
    ovs_mutex_unlock(&dummy_list_mutex);

    ovs_mutex_lock(&netdev->mutex);
    dummy_packet_conn_close(&netdev->conn);
    netdev->conn.type = NONE;

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

    dummy_packet_conn_get_config(&netdev->conn, args);

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_dummy_get_in4(const struct netdev *netdev_,
                     struct in_addr *address, struct in_addr *netmask)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *address = netdev->address;
    *netmask = netdev->netmask;
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_dummy_set_in4(struct netdev *netdev_, struct in_addr address,
                     struct in_addr netmask)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->address = address;
    netdev->netmask = netmask;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_dummy_set_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    const char *pcap;

    ovs_mutex_lock(&netdev->mutex);
    netdev->ifindex = smap_get_int(args, "ifindex", -EOPNOTSUPP);

    dummy_packet_conn_set_config(&netdev->conn, args);

    if (netdev->rxq_pcap) {
        fclose(netdev->rxq_pcap);
    }
    if (netdev->tx_pcap && netdev->tx_pcap != netdev->rxq_pcap) {
        fclose(netdev->tx_pcap);
    }
    netdev->rxq_pcap = netdev->tx_pcap = NULL;
    pcap = smap_get(args, "pcap");
    if (pcap) {
        netdev->rxq_pcap = netdev->tx_pcap = ovs_pcap_open(pcap, "ab");
    } else {
        const char *rxq_pcap = smap_get(args, "rxq_pcap");
        const char *tx_pcap = smap_get(args, "tx_pcap");

        if (rxq_pcap) {
            netdev->rxq_pcap = ovs_pcap_open(rxq_pcap, "ab");
        }
        if (tx_pcap) {
            netdev->tx_pcap = ovs_pcap_open(tx_pcap, "ab");
        }
    }

    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static struct netdev_rxq *
netdev_dummy_rxq_alloc(void)
{
    struct netdev_rxq_dummy *rx = xzalloc(sizeof *rx);
    return &rx->up;
}

static int
netdev_dummy_rxq_construct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    list_push_back(&netdev->rxes, &rx->node);
    list_init(&rx->recv_queue);
    rx->recv_queue_len = 0;
    rx->seq = seq_create();
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static void
netdev_dummy_rxq_destruct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    list_remove(&rx->node);
    pkt_list_delete(&rx->recv_queue);
    ovs_mutex_unlock(&netdev->mutex);
    seq_destroy(rx->seq);
}

static void
netdev_dummy_rxq_dealloc(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);

    free(rx);
}

static int
netdev_dummy_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet **arr,
                      int *c)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);
    struct dp_packet *packet;

    ovs_mutex_lock(&netdev->mutex);
    if (!list_is_empty(&rx->recv_queue)) {
        struct pkt_list_node *pkt_node;

        ASSIGN_CONTAINER(pkt_node, list_pop_front(&rx->recv_queue), list_node);
        packet = pkt_node->pkt;
        free(pkt_node);
        rx->recv_queue_len--;
    } else {
        packet = NULL;
    }
    ovs_mutex_unlock(&netdev->mutex);

    if (!packet) {
        return EAGAIN;
    }
    ovs_mutex_lock(&netdev->mutex);
    netdev->stats.rx_packets++;
    netdev->stats.rx_bytes += dp_packet_size(packet);
    ovs_mutex_unlock(&netdev->mutex);

    dp_packet_pad(packet);
    dp_packet_set_rss_hash(packet, 0);

    arr[0] = packet;
    *c = 1;
    return 0;
}

static void
netdev_dummy_rxq_wait(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);
    uint64_t seq = seq_read(rx->seq);

    ovs_mutex_lock(&netdev->mutex);
    if (!list_is_empty(&rx->recv_queue)) {
        poll_immediate_wake();
    } else {
        seq_wait(rx->seq, seq);
    }
    ovs_mutex_unlock(&netdev->mutex);
}

static int
netdev_dummy_rxq_drain(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    pkt_list_delete(&rx->recv_queue);
    rx->recv_queue_len = 0;
    ovs_mutex_unlock(&netdev->mutex);

    seq_change(rx->seq);

    return 0;
}

static int
netdev_dummy_send(struct netdev *netdev, int qid OVS_UNUSED,
                  struct dp_packet **pkts, int cnt, bool may_steal)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    int error = 0;
    int i;

    for (i = 0; i < cnt; i++) {
        const void *buffer = dp_packet_data(pkts[i]);
        size_t size = dp_packet_size(pkts[i]);

        if (size < ETH_HEADER_LEN) {
            error = EMSGSIZE;
            break;
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
                error = EMSGSIZE;
                break;
            }
        }

        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_packets++;
        dev->stats.tx_bytes += size;

        dummy_packet_conn_send(&dev->conn, buffer, size);

        if (dev->tx_pcap) {
            struct dp_packet packet;

            dp_packet_use_const(&packet, buffer, size);
            ovs_pcap_write(dev->tx_pcap, &packet);
            fflush(dev->tx_pcap);
        }

        ovs_mutex_unlock(&dev->mutex);
    }

    if (may_steal) {
        for (i = 0; i < cnt; i++) {
            dp_packet_delete(pkts[i]);
        }
    }

    return error;
}

static int
netdev_dummy_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
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
        netdev_change_seq_changed(&netdev->up);
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
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

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

    netdev_dummy_get_in4,       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_dummy_update_flags,

    netdev_dummy_rxq_alloc,
    netdev_dummy_rxq_construct,
    netdev_dummy_rxq_destruct,
    netdev_dummy_rxq_dealloc,
    netdev_dummy_rxq_recv,
    netdev_dummy_rxq_wait,
    netdev_dummy_rxq_drain,
};

static void
pkt_list_delete(struct ovs_list *l)
{
    struct pkt_list_node *pkt;

    LIST_FOR_EACH_POP(pkt, list_node, l) {
        dp_packet_delete(pkt->pkt);
        free(pkt);
    }
}

static struct dp_packet *
eth_from_packet_or_flow(const char *s)
{
    enum odp_key_fitness fitness;
    struct dp_packet *packet;
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

    packet = dp_packet_new(0);
    flow_compose(packet, &flow);

    ofpbuf_uninit(&odp_key);
    return packet;
}

static void
netdev_dummy_queue_packet__(struct netdev_rxq_dummy *rx, struct dp_packet *packet)
{
    struct pkt_list_node *pkt_node = xmalloc(sizeof *pkt_node);

    pkt_node->pkt = packet;
    list_push_back(&rx->recv_queue, &pkt_node->list_node);
    rx->recv_queue_len++;
    seq_change(rx->seq);
}

static void
netdev_dummy_queue_packet(struct netdev_dummy *dummy, struct dp_packet *packet)
    OVS_REQUIRES(dummy->mutex)
{
    struct netdev_rxq_dummy *rx, *prev;

    if (dummy->rxq_pcap) {
        ovs_pcap_write(dummy->rxq_pcap, packet);
        fflush(dummy->rxq_pcap);
    }
    prev = NULL;
    LIST_FOR_EACH (rx, node, &dummy->rxes) {
        if (rx->recv_queue_len < NETDEV_DUMMY_MAX_QUEUE) {
            if (prev) {
                netdev_dummy_queue_packet__(prev, dp_packet_clone(packet));
            }
            prev = rx;
        }
    }
    if (prev) {
        netdev_dummy_queue_packet__(prev, packet);
    } else {
        dp_packet_delete(packet);
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
        struct dp_packet *packet;

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

static void
display_conn_state__(struct ds *s, const char *name,
                     enum dummy_netdev_conn_state state)
{
    ds_put_format(s, "%s: ", name);

    switch (state) {
    case CONN_STATE_CONNECTED:
        ds_put_cstr(s, "connected\n");
        break;

    case CONN_STATE_NOT_CONNECTED:
        ds_put_cstr(s, "disconnected\n");
        break;

    case CONN_STATE_UNKNOWN:
    default:
        ds_put_cstr(s, "unknown\n");
        break;
    };
}

static void
netdev_dummy_conn_state(struct unixctl_conn *conn, int argc,
                        const char *argv[], void *aux OVS_UNUSED)
{
    enum dummy_netdev_conn_state state = CONN_STATE_UNKNOWN;
    struct ds s;

    ds_init(&s);

    if (argc > 1) {
        const char *dev_name = argv[1];
        struct netdev *netdev = netdev_from_name(dev_name);

        if (netdev && is_dummy_class(netdev->netdev_class)) {
            struct netdev_dummy *dummy_dev = netdev_dummy_cast(netdev);

            ovs_mutex_lock(&dummy_dev->mutex);
            state = dummy_netdev_get_conn_state(&dummy_dev->conn);
            ovs_mutex_unlock(&dummy_dev->mutex);

            netdev_close(netdev);
        }
        display_conn_state__(&s, dev_name, state);
    } else {
        struct netdev_dummy *netdev;

        ovs_mutex_lock(&dummy_list_mutex);
        LIST_FOR_EACH (netdev, list_node, &dummy_list) {
            ovs_mutex_lock(&netdev->mutex);
            state = dummy_netdev_get_conn_state(&netdev->conn);
            ovs_mutex_unlock(&netdev->mutex);
            if (state != CONN_STATE_UNKNOWN) {
                display_conn_state__(&s, netdev->up.name, state);
            }
        }
        ovs_mutex_unlock(&dummy_list_mutex);
    }

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
netdev_dummy_ip4addr(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[], void *aux OVS_UNUSED)
{
    struct netdev *netdev = netdev_from_name(argv[1]);

    if (netdev && is_dummy_class(netdev->netdev_class)) {
        struct in_addr ip;
        uint16_t plen;

        if (ovs_scan(argv[2], IP_SCAN_FMT"/%"SCNi16,
                     IP_SCAN_ARGS(&ip.s_addr), &plen)) {
            struct in_addr mask;

            mask.s_addr = be32_prefix_mask(plen);
            netdev_dummy_set_in4(netdev, ip, mask);
            unixctl_command_reply(conn, "OK");
        } else {
            unixctl_command_reply(conn, "Invalid parameters");
        }

        netdev_close(netdev);
    } else {
        unixctl_command_reply_error(conn, "Unknown Dummy Interface");
        netdev_close(netdev);
        return;
    }

}

void
netdev_dummy_register(bool override)
{
    unixctl_command_register("netdev-dummy/receive", "name packet|flow...",
                             2, INT_MAX, netdev_dummy_receive, NULL);
    unixctl_command_register("netdev-dummy/set-admin-state",
                             "[netdev] up|down", 1, 2,
                             netdev_dummy_set_admin_state, NULL);
    unixctl_command_register("netdev-dummy/conn-state",
                             "[netdev]", 0, 1,
                             netdev_dummy_conn_state, NULL);
    unixctl_command_register("netdev-dummy/ip4addr",
                             "[netdev] ipaddr/mask-prefix-len", 2, 2,
                             netdev_dummy_ip4addr, NULL);


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
