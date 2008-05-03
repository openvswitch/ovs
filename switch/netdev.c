/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include "netdev.h"

#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "fatal-signal.h"
#include "buffer.h"
#include "openflow.h"
#include "packets.h"
#include "poll-loop.h"

#define THIS_MODULE VLM_netdev
#include "vlog.h"

struct netdev {
    struct list node;
    char *name;
    int fd;
    uint8_t etheraddr[ETH_ADDR_LEN];
    int speed;
    int mtu;
    uint32_t features;
    int save_flags;
};

static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

static void init_netdev(void);
static int restore_flags(struct netdev *netdev);

/* Check whether device NAME has an IPv4 address assigned to it and, if so, log
 * an error. */
static void
check_ipv4_address(const char *name)
{
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        VLOG_WARN("socket(AF_INET): %s", strerror(errno));
        return;
    }

    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        VLOG_ERR("%s device has assigned IP address %s", name,
                 inet_ntoa(((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr));
    }

    close(sock);
}

/* Check whether device NAME has an IPv6 address assigned to it and, if so, log
 * an error. */
static void
check_ipv6_address(const char *name)
{
    FILE *file;
    char line[128];

    file = fopen("/proc/net/if_inet6", "r");
    if (file == NULL) {
        return;
    }

    while (fgets(line, sizeof line, file)) {
        struct in6_addr in6;
        uint8_t *s6 = in6.s6_addr;
        char ifname[16 + 1];

#define X8 "%2"SCNx8
        if (sscanf(line, " "X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8
                   "%*x %*x %*x %*x %16s\n",
                   &s6[0], &s6[1], &s6[2], &s6[3],
                   &s6[4], &s6[5], &s6[6], &s6[7],
                   &s6[8], &s6[9], &s6[10], &s6[11],
                   &s6[12], &s6[13], &s6[14], &s6[15],
                   ifname) == 17
            && !strcmp(name, ifname))
        {
            char in6_name[INET6_ADDRSTRLEN + 1];
            inet_ntop(AF_INET6, &in6, in6_name, sizeof in6_name);
            VLOG_ERR("%s device has assigned IPv6 address %s",
                     name, in6_name);
        }
    }

    fclose(file);
}

static void
do_ethtool(struct netdev *netdev) 
{
    struct ifreq ifr;
    struct ethtool_cmd ecmd;

    netdev->speed = 0;
    netdev->features = 0;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) &ecmd;

    memset(&ecmd, 0, sizeof ecmd);
    ecmd.cmd = ETHTOOL_GSET;
    if (ioctl(netdev->fd, SIOCETHTOOL, &ifr) == 0) {
        if (ecmd.supported & SUPPORTED_10baseT_Half) {
            netdev->features |= OFPPF_10MB_HD;
        }
        if (ecmd.supported & SUPPORTED_10baseT_Full) {
            netdev->features |= OFPPF_10MB_FD;
        }
        if (ecmd.supported & SUPPORTED_100baseT_Half)  {
            netdev->features |= OFPPF_100MB_HD;
        }
        if (ecmd.supported & SUPPORTED_100baseT_Full) {
            netdev->features |= OFPPF_100MB_FD;
        }
        if (ecmd.supported & SUPPORTED_1000baseT_Half) {
            netdev->features |= OFPPF_1GB_HD;
        }
        if (ecmd.supported & SUPPORTED_1000baseT_Full) {
            netdev->features |= OFPPF_1GB_FD;
        }
        /* 10Gbps half-duplex doesn't exist... */
        if (ecmd.supported & SUPPORTED_10000baseT_Full) {
            netdev->features |= OFPPF_10GB_FD;
        }

        switch (ecmd.speed) {
        case SPEED_10:
            netdev->speed = 10;
            break;

        case SPEED_100:
            netdev->speed = 100;
            break;

        case SPEED_1000:
            netdev->speed = 1000;
            break;

        case SPEED_2500:
            netdev->speed = 2500;
            break;

        case SPEED_10000:
            netdev->speed = 10000;
            break;
        }
    } else {
        VLOG_DBG("ioctl(SIOCETHTOOL) failed: %s", strerror(errno));
    }
}

/* Opens the network device named 'name' (e.g. "eth0") and returns zero if
 * successful, otherwise a positive errno value.  On success, sets '*netdev'
 * to the new network device, otherwise to null. */
int
netdev_open(const char *name, struct netdev **netdev_)
{
    int fd;
    struct sockaddr sa;
    struct ifreq ifr;
    unsigned int ifindex;
    socklen_t rcvbuf_len;
    size_t rcvbuf;
    uint8_t etheraddr[ETH_ADDR_LEN];
    int mtu;
    int error;
    struct netdev *netdev;

    *netdev_ = NULL;
    init_netdev();

    /* Create raw socket.
     *
     * We have to use SOCK_PACKET, despite its deprecation, because only
     * SOCK_PACKET lets us set the hardware source address of outgoing
     * packets. */
    fd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ALL));
    if (fd < 0) {
        return errno;
    }

    /* Bind to specific ethernet device. */
    memset(&sa, 0, sizeof sa);
    sa.sa_family = AF_UNSPEC;
    strncpy((char *) sa.sa_data, name, sizeof sa.sa_data);
    if (bind(fd, &sa, sizeof sa) < 0) {
        VLOG_ERR("bind to %s failed: %s", name, strerror(errno));
        goto error;
    }

    /* Between the socket() and bind() calls above, the socket receives all
     * packets on all system interfaces.  We do not want to receive that
     * data, but there is no way to avoid it.  So we must now drain out the
     * receive queue.  There is no way to know how long the receive queue is,
     * but we know that the total number of bytes queued does not exceed the
     * receive buffer size, so we pull packets until none are left or we've
     * read that many bytes. */
    rcvbuf_len = sizeof rcvbuf;
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbuf_len) < 0) {
        VLOG_ERR("getsockopt(SO_RCVBUF) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    while (rcvbuf > 0) {
        char buffer;
        ssize_t n_bytes = recv(fd, &buffer, 1, MSG_TRUNC | MSG_DONTWAIT);
        if (n_bytes <= 0) {
            break;
        }
        rcvbuf -= n_bytes;
    }

    /* Get ethernet device index. */
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFINDEX) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    ifindex = ifr.ifr_ifindex;

    /* Get MAC address. */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFHWADDR) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    if (ifr.ifr_hwaddr.sa_family != AF_UNSPEC
        && ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        VLOG_WARN("%s device has unknown hardware address family %d",
                  name, (int) ifr.ifr_hwaddr.sa_family);
    }
    memcpy(etheraddr, ifr.ifr_hwaddr.sa_data, sizeof etheraddr);

    /* Get MTU. */
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFMTU) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    mtu = ifr.ifr_mtu;

    /* Allocate network device. */
    netdev = xmalloc(sizeof *netdev);
    netdev->name = xstrdup(name);
    netdev->fd = fd;
    memcpy(netdev->etheraddr, etheraddr, sizeof etheraddr);
    netdev->mtu = mtu;

    /* Get speed, features. */
    do_ethtool(netdev);

    /* Save flags to restore at close or exit. */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFFLAGS) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    netdev->save_flags = ifr.ifr_flags;
    fatal_signal_block();
    list_push_back(&netdev_list, &netdev->node);
    fatal_signal_unblock();

    /* Bring up interface and set promiscuous mode. */
    ifr.ifr_flags |= IFF_PROMISC | IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        error = errno;
        VLOG_ERR("failed to set promiscuous mode on %s device: %s",
                 name, strerror(errno));
        netdev_close(netdev);
        return error;
    }

    /* Complain to administrator if any IP addresses are assigned to the
     * interface.  We warn about this because packets received for that IP
     * address will be processed both by the kernel TCP/IP stack and by us as a
     * switch, which produces poor results. */
    check_ipv4_address(name);
    check_ipv6_address(name);

    /* Success! */
    *netdev_ = netdev;
    return 0;

error:
    error = errno;
    close(fd);
    return error;
}

/* Closes and destroys 'netdev'. */
void
netdev_close(struct netdev *netdev)
{
    if (netdev) {
        /* Bring down interface and drop promiscuous mode, if we brought up
         * the interface or enabled promiscuous mode. */
        int error;
        fatal_signal_block();
        error = restore_flags(netdev);
        list_remove(&netdev->node);
        fatal_signal_unblock();
        if (error) {
            VLOG_WARN("failed to restore network device flags on %s: %s",
                      netdev->name, strerror(error));
        }

        /* Free. */
        free(netdev->name);
        close(netdev->fd);
        free(netdev);
    }
}

/* Pads 'buffer' out with zero-bytes to the minimum valid length of an
 * Ethernet packet, if necessary.  */
static void
pad_to_minimum_length(struct buffer *buffer)
{
    if (buffer->size < ETH_TOTAL_MIN) {
        size_t shortage = ETH_TOTAL_MIN - buffer->size;
        memset(buffer_put_uninit(buffer, shortage), 0, shortage);
    }
}

/* Attempts to receive a packet from 'netdev' into 'buffer', which the caller
 * must have initialized with sufficient room for the packet.  The space
 * required to receive any packet is ETH_HEADER_LEN bytes, plus VLAN_HEADER_LEN
 * bytes, plus the device's MTU (which may be retrieved via netdev_get_mtu()).
 * (Some devices do not allow for a VLAN header, in which case VLAN_HEADER_LEN
 * need not be included.)
 *
 * If a packet is successfully retrieved, returns 0.  In this case 'buffer' is
 * guaranteed to contain at least ETH_TOTAL_MIN bytes.  Otherwise, returns a
 * positive errno value.  Returns EAGAIN immediately if no packet is ready to
 * be returned.
 */
int
netdev_recv(struct netdev *netdev, struct buffer *buffer)
{
    ssize_t n_bytes;

    assert(buffer->size == 0);
    assert(buffer_tailroom(buffer) >= ETH_TOTAL_MIN);
    do {
        n_bytes = recv(netdev->fd,
                       buffer_tail(buffer), buffer_tailroom(buffer),
                       MSG_DONTWAIT);
    } while (n_bytes < 0 && errno == EINTR);
    if (n_bytes < 0) {
        if (errno != EAGAIN) {
            VLOG_WARN("error receiving Ethernet packet on %s: %s",
                      strerror(errno), netdev->name);
        }
        return errno;
    } else {
        buffer->size += n_bytes;

        /* When the kernel internally sends out an Ethernet frame on an
         * interface, it gives us a copy *before* padding the frame to the
         * minimum length.  Thus, when it sends out something like an ARP
         * request, we see a too-short frame.  So pad it out to the minimum
         * length. */
        pad_to_minimum_length(buffer);
        return 0;
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_recv() on 'netdev'. */
void
netdev_recv_wait(struct netdev *netdev)
{
    poll_fd_wait(netdev->fd, POLLIN);
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big to transmit on the device.
 *
 * The kernel maintains a packet transmission queue, so the caller is not
 * expected to do additional queuing of packets. */
int
netdev_send(struct netdev *netdev, struct buffer *buffer)
{
    ssize_t n_bytes;
    const struct eth_header *eh;
    struct sockaddr_pkt spkt;

    /* Ensure packet is long enough.  (Although all incoming packets are at
     * least ETH_TOTAL_MIN bytes long, we could have trimmed some data off a
     * minimum-size packet, e.g. by dropping a vlan header.)
     *
     * The kernel does not require this, but it ensures that we always access
     * valid memory in grabbing the sockaddr below. */
    pad_to_minimum_length(buffer);

    /* Construct packet sockaddr, which SOCK_PACKET requires. */
    spkt.spkt_family = AF_PACKET;
    strncpy((char *) spkt.spkt_device, netdev->name, sizeof spkt.spkt_device);
    eh = buffer_at_assert(buffer, 0, sizeof *eh);
    spkt.spkt_protocol = eh->eth_type;

    do {
        n_bytes = sendto(netdev->fd, buffer->data, buffer->size, 0,
                         (const struct sockaddr *) &spkt, sizeof spkt);
    } while (n_bytes < 0 && errno == EINTR);

    if (n_bytes < 0) {
        /* The Linux AF_PACKET implementation never blocks waiting for room
         * for packets, instead returning ENOBUFS.  Translate this into EAGAIN
         * for the caller. */
        if (errno == ENOBUFS) {
            return EAGAIN;
        } else if (errno != EAGAIN) {
            VLOG_WARN("error sending Ethernet packet on %s: %s",
                      netdev->name, strerror(errno));
        }
        return errno;
    } else if (n_bytes != buffer->size) {
        VLOG_WARN("send partial Ethernet packet (%d bytes of %d) on %s",
                  (int) n_bytes, buffer->size, netdev->name);
        return EMSGSIZE;
    } else {
        return 0;
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The kernel maintains a packet transmission queue, so the client is not
 * expected to do additional queuing of packets.  Thus, this function is
 * unlikely to ever be used.  It is included for completeness. */
void
netdev_send_wait(struct netdev *netdev)
{
    poll_fd_wait(netdev->fd, POLLOUT);
}

/* Returns a pointer to 'netdev''s MAC address.  The caller must not modify or
 * free the returned buffer. */
const uint8_t *
netdev_get_etheraddr(const struct netdev *netdev)
{
    return netdev->etheraddr;
}

/* Returns the name of the network device that 'netdev' represents,
 * e.g. "eth0".  The caller must not modify or free the returned string. */
const char *
netdev_get_name(const struct netdev *netdev)
{
    return netdev->name;
}

/* Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices. */
int
netdev_get_mtu(const struct netdev *netdev) 
{
    return netdev->mtu;
}

/* Returns the current speed of the network device that 'netdev' represents, in
 * megabits per second, or 0 if the speed is unknown. */
int
netdev_get_speed(const struct netdev *netdev) 
{
    return netdev->speed;
}

/* Returns the features supported by 'netdev', as a bitmap of bits from enum
 * ofp_phy_port, in host byte order. */
uint32_t
netdev_get_features(const struct netdev *netdev) 
{
    return netdev->features;
}

static void restore_all_flags(void *aux);

/* Set up a signal hook to restore network device flags on program
 * termination.  */
static void
init_netdev(void)
{
    static bool inited;
    if (!inited) {
        inited = true;
        fatal_signal_add_hook(restore_all_flags, NULL);
    }
}

/* Restore the network device flags on 'netdev' to those that were active
 * before we changed them.  Returns 0 if successful, otherwise a positive
 * errno value.
 *
 * To avoid reentry, the caller must ensure that fatal signals are blocked. */
static int
restore_flags(struct netdev *netdev)
{
    struct ifreq ifr;

    /* Get current flags. */
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    if (ioctl(netdev->fd, SIOCGIFFLAGS, &ifr) < 0) {
        return errno;
    }

    /* Restore flags that we might have changed, if necessary. */
    if ((ifr.ifr_flags ^ netdev->save_flags) & (IFF_PROMISC | IFF_UP)) {
        ifr.ifr_flags &= ~(IFF_PROMISC | IFF_UP);
        ifr.ifr_flags |= netdev->save_flags & (IFF_PROMISC | IFF_UP);
        if (ioctl(netdev->fd, SIOCSIFFLAGS, &ifr) < 0) {
            return errno;
        }
    }

    return 0;
}

/* Retores all the flags on all network devices that we modified.  Called from
 * a signal handler, so it does not attempt to report error conditions. */
static void
restore_all_flags(void *aux UNUSED)
{
    struct netdev *netdev;
    LIST_FOR_EACH (netdev, struct netdev, node, &netdev_list) {
        restore_flags(netdev);
    }
}
