/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "netdev.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "netdev-linux.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "socket-util.h"
#include "svec.h"

/* linux/if.h defines IFF_LOWER_UP, net/if.h doesn't.
 * net/if.h defines if_nameindex(), linux/if.h doesn't.
 * We can't include both headers, so define IFF_LOWER_UP ourselves. */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

/* These were introduced in Linux 2.6.14, so they might be missing if we have
 * old headers. */
#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause                (1 << 13)
#endif
#ifndef ADVERTISED_Asym_Pause
#define ADVERTISED_Asym_Pause           (1 << 14)
#endif

#define THIS_MODULE VLM_netdev
#include "vlog.h"

struct netdev {
    struct list node;
    char *name;

    /* File descriptors.  For ordinary network devices, the two fds below are
     * the same; for tap devices, they differ. */
    int netdev_fd;              /* Network device. */
    int tap_fd;                 /* TAP character device, if any, otherwise the
                                 * network device. */

    /* Cached network device information. */
    int ifindex;                /* -1 if not known. */
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in6_addr in6;
    int speed;
    int mtu;
    int txqlen;
    int hwaddr_family;

    int save_flags;             /* Initial device flags. */
    int changed_flags;          /* Flags that we changed. */
};

/* Policy for RTNLGRP_LINK messages.
 *
 * There are *many* more fields in these messages, but currently we only care
 * about interface names. */
static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
    [IFLA_STATS] = { .type = NL_A_UNSPEC, .optional = true,
                     .min_len = sizeof(struct rtnl_link_stats) },
};

/* All open network devices. */
static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

/* An AF_INET socket (used for ioctl operations). */
static int af_inet_sock = -1;

/* NETLINK_ROUTE socket. */
static struct nl_sock *rtnl_sock;

/* Can we use RTM_GETLINK to get network device statistics?  (In pre-2.6.19
 * kernels, this was only available if wireless extensions were enabled.) */
static bool use_netlink_stats;

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void init_netdev(void);
static int do_open_netdev(const char *name, int ethertype, int tap_fd,
                          struct netdev **netdev_);
static int restore_flags(struct netdev *netdev);
static int get_flags(const char *netdev_name, int *flagsp);
static int set_flags(const char *netdev_name, int flags);
static int do_get_ifindex(const char *netdev_name);
static int get_ifindex(const struct netdev *, int *ifindexp);
static int get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN],
                         int *hwaddr_familyp);
static int set_etheraddr(const char *netdev_name, int hwaddr_family,
                         const uint8_t[ETH_ADDR_LEN]);

/* Obtains the IPv6 address for 'name' into 'in6'. */
static void
get_ipv6_address(const char *name, struct in6_addr *in6)
{
    FILE *file;
    char line[128];

    file = fopen("/proc/net/if_inet6", "r");
    if (file == NULL) {
        /* This most likely indicates that the host doesn't have IPv6 support,
         * so it's not really a failure condition.*/
        *in6 = in6addr_any;
        return;
    }

    while (fgets(line, sizeof line, file)) {
        uint8_t *s6 = in6->s6_addr;
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
            fclose(file);
            return;
        }
    }
    *in6 = in6addr_any;

    fclose(file);
}

static int
do_ethtool(struct netdev *netdev, struct ethtool_cmd *ecmd,
           int cmd, const char *cmd_name)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) ecmd;

    ecmd->cmd = cmd;
    COVERAGE_INC(netdev_ethtool);
    if (ioctl(netdev->netdev_fd, SIOCETHTOOL, &ifr) == 0) {
        return 0;
    } else {
        if (errno != EOPNOTSUPP) {
            VLOG_WARN_RL(&rl, "ethtool command %s on network device %s "
                         "failed: %s", cmd_name, netdev->name,
                         strerror(errno));
        } else {
            /* The device doesn't support this operation.  That's pretty
             * common, so there's no point in logging anything. */
        }
        return errno;
    }
}

static int
do_get_features(struct netdev *netdev,
                uint32_t *current, uint32_t *advertised,
                uint32_t *supported, uint32_t *peer)
{
    struct ethtool_cmd ecmd;
    int error;

    *current = 0;
    *supported = 0;
    *advertised = 0;
    *peer = 0;

    memset(&ecmd, 0, sizeof ecmd);
    error = do_ethtool(netdev, &ecmd, ETHTOOL_GSET, "ETHTOOL_GSET");
    if (error) {
        return error;
    }

    if (ecmd.supported & SUPPORTED_10baseT_Half) {
        *supported |= OFPPF_10MB_HD;
    }
    if (ecmd.supported & SUPPORTED_10baseT_Full) {
        *supported |= OFPPF_10MB_FD;
    }
    if (ecmd.supported & SUPPORTED_100baseT_Half)  {
        *supported |= OFPPF_100MB_HD;
    }
    if (ecmd.supported & SUPPORTED_100baseT_Full) {
        *supported |= OFPPF_100MB_FD;
    }
    if (ecmd.supported & SUPPORTED_1000baseT_Half) {
        *supported |= OFPPF_1GB_HD;
    }
    if (ecmd.supported & SUPPORTED_1000baseT_Full) {
        *supported |= OFPPF_1GB_FD;
    }
    if (ecmd.supported & SUPPORTED_10000baseT_Full) {
        *supported |= OFPPF_10GB_FD;
    }
    if (ecmd.supported & SUPPORTED_TP) {
        *supported |= OFPPF_COPPER;
    }
    if (ecmd.supported & SUPPORTED_FIBRE) {
        *supported |= OFPPF_FIBER;
    }
    if (ecmd.supported & SUPPORTED_Autoneg) {
        *supported |= OFPPF_AUTONEG;
    }
    if (ecmd.supported & SUPPORTED_Pause) {
        *supported |= OFPPF_PAUSE;
    }
    if (ecmd.supported & SUPPORTED_Asym_Pause) {
        *supported |= OFPPF_PAUSE_ASYM;
    }

    /* Set the advertised features */
    if (ecmd.advertising & ADVERTISED_10baseT_Half) {
        *advertised |= OFPPF_10MB_HD;
    }
    if (ecmd.advertising & ADVERTISED_10baseT_Full) {
        *advertised |= OFPPF_10MB_FD;
    }
    if (ecmd.advertising & ADVERTISED_100baseT_Half) {
        *advertised |= OFPPF_100MB_HD;
    }
    if (ecmd.advertising & ADVERTISED_100baseT_Full) {
        *advertised |= OFPPF_100MB_FD;
    }
    if (ecmd.advertising & ADVERTISED_1000baseT_Half) {
        *advertised |= OFPPF_1GB_HD;
    }
    if (ecmd.advertising & ADVERTISED_1000baseT_Full) {
        *advertised |= OFPPF_1GB_FD;
    }
    if (ecmd.advertising & ADVERTISED_10000baseT_Full) {
        *advertised |= OFPPF_10GB_FD;
    }
    if (ecmd.advertising & ADVERTISED_TP) {
        *advertised |= OFPPF_COPPER;
    }
    if (ecmd.advertising & ADVERTISED_FIBRE) {
        *advertised |= OFPPF_FIBER;
    }
    if (ecmd.advertising & ADVERTISED_Autoneg) {
        *advertised |= OFPPF_AUTONEG;
    }
    if (ecmd.advertising & ADVERTISED_Pause) {
        *advertised |= OFPPF_PAUSE;
    }
    if (ecmd.advertising & ADVERTISED_Asym_Pause) {
        *advertised |= OFPPF_PAUSE_ASYM;
    }

    /* Set the current features */
    if (ecmd.speed == SPEED_10) {
        *current = (ecmd.duplex) ? OFPPF_10MB_FD : OFPPF_10MB_HD;
    }
    else if (ecmd.speed == SPEED_100) {
        *current = (ecmd.duplex) ? OFPPF_100MB_FD : OFPPF_100MB_HD;
    }
    else if (ecmd.speed == SPEED_1000) {
        *current = (ecmd.duplex) ? OFPPF_1GB_FD : OFPPF_1GB_HD;
    }
    else if (ecmd.speed == SPEED_10000) {
        *current = OFPPF_10GB_FD;
    }

    if (ecmd.port == PORT_TP) {
        *current |= OFPPF_COPPER;
    }
    else if (ecmd.port == PORT_FIBRE) {
        *current |= OFPPF_FIBER;
    }

    if (ecmd.autoneg) {
        *current |= OFPPF_AUTONEG;
    }
    return 0;
}

/* Opens the network device named 'name' (e.g. "eth0") and returns zero if
 * successful, otherwise a positive errno value.  On success, sets '*netdevp'
 * to the new network device, otherwise to null.
 *
 * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order to
 * capture frames of that type received on the device.  It may also be one of
 * the 'enum netdev_pseudo_ethertype' values to receive frames in one of those
 * categories. */
int
netdev_open(const char *name, int ethertype, struct netdev **netdevp) 
{
    if (!strncmp(name, "tap:", 4)) {
        return netdev_open_tap(name + 4, netdevp);
    } else {
        return do_open_netdev(name, ethertype, -1, netdevp); 
    }
}

/* Opens a TAP virtual network device.  If 'name' is a nonnull, non-empty
 * string, attempts to assign that name to the TAP device (failing if the name
 * is already in use); otherwise, a name is automatically assigned.  Returns
 * zero if successful, otherwise a positive errno value.  On success, sets
 * '*netdevp' to the new network device, otherwise to null.  */
int
netdev_open_tap(const char *name, struct netdev **netdevp)
{
    static const char tap_dev[] = "/dev/net/tun";
    struct ifreq ifr;
    int error;
    int tap_fd;

    tap_fd = open(tap_dev, O_RDWR);
    if (tap_fd < 0) {
        ovs_error(errno, "opening \"%s\" failed", tap_dev);
        return errno;
    }

    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (name) {
        strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    }
    if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
        int error = errno;
        ovs_error(error, "ioctl(TUNSETIFF) on \"%s\" failed", tap_dev);
        close(tap_fd);
        return error;
    }

    error = set_nonblocking(tap_fd);
    if (error) {
        ovs_error(error, "set_nonblocking on \"%s\" failed", tap_dev);
        close(tap_fd);
        return error;
    }

    error = do_open_netdev(ifr.ifr_name, NETDEV_ETH_TYPE_NONE, tap_fd,
                           netdevp);
    if (error) {
        close(tap_fd);
    }
    return error;
}

static int
do_open_netdev(const char *name, int ethertype, int tap_fd,
               struct netdev **netdev_)
{
    int netdev_fd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int ifindex = -1;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in6_addr in6;
    int mtu;
    int txqlen;
    int hwaddr_family;
    int error;
    struct netdev *netdev;

    init_netdev();
    *netdev_ = NULL;
    COVERAGE_INC(netdev_open);

    /* Create raw socket. */
    netdev_fd = socket(PF_PACKET, SOCK_RAW,
                       htons(ethertype == NETDEV_ETH_TYPE_NONE ? 0
                             : ethertype == NETDEV_ETH_TYPE_ANY ? ETH_P_ALL
                             : ethertype == NETDEV_ETH_TYPE_802_2 ? ETH_P_802_2
                             : ethertype));
    if (netdev_fd < 0) {
        return errno;
    }

    if (ethertype != NETDEV_ETH_TYPE_NONE) {
        /* Set non-blocking mode. */
        error = set_nonblocking(netdev_fd);
        if (error) {
            goto error_already_set;
        }

        /* Get ethernet device index. */
        ifindex = do_get_ifindex(name);
        if (ifindex < 0) {
            return -ifindex;
        }

        /* Bind to specific ethernet device. */
        memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        if (bind(netdev_fd, (struct sockaddr *) &sll, sizeof sll) < 0) {
            VLOG_ERR("bind to %s failed: %s", name, strerror(errno));
            goto error;
        }

        /* Between the socket() and bind() calls above, the socket receives all
         * packets of the requested type on all system interfaces.  We do not
         * want to receive that data, but there is no way to avoid it.  So we
         * must now drain out the receive queue. */
        error = drain_rcvbuf(netdev_fd);
        if (error) {
            goto error_already_set;
        }
    }

    /* Get MAC address. */
    error = get_etheraddr(name, etheraddr, &hwaddr_family);
    if (error) {
        goto error_already_set;
    }

    /* Get MTU. */
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(netdev_fd, SIOCGIFMTU, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFMTU) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    mtu = ifr.ifr_mtu;

    /* Get TX queue length. */
    if (ioctl(netdev_fd, SIOCGIFTXQLEN, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFTXQLEN) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    txqlen = ifr.ifr_qlen;

    get_ipv6_address(name, &in6);

    /* Allocate network device. */
    netdev = xmalloc(sizeof *netdev);
    netdev->name = xstrdup(name);
    netdev->ifindex = ifindex;
    netdev->txqlen = txqlen;
    netdev->hwaddr_family = hwaddr_family;
    netdev->netdev_fd = netdev_fd;
    netdev->tap_fd = tap_fd < 0 ? netdev_fd : tap_fd;
    memcpy(netdev->etheraddr, etheraddr, sizeof etheraddr);
    netdev->mtu = mtu;
    netdev->in6 = in6;

    /* Save flags to restore at close or exit. */
    error = get_flags(netdev->name, &netdev->save_flags);
    if (error) {
        goto error_already_set;
    }
    netdev->changed_flags = 0;
    fatal_signal_block();
    list_push_back(&netdev_list, &netdev->node);
    fatal_signal_unblock();

    /* Success! */
    *netdev_ = netdev;
    return 0;

error:
    error = errno;
error_already_set:
    close(netdev_fd);
    if (tap_fd >= 0) {
        close(tap_fd);
    }
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
        close(netdev->netdev_fd);
        if (netdev->netdev_fd != netdev->tap_fd) {
            close(netdev->tap_fd);
        }
        free(netdev);
    }
}

/* Pads 'buffer' out with zero-bytes to the minimum valid length of an
 * Ethernet packet, if necessary.  */
static void
pad_to_minimum_length(struct ofpbuf *buffer)
{
    if (buffer->size < ETH_TOTAL_MIN) {
        ofpbuf_put_zeros(buffer, ETH_TOTAL_MIN - buffer->size);
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
netdev_recv(struct netdev *netdev, struct ofpbuf *buffer)
{
    ssize_t n_bytes;

    assert(buffer->size == 0);
    assert(ofpbuf_tailroom(buffer) >= ETH_TOTAL_MIN);
    do {
        n_bytes = read(netdev->tap_fd,
                       ofpbuf_tail(buffer), ofpbuf_tailroom(buffer));
    } while (n_bytes < 0 && errno == EINTR);
    if (n_bytes < 0) {
        if (errno != EAGAIN) {
            VLOG_WARN_RL(&rl, "error receiving Ethernet packet on %s: %s",
                         strerror(errno), netdev->name);
        }
        return errno;
    } else {
        COVERAGE_INC(netdev_received);
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
    poll_fd_wait(netdev->tap_fd, POLLIN);
}

/* Discards all packets waiting to be received from 'netdev'. */
int
netdev_drain(struct netdev *netdev)
{
    if (netdev->tap_fd != netdev->netdev_fd) {
        drain_fd(netdev->tap_fd, netdev->txqlen);
        return 0;
    } else {
        return drain_rcvbuf(netdev->netdev_fd);
    }
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big or too small to transmit on the device.
 *
 * The caller retains ownership of 'buffer' in all cases.
 *
 * The kernel maintains a packet transmission queue, so the caller is not
 * expected to do additional queuing of packets. */
int
netdev_send(struct netdev *netdev, const struct ofpbuf *buffer)
{
    ssize_t n_bytes;

    do {
        n_bytes = write(netdev->tap_fd, buffer->data, buffer->size);
    } while (n_bytes < 0 && errno == EINTR);

    if (n_bytes < 0) {
        /* The Linux AF_PACKET implementation never blocks waiting for room
         * for packets, instead returning ENOBUFS.  Translate this into EAGAIN
         * for the caller. */
        if (errno == ENOBUFS) {
            return EAGAIN;
        } else if (errno != EAGAIN) {
            VLOG_WARN_RL(&rl, "error sending Ethernet packet on %s: %s",
                         netdev->name, strerror(errno));
        }
        return errno;
    } else if (n_bytes != buffer->size) {
        VLOG_WARN_RL(&rl,
                     "send partial Ethernet packet (%d bytes of %zu) on %s",
                     (int) n_bytes, buffer->size, netdev->name);
        return EMSGSIZE;
    } else {
        COVERAGE_INC(netdev_sent);
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
    if (netdev->tap_fd == netdev->netdev_fd) {
        poll_fd_wait(netdev->tap_fd, POLLOUT);
    } else {
        /* TAP device always accepts packets.*/
        poll_immediate_wake();
    }
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_set_etheraddr(struct netdev *netdev, const uint8_t mac[ETH_ADDR_LEN])
{
    int error = set_etheraddr(netdev->name, netdev->hwaddr_family, mac);
    if (!error) {
        memcpy(netdev->etheraddr, mac, ETH_ADDR_LEN);
    }
    return error;
}

int
netdev_nodev_set_etheraddr(const char *name, const uint8_t mac[ETH_ADDR_LEN])
{
    init_netdev();
    return set_etheraddr(name, ARPHRD_ETHER, mac);
}

/* Retrieves 'netdev''s MAC address.  If successful, returns 0 and copies the
 * the MAC address into 'mac'.  On failure, returns a positive errno value and
 * clears 'mac' to all-zeros. */
int
netdev_get_etheraddr(const struct netdev *netdev, uint8_t mac[ETH_ADDR_LEN])
{
    memcpy(mac, netdev->etheraddr, ETH_ADDR_LEN);
    return 0;
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

/* Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0. */
int
netdev_get_features(struct netdev *netdev,
                    uint32_t *current, uint32_t *advertised,
                    uint32_t *supported, uint32_t *peer)
{
    uint32_t dummy[4];
    return do_get_features(netdev,
                           current ? current : &dummy[0],
                           advertised ? advertised : &dummy[1],
                           supported ? supported : &dummy[2],
                           peer ? peer : &dummy[3]);
}

/* Set the features advertised by 'netdev' to 'advertise'. */
int
netdev_set_advertisements(struct netdev *netdev, uint32_t advertise)
{
    struct ethtool_cmd ecmd;
    int error;

    memset(&ecmd, 0, sizeof ecmd);
    error = do_ethtool(netdev, &ecmd, ETHTOOL_GSET, "ETHTOOL_GSET");
    if (error) {
        return error;
    }

    ecmd.advertising = 0;
    if (advertise & OFPPF_10MB_HD) {
        ecmd.advertising |= ADVERTISED_10baseT_Half;
    }
    if (advertise & OFPPF_10MB_FD) {
        ecmd.advertising |= ADVERTISED_10baseT_Full;
    }
    if (advertise & OFPPF_100MB_HD) {
        ecmd.advertising |= ADVERTISED_100baseT_Half;
    }
    if (advertise & OFPPF_100MB_FD) {
        ecmd.advertising |= ADVERTISED_100baseT_Full;
    }
    if (advertise & OFPPF_1GB_HD) {
        ecmd.advertising |= ADVERTISED_1000baseT_Half;
    }
    if (advertise & OFPPF_1GB_FD) {
        ecmd.advertising |= ADVERTISED_1000baseT_Full;
    }
    if (advertise & OFPPF_10GB_FD) {
        ecmd.advertising |= ADVERTISED_10000baseT_Full;
    }
    if (advertise & OFPPF_COPPER) {
        ecmd.advertising |= ADVERTISED_TP;
    }
    if (advertise & OFPPF_FIBER) {
        ecmd.advertising |= ADVERTISED_FIBRE;
    }
    if (advertise & OFPPF_AUTONEG) {
        ecmd.advertising |= ADVERTISED_Autoneg;
    }
    if (advertise & OFPPF_PAUSE) {
        ecmd.advertising |= ADVERTISED_Pause;
    }
    if (advertise & OFPPF_PAUSE_ASYM) {
        ecmd.advertising |= ADVERTISED_Asym_Pause;
    }
    return do_ethtool(netdev, &ecmd, ETHTOOL_SSET, "ETHTOOL_SSET");
}

/* If 'netdev' has an assigned IPv4 address, sets '*in4' to that address (if
 * 'in4' is non-null) and returns true.  Otherwise, returns false. */
bool
netdev_nodev_get_in4(const char *netdev_name, struct in_addr *in4)
{
    struct ifreq ifr;
    struct in_addr ip = { INADDR_ANY };

    init_netdev();

    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_family = AF_INET;
    COVERAGE_INC(netdev_get_in4);
    if (ioctl(af_inet_sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
        ip = sin->sin_addr;
    } else {
        VLOG_DBG_RL(&rl, "%s: ioctl(SIOCGIFADDR) failed: %s",
                    netdev_name, strerror(errno));
    }
    if (in4) {
        *in4 = ip;
    }
    return ip.s_addr != INADDR_ANY;
}

bool
netdev_get_in4(const struct netdev *netdev, struct in_addr *in4)
{
    return netdev_nodev_get_in4(netdev->name, in4);
}

static void
make_in4_sockaddr(struct sockaddr *sa, struct in_addr addr)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = addr;
    sin.sin_port = 0;

    memset(sa, 0, sizeof *sa);
    memcpy(sa, &sin, sizeof sin);
}

static int
do_set_addr(struct netdev *netdev, int sock,
            int ioctl_nr, const char *ioctl_name, struct in_addr addr)
{
    struct ifreq ifr;
    int error;

    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    make_in4_sockaddr(&ifr.ifr_addr, addr);
    COVERAGE_INC(netdev_set_in4);
    error = ioctl(sock, ioctl_nr, &ifr) < 0 ? errno : 0;
    if (error) {
        VLOG_WARN("ioctl(%s): %s", ioctl_name, strerror(error));
    }
    return error;
}

/* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value. */
int
netdev_set_in4(struct netdev *netdev, struct in_addr addr, struct in_addr mask)
{
    int error;

    error = do_set_addr(netdev, af_inet_sock,
                        SIOCSIFADDR, "SIOCSIFADDR", addr);
    if (!error && addr.s_addr != INADDR_ANY) {
        error = do_set_addr(netdev, af_inet_sock,
                            SIOCSIFNETMASK, "SIOCSIFNETMASK", mask);
    }
    return error;
}

/* Adds 'router' as a default IP gateway. */
int
netdev_add_router(struct in_addr router)
{
    struct in_addr any = { INADDR_ANY };
    struct rtentry rt;
    int error;

    memset(&rt, 0, sizeof rt);
    make_in4_sockaddr(&rt.rt_dst, any);
    make_in4_sockaddr(&rt.rt_gateway, router);
    make_in4_sockaddr(&rt.rt_genmask, any);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    COVERAGE_INC(netdev_add_router);
    error = ioctl(af_inet_sock, SIOCADDRT, &rt) < 0 ? errno : 0;
    if (error) {
        VLOG_WARN("ioctl(SIOCADDRT): %s", strerror(error));
    }
    return error;
}

/* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address (if
 * 'in6' is non-null) and returns true.  Otherwise, returns false. */
bool
netdev_get_in6(const struct netdev *netdev, struct in6_addr *in6)
{
    if (in6) {
        *in6 = netdev->in6;
    }
    return memcmp(&netdev->in6, &in6addr_any, sizeof netdev->in6) != 0;
}

/* Obtains the current flags for 'netdev' and stores them into '*flagsp'.
 * Returns 0 if successful, otherwise a positive errno value.  On failure,
 * stores 0 into '*flagsp'. */
int
netdev_get_flags(const struct netdev *netdev, enum netdev_flags *flagsp)
{
    return netdev_nodev_get_flags(netdev->name, flagsp);
}

static int
nd_to_iff_flags(enum netdev_flags nd)
{
    int iff = 0;
    if (nd & NETDEV_UP) {
        iff |= IFF_UP;
    }
    if (nd & NETDEV_PROMISC) {
        iff |= IFF_PROMISC;
    }
    return iff;
}

/* On 'netdev', turns off the flags in 'off' and then turns on the flags in
 * 'on'.  If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.  Returns 0 if
 * successful, otherwise a positive errno value. */
static int
do_update_flags(struct netdev *netdev, enum netdev_flags off,
                enum netdev_flags on, bool permanent)
{
    int old_flags, new_flags;
    int error;

    error = get_flags(netdev->name, &old_flags);
    if (error) {
        return error;
    }

    new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);
    if (!permanent) {
        netdev->changed_flags |= new_flags ^ old_flags; 
    }
    if (new_flags != old_flags) {
        error = set_flags(netdev->name, new_flags);
    }
    return error;
}

/* Sets the flags for 'netdev' to 'flags'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_flags(struct netdev *netdev, enum netdev_flags flags,
                 bool permanent)
{
    return do_update_flags(netdev, -1, flags, permanent);
}

/* Turns on the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_on(struct netdev *netdev, enum netdev_flags flags,
                     bool permanent)
{
    return do_update_flags(netdev, 0, flags, permanent);
}

/* Turns off the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_off(struct netdev *netdev, enum netdev_flags flags,
                      bool permanent)
{
    return do_update_flags(netdev, flags, 0, permanent);
}

/* Looks up the ARP table entry for 'ip' on 'netdev'.  If one exists and can be
 * successfully retrieved, it stores the corresponding MAC address in 'mac' and
 * returns 0.  Otherwise, it returns a positive errno value; in particular,
 * ENXIO indicates that there is not ARP table entry for 'ip' on 'netdev'. */
int
netdev_nodev_arp_lookup(const char *netdev_name, uint32_t ip, 
                        uint8_t mac[ETH_ADDR_LEN]) 
{
    struct arpreq r;
    struct sockaddr_in *pa;
    int retval;

    init_netdev();

    memset(&r, 0, sizeof r);
    pa = (struct sockaddr_in *) &r.arp_pa;
    pa->sin_family = AF_INET;
    pa->sin_addr.s_addr = ip;
    pa->sin_port = 0;
    r.arp_ha.sa_family = ARPHRD_ETHER;
    r.arp_flags = 0;
    strncpy(r.arp_dev, netdev_name, sizeof r.arp_dev);
    COVERAGE_INC(netdev_arp_lookup);
    retval = ioctl(af_inet_sock, SIOCGARP, &r) < 0 ? errno : 0;
    if (!retval) {
        memcpy(mac, r.arp_ha.sa_data, ETH_ADDR_LEN);
    } else if (retval != ENXIO) {
        VLOG_WARN_RL(&rl, "%s: could not look up ARP entry for "IP_FMT": %s",
                     netdev_name, IP_ARGS(&ip), strerror(retval));
    }
    return retval;
}

int
netdev_arp_lookup(const struct netdev *netdev, uint32_t ip, 
                  uint8_t mac[ETH_ADDR_LEN]) 
{
    return netdev_nodev_arp_lookup(netdev->name, ip, mac);
}

static int
get_stats_via_netlink(int ifindex, struct netdev_stats *stats)
{
    struct ofpbuf request;
    struct ofpbuf *reply;
    struct ifinfomsg *ifi;
    const struct rtnl_link_stats *rtnl_stats;
    struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
    int error;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, rtnl_sock, sizeof *ifi,
                        RTM_GETLINK, NLM_F_REQUEST);
    ifi = ofpbuf_put_zeros(&request, sizeof *ifi);
    ifi->ifi_family = PF_UNSPEC;
    ifi->ifi_index = ifindex;
    error = nl_sock_transact(rtnl_sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (error) {
        return error;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                         rtnlgrp_link_policy,
                         attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
        ofpbuf_delete(reply);
        return EPROTO;
    }

    if (!attrs[IFLA_STATS]) {
        VLOG_WARN_RL(&rl, "RTM_GETLINK reply lacks stats");
        return EPROTO;
    }

    rtnl_stats = nl_attr_get(attrs[IFLA_STATS]);
    stats->rx_packets = rtnl_stats->rx_packets;
    stats->tx_packets = rtnl_stats->tx_packets;
    stats->rx_bytes = rtnl_stats->rx_bytes;
    stats->tx_bytes = rtnl_stats->tx_bytes;
    stats->rx_errors = rtnl_stats->rx_errors;
    stats->tx_errors = rtnl_stats->tx_errors;
    stats->rx_dropped = rtnl_stats->rx_dropped;
    stats->tx_dropped = rtnl_stats->tx_dropped;
    stats->multicast = rtnl_stats->multicast;
    stats->collisions = rtnl_stats->collisions;
    stats->rx_length_errors = rtnl_stats->rx_length_errors;
    stats->rx_over_errors = rtnl_stats->rx_over_errors;
    stats->rx_crc_errors = rtnl_stats->rx_crc_errors;
    stats->rx_frame_errors = rtnl_stats->rx_frame_errors;
    stats->rx_fifo_errors = rtnl_stats->rx_fifo_errors;
    stats->rx_missed_errors = rtnl_stats->rx_missed_errors;
    stats->tx_aborted_errors = rtnl_stats->tx_aborted_errors;
    stats->tx_carrier_errors = rtnl_stats->tx_carrier_errors;
    stats->tx_fifo_errors = rtnl_stats->tx_fifo_errors;
    stats->tx_heartbeat_errors = rtnl_stats->tx_heartbeat_errors;
    stats->tx_window_errors = rtnl_stats->tx_window_errors;

    return 0;
}

static int
get_stats_via_proc(const char *netdev_name, struct netdev_stats *stats)
{
    static const char fn[] = "/proc/net/dev";
    char line[1024];
    FILE *stream;
    int ln;

    stream = fopen(fn, "r");
    if (!stream) {
        VLOG_WARN_RL(&rl, "%s: open failed: %s", fn, strerror(errno));
        return errno;
    }

    ln = 0;
    while (fgets(line, sizeof line, stream)) {
        if (++ln >= 3) {
            char devname[16];
#define X64 "%"SCNu64
            if (sscanf(line,
                       " %15[^:]:"
                       X64 X64 X64 X64 X64 X64 X64 "%*u"
                       X64 X64 X64 X64 X64 X64 X64 "%*u",
                       devname,
                       &stats->rx_bytes,
                       &stats->rx_packets,
                       &stats->rx_errors,
                       &stats->rx_dropped,
                       &stats->rx_fifo_errors,
                       &stats->rx_frame_errors,
                       &stats->multicast,
                       &stats->tx_bytes,
                       &stats->tx_packets,
                       &stats->tx_errors,
                       &stats->tx_dropped,
                       &stats->tx_fifo_errors,
                       &stats->collisions,
                       &stats->tx_carrier_errors) != 15) {
                VLOG_WARN_RL(&rl, "%s:%d: parse error", fn, ln);
            } else if (!strcmp(devname, netdev_name)) {
                stats->rx_length_errors = UINT64_MAX;
                stats->rx_over_errors = UINT64_MAX;
                stats->rx_crc_errors = UINT64_MAX;
                stats->rx_missed_errors = UINT64_MAX;
                stats->tx_aborted_errors = UINT64_MAX;
                stats->tx_heartbeat_errors = UINT64_MAX;
                stats->tx_window_errors = UINT64_MAX;
                fclose(stream);
                return 0;
            }
        }
    }
    VLOG_WARN_RL(&rl, "%s: no stats for %s", fn, netdev_name);
    fclose(stream);
    return ENODEV;
}

/* Sets 'carrier' to true if carrier is active (link light is on) on 
 * 'netdev'. */
int
netdev_get_carrier(const struct netdev *netdev, bool *carrier)
{
    return netdev_nodev_get_carrier(netdev->name, carrier);
}

int
netdev_nodev_get_carrier(const char *netdev_name, bool *carrier)
{
    char line[8];
    int retval;
    int error;
    char *fn;
    int fd;

    *carrier = false;

    fn = xasprintf("/sys/class/net/%s/carrier", netdev_name);
    fd = open(fn, O_RDONLY);
    if (fd < 0) {
        error = errno;
        VLOG_WARN_RL(&rl, "%s: open failed: %s", fn, strerror(error));
        goto exit;
    }

    retval = read(fd, line, sizeof line);
    if (retval < 0) {
        error = errno;
        if (error == EINVAL) {
            /* This is the normal return value when we try to check carrier if
             * the network device is not up. */
        } else {
            VLOG_WARN_RL(&rl, "%s: read failed: %s", fn, strerror(error));
        }
        goto exit_close;
    } else if (retval == 0) {
        error = EPROTO;
        VLOG_WARN_RL(&rl, "%s: unexpected end of file", fn);
        goto exit_close;
    }

    if (line[0] != '0' && line[0] != '1') {
        error = EPROTO;
        VLOG_WARN_RL(&rl, "%s: value is %c (expected 0 or 1)", fn, line[0]);
        goto exit_close;
    }
    *carrier = line[0] != '0';
    error = 0;

exit_close:
    close(fd);
exit:
    free(fn);
    return error;
}

/* Retrieves current device stats for 'netdev'. */
int
netdev_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    int error;

    COVERAGE_INC(netdev_get_stats);
    if (use_netlink_stats) {
        int ifindex;

        error = get_ifindex(netdev, &ifindex);
        if (!error) {
            error = get_stats_via_netlink(ifindex, stats);
        }
    } else {
        error = get_stats_via_proc(netdev->name, stats);
    }

    if (error) {
        memset(stats, 0xff, sizeof *stats);
    }
    return error;
}

#define POLICE_ADD_CMD "/sbin/tc qdisc add dev %s handle ffff: ingress"
#define POLICE_CONFIG_CMD "/sbin/tc filter add dev %s parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate %dkbit burst %dk mtu 65535 drop flowid :1"
/* We redirect stderr to /dev/null because we often want to remove all
 * traffic control configuration on a port so its in a known state.  If
 * this done when there is no such configuration, tc complains, so we just
 * always ignore it.
 */
#define POLICE_DEL_CMD "/sbin/tc qdisc del dev %s handle ffff: ingress 2>/dev/null"

/* Attempts to set input rate limiting (policing) policy. */
int
netdev_nodev_set_policing(const char *netdev_name, uint32_t kbits_rate,
                          uint32_t kbits_burst)
{
    char command[1024];

    init_netdev();

    COVERAGE_INC(netdev_set_policing);
    if (kbits_rate) {
        if (!kbits_burst) {
            /* Default to 10 kilobits if not specified. */
            kbits_burst = 10;
        }

        /* xxx This should be more careful about only adding if it
         * xxx actually exists, as opposed to always deleting it. */
        snprintf(command, sizeof(command), POLICE_DEL_CMD, netdev_name);
        if (system(command) == -1) {
            VLOG_WARN_RL(&rl, "%s: problem removing policing", netdev_name);
        }

        snprintf(command, sizeof(command), POLICE_ADD_CMD, netdev_name);
        if (system(command) != 0) {
            VLOG_WARN_RL(&rl, "%s: problem adding policing", netdev_name);
            return -1;
        }

        snprintf(command, sizeof(command), POLICE_CONFIG_CMD, netdev_name,
                kbits_rate, kbits_burst);
        if (system(command) != 0) {
            VLOG_WARN_RL(&rl, "%s: problem configuring policing", 
                    netdev_name);
            return -1;
        }
    } else {
        snprintf(command, sizeof(command), POLICE_DEL_CMD, netdev_name);
        if (system(command) == -1) {
            VLOG_WARN_RL(&rl, "%s: problem removing policing", netdev_name);
        }
    }

    return 0;
}

int
netdev_set_policing(struct netdev *netdev, uint32_t kbits_rate,
                    uint32_t kbits_burst)
{
    return netdev_nodev_set_policing(netdev->name, kbits_rate, kbits_burst);
}

/* Initializes 'svec' with a list of the names of all known network devices. */
void
netdev_enumerate(struct svec *svec)
{
    struct if_nameindex *names;

    svec_init(svec);
    names = if_nameindex();
    if (names) {
        size_t i;

        for (i = 0; names[i].if_name != NULL; i++) {
            svec_add(svec, names[i].if_name);
        }
        if_freenameindex(names);
    } else {
        VLOG_WARN("could not obtain list of network device names: %s",
                  strerror(errno));
    }
}

/* Attempts to locate a device based on its IPv4 address.  The caller
 * may provide a hint as to the device by setting 'netdev_name' to a
 * likely device name.  This string must be malloc'd, since if it is 
 * not correct then it will be freed.  If there is no hint, then
 * 'netdev_name' must be the NULL pointer.
 *
 * If the device is found, the return value will be true and 'netdev_name' 
 * contains the device's name as a string, which the caller is responsible 
 * for freeing.  If the device is not found, the return value is false. */
bool
netdev_find_dev_by_in4(const struct in_addr *in4, char **netdev_name)
{
    int i;
    struct in_addr dev_in4;
    struct svec dev_list;

    /* Check the hint first. */
    if (*netdev_name && (netdev_nodev_get_in4(*netdev_name, &dev_in4)) 
            && (dev_in4.s_addr == in4->s_addr)) {
        return true;
    }

    free(*netdev_name);
    *netdev_name = NULL;
    netdev_enumerate(&dev_list);

    for (i=0; i<dev_list.n; i++) {
        if ((netdev_nodev_get_in4(dev_list.names[i], &dev_in4)) 
                && (dev_in4.s_addr == in4->s_addr)) {
            *netdev_name = xstrdup(dev_list.names[i]);
            svec_destroy(&dev_list);
            return true;
        }
    }

    svec_destroy(&dev_list);
    return false;
}

/* Obtains the current flags for the network device named 'netdev_name' and
 * stores them into '*flagsp'.  Returns 0 if successful, otherwise a positive
 * errno value.  On error, stores 0 into '*flagsp'.
 *
 * If only device flags are needed, this is more efficient than calling
 * netdev_open(), netdev_get_flags(), netdev_close(). */
int
netdev_nodev_get_flags(const char *netdev_name, enum netdev_flags *flagsp)
{
    int error, flags;

    init_netdev();

    *flagsp = 0;
    error = get_flags(netdev_name, &flags);
    if (error) {
        return error;
    }

    if (flags & IFF_UP) {
        *flagsp |= NETDEV_UP;
    }
    if (flags & IFF_PROMISC) {
        *flagsp |= NETDEV_PROMISC;
    }
    return 0;
}

int
netdev_nodev_get_etheraddr(const char *netdev_name, uint8_t mac[6])
{
    init_netdev();

    return get_etheraddr(netdev_name, mac, NULL);
}

/* If 'netdev_name' is the name of a VLAN network device (e.g. one created with
 * vconfig(8)), sets '*vlan_vid' to the VLAN VID associated with that device
 * and returns 0.  Otherwise returns a errno value (specifically ENOENT if
 * 'netdev_name' is the name of a network device that is not a VLAN device) and
 * sets '*vlan_vid' to -1. */
int
netdev_get_vlan_vid(const char *netdev_name, int *vlan_vid)
{
    struct ds line = DS_EMPTY_INITIALIZER;
    FILE *stream = NULL;
    int error;
    char *fn;

    COVERAGE_INC(netdev_get_vlan_vid);
    fn = xasprintf("/proc/net/vlan/%s", netdev_name);
    stream = fopen(fn, "r");
    if (!stream) {
        error = errno;
        goto done;
    }

    if (ds_get_line(&line, stream)) {
        if (ferror(stream)) {
            error = errno;
            VLOG_ERR_RL(&rl, "error reading \"%s\": %s", fn, strerror(errno));
        } else {
            error = EPROTO;
            VLOG_ERR_RL(&rl, "unexpected end of file reading \"%s\"", fn);
        }
        goto done;
    }

    if (!sscanf(ds_cstr(&line), "%*s VID: %d", vlan_vid)) {
        error = EPROTO;
        VLOG_ERR_RL(&rl, "parse error reading \"%s\" line 1: \"%s\"",
                    fn, ds_cstr(&line));
        goto done;
    }

    error = 0;

done:
    free(fn);
    if (stream) {
        fclose(stream);
    }
    ds_destroy(&line);
    if (error) {
        *vlan_vid = -1;
    }
    return error;
}

struct netdev_monitor {
    struct linux_netdev_notifier notifier;
    struct shash polled_netdevs;
    struct shash changed_netdevs;
};

static void netdev_monitor_change(const struct linux_netdev_change *change,
                                  void *monitor);

int
netdev_monitor_create(struct netdev_monitor **monitorp)
{
    struct netdev_monitor *monitor;
    int error;

    monitor = xmalloc(sizeof *monitor);
    error = linux_netdev_notifier_register(&monitor->notifier,
                                           netdev_monitor_change, monitor);
    if (error) {
        free(monitor);
        return error;
    }
    shash_init(&monitor->polled_netdevs);
    shash_init(&monitor->changed_netdevs);
    *monitorp = monitor;
    return 0;
}

void
netdev_monitor_destroy(struct netdev_monitor *monitor)
{
    if (monitor) {
        linux_netdev_notifier_unregister(&monitor->notifier);
        shash_destroy(&monitor->polled_netdevs);
        free(monitor);
    }
}

void
netdev_monitor_add(struct netdev_monitor *monitor, struct netdev *netdev)
{
    if (!shash_find(&monitor->polled_netdevs, netdev_get_name(netdev))) {
        shash_add(&monitor->polled_netdevs, netdev_get_name(netdev), NULL);
    }
}

void
netdev_monitor_remove(struct netdev_monitor *monitor, struct netdev *netdev)
{
    struct shash_node *node;

    node = shash_find(&monitor->polled_netdevs, netdev_get_name(netdev));
    if (node) {
        shash_delete(&monitor->polled_netdevs, node);
        node = shash_find(&monitor->changed_netdevs, netdev_get_name(netdev));
        if (node) {
            shash_delete(&monitor->changed_netdevs, node);
        }
    }
}

int
netdev_monitor_poll(struct netdev_monitor *monitor, char **devnamep)
{
    int error = linux_netdev_notifier_get_error(&monitor->notifier);
    *devnamep = NULL;
    if (!error) {
        struct shash_node *node = shash_first(&monitor->changed_netdevs);
        if (!node) {
            return EAGAIN;
        }
        *devnamep = xstrdup(node->name);
        shash_delete(&monitor->changed_netdevs, node);
    } else {
        shash_clear(&monitor->changed_netdevs);
    }
    return error;
}

void
netdev_monitor_poll_wait(const struct netdev_monitor *monitor)
{
    if (!shash_is_empty(&monitor->changed_netdevs)
        || linux_netdev_notifier_peek_error(&monitor->notifier)) {
        poll_immediate_wake();
    } else {
        linux_netdev_notifier_wait();
    }
}

static void
netdev_monitor_change(const struct linux_netdev_change *change, void *monitor_)
{
    struct netdev_monitor *monitor = monitor_;
    if (shash_find(&monitor->polled_netdevs, change->ifname)
        && !shash_find(&monitor->changed_netdevs, change->ifname)) {
        shash_add(&monitor->changed_netdevs, change->ifname, NULL);
    }
}

static void restore_all_flags(void *aux);

/* Set up a signal hook to restore network device flags on program
 * termination.  */
static void
init_netdev(void)
{
    static bool inited;
    if (!inited) {
        int ifindex;
        int error;

        inited = true;

        fatal_signal_add_hook(restore_all_flags, NULL, true);

        af_inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (af_inet_sock < 0) {
            ovs_fatal(errno, "socket(AF_INET)");
        }

        error = nl_sock_create(NETLINK_ROUTE, 0, 0, 0, &rtnl_sock);
        if (error) {
            ovs_fatal(error, "socket(AF_NETLINK, NETLINK_ROUTE)");
        }

        /* Decide on the netdev_get_stats() implementation to use.  Netlink is
         * preferable, so if that works, we'll use it. */
        ifindex = do_get_ifindex("lo");
        if (ifindex < 0) {
            VLOG_WARN("failed to get ifindex for lo, "
                      "obtaining netdev stats from proc");
            use_netlink_stats = false;
        } else {
            struct netdev_stats stats;
            error = get_stats_via_netlink(ifindex, &stats);
            if (!error) {
                VLOG_DBG("obtaining netdev stats via rtnetlink");
                use_netlink_stats = true;
            } else {
                VLOG_INFO("RTM_GETLINK failed (%s), obtaining netdev stats "
                          "via proc (you are probably running a pre-2.6.19 "
                          "kernel)", strerror(error));
                use_netlink_stats = false;
            }
        }
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
    int restore_flags;

    /* Get current flags. */
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    COVERAGE_INC(netdev_get_flags);
    if (ioctl(netdev->netdev_fd, SIOCGIFFLAGS, &ifr) < 0) {
        return errno;
    }

    /* Restore flags that we might have changed, if necessary. */
    restore_flags = netdev->changed_flags & (IFF_PROMISC | IFF_UP);
    if ((ifr.ifr_flags ^ netdev->save_flags) & restore_flags) {
        ifr.ifr_flags &= ~restore_flags;
        ifr.ifr_flags |= netdev->save_flags & restore_flags;
        COVERAGE_INC(netdev_set_flags);
        if (ioctl(netdev->netdev_fd, SIOCSIFFLAGS, &ifr) < 0) {
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

static int
get_flags(const char *netdev_name, int *flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    COVERAGE_INC(netdev_get_flags);
    if (ioctl(af_inet_sock, SIOCGIFFLAGS, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFFLAGS) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    *flags = ifr.ifr_flags;
    return 0;
}

static int
set_flags(const char *netdev_name, int flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    ifr.ifr_flags = flags;
    COVERAGE_INC(netdev_set_flags);
    if (ioctl(af_inet_sock, SIOCSIFFLAGS, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCSIFFLAGS) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    return 0;
}

static int
do_get_ifindex(const char *netdev_name)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    COVERAGE_INC(netdev_get_ifindex);
    if (ioctl(af_inet_sock, SIOCGIFINDEX, &ifr) < 0) {
        VLOG_WARN_RL(&rl, "ioctl(SIOCGIFINDEX) on %s device failed: %s",
                     netdev_name, strerror(errno));
        return -errno;
    }
    return ifr.ifr_ifindex;
}

static int
get_ifindex(const struct netdev *netdev, int *ifindexp)
{
    *ifindexp = 0;
    if (netdev->ifindex < 0) {
        int ifindex = do_get_ifindex(netdev->name);
        if (ifindex < 0) {
            return -ifindex;
        }
        ((struct netdev *) netdev)->ifindex = ifindex;
    }
    *ifindexp = netdev->ifindex;
    return 0;
}

static int
get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN],
              int *hwaddr_familyp)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    COVERAGE_INC(netdev_get_hwaddr);
    if (ioctl(af_inet_sock, SIOCGIFHWADDR, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFHWADDR) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    if (hwaddr_familyp) {
        int hwaddr_family = ifr.ifr_hwaddr.sa_family;
        *hwaddr_familyp = hwaddr_family;
        if (hwaddr_family != AF_UNSPEC && hwaddr_family != ARPHRD_ETHER) {
            VLOG_WARN("%s device has unknown hardware address family %d",
                      netdev_name, hwaddr_family);
        }
    }
    memcpy(ea, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
    return 0;
}

static int
set_etheraddr(const char *netdev_name, int hwaddr_family,
              const uint8_t mac[ETH_ADDR_LEN])
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    ifr.ifr_hwaddr.sa_family = hwaddr_family;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, ETH_ADDR_LEN);
    COVERAGE_INC(netdev_set_hwaddr);
    if (ioctl(af_inet_sock, SIOCSIFHWADDR, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCSIFHWADDR) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    return 0;
}
