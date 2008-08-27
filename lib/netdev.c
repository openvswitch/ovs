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

#include <config.h>
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
#include <net/route.h>
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
#include "socket-util.h"

#define THIS_MODULE VLM_netdev
#include "vlog.h"

struct netdev {
    struct list node;
    char *name;
    int ifindex;
    int fd;
    uint8_t etheraddr[ETH_ADDR_LEN];
    int speed;
    int mtu;
    uint32_t features;
    struct in6_addr in6;
    int save_flags;             /* Initial device flags. */
    int changed_flags;          /* Flags that we changed. */
};

/* All open network devices. */
static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

/* An AF_INET socket (used for ioctl operations). */
static int af_inet_sock = -1;

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void init_netdev(void);
static int restore_flags(struct netdev *netdev);
static int get_flags(const struct netdev *, int *flagsp);
static int set_flags(struct netdev *, int flags);

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
            return;
        }
    }
    *in6 = in6addr_any;

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
 * to the new network device, otherwise to null.
 *
 * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order to
 * capture frames of that type received on the device.  It may also be one of
 * the 'enum netdev_pseudo_ethertype' values to receive frames in one of those
 * categories. */
int
netdev_open(const char *name, int ethertype, struct netdev **netdev_)
{
    int fd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    unsigned int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in6_addr in6;
    int mtu;
    int error;
    struct netdev *netdev;

    *netdev_ = NULL;
    init_netdev();

    /* Create raw socket. */
    fd = socket(PF_PACKET, SOCK_RAW,
                htons(ethertype == NETDEV_ETH_TYPE_NONE ? 0
                      : ethertype == NETDEV_ETH_TYPE_ANY ? ETH_P_ALL
                      : ethertype == NETDEV_ETH_TYPE_802_2 ? ETH_P_802_2
                      : ethertype));
    if (fd < 0) {
        return errno;
    }

    /* Get ethernet device index. */
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFINDEX) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    ifindex = ifr.ifr_ifindex;

    /* Bind to specific ethernet device. */
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *) &sll, sizeof sll) < 0) {
        VLOG_ERR("bind to %s failed: %s", name, strerror(errno));
        goto error;
    }

    if (ethertype != NETDEV_ETH_TYPE_NONE) {
        /* Between the socket() and bind() calls above, the socket receives all
         * packets of the requested type on all system interfaces.  We do not
         * want to receive that data, but there is no way to avoid it.  So we
         * must now drain out the receive queue. */
        error = drain_rcvbuf(fd);
        if (error) {
            goto error;
        }
    }

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

    get_ipv6_address(name, &in6);

    /* Allocate network device. */
    netdev = xmalloc(sizeof *netdev);
    netdev->name = xstrdup(name);
    netdev->ifindex = ifindex;
    netdev->fd = fd;
    memcpy(netdev->etheraddr, etheraddr, sizeof etheraddr);
    netdev->mtu = mtu;
    netdev->in6 = in6;

    /* Get speed, features. */
    do_ethtool(netdev);

    /* Save flags to restore at close or exit. */
    error = get_flags(netdev, &netdev->save_flags);
    if (error) {
        goto preset_error;
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
preset_error:
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
            VLOG_WARN_RL(&rl, "error receiving Ethernet packet on %s: %s",
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

/* Discards all packets waiting to be received from 'netdev'. */
void
netdev_drain(struct netdev *netdev)
{
    drain_rcvbuf(netdev->fd);
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
netdev_send(struct netdev *netdev, const struct buffer *buffer)
{
    ssize_t n_bytes;
    const struct eth_header *eh;

    /* Pull out the Ethernet header. */
    if (buffer->size < ETH_HEADER_LEN) {
        VLOG_WARN_RL(&rl, "cannot send %zu-byte frame on %s",
                     buffer->size, netdev->name);
        return EMSGSIZE;
    }
    eh = buffer_at_assert(buffer, 0, sizeof *eh);

    do {
        n_bytes = sendto(netdev->fd, buffer->data, buffer->size, 0, NULL, 0);
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

/* Checks the link status.  Returns 1 or 0 to indicate the link is active 
 * or not, respectively.  Any other return value indicates an error. */
int
netdev_get_link_status(const struct netdev *netdev) 
{
    struct ifreq ifr;
    struct ethtool_value edata;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) &edata;

    memset(&edata, 0, sizeof edata);
    edata.cmd = ETHTOOL_GLINK;
    if (ioctl(netdev->fd, SIOCETHTOOL, &ifr) == 0) {
        if (edata.data) {
            return 1;
        } else {
            return 0;
        }
    }

    return -1;
}

/* Returns the features supported by 'netdev', as a bitmap of bits from enum
 * ofp_phy_port, in host byte order. */
uint32_t
netdev_get_features(const struct netdev *netdev) 
{
    return netdev->features;
}

/* If 'netdev' has an assigned IPv4 address, sets '*in4' to that address (if
 * 'in4' is non-null) and returns true.  Otherwise, returns false. */
bool
netdev_get_in4(const struct netdev *netdev, struct in_addr *in4)
{
    struct ifreq ifr;
    struct in_addr ip = { INADDR_ANY };

    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(af_inet_sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
        ip = sin->sin_addr;
    } else {
        VLOG_DBG_RL(&rl, "%s: ioctl(SIOCGIFADDR) failed: %s",
                    netdev->name, strerror(errno));
    }
    if (in4) {
        *in4 = ip;
    }
    return ip.s_addr != INADDR_ANY;
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

/* Adds 'router' as a default gateway for 'netdev''s IP address. */
int
netdev_add_router(struct netdev *netdev, struct in_addr router)
{
    struct in_addr any = { INADDR_ANY };
    struct rtentry rt;
    int error;

    memset(&rt, 0, sizeof rt);
    make_in4_sockaddr(&rt.rt_dst, any);
    make_in4_sockaddr(&rt.rt_gateway, router);
    make_in4_sockaddr(&rt.rt_genmask, any);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
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
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_get_flags(const struct netdev *netdev, enum netdev_flags *flagsp)
{
    int error, flags;

    error = get_flags(netdev, &flags);
    if (error) {
        return error;
    }

    *flagsp = 0;
    if (flags & IFF_UP) {
        *flagsp |= NETDEV_UP;
    }
    if (flags & IFF_PROMISC) {
        *flagsp |= NETDEV_PROMISC;
    }
    return 0;
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

    error = get_flags(netdev, &old_flags);
    if (error) {
        return error;
    }

    new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);
    if (!permanent) {
        netdev->changed_flags |= new_flags ^ old_flags; 
    }
    if (new_flags != old_flags) {
        error = set_flags(netdev, new_flags);
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
netdev_arp_lookup(const struct netdev *netdev,
                  uint32_t ip, uint8_t mac[ETH_ADDR_LEN]) 
{
    struct arpreq r;
    struct sockaddr_in *pa;
    int retval;

    memset(&r, 0, sizeof r);
    pa = (struct sockaddr_in *) &r.arp_pa;
    pa->sin_family = AF_INET;
    pa->sin_addr.s_addr = ip;
    pa->sin_port = 0;
    r.arp_ha.sa_family = ARPHRD_ETHER;
    r.arp_flags = 0;
    strncpy(r.arp_dev, netdev->name, sizeof r.arp_dev);
    retval = ioctl(af_inet_sock, SIOCGARP, &r) < 0 ? errno : 0;
    if (!retval) {
        memcpy(mac, r.arp_ha.sa_data, ETH_ADDR_LEN);
    } else if (retval != ENXIO) {
        VLOG_WARN_RL(&rl, "%s: could not look up ARP entry for "IP_FMT": %s",
                     netdev->name, IP_ARGS(&ip), strerror(retval));
    }
    return retval;
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
        fatal_signal_add_hook(restore_all_flags, NULL, true);
        af_inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (af_inet_sock < 0) {
            fatal(errno, "socket(AF_INET)");
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
    if (ioctl(netdev->fd, SIOCGIFFLAGS, &ifr) < 0) {
        return errno;
    }

    /* Restore flags that we might have changed, if necessary. */
    restore_flags = netdev->changed_flags & (IFF_PROMISC | IFF_UP);
    if ((ifr.ifr_flags ^ netdev->save_flags) & restore_flags) {
        ifr.ifr_flags &= ~restore_flags;
        ifr.ifr_flags |= netdev->save_flags & restore_flags;
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

static int
get_flags(const struct netdev *netdev, int *flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    if (ioctl(netdev->fd, SIOCGIFFLAGS, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFFLAGS) on %s device failed: %s",
                 netdev->name, strerror(errno));
        return errno;
    }
    *flags = ifr.ifr_flags;
    return 0;
}

static int
set_flags(struct netdev *netdev, int flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_flags = flags;
    if (ioctl(netdev->fd, SIOCSIFFLAGS, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCSIFFLAGS) on %s device failed: %s",
                 netdev->name, strerror(errno));
        return errno;
    }
    return 0;
}
