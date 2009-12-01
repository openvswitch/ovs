/*
 * Copyright (c) 2009 Nicira Networks.
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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "socket-util.h"
#include "shash.h"
#include "svec.h"

#define THIS_MODULE VLM_netdev_linux
#include "vlog.h"

/* These were introduced in Linux 2.6.14, so they might be missing if we have
 * old headers. */
#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause                (1 << 13)
#endif
#ifndef ADVERTISED_Asym_Pause
#define ADVERTISED_Asym_Pause           (1 << 14)
#endif

/* Provider-specific netdev object.  Netdev objects are devices that are
 * created by the netdev library through a netdev_create() call. */
struct netdev_obj_linux {
    struct netdev_obj netdev_obj;

    int tap_fd;                 /* File descriptor for TAP device. */
};

struct netdev_linux {
    struct netdev netdev;

    /* File descriptors.  For ordinary network devices, the two fds below are
     * the same; for tap devices, they differ. */
    int netdev_fd;              /* Network device. */
    int tap_fd;                 /* TAP character device, if any, otherwise the
                                 * network device. */

    struct netdev_linux_cache *cache;
};

enum {
    VALID_IFINDEX = 1 << 0,
    VALID_ETHERADDR = 1 << 1,
    VALID_IN4 = 1 << 2,
    VALID_IN6 = 1 << 3,
    VALID_MTU = 1 << 4,
    VALID_CARRIER = 1 << 5,
    VALID_IS_INTERNAL = 1 << 6
};

/* Cached network device information. */
struct netdev_linux_cache {
    struct shash_node *shash_node;
    unsigned int valid;
    int ref_cnt;

    int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in_addr address, netmask;
    struct in6_addr in6;
    int mtu;
    int carrier;
    bool is_internal;
};

static struct shash cache_map = SHASH_INITIALIZER(&cache_map);
static struct rtnetlink_notifier netdev_linux_cache_notifier;

/* An AF_INET socket (used for ioctl operations). */
static int af_inet_sock = -1;

struct netdev_linux_notifier {
    struct netdev_notifier notifier;
    struct list node;
};

static struct shash netdev_linux_notifiers =
    SHASH_INITIALIZER(&netdev_linux_notifiers);
static struct rtnetlink_notifier netdev_linux_poll_notifier;

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int netdev_linux_do_ethtool(struct netdev *, struct ethtool_cmd *,
                                   int cmd, const char *cmd_name);
static int netdev_linux_do_ioctl(const struct netdev *, struct ifreq *,
                                 int cmd, const char *cmd_name);
static int netdev_linux_get_ipv4(const struct netdev *, struct in_addr *,
                                 int cmd, const char *cmd_name);
static int get_flags(const struct netdev *, int *flagsp);
static int set_flags(struct netdev *, int flags);
static int do_get_ifindex(const char *netdev_name);
static int get_ifindex(const struct netdev *, int *ifindexp);
static int do_set_addr(struct netdev *netdev,
                       int ioctl_nr, const char *ioctl_name,
                       struct in_addr addr);
static int get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN]);
static int set_etheraddr(const char *netdev_name, int hwaddr_family,
                         const uint8_t[ETH_ADDR_LEN]);
static int get_stats_via_netlink(int ifindex, struct netdev_stats *stats);
static int get_stats_via_proc(const char *netdev_name, struct netdev_stats *stats);

static struct netdev_obj_linux *
netdev_obj_linux_cast(const struct netdev_obj *netdev_obj)
{
    netdev_obj_assert_class(netdev_obj, &netdev_linux_class);
    return CONTAINER_OF(netdev_obj, struct netdev_obj_linux, netdev_obj);
}

static struct netdev_linux *
netdev_linux_cast(const struct netdev *netdev)
{
    netdev_assert_class(netdev, &netdev_linux_class);
    return CONTAINER_OF(netdev, struct netdev_linux, netdev);
}

static int
netdev_linux_init(void)
{
    static int status = -1;
    if (status < 0) {
        af_inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        status = af_inet_sock >= 0 ? 0 : errno;
        if (status) {
            VLOG_ERR("failed to create inet socket: %s", strerror(status));
        }
    }
    return status;
}

static void
netdev_linux_run(void)
{
    rtnetlink_notifier_run();
}

static void
netdev_linux_wait(void)
{
    rtnetlink_notifier_wait();
}

static void
netdev_linux_cache_cb(const struct rtnetlink_change *change,
                      void *aux UNUSED)
{
    struct netdev_linux_cache *cache;
    if (change) {
        cache = shash_find_data(&cache_map, change->ifname);
        if (cache) {
            cache->valid = 0;
        }
    } else {
        struct shash_node *node;
        SHASH_FOR_EACH (node, &cache_map) {
            cache = node->data;
            cache->valid = 0;
        }
    }
}

/* Creates the netdev object of 'type' with 'name'. */
static int
netdev_linux_create(const char *name, const char *type, 
                    const struct shash *args, bool created)
{
    struct netdev_obj_linux *netdev_obj;
    static const char tap_dev[] = "/dev/net/tun";
    struct ifreq ifr;
    int error;

    if (!shash_is_empty(args)) {
        VLOG_WARN("arguments for %s devices should be empty", type);
    }

    /* Create the name binding in the netdev library for this object. */
    netdev_obj = xcalloc(1, sizeof *netdev_obj);
    netdev_obj_init(&netdev_obj->netdev_obj, name, &netdev_linux_class,
                    created);
    netdev_obj->tap_fd = -1;

    if (strcmp(type, "tap")) {
        return 0;
    }

    /* Open tap device. */
    netdev_obj->tap_fd = open(tap_dev, O_RDWR);
    if (netdev_obj->tap_fd < 0) {
        error = errno;
        VLOG_WARN("opening \"%s\" failed: %s", tap_dev, strerror(error));
        goto error;
    }

    /* Create tap device. */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(netdev_obj->tap_fd, TUNSETIFF, &ifr) == -1) {
        VLOG_WARN("%s: creating tap device failed: %s", name,
                  strerror(errno));
        error = errno;
        goto error;
    }

    /* Make non-blocking. */
    error = set_nonblocking(netdev_obj->tap_fd);
    if (error) {
        goto error;
    }

    return 0;

error:
    netdev_destroy(name);
    return error;
}

/* Destroys the netdev object 'netdev_obj_'. */
static void
netdev_linux_destroy(struct netdev_obj *netdev_obj_)
{
    struct netdev_obj_linux *netdev_obj = netdev_obj_linux_cast(netdev_obj_);

    if (netdev_obj->tap_fd >= 0) {
        close(netdev_obj->tap_fd);
    }
    free(netdev_obj);

    return;
}

static int
netdev_linux_open(const char *name, int ethertype, struct netdev **netdevp)
{
    struct netdev_linux *netdev;
    enum netdev_flags flags;
    int error;

    /* Allocate network device. */
    netdev = xcalloc(1, sizeof *netdev);
    netdev_init(&netdev->netdev, name, &netdev_linux_class);
    netdev->netdev_fd = -1;
    netdev->tap_fd = -1;
    netdev->cache = shash_find_data(&cache_map, name);
    if (!netdev->cache) {
        if (shash_is_empty(&cache_map)) {
            int error = rtnetlink_notifier_register(
                &netdev_linux_cache_notifier, netdev_linux_cache_cb, NULL);
            if (error) {
                netdev_close(&netdev->netdev);
                return error;
            }
        }
        netdev->cache = xmalloc(sizeof *netdev->cache);
        netdev->cache->shash_node = shash_add(&cache_map, name,
                                              netdev->cache);
        netdev->cache->valid = 0;
        netdev->cache->ref_cnt = 0;
    }
    netdev->cache->ref_cnt++;

    if (!strcmp(netdev_get_type(&netdev->netdev), "tap")) {
        static const char tap_dev[] = "/dev/net/tun";
        struct ifreq ifr;

        /* Open tap device. */
        netdev->tap_fd = open(tap_dev, O_RDWR);
        if (netdev->tap_fd < 0) {
            error = errno;
            VLOG_WARN("opening \"%s\" failed: %s", tap_dev, strerror(error));
            goto error;
        }

        /* Create tap device. */
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
        if (ioctl(netdev->tap_fd, TUNSETIFF, &ifr) == -1) {
            VLOG_WARN("%s: creating tap device failed: %s", name,
                      strerror(errno));
            error = errno;
            goto error;
        }

        /* Make non-blocking. */
        error = set_nonblocking(netdev->tap_fd);
        if (error) {
            goto error;
        }
    }

    error = netdev_get_flags(&netdev->netdev, &flags);
    if (error == ENODEV) {
        goto error;
    }

    if (netdev->tap_fd >= 0 || ethertype != NETDEV_ETH_TYPE_NONE) {
        struct sockaddr_ll sll;
        int protocol;
        int ifindex;

        /* Create file descriptor. */
        protocol = (ethertype == NETDEV_ETH_TYPE_ANY ? ETH_P_ALL
                    : ethertype == NETDEV_ETH_TYPE_802_2 ? ETH_P_802_2
                    : ethertype);
        netdev->netdev_fd = socket(PF_PACKET, SOCK_RAW, htons(protocol));
        if (netdev->netdev_fd < 0) {
            error = errno;
            goto error;
        }
        if (netdev->tap_fd < 0) {
            netdev->tap_fd = netdev->netdev_fd;
        }

        /* Set non-blocking mode. */
        error = set_nonblocking(netdev->netdev_fd);
        if (error) {
            goto error;
        }

        /* Get ethernet device index. */
        error = get_ifindex(&netdev->netdev, &ifindex);
        if (error) {
            goto error;
        }

        /* Bind to specific ethernet device. */
        memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        if (bind(netdev->netdev_fd,
                 (struct sockaddr *) &sll, sizeof sll) < 0) {
            error = errno;
            VLOG_ERR("bind to %s failed: %s", name, strerror(error));
            goto error;
        }

        /* Between the socket() and bind() calls above, the socket receives all
         * packets of the requested type on all system interfaces.  We do not
         * want to receive that data, but there is no way to avoid it.  So we
         * must now drain out the receive queue. */
        error = drain_rcvbuf(netdev->netdev_fd);
        if (error) {
            goto error;
        }
    }

    *netdevp = &netdev->netdev;
    return 0;

error:
    netdev_close(&netdev->netdev);
    return error;
}

/* Closes and destroys 'netdev'. */
static void
netdev_linux_close(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);

    if (netdev->cache && !--netdev->cache->ref_cnt) {
        shash_delete(&cache_map, netdev->cache->shash_node);
        free(netdev->cache);

        if (shash_is_empty(&cache_map)) {
            rtnetlink_notifier_unregister(&netdev_linux_cache_notifier);
        }
    }
    if (netdev->netdev_fd >= 0) {
        close(netdev->netdev_fd);
    }
    if (netdev->tap_fd >= 0 && netdev->netdev_fd != netdev->tap_fd) {
        close(netdev->tap_fd);
    }
    free(netdev);
}

/* Initializes 'svec' with a list of the names of all known network devices. */
static int
netdev_linux_enumerate(struct svec *svec)
{
    struct if_nameindex *names;

    names = if_nameindex();
    if (names) {
        size_t i;

        for (i = 0; names[i].if_name != NULL; i++) {
            svec_add(svec, names[i].if_name);
        }
        if_freenameindex(names);
        return 0;
    } else {
        VLOG_WARN("could not obtain list of network device names: %s",
                  strerror(errno));
        return errno;
    }
}

static int
netdev_linux_recv(struct netdev *netdev_, void *data, size_t size)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);

    if (netdev->tap_fd < 0) {
        /* Device was opened with NETDEV_ETH_TYPE_NONE. */
        return -EAGAIN;
    }

    for (;;) {
        ssize_t retval = read(netdev->tap_fd, data, size);
        if (retval >= 0) {
            return retval;
        } else if (errno != EINTR) {
            if (errno != EAGAIN) {
                VLOG_WARN_RL(&rl, "error receiving Ethernet packet on %s: %s",
                             strerror(errno), netdev_get_name(netdev_));
            }
            return -errno;
        }
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_recv() on 'netdev'. */
static void
netdev_linux_recv_wait(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (netdev->tap_fd >= 0) {
        poll_fd_wait(netdev->tap_fd, POLLIN);
    }
}

/* Discards all packets waiting to be received from 'netdev'. */
static int
netdev_linux_drain(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (netdev->tap_fd < 0 && netdev->netdev_fd < 0) {
        return 0;
    } else if (netdev->tap_fd != netdev->netdev_fd) {
        struct ifreq ifr;
        int error = netdev_linux_do_ioctl(netdev_, &ifr,
                                          SIOCGIFTXQLEN, "SIOCGIFTXQLEN");
        if (error) {
            return error;
        }
        drain_fd(netdev->tap_fd, ifr.ifr_qlen);
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
static int
netdev_linux_send(struct netdev *netdev_, const void *data, size_t size)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);

    /* XXX should support sending even if 'ethertype' was NETDEV_ETH_TYPE_NONE.
     */
    if (netdev->tap_fd < 0) {
        return EPIPE;
    }

    for (;;) {
        ssize_t retval = write(netdev->tap_fd, data, size);
        if (retval < 0) {
            /* The Linux AF_PACKET implementation never blocks waiting for room
             * for packets, instead returning ENOBUFS.  Translate this into
             * EAGAIN for the caller. */
            if (errno == ENOBUFS) {
                return EAGAIN;
            } else if (errno == EINTR) {
                continue;
            } else if (errno != EAGAIN) {
                VLOG_WARN_RL(&rl, "error sending Ethernet packet on %s: %s",
                             netdev_get_name(netdev_), strerror(errno));
            }
            return errno;
        } else if (retval != size) {
            VLOG_WARN_RL(&rl, "sent partial Ethernet packet (%zd bytes of "
                         "%zu) on %s", retval, size, netdev_get_name(netdev_));
            return EMSGSIZE;
        } else {
            return 0;
        }
    }
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The kernel maintains a packet transmission queue, so the client is not
 * expected to do additional queuing of packets.  Thus, this function is
 * unlikely to ever be used.  It is included for completeness. */
static void
netdev_linux_send_wait(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (netdev->tap_fd < 0 && netdev->netdev_fd < 0) {
        /* Nothing to do. */
    } else if (netdev->tap_fd == netdev->netdev_fd) {
        poll_fd_wait(netdev->tap_fd, POLLOUT);
    } else {
        /* TAP device always accepts packets.*/
        poll_immediate_wake();
    }
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
netdev_linux_set_etheraddr(struct netdev *netdev_,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    int error;

    if (!(netdev->cache->valid & VALID_ETHERADDR)
        || !eth_addr_equals(netdev->cache->etheraddr, mac)) {
        error = set_etheraddr(netdev_get_name(netdev_), ARPHRD_ETHER, mac);
        if (!error) {
            netdev->cache->valid |= VALID_ETHERADDR;
            memcpy(netdev->cache->etheraddr, mac, ETH_ADDR_LEN);
        }
    } else {
        error = 0;
    }
    return error;
}

/* Returns a pointer to 'netdev''s MAC address.  The caller must not modify or
 * free the returned buffer. */
static int
netdev_linux_get_etheraddr(const struct netdev *netdev_,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (!(netdev->cache->valid & VALID_ETHERADDR)) {
        int error = get_etheraddr(netdev_get_name(netdev_),
                                  netdev->cache->etheraddr);
        if (error) {
            return error;
        }
        netdev->cache->valid |= VALID_ETHERADDR;
    }
    memcpy(mac, netdev->cache->etheraddr, ETH_ADDR_LEN);
    return 0;
}

/* Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices. */
static int
netdev_linux_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (!(netdev->cache->valid & VALID_MTU)) {
        struct ifreq ifr;
        int error;

        error = netdev_linux_do_ioctl(netdev_, &ifr, SIOCGIFMTU, "SIOCGIFMTU");
        if (error) {
            return error;
        }
        netdev->cache->mtu = ifr.ifr_mtu;
        netdev->cache->valid |= VALID_MTU;
    }
    *mtup = netdev->cache->mtu;
    return 0;
}

/* Returns the ifindex of 'netdev', if successful, as a positive number.
 * On failure, returns a negative errno value. */
static int
netdev_linux_get_ifindex(const struct netdev *netdev)
{
    int ifindex, error;

    error = get_ifindex(netdev, &ifindex);
    return error ? -error : ifindex;
}

static int
netdev_linux_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    int error = 0;
    char *fn = NULL;
    int fd = -1;

    if (!(netdev->cache->valid & VALID_CARRIER)) {
        char line[8];
        int retval;

        fn = xasprintf("/sys/class/net/%s/carrier", netdev_get_name(netdev_));
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
                /* This is the normal return value when we try to check carrier
                 * if the network device is not up. */
            } else {
                VLOG_WARN_RL(&rl, "%s: read failed: %s", fn, strerror(error));
            }
            goto exit;
        } else if (retval == 0) {
            error = EPROTO;
            VLOG_WARN_RL(&rl, "%s: unexpected end of file", fn);
            goto exit;
        }

        if (line[0] != '0' && line[0] != '1') {
            error = EPROTO;
            VLOG_WARN_RL(&rl, "%s: value is %c (expected 0 or 1)",
                         fn, line[0]);
            goto exit;
        }
        netdev->cache->carrier = line[0] != '0';
        netdev->cache->valid |= VALID_CARRIER;
    }
    *carrier = netdev->cache->carrier;
    error = 0;

exit:
    if (fd >= 0) {
        close(fd);
    }
    free(fn);
    return error;
}

/* Check whether we can we use RTM_GETLINK to get network device statistics.
 * In pre-2.6.19 kernels, this was only available if wireless extensions were
 * enabled. */
static bool
check_for_working_netlink_stats(void)
{
    /* Decide on the netdev_get_stats() implementation to use.  Netlink is
     * preferable, so if that works, we'll use it. */
    int ifindex = do_get_ifindex("lo");
    if (ifindex < 0) {
        VLOG_WARN("failed to get ifindex for lo, "
                  "obtaining netdev stats from proc");
        return false;
    } else {
        struct netdev_stats stats;
        int error = get_stats_via_netlink(ifindex, &stats);
        if (!error) {
            VLOG_DBG("obtaining netdev stats via rtnetlink");
            return true;
        } else {
            VLOG_INFO("RTM_GETLINK failed (%s), obtaining netdev stats "
                      "via proc (you are probably running a pre-2.6.19 "
                      "kernel)", strerror(error));
            return false;
        }
    }
}

/* Retrieves current device stats for 'netdev'.
 *
 * XXX All of the members of struct netdev_stats are 64 bits wide, but on
 * 32-bit architectures the Linux network stats are only 32 bits. */
static int
netdev_linux_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    static int use_netlink_stats = -1;
    int error;
    struct netdev_stats raw_stats;
    struct netdev_stats *collect_stats = stats;

    COVERAGE_INC(netdev_get_stats);

    if (!(netdev->cache->valid & VALID_IS_INTERNAL)) {
        netdev->cache->is_internal = (netdev->tap_fd != -1);

        if (!netdev->cache->is_internal) {
            struct ethtool_drvinfo drvinfo;

            memset(&drvinfo, 0, sizeof drvinfo);
            error = netdev_linux_do_ethtool(&netdev->netdev,
                                            (struct ethtool_cmd *)&drvinfo,
                                            ETHTOOL_GDRVINFO,
                                            "ETHTOOL_GDRVINFO");

            if (!error) {
                netdev->cache->is_internal = !strcmp(drvinfo.driver,
                                                     "openvswitch");
            }
        }

        netdev->cache->valid |= VALID_IS_INTERNAL;
    }

    if (netdev->cache->is_internal) {
        collect_stats = &raw_stats;
    }

    if (use_netlink_stats < 0) {
        use_netlink_stats = check_for_working_netlink_stats();
    }
    if (use_netlink_stats) {
        int ifindex;

        error = get_ifindex(&netdev->netdev, &ifindex);
        if (!error) {
            error = get_stats_via_netlink(ifindex, collect_stats);
        }
    } else {
        error = get_stats_via_proc(netdev->netdev.name, collect_stats);
    }

    /* If this port is an internal port then the transmit and receive stats
     * will appear to be swapped relative to the other ports since we are the
     * one sending the data, not a remote computer.  For consistency, we swap
     * them back here. */
    if (netdev->cache->is_internal) {
        stats->rx_packets = raw_stats.tx_packets;
        stats->tx_packets = raw_stats.rx_packets;
        stats->rx_bytes = raw_stats.tx_bytes;
        stats->tx_bytes = raw_stats.rx_bytes;
        stats->rx_errors = raw_stats.tx_errors;
        stats->tx_errors = raw_stats.rx_errors;
        stats->rx_dropped = raw_stats.tx_dropped;
        stats->tx_dropped = raw_stats.rx_dropped;
        stats->multicast = raw_stats.multicast;
        stats->collisions = raw_stats.collisions;
        stats->rx_length_errors = 0;
        stats->rx_over_errors = 0;
        stats->rx_crc_errors = 0;
        stats->rx_frame_errors = 0;
        stats->rx_fifo_errors = 0;
        stats->rx_missed_errors = 0;
        stats->tx_aborted_errors = 0;
        stats->tx_carrier_errors = 0;
        stats->tx_fifo_errors = 0;
        stats->tx_heartbeat_errors = 0;
        stats->tx_window_errors = 0;
    }

    return error;
}

/* Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value. */
static int
netdev_linux_get_features(struct netdev *netdev,
                          uint32_t *current, uint32_t *advertised,
                          uint32_t *supported, uint32_t *peer)
{
    struct ethtool_cmd ecmd;
    int error;

    memset(&ecmd, 0, sizeof ecmd);
    error = netdev_linux_do_ethtool(netdev, &ecmd,
                                    ETHTOOL_GSET, "ETHTOOL_GSET");
    if (error) {
        return error;
    }

    /* Supported features. */
    *supported = 0;
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

    /* Advertised features. */
    *advertised = 0;
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

    /* Current settings. */
    if (ecmd.speed == SPEED_10) {
        *current = ecmd.duplex ? OFPPF_10MB_FD : OFPPF_10MB_HD;
    } else if (ecmd.speed == SPEED_100) {
        *current = ecmd.duplex ? OFPPF_100MB_FD : OFPPF_100MB_HD;
    } else if (ecmd.speed == SPEED_1000) {
        *current = ecmd.duplex ? OFPPF_1GB_FD : OFPPF_1GB_HD;
    } else if (ecmd.speed == SPEED_10000) {
        *current = OFPPF_10GB_FD;
    } else {
        *current = 0;
    }

    if (ecmd.port == PORT_TP) {
        *current |= OFPPF_COPPER;
    } else if (ecmd.port == PORT_FIBRE) {
        *current |= OFPPF_FIBER;
    }

    if (ecmd.autoneg) {
        *current |= OFPPF_AUTONEG;
    }

    /* Peer advertisements. */
    *peer = 0;                  /* XXX */

    return 0;
}

/* Set the features advertised by 'netdev' to 'advertise'. */
static int
netdev_linux_set_advertisements(struct netdev *netdev, uint32_t advertise)
{
    struct ethtool_cmd ecmd;
    int error;

    memset(&ecmd, 0, sizeof ecmd);
    error = netdev_linux_do_ethtool(netdev, &ecmd,
                                    ETHTOOL_GSET, "ETHTOOL_GSET");
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
    return netdev_linux_do_ethtool(netdev, &ecmd,
                                   ETHTOOL_SSET, "ETHTOOL_SSET");
}

/* If 'netdev_name' is the name of a VLAN network device (e.g. one created with
 * vconfig(8)), sets '*vlan_vid' to the VLAN VID associated with that device
 * and returns 0.  Otherwise returns a errno value (specifically ENOENT if
 * 'netdev_name' is the name of a network device that is not a VLAN device) and
 * sets '*vlan_vid' to -1. */
static int
netdev_linux_get_vlan_vid(const struct netdev *netdev, int *vlan_vid)
{
    const char *netdev_name = netdev_get_name(netdev);
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

#define POLICE_ADD_CMD "/sbin/tc qdisc add dev %s handle ffff: ingress"
#define POLICE_CONFIG_CMD "/sbin/tc filter add dev %s parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate %dkbit burst %dk mtu 65535 drop flowid :1"
/* We redirect stderr to /dev/null because we often want to remove all
 * traffic control configuration on a port so its in a known state.  If
 * this done when there is no such configuration, tc complains, so we just
 * always ignore it.
 */
#define POLICE_DEL_CMD "/sbin/tc qdisc del dev %s handle ffff: ingress 2>/dev/null"

/* Attempts to set input rate limiting (policing) policy. */
static int
netdev_linux_set_policing(struct netdev *netdev,
                          uint32_t kbits_rate, uint32_t kbits_burst)
{
    const char *netdev_name = netdev_get_name(netdev);
    char command[1024];

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

static int
netdev_linux_get_in4(const struct netdev *netdev_,
                     struct in_addr *address, struct in_addr *netmask)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (!(netdev->cache->valid & VALID_IN4)) {
        int error;

        error = netdev_linux_get_ipv4(netdev_, &netdev->cache->address,
                                      SIOCGIFADDR, "SIOCGIFADDR");
        if (error) {
            return error;
        }

        error = netdev_linux_get_ipv4(netdev_, &netdev->cache->netmask,
                                      SIOCGIFNETMASK, "SIOCGIFNETMASK");
        if (error) {
            return error;
        }

        netdev->cache->valid |= VALID_IN4;
    }
    *address = netdev->cache->address;
    *netmask = netdev->cache->netmask;
    return address->s_addr == INADDR_ANY ? EADDRNOTAVAIL : 0;
}

static int
netdev_linux_set_in4(struct netdev *netdev_, struct in_addr address,
                     struct in_addr netmask)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    int error;

    error = do_set_addr(netdev_, SIOCSIFADDR, "SIOCSIFADDR", address);
    if (!error) {
        netdev->cache->valid |= VALID_IN4;
        netdev->cache->address = address;
        netdev->cache->netmask = netmask;
        if (address.s_addr != INADDR_ANY) {
            error = do_set_addr(netdev_, SIOCSIFNETMASK,
                                "SIOCSIFNETMASK", netmask);
        }
    }
    return error;
}

static bool
parse_if_inet6_line(const char *line,
                    struct in6_addr *in6, char ifname[16 + 1])
{
    uint8_t *s6 = in6->s6_addr;
#define X8 "%2"SCNx8
    return sscanf(line,
                  " "X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8
                  "%*x %*x %*x %*x %16s\n",
                  &s6[0], &s6[1], &s6[2], &s6[3],
                  &s6[4], &s6[5], &s6[6], &s6[7],
                  &s6[8], &s6[9], &s6[10], &s6[11],
                  &s6[12], &s6[13], &s6[14], &s6[15],
                  ifname) == 17;
}

/* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address (if
 * 'in6' is non-null) and returns true.  Otherwise, returns false. */
static int
netdev_linux_get_in6(const struct netdev *netdev_, struct in6_addr *in6)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    if (!(netdev->cache->valid & VALID_IN6)) {
        FILE *file;
        char line[128];

        netdev->cache->in6 = in6addr_any;

        file = fopen("/proc/net/if_inet6", "r");
        if (file != NULL) {
            const char *name = netdev_get_name(netdev_);
            while (fgets(line, sizeof line, file)) {
                struct in6_addr in6;
                char ifname[16 + 1];
                if (parse_if_inet6_line(line, &in6, ifname)
                    && !strcmp(name, ifname))
                {
                    netdev->cache->in6 = in6;
                    break;
                }
            }
            fclose(file);
        }
        netdev->cache->valid |= VALID_IN6;
    }
    *in6 = netdev->cache->in6;
    return 0;
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
do_set_addr(struct netdev *netdev,
            int ioctl_nr, const char *ioctl_name, struct in_addr addr)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    make_in4_sockaddr(&ifr.ifr_addr, addr);
    return netdev_linux_do_ioctl(netdev, &ifr, ioctl_nr, ioctl_name);
}

/* Adds 'router' as a default IP gateway. */
static int
netdev_linux_add_router(struct netdev *netdev UNUSED, struct in_addr router)
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

static int
netdev_linux_get_next_hop(const struct in_addr *host, struct in_addr *next_hop,
                          char **netdev_name)
{
    static const char fn[] = "/proc/net/route";
    FILE *stream;
    char line[256];
    int ln;

    *netdev_name = NULL;
    stream = fopen(fn, "r");
    if (stream == NULL) {
        VLOG_WARN_RL(&rl, "%s: open failed: %s", fn, strerror(errno));
        return errno;
    }

    ln = 0;
    while (fgets(line, sizeof line, stream)) {
        if (++ln >= 2) {
            char iface[17];
            uint32_t dest, gateway, mask;
            int refcnt, metric, mtu;
            unsigned int flags, use, window, irtt;

            if (sscanf(line,
                       "%16s %"SCNx32" %"SCNx32" %04X %d %u %d %"SCNx32
                       " %d %u %u\n",
                       iface, &dest, &gateway, &flags, &refcnt,
                       &use, &metric, &mask, &mtu, &window, &irtt) != 11) {

                VLOG_WARN_RL(&rl, "%s: could not parse line %d: %s", 
                        fn, ln, line);
                continue;
            }
            if (!(flags & RTF_UP)) {
                /* Skip routes that aren't up. */
                continue;
            }

            /* The output of 'dest', 'mask', and 'gateway' were given in
             * network byte order, so we don't need need any endian 
             * conversions here. */
            if ((dest & mask) == (host->s_addr & mask)) {
                if (!gateway) {
                    /* The host is directly reachable. */
                    next_hop->s_addr = 0;
                } else {
                    /* To reach the host, we must go through a gateway. */
                    next_hop->s_addr = gateway;
                }
                *netdev_name = xstrdup(iface);
                fclose(stream);
                return 0;
            }
        }
    }

    fclose(stream);
    return ENXIO;
}

/* Looks up the ARP table entry for 'ip' on 'netdev'.  If one exists and can be
 * successfully retrieved, it stores the corresponding MAC address in 'mac' and
 * returns 0.  Otherwise, it returns a positive errno value; in particular,
 * ENXIO indicates that there is not ARP table entry for 'ip' on 'netdev'. */
static int
netdev_linux_arp_lookup(const struct netdev *netdev,
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
    COVERAGE_INC(netdev_arp_lookup);
    retval = ioctl(af_inet_sock, SIOCGARP, &r) < 0 ? errno : 0;
    if (!retval) {
        memcpy(mac, r.arp_ha.sa_data, ETH_ADDR_LEN);
    } else if (retval != ENXIO) {
        VLOG_WARN_RL(&rl, "%s: could not look up ARP entry for "IP_FMT": %s",
                     netdev->name, IP_ARGS(&ip), strerror(retval));
    }
    return retval;
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

static int
iff_to_nd_flags(int iff)
{
    enum netdev_flags nd = 0;
    if (iff & IFF_UP) {
        nd |= NETDEV_UP;
    }
    if (iff & IFF_PROMISC) {
        nd |= NETDEV_PROMISC;
    }
    return nd;
}

static int
netdev_linux_update_flags(struct netdev *netdev, enum netdev_flags off,
                          enum netdev_flags on, enum netdev_flags *old_flagsp)
{
    int old_flags, new_flags;
    int error;

    error = get_flags(netdev, &old_flags);
    if (!error) {
        *old_flagsp = iff_to_nd_flags(old_flags);
        new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);
        if (new_flags != old_flags) {
            error = set_flags(netdev, new_flags);
        }
    }
    return error;
}

static void
poll_notify(struct list *list)
{
    struct netdev_linux_notifier *notifier;
    LIST_FOR_EACH (notifier, struct netdev_linux_notifier, node, list) {
        struct netdev_notifier *n = &notifier->notifier;
        n->cb(n);
    }
}

static void
netdev_linux_poll_cb(const struct rtnetlink_change *change,
                     void *aux UNUSED)
{
    if (change) {
        struct list *list = shash_find_data(&netdev_linux_notifiers,
                                            change->ifname);
        if (list) {
            poll_notify(list);
        }
    } else {
        struct shash_node *node;
        SHASH_FOR_EACH (node, &netdev_linux_notifiers) {
            poll_notify(node->data);
        }
    }
}

static int
netdev_linux_poll_add(struct netdev *netdev,
                      void (*cb)(struct netdev_notifier *), void *aux,
                      struct netdev_notifier **notifierp)
{
    const char *netdev_name = netdev_get_name(netdev);
    struct netdev_linux_notifier *notifier;
    struct list *list;

    if (shash_is_empty(&netdev_linux_notifiers)) {
        int error = rtnetlink_notifier_register(&netdev_linux_poll_notifier,
                                                   netdev_linux_poll_cb, NULL);
        if (error) {
            return error;
        }
    }

    list = shash_find_data(&netdev_linux_notifiers, netdev_name);
    if (!list) {
        list = xmalloc(sizeof *list);
        list_init(list);
        shash_add(&netdev_linux_notifiers, netdev_name, list);
    }

    notifier = xmalloc(sizeof *notifier);
    netdev_notifier_init(&notifier->notifier, netdev, cb, aux);
    list_push_back(list, &notifier->node);
    *notifierp = &notifier->notifier;
    return 0;
}

static void
netdev_linux_poll_remove(struct netdev_notifier *notifier_)
{
    struct netdev_linux_notifier *notifier =
        CONTAINER_OF(notifier_, struct netdev_linux_notifier, notifier);
    struct list *list;

    /* Remove 'notifier' from its list. */
    list = list_remove(&notifier->node);
    if (list_is_empty(list)) {
        /* The list is now empty.  Remove it from the hash and free it. */
        const char *netdev_name = netdev_get_name(notifier->notifier.netdev);
        shash_delete(&netdev_linux_notifiers,
                     shash_find(&netdev_linux_notifiers, netdev_name));
        free(list);
    }
    free(notifier);

    /* If that was the last notifier, unregister. */
    if (shash_is_empty(&netdev_linux_notifiers)) {
        rtnetlink_notifier_unregister(&netdev_linux_poll_notifier);
    }
}

const struct netdev_class netdev_linux_class = {
    "system",                   /* type */

    netdev_linux_init,
    netdev_linux_run,
    netdev_linux_wait,

    netdev_linux_create,
    netdev_linux_destroy,
    NULL,                       /* reconfigure */

    netdev_linux_open,
    netdev_linux_close,

    netdev_linux_enumerate,

    netdev_linux_recv,
    netdev_linux_recv_wait,
    netdev_linux_drain,

    netdev_linux_send,
    netdev_linux_send_wait,

    netdev_linux_set_etheraddr,
    netdev_linux_get_etheraddr,
    netdev_linux_get_mtu,
    netdev_linux_get_ifindex,
    netdev_linux_get_carrier,
    netdev_linux_get_stats,

    netdev_linux_get_features,
    netdev_linux_set_advertisements,
    netdev_linux_get_vlan_vid,
    netdev_linux_set_policing,

    netdev_linux_get_in4,
    netdev_linux_set_in4,
    netdev_linux_get_in6,
    netdev_linux_add_router,
    netdev_linux_get_next_hop,
    netdev_linux_arp_lookup,

    netdev_linux_update_flags,

    netdev_linux_poll_add,
    netdev_linux_poll_remove,
};

const struct netdev_class netdev_tap_class = {
    "tap",                      /* type */

    netdev_linux_init,
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_linux_create,
    netdev_linux_destroy,
    NULL,                       /* reconfigure */

    netdev_linux_open,
    netdev_linux_close,

    netdev_linux_enumerate,

    netdev_linux_recv,
    netdev_linux_recv_wait,
    netdev_linux_drain,

    netdev_linux_send,
    netdev_linux_send_wait,

    netdev_linux_set_etheraddr,
    netdev_linux_get_etheraddr,
    netdev_linux_get_mtu,
    netdev_linux_get_ifindex,
    netdev_linux_get_carrier,
    netdev_linux_get_stats,

    netdev_linux_get_features,
    netdev_linux_set_advertisements,
    netdev_linux_get_vlan_vid,
    netdev_linux_set_policing,

    netdev_linux_get_in4,
    netdev_linux_set_in4,
    netdev_linux_get_in6,
    netdev_linux_add_router,
    netdev_linux_get_next_hop,
    netdev_linux_arp_lookup,

    netdev_linux_update_flags,

    netdev_linux_poll_add,
    netdev_linux_poll_remove,
};

static int
get_stats_via_netlink(int ifindex, struct netdev_stats *stats)
{
    /* Policy for RTNLGRP_LINK messages.
     *
     * There are *many* more fields in these messages, but currently we only
     * care about these fields. */
    static const struct nl_policy rtnlgrp_link_policy[] = {
        [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
        [IFLA_STATS] = { .type = NL_A_UNSPEC, .optional = true,
                         .min_len = sizeof(struct rtnl_link_stats) },
    };


    static struct nl_sock *rtnl_sock;
    struct ofpbuf request;
    struct ofpbuf *reply;
    struct ifinfomsg *ifi;
    const struct rtnl_link_stats *rtnl_stats;
    struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
    int error;

    if (!rtnl_sock) {
        error = nl_sock_create(NETLINK_ROUTE, 0, 0, 0, &rtnl_sock);
        if (error) {
            VLOG_ERR_RL(&rl, "failed to create rtnetlink socket: %s",
                        strerror(error));
            return error;
        }
    }

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
        ofpbuf_delete(reply);
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

    ofpbuf_delete(reply);

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

static int
get_flags(const struct netdev *netdev, int *flags)
{
    struct ifreq ifr;
    int error;

    error = netdev_linux_do_ioctl(netdev, &ifr, SIOCGIFFLAGS, "SIOCGIFFLAGS");
    *flags = ifr.ifr_flags;
    return error;
}

static int
set_flags(struct netdev *netdev, int flags)
{
    struct ifreq ifr;

    ifr.ifr_flags = flags;
    return netdev_linux_do_ioctl(netdev, &ifr, SIOCSIFFLAGS, "SIOCSIFFLAGS");
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
get_ifindex(const struct netdev *netdev_, int *ifindexp)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    *ifindexp = 0;
    if (!(netdev->cache->valid & VALID_IFINDEX)) {
        int ifindex = do_get_ifindex(netdev_get_name(netdev_));
        if (ifindex < 0) {
            return -ifindex;
        }
        netdev->cache->valid |= VALID_IFINDEX;
        netdev->cache->ifindex = ifindex;
    }
    *ifindexp = netdev->cache->ifindex;
    return 0;
}

static int
get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN])
{
    struct ifreq ifr;
    int hwaddr_family;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    COVERAGE_INC(netdev_get_hwaddr);
    if (ioctl(af_inet_sock, SIOCGIFHWADDR, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCGIFHWADDR) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    hwaddr_family = ifr.ifr_hwaddr.sa_family;
    if (hwaddr_family != AF_UNSPEC && hwaddr_family != ARPHRD_ETHER) {
        VLOG_WARN("%s device has unknown hardware address family %d",
                  netdev_name, hwaddr_family);
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

static int
netdev_linux_do_ethtool(struct netdev *netdev, struct ethtool_cmd *ecmd,
                        int cmd, const char *cmd_name)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) ecmd;

    ecmd->cmd = cmd;
    COVERAGE_INC(netdev_ethtool);
    if (ioctl(af_inet_sock, SIOCETHTOOL, &ifr) == 0) {
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
netdev_linux_do_ioctl(const struct netdev *netdev, struct ifreq *ifr,
                      int cmd, const char *cmd_name)
{
    strncpy(ifr->ifr_name, netdev_get_name(netdev), sizeof ifr->ifr_name);
    if (ioctl(af_inet_sock, cmd, ifr) == -1) {
        VLOG_DBG_RL(&rl, "%s: ioctl(%s) failed: %s",
                    netdev_get_name(netdev), cmd_name, strerror(errno));
        return errno;
    }
    return 0;
}

static int
netdev_linux_get_ipv4(const struct netdev *netdev, struct in_addr *ip,
                      int cmd, const char *cmd_name)
{
    struct ifreq ifr;
    int error;

    ifr.ifr_addr.sa_family = AF_INET;
    error = netdev_linux_do_ioctl(netdev, &ifr, cmd, cmd_name);
    if (!error) {
        const struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
        *ip = sin->sin_addr;
    }
    return error;
}
