/*
 * Copyright (c) 2014, 2016 VMware, Inc.
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

#include <stdlib.h>
#include <config.h>
#include <errno.h>
#include <iphlpapi.h>

#include <net/if.h>

#include "coverage.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "openvswitch/shash.h"
#include "svec.h"
#include "openvswitch/vlog.h"
#include "odp-netlink.h"
#include "netlink-socket.h"
#include "netlink.h"

VLOG_DEFINE_THIS_MODULE(netdev_windows);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(9999, 5);

enum {
    VALID_ETHERADDR         = 1 << 0,
    VALID_MTU               = 1 << 1,
    VALID_IFFLAG            = 1 << 5,
};

/* Caches the information of a netdev. */
struct netdev_windows {
    struct netdev up;
    int32_t dev_type;
    uint32_t port_no;

    unsigned int change_seq;

    unsigned int cache_valid;
    int ifindex;
    struct eth_addr mac;
    uint32_t mtu;
    unsigned int ifi_flags;
};

/* Utility structure for netdev commands. */
struct netdev_windows_netdev_info {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* Information that is relevant to ovs. */
    uint32_t dp_ifindex;
    uint32_t port_no;
    uint32_t ovs_type;

    /* General information of a network device. */
    const char *name;
    struct eth_addr mac_address;
    uint32_t mtu;
    uint32_t ifi_flags;
};

static int query_netdev(const char *devname,
                        struct netdev_windows_netdev_info *reply,
                        struct ofpbuf **bufp);
static struct netdev *netdev_windows_alloc(void);
static int netdev_windows_init_(void);

/* Generic Netlink family numbers for OVS.
 *
 * Initialized by netdev_windows_init_(). */
static int ovs_win_netdev_family;
struct nl_sock *ovs_win_netdev_sock;


static bool
is_netdev_windows_class(const struct netdev_class *netdev_class)
{
    return netdev_class->alloc == netdev_windows_alloc;
}

static struct netdev_windows *
netdev_windows_cast(const struct netdev *netdev_)
{
    ovs_assert(is_netdev_windows_class(netdev_get_class(netdev_)));
    return CONTAINER_OF(netdev_, struct netdev_windows, up);
}

static int
netdev_windows_init_(void)
{
    int error = 0;
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        error = nl_lookup_genl_family(OVS_WIN_NETDEV_FAMILY,
                                      &ovs_win_netdev_family);
        if (error) {
            VLOG_ERR("Generic Netlink family '%s' does not exist. "
                     "The Open vSwitch kernel module is probably not loaded.",
                     OVS_WIN_NETDEV_FAMILY);
        }
        if (!error) {
            /* XXX: Where to close this socket? */
            error = nl_sock_create(NETLINK_GENERIC, &ovs_win_netdev_sock);
        }

        ovsthread_once_done(&once);
    }

    return error;
}

static struct netdev *
netdev_windows_alloc(void)
{
    struct netdev_windows *netdev = xzalloc(sizeof *netdev);
    return netdev ? &netdev->up : NULL;
}

static uint32_t
dp_to_netdev_ifi_flags(uint32_t dp_flags)
{
    uint32_t nd_flags = 0;

    if (dp_flags & OVS_WIN_NETDEV_IFF_UP) {
        nd_flags |= NETDEV_UP;
    }

    if (dp_flags & OVS_WIN_NETDEV_IFF_PROMISC) {
        nd_flags |= NETDEV_PROMISC;
    }

    return nd_flags;
}

static int
netdev_windows_system_construct(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    struct netdev_windows_netdev_info info;
    struct ofpbuf *buf;
    int ret;

    /* Query the attributes and runtime status of the netdev. */
    ret = query_netdev(netdev_get_name(&netdev->up), &info, &buf);
    /* "Internal" netdevs do not exist in the kernel yet.  They need to be
     * transformed into a netdev object and passed to dpif_port_add(), which
     * will add them to the kernel.  */
    if (strcmp(netdev_get_type(&netdev->up), "internal") && ret) {
        return ret;
    }
    ofpbuf_delete(buf);

    netdev->change_seq = 1;
    netdev->dev_type = info.ovs_type;
    netdev->port_no = info.port_no;

    netdev->mac = info.mac_address;
    netdev->cache_valid = VALID_ETHERADDR;
    netdev->ifindex = -EOPNOTSUPP;

    netdev->mtu = info.mtu;
    netdev->cache_valid |= VALID_MTU;

    netdev->ifi_flags = dp_to_netdev_ifi_flags(info.ifi_flags);
    netdev->cache_valid |= VALID_IFFLAG;

    VLOG_DBG("construct device %s, ovs_type: %u.",
             netdev_get_name(&netdev->up), info.ovs_type);
    return 0;
}

static int
netdev_windows_netdev_to_ofpbuf(struct netdev_windows_netdev_info *info,
                                struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;
    int error = EINVAL;

    nl_msg_put_genlmsghdr(buf, 0, ovs_win_netdev_family,
                          NLM_F_REQUEST | NLM_F_ECHO,
                          info->cmd, OVS_WIN_NETDEV_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = info->dp_ifindex;

    if (info->name) {
        nl_msg_put_string(buf, OVS_WIN_NETDEV_ATTR_NAME, info->name);
        error = 0;
    }

    return error;
}

static void
netdev_windows_info_init(struct netdev_windows_netdev_info *info)
{
    memset(info, 0, sizeof *info);
}

static int
netdev_windows_netdev_from_ofpbuf(struct netdev_windows_netdev_info *info,
                                  struct ofpbuf *buf)
{
    static const struct nl_policy ovs_netdev_policy[] = {
        [OVS_WIN_NETDEV_ATTR_PORT_NO] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_TYPE] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_NAME] = { .type = NL_A_STRING, .max_len = IFNAMSIZ },
        [OVS_WIN_NETDEV_ATTR_MAC_ADDR] = { NL_POLICY_FOR(info->mac_address) },
        [OVS_WIN_NETDEV_ATTR_MTU] = { .type = NL_A_U32 },
        [OVS_WIN_NETDEV_ATTR_IF_FLAGS] = { .type = NL_A_U32 },
    };

    netdev_windows_info_init(info);

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct ovs_header *ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);

    struct nlattr *a[ARRAY_SIZE(ovs_netdev_policy)];
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_win_netdev_family
        || !nl_policy_parse(&b, 0, ovs_netdev_policy, a,
                            ARRAY_SIZE(ovs_netdev_policy))) {
        return EINVAL;
    }

    info->cmd = genl->cmd;
    info->dp_ifindex = ovs_header->dp_ifindex;
    info->port_no = nl_attr_get_odp_port(a[OVS_WIN_NETDEV_ATTR_PORT_NO]);
    info->ovs_type = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_TYPE]);
    info->name = nl_attr_get_string(a[OVS_WIN_NETDEV_ATTR_NAME]);
    memcpy(&info->mac_address, nl_attr_get_unspec(a[OVS_WIN_NETDEV_ATTR_MAC_ADDR],
               sizeof(info->mac_address)), sizeof(info->mac_address));
    info->mtu = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_MTU]);
    info->ifi_flags = nl_attr_get_u32(a[OVS_WIN_NETDEV_ATTR_IF_FLAGS]);

    return 0;
}

static int
query_netdev(const char *devname,
             struct netdev_windows_netdev_info *info,
             struct ofpbuf **bufp)
{
    int error = 0;
    struct ofpbuf *request_buf;

    ovs_assert(info != NULL);
    netdev_windows_info_init(info);

    error = netdev_windows_init_();
    if (error) {
        if (info) {
            *bufp = NULL;
            netdev_windows_info_init(info);
        }
        return error;
    }

    request_buf = ofpbuf_new(1024);
    info->cmd = OVS_WIN_NETDEV_CMD_GET;
    info->name = devname;
    error = netdev_windows_netdev_to_ofpbuf(info, request_buf);
    if (error) {
        ofpbuf_delete(request_buf);
        return error;
    }

    error = nl_transact(NETLINK_GENERIC, request_buf, bufp);
    ofpbuf_delete(request_buf);

    if (info) {
        if (!error) {
            error = netdev_windows_netdev_from_ofpbuf(info, *bufp);
        }
        if (error) {
            netdev_windows_info_init(info);
            ofpbuf_delete(*bufp);
            *bufp = NULL;
        }
    }

    return error;
}

static void
netdev_windows_destruct(struct netdev *netdev_)
{

}

static void
netdev_windows_dealloc(struct netdev *netdev_)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);
    free(netdev);
}

static int
netdev_windows_get_etheraddr(const struct netdev *netdev_,
                             struct eth_addr *mac)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_ETHERADDR) != 0);
    if (netdev->cache_valid & VALID_ETHERADDR) {
        *mac = netdev->mac;
    } else {
        return EINVAL;
    }
    return 0;
}

static int
netdev_windows_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_MTU) != 0);
    if (netdev->cache_valid & VALID_MTU) {
        *mtup = netdev->mtu;
    } else {
        return EINVAL;
    }
    return 0;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_set_etheraddr(const struct netdev *netdev_,
                             const struct eth_addr mac)
{
    return 0;
}

/* This functionality is not really required by the datapath.
 * But vswitchd bringup expects this to be implemented. */
static int
netdev_windows_update_flags(struct netdev *netdev_,
                            enum netdev_flags off,
                            enum netdev_flags on,
                            enum netdev_flags *old_flagsp)
{
    struct netdev_windows *netdev = netdev_windows_cast(netdev_);

    ovs_assert((netdev->cache_valid & VALID_IFFLAG) != 0);
    if (netdev->cache_valid & VALID_IFFLAG) {
        *old_flagsp = netdev->ifi_flags;
        /* Setting the interface flags is not supported. */
    } else {
        return EINVAL;
    }
    return 0;
}

/* Looks up in the ARP table entry for a given 'ip'. If it is found, the
 * corresponding MAC address will be copied in 'mac' and return 0. If no
 * matching entry is found or an error occurs it will log it and return ENXIO.
 */
static int
netdev_windows_arp_lookup(const struct netdev *netdev,
                          ovs_be32 ip, struct eth_addr *mac)
{
    PMIB_IPNETTABLE arp_table = NULL;
    /* The buffer length of all ARP entries */
    uint32_t buffer_length = 0;
    uint32_t ret_val = 0;
    uint32_t counter = 0;

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val != ERROR_INSUFFICIENT_BUFFER ) {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    arp_table = (MIB_IPNETTABLE *) xmalloc(buffer_length);

    ret_val = GetIpNetTable(arp_table, &buffer_length, false);

    if (ret_val == NO_ERROR) {
        for (counter = 0; counter < arp_table->dwNumEntries; counter++) {
            if (arp_table->table[counter].dwAddr == ip) {
                memcpy(mac, arp_table->table[counter].bPhysAddr, ETH_ADDR_LEN);

                free(arp_table);
                return 0;
            }
        }
    } else {
        VLOG_ERR("Call to GetIpNetTable failed with error: %s",
                 ovs_format_message(ret_val));
    }

    free(arp_table);
    return ENXIO;
}

static int
netdev_windows_get_next_hop(const struct in_addr *host,
                            struct in_addr *next_hop,
                            char **netdev_name)
{
    uint32_t ret_val = 0;
    /* The buffer length of all addresses */
    uint32_t buffer_length = 0;
    PIP_ADAPTER_ADDRESSES all_addr = NULL;
    PIP_ADAPTER_ADDRESSES cur_addr = NULL;

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, NULL, &buffer_length);

    if (ret_val != ERROR_BUFFER_OVERFLOW ) {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
        return ENXIO;
    }

    all_addr = (IP_ADAPTER_ADDRESSES *) xmalloc(buffer_length);

    ret_val = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_INCLUDE_PREFIX |
                                   GAA_FLAG_INCLUDE_GATEWAYS,
                                   NULL, all_addr, &buffer_length);

    if (ret_val == NO_ERROR) {
        cur_addr = all_addr;
        while (cur_addr) {
            if(cur_addr->FirstGatewayAddress &&
               cur_addr->FirstGatewayAddress->Address.lpSockaddr) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)
                                           cur_addr->FirstGatewayAddress->Address.lpSockaddr;
                next_hop->s_addr = ipv4->sin_addr.S_un.S_addr;
                *netdev_name = xstrdup((char *)cur_addr->FriendlyName);

                free(all_addr);

                return 0;
            }

            cur_addr = cur_addr->Next;
        }
    } else {
        VLOG_ERR("Call to GetAdaptersAddresses failed with error: %s",
                 ovs_format_message(ret_val));
    }

    if (all_addr) {
        free(all_addr);
    }
    return ENXIO;
}

static int
netdev_windows_internal_construct(struct netdev *netdev_)
{
    return netdev_windows_system_construct(netdev_);
}


#define NETDEV_WINDOWS_CLASS(NAME, CONSTRUCT)                           \
{                                                                       \
    .type               = NAME,                                         \
    .is_pmd             = false,                                        \
    .alloc              = netdev_windows_alloc,                         \
    .construct          = CONSTRUCT,                                    \
    .destruct           = netdev_windows_destruct,                      \
    .dealloc            = netdev_windows_dealloc,                       \
    .get_etheraddr      = netdev_windows_get_etheraddr,                 \
    .set_etheraddr      = netdev_windows_set_etheraddr,                 \
    .update_flags       = netdev_windows_update_flags,                  \
    .get_next_hop       = netdev_windows_get_next_hop,                  \
    .arp_lookup         = netdev_windows_arp_lookup,                    \
}

const struct netdev_class netdev_windows_class =
    NETDEV_WINDOWS_CLASS(
        "system",
        netdev_windows_system_construct);

const struct netdev_class netdev_internal_class =
    NETDEV_WINDOWS_CLASS(
        "internal",
        netdev_windows_internal_construct);
