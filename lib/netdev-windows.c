/*
 * Copyright (c) 2014 VMware, Inc.
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

#include <net/if.h>

#include "coverage.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "shash.h"
#include "svec.h"
#include "vlog.h"
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
    uint8_t mac[ETH_ADDR_LEN];
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
    uint8_t mac_address[ETH_ADDR_LEN];
    uint32_t mtu;
    uint32_t ifi_flags;
};

static int
netdev_windows_init(void)
{
    return EINVAL;
}

static struct netdev *
netdev_windows_alloc(void)
{
    return NULL;
}

static int
netdev_windows_system_construct(struct netdev *netdev_)
{
    return EINVAL;
}

static void
netdev_windows_dealloc(struct netdev *netdev_)
{
}

static int
netdev_windows_get_etheraddr(const struct netdev *netdev_, uint8_t mac[6])
{
    return EINVAL;
}

static int
netdev_windows_get_mtu(const struct netdev *netdev_, int *mtup)
{
    return EINVAL;
}


static int
netdev_windows_internal_construct(struct netdev *netdev_)
{
    return netdev_windows_system_construct(netdev_);
}


#define NETDEV_WINDOWS_CLASS(NAME, CONSTRUCT)                           \
{                                                                       \
    .type               = NAME,                                         \
    .init               = netdev_windows_init,                          \
    .alloc              = netdev_windows_alloc,                         \
    .construct          = CONSTRUCT,                                    \
    .dealloc            = netdev_windows_dealloc,                       \
    .get_etheraddr      = netdev_windows_get_etheraddr,                 \
}

const struct netdev_class netdev_windows_class =
    NETDEV_WINDOWS_CLASS(
        "system",
        netdev_windows_system_construct);

const struct netdev_class netdev_internal_class =
    NETDEV_WINDOWS_CLASS(
        "internal",
        netdev_windows_internal_construct);
