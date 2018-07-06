/*
 * Copyright (c) 2017 Red Hat, Inc.
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

#include "dpif-netlink-rtnl.h"

#include <net/if.h>
#include <linux/ip.h>
#include <linux/rtnetlink.h>

#include "dpif-netlink.h"
#include "netdev-vport.h"
#include "netlink-socket.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netlink_rtnl);

/* On some older systems, these enums are not defined. */
#ifndef IFLA_VXLAN_MAX
#define IFLA_VXLAN_MAX 0
#endif
#if IFLA_VXLAN_MAX < 27
#define IFLA_VXLAN_LEARNING 7
#define IFLA_VXLAN_PORT 15
#define IFLA_VXLAN_UDP_ZERO_CSUM6_RX 20
#define IFLA_VXLAN_GBP 23
#define IFLA_VXLAN_COLLECT_METADATA 25
#define IFLA_VXLAN_GPE 27
#endif

#ifndef IFLA_GRE_MAX
#define IFLA_GRE_MAX 0
#endif
#if IFLA_GRE_MAX < 18
#define IFLA_GRE_COLLECT_METADATA 18
#endif

#ifndef IFLA_GENEVE_MAX
#define IFLA_GENEVE_MAX 0
#endif
#if IFLA_GENEVE_MAX < 10
#define IFLA_GENEVE_PORT 5
#define IFLA_GENEVE_COLLECT_METADATA 6
#define IFLA_GENEVE_UDP_ZERO_CSUM6_RX 10
#endif

static const struct nl_policy rtlink_policy[] = {
    [IFLA_LINKINFO] = { .type = NL_A_NESTED },
};
static const struct nl_policy linkinfo_policy[] = {
    [IFLA_INFO_KIND] = { .type = NL_A_STRING },
    [IFLA_INFO_DATA] = { .type = NL_A_NESTED },
};
static const struct nl_policy vxlan_policy[] = {
    [IFLA_VXLAN_COLLECT_METADATA] = { .type = NL_A_U8 },
    [IFLA_VXLAN_LEARNING] = { .type = NL_A_U8 },
    [IFLA_VXLAN_UDP_ZERO_CSUM6_RX] = { .type = NL_A_U8 },
    [IFLA_VXLAN_PORT] = { .type = NL_A_U16 },
    [IFLA_VXLAN_GBP] = { .type = NL_A_FLAG, .optional = true },
    [IFLA_VXLAN_GPE] = { .type = NL_A_FLAG, .optional = true },
};
static const struct nl_policy gre_policy[] = {
    [IFLA_GRE_COLLECT_METADATA] = { .type = NL_A_FLAG },
};
static const struct nl_policy geneve_policy[] = {
    [IFLA_GENEVE_COLLECT_METADATA] = { .type = NL_A_FLAG },
    [IFLA_GENEVE_UDP_ZERO_CSUM6_RX] = { .type = NL_A_U8 },
    [IFLA_GENEVE_PORT] = { .type = NL_A_U16 },
};

static const char *
vport_type_to_kind(enum ovs_vport_type type,
                   const struct netdev_tunnel_config *tnl_cfg)
{
    switch (type) {
    case OVS_VPORT_TYPE_VXLAN:
        return "vxlan";
    case OVS_VPORT_TYPE_GRE:
        if (tnl_cfg->pt_mode == NETDEV_PT_LEGACY_L3) {
            return "gre";
        } else if (tnl_cfg->pt_mode == NETDEV_PT_LEGACY_L2) {
            return "gretap";
        } else {
            return NULL;
        }
    case OVS_VPORT_TYPE_GENEVE:
        return "geneve";
    case OVS_VPORT_TYPE_ERSPAN:
        return "erspan";
    case OVS_VPORT_TYPE_IP6ERSPAN:
        return "ip6erspan";
    case OVS_VPORT_TYPE_IP6GRE:
        return "ip6gre";
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        break;
    }

    return NULL;
}

static int
rtnl_transact(uint32_t type, uint32_t flags, const char *name,
              struct ofpbuf **reply)
{
    struct ofpbuf request;
    int err;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, type, flags);
    ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    nl_msg_put_string(&request, IFLA_IFNAME, name);

    err = nl_transact(NETLINK_ROUTE, &request, reply);
    ofpbuf_uninit(&request);

    return err;
}

static int
dpif_netlink_rtnl_destroy(const char *name)
{
    return rtnl_transact(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, name, NULL);
}

static int
dpif_netlink_rtnl_getlink(const char *name, struct ofpbuf **reply)
{
    return rtnl_transact(RTM_GETLINK, NLM_F_REQUEST, name, reply);
}

static int
rtnl_policy_parse(const char *kind, struct ofpbuf *reply,
                  const struct nl_policy *policy,
                  struct nlattr *tnl_info[],
                  size_t policy_size)
{
    struct nlattr *linkinfo[ARRAY_SIZE(linkinfo_policy)];
    struct nlattr *rtlink[ARRAY_SIZE(rtlink_policy)];
    int error = 0;

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                         rtlink_policy, rtlink, ARRAY_SIZE(rtlink_policy))
        || !nl_parse_nested(rtlink[IFLA_LINKINFO], linkinfo_policy,
                            linkinfo, ARRAY_SIZE(linkinfo_policy))
        || strcmp(nl_attr_get_string(linkinfo[IFLA_INFO_KIND]), kind)
        || !nl_parse_nested(linkinfo[IFLA_INFO_DATA], policy,
                            tnl_info, policy_size)) {
        error = EINVAL;
    }

    return error;
}

static int
dpif_netlink_rtnl_vxlan_verify(const struct netdev_tunnel_config *tnl_cfg,
                               const char *kind, struct ofpbuf *reply)
{
    struct nlattr *vxlan[ARRAY_SIZE(vxlan_policy)];
    int err;

    err = rtnl_policy_parse(kind, reply, vxlan_policy, vxlan,
                            ARRAY_SIZE(vxlan_policy));
    if (!err) {
        if (0 != nl_attr_get_u8(vxlan[IFLA_VXLAN_LEARNING])
            || 1 != nl_attr_get_u8(vxlan[IFLA_VXLAN_COLLECT_METADATA])
            || 1 != nl_attr_get_u8(vxlan[IFLA_VXLAN_UDP_ZERO_CSUM6_RX])
            || (tnl_cfg->dst_port
                != nl_attr_get_be16(vxlan[IFLA_VXLAN_PORT]))
            || (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GBP)
                && !nl_attr_get_flag(vxlan[IFLA_VXLAN_GBP]))
            || (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GPE)
                && !nl_attr_get_flag(vxlan[IFLA_VXLAN_GPE]))) {
            err = EINVAL;
        }
    }

    return err;
}

static int
dpif_netlink_rtnl_gre_verify(const struct netdev_tunnel_config OVS_UNUSED *tnl,
                             const char *kind, struct ofpbuf *reply)
{
    struct nlattr *gre[ARRAY_SIZE(gre_policy)];
    int err;

    err = rtnl_policy_parse(kind, reply, gre_policy, gre,
                            ARRAY_SIZE(gre_policy));
    if (!err) {
        if (!nl_attr_get_flag(gre[IFLA_GRE_COLLECT_METADATA])) {
            err = EINVAL;
        }
    }

    return err;
}

static int
dpif_netlink_rtnl_geneve_verify(const struct netdev_tunnel_config *tnl_cfg,
                                const char *kind, struct ofpbuf *reply)
{
    struct nlattr *geneve[ARRAY_SIZE(geneve_policy)];
    int err;

    err = rtnl_policy_parse(kind, reply, geneve_policy, geneve,
                            ARRAY_SIZE(geneve_policy));
    if (!err) {
        if (!nl_attr_get_flag(geneve[IFLA_GENEVE_COLLECT_METADATA])
            || 1 != nl_attr_get_u8(geneve[IFLA_GENEVE_UDP_ZERO_CSUM6_RX])
            || (tnl_cfg->dst_port
                != nl_attr_get_be16(geneve[IFLA_GENEVE_PORT]))) {
            err = EINVAL;
        }
    }

    return err;
}

static int
dpif_netlink_rtnl_verify(const struct netdev_tunnel_config *tnl_cfg,
                         enum ovs_vport_type type, const char *name)
{
    struct ofpbuf *reply;
    const char *kind;
    int err;

    kind = vport_type_to_kind(type, tnl_cfg);
    if (!kind) {
        return EOPNOTSUPP;
    }

    err = dpif_netlink_rtnl_getlink(name, &reply);
    if (err) {
        return err;
    }

    switch (type) {
    case OVS_VPORT_TYPE_VXLAN:
        err = dpif_netlink_rtnl_vxlan_verify(tnl_cfg, kind, reply);
        break;
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_ERSPAN:
    case OVS_VPORT_TYPE_IP6ERSPAN:
    case OVS_VPORT_TYPE_IP6GRE:
        err = dpif_netlink_rtnl_gre_verify(tnl_cfg, kind, reply);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        err = dpif_netlink_rtnl_geneve_verify(tnl_cfg, kind, reply);
        break;
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        OVS_NOT_REACHED();
    }

    ofpbuf_delete(reply);
    return err;
}

static int
rtnl_set_mtu(const char *name, uint32_t mtu, struct ofpbuf *request)
{
    ofpbuf_clear(request);
    nl_msg_put_nlmsghdr(request, 0, RTM_SETLINK,
                        NLM_F_REQUEST | NLM_F_ACK);
    ofpbuf_put_zeros(request, sizeof(struct ifinfomsg));
    nl_msg_put_string(request, IFLA_IFNAME, name);
    nl_msg_put_u32(request, IFLA_MTU, mtu);

    return nl_transact(NETLINK_ROUTE, request, NULL);
}

static int
dpif_netlink_rtnl_create(const struct netdev_tunnel_config *tnl_cfg,
                         const char *name, enum ovs_vport_type type,
                         const char *kind, uint32_t flags)
{
    enum {
        /* For performance, we want to use the largest MTU that the system
         * supports.  Most existing tunnels will accept UINT16_MAX, treating it
         * as the actual max MTU, but some do not.  Thus, we use a slightly
         * smaller value, that should always be safe yet does not noticeably
         * reduce performance. */
        MAX_MTU = 65000
    };

    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    int err;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK, flags);
    ifinfo = ofpbuf_put_zeros(&request, sizeof(struct ifinfomsg));
    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    nl_msg_put_string(&request, IFLA_IFNAME, name);
    nl_msg_put_u32(&request, IFLA_MTU, MAX_MTU);
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, kind);
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);

    /* tunnel unique info */
    switch (type) {
    case OVS_VPORT_TYPE_VXLAN:
        nl_msg_put_u8(&request, IFLA_VXLAN_LEARNING, 0);
        nl_msg_put_u8(&request, IFLA_VXLAN_COLLECT_METADATA, 1);
        nl_msg_put_u8(&request, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, 1);
        if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GBP)) {
            nl_msg_put_flag(&request, IFLA_VXLAN_GBP);
        }
        if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GPE)) {
            nl_msg_put_flag(&request, IFLA_VXLAN_GPE);
        }
        nl_msg_put_be16(&request, IFLA_VXLAN_PORT, tnl_cfg->dst_port);
        break;
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_ERSPAN:
    case OVS_VPORT_TYPE_IP6ERSPAN:
    case OVS_VPORT_TYPE_IP6GRE:
        nl_msg_put_flag(&request, IFLA_GRE_COLLECT_METADATA);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        nl_msg_put_flag(&request, IFLA_GENEVE_COLLECT_METADATA);
        nl_msg_put_u8(&request, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, 1);
        nl_msg_put_be16(&request, IFLA_GENEVE_PORT, tnl_cfg->dst_port);
        break;
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        err = EOPNOTSUPP;
        goto exit;
    }

    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);
    if (!err && (type == OVS_VPORT_TYPE_GRE ||
                 type == OVS_VPORT_TYPE_IP6GRE)) {
        /* Work around a bug in kernel GRE driver, which ignores IFLA_MTU in
         * RTM_NEWLINK, by setting the MTU again.  See
         * https://bugzilla.redhat.com/show_bug.cgi?id=1488484.
         *
         * In case of MAX_MTU exceeds hw max MTU, retry a smaller value. */
        int err2 = rtnl_set_mtu(name, MAX_MTU, &request);
        if (err2) {
            err2 = rtnl_set_mtu(name, 1450, &request);
        }
        if (err2) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "setting MTU of tunnel %s failed (%s)",
                         name, ovs_strerror(err2));
        }
    }

exit:
    ofpbuf_uninit(&request);

    return err;
}

int
dpif_netlink_rtnl_port_create(struct netdev *netdev)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    enum ovs_vport_type type;
    const char *name;
    const char *kind;
    uint32_t flags;
    int err;

    type = netdev_to_ovs_vport_type(netdev_get_type(netdev));
    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (!tnl_cfg) {
        return EOPNOTSUPP;
    }

    kind = vport_type_to_kind(type, tnl_cfg);
    if (!kind) {
        return EOPNOTSUPP;
    }

    name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

    err = dpif_netlink_rtnl_create(tnl_cfg, name, type, kind, flags);

    /* If the device exists, validate and/or attempt to recreate it. */
    if (err == EEXIST) {
        err = dpif_netlink_rtnl_verify(tnl_cfg, type, name);
        if (!err) {
            return 0;
        }
        err = dpif_netlink_rtnl_destroy(name);
        if (err) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "RTNL device %s exists and cannot be "
                         "deleted: %s", name, ovs_strerror(err));
            return err;
        }
        err = dpif_netlink_rtnl_create(tnl_cfg, name, type, kind, flags);
    }
    if (err) {
        return err;
    }

    err = dpif_netlink_rtnl_verify(tnl_cfg, type, name);
    if (err) {
        int err2 = dpif_netlink_rtnl_destroy(name);

        if (err2) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "Failed to delete device %s during rtnl port "
                         "creation: %s", name, ovs_strerror(err2));
        }
    }

    return err;
}

int
dpif_netlink_rtnl_port_destroy(const char *name, const char *type)
{
    switch (netdev_to_ovs_vport_type(type)) {
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_GENEVE:
    case OVS_VPORT_TYPE_ERSPAN:
    case OVS_VPORT_TYPE_IP6ERSPAN:
    case OVS_VPORT_TYPE_IP6GRE:
        return dpif_netlink_rtnl_destroy(name);
    case OVS_VPORT_TYPE_NETDEV:
    case OVS_VPORT_TYPE_INTERNAL:
    case OVS_VPORT_TYPE_LISP:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_UNSPEC:
    case __OVS_VPORT_TYPE_MAX:
    default:
        return EOPNOTSUPP;
    }
    return 0;
}

/**
 * Probe for whether the modules are out-of-tree (openvswitch) or in-tree
 * (upstream kernel).
 *
 * We probe for "ovs_geneve" via rtnetlink. As long as this returns something
 * other than EOPNOTSUPP we know that the module in use is the out-of-tree one.
 * This will be used to determine which netlink interface to use when creating
 * ports; rtnetlink or compat/genetlink.
 *
 * See ovs_tunnels_out_of_tree
 */
bool
dpif_netlink_rtnl_probe_oot_tunnels(void)
{
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    struct netdev *netdev = NULL;
    bool out_of_tree = false;
    const char *name;
    int error;

    error = netdev_open("ovs-system-probe", "geneve", &netdev);
    if (!error) {
        struct ofpbuf *reply;
        const struct netdev_tunnel_config *tnl_cfg;

        tnl_cfg = netdev_get_tunnel_config(netdev);
        if (!tnl_cfg) {
            return true;
        }

        name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

        /* The geneve module exists when ovs-vswitchd crashes
         * and restarts, handle the case here.
         */
        error = dpif_netlink_rtnl_getlink(name, &reply);
        if (!error) {

            struct nlattr *linkinfo[ARRAY_SIZE(linkinfo_policy)];
            struct nlattr *rtlink[ARRAY_SIZE(rtlink_policy)];
            const char *kind;

            if (!nl_policy_parse(reply,
                                 NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                 rtlink_policy, rtlink,
                                 ARRAY_SIZE(rtlink_policy))
                || !nl_parse_nested(rtlink[IFLA_LINKINFO], linkinfo_policy,
                                    linkinfo, ARRAY_SIZE(linkinfo_policy))) {
                VLOG_ABORT("Error fetching Geneve tunnel device %s "
                           "linkinfo", name);
            }

            kind = nl_attr_get_string(linkinfo[IFLA_INFO_KIND]);

            if (!strcmp(kind, "ovs_geneve")) {
                out_of_tree = true;
            } else if (!strcmp(kind, "geneve")) {
                out_of_tree = false;
            } else {
                VLOG_ABORT("Geneve tunnel device %s with kind %s"
                           " not supported", name, kind);
            }

            ofpbuf_delete(reply);
            netdev_close(netdev);

            return out_of_tree;
        }

        error = dpif_netlink_rtnl_create(tnl_cfg, name, OVS_VPORT_TYPE_GENEVE,
                                         "ovs_geneve",
                                         (NLM_F_REQUEST | NLM_F_ACK
                                          | NLM_F_CREATE));
        if (error != EOPNOTSUPP) {
            if (!error) {
                dpif_netlink_rtnl_destroy(name);
            }
            out_of_tree = true;
        }
        netdev_close(netdev);
    }

    return out_of_tree;
}
