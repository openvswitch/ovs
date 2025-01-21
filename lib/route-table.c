/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
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

#include "route-table.h"

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "coverage.h"
#include "hash.h"
#include "netdev.h"
#include "netlink.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-router.h"
#include "packets.h"
#include "rtnetlink.h"
#include "tnl-ports.h"
#include "openvswitch/vlog.h"

/* Linux 2.6.36 added RTA_MARK, so define it just in case we're building with
 * old headers.  (We can't test for it with #ifdef because it's an enum.) */
#define RTA_MARK 16

VLOG_DEFINE_THIS_MODULE(route_table);

COVERAGE_DEFINE(route_table_dump);

static struct ovs_mutex route_table_mutex = OVS_MUTEX_INITIALIZER;
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* Global change number for route-table, which should be incremented
 * every time route_table_reset() is called.  */
static uint64_t rt_change_seq;

static struct nln *nln = NULL;
static struct route_table_msg nln_rtmsg_change;
static struct nln_notifier *route_notifier = NULL;
static struct nln_notifier *route6_notifier = NULL;
static struct nln_notifier *name_notifier = NULL;

static bool route_table_valid = false;

static void route_table_reset(void);
static void route_table_handle_msg(const struct route_table_msg *, void *aux);
static void route_table_change(struct route_table_msg *, void *aux);
static void route_map_clear(void);

static void name_table_init(void);
static void name_table_change(const struct rtnetlink_change *, void *);

static void
route_data_destroy_nexthops__(struct route_data *rd)
{
    struct route_data_nexthop *rdnh;

    LIST_FOR_EACH_POP (rdnh, nexthop_node, &rd->nexthops) {
        if (rdnh && rdnh != &rd->primary_next_hop__) {
            free(rdnh);
        }
    }
}

void
route_data_destroy(struct route_data *rd)
{
    route_data_destroy_nexthops__(rd);
}

uint64_t
route_table_get_change_seq(void)
{
    return rt_change_seq;
}

/* Users of the route_table module should register themselves with this
 * function before making any other route_table function calls. */
void
route_table_init(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    ovs_assert(!nln);
    ovs_assert(!route_notifier);
    ovs_assert(!route6_notifier);

    ovs_router_init();
    nln = nln_create(NETLINK_ROUTE, route_table_parse, &nln_rtmsg_change);

    route_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
                            (nln_notify_func *) route_table_change, NULL);
    route6_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV6_ROUTE,
                            (nln_notify_func *) route_table_change, NULL);

    route_table_reset();
    name_table_init();

    ovs_mutex_unlock(&route_table_mutex);
}

/* Run periodically to update the locally maintained routing table. */
void
route_table_run(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    if (nln) {
        rtnetlink_run();
        nln_run(nln);

        if (!route_table_valid) {
            route_table_reset();
        }
    }
    ovs_mutex_unlock(&route_table_mutex);
}

/* Causes poll_block() to wake up when route_table updates are required. */
void
route_table_wait(void)
    OVS_EXCLUDED(route_table_mutex)
{
    ovs_mutex_lock(&route_table_mutex);
    if (nln) {
        rtnetlink_wait();
        nln_wait(nln);
    }
    ovs_mutex_unlock(&route_table_mutex);
}

bool
route_table_dump_one_table(uint32_t id,
                           route_table_handle_msg_callback *handle_msg_cb,
                           void *aux)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct rtmsg *rq_msg;
    bool filtered = true;
    struct nl_dump dump;

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, sizeof *rq_msg, RTM_GETROUTE, NLM_F_REQUEST);

    rq_msg = ofpbuf_put_zeros(&request, sizeof *rq_msg);
    rq_msg->rtm_family = AF_UNSPEC;

    if (id > UCHAR_MAX) {
        rq_msg->rtm_table = RT_TABLE_UNSPEC;
        nl_msg_put_u32(&request, RTA_TABLE, id);
    } else {
        rq_msg->rtm_table = id;
    }

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct route_table_msg msg;

        if (route_table_parse(&reply, &msg)) {
            struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(&reply);

            /* Older kernels do not support filtering. */
            if (!(nlmsghdr->nlmsg_flags & NLM_F_DUMP_FILTERED)) {
                filtered = false;
            }
            handle_msg_cb(&msg, aux);
            route_data_destroy(&msg.rd);
        }
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);

    return filtered;
}

static void
route_table_reset(void)
{
    uint32_t tables[] = {
        RT_TABLE_DEFAULT,
        RT_TABLE_MAIN,
        RT_TABLE_LOCAL,
    };

    route_map_clear();
    netdev_get_addrs_list_flush();
    route_table_valid = true;
    rt_change_seq++;

    COVERAGE_INC(route_table_dump);

    for (size_t i = 0; i < ARRAY_SIZE(tables); i++) {
        if (!route_table_dump_one_table(tables[i],
                                        route_table_handle_msg, NULL)) {
            /* Got unfiltered reply, no need to dump further. */
            break;
        }
    }
}

static int
route_table_parse__(struct ofpbuf *buf, size_t ofs,
                    const struct nlmsghdr *nlmsg,
                    const struct rtmsg *rtm,
                    const struct rtnexthop *rtnh,
                    struct route_table_msg *change)
{
    bool parsed, ipv4 = false;

    static const struct nl_policy policy[] = {
        [RTA_DST] = { .type = NL_A_U32, .optional = true  },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_U32, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
        [RTA_PRIORITY] = { .type = NL_A_U32, .optional = true },
        [RTA_VIA] = { .type = NL_A_RTA_VIA, .optional = true },
        [RTA_MULTIPATH] = { .type = NL_A_NESTED, .optional = true },
    };

    static const struct nl_policy policy6[] = {
        [RTA_DST] = { .type = NL_A_IPV6, .optional = true },
        [RTA_OIF] = { .type = NL_A_U32, .optional = true },
        [RTA_MARK] = { .type = NL_A_U32, .optional = true },
        [RTA_GATEWAY] = { .type = NL_A_IPV6, .optional = true },
        [RTA_PREFSRC] = { .type = NL_A_IPV6, .optional = true },
        [RTA_TABLE] = { .type = NL_A_U32, .optional = true },
        [RTA_PRIORITY] = { .type = NL_A_U32, .optional = true },
        [RTA_VIA] = { .type = NL_A_RTA_VIA, .optional = true },
        [RTA_MULTIPATH] = { .type = NL_A_NESTED, .optional = true },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];

    if (rtm->rtm_family == AF_INET) {
        parsed = nl_policy_parse(buf, ofs, policy, attrs,
                                 ARRAY_SIZE(policy));
        ipv4 = true;
    } else if (rtm->rtm_family == AF_INET6) {
        parsed = nl_policy_parse(buf, ofs, policy6, attrs,
                                 ARRAY_SIZE(policy6));
    } else {
        VLOG_DBG_RL(&rl, "received non AF_INET rtnetlink route message");
        return 0;
    }

    if (parsed) {
        struct route_data_nexthop *rdnh = NULL;
        int rta_oif;      /* Output interface index. */

        memset(change, 0, sizeof *change);

        ovs_list_init(&change->rd.nexthops);
        rdnh = rtnh ? xzalloc(sizeof *rdnh) : &change->rd.primary_next_hop__;
        ovs_list_insert(&change->rd.nexthops, &rdnh->nexthop_node);

        rdnh->family = rtm->rtm_family;
        change->relevant = true;

        if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
            change->relevant = false;
        }

        if (rtm->rtm_type != RTN_UNICAST &&
            rtm->rtm_type != RTN_LOCAL) {
            change->relevant = false;
        }

        change->rd.rta_table_id = rtm->rtm_table;
        if (attrs[RTA_TABLE]) {
            change->rd.rta_table_id = nl_attr_get_u32(attrs[RTA_TABLE]);
        }

        change->nlmsg_type     = nlmsg->nlmsg_type;
        change->rd.rtm_dst_len = rtm->rtm_dst_len;
        change->rd.rtm_protocol = rtm->rtm_protocol;
        change->rd.rtn_local = rtm->rtm_type == RTN_LOCAL;
        if (attrs[RTA_OIF] && rtnh) {
            VLOG_DBG_RL(&rl, "unexpected RTA_OIF attribute while parsing "
                             "nested RTA_MULTIPATH attributes");
            goto error_out;
        }
        if (attrs[RTA_OIF] || rtnh) {
            rta_oif = rtnh ? rtnh->rtnh_ifindex
                           : nl_attr_get_u32(attrs[RTA_OIF]);

            if (!if_indextoname(rta_oif, rdnh->ifname)) {
                int error = errno;

                VLOG_DBG_RL(&rl, "could not find interface name[%u]: %s",
                            rta_oif, ovs_strerror(error));
                if (error == ENXIO) {
                    change->relevant = false;
                } else {
                    goto error_out;
                }
            }
        }

        if (attrs[RTA_DST]) {
            if (ipv4) {
                ovs_be32 dst;
                dst = nl_attr_get_be32(attrs[RTA_DST]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_dst, dst);
            } else {
                change->rd.rta_dst = nl_attr_get_in6_addr(attrs[RTA_DST]);
            }
        } else if (ipv4) {
            in6_addr_set_mapped_ipv4(&change->rd.rta_dst, 0);
        }
        if (attrs[RTA_PREFSRC]) {
            if (ipv4) {
                ovs_be32 prefsrc;
                prefsrc = nl_attr_get_be32(attrs[RTA_PREFSRC]);
                in6_addr_set_mapped_ipv4(&change->rd.rta_prefsrc, prefsrc);
            } else {
                change->rd.rta_prefsrc =
                    nl_attr_get_in6_addr(attrs[RTA_PREFSRC]);
            }
        }
        if (attrs[RTA_GATEWAY]) {
            if (ipv4) {
                ovs_be32 gw;
                gw = nl_attr_get_be32(attrs[RTA_GATEWAY]);
                in6_addr_set_mapped_ipv4(&rdnh->addr, gw);
            } else {
                rdnh->addr = nl_attr_get_in6_addr(attrs[RTA_GATEWAY]);
            }
        }
        if (attrs[RTA_MARK]) {
            change->rd.rta_mark = nl_attr_get_u32(attrs[RTA_MARK]);
        }
        if (attrs[RTA_PRIORITY]) {
            change->rd.rta_priority = nl_attr_get_u32(attrs[RTA_PRIORITY]);
        }
        if (attrs[RTA_VIA]) {
            const struct rtvia *rtvia = nl_attr_get(attrs[RTA_VIA]);
            ovs_be32 addr;

            if (attrs[RTA_GATEWAY]) {
                VLOG_DBG_RL(&rl, "route message can not contain both "
                                 "RTA_GATEWAY and RTA_VIA");
                goto error_out;
            }

            rdnh->family = rtvia->rtvia_family;

            switch (rdnh->family) {
            case AF_INET:
                if (nl_attr_get_size(attrs[RTA_VIA])
                        - sizeof *rtvia < sizeof addr) {
                    VLOG_DBG_RL(&rl, "got short message while parsing RTA_VIA "
                                     "attribute for family AF_INET");
                    goto error_out;
                }
                memcpy(&addr, rtvia->rtvia_addr, sizeof addr);
                in6_addr_set_mapped_ipv4(&rdnh->addr, addr);
                break;

            case AF_INET6:
                if (nl_attr_get_size(attrs[RTA_VIA])
                        - sizeof *rtvia < sizeof rdnh->addr) {
                    VLOG_DBG_RL(&rl, "got short message while parsing RTA_VIA "
                                     "attribute for family AF_INET6");
                    goto error_out;
                }
                memcpy(&rdnh->addr, rtvia->rtvia_addr, sizeof rdnh->addr);
                break;

            default:
                VLOG_DBG_RL(&rl, "unsupported address family, %d, "
                                 "in via attribute", rdnh->family);
                goto error_out;
            }
        }
        if (attrs[RTA_MULTIPATH]) {
            const struct nlattr *nla;
            size_t left;

            if (rtnh) {
                VLOG_DBG_RL(&rl, "unexpected nested RTA_MULTIPATH attribute");
                goto error_out;
            }

            /* The change->rd->nexthops list is unconditionally populated with
             * a single rdnh entry as we start parsing above.  Multiple
             * branches above may access it or jump to error_out, and having it
             * on the list is the only way to ensure proper cleanup.
             *
             * Getting to this point, we know that the above branches has not
             * provided next hop information, because information about
             * multiple next hops is encoded in the nested attributes after the
             * RTA_MULTIPATH attribute.
             *
             * Before retrieving those we need to remove the empty rdnh entry
             * from the list. */
            route_data_destroy_nexthops__(&change->rd);

            NL_NESTED_FOR_EACH (nla, left, attrs[RTA_MULTIPATH]) {
                struct route_table_msg mp_change;
                struct rtnexthop *mp_rtnh;
                struct ofpbuf mp_buf;

                ofpbuf_use_const(&mp_buf, nla, nla->nla_len);
                mp_rtnh = ofpbuf_try_pull(&mp_buf, sizeof *mp_rtnh);

                if (!mp_rtnh) {
                    VLOG_DBG_RL(&rl, "got short message while parsing "
                                     "multipath attribute");
                    goto error_out;
                }

                if (!route_table_parse__(&mp_buf, 0, nlmsg, rtm, mp_rtnh,
                                         &mp_change)) {
                    goto error_out;
                }
                ovs_list_push_back_all(&change->rd.nexthops,
                                       &mp_change.rd.nexthops);
            }
        }
        if (!attrs[RTA_OIF] && !attrs[RTA_GATEWAY]
                && !attrs[RTA_VIA] && !attrs[RTA_MULTIPATH]) {
            VLOG_DBG_RL(&rl, "route message needs an RTA_OIF, RTA_GATEWAY, "
                             "RTA_VIA or RTA_MULTIPATH attribute");
            goto error_out;
        }
        /* Add any additional RTA attribute processing before RTA_MULTIPATH. */
    } else {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink route message");
        goto error_out;
    }

    /* Success. */
    return ipv4 ? RTNLGRP_IPV4_ROUTE : RTNLGRP_IPV6_ROUTE;

error_out:
    route_data_destroy(&change->rd);
    return 0;
}

/* Parse Netlink message in buf, which is expected to contain a UAPI rtmsg
 * header and associated route attributes.
 *
 * Return RTNLGRP_IPV4_ROUTE or RTNLGRP_IPV6_ROUTE on success, and 0 on a parse
 * error.
 *
 * On success, memory may have been allocated, and it is the caller's
 * responsibility to free it with a call to route_data_destroy().
 *
 * In case of error, any allocated memory will be freed before returning. */
int
route_table_parse(struct ofpbuf *buf, void *change)
{
    struct nlmsghdr *nlmsg;
    struct rtmsg *rtm;

    nlmsg = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    rtm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *rtm);

    if (!nlmsg || !rtm) {
        return 0;
    }

    return route_table_parse__(buf, NLMSG_HDRLEN + sizeof *rtm,
                               nlmsg, rtm, NULL, change);
}

static bool
is_standard_table_id(uint32_t table_id)
{
    return !table_id
           || table_id == RT_TABLE_DEFAULT
           || table_id == RT_TABLE_MAIN
           || table_id == RT_TABLE_LOCAL;
}

static void
route_table_change(struct route_table_msg *change, void *aux OVS_UNUSED)
{
    if (!change
        || (change->relevant
            && is_standard_table_id(change->rd.rta_table_id))) {
        route_table_valid = false;
    }
    if (change) {
        route_data_destroy(&change->rd);
    }
}

static void
route_table_handle_msg(const struct route_table_msg *change,
                       void *aux OVS_UNUSED)
{
    if (change->relevant && change->nlmsg_type == RTM_NEWROUTE
            && !ovs_list_is_empty(&change->rd.nexthops)) {
        const struct route_data *rd = &change->rd;
        const struct route_data_nexthop *rdnh;

        /* The ovs-router module currently does not implement lookup or
         * storage for routes with multiple next hops.  For backwards
         * compatibility, we use the first next hop. */
        rdnh = CONTAINER_OF(ovs_list_front(&change->rd.nexthops),
                            const struct route_data_nexthop, nexthop_node);

        ovs_router_insert(rd->rta_mark, &rd->rta_dst,
                          IN6_IS_ADDR_V4MAPPED(&rd->rta_dst)
                          ? rd->rtm_dst_len + 96 : rd->rtm_dst_len,
                          rd->rtn_local, rdnh->ifname, &rdnh->addr,
                          &rd->rta_prefsrc);
    }
}

static void
route_map_clear(void)
{
    ovs_router_flush();
}

bool
route_table_fallback_lookup(const struct in6_addr *ip6_dst OVS_UNUSED,
                            char name[] OVS_UNUSED,
                            struct in6_addr *gw6)
{
    *gw6 = in6addr_any;
    return false;
}


/* name_table . */

static void
name_table_init(void)
{
    name_notifier = rtnetlink_notifier_create(name_table_change, NULL);
}


static void
name_table_change(const struct rtnetlink_change *change,
                  void *aux OVS_UNUSED)
{
    if (change && change->irrelevant) {
        return;
    }

    /* Changes to interface status can cause routing table changes that some
     * versions of the linux kernel do not advertise for some reason. */
    route_table_valid = false;

    if (change && change->nlmsg_type == RTM_DELLINK) {
        if (change->ifname) {
            tnl_port_map_delete_ipdev(change->ifname);
        }
    }
}
