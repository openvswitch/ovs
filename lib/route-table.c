/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "hash.h"
#include "hmap.h"
#include "netlink.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "ofpbuf.h"
#include "rtnetlink-link.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(route_table);

struct route_data {
    /* Copied from struct rtmsg. */
    unsigned char rtm_dst_len;

    /* Extracted from Netlink attributes. */
    uint32_t rta_dst; /* Destination in host byte order. 0 if missing. */
    int rta_oif;      /* Output interface index. */
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct route_table_msg {
    bool relevant;        /* Should this message be processed? */
    int nlmsg_type;       /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
    struct route_data rd; /* Data parsed from this message. */
};

struct route_node {
    struct hmap_node node; /* Node in route_map. */
    struct route_data rd;  /* Data associated with this node. */
};

struct name_node {
    struct hmap_node node; /* Node in name_map. */
    uint32_t ifi_index;    /* Kernel interface index. */

    char ifname[IFNAMSIZ]; /* Interface name. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static unsigned int register_count = 0;
static struct nln *nln = NULL;
static struct route_table_msg rtmsg;
static struct nln_notifier *route_notifier = NULL;
static struct nln_notifier *name_notifier = NULL;

static bool route_table_valid = false;
static bool name_table_valid = false;
static struct hmap route_map;
static struct hmap name_map;

static int route_table_reset(void);
static void route_table_handle_msg(const struct route_table_msg *);
static bool route_table_parse(struct ofpbuf *, struct route_table_msg *);
static void route_table_change(const struct route_table_msg *, void *);
static struct route_node *route_node_lookup(const struct route_data *);
static struct route_node *route_node_lookup_by_ip(uint32_t ip);
static void route_map_clear(void);
static uint32_t hash_route_data(const struct route_data *);

static void name_table_init(void);
static void name_table_uninit(void);
static int name_table_reset(void);
static void name_table_change(const struct rtnetlink_link_change *, void *);
static void name_map_clear(void);
static struct name_node *name_node_lookup(int ifi_index);

/* Populates 'name' with the name of the interface traffic destined for 'ip'
 * is likely to egress out of (see route_table_get_ifindex).
 *
 * Returns true if successful, otherwise false. */
bool
route_table_get_name(ovs_be32 ip, char name[IFNAMSIZ])
{
    int ifindex;

    if (!name_table_valid) {
        name_table_reset();
    }

    if (route_table_get_ifindex(ip, &ifindex)) {
        struct name_node *nn;

        nn = name_node_lookup(ifindex);
        if (nn) {
            ovs_strlcpy(name, nn->ifname, IFNAMSIZ);
            return true;
        }
    }

    return false;
}

/* Populates 'ifindex' with the interface index traffic destined for 'ip' is
 * likely to egress.  There is no hard guarantee that traffic destined for 'ip'
 * will egress out the specified interface.  'ifindex' may refer to an
 * interface which is not physical (such as a bridge port).
 *
 * Returns true if successful, otherwise false. */
bool
route_table_get_ifindex(ovs_be32 ip_, int *ifindex)
{
    struct route_node *rn;
    uint32_t ip = ntohl(ip_);

    *ifindex = 0;

    if (!route_table_valid) {
        route_table_reset();
    }

    rn = route_node_lookup_by_ip(ip);

    if (rn) {
        *ifindex = rn->rd.rta_oif;
        return true;
    }

    /* Choose a default route. */
    HMAP_FOR_EACH(rn, node, &route_map) {
        if (rn->rd.rta_dst == 0 && rn->rd.rtm_dst_len == 0) {
            *ifindex = rn->rd.rta_oif;
            return true;
        }
    }

    return false;
}

/* Users of the route_table module should register themselves with this
 * function before making any other route_table function calls. */
void
route_table_register(void)
{
    if (!register_count) {
        assert(!nln);
        assert(!route_notifier);

        nln = nln_create(NETLINK_ROUTE, RTNLGRP_IPV4_ROUTE,
                         (nln_parse_func *) route_table_parse, &rtmsg);

        route_notifier =
            nln_notifier_create(nln, (nln_notify_func *) route_table_change,
                                NULL);

        hmap_init(&route_map);
        route_table_reset();
        name_table_init();
    }

    register_count++;
}

/* Users of the route_table module should unregister themselves with this
 * function when they will no longer be making any more route_table fuction
 * calls. */
void
route_table_unregister(void)
{
    register_count--;

    if (!register_count) {
        nln_notifier_destroy(route_notifier);
        route_notifier = NULL;
        nln_destroy(nln);
        nln = NULL;

        route_map_clear();
        hmap_destroy(&route_map);
        name_table_uninit();
    }
}

/* Run periodically to update the locally maintained routing table. */
void
route_table_run(void)
{
    if (nln) {
        rtnetlink_link_run();
        nln_run(nln);
    }
}

/* Causes poll_block() to wake up when route_table updates are required. */
void
route_table_wait(void)
{
    if (nln) {
        rtnetlink_link_wait();
        nln_wait(nln);
    }
}

static int
route_table_reset(void)
{
    int error;
    struct nl_dump dump;
    struct rtgenmsg *rtmsg;
    struct ofpbuf request, reply;
    static struct nl_sock *rtnl_sock;

    route_map_clear();
    route_table_valid = true;

    error = nl_sock_create(NETLINK_ROUTE, &rtnl_sock);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to reset routing table, "
                     "cannot create RTNETLINK_ROUTE socket");
        return error;
    }

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, sizeof *rtmsg, RTM_GETROUTE, NLM_F_REQUEST);

    rtmsg = ofpbuf_put_zeros(&request, sizeof *rtmsg);
    rtmsg->rtgen_family = AF_INET;

    nl_dump_start(&dump, rtnl_sock, &request);
    ofpbuf_uninit(&request);

    while (nl_dump_next(&dump, &reply)) {
        struct route_table_msg msg;

        if (route_table_parse(&reply, &msg)) {
            route_table_handle_msg(&msg);
        }
    }

    error = nl_dump_done(&dump);
    nl_sock_destroy(rtnl_sock);

    return error;
}


static bool
route_table_parse(struct ofpbuf *buf, struct route_table_msg *change)
{
    bool parsed;

    static const struct nl_policy policy[] = {
        [RTA_DST] = { .type = NL_A_U32, .optional = true  },
        [RTA_OIF] = { .type = NL_A_U32, .optional = false },
    };

    static struct nlattr *attrs[ARRAY_SIZE(policy)];

    parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
                             policy, attrs, ARRAY_SIZE(policy));

    if (parsed) {
        const struct rtmsg *rtm;
        const struct nlmsghdr *nlmsg;

        nlmsg = buf->data;
        rtm = (const struct rtmsg *) ((const char *) buf->data + NLMSG_HDRLEN);

        if (rtm->rtm_family != AF_INET) {
            VLOG_DBG_RL(&rl, "received non AF_INET rtnetlink route message");
            return false;
        }

        memset(change, 0, sizeof *change);
        change->relevant = true;

        if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
            change->relevant = false;
        }

        if (rtm->rtm_type != RTN_UNICAST &&
            rtm->rtm_type != RTN_LOCAL) {
            change->relevant = false;
        }

        change->nlmsg_type     = nlmsg->nlmsg_type;
        change->rd.rtm_dst_len = rtm->rtm_dst_len;
        change->rd.rta_oif     = nl_attr_get_u32(attrs[RTA_OIF]);

        if (attrs[RTA_DST]) {
            change->rd.rta_dst = ntohl(nl_attr_get_be32(attrs[RTA_DST]));
        }

    } else {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink route message");
    }

    return parsed;
}

static void
route_table_change(const struct route_table_msg *change OVS_UNUSED,
                   void *aux OVS_UNUSED)
{
    route_table_valid = false;
}

static void
route_table_handle_msg(const struct route_table_msg *change)
{
    if (change->relevant && change->nlmsg_type == RTM_NEWROUTE &&
        !route_node_lookup(&change->rd)) {
        struct route_node *rn;

        rn = xzalloc(sizeof *rn);
        memcpy(&rn->rd, &change->rd, sizeof change->rd);

        hmap_insert(&route_map, &rn->node, hash_route_data(&rn->rd));
    }
}

static struct route_node *
route_node_lookup(const struct route_data *rd)
{
    struct route_node *rn;

    HMAP_FOR_EACH_WITH_HASH(rn, node, hash_route_data(rd), &route_map) {
        if (!memcmp(&rn->rd, rd, sizeof *rd)) {
            return rn;
        }
    }

    return NULL;
}

static struct route_node *
route_node_lookup_by_ip(uint32_t ip)
{
    int dst_len;
    struct route_node *rn, *rn_ret;

    dst_len = -1;
    rn_ret  = NULL;

    HMAP_FOR_EACH(rn, node, &route_map) {
        uint32_t mask = 0xffffffff << (32 - rn->rd.rtm_dst_len);

        if (rn->rd.rta_dst == 0 && rn->rd.rtm_dst_len == 0) {
            /* Default route. */
            continue;
        }

        if (rn->rd.rtm_dst_len > dst_len &&
            (ip & mask) == (rn->rd.rta_dst & mask)) {
            rn_ret  = rn;
            dst_len = rn->rd.rtm_dst_len;
        }
    }

    return rn_ret;
}

static void
route_map_clear(void)
{
    struct route_node *rn, *rn_next;

    HMAP_FOR_EACH_SAFE(rn, rn_next, node, &route_map) {
        hmap_remove(&route_map, &rn->node);
        free(rn);
    }
}

static uint32_t
hash_route_data(const struct route_data *rd)
{
    return hash_bytes(rd, sizeof *rd, 0);
}

/* name_table . */

static void
name_table_init(void)
{
    hmap_init(&name_map);
    name_notifier = rtnetlink_link_notifier_create(name_table_change, NULL);
    name_table_valid = false;
}

static void
name_table_uninit(void)
{
    rtnetlink_link_notifier_destroy(name_notifier);
    name_notifier = NULL;
    name_map_clear();
    hmap_destroy(&name_map);
}

static int
name_table_reset(void)
{
    int error;
    struct nl_dump dump;
    struct rtgenmsg *rtmsg;
    struct ofpbuf request, reply;
    static struct nl_sock *rtnl_sock;

    name_table_valid = true;
    name_map_clear();
    error = nl_sock_create(NETLINK_ROUTE, &rtnl_sock);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to create NETLINK_ROUTE socket");
        return error;
    }

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, sizeof *rtmsg, RTM_GETLINK, NLM_F_REQUEST);
    rtmsg = ofpbuf_put_zeros(&request, sizeof *rtmsg);
    rtmsg->rtgen_family = AF_INET;

    nl_dump_start(&dump, rtnl_sock, &request);
    ofpbuf_uninit(&request);

    while (nl_dump_next(&dump, &reply)) {
        struct rtnetlink_link_change change;

        if (rtnetlink_link_parse(&reply, &change)
            && change.nlmsg_type == RTM_NEWLINK
            && !name_node_lookup(change.ifi_index)) {
            struct name_node *nn;

            nn = xzalloc(sizeof *nn);
            nn->ifi_index = change.ifi_index;
            ovs_strlcpy(nn->ifname, change.ifname, IFNAMSIZ);
            hmap_insert(&name_map, &nn->node, hash_int(nn->ifi_index, 0));
        }
    }
    nl_sock_destroy(rtnl_sock);
    return nl_dump_done(&dump);
}

static void
name_table_change(const struct rtnetlink_link_change *change OVS_UNUSED,
                  void *aux OVS_UNUSED)
{
    /* Changes to interface status can cause routing table changes that some
     * versions of the linux kernel do not advertise for some reason. */
    route_table_valid = false;
    name_table_valid = false;
}

static struct name_node *
name_node_lookup(int ifi_index)
{
    struct name_node *nn;

    HMAP_FOR_EACH_WITH_HASH(nn, node, hash_int(ifi_index, 0), &name_map) {
        if (nn->ifi_index == ifi_index) {
            return nn;
        }
    }

    return NULL;
}

static void
name_map_clear(void)
{
    struct name_node *nn, *nn_next;

    HMAP_FOR_EACH_SAFE(nn, nn_next, node, &name_map) {
        hmap_remove(&name_map, &nn->node);
        free(nn);
    }
}
