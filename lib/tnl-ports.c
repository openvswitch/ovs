/*
 * Copyright (c) 2014, 2015, 2017 Nicira, Inc.
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

#include "tnl-ports.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "classifier.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "netdev.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "odp-util.h"
#include "ovs-thread.h"
#include "unixctl.h"
#include "util.h"

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct classifier cls;   /* Tunnel ports. */

struct ip_device {
    struct netdev *dev;
    struct eth_addr mac;
    struct in6_addr *addr;
    int n_addr;
    uint64_t change_seq;
    struct ovs_list node;
    char dev_name[IFNAMSIZ];
};

static struct ovs_list addr_list;

struct tnl_port {
    odp_port_t port;
    struct ovs_refcount ref_cnt;
    ovs_be16 tp_port;
    uint8_t nw_proto;
    char dev_name[IFNAMSIZ];
    struct ovs_list node;
};

static struct ovs_list port_list;

struct tnl_port_in {
    struct cls_rule cr;
    odp_port_t portno;
    struct ovs_refcount ref_cnt;
    char dev_name[IFNAMSIZ];
};

static struct tnl_port_in *
tnl_port_cast(const struct cls_rule *cr)
{
    BUILD_ASSERT_DECL(offsetof(struct tnl_port_in, cr) == 0);

    return CONTAINER_OF(cr, struct tnl_port_in, cr);
}

static void
tnl_port_free(struct tnl_port_in *p)
{
    cls_rule_destroy(&p->cr);
    free(p);
}

static void
tnl_port_init_flow(struct flow *flow, struct eth_addr mac,
                   struct in6_addr *addr, uint8_t nw_proto, ovs_be16 tp_port)
{
    memset(flow, 0, sizeof *flow);

    flow->dl_dst = mac;
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        flow->dl_type = htons(ETH_TYPE_IP);
        flow->nw_dst = in6_addr_get_mapped_ipv4(addr);
    } else {
        flow->dl_type = htons(ETH_TYPE_IPV6);
        flow->ipv6_dst = *addr;
    }

    flow->nw_proto = nw_proto;
    flow->tp_dst = tp_port;
}

static void
map_insert(odp_port_t port, struct eth_addr mac, struct in6_addr *addr,
           uint8_t nw_proto, ovs_be16 tp_port, const char dev_name[])
{
    const struct cls_rule *cr;
    struct tnl_port_in *p;
    struct match match;

    memset(&match, 0, sizeof match);
    tnl_port_init_flow(&match.flow, mac, addr, nw_proto, tp_port);

    do {
        cr = classifier_lookup(&cls, OVS_VERSION_MAX, &match.flow, NULL);
        p = tnl_port_cast(cr);
        /* Try again if the rule was released before we get the reference. */
    } while (p && !ovs_refcount_try_ref_rcu(&p->ref_cnt));

    if (!p) {
        p = xzalloc(sizeof *p);
        p->portno = port;

        match.wc.masks.dl_type = OVS_BE16_MAX;
        match.wc.masks.nw_proto = 0xff;
         /* XXX: No fragments support. */
        match.wc.masks.nw_frag = FLOW_NW_FRAG_MASK;

        /* 'tp_port' is zero for GRE tunnels. In this case it
         * doesn't make sense to match on UDP port numbers. */
        if (tp_port) {
            match.wc.masks.tp_dst = OVS_BE16_MAX;
        }
        if (IN6_IS_ADDR_V4MAPPED(addr)) {
            match.wc.masks.nw_dst = OVS_BE32_MAX;
        } else {
            match.wc.masks.ipv6_dst = in6addr_exact;
        }
        match.wc.masks.vlans[0].tci = OVS_BE16_MAX;
        memset(&match.wc.masks.dl_dst, 0xff, sizeof (struct eth_addr));

        cls_rule_init(&p->cr, &match, 0); /* Priority == 0. */
        ovs_refcount_init(&p->ref_cnt);
        ovs_strlcpy(p->dev_name, dev_name, sizeof p->dev_name);

        classifier_insert(&cls, &p->cr, OVS_VERSION_MIN, NULL, 0);
    }
}

static void
map_insert_ipdev__(struct ip_device *ip_dev, char dev_name[],
                   odp_port_t port, uint8_t nw_proto, ovs_be16 tp_port)
{
    if (ip_dev->n_addr) {
        int i;

        for (i = 0; i < ip_dev->n_addr; i++) {
            map_insert(port, ip_dev->mac, &ip_dev->addr[i],
                       nw_proto, tp_port, dev_name);
        }
    }
}

static uint8_t
tnl_type_to_nw_proto(const char type[])
{
    if (!strcmp(type, "geneve")) {
        return IPPROTO_UDP;
    }
    if (!strcmp(type, "stt")) {
        return IPPROTO_TCP;
    }
    if (!strcmp(type, "gre") || !strcmp(type, "erspan") ||
        !strcmp(type, "ip6erspan") || !strcmp(type, "ip6gre")) {
        return IPPROTO_GRE;
    }
    if (!strcmp(type, "vxlan")) {
        return IPPROTO_UDP;
    }
    return 0;
}

void
tnl_port_map_insert(odp_port_t port, ovs_be16 tp_port,
                    const char dev_name[], const char type[])
{
    struct tnl_port *p;
    struct ip_device *ip_dev;
    uint8_t nw_proto;

    nw_proto = tnl_type_to_nw_proto(type);
    if (!nw_proto) {
        return;
    }

    ovs_mutex_lock(&mutex);
    LIST_FOR_EACH(p, node, &port_list) {
        if (p->port == port && p->nw_proto == nw_proto) {
            ovs_refcount_ref(&p->ref_cnt);
            goto out;
        }
    }

    p = xzalloc(sizeof *p);
    p->port = port;
    p->tp_port = tp_port;
    p->nw_proto = nw_proto;
    ovs_strlcpy(p->dev_name, dev_name, sizeof p->dev_name);
    ovs_refcount_init(&p->ref_cnt);
    ovs_list_insert(&port_list, &p->node);

    LIST_FOR_EACH(ip_dev, node, &addr_list) {
        map_insert_ipdev__(ip_dev, p->dev_name, p->port, p->nw_proto, p->tp_port);
    }

out:
    ovs_mutex_unlock(&mutex);
}

static void
tnl_port_unref(const struct cls_rule *cr)
{
    struct tnl_port_in *p = tnl_port_cast(cr);

    if (cr && ovs_refcount_unref_relaxed(&p->ref_cnt) == 1) {
        classifier_remove_assert(&cls, cr);
        ovsrcu_postpone(tnl_port_free, p);
    }
}

static void
map_delete(struct eth_addr mac, struct in6_addr *addr,
           ovs_be16 tp_port, uint8_t nw_proto)
{
    const struct cls_rule *cr;
    struct flow flow;

    tnl_port_init_flow(&flow, mac, addr, nw_proto, tp_port);

    cr = classifier_lookup(&cls, OVS_VERSION_MAX, &flow, NULL);
    tnl_port_unref(cr);
}

static void
ipdev_map_delete(struct ip_device *ip_dev, ovs_be16 tp_port, uint8_t nw_proto)
{
    if (ip_dev->n_addr) {
        int i;

        for (i = 0; i < ip_dev->n_addr; i++) {
            map_delete(ip_dev->mac, &ip_dev->addr[i], tp_port, nw_proto);
        }
    }
}

void
tnl_port_map_delete(odp_port_t port, const char type[])
{
    struct tnl_port *p, *next;
    struct ip_device *ip_dev;
    uint8_t nw_proto;

    nw_proto = tnl_type_to_nw_proto(type);

    ovs_mutex_lock(&mutex);
    LIST_FOR_EACH_SAFE(p, next, node, &port_list) {
        if (p->port == port && p->nw_proto == nw_proto &&
                    ovs_refcount_unref_relaxed(&p->ref_cnt) == 1) {
            ovs_list_remove(&p->node);
            LIST_FOR_EACH(ip_dev, node, &addr_list) {
                ipdev_map_delete(ip_dev, p->tp_port, p->nw_proto);
            }
            free(p);
            break;
        }
    }
    ovs_mutex_unlock(&mutex);
}

/* 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
odp_port_t
tnl_port_map_lookup(struct flow *flow, struct flow_wildcards *wc)
{
    const struct cls_rule *cr = classifier_lookup(&cls, OVS_VERSION_MAX, flow,
                                                  wc);

    return (cr) ? tnl_port_cast(cr)->portno : ODPP_NONE;
}

static void
tnl_port_show_v(struct ds *ds)
{
    const struct tnl_port_in *p;

    CLS_FOR_EACH(p, cr, &cls) {
        struct odputil_keybuf keybuf;
        struct odputil_keybuf maskbuf;
        struct flow flow;
        const struct nlattr *key, *mask;
        size_t key_len, mask_len;
        struct flow_wildcards wc;
        struct ofpbuf buf;
        struct odp_flow_key_parms odp_parms = {
            .flow = &flow,
            .mask = &wc.masks,
        };

        ds_put_format(ds, "%s (%"PRIu32") : ", p->dev_name, p->portno);
        minimask_expand(p->cr.match.mask, &wc);
        miniflow_expand(p->cr.match.flow, &flow);

        /* Key. */
        odp_parms.support.recirc = true;
        ofpbuf_use_stack(&buf, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&odp_parms, &buf);
        key = buf.data;
        key_len = buf.size;

        /* mask*/
        odp_parms.support.recirc = false;
        ofpbuf_use_stack(&buf, &maskbuf, sizeof maskbuf);
        odp_flow_key_from_mask(&odp_parms, &buf);
        mask = buf.data;
        mask_len = buf.size;

        /* build string. */
        odp_flow_format(key, key_len, mask, mask_len, NULL, ds, false);
        ds_put_format(ds, "\n");
    }
}

static void
tnl_port_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_port *p;

    ds_put_format(&ds, "Listening ports:\n");
    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        if (!strcasecmp(argv[1], "-v")) {
            tnl_port_show_v(&ds);
            goto out;
        }
    }

    LIST_FOR_EACH(p, node, &port_list) {
        ds_put_format(&ds, "%s (%"PRIu32") ref_cnt=%u\n", p->dev_name, p->port,
                      ovs_refcount_read(&p->ref_cnt));
    }

out:
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
map_insert_ipdev(struct ip_device *ip_dev)
{
    struct tnl_port *p;

    LIST_FOR_EACH(p, node, &port_list) {
        map_insert_ipdev__(ip_dev, p->dev_name, p->port, p->nw_proto, p->tp_port);
    }
}

static void
insert_ipdev__(struct netdev *dev,
               struct in6_addr *addr, int n_addr)
{
    struct ip_device *ip_dev;
    enum netdev_flags flags;
    int error;

    error = netdev_get_flags(dev, &flags);
    if (error || (flags & NETDEV_LOOPBACK)) {
        goto err;
    }

    ip_dev = xzalloc(sizeof *ip_dev);
    ip_dev->dev = netdev_ref(dev);
    ip_dev->change_seq = netdev_get_change_seq(dev);
    error = netdev_get_etheraddr(ip_dev->dev, &ip_dev->mac);
    if (error) {
        goto err_free_ipdev;
    }
    ip_dev->addr = addr;
    ip_dev->n_addr = n_addr;
    ovs_strlcpy(ip_dev->dev_name, netdev_get_name(dev), sizeof ip_dev->dev_name);
    ovs_list_insert(&addr_list, &ip_dev->node);
    map_insert_ipdev(ip_dev);
    return;

err_free_ipdev:
    netdev_close(ip_dev->dev);
    free(ip_dev);
err:
    free(addr);
}

static void
insert_ipdev(const char dev_name[])
{
    struct in6_addr *addr, *mask;
    struct netdev *dev;
    int error, n_in6;

    error = netdev_open(dev_name, netdev_get_type_from_name(dev_name), &dev);
    if (error) {
        return;
    }

    error = netdev_get_addr_list(dev, &addr, &mask, &n_in6);
    if (error) {
        netdev_close(dev);
        return;
    }
    free(mask);
    insert_ipdev__(dev, addr, n_in6);
    netdev_close(dev);
}

static void
delete_ipdev(struct ip_device *ip_dev)
{
    struct tnl_port *p;

    LIST_FOR_EACH(p, node, &port_list) {
        ipdev_map_delete(ip_dev, p->tp_port, p->nw_proto);
    }

    ovs_list_remove(&ip_dev->node);
    netdev_close(ip_dev->dev);
    free(ip_dev->addr);
    free(ip_dev);
}

void
tnl_port_map_insert_ipdev(const char dev_name[])
{
    struct ip_device *ip_dev, *next;

    ovs_mutex_lock(&mutex);

    LIST_FOR_EACH_SAFE(ip_dev, next, node, &addr_list) {
        if (!strcmp(netdev_get_name(ip_dev->dev), dev_name)) {
            if (ip_dev->change_seq == netdev_get_change_seq(ip_dev->dev)) {
                goto out;
            }
            /* Address changed. */
            delete_ipdev(ip_dev);
        }
    }
    insert_ipdev(dev_name);

out:
    ovs_mutex_unlock(&mutex);
}

void
tnl_port_map_delete_ipdev(const char dev_name[])
{
    struct ip_device *ip_dev, *next;

    ovs_mutex_lock(&mutex);
    LIST_FOR_EACH_SAFE(ip_dev, next, node, &addr_list) {
        if (!strcmp(netdev_get_name(ip_dev->dev), dev_name)) {
            delete_ipdev(ip_dev);
        }
    }
    ovs_mutex_unlock(&mutex);
}

void
tnl_port_map_run(void)
{
    struct ip_device *ip_dev, *next;

    ovs_mutex_lock(&mutex);
    LIST_FOR_EACH_SAFE(ip_dev, next, node, &addr_list) {
        char dev_name[IFNAMSIZ];

        if (ip_dev->change_seq == netdev_get_change_seq(ip_dev->dev)) {
            continue;
        }

        /* Address changed. */
        ovs_strlcpy_arrays(dev_name, ip_dev->dev_name);
        delete_ipdev(ip_dev);
        insert_ipdev(dev_name);
    }
    ovs_mutex_unlock(&mutex);
}

void
tnl_port_map_init(void)
{
    classifier_init(&cls, flow_segment_u64s);
    ovs_list_init(&addr_list);
    ovs_list_init(&port_list);
    unixctl_command_register("tnl/ports/show", "-v", 0, 1, tnl_port_show, NULL);
}
