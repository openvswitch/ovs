/*
 * Copyright (c) 2014, 2015 Nicira, Inc.
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
#include <stddef.h>
#include <stdint.h>

#include "classifier.h"
#include "dynamic-string.h"
#include "hash.h"
#include "ofpbuf.h"
#include "ovs-thread.h"
#include "odp-util.h"
#include "tnl-arp-cache.h"
#include "tnl-ports.h"
#include "ovs-thread.h"
#include "unixctl.h"
#include "util.h"

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct classifier cls;   /* Tunnel ports. */

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
tnl_port_init_flow(struct flow *flow, ovs_be32 ip_dst, ovs_be16 udp_port)
{
    memset(flow, 0, sizeof *flow);
    flow->dl_type = htons(ETH_TYPE_IP);
    if (udp_port) {
        flow->nw_proto = IPPROTO_UDP;
    } else {
        flow->nw_proto = IPPROTO_GRE;
    }
    flow->tp_dst = udp_port;
    /* When matching on incoming flow from remove tnl end point,
     * our dst ip address is source ip for them. */
    flow->nw_src = ip_dst;
}

void
tnl_port_map_insert(odp_port_t port, ovs_be32 ip_dst, ovs_be16 udp_port,
                    const char dev_name[])
{
    const struct cls_rule *cr;
    struct tnl_port_in *p;
    struct match match;

    memset(&match, 0, sizeof match);
    tnl_port_init_flow(&match.flow, ip_dst, udp_port);

    ovs_mutex_lock(&mutex);
    do {
        cr = classifier_lookup(&cls, &match.flow, NULL);
        p = tnl_port_cast(cr);
        /* Try again if the rule was released before we get the reference. */
    } while (p && !ovs_refcount_try_ref_rcu(&p->ref_cnt));

    if (!p) {
        p = xzalloc(sizeof *p);
        p->portno = port;

        match.wc.masks.dl_type = OVS_BE16_MAX;
        match.wc.masks.nw_proto = 0xff;
        match.wc.masks.nw_frag = 0xff;      /* XXX: No fragments support. */
        match.wc.masks.tp_dst = OVS_BE16_MAX;
        match.wc.masks.nw_src = OVS_BE32_MAX;

        cls_rule_init(&p->cr, &match, 0);   /* Priority == 0. */
        ovs_refcount_init(&p->ref_cnt);
        ovs_strlcpy(p->dev_name, dev_name, sizeof p->dev_name);

        classifier_insert(&cls, &p->cr, NULL, 0);
    }
    ovs_mutex_unlock(&mutex);
}

static void
tnl_port_unref(const struct cls_rule *cr)
{
    struct tnl_port_in *p = tnl_port_cast(cr);

    if (cr && ovs_refcount_unref_relaxed(&p->ref_cnt) == 1) {
        ovs_mutex_lock(&mutex);
        if (classifier_remove(&cls, cr)) {
            ovsrcu_postpone(tnl_port_free, p);
        }
        ovs_mutex_unlock(&mutex);
    }
}

void
tnl_port_map_delete(ovs_be32 ip_dst, ovs_be16 udp_port)
{
    const struct cls_rule *cr;
    struct flow flow;

    tnl_port_init_flow(&flow, ip_dst, udp_port);

    cr = classifier_lookup(&cls, &flow, NULL);
    tnl_port_unref(cr);
}

/* 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
odp_port_t
tnl_port_map_lookup(struct flow *flow, struct flow_wildcards *wc)
{
    const struct cls_rule *cr = classifier_lookup(&cls, flow, wc);

    return (cr) ? tnl_port_cast(cr)->portno : ODPP_NONE;
}

static void
tnl_port_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct tnl_port_in *p;

    ds_put_format(&ds, "Listening ports:\n");
    CLS_FOR_EACH(p, cr, &cls) {
        struct odputil_keybuf keybuf;
        struct odputil_keybuf maskbuf;
        struct flow flow;
        const struct nlattr *key, *mask;
        size_t key_len, mask_len;
        struct flow_wildcards wc;
        struct ofpbuf buf;

        ds_put_format(&ds, "%s (%"PRIu32") : ", p->dev_name, p->portno);
        minimask_expand(&p->cr.match.mask, &wc);
        miniflow_expand(&p->cr.match.flow, &flow);

        /* Key. */
        ofpbuf_use_stack(&buf, &keybuf, sizeof keybuf);
        odp_flow_key_from_flow(&buf, &flow, &wc.masks,
                               flow.in_port.odp_port, true);
        key = buf.data;
        key_len = buf.size;
        /* mask*/
        ofpbuf_use_stack(&buf, &maskbuf, sizeof maskbuf);
        odp_flow_key_from_mask(&buf, &wc.masks, &flow,
                               odp_to_u32(wc.masks.in_port.odp_port),
                               SIZE_MAX, false);
        mask = buf.data;
        mask_len = buf.size;

        /* build string. */
        odp_flow_format(key, key_len, mask, mask_len, NULL, &ds, false);
        ds_put_format(&ds, "\n");
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
tnl_port_map_init(void)
{
    classifier_init(&cls, flow_segment_u64s);
    unixctl_command_register("tnl/ports/show", "", 0, 0, tnl_port_show, NULL);
}
