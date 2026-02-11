/*
 * Copyright (c) 2024 Canonical Ltd.
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

#undef NDEBUG

#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>

#include "netlink-notifier.h"
#include "ovstest.h"
#include "packets.h"
#include "route-table.h"

/* The following definition should be available in Linux 6.15 and might be
 * missing if we have older headers. */
#ifndef RTPROT_OVN
#define RTPROT_OVN 84
#endif

/* Definition was added in Linux v4.18. */
#ifndef RTPROT_BGP
#define RTPROT_BGP 186
#endif

static char *
rt_prot_name(unsigned char p)
{
    /* We concentrate on the most used protocols, as they are the ones most
     * likely to be defined in the build environment. */
    return p == RTPROT_UNSPEC     ? "RTPROT_UNSPEC"     :
           p == RTPROT_REDIRECT   ? "RTPROT_REDIRECT"   :
           p == RTPROT_KERNEL     ? "RTPROT_KERNEL"     :
           p == RTPROT_BOOT       ? "RTPROT_BOOT"       :
           p == RTPROT_STATIC     ? "RTPROT_STATIC"     :
           p == RTPROT_RA         ? "RTPROT_RA"         :
           p == RTPROT_DHCP       ? "RTPROT_DHCP"       :
           p == RTPROT_OVN        ? "RTPROT_OVN"        :
           p == RTPROT_BGP        ? "RTPROT_BGP"        :
           "UNKNOWN";
}

static char *
rt_table_name(uint32_t id)
{
    static char tid[11] = "";

    snprintf(tid, sizeof tid, "%"PRIu32, id);

    return id == RT_TABLE_UNSPEC  ? "RT_TABLE_UNSPEC"  :
           id == RT_TABLE_COMPAT  ? "RT_TABLE_COMPAT"  :
           id == RT_TABLE_DEFAULT ? "RT_TABLE_DEFAULT" :
           id == RT_TABLE_MAIN    ? "RT_TABLE_MAIN"    :
           id == RT_TABLE_LOCAL   ? "RT_TABLE_LOCAL"   :
           tid;
}

static void
test_lib_route_table_handle_msg(const struct route_table_msg *change,
                                void *data OVS_UNUSED,
                                uint32_t table OVS_UNUSED)
{
    struct ds nexthop_addr = DS_EMPTY_INITIALIZER;
    struct ds rta_prefsrc = DS_EMPTY_INITIALIZER;
    const struct route_data *rd = &change->rd;
    struct ds rta_dst = DS_EMPTY_INITIALIZER;
    const struct route_data_nexthop *rdnh;

    ipv6_format_mapped(&change->rd.rta_prefsrc, &rta_prefsrc);
    ipv6_format_mapped(&change->rd.rta_dst, &rta_dst);

    printf("%s/%u relevant: %d nlmsg_type: %d rtm_protocol: %s (%u) "
           "rtn_local: %d rta_prefsrc: %s rta_mark: %"PRIu32" "
           "rta_table_id: %s rta_priority: %"PRIu32"\n",
           ds_cstr(&rta_dst), rd->rtm_dst_len, change->relevant,
           change->nlmsg_type, rt_prot_name(rd->rtm_protocol),
           rd->rtm_protocol, rd->rtn_local, ds_cstr(&rta_prefsrc),
           rd->rta_mark, rt_table_name(rd->rta_table_id), rd->rta_priority);

    LIST_FOR_EACH (rdnh, nexthop_node, &rd->nexthops) {
        ds_clear(&nexthop_addr);
        ipv6_format_mapped(&rdnh->addr, &nexthop_addr);
        printf("    %s/%u nexthop family: %s addr: %s ifname: %s\n",
               ds_cstr(&rta_dst), rd->rtm_dst_len,
               rdnh->family == AF_INET ? "AF_INET" :
               rdnh->family == AF_INET6 ? "AF_INET6" :
               "UNKNOWN",
               ds_cstr(&nexthop_addr),
               rdnh->ifname);
    }

    ds_destroy(&nexthop_addr);
    ds_destroy(&rta_prefsrc);
    ds_destroy(&rta_dst);
}

static void
test_lib_route_table_dump(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{

    route_table_dump_one_table(RT_TABLE_UNSPEC, AF_INET,
                               test_lib_route_table_handle_msg,
                               NULL);
    route_table_dump_one_table(RT_TABLE_UNSPEC, AF_INET6,
                               test_lib_route_table_handle_msg,
                               NULL);
}

static void
test_lib_route_table_change(struct route_table_msg *change,
                            void *aux OVS_UNUSED)
{
    test_lib_route_table_handle_msg(change, NULL, 0);
    route_data_destroy(&change->rd);
}

static void
test_lib_route_table_monitor(int argc, char *argv[])
{
    static struct nln_notifier *route6_notifier OVS_UNUSED;
    static struct nln_notifier *route_notifier OVS_UNUSED;
    static struct route_table_msg rtmsg;
    static struct nln *nln OVS_UNUSED;
    const char *cmd = argv[1];

    if (argc != 2) {
        printf("usage: ovstest %s 'ip route add ...'\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    nln = nln_create(NETLINK_ROUTE, route_table_parse, &rtmsg);

    route_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
                            (nln_notify_func *) test_lib_route_table_change,
                            NULL);
    route6_notifier =
        nln_notifier_create(nln, RTNLGRP_IPV6_ROUTE,
                            (nln_notify_func *) test_lib_route_table_change,
                            NULL);
    nln_run(nln);
    nln_wait(nln);
    int rc = system(cmd);
    if (rc) {
        exit(rc);
    }
    nln_run(nln);
}

OVSTEST_REGISTER("test-lib-route-table-monitor", test_lib_route_table_monitor);
OVSTEST_REGISTER("test-lib-route-table-dump", test_lib_route_table_dump);
