/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
 * Copyright (c) 2019 Samsung Electronics Co.,Ltd.
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

#ifndef NETDEV_OFFLOAD_H
#define NETDEV_OFFLOAD_H 1

#include "openvswitch/netdev.h"
#include "openvswitch/types.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "openvswitch/ofp-meter.h"
#include "packets.h"
#include "flow.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct dp_packet_batch;
struct dp_packet;
struct netdev_class;
struct netdev_rxq;
struct netdev_saved_flags;
struct ofpbuf;
struct in_addr;
struct in6_addr;
struct smap;
struct sset;
struct ovs_action_push_tnl;


/* Offload-capable (HW) netdev information */
struct netdev_hw_info {
    bool oor;                         /* Out of Offload Resources ? */
    atomic_bool miss_api_supported;   /* hw_miss_packet_recover() supported.*/
    int offload_count;                /* Offloaded flow count */
    int pending_count;                /* Pending (non-offloaded) flow count */
    OVSRCU_TYPE(void *) offload_data; /* Offload metadata. */
};

enum hw_info_type {
    HW_INFO_TYPE_OOR = 1,		/* OOR state */
    HW_INFO_TYPE_PEND_COUNT = 2,	/* Pending(non-offloaded) flow count */
    HW_INFO_TYPE_OFFL_COUNT = 3		/* Offloaded flow count */
};

struct netdev_flow_dump {
    struct netdev *netdev;
    odp_port_t port;
    bool terse;
    struct nl_dump *nl_dump;
};

/* Flow offloading. */
struct offload_info {
    bool recirc_id_shared_with_tc;  /* Indicates whever tc chains will be in
                                     * sync with datapath recirc ids. */

    /*
     * The flow mark id assigned to the flow. If any pkts hit the flow,
     * it will be in the pkt meta data.
     */
    uint32_t flow_mark;

    bool tc_modify_flow_deleted; /* Indicate the tc modify flow put success
                                  * to delete the original flow. */
    odp_port_t orig_in_port; /* Originating in_port for tnl flows. */
};

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, netdev_offload_thread_id);

unsigned int netdev_offload_thread_nb(void);
unsigned int netdev_offload_thread_init(void);
unsigned int netdev_offload_ufid_to_thread_id(const ovs_u128 ufid);

static inline unsigned int
netdev_offload_thread_id(void)
{
    unsigned int id = *netdev_offload_thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        id = netdev_offload_thread_init();
    }

    return id;
}

int netdev_flow_dump_create(struct netdev *, struct netdev_flow_dump **dump,
                            bool terse);
int netdev_flow_dump_destroy(struct netdev_flow_dump *);
bool netdev_flow_dump_next(struct netdev_flow_dump *, struct match *,
                          struct nlattr **actions, struct dpif_flow_stats *,
                          struct dpif_flow_attrs *, ovs_u128 *ufid,
                          struct ofpbuf *rbuffer, struct ofpbuf *wbuffer);
int netdev_flow_put(struct netdev *, struct match *, struct nlattr *actions,
                    size_t actions_len, const ovs_u128 *,
                    struct offload_info *, struct dpif_flow_stats *);
int netdev_hw_miss_packet_recover(struct netdev *, struct dp_packet *);
int netdev_flow_get(struct netdev *, struct match *, struct nlattr **actions,
                    const ovs_u128 *, struct dpif_flow_stats *,
                    struct dpif_flow_attrs *, struct ofpbuf *wbuffer);
int netdev_flow_del(struct netdev *, const ovs_u128 *,
                    struct dpif_flow_stats *);
int netdev_init_flow_api(struct netdev *);
void netdev_uninit_flow_api(struct netdev *);
uint32_t netdev_get_block_id(struct netdev *);
int netdev_get_hw_info(struct netdev *, int);
void netdev_set_hw_info(struct netdev *, int, int);
bool netdev_any_oor(void);
void netdev_set_flow_api_enabled(const struct smap *ovs_other_config);

struct dpif_port;
int netdev_ports_insert(struct netdev *, struct dpif_port *);
struct netdev *netdev_ports_get(odp_port_t port, const char *dpif_type);
int netdev_ports_remove(odp_port_t port, const char *dpif_type);
odp_port_t netdev_ifindex_to_odp_port(int ifindex);

/* For each of the ports with dpif_type, call cb with the netdev and port
 * number of the port, and an opaque user argument.
 * The returned value is used to continue traversing upon false or stop if
 * true.
 */
void netdev_ports_traverse(const char *dpif_type,
                           bool (*cb)(struct netdev *, odp_port_t, void *),
                           void *aux);
struct netdev_flow_dump **netdev_ports_flow_dump_create(
                                        const char *dpif_type,
                                        int *ports,
                                        bool terse);
int netdev_ports_flow_del(const char *dpif_type, const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats);
int netdev_ports_flow_get(const char *dpif_type, struct match *match,
                          struct nlattr **actions,
                          const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats,
                          struct dpif_flow_attrs *attrs,
                          struct ofpbuf *buf);

#ifdef  __cplusplus
}
#endif

#endif /* netdev-offload.h */
