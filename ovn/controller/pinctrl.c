/* Copyright (c) 2015, 2016, 2017 Red Hat, Inc.
 * Copyright (c) 2017 Nicira, Inc.
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

#include "pinctrl.h"

#include "coverage.h"
#include "csum.h"
#include "dirs.h"
#include "dp-packet.h"
#include "encaps.h"
#include "flow.h"
#include "ha-chassis.h"
#include "lport.h"
#include "nx-match.h"
#include "ovn-controller.h"
#include "latch.h"
#include "lib/packets.h"
#include "lib/sset.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-switch.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/vlog.h"

#include "lib/dhcp.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/lex.h"
#include "ovn/lib/acl-log.h"
#include "ovn/lib/ip-mcast-index.h"
#include "ovn/lib/mcast-group-index.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-util.h"
#include "ovn/logical-fields.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "socket-util.h"
#include "seq.h"
#include "timeval.h"
#include "vswitch-idl.h"
#include "lflow.h"
#include "ip-mcast.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

/* pinctrl module creates a thread - pinctrl_handler to handle
 * the packet-ins from ovs-vswitchd. Some of the OVN actions
 * are translated to OF 'controller' actions. See include/ovn/actions.h
 * for more details.
 *
 * pinctrl_handler thread doesn't access the Southbound IDL object. But
 * some of the OVN actions which gets translated to 'controller'
 * OF action, require data from Southbound DB.  Below are the details
 * on how these actions are implemented.
 *
 * pinctrl_run() function is called by ovn-controller main thread.
 * A Mutex - 'pinctrl_mutex' is used between the pinctrl_handler() thread
 * and pinctrl_run().
 *
 *   - dns_lookup -     In order to do a DNS lookup, this action needs
 *                      to access the 'DNS' table. pinctrl_run() builds a
 *                      local DNS cache - 'dns_cache'. See sync_dns_cache()
 *                      for more details.
 *                      The function 'pinctrl_handle_dns_lookup()' (which is
 *                      called with in the pinctrl_handler thread) looks into
 *                      the local DNS cache to resolve the DNS requests.
 *
 *   - put_arp/put_nd - These actions stores the IPv4/IPv6 and MAC addresses
 *                      in the 'MAC_Binding' table.
 *                      The function 'pinctrl_handle_put_mac_binding()' (which
 *                      is called with in the pinctrl_handler thread), stores
 *                      the IPv4/IPv6 and MAC addresses in the
 *                      hmap - put_mac_bindings.
 *
 *                      pinctrl_run(), reads these mac bindings from the hmap
 *                      'put_mac_bindings' and writes to the 'MAC_Binding'
 *                      table in the Southbound DB.
 *
 *   - arp/nd_ns      - These actions generate an ARP/IPv6 Neighbor solicit
 *                      requests. The original packets are buffered and
 *                      injected back when put_arp/put_nd resolves
 *                      corresponding ARP/IPv6 Neighbor solicit requests.
 *                      When pinctrl_run(), writes the mac bindings from the
 *                      'put_mac_bindings' hmap to the MAC_Binding table in
 *                      SB DB, run_buffered_binding will add the buffered
 *                      packets to buffered_mac_bindings and notify
 *                      pinctrl_handler.
 *
 *                      The pinctrl_handler thread calls the function -
 *                      send_mac_binding_buffered_pkts(), which uses
 *                      the hmap - 'buffered_mac_bindings' and reinjects the
 *                      buffered packets.
 *
 *    - igmp          - This action punts an IGMP packet to the controller
 *                      which maintains multicast group information. The
 *                      multicast groups (mcast_snoop_map) are synced to
 *                      the 'IGMP_Group' table by ip_mcast_sync().
 *                      ip_mcast_sync() also reads the 'IP_Multicast'
 *                      (snooping and querier) configuration and builds a
 *                      local configuration mcast_cfg_map.
 *                      ip_mcast_snoop_run() which runs in the
 *                      pinctrl_handler() thread configures the per datapath
 *                      mcast_snoop_map entries according to mcast_cfg_map.
 *
 * pinctrl module also periodically sends IPv6 Router Solicitation requests
 * and gARPs (for the router gateway IPs and configured NAT addresses).
 *
 * IPv6 RA handling - pinctrl_run() prepares the IPv6 RA information
 *                    (see prepare_ipv6_ras()) in the shash 'ipv6_ras' by
 *                    looking into the Southbound DB table - Port_Binding.
 *
 *                    pinctrl_handler thread sends the periodic IPv6 RAs using
 *                    the shash - 'ipv6_ras'
 *
 * gARP handling    - pinctrl_run() prepares the gARP information
 *                    (see send_garp_prepare()) in the shash 'send_garp_data'
 *                    by looking into the Southbound DB table Port_Binding.
 *
 *                    pinctrl_handler() thread sends these gARPs using the
 *                    shash 'send_garp_data'.
 *
 * IGMP Queries     - pinctrl_run() prepares the IGMP queries (at most one
 *                    per local datapath) based on the mcast_snoop_map
 *                    contents and stores them in mcast_query_list.
 *
 *                    pinctrl_handler thread sends the periodic IGMP queries
 *                    by walking the mcast_query_list.
 *
 * Notification between pinctrl_handler() and pinctrl_run()
 * -------------------------------------------------------
 * 'struct seq' is used for notification between pinctrl_handler() thread
 *  and pinctrl_run().
 *  'pinctrl_handler_seq' is used by pinctrl_run() to
 *  wake up pinctrl_handler thread from poll_block() if any changes happened
 *  in 'send_garp_data', 'ipv6_ras' and 'buffered_mac_bindings' structures.
 *
 *  'pinctrl_main_seq' is used by pinctrl_handler() thread to wake up
 *  the main thread from poll_block() when mac bindings/igmp groups need to
 *  be updated in the Southboubd DB.
 * */

static struct ovs_mutex pinctrl_mutex = OVS_MUTEX_INITIALIZER;
static struct seq *pinctrl_handler_seq;
static struct seq *pinctrl_main_seq;

static void *pinctrl_handler(void *arg);

struct pinctrl {
    char *br_int_name;
    pthread_t pinctrl_thread;
    /* Latch to destroy the 'pinctrl_thread' */
    struct latch pinctrl_thread_exit;
};

static struct pinctrl pinctrl;

static void init_buffered_packets_map(void);
static void destroy_buffered_packets_map(void);
static void
run_buffered_binding(struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                     const struct hmap *local_datapaths)
    OVS_REQUIRES(pinctrl_mutex);

static void pinctrl_handle_put_mac_binding(const struct flow *md,
                                           const struct flow *headers,
                                           bool is_arp)
    OVS_REQUIRES(pinctrl_mutex);
static void init_put_mac_bindings(void);
static void destroy_put_mac_bindings(void);
static void run_put_mac_bindings(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void flush_put_mac_bindings(void);
static void send_mac_binding_buffered_pkts(struct rconn *swconn)
    OVS_REQUIRES(pinctrl_mutex);

static void init_send_garps(void);
static void destroy_send_garps(void);
static void send_garp_wait(long long int send_garp_time);
static void send_garp_prepare(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct ovsrec_bridge *,
    const struct sbrec_chassis *,
    const struct hmap *local_datapaths,
    const struct sset *active_tunnels)
    OVS_REQUIRES(pinctrl_mutex);
static void send_garp_run(struct rconn *swconn, long long int *send_garp_time)
    OVS_REQUIRES(pinctrl_mutex);
static void pinctrl_handle_nd_na(struct rconn *swconn,
                                 const struct flow *ip_flow,
                                 const struct match *md,
                                 struct ofpbuf *userdata,
                                 bool is_router);
static void reload_metadata(struct ofpbuf *ofpacts,
                            const struct match *md);
static void pinctrl_handle_put_nd_ra_opts(
    struct rconn *swconn,
    const struct flow *ip_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation);
static void pinctrl_handle_nd_ns(struct rconn *swconn,
                                 const struct flow *ip_flow,
                                 struct dp_packet *pkt_in,
                                 const struct match *md,
                                 struct ofpbuf *userdata);
static void pinctrl_handle_put_icmp4_frag_mtu(struct rconn *swconn,
                                              const struct flow *in_flow,
                                              struct dp_packet *pkt_in,
                                              struct ofputil_packet_in *pin,
                                              struct ofpbuf *userdata,
                                              struct ofpbuf *continuation);
static void
pinctrl_handle_event(struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_controller_event(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void init_ipv6_ras(void);
static void destroy_ipv6_ras(void);
static void ipv6_ra_wait(long long int send_ipv6_ra_time);
static void prepare_ipv6_ras(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct hmap *local_datapaths)
    OVS_REQUIRES(pinctrl_mutex);
static void send_ipv6_ras(struct rconn *swconn,
                          long long int *send_ipv6_ra_time)
    OVS_REQUIRES(pinctrl_mutex);

static void ip_mcast_snoop_init(void);
static void ip_mcast_snoop_destroy(void);
static void ip_mcast_snoop_run(void)
    OVS_REQUIRES(pinctrl_mutex);
static void ip_mcast_querier_run(struct rconn *swconn,
                                 long long int *query_time);
static void ip_mcast_querier_wait(long long int query_time);
static void ip_mcast_sync(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    const struct sbrec_chassis *chassis,
    const struct hmap *local_datapaths,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    struct ovsdb_idl_index *sbrec_igmp_groups,
    struct ovsdb_idl_index *sbrec_ip_multicast)
    OVS_REQUIRES(pinctrl_mutex);
static void pinctrl_ip_mcast_handle_igmp(
    struct rconn *swconn,
    const struct flow *ip_flow,
    struct dp_packet *pkt_in,
    const struct match *md,
    struct ofpbuf *userdata);

static bool may_inject_pkts(void);

static void init_put_vport_bindings(void);
static void destroy_put_vport_bindings(void);
static void run_put_vport_bindings(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void pinctrl_handle_bind_vport(const struct flow *md,
                                      struct ofpbuf *userdata);

COVERAGE_DEFINE(pinctrl_drop_put_mac_binding);
COVERAGE_DEFINE(pinctrl_drop_buffered_packets_map);
COVERAGE_DEFINE(pinctrl_drop_controller_event);
COVERAGE_DEFINE(pinctrl_drop_put_vport_binding);

struct empty_lb_backends_event {
    struct hmap_node hmap_node;
    long long int timestamp;

    char *vip;
    char *protocol;
    char *load_balancer;
};

static struct hmap event_table[OVN_EVENT_MAX];
static int64_t event_seq_num;

static void
init_event_table(void)
{
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        hmap_init(&event_table[i]);
    }
}

#define EVENT_TIMEOUT   10000
static void
empty_lb_backends_event_gc(bool flush)
{
    struct empty_lb_backends_event *cur_ce, *next_ce;
    long long int now = time_msec();

    HMAP_FOR_EACH_SAFE (cur_ce, next_ce, hmap_node,
                        &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        if ((now < cur_ce->timestamp + EVENT_TIMEOUT) && !flush) {
            continue;
        }

        free(cur_ce->vip);
        free(cur_ce->protocol);
        free(cur_ce->load_balancer);
        hmap_remove(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS],
                    &cur_ce->hmap_node);
        free(cur_ce);
    }
}

static void
event_table_gc(bool flush)
{
    empty_lb_backends_event_gc(flush);
}

static void
event_table_destroy(void)
{
    event_table_gc(true);
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        hmap_destroy(&event_table[i]);
    }
}

static struct empty_lb_backends_event *
pinctrl_find_empty_lb_backends_event(char *vip, char *protocol,
                                     char *load_balancer, uint32_t hash)
{
    struct empty_lb_backends_event *ce;
    HMAP_FOR_EACH_WITH_HASH (ce, hmap_node, hash,
                             &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        if (!strcmp(ce->vip, vip) &&
            !strcmp(ce->protocol, protocol) &&
            !strcmp(ce->load_balancer, load_balancer)) {
            return ce;
        }
    }
    return NULL;
}

static const struct sbrec_controller_event *
empty_lb_backends_lookup(struct empty_lb_backends_event *event,
                         const struct sbrec_controller_event_table *ce_table,
                         const struct sbrec_chassis *chassis)
{
    const struct sbrec_controller_event *sbrec_event;
    const char *event_type = event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS);
    char ref_uuid[UUID_LEN + 1];
    sprintf(ref_uuid, UUID_FMT, UUID_ARGS(&chassis->header_.uuid));

    SBREC_CONTROLLER_EVENT_TABLE_FOR_EACH (sbrec_event, ce_table) {
        if (strcmp(sbrec_event->event_type, event_type)) {
            continue;
        }

        char chassis_uuid[UUID_LEN + 1];
        sprintf(chassis_uuid, UUID_FMT,
                UUID_ARGS(&sbrec_event->chassis->header_.uuid));
        if (strcmp(ref_uuid, chassis_uuid)) {
            continue;
        }

        const char *vip = smap_get(&sbrec_event->event_info, "vip");
        const char *protocol = smap_get(&sbrec_event->event_info, "protocol");
        const char *load_balancer = smap_get(&sbrec_event->event_info,
                                             "load_balancer");

        if (!strcmp(event->vip, vip) &&
            !strcmp(event->protocol, protocol) &&
            !strcmp(event->load_balancer, load_balancer)) {
            return sbrec_event;
        }
    }

    return NULL;
}

static void
controller_event_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sbrec_controller_event_table *ce_table,
                     const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        goto out;
    }

    struct empty_lb_backends_event *empty_lbs;
    HMAP_FOR_EACH (empty_lbs, hmap_node,
                   &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        const struct sbrec_controller_event *event;

        event = empty_lb_backends_lookup(empty_lbs, ce_table, chassis);
        if (!event) {
            struct smap event_info = SMAP_INITIALIZER(&event_info);

            smap_add(&event_info, "vip", empty_lbs->vip);
            smap_add(&event_info, "protocol", empty_lbs->protocol);
            smap_add(&event_info, "load_balancer", empty_lbs->load_balancer);

            event = sbrec_controller_event_insert(ovnsb_idl_txn);
            sbrec_controller_event_set_event_type(event,
                    event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS));
            sbrec_controller_event_set_seq_num(event, ++event_seq_num);
            sbrec_controller_event_set_event_info(event, &event_info);
            sbrec_controller_event_set_chassis(event, chassis);
        }
    }

out:
    event_table_gc(!!ovnsb_idl_txn);
}

void
pinctrl_init(void)
{
    init_put_mac_bindings();
    init_send_garps();
    init_ipv6_ras();
    init_buffered_packets_map();
    init_event_table();
    ip_mcast_snoop_init();
    init_put_vport_bindings();
    pinctrl.br_int_name = NULL;
    pinctrl_handler_seq = seq_create();
    pinctrl_main_seq = seq_create();

    latch_init(&pinctrl.pinctrl_thread_exit);
    pinctrl.pinctrl_thread = ovs_thread_create("ovn_pinctrl", pinctrl_handler,
                                                &pinctrl);
}

static ovs_be32
queue_msg(struct rconn *swconn, struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;

    rconn_send(swconn, msg, NULL);
    return xid;
}

/* Sets up 'swconn', a newly (re)connected connection to a switch. */
static void
pinctrl_setup(struct rconn *swconn)
{
    /* Fetch the switch configuration.  The response later will allow us to
     * change the miss_send_len to UINT16_MAX, so that we can enable
     * asynchronous messages. */
    queue_msg(swconn, ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                                   rconn_get_version(swconn), 0));

    /* Set a packet-in format that supports userdata.  */
    queue_msg(swconn,
              ofputil_encode_set_packet_in_format(rconn_get_version(swconn),
                                                  OFPUTIL_PACKET_IN_NXT2));
}

static void
set_switch_config(struct rconn *swconn,
                  const struct ofputil_switch_config *config)
{
    enum ofp_version version = rconn_get_version(swconn);
    struct ofpbuf *request = ofputil_encode_set_config(config, version);
    queue_msg(swconn, request);
}

static void
set_actions_and_enqueue_msg(struct rconn *swconn,
                            const struct dp_packet *packet,
                            const struct match *md,
                            struct ofpbuf *userdata)
{
    /* Copy metadata from 'md' into the packet-out via "set_field"
     * actions, then add actions from 'userdata'.
     */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);

    reload_metadata(&ofpacts, md);
    enum ofperr error = ofpacts_pull_openflow_actions(userdata, userdata->size,
                                                      version, NULL, NULL,
                                                      &ofpacts);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "failed to parse actions from userdata (%s)",
                     ofperr_to_string(error));
        ofpbuf_uninit(&ofpacts);
        return;
    }

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(packet),
        .packet_len = dp_packet_size(packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    ofpbuf_uninit(&ofpacts);
}

struct buffer_info {
    struct ofpbuf ofpacts;
    struct dp_packet *p;
};

#define BUFFER_QUEUE_DEPTH     4
struct buffered_packets {
    struct hmap_node hmap_node;
    struct ovs_list list;

    /* key */
    struct in6_addr ip;
    struct eth_addr ea;

    long long int timestamp;

    struct buffer_info data[BUFFER_QUEUE_DEPTH];
    uint32_t head, tail;
};

static struct hmap buffered_packets_map;
static struct ovs_list buffered_mac_bindings;

static void
init_buffered_packets_map(void)
{
    hmap_init(&buffered_packets_map);
    ovs_list_init(&buffered_mac_bindings);
}

static void
destroy_buffered_packets(struct buffered_packets *bp)
{
    struct buffer_info *bi;

    while (bp->head != bp->tail) {
        bi = &bp->data[bp->head];
        dp_packet_delete(bi->p);
        ofpbuf_uninit(&bi->ofpacts);

        bp->head = (bp->head + 1) % BUFFER_QUEUE_DEPTH;
    }
}

static void
destroy_buffered_packets_map(void)
{
    struct buffered_packets *bp, *next;
    HMAP_FOR_EACH_SAFE (bp, next, hmap_node, &buffered_packets_map) {
        destroy_buffered_packets(bp);
        hmap_remove(&buffered_packets_map, &bp->hmap_node);
        free(bp);
    }
    hmap_destroy(&buffered_packets_map);

    LIST_FOR_EACH_POP (bp, list, &buffered_mac_bindings) {
        destroy_buffered_packets(bp);
        free(bp);
    }
}

static void
buffered_push_packet(struct buffered_packets *bp,
                     struct dp_packet *packet,
                     const struct match *md)
{
    uint32_t next = (bp->tail + 1) % BUFFER_QUEUE_DEPTH;
    struct buffer_info *bi = &bp->data[bp->tail];

    ofpbuf_init(&bi->ofpacts, 4096);

    reload_metadata(&bi->ofpacts, md);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&bi->ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_REMOTE_OUTPUT;

    bi->p = packet;

    if (next == bp->head) {
        bi = &bp->data[bp->head];
        dp_packet_delete(bi->p);
        ofpbuf_uninit(&bi->ofpacts);
        bp->head = (bp->head + 1) % BUFFER_QUEUE_DEPTH;
    }
    bp->tail = next;
}

static void
buffered_send_packets(struct rconn *swconn, struct buffered_packets *bp,
                      struct eth_addr *addr)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);

    while (bp->head != bp->tail) {
        struct buffer_info *bi = &bp->data[bp->head];
        struct eth_header *eth = dp_packet_data(bi->p);

        eth->eth_dst = *addr;
        struct ofputil_packet_out po = {
            .packet = dp_packet_data(bi->p),
            .packet_len = dp_packet_size(bi->p),
            .buffer_id = UINT32_MAX,
            .ofpacts = bi->ofpacts.data,
            .ofpacts_len = bi->ofpacts.size,
        };
        match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
        queue_msg(swconn, ofputil_encode_packet_out(&po, proto));

        ofpbuf_uninit(&bi->ofpacts);
        dp_packet_delete(bi->p);

        bp->head = (bp->head + 1) % BUFFER_QUEUE_DEPTH;
    }
}

#define BUFFER_MAP_TIMEOUT   10000
static void
buffered_packets_map_gc(void)
{
    struct buffered_packets *cur_qp, *next_qp;
    long long int now = time_msec();

    HMAP_FOR_EACH_SAFE (cur_qp, next_qp, hmap_node, &buffered_packets_map) {
        if (now > cur_qp->timestamp + BUFFER_MAP_TIMEOUT) {
            destroy_buffered_packets(cur_qp);
            hmap_remove(&buffered_packets_map, &cur_qp->hmap_node);
            free(cur_qp);
        }
    }
}

static struct buffered_packets *
pinctrl_find_buffered_packets(const struct in6_addr *ip, uint32_t hash)
{
    struct buffered_packets *qp;

    HMAP_FOR_EACH_WITH_HASH (qp, hmap_node, hash,
                             &buffered_packets_map) {
        if (IN6_ARE_ADDR_EQUAL(&qp->ip, ip)) {
            return qp;
        }
    }
    return NULL;
}

/* Called with in the pinctrl_handler thread context. */
static int
pinctrl_handle_buffered_packets(const struct flow *ip_flow,
                                struct dp_packet *pkt_in,
                                const struct match *md, bool is_arp)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct buffered_packets *bp;
    struct dp_packet *clone;
    struct in6_addr addr;

    if (is_arp) {
        addr = in6_addr_mapped_ipv4(ip_flow->nw_dst);
    } else {
        addr = ip_flow->ipv6_dst;
    }

    uint32_t hash = hash_bytes(&addr, sizeof addr, 0);
    bp = pinctrl_find_buffered_packets(&addr, hash);
    if (!bp) {
        if (hmap_count(&buffered_packets_map) >= 1000) {
            COVERAGE_INC(pinctrl_drop_buffered_packets_map);
            return -ENOMEM;
        }

        bp = xmalloc(sizeof *bp);
        hmap_insert(&buffered_packets_map, &bp->hmap_node, hash);
        bp->head = bp->tail = 0;
        bp->ip = addr;
    }
    bp->timestamp = time_msec();
    /* clone the packet to send it later with correct L2 address */
    clone = dp_packet_clone_data(dp_packet_data(pkt_in),
                                 dp_packet_size(pkt_in));
    buffered_push_packet(bp, clone, md);

    return 0;
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_arp(struct rconn *swconn, const struct flow *ip_flow,
                   struct dp_packet *pkt_in,
                   const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "ARP action on non-IP packet (Ethertype %"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_handle_buffered_packets(ip_flow, pkt_in, md, true);
    ovs_mutex_unlock(&pinctrl_mutex);

    /* Compose an ARP packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_arp__(&packet);

    struct eth_header *eth = dp_packet_eth(&packet);
    eth->eth_dst = ip_flow->dl_dst;
    eth->eth_src = ip_flow->dl_src;

    struct arp_eth_header *arp = dp_packet_l3(&packet);
    arp->ar_op = htons(ARP_OP_REQUEST);
    arp->ar_sha = ip_flow->dl_src;
    put_16aligned_be32(&arp->ar_spa, ip_flow->nw_src);
    arp->ar_tha = eth_addr_zero;
    put_16aligned_be32(&arp->ar_tpa, ip_flow->nw_dst);

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_icmp(struct rconn *swconn, const struct flow *ip_flow,
                    struct dp_packet *pkt_in,
                    const struct match *md, struct ofpbuf *userdata,
                    bool include_orig_ip_datagram)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP) &&
        ip_flow->dl_type != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "ICMP action on non-IP packet (eth_type 0x%"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    dp_packet_clear(&packet);
    packet.packet_type = htonl(PT_ETH);

    struct eth_header *eh = dp_packet_put_zeros(&packet, sizeof *eh);
    eh->eth_dst = ip_flow->dl_dst;
    eh->eth_src = ip_flow->dl_src;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IP)) {
        struct ip_header *in_ip = dp_packet_l3(pkt_in);
        uint16_t in_ip_len = ntohs(in_ip->ip_tot_len);
        if (in_ip_len < IP_HEADER_LEN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl,
                        "ICMP action on IP packet with invalid length (%u)",
                        in_ip_len);
            return;
        }

        struct ip_header *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IP);
        dp_packet_set_l3(&packet, nh);
        nh->ip_ihl_ver = IP_IHL_VER(5, 4);
        nh->ip_tot_len = htons(sizeof(struct ip_header) +
                               sizeof(struct icmp_header));
        nh->ip_proto = IPPROTO_ICMP;
        nh->ip_frag_off = htons(IP_DF);
        packet_set_ipv4(&packet, ip_flow->nw_src, ip_flow->nw_dst,
                        ip_flow->nw_tos, 255);

        struct icmp_header *ih = dp_packet_put_zeros(&packet, sizeof *ih);
        dp_packet_set_l4(&packet, ih);
        packet_set_icmp(&packet, ICMP4_DST_UNREACH, 1);

        if (include_orig_ip_datagram) {
            /* RFC 1122: 3.2.2	MUST send at least the IP header and 8 bytes
             * of header. MAY send more.
             * RFC says return as much as we can without exceeding 576
             * bytes.
             * So, lets return as much as we can. */

            /* Calculate available room to include the original IP + data. */
            nh = dp_packet_l3(&packet);
            uint16_t room = 576 - (sizeof *eh + ntohs(nh->ip_tot_len));
            if (in_ip_len > room) {
                in_ip_len = room;
            }
            dp_packet_put(&packet, in_ip, in_ip_len);

            /* dp_packet_put may reallocate the buffer. Get the l3 and l4
             * header pointers again. */
            nh = dp_packet_l3(&packet);
            ih = dp_packet_l4(&packet);
            uint16_t ip_total_len = ntohs(nh->ip_tot_len) + in_ip_len;
            nh->ip_tot_len = htons(ip_total_len);
            ih->icmp_csum = 0;
            ih->icmp_csum = csum(ih, sizeof *ih + in_ip_len);
            nh->ip_csum = 0;
            nh->ip_csum = csum(nh, sizeof *nh);
        }
    } else {
        struct ip6_hdr *nh = dp_packet_put_zeros(&packet, sizeof *nh);
        struct icmp6_data_header *ih;
        uint32_t icmpv6_csum;

        eh->eth_type = htons(ETH_TYPE_IPV6);
        dp_packet_set_l3(&packet, nh);
        nh->ip6_vfc = 0x60;
        nh->ip6_nxt = IPPROTO_ICMPV6;
        nh->ip6_plen = htons(sizeof(*nh) + ICMP6_DATA_HEADER_LEN);
        packet_set_ipv6(&packet, &ip_flow->ipv6_src, &ip_flow->ipv6_dst,
                        ip_flow->nw_tos, ip_flow->ipv6_label, 255);

        ih = dp_packet_put_zeros(&packet, sizeof *ih);
        dp_packet_set_l4(&packet, ih);
        ih->icmp6_base.icmp6_type = ICMP6_DST_UNREACH;
        ih->icmp6_base.icmp6_code = 1;
        ih->icmp6_base.icmp6_cksum = 0;

        uint8_t *data = dp_packet_put_zeros(&packet, sizeof *nh);
        memcpy(data, dp_packet_l3(pkt_in), sizeof(*nh));

        icmpv6_csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
        ih->icmp6_base.icmp6_cksum = csum_finish(
            csum_continue(icmpv6_csum, ih,
                          sizeof(*nh) + ICMP6_DATA_HEADER_LEN));
    }

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_tcp_reset(struct rconn *swconn, const struct flow *ip_flow,
                         struct dp_packet *pkt_in,
                         const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for TCP segments, and the switch should only send
     * us TCP segments this way, but check here just to be sure. */
    if (ip_flow->nw_proto != IPPROTO_TCP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "TCP_RESET action on non-TCP packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    dp_packet_clear(&packet);
    packet.packet_type = htonl(PT_ETH);

    struct eth_header *eh = dp_packet_put_zeros(&packet, sizeof *eh);
    eh->eth_dst = ip_flow->dl_dst;
    eh->eth_src = ip_flow->dl_src;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IPV6)) {
        struct ip6_hdr *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IPV6);
        dp_packet_set_l3(&packet, nh);
        nh->ip6_vfc = 0x60;
        nh->ip6_nxt = IPPROTO_TCP;
        nh->ip6_plen = htons(TCP_HEADER_LEN);
        packet_set_ipv6(&packet, &ip_flow->ipv6_src, &ip_flow->ipv6_dst,
                        ip_flow->nw_tos, ip_flow->ipv6_label, 255);
    } else {
        struct ip_header *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IP);
        dp_packet_set_l3(&packet, nh);
        nh->ip_ihl_ver = IP_IHL_VER(5, 4);
        nh->ip_tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
        nh->ip_proto = IPPROTO_TCP;
        nh->ip_frag_off = htons(IP_DF);
        packet_set_ipv4(&packet, ip_flow->nw_src, ip_flow->nw_dst,
                        ip_flow->nw_tos, 255);
    }

    struct tcp_header *th = dp_packet_put_zeros(&packet, sizeof *th);
    struct tcp_header *tcp_in = dp_packet_l4(pkt_in);
    dp_packet_set_l4(&packet, th);
    th->tcp_ctl = TCP_CTL(TCP_RST, 5);
    if (ip_flow->tcp_flags & htons(TCP_ACK)) {
        th->tcp_seq = tcp_in->tcp_ack;
    } else {
        uint32_t tcp_seq, ack_seq, tcp_len;

        tcp_seq = ntohl(get_16aligned_be32(&tcp_in->tcp_seq));
        tcp_len = TCP_OFFSET(tcp_in->tcp_ctl) * 4;
        ack_seq = tcp_seq + dp_packet_l4_size(pkt_in) - tcp_len;
        put_16aligned_be32(&th->tcp_ack, htonl(ack_seq));
        put_16aligned_be32(&th->tcp_seq, 0);
    }
    packet_set_tcp_port(&packet, ip_flow->tp_dst, ip_flow->tp_src);

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_dhcp_opts(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Parse result offset and offer IP. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    ovs_be32 *offer_ip = ofpbuf_try_pull(userdata, sizeof *offer_ip);
    if (!ofsp || !offer_ip) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "offset or offer_ip not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP options not present in the userdata");
        goto exit;
    }

    /* Validate the DHCP request packet.
     * Format of the DHCP packet is
     * ------------------------------------------------------------------------
     *| UDP HEADER  | DHCP HEADER  | 4 Byte DHCP Cookie | DHCP OPTIONS(var len)|
     * ------------------------------------------------------------------------
     */

    const char *end = (char *)dp_packet_l4(pkt_in) + dp_packet_l4_size(pkt_in);
    const char *in_dhcp_ptr = dp_packet_get_udp_payload(pkt_in);
    if (!in_dhcp_ptr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid or incomplete DHCP packet received");
        goto exit;
    }

    const struct dhcp_header *in_dhcp_data
        = (const struct dhcp_header *) in_dhcp_ptr;
    in_dhcp_ptr += sizeof *in_dhcp_data;
    if (in_dhcp_ptr > end) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid or incomplete DHCP packet received, "
                     "bad data length");
        goto exit;
    }
    if (in_dhcp_data->op != DHCP_OP_REQUEST) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid opcode in the DHCP packet: %d",
                     in_dhcp_data->op);
        goto exit;
    }

    /* DHCP options follow the DHCP header. The first 4 bytes of the DHCP
     * options is the DHCP magic cookie followed by the actual DHCP options.
     */
    ovs_be32 magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    if (in_dhcp_ptr + sizeof magic_cookie > end ||
        get_unaligned_be32((const void *) in_dhcp_ptr) != magic_cookie) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP magic cookie not present in the DHCP packet");
        goto exit;
    }
    in_dhcp_ptr += sizeof magic_cookie;

    const uint8_t *in_dhcp_msg_type = NULL;
    ovs_be32 request_ip = in_dhcp_data->ciaddr;
    while (in_dhcp_ptr < end) {
        const struct dhcp_opt_header *in_dhcp_opt =
            (const struct dhcp_opt_header *)in_dhcp_ptr;
        if (in_dhcp_opt->code == DHCP_OPT_END) {
            break;
        }
        if (in_dhcp_opt->code == DHCP_OPT_PAD) {
            in_dhcp_ptr += 1;
            continue;
        }
        in_dhcp_ptr += sizeof *in_dhcp_opt;
        if (in_dhcp_ptr > end) {
            break;
        }
        in_dhcp_ptr += in_dhcp_opt->len;
        if (in_dhcp_ptr > end) {
            break;
        }

        switch (in_dhcp_opt->code) {
        case DHCP_OPT_MSG_TYPE:
            if (in_dhcp_opt->len == 1) {
                in_dhcp_msg_type = DHCP_OPT_PAYLOAD(in_dhcp_opt);
            }
            break;
        case DHCP_OPT_REQ_IP:
            if (in_dhcp_opt->len == 4) {
                request_ip = get_unaligned_be32(DHCP_OPT_PAYLOAD(in_dhcp_opt));
            }
            break;
        default:
            break;
        }
    }

    /* Check that the DHCP Message Type (opt 53) is present or not with
     * valid values - DHCP_MSG_DISCOVER or DHCP_MSG_REQUEST.
     */
    if (!in_dhcp_msg_type) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Missing DHCP message type");
        goto exit;
    }
    if (*in_dhcp_msg_type != DHCP_MSG_DISCOVER &&
        *in_dhcp_msg_type != DHCP_MSG_REQUEST) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid DHCP message type: %d", *in_dhcp_msg_type);
        goto exit;
    }

    uint8_t msg_type;
    if (*in_dhcp_msg_type == DHCP_MSG_DISCOVER) {
        msg_type = DHCP_MSG_OFFER;
    } else {
        /* This is a DHCPREQUEST. If the client has requested an IP that
         * does not match the offered IP address, reply with a NAK. The
         * requested IP address may be supplied either via Requested IP Address
         * (opt 50) or via ciaddr, depending on the client's state.
         */
        msg_type = DHCP_MSG_ACK;
        if (request_ip != *offer_ip) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "DHCPREQUEST requested IP "IP_FMT" does not "
                         "match offer "IP_FMT, IP_ARGS(request_ip),
                         IP_ARGS(*offer_ip));
            msg_type = DHCP_MSG_NAK;
        }
    }

    /* Frame the DHCP reply packet
     * Total DHCP options length will be options stored in the userdata +
     * 16 bytes. Note that the DHCP options stored in userdata are not included
     * in DHCPNAK messages.
     *
     * --------------------------------------------------------------
     *| 4 Bytes (dhcp cookie) | 3 Bytes (option type) | DHCP options |
     * --------------------------------------------------------------
     *| 4 Bytes padding | 1 Byte (option end 0xFF ) | 4 Bytes padding|
     * --------------------------------------------------------------
     */
    uint16_t new_l4_size = UDP_HEADER_LEN + DHCP_HEADER_LEN + 16;
    if (msg_type != DHCP_MSG_NAK) {
        new_l4_size += userdata->size;
    }
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    struct dhcp_header *dhcp_data = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, DHCP_HEADER_LEN), DHCP_HEADER_LEN);
    dhcp_data->op = DHCP_OP_REPLY;
    dhcp_data->yiaddr = (msg_type == DHCP_MSG_NAK) ? 0 : *offer_ip;
    dp_packet_put(&pkt_out, &magic_cookie, sizeof(ovs_be32));

    uint16_t out_dhcp_opts_size = 12;
    if (msg_type != DHCP_MSG_NAK) {
      out_dhcp_opts_size += userdata->size;
    }
    uint8_t *out_dhcp_opts = dp_packet_put_zeros(&pkt_out,
                                                 out_dhcp_opts_size);
    /* DHCP option - type */
    out_dhcp_opts[0] = DHCP_OPT_MSG_TYPE;
    out_dhcp_opts[1] = 1;
    out_dhcp_opts[2] = msg_type;
    out_dhcp_opts += 3;

    if (msg_type != DHCP_MSG_NAK) {
      memcpy(out_dhcp_opts, userdata->data, userdata->size);
      out_dhcp_opts += userdata->size;
    }

    /* Padding */
    out_dhcp_opts += 4;
    /* End */
    out_dhcp_opts[0] = DHCP_OPT_END;

    udp->udp_len = htons(new_l4_size);

    struct ip_header *out_ip = dp_packet_l3(&pkt_out);
    out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs + new_l4_size);
    udp->udp_csum = 0;
    /* Checksum needs to be initialized to zero. */
    out_ip->ip_csum = 0;
    out_ip->ip_csum = csum(out_ip, sizeof *out_ip);

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    /* Log the response. */
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
    const struct eth_header *l2 = dp_packet_eth(&pkt_out);
    VLOG_INFO_RL(&rl, "DHCP%s "ETH_ADDR_FMT" "IP_FMT"",
                 msg_type == DHCP_MSG_OFFER ? "OFFER" :
                   (msg_type == DHCP_MSG_ACK ? "ACK": "NAK"),
                 ETH_ADDR_ARGS(l2->eth_src), IP_ARGS(*offer_ip));

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    if (pkt_out_ptr) {
        dp_packet_uninit(pkt_out_ptr);
    }
}

static bool
compose_out_dhcpv6_opts(struct ofpbuf *userdata,
                        struct ofpbuf *out_dhcpv6_opts, ovs_be32 iaid)
{
    while (userdata->size) {
        struct dhcp_opt6_header *userdata_opt = ofpbuf_try_pull(
            userdata, sizeof *userdata_opt);
        if (!userdata_opt) {
            return false;
        }

        size_t size = ntohs(userdata_opt->size);
        uint8_t *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }

        switch (ntohs(userdata_opt->opt_code)) {
        case DHCPV6_OPT_SERVER_ID_CODE:
        {
            /* The Server Identifier option carries a DUID
             * identifying a server between a client and a server.
             * See RFC 3315 Sec 9 and Sec 22.3.
             *
             * We use DUID Based on Link-layer Address [DUID-LL].
             */

            struct dhcpv6_opt_server_id *opt_server_id = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_server_id);

            opt_server_id->opt.code = htons(DHCPV6_OPT_SERVER_ID_CODE);
            opt_server_id->opt.len = htons(size + 4);
            opt_server_id->duid_type = htons(DHCPV6_DUID_LL);
            opt_server_id->hw_type = htons(DHCPV6_HW_TYPE_ETH);
            memcpy(&opt_server_id->mac, userdata_opt_data,
                    sizeof(struct eth_addr));
            break;
        }

        case DHCPV6_OPT_IA_ADDR_CODE:
        {
            if (size != sizeof(struct in6_addr)) {
                return false;
            }

            if (!iaid) {
                /* If iaid is None, it means its an DHCPv6 information request.
                 * Don't put IA_NA option in the response. */
                 break;
            }
            /* IA Address option is used to specify IPv6 addresses associated
             * with an IA_NA or IA_TA. The IA Address option must be
             * encapsulated in the Options field of an IA_NA or IA_TA option.
             *
             * We will encapsulate the IA Address within the IA_NA option.
             * Please see RFC 3315 section 22.5 and 22.6
             */
            struct dhcpv6_opt_ia_na *opt_ia_na = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_na);
            opt_ia_na->opt.code = htons(DHCPV6_OPT_IA_NA_CODE);
            /* IA_NA length (in bytes)-
             *  IAID - 4
             *  T1   - 4
             *  T2   - 4
             *  IA Address - sizeof(struct dhcpv6_opt_ia_addr)
             */
            opt_ia_na->opt.len = htons(12 + sizeof(struct dhcpv6_opt_ia_addr));
            opt_ia_na->iaid = iaid;
            /* Set the lifetime of the address(es) to infinity */
            opt_ia_na->t1 = OVS_BE32_MAX;
            opt_ia_na->t2 = OVS_BE32_MAX;

            struct dhcpv6_opt_ia_addr *opt_ia_addr = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_addr);
            opt_ia_addr->opt.code = htons(DHCPV6_OPT_IA_ADDR_CODE);
            opt_ia_addr->opt.len = htons(size + 8);
            memcpy(opt_ia_addr->ipv6.s6_addr, userdata_opt_data, size);
            opt_ia_addr->t1 = OVS_BE32_MAX;
            opt_ia_addr->t2 = OVS_BE32_MAX;
            break;
        }

        case DHCPV6_OPT_DNS_SERVER_CODE:
        {
            struct dhcpv6_opt_header *opt_dns = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dns);
            opt_dns->code = htons(DHCPV6_OPT_DNS_SERVER_CODE);
            opt_dns->len = htons(size);
            ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            break;
        }

        case DHCPV6_OPT_DOMAIN_SEARCH_CODE:
        {
            struct dhcpv6_opt_header *opt_dsl = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dsl);
            opt_dsl->code = htons(DHCPV6_OPT_DOMAIN_SEARCH_CODE);
            opt_dsl->len = htons(size + 2);
            uint8_t *data = ofpbuf_put_zeros(out_dhcpv6_opts, size + 2);
            *data = size;
            memcpy(data + 1, userdata_opt_data, size);
            break;
        }

        default:
            return false;
        }
    }
    return true;
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_dhcpv6_opts(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation OVS_UNUSED)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "DHCPv6 options not present in the userdata");
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    const uint8_t *in_dhcpv6_data = dp_packet_get_udp_payload(pkt_in);
    if (!in_udp || !in_dhcpv6_data) {
        VLOG_WARN_RL(&rl, "truncated dhcpv6 packet");
        goto exit;
    }

    uint8_t out_dhcpv6_msg_type;
    uint8_t in_dhcpv6_msg_type = *in_dhcpv6_data;
    switch (in_dhcpv6_msg_type) {
    case DHCPV6_MSG_TYPE_SOLICIT:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_ADVT;
        break;

    case DHCPV6_MSG_TYPE_REQUEST:
    case DHCPV6_MSG_TYPE_CONFIRM:
    case DHCPV6_MSG_TYPE_DECLINE:
    case DHCPV6_MSG_TYPE_INFO_REQ:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_REPLY;
        break;

    default:
        /* Invalid or unsupported DHCPv6 message type */
        goto exit;
    }

    /* Skip 4 bytes (message type (1 byte) + transaction ID (3 bytes). */
    in_dhcpv6_data += 4;
    /* We need to extract IAID from the IA-NA option of the client's DHCPv6
     * solicit/request/confirm packet and copy the same IAID in the Server's
     * response.
     * DHCPv6 information packet (for stateless request will not have IA-NA
     * option. So we don't need to copy that in the Server's response.
     * */
    ovs_be32 iaid = 0;
    struct dhcpv6_opt_header const *in_opt_client_id = NULL;
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    while (in_dhcpv6_data < end) {
        struct dhcpv6_opt_header const *in_opt =
             (struct dhcpv6_opt_header *)in_dhcpv6_data;
        switch(ntohs(in_opt->code)) {
        case DHCPV6_OPT_IA_NA_CODE:
        {
            struct dhcpv6_opt_ia_na *opt_ia_na = (
                struct dhcpv6_opt_ia_na *)in_opt;
            iaid = opt_ia_na->iaid;
            break;
        }

        case DHCPV6_OPT_CLIENT_ID_CODE:
            in_opt_client_id = in_opt;
            break;

        default:
            break;
        }
        in_dhcpv6_data += sizeof *in_opt + ntohs(in_opt->len);
    }

    if (!in_opt_client_id) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - Client id not present in the "
                     "DHCPv6 packet");
        goto exit;
    }

    if (!iaid && in_dhcpv6_msg_type != DHCPV6_MSG_TYPE_INFO_REQ) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - IA NA not present in the "
                     "DHCPv6 packet");
        goto exit;
    }

    uint64_t out_ofpacts_dhcpv6_opts_stub[256 / 8];
    struct ofpbuf out_dhcpv6_opts =
        OFPBUF_STUB_INITIALIZER(out_ofpacts_dhcpv6_opts_stub);

    if (!compose_out_dhcpv6_opts(userdata, &out_dhcpv6_opts, iaid)) {
        VLOG_WARN_RL(&rl, "Invalid userdata");
        goto exit;
    }

    uint16_t new_l4_size
        = (UDP_HEADER_LEN + 4 + sizeof *in_opt_client_id +
           ntohs(in_opt_client_id->len) + out_dhcpv6_opts.size);
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Pull the DHCPv6 message type and transaction id from the pkt_in.
     * Need to preserve the transaction id in the DHCPv6 reply packet. */
    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);
    uint8_t *out_dhcpv6 = dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, 4), 4);

    /* Set the proper DHCPv6 message type. */
    *out_dhcpv6 = out_dhcpv6_msg_type;

    /* Copy the Client Identifier. */
    dp_packet_put(&pkt_out, in_opt_client_id,
                  sizeof *in_opt_client_id + ntohs(in_opt_client_id->len));

    /* Copy the DHCPv6 Options. */
    dp_packet_put(&pkt_out, out_dhcpv6_opts.data, out_dhcpv6_opts.size);
    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct ovs_16aligned_ip6_hdr *out_ip6 = dp_packet_l3(&pkt_out);
    out_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = out_udp->udp_len;

    uint32_t csum;
    csum = packet_csum_pseudoheader6(dp_packet_l3(&pkt_out));
    csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                         ((const unsigned char *)out_udp -
                         (const unsigned char *)dp_packet_eth(&pkt_out)));
    out_udp->udp_csum = csum_finish(csum);
    if (!out_udp->udp_csum) {
        out_udp->udp_csum = htons(0xffff);
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    ofpbuf_uninit(&out_dhcpv6_opts);
    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

static void
put_be16(struct ofpbuf *buf, ovs_be16 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

static void
put_be32(struct ofpbuf *buf, ovs_be32 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

struct dns_data {
    uint64_t *dps;
    size_t n_dps;
    struct smap records;
    bool delete;
};

static struct shash dns_cache = SHASH_INITIALIZER(&dns_cache);

/* Called by pinctrl_run(). Runs within the main ovn-controller
 * thread context. */
static void
sync_dns_cache(const struct sbrec_dns_table *dns_table)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        d->delete = true;
    }

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH (sbrec_dns, dns_table) {
        const char *dns_id = smap_get(&sbrec_dns->external_ids, "dns_id");
        if (!dns_id) {
            continue;
        }

        struct dns_data *dns_data = shash_find_data(&dns_cache, dns_id);
        if (!dns_data) {
            dns_data = xmalloc(sizeof *dns_data);
            smap_init(&dns_data->records);
            shash_add(&dns_cache, dns_id, dns_data);
            dns_data->n_dps = 0;
            dns_data->dps = NULL;
        } else {
            free(dns_data->dps);
        }

        dns_data->delete = false;

        if (!smap_equal(&dns_data->records, &sbrec_dns->records)) {
            smap_clear(&dns_data->records);
            smap_clone(&dns_data->records, &sbrec_dns->records);
        }

        dns_data->n_dps = sbrec_dns->n_datapaths;
        dns_data->dps = xcalloc(dns_data->n_dps, sizeof(uint64_t));
        for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
            dns_data->dps[i] = sbrec_dns->datapaths[i]->tunnel_key;
        }
    }

    struct shash_node *next;
    SHASH_FOR_EACH_SAFE (iter, next, &dns_cache) {
        struct dns_data *d = iter->data;
        if (d->delete) {
            shash_delete(&dns_cache, iter);
            free(d);
        }
    }
}

static void
destroy_dns_cache(void)
{
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &dns_cache) {
        struct dns_data *d = iter->data;
        shash_delete(&dns_cache, iter);
        free(d);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_dns_lookup(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation)
    OVS_REQUIRES(pinctrl_mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Check that the packet stores at least the minimal headers. */
    if (dp_packet_l4_size(pkt_in) < (UDP_HEADER_LEN + DNS_HEADER_LEN)) {
        VLOG_WARN_RL(&rl, "truncated dns packet");
        goto exit;
    }

    /* Extract the DNS header */
    struct dns_header const *in_dns_header = dp_packet_get_udp_payload(pkt_in);
    if (!in_dns_header) {
        VLOG_WARN_RL(&rl, "truncated dns packet");
        goto exit;
    }

    /* Check if it is DNS request or not */
    if (in_dns_header->lo_flag & 0x80) {
        /* It's a DNS response packet which we are not interested in */
        goto exit;
    }

    /* Check if at least one query request is present */
    if (!in_dns_header->qdcount) {
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    uint8_t *in_dns_data = (uint8_t *)(in_dns_header + 1);
    uint8_t *in_queryname = in_dns_data;
    uint16_t idx = 0;
    struct ds query_name;
    ds_init(&query_name);
    /* Extract the query_name. If the query name is - 'www.ovn.org' it would be
     * encoded as (in hex) - 03 77 77 77 03 6f 76 63 03 6f 72 67 00.
     */
    while ((in_dns_data + idx) < end && in_dns_data[idx]) {
        uint8_t label_len = in_dns_data[idx++];
        if (in_dns_data + idx + label_len > end) {
            ds_destroy(&query_name);
            goto exit;
        }
        ds_put_buffer(&query_name, (const char *) in_dns_data + idx, label_len);
        idx += label_len;
        ds_put_char(&query_name, '.');
    }

    idx++;
    ds_chomp(&query_name, '.');
    in_dns_data += idx;

    /* Query should have TYPE and CLASS fields */
    if (in_dns_data + (2 * sizeof(ovs_be16)) > end) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint16_t query_type = ntohs(*ALIGNED_CAST(const ovs_be16 *, in_dns_data));
    /* Supported query types - A, AAAA and ANY */
    if (!(query_type == DNS_QUERY_TYPE_A || query_type == DNS_QUERY_TYPE_AAAA
          || query_type == DNS_QUERY_TYPE_ANY)) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint64_t dp_key = ntohll(pin->flow_metadata.flow.metadata);
    const char *answer_ips = NULL;
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        for (size_t i = 0; i < d->n_dps; i++) {
            if (d->dps[i] == dp_key) {
                answer_ips = smap_get(&d->records, ds_cstr(&query_name));
                if (answer_ips) {
                    break;
                }
            }
        }

        if (answer_ips) {
            break;
        }
    }

    ds_destroy(&query_name);
    if (!answer_ips) {
        goto exit;
    }

    struct lport_addresses ip_addrs;
    if (!extract_ip_addresses(answer_ips, &ip_addrs)) {
        goto exit;
    }

    uint16_t ancount = 0;
    uint64_t dns_ans_stub[128 / 8];
    struct ofpbuf dns_answer = OFPBUF_STUB_INITIALIZER(dns_ans_stub);

    if (query_type == DNS_QUERY_TYPE_A || query_type == DNS_QUERY_TYPE_ANY) {
        for (size_t i = 0; i < ip_addrs.n_ipv4_addrs; i++) {
            /* Copy the answer section */
            /* Format of the answer section is
             *  - NAME     -> The domain name
             *  - TYPE     -> 2 octets containing one of the RR type codes
             *  - CLASS    -> 2 octets which specify the class of the data
             *                in the RDATA field.
             *  - TTL      -> 32 bit unsigned int specifying the time
             *                interval (in secs) that the resource record
             *                 may be cached before it should be discarded.
             *  - RDLENGTH -> 16 bit integer specifying the length of the
             *                RDATA field.
             *  - RDATA    -> a variable length string of octets that
             *                describes the resource. In our case it will
             *                be IP address of the domain name.
             */
            ofpbuf_put(&dns_answer, in_queryname, idx);
            put_be16(&dns_answer, htons(DNS_QUERY_TYPE_A));
            put_be16(&dns_answer, htons(DNS_CLASS_IN));
            put_be32(&dns_answer, htonl(DNS_DEFAULT_RR_TTL));
            put_be16(&dns_answer, htons(sizeof(ovs_be32)));
            put_be32(&dns_answer, ip_addrs.ipv4_addrs[i].addr);
            ancount++;
        }
    }

    if (query_type == DNS_QUERY_TYPE_AAAA ||
        query_type == DNS_QUERY_TYPE_ANY) {
        for (size_t i = 0; i < ip_addrs.n_ipv6_addrs; i++) {
            ofpbuf_put(&dns_answer, in_queryname, idx);
            put_be16(&dns_answer, htons(DNS_QUERY_TYPE_AAAA));
            put_be16(&dns_answer, htons(DNS_CLASS_IN));
            put_be32(&dns_answer, htonl(DNS_DEFAULT_RR_TTL));
            const struct in6_addr *ip6 = &ip_addrs.ipv6_addrs[i].addr;
            put_be16(&dns_answer, htons(sizeof *ip6));
            ofpbuf_put(&dns_answer, ip6, sizeof *ip6);
            ancount++;
        }
    }

    destroy_lport_addresses(&ip_addrs);

    if (!ancount) {
        ofpbuf_uninit(&dns_answer);
        goto exit;
    }

    uint16_t new_l4_size = ntohs(in_udp->udp_len) +  dns_answer.size;
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same.*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    /* Copy the DNS header. */
    struct dns_header *out_dns_header = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, sizeof *out_dns_header),
        sizeof *out_dns_header);

    /* Set the response bit to 1 in the flags. */
    out_dns_header->lo_flag |= 0x80;

    /* Set the answer RR. */
    out_dns_header->ancount = htons(ancount);

    /* Copy the Query section. */
    dp_packet_put(&pkt_out, dp_packet_data(pkt_in), dp_packet_size(pkt_in));

    /* Copy the answer sections. */
    dp_packet_put(&pkt_out, dns_answer.data, dns_answer.size);
    ofpbuf_uninit(&dns_answer);

    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct eth_header *eth = dp_packet_data(&pkt_out);
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        struct ip_header *out_ip = dp_packet_l3(&pkt_out);
        out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs
                                   + new_l4_size);
        /* Checksum needs to be initialized to zero. */
        out_ip->ip_csum = 0;
        out_ip->ip_csum = csum(out_ip, sizeof *out_ip);
    } else {
        struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);
        nh->ip6_plen = htons(new_l4_size);

        /* IPv6 needs UDP checksum calculated */
        uint32_t csum;
        csum = packet_csum_pseudoheader6(nh);
        csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                             ((const unsigned char *)out_udp -
                             (const unsigned char *)eth));
        out_udp->udp_csum = csum_finish(csum);
        if (!out_udp->udp_csum) {
            out_udp->udp_csum = htons(0xffff);
        }
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

/* Called with in the pinctrl_handler thread context. */
static void
process_packet_in(struct rconn *swconn, const struct ofp_header *msg)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    struct ofputil_packet_in pin;
    struct ofpbuf continuation;
    enum ofperr error = ofputil_decode_packet_in(msg, true, NULL, NULL, &pin,
                                                 NULL, NULL, &continuation);

    if (error) {
        VLOG_WARN_RL(&rl, "error decoding packet-in: %s",
                     ofperr_to_string(error));
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }

    struct ofpbuf userdata = ofpbuf_const_initializer(pin.userdata,
                                                      pin.userdata_len);
    const struct action_header *ah = ofpbuf_pull(&userdata, sizeof *ah);
    if (!ah) {
        VLOG_WARN_RL(&rl, "packet-in userdata lacks action header");
        return;
    }

    struct dp_packet packet;
    dp_packet_use_const(&packet, pin.packet, pin.packet_len);
    struct flow headers;
    flow_extract(&packet, &headers);

    switch (ntohl(ah->opcode)) {
    case ACTION_OPCODE_ARP:
        pinctrl_handle_arp(swconn, &headers, &packet, &pin.flow_metadata,
                           &userdata);
        break;
    case ACTION_OPCODE_IGMP:
        pinctrl_ip_mcast_handle_igmp(swconn, &headers, &packet,
                                     &pin.flow_metadata, &userdata);
        break;

    case ACTION_OPCODE_PUT_ARP:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       true);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_PUT_DHCP_OPTS:
        pinctrl_handle_put_dhcp_opts(swconn, &packet, &pin, &userdata,
                                     &continuation);
        break;

    case ACTION_OPCODE_ND_NA:
        pinctrl_handle_nd_na(swconn, &headers, &pin.flow_metadata, &userdata,
                             false);
        break;

    case ACTION_OPCODE_ND_NA_ROUTER:
        pinctrl_handle_nd_na(swconn, &headers, &pin.flow_metadata, &userdata,
                             true);
        break;

    case ACTION_OPCODE_PUT_ND:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       false);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_PUT_DHCPV6_OPTS:
        pinctrl_handle_put_dhcpv6_opts(swconn, &packet, &pin, &userdata,
                                       &continuation);
        break;

    case ACTION_OPCODE_DNS_LOOKUP:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_dns_lookup(swconn, &packet, &pin, &userdata,
                                  &continuation);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_LOG:
        handle_acl_log(&headers, &userdata);
        break;

    case ACTION_OPCODE_PUT_ND_RA_OPTS:
        pinctrl_handle_put_nd_ra_opts(swconn, &headers, &packet, &pin,
                                      &userdata, &continuation);
        break;

    case ACTION_OPCODE_ND_NS:
        pinctrl_handle_nd_ns(swconn, &headers, &packet, &pin.flow_metadata,
                             &userdata);
        break;

    case ACTION_OPCODE_ICMP:
        pinctrl_handle_icmp(swconn, &headers, &packet, &pin.flow_metadata,
                            &userdata, false);
        break;

    case ACTION_OPCODE_ICMP4_ERROR:
        pinctrl_handle_icmp(swconn, &headers, &packet, &pin.flow_metadata,
                            &userdata, true);
        break;

    case ACTION_OPCODE_TCP_RESET:
        pinctrl_handle_tcp_reset(swconn, &headers, &packet, &pin.flow_metadata,
                                 &userdata);
        break;

    case ACTION_OPCODE_PUT_ICMP4_FRAG_MTU:
        pinctrl_handle_put_icmp4_frag_mtu(swconn, &headers, &packet,
                                          &pin, &userdata, &continuation);
        break;

    case ACTION_OPCODE_EVENT:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_event(&userdata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_BIND_VPORT:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_bind_vport(&pin.flow_metadata.flow, &userdata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    default:
        VLOG_WARN_RL(&rl, "unrecognized packet-in opcode %"PRIu32,
                     ntohl(ah->opcode));
        break;
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_recv(struct rconn *swconn, const struct ofp_header *oh,
             enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(swconn, ofputil_encode_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        /* Enable asynchronous messages */
        struct ofputil_switch_config config;

        ofputil_decode_get_config_reply(oh, &config);
        config.miss_send_len = UINT16_MAX;
        set_switch_config(swconn, &config);
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(swconn, oh);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

/* Called with in the main ovn-controller thread context. */
static void
notify_pinctrl_handler(void)
{
    seq_change(pinctrl_handler_seq);
}

/* Called with in the pinctrl_handler thread context. */
static void
notify_pinctrl_main(void)
{
    seq_change(pinctrl_main_seq);
}

/* pinctrl_handler pthread function. */
static void *
pinctrl_handler(void *arg_)
{
    struct pinctrl *pctrl = arg_;
    /* OpenFlow connection to the switch. */
    struct rconn *swconn;
    /* Last seen sequence number for 'swconn'.  When this differs from
     * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
    unsigned int conn_seq_no = 0;

    char *br_int_name = NULL;
    uint64_t new_seq;

    /* Next IPV6 RA in seconds. */
    static long long int send_ipv6_ra_time = LLONG_MAX;
    /* Next GARP announcement in ms. */
    static long long int send_garp_time = LLONG_MAX;
    /* Next multicast query (IGMP) in ms. */
    static long long int send_mcast_query_time = LLONG_MAX;

    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);

    while (!latch_is_set(&pctrl->pinctrl_thread_exit)) {
        if (pctrl->br_int_name) {
            if (!br_int_name || strcmp(br_int_name, pctrl->br_int_name)) {
                free(br_int_name);
                br_int_name = xstrdup(pctrl->br_int_name);
            }
        }

        if (br_int_name) {
            char *target;

            target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int_name);
            if (strcmp(target, rconn_get_target(swconn))) {
                VLOG_INFO("%s: connecting to switch", target);
                rconn_connect(swconn, target, target);
            }
            free(target);
        } else {
            rconn_disconnect(swconn);
        }

        ovs_mutex_lock(&pinctrl_mutex);
        ip_mcast_snoop_run();
        ovs_mutex_unlock(&pinctrl_mutex);

        rconn_run(swconn);
        if (rconn_is_connected(swconn)) {
            if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
                pinctrl_setup(swconn);
                conn_seq_no = rconn_get_connection_seqno(swconn);
            }

            for (int i = 0; i < 50; i++) {
                struct ofpbuf *msg = rconn_recv(swconn);
                if (!msg) {
                    break;
                }

                const struct ofp_header *oh = msg->data;
                enum ofptype type;

                ofptype_decode(&type, oh);
                pinctrl_recv(swconn, oh, type);
                ofpbuf_delete(msg);
            }

            if (may_inject_pkts()) {
                ovs_mutex_lock(&pinctrl_mutex);
                send_garp_run(swconn, &send_garp_time);
                send_ipv6_ras(swconn, &send_ipv6_ra_time);
                send_mac_binding_buffered_pkts(swconn);
                ovs_mutex_unlock(&pinctrl_mutex);

                ip_mcast_querier_run(swconn, &send_mcast_query_time);
            }
        }

        rconn_run_wait(swconn);
        rconn_recv_wait(swconn);
        send_garp_wait(send_garp_time);
        ipv6_ra_wait(send_ipv6_ra_time);
        ip_mcast_querier_wait(send_mcast_query_time);

        new_seq = seq_read(pinctrl_handler_seq);
        seq_wait(pinctrl_handler_seq, new_seq);

        latch_wait(&pctrl->pinctrl_thread_exit);
        poll_block();
    }

    free(br_int_name);
    rconn_destroy(swconn);
    return NULL;
}

/* Called by ovn-controller. */
void
pinctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
            struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
            struct ovsdb_idl_index *sbrec_port_binding_by_key,
            struct ovsdb_idl_index *sbrec_port_binding_by_name,
            struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
            struct ovsdb_idl_index *sbrec_igmp_groups,
            struct ovsdb_idl_index *sbrec_ip_multicast_opts,
            const struct sbrec_dns_table *dns_table,
            const struct sbrec_controller_event_table *ce_table,
            const struct ovsrec_bridge *br_int,
            const struct sbrec_chassis *chassis,
            const struct hmap *local_datapaths,
            const struct sset *active_tunnels)
{
    ovs_mutex_lock(&pinctrl_mutex);
    if (br_int && (!pinctrl.br_int_name || strcmp(pinctrl.br_int_name,
                                                  br_int->name))) {
        if (pinctrl.br_int_name) {
            free(pinctrl.br_int_name);
        }
        pinctrl.br_int_name = xstrdup(br_int->name);
        /* Notify pinctrl_handler that integration bridge is
         * set/changed. */
        notify_pinctrl_handler();
    }
    run_put_mac_bindings(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_key,
                         sbrec_mac_binding_by_lport_ip);
    run_put_vport_bindings(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                           sbrec_port_binding_by_key, chassis);
    send_garp_prepare(sbrec_port_binding_by_datapath,
                      sbrec_port_binding_by_name, br_int, chassis,
                      local_datapaths, active_tunnels);
    prepare_ipv6_ras(sbrec_port_binding_by_datapath,
                     sbrec_port_binding_by_name, local_datapaths);
    sync_dns_cache(dns_table);
    controller_event_run(ovnsb_idl_txn, ce_table, chassis);
    ip_mcast_sync(ovnsb_idl_txn, chassis, local_datapaths,
                  sbrec_datapath_binding_by_key,
                  sbrec_port_binding_by_key,
                  sbrec_igmp_groups,
                  sbrec_ip_multicast_opts);
    run_buffered_binding(sbrec_port_binding_by_datapath,
                         sbrec_mac_binding_by_lport_ip,
                         local_datapaths);
    ovs_mutex_unlock(&pinctrl_mutex);
}

/* Table of ipv6_ra_state structures, keyed on logical port name.
 * Protected by pinctrl_mutex. */
static struct shash ipv6_ras;

struct ipv6_ra_config {
    time_t min_interval;
    time_t max_interval;
    struct eth_addr eth_src;
    struct eth_addr eth_dst;
    struct in6_addr ipv6_src;
    struct in6_addr ipv6_dst;
    int32_t mtu;
    uint8_t mo_flags; /* Managed/Other flags for RAs */
    uint8_t la_flags; /* On-link/autonomous flags for address prefixes */
    struct lport_addresses prefixes;
};

struct ipv6_ra_state {
    long long int next_announce;
    struct ipv6_ra_config *config;
    int64_t port_key;
    int64_t metadata;
    bool delete_me;
};

static void
init_ipv6_ras(void)
{
    shash_init(&ipv6_ras);
}

static void
ipv6_ra_config_delete(struct ipv6_ra_config *config)
{
    if (config) {
        destroy_lport_addresses(&config->prefixes);
        free(config);
    }
}

static void
ipv6_ra_delete(struct ipv6_ra_state *ra)
{
    if (ra) {
        ipv6_ra_config_delete(ra->config);
        free(ra);
    }
}

static void
destroy_ipv6_ras(void)
{
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ipv6_ra_delete(ra);
        shash_delete(&ipv6_ras, iter);
    }
    shash_destroy(&ipv6_ras);
}

static struct ipv6_ra_config *
ipv6_ra_update_config(const struct sbrec_port_binding *pb)
{
    struct ipv6_ra_config *config;

    config = xzalloc(sizeof *config);

    config->max_interval = smap_get_int(&pb->options, "ipv6_ra_max_interval",
            ND_RA_MAX_INTERVAL_DEFAULT);
    config->min_interval = smap_get_int(&pb->options, "ipv6_ra_min_interval",
            nd_ra_min_interval_default(config->max_interval));
    config->mtu = smap_get_int(&pb->options, "ipv6_ra_mtu", ND_MTU_DEFAULT);
    config->la_flags = IPV6_ND_RA_OPT_PREFIX_ON_LINK;

    const char *address_mode = smap_get(&pb->options, "ipv6_ra_address_mode");
    if (!address_mode) {
        VLOG_WARN("No address mode specified");
        goto fail;
    }
    if (!strcmp(address_mode, "dhcpv6_stateless")) {
        config->mo_flags = IPV6_ND_RA_FLAG_OTHER_ADDR_CONFIG;
        config->la_flags |= IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS;
    } else if (!strcmp(address_mode, "dhcpv6_stateful")) {
        config->mo_flags = IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG;
    } else if (!strcmp(address_mode, "slaac")) {
        config->la_flags |= IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS;
    } else {
        VLOG_WARN("Invalid address mode %s", address_mode);
        goto fail;
    }

    const char *prefixes = smap_get(&pb->options, "ipv6_ra_prefixes");
    if (prefixes && !extract_ip_addresses(prefixes, &config->prefixes)) {
        VLOG_WARN("Invalid IPv6 prefixes: %s", prefixes);
        goto fail;
    }

    /* All nodes multicast addresses */
    config->eth_dst = (struct eth_addr) ETH_ADDR_C(33,33,00,00,00,01);
    ipv6_parse("ff02::1", &config->ipv6_dst);

    const char *eth_addr = smap_get(&pb->options, "ipv6_ra_src_eth");
    if (!eth_addr || !eth_addr_from_string(eth_addr, &config->eth_src)) {
        VLOG_WARN("Invalid ethernet source %s", eth_addr);
        goto fail;
    }
    const char *ip_addr = smap_get(&pb->options, "ipv6_ra_src_addr");
    if (!ip_addr || !ipv6_parse(ip_addr, &config->ipv6_src)) {
        VLOG_WARN("Invalid IP source %s", ip_addr);
        goto fail;
    }

    return config;

fail:
    ipv6_ra_config_delete(config);
    return NULL;
}

static long long int
ipv6_ra_calc_next_announce(time_t min_interval, time_t max_interval)
{
    long long int min_interval_ms = min_interval * 1000LL;
    long long int max_interval_ms = max_interval * 1000LL;

    return time_msec() + min_interval_ms +
        random_range(max_interval_ms - min_interval_ms);
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

/* Called with in the pinctrl_handler thread context. */
static long long int
ipv6_ra_send(struct rconn *swconn, struct ipv6_ra_state *ra)
{
    if (time_msec() < ra->next_announce) {
        return ra->next_announce;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_nd_ra(&packet, ra->config->eth_src, ra->config->eth_dst,
            &ra->config->ipv6_src, &ra->config->ipv6_dst,
            255, ra->config->mo_flags, htons(IPV6_ND_RA_LIFETIME), 0, 0,
            ra->config->mtu);

    for (int i = 0; i < ra->config->prefixes.n_ipv6_addrs; i++) {
        ovs_be128 addr;
        memcpy(&addr, &ra->config->prefixes.ipv6_addrs[i].addr, sizeof addr);
        packet_put_ra_prefix_opt(&packet,
            ra->config->prefixes.ipv6_addrs[i].plen,
            ra->config->la_flags, htonl(IPV6_ND_RA_OPT_PREFIX_VALID_LIFETIME),
            htonl(IPV6_ND_RA_OPT_PREFIX_PREFERRED_LIFETIME), addr);
    }

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = ra->metadata;
    uint32_t port_key = ra->port_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY_BIT, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };

    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    ra->next_announce = ipv6_ra_calc_next_announce(ra->config->min_interval,
            ra->config->max_interval);

    return ra->next_announce;
}

/* Called with in the pinctrl_handler thread context. */
static void
ipv6_ra_wait(long long int send_ipv6_ra_time)
{
    /* Set the poll timer for next IPv6 RA only if IPv6 RAs needs to
     * be sent. */
    if (!shash_is_empty(&ipv6_ras)) {
        poll_timer_wait_until(send_ipv6_ra_time);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
send_ipv6_ras(struct rconn *swconn, long long int *send_ipv6_ra_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    *send_ipv6_ra_time = LLONG_MAX;
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        long long int next_ra = ipv6_ra_send(swconn, ra);
        if (*send_ipv6_ra_time > next_ra) {
            *send_ipv6_ra_time = next_ra;
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
prepare_ipv6_ras(struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                 struct ovsdb_idl_index *sbrec_port_binding_by_name,
                 const struct hmap *local_datapaths)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct shash_node *iter, *iter_next;

    SHASH_FOR_EACH (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ra->delete_me = true;
    }

    bool changed = false;
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
            sbrec_port_binding_by_datapath);
        sbrec_port_binding_index_set_datapath(target, ld->datapath);

        struct sbrec_port_binding *pb;
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                           sbrec_port_binding_by_datapath) {
            if (!smap_get_bool(&pb->options, "ipv6_ra_send_periodic", false)) {
                continue;
            }

            const char *peer_s = smap_get(&pb->options, "peer");
            if (!peer_s) {
                continue;
            }

            const struct sbrec_port_binding *peer
                = lport_lookup_by_name(sbrec_port_binding_by_name, peer_s);
            if (!peer) {
                continue;
            }

            struct ipv6_ra_config *config = ipv6_ra_update_config(pb);
            if (!config) {
                continue;
            }

            struct ipv6_ra_state *ra
                = shash_find_data(&ipv6_ras, pb->logical_port);
            if (!ra) {
                ra = xzalloc(sizeof *ra);
                ra->config = config;
                ra->next_announce = ipv6_ra_calc_next_announce(
                    ra->config->min_interval,
                    ra->config->max_interval);
                shash_add(&ipv6_ras, pb->logical_port, ra);
                changed = true;
            } else {
                if (config->min_interval != ra->config->min_interval ||
                    config->max_interval != ra->config->max_interval)
                    ra->next_announce = ipv6_ra_calc_next_announce(
                        config->min_interval,
                        config->max_interval);
                ipv6_ra_config_delete(ra->config);
                ra->config = config;
            }

            /* Peer is the logical switch port that the logical
             * router port is connected to. The RA is injected
             * into that logical switch port.
             */
            ra->port_key = peer->tunnel_key;
            ra->metadata = peer->datapath->tunnel_key;
            ra->delete_me = false;

            /* pinctrl_handler thread will send the IPv6 RAs. */
        }
        sbrec_port_binding_index_destroy_row(target);
    }

    /* Remove those that are no longer in the SB database */
    SHASH_FOR_EACH_SAFE (iter, iter_next, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        if (ra->delete_me) {
            shash_delete(&ipv6_ras, iter);
            ipv6_ra_delete(ra);
        }
    }

    if (changed) {
        notify_pinctrl_handler();
    }

}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
void
pinctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    wait_put_mac_bindings(ovnsb_idl_txn);
    wait_controller_event(ovnsb_idl_txn);
    wait_put_vport_bindings(ovnsb_idl_txn);
    int64_t new_seq = seq_read(pinctrl_main_seq);
    seq_wait(pinctrl_main_seq, new_seq);
}

/* Called by ovn-controller. */
void
pinctrl_destroy(void)
{
    latch_set(&pinctrl.pinctrl_thread_exit);
    pthread_join(pinctrl.pinctrl_thread, NULL);
    latch_destroy(&pinctrl.pinctrl_thread_exit);
    free(pinctrl.br_int_name);
    destroy_send_garps();
    destroy_ipv6_ras();
    destroy_buffered_packets_map();
    event_table_destroy();
    destroy_put_mac_bindings();
    destroy_put_vport_bindings();
    destroy_dns_cache();
    ip_mcast_snoop_destroy();
    seq_destroy(pinctrl_main_seq);
    seq_destroy(pinctrl_handler_seq);
}

/* Implementation of the "put_arp" and "put_nd" OVN actions.  These
 * actions send a packet to ovn-controller, using the flow as an API
 * (see actions.h for details).  This code implements the actions by
 * updating the MAC_Binding table in the southbound database.
 *
 * This code could be a lot simpler if the database could always be updated,
 * but in fact we can only update it when 'ovnsb_idl_txn' is nonnull.  Thus,
 * we buffer up a few put_mac_bindings (but we don't keep them longer
 * than 1 second) and apply them whenever a database transaction is
 * available. */

/* Buffered "put_mac_binding" operation. */
struct put_mac_binding {
    struct hmap_node hmap_node; /* In 'put_mac_bindings'. */

    /* Key. */
    uint32_t dp_key;
    uint32_t port_key;
    struct in6_addr ip_key;

    /* Value. */
    struct eth_addr mac;
};

/* Contains "struct put_mac_binding"s. */
static struct hmap put_mac_bindings;

static void
init_put_mac_bindings(void)
{
    hmap_init(&put_mac_bindings);
}

static void
destroy_put_mac_bindings(void)
{
    flush_put_mac_bindings();
    hmap_destroy(&put_mac_bindings);
}

static struct put_mac_binding *
pinctrl_find_put_mac_binding(uint32_t dp_key, uint32_t port_key,
                             const struct in6_addr *ip_key, uint32_t hash)
{
    struct put_mac_binding *pa;
    HMAP_FOR_EACH_WITH_HASH (pa, hmap_node, hash, &put_mac_bindings) {
        if (pa->dp_key == dp_key
            && pa->port_key == port_key
            && IN6_ARE_ADDR_EQUAL(&pa->ip_key, ip_key)) {
            return pa;
        }
    }
    return NULL;
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_mac_binding(const struct flow *md,
                               const struct flow *headers,
                               bool is_arp)
    OVS_REQUIRES(pinctrl_mutex)
{
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t port_key = md->regs[MFF_LOG_INPORT - MFF_REG0];
    struct in6_addr ip_key;

    if (is_arp) {
        ip_key = in6_addr_mapped_ipv4(htonl(md->regs[0]));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(md, 0));
        memcpy(&ip_key, &ip6, sizeof ip_key);
    }
    uint32_t hash = hash_bytes(&ip_key, sizeof ip_key,
                               hash_2words(dp_key, port_key));
    struct put_mac_binding *pmb
        = pinctrl_find_put_mac_binding(dp_key, port_key, &ip_key, hash);
    if (!pmb) {
        if (hmap_count(&put_mac_bindings) >= 1000) {
            COVERAGE_INC(pinctrl_drop_put_mac_binding);
            return;
        }

        pmb = xmalloc(sizeof *pmb);
        hmap_insert(&put_mac_bindings, &pmb->hmap_node, hash);
        pmb->dp_key = dp_key;
        pmb->port_key = port_key;
        pmb->ip_key = ip_key;
    }
    pmb->mac = headers->dl_src;

    /* We can send the buffered packet once the main ovn-controller
     * thread calls pinctrl_run() and it writes the mac_bindings stored
     * in 'put_mac_bindings' hmap into the Southbound MAC_Binding table. */
    notify_pinctrl_main();
}

/* Called with in the pinctrl_handler thread context. */
static void
send_mac_binding_buffered_pkts(struct rconn *swconn)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct buffered_packets *bp;
    LIST_FOR_EACH_POP (bp, list, &buffered_mac_bindings) {
        buffered_send_packets(swconn, bp, &bp->ea);
        free(bp);
    }
    ovs_list_init(&buffered_mac_bindings);
}

static const struct sbrec_mac_binding *
mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                   const char *logical_port,
                   const char *ip)
{
    struct sbrec_mac_binding *mb = sbrec_mac_binding_index_init_row(
        sbrec_mac_binding_by_lport_ip);
    sbrec_mac_binding_index_set_logical_port(mb, logical_port);
    sbrec_mac_binding_index_set_ip(mb, ip);

    const struct sbrec_mac_binding *retval
        = sbrec_mac_binding_index_find(sbrec_mac_binding_by_lport_ip,
                                       mb);

    sbrec_mac_binding_index_destroy_row(mb);

    return retval;
}

static void
run_put_mac_binding(struct ovsdb_idl_txn *ovnsb_idl_txn,
                    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                    struct ovsdb_idl_index *sbrec_port_binding_by_key,
                    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                    const struct put_mac_binding *pmb)
{
    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        pmb->dp_key, pmb->port_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, pmb->dp_key, pmb->port_key);
        return;
    }

    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string,
             ETH_ADDR_FMT, ETH_ADDR_ARGS(pmb->mac));

    struct ds ip_s = DS_EMPTY_INITIALIZER;
    ipv6_format_mapped(&pmb->ip_key, &ip_s);

    /* Update or add an IP-MAC binding for this logical port. */
    const struct sbrec_mac_binding *b =
        mac_binding_lookup(sbrec_mac_binding_by_lport_ip, pb->logical_port,
                           ds_cstr(&ip_s));
    if (!b) {
        b = sbrec_mac_binding_insert(ovnsb_idl_txn);
        sbrec_mac_binding_set_logical_port(b, pb->logical_port);
        sbrec_mac_binding_set_ip(b, ds_cstr(&ip_s));
        sbrec_mac_binding_set_mac(b, mac_string);
        sbrec_mac_binding_set_datapath(b, pb->datapath);
    } else if (strcmp(b->mac, mac_string)) {
        sbrec_mac_binding_set_mac(b, mac_string);
    }
    ds_destroy(&ip_s);
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
run_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_key,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    const struct put_mac_binding *pmb;
    HMAP_FOR_EACH (pmb, hmap_node, &put_mac_bindings) {
        run_put_mac_binding(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                            sbrec_port_binding_by_key,
                            sbrec_mac_binding_by_lport_ip,
                            pmb);
    }
    flush_put_mac_bindings();
}

static void
run_buffered_binding(struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                     const struct hmap *local_datapaths)
    OVS_REQUIRES(pinctrl_mutex)
{
    const struct local_datapath *ld;
    bool notify = false;

    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
                sbrec_port_binding_by_datapath);
        sbrec_port_binding_index_set_datapath(target, ld->datapath);

        const struct sbrec_port_binding *pb;
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                           sbrec_port_binding_by_datapath) {
            struct buffered_packets *cur_qp, *next_qp;
            HMAP_FOR_EACH_SAFE (cur_qp, next_qp, hmap_node,
                                &buffered_packets_map) {
                struct ds ip_s = DS_EMPTY_INITIALIZER;
                ipv6_format_mapped(&cur_qp->ip, &ip_s);
                const struct sbrec_mac_binding *b = mac_binding_lookup(
                        sbrec_mac_binding_by_lport_ip, pb->logical_port,
                        ds_cstr(&ip_s));
                if (b && ovs_scan(b->mac, ETH_ADDR_SCAN_FMT,
                                  ETH_ADDR_SCAN_ARGS(cur_qp->ea))) {
                    hmap_remove(&buffered_packets_map, &cur_qp->hmap_node);
                    ovs_list_push_back(&buffered_mac_bindings, &cur_qp->list);
                    notify = true;
                }
                ds_destroy(&ip_s);
            }
        }
        sbrec_port_binding_index_destroy_row(target);
    }
    buffered_packets_map_gc();

    if (notify) {
        notify_pinctrl_handler();
    }
}

static void
wait_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (ovnsb_idl_txn && !hmap_is_empty(&put_mac_bindings)) {
        poll_immediate_wake();
    }
}

static void
flush_put_mac_bindings(void)
{
    struct put_mac_binding *pmb;
    HMAP_FOR_EACH_POP (pmb, hmap_node, &put_mac_bindings) {
        free(pmb);
    }
}

/*
 * Send gratuitous ARP for vif on localnet.
 *
 * When a new vif on localnet is added, gratuitous ARPs are sent announcing
 * the port's mac,ip mapping.  On localnet, such announcements are needed for
 * switches and routers on the broadcast segment to update their port-mac
 * and ARP tables.
 */
struct garp_data {
    struct eth_addr ea;          /* Ethernet address of port. */
    ovs_be32 ipv4;               /* Ipv4 address of port. */
    long long int announce_time; /* Next announcement in ms. */
    int backoff;                 /* Backoff for the next announcement. */
    uint32_t dp_key;             /* Datapath used to output this GARP. */
    uint32_t port_key;           /* Port to inject the GARP into. */
};

/* Contains GARPs to be sent. Protected by pinctrl_mutex*/
static struct shash send_garp_data;

static void
init_send_garps(void)
{
    shash_init(&send_garp_data);
}

static void
destroy_send_garps(void)
{
    shash_destroy_free_data(&send_garp_data);
}

/* Runs with in the main ovn-controller thread context. */
static void
add_garp(const char *name, const struct eth_addr ea, ovs_be32 ip,
         uint32_t dp_key, uint32_t port_key)
{
    struct garp_data *garp = xmalloc(sizeof *garp);
    garp->ea = ea;
    garp->ipv4 = ip;
    garp->announce_time = time_msec() + 1000;
    garp->backoff = 1;
    garp->dp_key = dp_key;
    garp->port_key = port_key;
    shash_add(&send_garp_data, name, garp);

    /* Notify pinctrl_handler so that it can wakeup and process
     * these GARP requests. */
    notify_pinctrl_handler();
}

/* Add or update a vif for which GARPs need to be announced. */
static void
send_garp_update(const struct sbrec_port_binding *binding_rec,
                 struct shash *nat_addresses)
{
    volatile struct garp_data *garp = NULL;
    /* Update GARP for NAT IP if it exists.  Consider port bindings with type
     * "l3gateway" for logical switch ports attached to gateway routers, and
     * port bindings with type "patch" for logical switch ports attached to
     * distributed gateway ports. */
    if (!strcmp(binding_rec->type, "l3gateway")
        || !strcmp(binding_rec->type, "patch")) {
        struct lport_addresses *laddrs = NULL;
        while ((laddrs = shash_find_and_delete(nat_addresses,
                                               binding_rec->logical_port))) {
            int i;
            for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
                char *name = xasprintf("%s-%s", binding_rec->logical_port,
                                                laddrs->ipv4_addrs[i].addr_s);
                garp = shash_find_data(&send_garp_data, name);
                if (garp) {
                    garp->dp_key = binding_rec->datapath->tunnel_key;
                    garp->port_key = binding_rec->tunnel_key;
                } else {
                    add_garp(name, laddrs->ea,
                             laddrs->ipv4_addrs[i].addr,
                             binding_rec->datapath->tunnel_key,
                             binding_rec->tunnel_key);
                }
                free(name);
            }
            destroy_lport_addresses(laddrs);
            free(laddrs);
        }
        return;
    }

    /* Update GARP for vif if it exists. */
    garp = shash_find_data(&send_garp_data, binding_rec->logical_port);
    if (garp) {
        garp->dp_key = binding_rec->datapath->tunnel_key;
        garp->port_key = binding_rec->tunnel_key;
        return;
    }

    /* Add GARP for new vif. */
    int i;
    for (i = 0; i < binding_rec->n_mac; i++) {
        struct lport_addresses laddrs;
        if (!extract_lsp_addresses(binding_rec->mac[i], &laddrs)
            || !laddrs.n_ipv4_addrs) {
            continue;
        }

        add_garp(binding_rec->logical_port,
                 laddrs.ea, laddrs.ipv4_addrs[0].addr,
                 binding_rec->datapath->tunnel_key, binding_rec->tunnel_key);

        destroy_lport_addresses(&laddrs);
        break;
    }
}

/* Remove a vif from GARP announcements. */
static void
send_garp_delete(const char *lport)
{
    struct garp_data *garp = shash_find_and_delete(&send_garp_data, lport);
    free(garp);
    notify_pinctrl_handler();
}

/* Called with in the pinctrl_handler thread context. */
static long long int
send_garp(struct rconn *swconn, struct garp_data *garp,
          long long int current_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (current_time < garp->announce_time) {
        return garp->announce_time;
    }

    /* Compose a GARP request packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_arp(&packet, ARP_OP_REQUEST, garp->ea, eth_addr_zero,
                true, garp->ipv4, garp->ipv4);

    /* Inject GARP request. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(garp->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(garp->port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    /* Set the next announcement.  At most 5 announcements are sent for a
     * vif. */
    if (garp->backoff < 16) {
        garp->backoff *= 2;
        garp->announce_time = current_time + garp->backoff * 1000;
    } else {
        garp->announce_time = LLONG_MAX;
    }
    return garp->announce_time;
}

/*
 * Multicast snooping configuration.
 */
struct ip_mcast_snoop_cfg {
    bool enabled;
    bool querier_enabled;

    uint32_t table_size;       /* Max number of allowed multicast groups. */
    uint32_t idle_time_s;      /* Idle timeout for multicast groups. */
    uint32_t query_interval_s; /* Multicast query interval. */
    uint32_t query_max_resp_s; /* Multicast query max-response field. */
    uint32_t seq_no;           /* Used for flushing learnt groups. */

    struct eth_addr query_eth_src; /* Src ETH address used for queries. */
    struct eth_addr query_eth_dst; /* Dst ETH address used for queries. */
    ovs_be32 query_ipv4_src;       /* Src IPv4 address used for queries. */
    ovs_be32 query_ipv4_dst;       /* Dsc IPv4 address used for queries. */
};

/*
 * Holds per-datapath information about multicast snooping. Maintained by
 * pinctrl_handler().
 */
struct ip_mcast_snoop {
    struct hmap_node hmap_node;    /* Linkage in the hash map. */
    struct ovs_list query_node;    /* Linkage in the query list. */
    struct ip_mcast_snoop_cfg cfg; /* Multicast configuration. */
    struct mcast_snooping *ms;     /* Multicast group state. */
    int64_t dp_key;                /* Datapath running the snooping. */

    long long int query_time_ms;   /* Next query time in ms. */
};

/*
 * Holds the per-datapath multicast configuration state. Maintained by
 * pinctrl_run().
 */
struct ip_mcast_snoop_state {
    struct hmap_node hmap_node;
    int64_t dp_key;
    struct ip_mcast_snoop_cfg cfg;
};

/* Only default vlan supported for now. */
#define IP_MCAST_VLAN 1

/* Multicast snooping information stored independently by datapath key.
 * Protected by pinctrl_mutex. pinctrl_handler has RW access and pinctrl_main
 * has RO access.
 */
static struct hmap mcast_snoop_map OVS_GUARDED_BY(pinctrl_mutex);

/* Contains multicast queries to be sent. Only used by pinctrl_handler so no
 * locking needed.
 */
static struct ovs_list mcast_query_list;

/* Multicast config information stored independently by datapath key.
 * Protected by pinctrl_mutex. pinctrl_handler has RO access and pinctrl_main
 * has RW access. Read accesses from pinctrl_ip_mcast_handle_igmp() can be
 * performed without taking the lock as they are executed in the pinctrl_main
 * thread.
 */
static struct hmap mcast_cfg_map OVS_GUARDED_BY(pinctrl_mutex);

static void
ip_mcast_snoop_cfg_load(struct ip_mcast_snoop_cfg *cfg,
                        const struct sbrec_ip_multicast *ip_mcast)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    memset(cfg, 0, sizeof *cfg);
    cfg->enabled =
        (ip_mcast->enabled && ip_mcast->enabled[0]);
    cfg->querier_enabled =
        (cfg->enabled && ip_mcast->querier && ip_mcast->querier[0]);

    if (ip_mcast->table_size) {
        cfg->table_size = ip_mcast->table_size[0];
    } else {
        cfg->table_size = OVN_MCAST_DEFAULT_MAX_ENTRIES;
    }

    if (ip_mcast->idle_timeout) {
        cfg->idle_time_s = ip_mcast->idle_timeout[0];
    } else {
        cfg->idle_time_s = OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S;
    }

    if (ip_mcast->query_interval) {
        cfg->query_interval_s = ip_mcast->query_interval[0];
    } else {
        cfg->query_interval_s = cfg->idle_time_s / 2;
        if (cfg->query_interval_s < OVN_MCAST_MIN_QUERY_INTERVAL_S) {
            cfg->query_interval_s = OVN_MCAST_MIN_QUERY_INTERVAL_S;
        }
    }

    if (ip_mcast->query_max_resp) {
        cfg->query_max_resp_s = ip_mcast->query_max_resp[0];
    } else {
        cfg->query_max_resp_s = OVN_MCAST_DEFAULT_QUERY_MAX_RESPONSE_S;
    }

    cfg->seq_no = ip_mcast->seq_no;

    if (cfg->querier_enabled) {
        /* Try to parse the source ETH address. */
        if (!ip_mcast->eth_src ||
                !eth_addr_from_string(ip_mcast->eth_src,
                                      &cfg->query_eth_src)) {
            VLOG_WARN_RL(&rl,
                         "IGMP Querier enabled with invalid ETH src address");
            /* Failed to parse the IPv4 source address. Disable the querier. */
            cfg->querier_enabled = false;
        }

        /* Try to parse the source IP address. */
        if (!ip_mcast->ip4_src ||
                !ip_parse(ip_mcast->ip4_src, &cfg->query_ipv4_src)) {
            VLOG_WARN_RL(&rl,
                         "IGMP Querier enabled with invalid IPv4 src address");
            /* Failed to parse the IPv4 source address. Disable the querier. */
            cfg->querier_enabled = false;
        }

        /* IGMP queries must be sent to 224.0.0.1. */
        cfg->query_eth_dst =
            (struct eth_addr)ETH_ADDR_C(01, 00, 5E, 00, 00, 01);
        cfg->query_ipv4_dst = htonl(0xe0000001);
    }
}

static uint32_t
ip_mcast_snoop_hash(int64_t dp_key)
{
    return hash_uint64(dp_key);
}

static struct ip_mcast_snoop_state *
ip_mcast_snoop_state_add(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop_state *ms_state = xmalloc(sizeof *ms_state);

    ms_state->dp_key = dp_key;
    hmap_insert(&mcast_cfg_map, &ms_state->hmap_node,
                ip_mcast_snoop_hash(dp_key));
    return ms_state;
}

static struct ip_mcast_snoop_state *
ip_mcast_snoop_state_find(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop_state *ms_state;
    uint32_t hash = ip_mcast_snoop_hash(dp_key);

    HMAP_FOR_EACH_WITH_HASH (ms_state, hmap_node, hash, &mcast_cfg_map) {
        if (ms_state->dp_key == dp_key) {
            return ms_state;
        }
    }
    return NULL;
}

static bool
ip_mcast_snoop_state_update(int64_t dp_key,
                            const struct ip_mcast_snoop_cfg *cfg)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool notify = false;
    struct ip_mcast_snoop_state *ms_state = ip_mcast_snoop_state_find(dp_key);

    if (!ms_state) {
        ms_state = ip_mcast_snoop_state_add(dp_key);
        notify = true;
    } else if (memcmp(cfg, &ms_state->cfg, sizeof *cfg)) {
        notify = true;
    }

    ms_state->cfg = *cfg;
    return notify;
}

static void
ip_mcast_snoop_state_remove(struct ip_mcast_snoop_state *ms_state)
    OVS_REQUIRES(pinctrl_mutex)
{
    hmap_remove(&mcast_cfg_map, &ms_state->hmap_node);
    free(ms_state);
}

static bool
ip_mcast_snoop_enable(struct ip_mcast_snoop *ip_ms)
{
    if (ip_ms->cfg.enabled) {
        return true;
    }

    ip_ms->ms = mcast_snooping_create();
    return ip_ms->ms != NULL;
}

static void
ip_mcast_snoop_flush(struct ip_mcast_snoop *ip_ms)
{
    if (!ip_ms->cfg.enabled) {
        return;
    }

    mcast_snooping_flush(ip_ms->ms);
}

static void
ip_mcast_snoop_disable(struct ip_mcast_snoop *ip_ms)
{
    if (!ip_ms->cfg.enabled) {
        return;
    }

    mcast_snooping_unref(ip_ms->ms);
    ip_ms->ms = NULL;
}

static bool
ip_mcast_snoop_configure(struct ip_mcast_snoop *ip_ms,
                         const struct ip_mcast_snoop_cfg *cfg)
{
    if (cfg->enabled) {
        if (!ip_mcast_snoop_enable(ip_ms)) {
            return false;
        }
        if (ip_ms->cfg.seq_no != cfg->seq_no) {
            ip_mcast_snoop_flush(ip_ms);
        }

        if (ip_ms->cfg.querier_enabled && !cfg->querier_enabled) {
            ovs_list_remove(&ip_ms->query_node);
        } else if (!ip_ms->cfg.querier_enabled && cfg->querier_enabled) {
            ovs_list_push_back(&mcast_query_list, &ip_ms->query_node);
        }
    } else {
        ip_mcast_snoop_disable(ip_ms);
        goto set_fields;
    }

    ovs_rwlock_wrlock(&ip_ms->ms->rwlock);
    if (cfg->table_size != ip_ms->cfg.table_size) {
        mcast_snooping_set_max_entries(ip_ms->ms, cfg->table_size);
    }

    if (cfg->idle_time_s != ip_ms->cfg.idle_time_s) {
        mcast_snooping_set_idle_time(ip_ms->ms, cfg->idle_time_s);
    }
    ovs_rwlock_unlock(&ip_ms->ms->rwlock);

    if (cfg->query_interval_s != ip_ms->cfg.query_interval_s) {
        long long int now = time_msec();

        if (ip_ms->query_time_ms > now + cfg->query_interval_s * 1000) {
            ip_ms->query_time_ms = now;
        }
    }

set_fields:
    memcpy(&ip_ms->cfg, cfg, sizeof ip_ms->cfg);
    return true;
}

static struct ip_mcast_snoop *
ip_mcast_snoop_add(int64_t dp_key, const struct ip_mcast_snoop_cfg *cfg)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms = xzalloc(sizeof *ip_ms);

    ip_ms->dp_key = dp_key;
    if (!ip_mcast_snoop_configure(ip_ms, cfg)) {
        free(ip_ms);
        return NULL;
    }

    hmap_insert(&mcast_snoop_map, &ip_ms->hmap_node,
                ip_mcast_snoop_hash(dp_key));
    return ip_ms;
}

static struct ip_mcast_snoop *
ip_mcast_snoop_find(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms;

    HMAP_FOR_EACH_WITH_HASH (ip_ms, hmap_node, ip_mcast_snoop_hash(dp_key),
                             &mcast_snoop_map) {
        if (ip_ms->dp_key == dp_key) {
            return ip_ms;
        }
    }
    return NULL;
}

static void
ip_mcast_snoop_remove(struct ip_mcast_snoop *ip_ms)
    OVS_REQUIRES(pinctrl_mutex)
{
    hmap_remove(&mcast_snoop_map, &ip_ms->hmap_node);

    if (ip_ms->cfg.querier_enabled) {
        ovs_list_remove(&ip_ms->query_node);
    }

    ip_mcast_snoop_disable(ip_ms);
    free(ip_ms);
}

static void
ip_mcast_snoop_init(void)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    hmap_init(&mcast_snoop_map);
    ovs_list_init(&mcast_query_list);
    hmap_init(&mcast_cfg_map);
}

static void
ip_mcast_snoop_destroy(void)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct ip_mcast_snoop *ip_ms, *ip_ms_next;

    HMAP_FOR_EACH_SAFE (ip_ms, ip_ms_next, hmap_node, &mcast_snoop_map) {
        ip_mcast_snoop_remove(ip_ms);
    }
    hmap_destroy(&mcast_snoop_map);

    struct ip_mcast_snoop_state *ip_ms_state;

    HMAP_FOR_EACH_POP (ip_ms_state, hmap_node, &mcast_cfg_map) {
        free(ip_ms_state);
    }
}

static void
ip_mcast_snoop_run(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms, *ip_ms_next;

    /* First read the config updated by pinctrl_main. If there's any new or
     * updated config then apply it.
     */
    struct ip_mcast_snoop_state *ip_ms_state;

    HMAP_FOR_EACH (ip_ms_state, hmap_node, &mcast_cfg_map) {
        ip_ms = ip_mcast_snoop_find(ip_ms_state->dp_key);

        if (!ip_ms) {
            ip_mcast_snoop_add(ip_ms_state->dp_key, &ip_ms_state->cfg);
        } else if (memcmp(&ip_ms_state->cfg, &ip_ms->cfg,
                          sizeof ip_ms_state->cfg)) {
            ip_mcast_snoop_configure(ip_ms, &ip_ms_state->cfg);
        }
    }

    bool notify = false;

    /* Then walk the multicast snoop instances. */
    HMAP_FOR_EACH_SAFE (ip_ms, ip_ms_next, hmap_node, &mcast_snoop_map) {

        /* Delete the stale ones. */
        if (!ip_mcast_snoop_state_find(ip_ms->dp_key)) {
            ip_mcast_snoop_remove(ip_ms);
            continue;
        }

        /* If enabled run the snooping instance to timeout old groups. */
        if (ip_ms->cfg.enabled) {
            if (mcast_snooping_run(ip_ms->ms)) {
                notify = true;
            }

            mcast_snooping_wait(ip_ms->ms);
        }
    }

    if (notify) {
        notify_pinctrl_main();
    }
}

/*
 * This runs in the pinctrl main thread, so it has access to the southbound
 * database. It reads the IP_Multicast table and updates the local multicast
 * configuration. Then writes to the southbound database the updated
 * IGMP_Groups.
 */
static void
ip_mcast_sync(struct ovsdb_idl_txn *ovnsb_idl_txn,
              const struct sbrec_chassis *chassis,
              const struct hmap *local_datapaths,
              struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
              struct ovsdb_idl_index *sbrec_port_binding_by_key,
              struct ovsdb_idl_index *sbrec_igmp_groups,
              struct ovsdb_idl_index *sbrec_ip_multicast)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool notify = false;

    if (!ovnsb_idl_txn || !chassis) {
        return;
    }

    struct sbrec_ip_multicast *ip_mcast;
    struct ip_mcast_snoop_state *ip_ms_state, *ip_ms_state_next;

    /* First read and update our own local multicast configuration for the
     * local datapaths.
     */
    SBREC_IP_MULTICAST_FOR_EACH_BYINDEX (ip_mcast, sbrec_ip_multicast) {

        int64_t dp_key = ip_mcast->datapath->tunnel_key;
        struct ip_mcast_snoop_cfg cfg;

        ip_mcast_snoop_cfg_load(&cfg, ip_mcast);
        if (ip_mcast_snoop_state_update(dp_key, &cfg)) {
            notify = true;
        }
    }

    /* Then delete the old entries. */
    HMAP_FOR_EACH_SAFE (ip_ms_state, ip_ms_state_next, hmap_node,
                        &mcast_cfg_map) {
        if (!get_local_datapath(local_datapaths, ip_ms_state->dp_key)) {
            ip_mcast_snoop_state_remove(ip_ms_state);
            notify = true;
        }
    }

    const struct sbrec_igmp_group *sbrec_igmp;

    /* Then flush any IGMP_Group entries that are not needed anymore:
     * - either multicast snooping was disabled on the datapath
     * - or the group has expired.
     */
    SBREC_IGMP_GROUP_FOR_EACH_BYINDEX (sbrec_igmp, sbrec_igmp_groups) {
        ovs_be32 group_addr;

        if (!sbrec_igmp->datapath) {
            continue;
        }

        int64_t dp_key = sbrec_igmp->datapath->tunnel_key;
        struct ip_mcast_snoop *ip_ms = ip_mcast_snoop_find(dp_key);

        /* If the datapath doesn't exist anymore or IGMP snooping was disabled
         * on it then delete the IGMP_Group entry.
         */
        if (!ip_ms || !ip_ms->cfg.enabled) {
            igmp_group_delete(sbrec_igmp);
            continue;
        }

        if (!ip_parse(sbrec_igmp->address, &group_addr)) {
            continue;
        }

        ovs_rwlock_rdlock(&ip_ms->ms->rwlock);
        struct mcast_group *mc_group =
            mcast_snooping_lookup4(ip_ms->ms, group_addr,
                                   IP_MCAST_VLAN);

        if (!mc_group || ovs_list_is_empty(&mc_group->bundle_lru)) {
            igmp_group_delete(sbrec_igmp);
        }
        ovs_rwlock_unlock(&ip_ms->ms->rwlock);
    }

    struct ip_mcast_snoop *ip_ms, *ip_ms_next;

    /* Last: write new IGMP_Groups to the southbound DB and update existing
     * ones (if needed). We also flush any old per-datapath multicast snoop
     * structures.
     */
    HMAP_FOR_EACH_SAFE (ip_ms, ip_ms_next, hmap_node, &mcast_snoop_map) {
        /* Flush any non-local snooping datapaths (e.g., stale). */
        struct local_datapath *local_dp =
            get_local_datapath(local_datapaths, ip_ms->dp_key);

        if (!local_dp) {
            continue;
        }

        /* Skip datapaths on which snooping is disabled. */
        if (!ip_ms->cfg.enabled) {
            continue;
        }

        struct mcast_group *mc_group;

        ovs_rwlock_rdlock(&ip_ms->ms->rwlock);
        LIST_FOR_EACH (mc_group, group_node, &ip_ms->ms->group_lru) {
            if (ovs_list_is_empty(&mc_group->bundle_lru)) {
                continue;
            }
            sbrec_igmp = igmp_group_lookup(sbrec_igmp_groups, &mc_group->addr,
                                           local_dp->datapath, chassis);
            if (!sbrec_igmp) {
                sbrec_igmp = igmp_group_create(ovnsb_idl_txn, &mc_group->addr,
                                               local_dp->datapath, chassis);
            }

            igmp_group_update_ports(sbrec_igmp, sbrec_datapath_binding_by_key,
                                    sbrec_port_binding_by_key, ip_ms->ms,
                                    mc_group);
        }
        ovs_rwlock_unlock(&ip_ms->ms->rwlock);
    }

    if (notify) {
        notify_pinctrl_handler();
    }
}

static void
pinctrl_ip_mcast_handle_igmp(struct rconn *swconn OVS_UNUSED,
                             const struct flow *ip_flow,
                             struct dp_packet *pkt_in,
                             const struct match *md,
                             struct ofpbuf *userdata OVS_UNUSED)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure.
     */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP)) {
        VLOG_WARN_RL(&rl,
                     "IGMP action on non-IP packet (eth_type 0x%"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    int64_t dp_key = ntohll(md->flow.metadata);
    uint32_t port_key = md->flow.regs[MFF_LOG_INPORT - MFF_REG0];

    const struct igmp_header *igmp;
    size_t offset;

    offset = (char *) dp_packet_l4(pkt_in) - (char *) dp_packet_data(pkt_in);
    igmp = dp_packet_at(pkt_in, offset, IGMP_HEADER_LEN);
    if (!igmp || csum(igmp, dp_packet_l4_size(pkt_in)) != 0) {
        VLOG_WARN_RL(&rl, "multicast snooping received bad IGMP checksum");
        return;
    }

    ovs_be32 ip4 = ip_flow->igmp_group_ip4;

    struct ip_mcast_snoop *ip_ms = ip_mcast_snoop_find(dp_key);
    if (!ip_ms || !ip_ms->cfg.enabled) {
        /* IGMP snooping is not configured or is disabled. */
        return;
    }

    void *port_key_data = (void *)(uintptr_t)port_key;

    bool group_change = false;

    ovs_rwlock_wrlock(&ip_ms->ms->rwlock);
    switch (ntohs(ip_flow->tp_src)) {
     /* Only default VLAN is supported for now. */
    case IGMP_HOST_MEMBERSHIP_REPORT:
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        group_change =
            mcast_snooping_add_group4(ip_ms->ms, ip4, IP_MCAST_VLAN,
                                      port_key_data);
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        group_change =
            mcast_snooping_leave_group4(ip_ms->ms, ip4, IP_MCAST_VLAN,
                                        port_key_data);
        break;
    case IGMP_HOST_MEMBERSHIP_QUERY:
        /* Shouldn't be receiving any of these since we are the multicast
         * router. Store them for now.
         */
        group_change =
            mcast_snooping_add_mrouter(ip_ms->ms, IP_MCAST_VLAN,
                                       port_key_data);
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        group_change =
            mcast_snooping_add_report(ip_ms->ms, pkt_in, IP_MCAST_VLAN,
                                      port_key_data);
        break;
    }
    ovs_rwlock_unlock(&ip_ms->ms->rwlock);

    if (group_change) {
        notify_pinctrl_main();
    }
}

static long long int
ip_mcast_querier_send(struct rconn *swconn, struct ip_mcast_snoop *ip_ms,
                      long long int current_time)
{
    if (current_time < ip_ms->query_time_ms) {
        return ip_ms->query_time_ms;
    }

    /* Compose a multicast query. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    uint8_t ip_tos = 0;
    uint8_t igmp_ttl = 1;

    dp_packet_clear(&packet);
    packet.packet_type = htonl(PT_ETH);

    struct eth_header *eh = dp_packet_put_zeros(&packet, sizeof *eh);
    eh->eth_dst = ip_ms->cfg.query_eth_dst;
    eh->eth_src = ip_ms->cfg.query_eth_src;

    struct ip_header *nh = dp_packet_put_zeros(&packet, sizeof *nh);

    eh->eth_type = htons(ETH_TYPE_IP);
    dp_packet_set_l3(&packet, nh);
    nh->ip_ihl_ver = IP_IHL_VER(5, 4);
    nh->ip_tot_len = htons(sizeof(struct ip_header) +
                            sizeof(struct igmpv3_query_header));
    nh->ip_tos = IP_DSCP_CS6;
    nh->ip_proto = IPPROTO_IGMP;
    nh->ip_frag_off = htons(IP_DF);
    packet_set_ipv4(&packet, ip_ms->cfg.query_ipv4_src,
                    ip_ms->cfg.query_ipv4_dst, ip_tos, igmp_ttl);

    nh->ip_csum = 0;
    nh->ip_csum = csum(nh, sizeof *nh);

    struct igmpv3_query_header *igh =
        dp_packet_put_zeros(&packet, sizeof *igh);
    dp_packet_set_l4(&packet, igh);

    /* IGMP query max-response in tenths of seconds. */
    uint8_t max_response = ip_ms->cfg.query_max_resp_s * 10;
    uint8_t qqic = max_response;
    packet_set_igmp3_query(&packet, max_response, 0, false, 0, qqic);

    /* Inject multicast query. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(ip_ms->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(OVN_MCAST_FLOOD_TUNNEL_KEY, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOCAL_OUTPUT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    /* Set the next query time. */
    ip_ms->query_time_ms = current_time + ip_ms->cfg.query_interval_s * 1000;
    return ip_ms->query_time_ms;
}

static void
ip_mcast_querier_run(struct rconn *swconn, long long int *query_time)
{
    if (ovs_list_is_empty(&mcast_query_list)) {
        return;
    }

    /* Send multicast queries and update the next query time. */
    long long int current_time = time_msec();
    *query_time = LLONG_MAX;

    struct ip_mcast_snoop *ip_ms;

    LIST_FOR_EACH (ip_ms, query_node, &mcast_query_list) {
        long long int next_query_time =
            ip_mcast_querier_send(swconn, ip_ms, current_time);
        if (*query_time > next_query_time) {
            *query_time = next_query_time;
        }
    }
}

static void
ip_mcast_querier_wait(long long int query_time)
{
    if (!ovs_list_is_empty(&mcast_query_list)) {
        poll_timer_wait_until(query_time);
    }
}

/* Get localnet vifs, local l3gw ports and ofport for localnet patch ports. */
static void
get_localnet_vifs_l3gwports(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct ovsrec_bridge *br_int,
    const struct sbrec_chassis *chassis,
    const struct hmap *local_datapaths,
    struct sset *localnet_vifs,
    struct sset *local_l3gw_ports)
{
    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }
        const char *tunnel_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (tunnel_id &&
                encaps_tunnel_id_match(tunnel_id, chassis->name, NULL)) {
            continue;
        }
        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        if (localnet) {
            continue;
        }
        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];
            if (!iface_rec->n_ofport) {
                continue;
            }
            /* Get localnet vif. */
            const char *iface_id = smap_get(&iface_rec->external_ids,
                                            "iface-id");
            if (!iface_id) {
                continue;
            }
            const struct sbrec_port_binding *pb
                = lport_lookup_by_name(sbrec_port_binding_by_name, iface_id);
            if (!pb) {
                continue;
            }
            struct local_datapath *ld
                = get_local_datapath(local_datapaths,
                                     pb->datapath->tunnel_key);
            if (ld && ld->localnet_port) {
                sset_add(localnet_vifs, iface_id);
            }
        }
    }

    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        sbrec_port_binding_by_datapath);

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        const struct sbrec_port_binding *pb;

        if (!ld->localnet_port) {
            continue;
        }

        /* Get l3gw ports.  Consider port bindings with type "l3gateway"
         * that connect to gateway routers (if local), and consider port
         * bindings of type "patch" since they might connect to
         * distributed gateway ports with NAT addresses. */

        sbrec_port_binding_index_set_datapath(target, ld->datapath);
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                           sbrec_port_binding_by_datapath) {
            if ((ld->has_local_l3gateway && !strcmp(pb->type, "l3gateway"))
                || !strcmp(pb->type, "patch")) {
                sset_add(local_l3gw_ports, pb->logical_port);
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}

static bool
pinctrl_is_chassis_resident(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                            const struct sbrec_chassis *chassis,
                            const struct sset *active_tunnels,
                            const char *port_name)
{
    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(sbrec_port_binding_by_name, port_name);
    if (!pb || !pb->chassis) {
        return false;
    }
    if (strcmp(pb->type, "chassisredirect")) {
        return pb->chassis == chassis;
    } else {
        return ha_chassis_group_is_active(pb->ha_chassis_group,
                                          active_tunnels, chassis);
    }
}

/* Extracts the mac, IPv4 and IPv6 addresses, and logical port from
 * 'addresses' which should be of the format 'MAC [IP1 IP2 ..]
 * [is_chassis_resident("LPORT_NAME")]', where IPn should be a valid IPv4
 * or IPv6 address, and stores them in the 'ipv4_addrs' and 'ipv6_addrs'
 * fields of 'laddrs'.  The logical port name is stored in 'lport'.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses() and free(*lport). */
static bool
extract_addresses_with_port(const char *addresses,
                            struct lport_addresses *laddrs,
                            char **lport)
{
    int ofs;
    if (!extract_addresses(addresses, laddrs, &ofs)) {
        return false;
    } else if (ofs >= strlen(addresses)) {
        return true;
    }

    struct lexer lexer;
    lexer_init(&lexer, addresses + ofs);
    lexer_get(&lexer);

    if (lexer.error || lexer.token.type != LEX_T_ID
        || !lexer_match_id(&lexer, "is_chassis_resident")) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", addresses);
        lexer_destroy(&lexer);
        return true;
    }

    if (!lexer_match(&lexer, LEX_T_LPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting '(' after "
                          "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    if (lexer.token.type != LEX_T_STRING) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl,
                    "Syntax error: expecting quoted string after "
                    "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    *lport = xstrdup(lexer.token.s);

    lexer_get(&lexer);
    if (!lexer_match(&lexer, LEX_T_RPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting ')' after quoted string in "
                          "'is_chassis_resident()' in address '%s'",
                          addresses);
        lexer_destroy(&lexer);
        return false;
    }

    lexer_destroy(&lexer);
    return true;
}

static void
consider_nat_address(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const char *nat_address,
                     const struct sbrec_port_binding *pb,
                     struct sset *nat_address_keys,
                     const struct sbrec_chassis *chassis,
                     const struct sset *active_tunnels,
                     struct shash *nat_addresses)
{
    struct lport_addresses *laddrs = xmalloc(sizeof *laddrs);
    char *lport = NULL;
    if (!extract_addresses_with_port(nat_address, laddrs, &lport)
        || (!lport && !strcmp(pb->type, "patch"))
        || (lport && !pinctrl_is_chassis_resident(
                sbrec_port_binding_by_name, chassis,
                active_tunnels, lport))) {
        destroy_lport_addresses(laddrs);
        free(laddrs);
        free(lport);
        return;
    }
    free(lport);

    int i;
    for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
        char *name = xasprintf("%s-%s", pb->logical_port,
                                        laddrs->ipv4_addrs[i].addr_s);
        sset_add(nat_address_keys, name);
        free(name);
    }
    shash_add(nat_addresses, pb->logical_port, laddrs);
}

static void
get_nat_addresses_and_keys(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                           struct sset *nat_address_keys,
                           struct sset *local_l3gw_ports,
                           const struct sbrec_chassis *chassis,
                           const struct sset *active_tunnels,
                           struct shash *nat_addresses)
{
    const char *gw_port;
    SSET_FOR_EACH(gw_port, local_l3gw_ports) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(sbrec_port_binding_by_name, gw_port);
        if (!pb) {
            continue;
        }

        if (pb->n_nat_addresses) {
            for (int i = 0; i < pb->n_nat_addresses; i++) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     pb->nat_addresses[i], pb,
                                     nat_address_keys, chassis,
                                     active_tunnels,
                                     nat_addresses);
            }
        } else {
            /* Continue to support options:nat-addresses for version
             * upgrade. */
            const char *nat_addresses_options = smap_get(&pb->options,
                                                         "nat-addresses");
            if (nat_addresses_options) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     nat_addresses_options, pb,
                                     nat_address_keys, chassis,
                                     active_tunnels,
                                     nat_addresses);
            }
        }
    }
}

static void
send_garp_wait(long long int send_garp_time)
{
    /* Set the poll timer for next garp only if there is garp data to
     * be sent. */
    if (!shash_is_empty(&send_garp_data)) {
        poll_timer_wait_until(send_garp_time);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
send_garp_run(struct rconn *swconn, long long int *send_garp_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (shash_is_empty(&send_garp_data)) {
        return;
    }

    /* Send GARPs, and update the next announcement. */
    struct shash_node *iter;
    long long int current_time = time_msec();
    *send_garp_time = LLONG_MAX;
    SHASH_FOR_EACH (iter, &send_garp_data) {
        long long int next_announce = send_garp(swconn, iter->data,
                                                current_time);
        if (*send_garp_time > next_announce) {
            *send_garp_time = next_announce;
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
send_garp_prepare(struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                  struct ovsdb_idl_index *sbrec_port_binding_by_name,
                  const struct ovsrec_bridge *br_int,
                  const struct sbrec_chassis *chassis,
                  const struct hmap *local_datapaths,
                  const struct sset *active_tunnels)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct sset localnet_vifs = SSET_INITIALIZER(&localnet_vifs);
    struct sset local_l3gw_ports = SSET_INITIALIZER(&local_l3gw_ports);
    struct sset nat_ip_keys = SSET_INITIALIZER(&nat_ip_keys);
    struct shash nat_addresses;

    shash_init(&nat_addresses);

    get_localnet_vifs_l3gwports(sbrec_port_binding_by_datapath,
                                sbrec_port_binding_by_name,
                                br_int, chassis, local_datapaths,
                                &localnet_vifs, &local_l3gw_ports);

    get_nat_addresses_and_keys(sbrec_port_binding_by_name,
                               &nat_ip_keys, &local_l3gw_ports,
                               chassis, active_tunnels,
                               &nat_addresses);
    /* For deleted ports and deleted nat ips, remove from send_garp_data. */
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &send_garp_data) {
        if (!sset_contains(&localnet_vifs, iter->name) &&
            !sset_contains(&nat_ip_keys, iter->name)) {
            send_garp_delete(iter->name);
        }
    }

    /* Update send_garp_data. */
    const char *iface_id;
    SSET_FOR_EACH (iface_id, &localnet_vifs) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            sbrec_port_binding_by_name, iface_id);
        if (pb) {
            send_garp_update(pb, &nat_addresses);
        }
    }

    /* Update send_garp_data for nat-addresses. */
    const char *gw_port;
    SSET_FOR_EACH (gw_port, &local_l3gw_ports) {
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(sbrec_port_binding_by_name, gw_port);
        if (pb) {
            send_garp_update(pb, &nat_addresses);
        }
    }

    /* pinctrl_handler thread will send the GARPs. */

    sset_destroy(&localnet_vifs);
    sset_destroy(&local_l3gw_ports);

    SHASH_FOR_EACH_SAFE (iter, next, &nat_addresses) {
        struct lport_addresses *laddrs = iter->data;
        destroy_lport_addresses(laddrs);
        shash_delete(&nat_addresses, iter);
        free(laddrs);
    }
    shash_destroy(&nat_addresses);

    sset_destroy(&nat_ip_keys);
}

static bool
may_inject_pkts(void)
{
    return (!shash_is_empty(&ipv6_ras) ||
            !shash_is_empty(&send_garp_data) ||
            !ovs_list_is_empty(&mcast_query_list) ||
            !ovs_list_is_empty(&buffered_mac_bindings));
}

static void
reload_metadata(struct ofpbuf *ofpacts, const struct match *md)
{
    enum mf_field_id md_fields[] = {
#if FLOW_N_REGS == 16
        MFF_REG0,
        MFF_REG1,
        MFF_REG2,
        MFF_REG3,
        MFF_REG4,
        MFF_REG5,
        MFF_REG6,
        MFF_REG7,
        MFF_REG8,
        MFF_REG9,
        MFF_REG10,
        MFF_REG11,
        MFF_REG12,
        MFF_REG13,
        MFF_REG14,
        MFF_REG15,
#else
#error
#endif
        MFF_METADATA,
    };
    for (size_t i = 0; i < ARRAY_SIZE(md_fields); i++) {
        const struct mf_field *field = mf_from_id(md_fields[i]);
        if (!mf_is_all_wild(field, &md->wc)) {
            union mf_value value;
            mf_get_value(field, &md->flow, &value);
            ofpact_put_set_field(ofpacts, field, &value, NULL);
        }
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_nd_na(struct rconn *swconn, const struct flow *ip_flow,
                     const struct match *md,
                     struct ofpbuf *userdata, bool is_router)
{
    /* This action only works for IPv6 ND packets, and the switch should only
     * send us ND packets this way, but check here just to be sure. */
    if (!is_nd(ip_flow, NULL)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NA action on non-ND packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    /* These flags are not exactly correct.  Look at section 7.2.4
     * of RFC 4861. */
    uint32_t rso_flags = ND_RSO_SOLICITED | ND_RSO_OVERRIDE;
    if (is_router) {
        rso_flags |= ND_RSO_ROUTER;
    }
    compose_nd_na(&packet, ip_flow->dl_dst, ip_flow->dl_src,
                  &ip_flow->nd_target, &ip_flow->ipv6_src,
                  htonl(rso_flags));

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_nd_ns(struct rconn *swconn, const struct flow *ip_flow,
                     struct dp_packet *pkt_in,
                     const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for IPv6 packets. */
    if (get_dl_type(ip_flow) != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NS action on non-IPv6 packet");
        return;
    }

    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_handle_buffered_packets(ip_flow, pkt_in, md, false);
    ovs_mutex_unlock(&pinctrl_mutex);

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    compose_nd_ns(&packet, ip_flow->dl_src, &ip_flow->ipv6_src,
                  &ip_flow->ipv6_dst);

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_nd_ra_opts(
    struct rconn *swconn,
    const struct flow *in_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "IPv6 ND RA options not present in the userdata");
        goto exit;
    }

    if (!is_icmpv6(in_flow, NULL) || in_flow->tp_dst != htons(0) ||
        in_flow->tp_src != htons(ND_ROUTER_SOLICIT)) {
        VLOG_WARN_RL(&rl, "put_nd_ra action on invalid or unsupported packet");
        goto exit;
    }

    size_t new_packet_size = pkt_in->l4_ofs + userdata->size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Copy the ICMPv6 Router Advertisement data from 'userdata' field. */
    dp_packet_put(&pkt_out, userdata->data, userdata->size);

    /* Set the IPv6 payload length and calculate the ICMPv6 checksum. */
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);
    nh->ip6_plen = htons(userdata->size);
    struct ovs_ra_msg *ra = dp_packet_l4(&pkt_out);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(nh);
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, ra, userdata->size));
    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    success = 1;

exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_icmp4_frag_mtu(struct rconn *swconn,
                                  const struct flow *in_flow,
                                  struct dp_packet *pkt_in,
                                  struct ofputil_packet_in *pin,
                                  struct ofpbuf *userdata,
                                  struct ofpbuf *continuation)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out = NULL;

    /* This action only works for ICMPv4 packets. */
    if (!is_icmpv4(in_flow, NULL)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "put_icmp4_frag_mtu action on non-ICMPv4 packet");
        goto exit;
    }

    ovs_be16 *mtu = ofpbuf_try_pull(userdata, sizeof *mtu);
    if (!mtu) {
        goto exit;
    }

    pkt_out = dp_packet_clone(pkt_in);
    pkt_out->l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out->l2_pad_size = pkt_in->l2_pad_size;
    pkt_out->l3_ofs = pkt_in->l3_ofs;
    pkt_out->l4_ofs = pkt_in->l4_ofs;

    struct ip_header *nh = dp_packet_l3(pkt_out);
    struct icmp_header *ih = dp_packet_l4(pkt_out);
    ovs_be16 old_frag_mtu = ih->icmp_fields.frag.mtu;
    ih->icmp_fields.frag.mtu = *mtu;
    ih->icmp_csum = recalc_csum16(ih->icmp_csum, old_frag_mtu, *mtu);
    nh->ip_csum = 0;
    nh->ip_csum = csum(nh, sizeof *nh);

    pin->packet = dp_packet_data(pkt_out);
    pin->packet_len = dp_packet_size(pkt_out);

exit:
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    if (pkt_out) {
        dp_packet_delete(pkt_out);
    }
}

static void
wait_controller_event(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        if (!hmap_is_empty(&event_table[i])) {
            poll_immediate_wake();
            break;
        }
    }
}

static bool
pinctrl_handle_empty_lb_backends_opts(struct ofpbuf *userdata)
{
    struct controller_event_opt_header *userdata_opt;
    uint32_t hash = 0;
    char *vip = NULL;
    char *protocol = NULL;
    char *load_balancer = NULL;

    while (userdata->size) {
        userdata_opt = ofpbuf_try_pull(userdata, sizeof *userdata_opt);
        if (!userdata_opt) {
            return false;
        }
        size_t size = ntohs(userdata_opt->size);
        char *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }
        switch (ntohs(userdata_opt->opt_code)) {
        case EMPTY_LB_VIP:
            vip = xmemdup0(userdata_opt_data, size);
            break;
        case EMPTY_LB_PROTOCOL:
            protocol = xmemdup0(userdata_opt_data, size);
            break;
        case EMPTY_LB_LOAD_BALANCER:
            load_balancer = xmemdup0(userdata_opt_data, size);
            break;
        default:
            OVS_NOT_REACHED();
        }
        hash = hash_bytes(userdata_opt_data, size, hash);
    }
    if (!vip || !protocol || !load_balancer) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "missing lb parameters in userdata");
        return false;
    }

    struct empty_lb_backends_event *event;

    event = pinctrl_find_empty_lb_backends_event(vip, protocol,
                                                 load_balancer, hash);
    if (!event) {
        if (hmap_count(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) >= 1000) {
            COVERAGE_INC(pinctrl_drop_controller_event);
            return false;
        }

        event = xzalloc(sizeof *event);
        hmap_insert(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS],
                    &event->hmap_node, hash);
        event->vip = vip;
        event->protocol = protocol;
        event->load_balancer = load_balancer;
        event->timestamp = time_msec();
        notify_pinctrl_main();
    } else {
        free(vip);
        free(protocol);
        free(load_balancer);
    }
    return true;
}

static void
pinctrl_handle_event(struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex)
{
    ovs_be32 *pevent;

    pevent = ofpbuf_try_pull(userdata, sizeof *pevent);
    if (!pevent) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "event not present in the userdata");
        return;
    }

    switch (ntohl(*pevent)) {
    case OVN_EVENT_EMPTY_LB_BACKENDS:
        pinctrl_handle_empty_lb_backends_opts(userdata);
        break;
    default:
        return;
    }
}

struct put_vport_binding {
    struct hmap_node hmap_node;

    /* Key and value. */
    uint32_t dp_key;
    uint32_t vport_key;

    uint32_t vport_parent_key;
};

/* Contains "struct put_vport_binding"s. */
static struct hmap put_vport_bindings;

static void
init_put_vport_bindings(void)
{
    hmap_init(&put_vport_bindings);
}

static void
flush_put_vport_bindings(void)
{
    struct put_vport_binding *vport_b;
    HMAP_FOR_EACH_POP (vport_b, hmap_node, &put_vport_bindings) {
        free(vport_b);
    }
}

static void
destroy_put_vport_bindings(void)
{
    flush_put_vport_bindings();
    hmap_destroy(&put_vport_bindings);
}

static void
wait_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (ovnsb_idl_txn && !hmap_is_empty(&put_vport_bindings)) {
        poll_immediate_wake();
    }
}

static struct put_vport_binding *
pinctrl_find_put_vport_binding(uint32_t dp_key, uint32_t vport_key,
                               uint32_t hash)
{
    struct put_vport_binding *vpb;
    HMAP_FOR_EACH_WITH_HASH (vpb, hmap_node, hash, &put_vport_bindings) {
        if (vpb->dp_key == dp_key && vpb->vport_key == vport_key) {
            return vpb;
        }
    }
    return NULL;
}

static void
run_put_vport_binding(struct ovsdb_idl_txn *ovnsb_idl_txn OVS_UNUSED,
                      struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                      struct ovsdb_idl_index *sbrec_port_binding_by_key,
                      const struct sbrec_chassis *chassis,
                      const struct put_vport_binding *vpb)
{
    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        vpb->dp_key, vpb->vport_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, vpb->dp_key, vpb->vport_key);
        return;
    }

    /* pinctrl module updates the port binding only for type 'virtual'. */
    if (!strcmp(pb->type, "virtual")) {
        const struct sbrec_port_binding *parent = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        vpb->dp_key, vpb->vport_parent_key);
        if (parent) {
            VLOG_INFO("Claiming virtual lport %s for this chassis "
                       "with the virtual parent %s",
                       pb->logical_port, parent->logical_port);
            sbrec_port_binding_set_chassis(pb, chassis);
            sbrec_port_binding_set_virtual_parent(pb, parent->logical_port);
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
run_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                      struct ovsdb_idl_index *sbrec_port_binding_by_key,
                      const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    const struct put_vport_binding *vpb;
    HMAP_FOR_EACH (vpb, hmap_node, &put_vport_bindings) {
        run_put_vport_binding(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                              sbrec_port_binding_by_key, chassis, vpb);
    }

    flush_put_vport_bindings();
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_bind_vport(
    const struct flow *md, struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex)
{
    /* Get the datapath key from the packet metadata. */
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t vport_parent_key = md->regs[MFF_LOG_INPORT - MFF_REG0];

    /* Get the virtual port key from the userdata buffer. */
    ovs_be32 *vp_key = ofpbuf_try_pull(userdata, sizeof *vp_key);

    if (!vp_key) {
        return;
    }

    uint32_t vport_key = ntohl(*vp_key);
    uint32_t hash = hash_2words(dp_key, vport_key);

    struct put_vport_binding *vpb
        = pinctrl_find_put_vport_binding(dp_key, vport_key, hash);
    if (!vpb) {
        if (hmap_count(&put_vport_bindings) >= 1000) {
            COVERAGE_INC(pinctrl_drop_put_vport_binding);
            return;
        }

        vpb = xmalloc(sizeof *vpb);
        hmap_insert(&put_vport_bindings, &vpb->hmap_node, hash);
    }

    vpb->dp_key = dp_key;
    vpb->vport_key = vport_key;
    vpb->vport_parent_key = vport_parent_key;

    notify_pinctrl_main();
}
