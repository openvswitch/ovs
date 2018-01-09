/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#ifndef CONNMGR_H
#define CONNMGR_H 1

#include "classifier.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-util.h"
#include "ofproto.h"
#include "ofproto-provider.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"

struct nlattr;
struct ofconn;
struct rule;
struct simap;
struct sset;

/* ofproto supports two kinds of OpenFlow connections:
 *
 *   - "Primary" connections to ordinary OpenFlow controllers.  ofproto
 *     maintains persistent connections to these controllers and by default
 *     sends them asynchronous messages such as packet-ins.
 *
 *   - "Service" connections, e.g. from ovs-ofctl.  When these connections
 *     drop, it is the other side's responsibility to reconnect them if
 *     necessary.  ofproto does not send them asynchronous messages by default.
 *
 * Currently, active (tcp, ssl, unix) connections are always "primary"
 * connections and passive (ptcp, pssl, punix) connections are always "service"
 * connections.  There is no inherent reason for this, but it reflects the
 * common case.
 */
enum ofconn_type {
    OFCONN_PRIMARY,             /* An ordinary OpenFlow controller. */
    OFCONN_SERVICE              /* A service connection, e.g. "ovs-ofctl". */
};

/* An asynchronous message that might need to be queued between threads. */
struct ofproto_async_msg {
    struct ovs_list list_node;  /* For queuing. */
    uint16_t controller_id;     /* Controller ID to send to. */

    enum ofputil_async_msg_type oam;
    /* OAM_PACKET_IN. */
    struct {
        struct ofputil_packet_in_private up;
        int max_len;            /* From action, or -1 if none. */
    } pin;
};
void ofproto_async_msg_free(struct ofproto_async_msg *);

/* Basics. */
struct connmgr *connmgr_create(struct ofproto *ofproto,
                               const char *dpif_name, const char *local_name);
void connmgr_destroy(struct connmgr *)
    OVS_REQUIRES(ofproto_mutex);

void connmgr_run(struct connmgr *,
                 void (*handle_openflow)(struct ofconn *,
                                         const struct ofpbuf *ofp_msg));
void connmgr_wait(struct connmgr *);

void connmgr_get_memory_usage(const struct connmgr *, struct simap *usage);

struct ofproto *ofconn_get_ofproto(const struct ofconn *);

void connmgr_retry(struct connmgr *);

/* OpenFlow configuration. */
bool connmgr_has_controllers(const struct connmgr *);
void connmgr_get_controller_info(struct connmgr *, struct shash *);
void connmgr_free_controller_info(struct shash *);
void connmgr_set_controllers(struct connmgr *,
                             const struct ofproto_controller[], size_t n,
                             uint32_t allowed_versions);
void connmgr_reconnect(const struct connmgr *);

int connmgr_set_snoops(struct connmgr *, const struct sset *snoops);
bool connmgr_has_snoops(const struct connmgr *);
void connmgr_get_snoops(const struct connmgr *, struct sset *snoops);

/* Individual connections to OpenFlow controllers. */
enum ofconn_type ofconn_get_type(const struct ofconn *);

bool ofconn_get_master_election_id(const struct ofconn *, uint64_t *idp);
bool ofconn_set_master_election_id(struct ofconn *, uint64_t);
enum ofp12_controller_role ofconn_get_role(const struct ofconn *);
void ofconn_set_role(struct ofconn *, enum ofp12_controller_role);

enum ofputil_protocol ofconn_get_protocol(const struct ofconn *);
void ofconn_set_protocol(struct ofconn *, enum ofputil_protocol);

enum nx_packet_in_format ofconn_get_packet_in_format(struct ofconn *);
void ofconn_set_packet_in_format(struct ofconn *, enum nx_packet_in_format);

void ofconn_set_controller_id(struct ofconn *, uint16_t controller_id);

void ofconn_set_invalid_ttl_to_controller(struct ofconn *, bool);
bool ofconn_get_invalid_ttl_to_controller(struct ofconn *);

int ofconn_get_miss_send_len(const struct ofconn *);
void ofconn_set_miss_send_len(struct ofconn *, int miss_send_len);

void ofconn_set_async_config(struct ofconn *,
                             const struct ofputil_async_cfg *);
struct ofputil_async_cfg ofconn_get_async_config(const struct ofconn *);

void ofconn_send_reply(const struct ofconn *, struct ofpbuf *);
void ofconn_send_replies(const struct ofconn *, struct ovs_list *);
void ofconn_send_error(const struct ofconn *, const struct ofp_header *request,
                       enum ofperr);

struct ofp_bundle;

struct ofp_bundle *ofconn_get_bundle(struct ofconn *, uint32_t id);
void ofconn_insert_bundle(struct ofconn *, struct ofp_bundle *);
void ofconn_remove_bundle(struct ofconn *, struct ofp_bundle *);

/* Logging flow_mod summaries. */
void ofconn_report_flow_mod(struct ofconn *, enum ofp_flow_mod_command);

/* Sending asynchronous messages. */
bool connmgr_wants_packet_in_on_miss(struct connmgr *mgr);
void connmgr_send_port_status(struct connmgr *, struct ofconn *source,
                              const struct ofputil_phy_port *, uint8_t reason);
void connmgr_send_flow_removed(struct connmgr *,
                               const struct ofputil_flow_removed *)
    OVS_REQUIRES(ofproto_mutex);
void connmgr_send_async_msg(struct connmgr *,
                            const struct ofproto_async_msg *);
void ofconn_send_role_status(struct ofconn *ofconn, uint32_t role,
                             uint8_t reason);

void connmgr_send_requestforward(struct connmgr *, const struct ofconn *source,
                                 const struct ofputil_requestforward *);

/* Fail-open settings. */
enum ofproto_fail_mode connmgr_get_fail_mode(const struct connmgr *);
void connmgr_set_fail_mode(struct connmgr *, enum ofproto_fail_mode);

/* Fail-open implementation. */
int connmgr_get_max_probe_interval(const struct connmgr *);
bool connmgr_is_any_controller_connected(const struct connmgr *);
bool connmgr_is_any_controller_admitted(const struct connmgr *);
int connmgr_failure_duration(const struct connmgr *);

/* In-band configuration. */
void connmgr_set_extra_in_band_remotes(struct connmgr *,
                                       const struct sockaddr_in *, size_t);
void connmgr_set_in_band_queue(struct connmgr *, int queue_id);

/* In-band implementation. */
bool connmgr_has_in_band(struct connmgr *);

/* Fail-open and in-band implementation. */
void connmgr_flushed(struct connmgr *);

int connmgr_count_hidden_rules(const struct connmgr *);

/* A flow monitor managed by NXST_FLOW_MONITOR and related requests. */
struct ofmonitor {
    struct ofconn *ofconn;      /* Owning 'ofconn'. */
    struct hmap_node ofconn_node; /* In ofconn's 'monitors' hmap. */
    uint32_t id;

    enum nx_flow_monitor_flags flags;

    /* Matching. */
    ofp_port_t out_port;
    uint8_t table_id;
    struct minimatch match;
};

struct ofputil_flow_monitor_request;

enum ofperr ofmonitor_create(const struct ofputil_flow_monitor_request *,
                             struct ofconn *, struct ofmonitor **)
    OVS_REQUIRES(ofproto_mutex);
struct ofmonitor *ofmonitor_lookup(struct ofconn *, uint32_t id)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_destroy(struct ofmonitor *)
    OVS_REQUIRES(ofproto_mutex);

void ofmonitor_report(struct connmgr *, struct rule *,
                      enum nx_flow_update_event, enum ofp_flow_removed_reason,
                      const struct ofconn *abbrev_ofconn, ovs_be32 abbrev_xid,
                      const struct rule_actions *old_actions)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_flush(struct connmgr *) OVS_REQUIRES(ofproto_mutex);


struct rule_collection;
void ofmonitor_collect_resume_rules(struct ofmonitor *, uint64_t seqno,
                                    struct rule_collection *)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_compose_refresh_updates(struct rule_collection *rules,
                                       struct ovs_list *msgs)
    OVS_REQUIRES(ofproto_mutex);

void connmgr_send_table_status(struct connmgr *,
                               const struct ofputil_table_desc *td,
                               uint8_t reason);
#endif /* connmgr.h */
