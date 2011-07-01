/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#include "hmap.h"
#include "list.h"
#include "ofproto.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/types.h"

struct ofconn;
struct ofopgroup;
struct ofputil_flow_removed;
struct ofputil_packet_in;
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

/* Basics. */
struct connmgr *connmgr_create(struct ofproto *ofproto,
                               const char *dpif_name, const char *local_name);
void connmgr_destroy(struct connmgr *);

void connmgr_run(struct connmgr *,
                 bool (*handle_openflow)(struct ofconn *,
                                         struct ofpbuf *ofp_msg));
void connmgr_wait(struct connmgr *, bool handling_openflow);

struct ofproto *ofconn_get_ofproto(const struct ofconn *);

void connmgr_retry(struct connmgr *);

/* OpenFlow configuration. */
bool connmgr_has_controllers(const struct connmgr *);
void connmgr_get_controller_info(struct connmgr *, struct shash *);
void connmgr_free_controller_info(struct shash *);
void connmgr_set_controllers(struct connmgr *,
                             const struct ofproto_controller[], size_t n);
void connmgr_reconnect(const struct connmgr *);

int connmgr_set_snoops(struct connmgr *, const struct sset *snoops);
bool connmgr_has_snoops(const struct connmgr *);
void connmgr_get_snoops(const struct connmgr *, struct sset *snoops);

/* Individual connections to OpenFlow controllers. */
enum ofconn_type ofconn_get_type(const struct ofconn *);

enum nx_role ofconn_get_role(const struct ofconn *);
void ofconn_set_role(struct ofconn *, enum nx_role);

enum nx_flow_format ofconn_get_flow_format(struct ofconn *);
void ofconn_set_flow_format(struct ofconn *, enum nx_flow_format);

bool ofconn_get_flow_mod_table_id(const struct ofconn *);
void ofconn_set_flow_mod_table_id(struct ofconn *, bool enable);

int ofconn_get_miss_send_len(const struct ofconn *);
void ofconn_set_miss_send_len(struct ofconn *, int miss_send_len);

void ofconn_send_reply(const struct ofconn *, struct ofpbuf *);
void ofconn_send_replies(const struct ofconn *, struct list *);
void ofconn_send_error(const struct ofconn *, const struct ofp_header *request,
                       int error);

int ofconn_pktbuf_retrieve(struct ofconn *, uint32_t id,
                           struct ofpbuf **bufferp, uint16_t *in_port);

size_t ofconn_n_pending_opgroups(const struct ofconn *);
bool ofconn_has_pending_opgroups(const struct ofconn *);
void ofconn_add_opgroup(struct ofconn *, struct list *);
void ofconn_remove_opgroup(struct ofconn *, struct list *,
                           const struct ofp_header *request, int error);

/* Sending asynchronous messages. */
void connmgr_send_port_status(struct connmgr *, const struct ofp_phy_port *,
                              uint8_t reason);
void connmgr_send_flow_removed(struct connmgr *,
                               const struct ofputil_flow_removed *);
void connmgr_send_packet_in(struct connmgr *, const struct ofputil_packet_in *,
                            const struct flow *, struct ofpbuf *rw_packet);

/* Fail-open settings. */
enum ofproto_fail_mode connmgr_get_fail_mode(const struct connmgr *);
void connmgr_set_fail_mode(struct connmgr *, enum ofproto_fail_mode);

/* Fail-open implementation. */
int connmgr_get_max_probe_interval(const struct connmgr *);
bool connmgr_is_any_controller_connected(const struct connmgr *);
bool connmgr_is_any_controller_admitted(const struct connmgr *);
int connmgr_failure_duration(const struct connmgr *);
void connmgr_broadcast(struct connmgr *, struct ofpbuf *);

/* In-band configuration. */
void connmgr_set_extra_in_band_remotes(struct connmgr *,
                                       const struct sockaddr_in *, size_t);
void connmgr_set_in_band_queue(struct connmgr *, int queue_id);

/* In-band implementation. */
bool connmgr_msg_in_hook(struct connmgr *, const struct flow *,
                         const struct ofpbuf *packet);
bool connmgr_may_set_up_flow(struct connmgr *, const struct flow *,
                             const struct nlattr *odp_actions,
                             size_t actions_len);

/* Fail-open and in-band implementation. */
void connmgr_flushed(struct connmgr *);

#endif /* connmgr.h */
