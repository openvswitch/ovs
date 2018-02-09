/*
 * Copyright (c) 2008-2016 Nicira, Inc.
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

#ifndef OPENVSWITCH_VCONN_H
#define OPENVSWITCH_VCONN_H 1

#include <stdbool.h>
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "openvswitch/ofp-protocol.h"
#include "openflow/openflow.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofpbuf;
struct ofputil_flow_stats;
struct ofputil_flow_stats_request;
struct pvconn;
struct pvconn_class;
struct vconn;
struct vconn_class;

void vconn_usage(bool active, bool passive, bool bootstrap);

/* Active vconns: virtual connections to OpenFlow devices. */
int vconn_verify_name(const char *name);
int vconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
               struct vconn **vconnp);
void vconn_close(struct vconn *);
const char *vconn_get_name(const struct vconn *);

uint32_t vconn_get_allowed_versions(const struct vconn *vconn);
void vconn_set_allowed_versions(struct vconn *vconn,
                                uint32_t allowed_versions);
int vconn_get_version(const struct vconn *);
void vconn_set_recv_any_version(struct vconn *);

int vconn_connect(struct vconn *);
int vconn_recv(struct vconn *, struct ofpbuf **);
int vconn_send(struct vconn *, struct ofpbuf *);
int vconn_recv_xid(struct vconn *, ovs_be32 xid, struct ofpbuf **);
int vconn_transact(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_noreply(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_multiple_noreply(struct vconn *, struct ovs_list *requests,
                                    struct ofpbuf **replyp);

int vconn_dump_flows(struct vconn *, const struct ofputil_flow_stats_request *,
                     enum ofputil_protocol,
                     struct ofputil_flow_stats **fsesp, size_t *n_fsesp);

int vconn_bundle_transact(struct vconn *, struct ovs_list *requests,
                          uint16_t bundle_flags,
                          struct ovs_list *errors);

void vconn_run(struct vconn *);
void vconn_run_wait(struct vconn *);

int vconn_get_status(const struct vconn *);

int vconn_open_block(const char *name, uint32_t allowed_versions, uint8_t dscp,
                     struct vconn **);
int vconn_connect_block(struct vconn *);
int vconn_send_block(struct vconn *, struct ofpbuf *);
int vconn_recv_block(struct vconn *, struct ofpbuf **);

enum vconn_wait_type {
    WAIT_CONNECT,
    WAIT_RECV,
    WAIT_SEND
};
void vconn_wait(struct vconn *, enum vconn_wait_type);
void vconn_connect_wait(struct vconn *);
void vconn_recv_wait(struct vconn *);
void vconn_send_wait(struct vconn *);

/* Passive vconns: virtual listeners for incoming OpenFlow connections. */
int pvconn_verify_name(const char *name);
int pvconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
                struct pvconn **pvconnp);
const char *pvconn_get_name(const struct pvconn *);
void pvconn_close(struct pvconn *);
int pvconn_accept(struct pvconn *, struct vconn **);
void pvconn_wait(struct pvconn *);

#ifdef __cplusplus
}
#endif

#endif /* vconn.h */
