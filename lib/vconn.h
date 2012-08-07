/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#ifndef VCONN_H
#define VCONN_H 1

#include <stdbool.h>
#include "openvswitch/types.h"
#include "openflow/openflow.h"

#ifdef __cplusplus
extern "C" {
#endif

struct list;
struct ofpbuf;
struct pvconn;
struct vconn;

void vconn_usage(bool active, bool passive, bool bootstrap);

/* Active vconns: virtual connections to OpenFlow devices. */
int vconn_verify_name(const char *name);
int vconn_open(const char *name, int min_version,
               struct vconn **, uint8_t dscp);
void vconn_close(struct vconn *);
const char *vconn_get_name(const struct vconn *);
ovs_be32 vconn_get_remote_ip(const struct vconn *);
ovs_be16 vconn_get_remote_port(const struct vconn *);
ovs_be32 vconn_get_local_ip(const struct vconn *);
ovs_be16 vconn_get_local_port(const struct vconn *);
int vconn_get_version(const struct vconn *);
int vconn_connect(struct vconn *);
int vconn_recv(struct vconn *, struct ofpbuf **);
int vconn_send(struct vconn *, struct ofpbuf *);
int vconn_recv_xid(struct vconn *, ovs_be32 xid, struct ofpbuf **);
int vconn_transact(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_noreply(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_multiple_noreply(struct vconn *, struct list *requests,
                                    struct ofpbuf **replyp);

void vconn_run(struct vconn *);
void vconn_run_wait(struct vconn *);

int vconn_open_block(const char *name, enum ofp_version min_version,
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
int pvconn_open(const char *name, struct pvconn **, uint8_t dscp);
const char *pvconn_get_name(const struct pvconn *);
void pvconn_close(struct pvconn *);
int pvconn_accept(struct pvconn *, int min_version, struct vconn **);
void pvconn_wait(struct pvconn *);

#ifdef __cplusplus
}
#endif

#endif /* vconn.h */
