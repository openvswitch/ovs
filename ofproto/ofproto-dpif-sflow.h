/*
 * Copyright (c) 2009, 2010 InMon Corp.
 * Copyright (c) 2009, 2012 Nicira, Inc.
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

#ifndef OFPROTO_DPIF_SFLOW_H
#define OFPROTO_DPIF_SFLOW_H 1

#include <stdint.h>
#include "svec.h"
#include "lib/odp-util.h"

struct dpif;
struct dpif_upcall;
struct flow;
struct ofproto_sflow_options;
struct ofport;

/* When we have the actions for a sampled packet that
 * will go to just one output, then this structure is
 * populated by parsing them.  Only fields relevant to
 * the sFlow export are extracted.
 */
struct dpif_sflow_actions {
    odp_port_t out_port;     /* ODP output port. */

    uint32_t encap_depth;    /* Count layers of tunnel-encap. */
    struct flow_tnl tunnel;  /* Egress tunnel push/set. */
    uint8_t tunnel_ipproto;  /* Tunnel push action can set ipproto. */
    bool tunnel_err;         /* Tunnel actions parse failure. */
    
    /* Using host-byte order for the mpls stack here
       to match the expectations of the sFlow library. Also
       the ordering is reversed, so that the entry at offset 0
       is the bottom of the stack.
    */
    uint32_t mpls_lse[FLOW_MAX_MPLS_LABELS]; /* Out stack in host byte order. */
    uint32_t mpls_stack_depth;               /* Out stack depth. */
    bool mpls_err;                           /* MPLS actions parse failure. */
};

struct dpif_sflow *dpif_sflow_create(void);
struct dpif_sflow *dpif_sflow_ref(const struct dpif_sflow *);
void dpif_sflow_unref(struct dpif_sflow *);

uint32_t dpif_sflow_get_probability(const struct dpif_sflow *);

void dpif_sflow_set_options(struct dpif_sflow *,
                            const struct ofproto_sflow_options *);
void dpif_sflow_clear(struct dpif_sflow *);
bool dpif_sflow_is_enabled(const struct dpif_sflow *);

void dpif_sflow_add_port(struct dpif_sflow *ds, struct ofport *ofport,
                         odp_port_t odp_port);
void dpif_sflow_del_port(struct dpif_sflow *, odp_port_t odp_port);

void dpif_sflow_run(struct dpif_sflow *);
void dpif_sflow_wait(struct dpif_sflow *);

void dpif_sflow_read_actions(const struct flow *,
			     const struct nlattr *actions, size_t actions_len,
			     struct dpif_sflow_actions *);

void dpif_sflow_received(struct dpif_sflow *, const struct dp_packet *,
                         const struct flow *, odp_port_t odp_port,
                         const union user_action_cookie *,
			 const struct dpif_sflow_actions *);

int dpif_sflow_odp_port_to_ifindex(const struct dpif_sflow *,
                                   odp_port_t odp_port);

#endif /* ofproto/ofproto-dpif-sflow.h */
