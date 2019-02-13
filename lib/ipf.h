/*
 * Copyright (c) 2019 Nicira, Inc.
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

#ifndef IPF_H
#define IPF_H 1

#include "dp-packet.h"
#include "openvswitch/types.h"

struct ipf;

struct ipf_proto_status {
   uint64_t nfrag_accepted;
   uint64_t nfrag_completed_sent;
   uint64_t nfrag_expired_sent;
   uint64_t nfrag_too_small;
   uint64_t nfrag_overlap;
   uint64_t nfrag_purged;
   unsigned int min_frag_size;
   bool enabled;
};

struct ipf_status {
   struct ipf_proto_status v4;
   struct ipf_proto_status v6;
   unsigned int nfrag;
   unsigned int nfrag_max;
};

struct ipf *ipf_init(void);
void ipf_destroy(struct ipf *ipf);
void ipf_preprocess_conntrack(struct ipf *ipf, struct dp_packet_batch *pb,
                              long long now, ovs_be16 dl_type, uint16_t zone,
                              uint32_t hash_basis);

void ipf_postprocess_conntrack(struct ipf *ipf, struct dp_packet_batch *pb,
                               long long now, ovs_be16 dl_type);

int ipf_set_enabled(struct ipf *ipf, bool v6, bool enable);
int ipf_set_min_frag(struct ipf *ipf, bool v6, uint32_t value);
int ipf_set_max_nfrags(struct ipf *ipf, uint32_t value);
int ipf_get_status(struct ipf *ipf, struct ipf_status *ipf_status);

struct ipf_dump_ctx;
int ipf_dump_start(struct ipf_dump_ctx **ipf_dump_ctx);
int ipf_dump_next(struct ipf *ipf, struct ipf_dump_ctx *ipf_dump_ctx,
                  char **dump);
int ipf_dump_done(struct ipf_dump_ctx *ipf_dump_ctx);

#endif /* ipf.h */
