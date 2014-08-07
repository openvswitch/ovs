/* Copyright (c) 2013, 2014 Nicira, Inc.
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
 * limitations under the License. */

#ifndef OFPROTO_DPIF_UPCALL_H
#define OFPROTO_DPIF_UPCALL_H

#include <stddef.h>

struct dpif;
struct dpif_backer;
struct dpif_upcall;
struct ofpbuf;
struct seq;
struct simap;

/* Udif is responsible for retrieving upcalls from the kernel and processing
 * them.  Additionally, it's responsible for maintaining the datapath flow
 * table. */

struct udpif *udpif_create(struct dpif_backer *, struct dpif *);
void udpif_run(struct udpif *udpif);
void udpif_set_threads(struct udpif *, size_t n_handlers,
                       size_t n_revalidators);
void udpif_synchronize(struct udpif *);
void udpif_destroy(struct udpif *);
void udpif_revalidate(struct udpif *);
void udpif_get_memory_usage(struct udpif *, struct simap *usage);
struct seq *udpif_dump_seq(struct udpif *);
void udpif_flush(struct udpif *);

#endif /* ofproto-dpif-upcall.h */
