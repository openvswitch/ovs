/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef PINSCHED_H
#define PINSCHED_H_H 1

#include <stdint.h>
#include "flow.h"

struct ovs_list;
struct ofpbuf;

struct pinsched *pinsched_create(int rate_limit, int burst_limit);
void pinsched_get_limits(const struct pinsched *,
                         int *rate_limit, int *burst_limit);
void pinsched_set_limits(struct pinsched *, int rate_limit, int burst_limit);
void pinsched_destroy(struct pinsched *);
void pinsched_send(struct pinsched *, ofp_port_t port_no, struct ofpbuf *,
                   struct ovs_list *txq);
void pinsched_run(struct pinsched *, struct ovs_list *txq);
void pinsched_wait(struct pinsched *);

struct pinsched_stats {
    unsigned int n_queued;              /* # currently queued to send. */
    unsigned long long n_normal;        /* # txed w/o rate limit queuing. */
    unsigned long long n_limited;       /* # queued for rate limiting. */
    unsigned long long n_queue_dropped; /* # dropped due to queue overflow. */
};

void pinsched_get_stats(const struct pinsched *, struct pinsched_stats *);

#endif /* pinsched.h */
