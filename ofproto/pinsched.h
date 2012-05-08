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

#ifndef PINSCHED_H
#define PINSCHED_H_H 1

#include <stdint.h>

struct ofpbuf;

typedef void pinsched_tx_cb(struct ofpbuf *, void *aux);
struct pinsched *pinsched_create(int rate_limit, int burst_limit);
void pinsched_get_limits(const struct pinsched *,
                         int *rate_limit, int *burst_limit);
void pinsched_set_limits(struct pinsched *, int rate_limit, int burst_limit);
void pinsched_destroy(struct pinsched *);
void pinsched_send(struct pinsched *, uint16_t port_no, struct ofpbuf *,
                   pinsched_tx_cb *, void *aux);
void pinsched_run(struct pinsched *, pinsched_tx_cb *, void *aux);
void pinsched_wait(struct pinsched *);

unsigned int pinsched_count_txqlen(const struct pinsched *);

#endif /* pinsched.h */
