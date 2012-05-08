/*
 * Copyright (c) 2008, 2009, 2011, 2012 Nicira, Inc.
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

#ifndef PKTBUF_H
#define PKTBUF_H 1

#include <stddef.h>
#include <stdint.h>

#include "ofp-errors.h"

struct pktbuf;
struct ofpbuf;

int pktbuf_capacity(void);

struct pktbuf *pktbuf_create(void);
void pktbuf_destroy(struct pktbuf *);
uint32_t pktbuf_save(struct pktbuf *, const void *buffer, size_t buffer_size,
                     uint16_t in_port);
uint32_t pktbuf_get_null(void);
enum ofperr pktbuf_retrieve(struct pktbuf *, uint32_t id,
                            struct ofpbuf **bufferp, uint16_t *in_port);
void pktbuf_discard(struct pktbuf *, uint32_t id);

unsigned int pktbuf_count_packets(const struct pktbuf *);

#endif /* pktbuf.h */
