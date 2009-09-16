/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#include <stdint.h>

struct pktbuf;
struct ofpbuf;

int pktbuf_capacity(void);

struct pktbuf *pktbuf_create(void);
void pktbuf_destroy(struct pktbuf *);
uint32_t pktbuf_save(struct pktbuf *, struct ofpbuf *buffer, uint16_t in_port);
uint32_t pktbuf_get_null(void);
int pktbuf_retrieve(struct pktbuf *, uint32_t id, struct ofpbuf **bufferp,
                    uint16_t *in_port);
void pktbuf_discard(struct pktbuf *, uint32_t id);

#endif /* pktbuf.h */
