/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PINSCHED_H
#define PINSCHED_H_H 1

#include <stdint.h>

struct ofpbuf;
struct switch_status;

typedef void pinsched_tx_cb(struct ofpbuf *, void *aux);
struct pinsched *pinsched_create(int rate_limit, int burst_limit,
                                 struct switch_status *);
void pinsched_set_limits(struct pinsched *, int rate_limit, int burst_limit);
void pinsched_destroy(struct pinsched *);
void pinsched_send(struct pinsched *, uint16_t port_no, struct ofpbuf *,
                   pinsched_tx_cb *, void *aux);
void pinsched_run(struct pinsched *, pinsched_tx_cb *, void *aux);
void pinsched_wait(struct pinsched *);

#endif /* pinsched.h */
