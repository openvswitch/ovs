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

#ifndef FAIL_OPEN_H
#define FAIL_OPEN_H 1

#include <stdbool.h>
#include <stdint.h>
#include "flow.h"

struct fail_open;
struct ofproto;
struct rconn;
struct switch_status;

struct fail_open *fail_open_create(struct ofproto *, int trigger_duration,
                                   struct switch_status *,
                                   struct rconn *controller);
void fail_open_set_trigger_duration(struct fail_open *, int trigger_duration);
void fail_open_destroy(struct fail_open *);
void fail_open_wait(struct fail_open *);
void fail_open_run(struct fail_open *);
void fail_open_flushed(struct fail_open *);

#endif /* fail-open.h */
