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

#ifndef DISCOVERY_H
#define DISCOVERY_H 1

#include <stdbool.h>

struct dpif;
struct discovery;
struct settings;
struct switch_status;

int discovery_create(const char *accept_controller_re, bool update_resolv_conf,
                     struct dpif *, struct switch_status *,
                     struct discovery **);
void discovery_destroy(struct discovery *);
void discovery_set_update_resolv_conf(struct discovery *,
                                      bool update_resolv_conf);
int discovery_set_accept_controller_re(struct discovery *, const char *re);
void discovery_question_connectivity(struct discovery *);
bool discovery_run(struct discovery *, char **controller_name);
void discovery_wait(struct discovery *);

#endif /* discovery.h */
