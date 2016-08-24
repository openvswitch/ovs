/*
 * Copyright (c) 2009 Nicira, Inc.
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

#ifndef NETLINK_NOTIFIER_H
#define NETLINK_NOTIFIER_H 1

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

#include "openvswitch/list.h"

struct nln;
struct nln_notifier;

struct nlattr;
struct ofpbuf;

/* Function called to report netlink notifications.  'change' describes the
 * specific change filled out by an nln_parse_func.  It may be null if the
 * buffer of change information overflowed, in which case the function must
 * assume that everything may have changed. 'aux' is as specified in
 * nln_notifier_register(). */
typedef void nln_notify_func(const void *change, void *aux);

/* Function called to parse incoming nln notifications.  The 'buf' message
 * should be parsed into 'change' as specified in nln_create().
 * Returns the multicast_group the change belongs to, or 0 for a parse error.
 */
typedef int nln_parse_func(struct ofpbuf *buf, void *change);

struct nln *nln_create(int protocol, nln_parse_func *, void *change);
void nln_destroy(struct nln *);
struct nln_notifier *nln_notifier_create(struct nln *, int multicast_group,
                                         nln_notify_func *, void *aux);
void nln_notifier_destroy(struct nln_notifier *);
void nln_run(struct nln *);
void nln_wait(struct nln *);
#endif /* netlink-notifier.h */
