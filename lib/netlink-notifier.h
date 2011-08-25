/*
 * Copyright (c) 2009 Nicira Networks.
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

#ifndef RTNETLINK_H
#define RTNETLINK_H 1

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

#include "list.h"

struct rtnetlink;
struct nlattr;
struct ofpbuf;

/* Function called to report rtnetlink notifications.  'change' describes the
 * specific change filled out by an rtnetlink_parse_func.  It may be null if
 * the buffer of change information overflowed, in which case the function must
 * assume that everything may have changed. 'aux' is as specified in
 * rtnetlink_notifier_register().
 */
typedef void rtnetlink_notify_func(const void *change, void *aux);

/* Function called to parse incoming rtnetlink notifications.  The 'buf'
 * message should be parsed into 'change' as specified in rtnetlink_create().
 */
typedef bool rtnetlink_parse_func(struct ofpbuf *buf, void *change);

struct rtnetlink_notifier {
    struct list node;
    rtnetlink_notify_func *cb;
    void *aux;
};

struct rtnetlink *rtnetlink_create(int multicast_group,
                                   rtnetlink_parse_func *,
                                   void *change);
void rtnetlink_destroy(struct rtnetlink *rtn);
int rtnetlink_notifier_register(struct rtnetlink *,
                                struct rtnetlink_notifier *,
                                rtnetlink_notify_func *, void *aux);
void rtnetlink_notifier_unregister(struct rtnetlink *,
                                   struct rtnetlink_notifier *);
void rtnetlink_notifier_run(struct rtnetlink *);
void rtnetlink_notifier_wait(struct rtnetlink *);
#endif /* rtnetlink.h */
