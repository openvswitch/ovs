/*
 * Copyright (c) 2011 Gaetano Catalli.
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

#ifndef RTBSD_H
#define RTBSD_H 1

#include "list.h"

/*
 * A digested version of a message received from a PF_ROUTE socket which
 * indicates that a network device has been created or destroyed or changed.
 */
struct rtbsd_change {
    /* Copied from struct if_msghdr. */
    int msg_type;             /* e.g. XXX. */

    /* Copied from struct if_msghdr. */
    int if_index;              /* Index of network device. */

    char if_name[IF_NAMESIZE];         /* Name of network device. */
    int master_ifindex;         /* Ifindex of datapath master (0 if none). */
};

/*
 * Function called to report that a netdev has changed.  'change' describes the
 * specific change.  It may be null if the buffer of change information
 * overflowed, in which case the function must assume that every device may
 * have changed.  'aux' is as specified in the call to
 * rtbsd_notifier_register().
 */
typedef void rtbsd_notify_func(const struct rtbsd_change *, void *aux);

struct rtbsd_notifier {
    struct list node;
    rtbsd_notify_func *cb;
    void *aux;
};

int rtbsd_notifier_register(struct rtbsd_notifier *,
                                rtbsd_notify_func *, void *aux);
void rtbsd_notifier_unregister(struct rtbsd_notifier *);
void rtbsd_notifier_run(void);
void rtbsd_notifier_wait(void);

#endif /* rtbsd.h */
