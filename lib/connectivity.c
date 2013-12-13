/*
 * Copyright (c) 2013 Nicira, Inc.
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

#include <config.h>
#include "connectivity.h"
#include "ovs-thread.h"
#include "seq.h"

static struct seq *connectivity_seq;

/* Provides a global seq for connectivity changes.
 *
 * Connectivity monitoring modules should call seq_change() on the returned
 * object whenever the status of a port changes, whether the cause is local or
 * remote.
 *
 * Clients can seq_wait() on this object for changes to netdev flags, features,
 * ethernet addresses, carrier changes, and bfd/cfm/lacp/stp status. */
struct seq *
connectivity_seq_get(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        connectivity_seq = seq_create();
        ovsthread_once_done(&once);
    }

    return connectivity_seq;
}
