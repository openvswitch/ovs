/*
 * Copyright (c) 2019 Ilya Maximets <i.maximets@ovn.org>.
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
#include "openvswitch/compiler.h"
#include "openvswitch/thread.h"
#include "openvswitch/util.h"
#include "if-notifier.h"

/* Implementation of a manual interface notifier.
 *
 * Intended for catching interface events that could not be tracked by
 * OS specific interface notifiers, e.g. iface updates in netdev-dpdk.
 * For that purpose 'if_notifier_manual_report()' should be called directly
 * by the code that aware of interface changes.
 *
 * Thread-safety
 * =============
 * This notifier is thread-safe in terms of calling its functions from
 * different thread contexts,  however if the callback passed to
 * 'if_notifier_manual_set_cb' is used by some other code (i.e. by OS
 * specific notifiers) it must be thread-safe itself.
 */

static struct ovs_mutex manual_notifier_mutex = OVS_MUTEX_INITIALIZER;
static if_notify_func *notify OVS_GUARDED_BY(manual_notifier_mutex) = NULL;

void
if_notifier_manual_set_cb(if_notify_func *cb)
{
    ovs_mutex_lock(&manual_notifier_mutex);
    notify = cb;
    ovs_mutex_unlock(&manual_notifier_mutex);
}

void
if_notifier_manual_report(void)
{
    ovs_mutex_lock(&manual_notifier_mutex);
    if (notify) {
        notify(NULL);
    }
    ovs_mutex_unlock(&manual_notifier_mutex);
}
