/*
 * Copyright (c) 2015 Red Hat, Inc.
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
#include "if-notifier.h"
#include "rtbsd.h"
#include "util.h"

struct if_notifier {
    struct rtbsd_notifier notifier;
    if_notify_func *cb;
    void *aux;
};

static void
if_notifier_cb(const struct rtbsd_change *change OVS_UNUSED, void *aux)
{
    struct if_notifier *notifier;
    notifier = aux;
    notifier->cb(notifier->aux);
}

struct if_notifier *
if_notifier_create(if_notify_func *cb, void *aux)
{
    struct if_notifier *notifier;
    int ret;
    notifier = xzalloc(sizeof *notifier);
    notifier->cb = cb;
    notifier->aux = aux;
    ret = rtbsd_notifier_register(&notifier->notifier, if_notifier_cb,
                                  notifier);
    if (ret) {
        free(notifier);
        return NULL;
    }
    return notifier;
}

void
if_notifier_destroy(struct if_notifier *notifier)
{
    if (notifier) {
        rtbsd_notifier_unregister(&notifier->notifier);
        free(notifier);
    }
}

void
if_notifier_run(void)
{
    rtbsd_notifier_run();
}

void
if_notifier_wait(void)
{
    rtbsd_notifier_wait();
}
