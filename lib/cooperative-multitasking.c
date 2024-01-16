/*
 * Copyright (c) 2024 Canonical Ltd.
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

#include "backtrace.h"
#include "cooperative-multitasking-private.h"
#include "cooperative-multitasking.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(cooperative_multitasking);

struct hmap cooperative_multitasking_callbacks = HMAP_INITIALIZER(
    &cooperative_multitasking_callbacks);

/* Free any data allocated by calls to cooperative_multitasking_set(). */
void
cooperative_multitasking_destroy(void)
{
    struct cm_entry *cm_entry;
    HMAP_FOR_EACH_SAFE (cm_entry, node, &cooperative_multitasking_callbacks) {
        hmap_remove(&cooperative_multitasking_callbacks, &cm_entry->node);
        free(cm_entry);
    }
}

/* Set/update callback as identified by 'cb' and 'arg'.
 *
 * 'name' is used for logging events related to this callback.
 *
 * The value for 'last_run' must be updated each time the callback is run.
 *
 * Updating the value for 'threshold' may be necessary as a consequence of
 * change in runtime configuration or requirements of the part of the program
 * serviced by the callback.
 *
 * Providing a value of 0 for 'last_run' or 'threshold' will leave the stored
 * value untouched. */
void
cooperative_multitasking_set(void (*cb)(void *), void *arg,
                             long long int last_run, long long int threshold,
                             const char *name)
{
    struct cm_entry *cm_entry;

    HMAP_FOR_EACH_WITH_HASH (cm_entry, node, hash_pointer((void *) cb, 0),
                             &cooperative_multitasking_callbacks) {
        if (cm_entry->cb == cb && cm_entry->arg == arg) {
            if (last_run) {
                cm_entry->last_run = last_run;
            }

            if (threshold) {
                cm_entry->threshold = threshold;
            }
            return;
        }
    }

    cm_entry = xzalloc(sizeof *cm_entry);
    cm_entry->cb = cb;
    cm_entry->arg = arg;
    cm_entry->threshold = threshold;
    cm_entry->last_run = last_run ? last_run : time_msec();
    cm_entry->name = name;

    hmap_insert(&cooperative_multitasking_callbacks,
                &cm_entry->node, hash_pointer((void *) cm_entry->cb, 0));
}

/* Remove callback identified by 'cb' and 'arg'. */
void
cooperative_multitasking_remove(void (*cb)(void *), void *arg)
{
    struct cm_entry *cm_entry;

    HMAP_FOR_EACH_WITH_HASH (cm_entry, node, hash_pointer((void *) cb, 0),
                             &cooperative_multitasking_callbacks) {
        if (cm_entry->cb == cb && cm_entry->arg == arg) {
            hmap_remove(&cooperative_multitasking_callbacks, &cm_entry->node);
            free(cm_entry);
            return;
        }
    }
}

static void
cooperative_multitasking_yield_at__(const char *source_location)
{
    long long int start = time_msec();
    struct cm_entry *cm_entry;
    long long int elapsed;
    bool warn;

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        elapsed = time_msec() - cm_entry->last_run;

        if (elapsed >= cm_entry->threshold) {
            warn = elapsed - cm_entry->threshold > cm_entry->threshold / 8;

            VLOG(warn ? VLL_WARN : VLL_DBG, "%s: yield for %s(%p): "
                 "elapsed(%lld) >= threshold(%lld), overrun: %lld",
                 source_location, cm_entry->name, cm_entry->arg, elapsed,
                 cm_entry->threshold, elapsed - cm_entry->threshold);

            if (warn && VLOG_IS_DBG_ENABLED()) {
                log_backtrace();
            }

            (*cm_entry->cb)(cm_entry->arg);
        }
    }

    elapsed = time_msec() - start;
    if (elapsed > 1000) {
        VLOG_WARN("Unreasonably long %lldms runtime for callbacks.", elapsed);
    }
}

/* Iterate over registered callbacks and execute callbacks as demanded by the
 * recorded time threshold. */
void
cooperative_multitasking_yield_at(const char *source_location)
{
    static bool yield_in_progress = false;

    if (yield_in_progress) {
        VLOG_ERR_ONCE("Nested yield avoided, this is a bug! "
                      "Enable debug logging for more details.");
        if (VLOG_IS_DBG_ENABLED()) {
            VLOG_DBG("%s: nested yield.", source_location);
            log_backtrace();
        }
        return;
    }
    yield_in_progress = true;

    cooperative_multitasking_yield_at__(source_location);

    yield_in_progress = false;
}
