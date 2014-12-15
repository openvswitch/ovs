/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#include <inttypes.h>

#include "backtrace.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(backtrace);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
void
backtrace_capture(struct backtrace *b)
{
    void *frames[BACKTRACE_MAX_FRAMES];
    int i;

    b->n_frames = backtrace(frames, BACKTRACE_MAX_FRAMES);
    for (i = 0; i < b->n_frames; i++) {
        b->frames[i] = (uintptr_t) frames[i];
    }
}

#else
void
backtrace_capture(struct backtrace *backtrace)
{
    backtrace->n_frames = 0;
}
#endif

static char *
backtrace_format(const struct backtrace *b, struct ds *ds)
{
    if (b->n_frames) {
        int i;

        ds_put_cstr(ds, " (backtrace:");
        for (i = 0; i < b->n_frames; i++) {
            ds_put_format(ds, " 0x%08"PRIxPTR, b->frames[i]);
        }
        ds_put_cstr(ds, ")");
    }

    return ds_cstr(ds);
}

void
log_backtrace_at(const char *msg, const char *where)
{
    struct backtrace b;
    struct ds ds = DS_EMPTY_INITIALIZER;

    backtrace_capture(&b);
    if (msg) {
        ds_put_format(&ds, "%s ", msg);
    }

    ds_put_cstr(&ds, where);
    VLOG_ERR("%s", backtrace_format(&b, &ds));

    ds_destroy(&ds);
}
