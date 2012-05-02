/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "compiler.h"
#include "vlog.h"

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
#elif __GNUC__
static uintptr_t
get_max_stack(void)
{
    static const char file_name[] = "/proc/self/maps";
    char line[1024];
    int line_number;
    FILE *f;

    f = fopen(file_name, "r");
    if (f == NULL) {
        VLOG_WARN("opening %s failed: %s", file_name, strerror(errno));
        return -1;
    }

    for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
        if (strstr(line, "[stack]")) {
            uintptr_t end;
            if (sscanf(line, "%*x-%"SCNxPTR, &end) != 1) {
                VLOG_WARN("%s:%d: parse error", file_name, line_number);
                continue;
            }
            fclose(f);
            return end;
        }
    }
    fclose(f);

    VLOG_WARN("%s: no stack found", file_name);
    return -1;
}

static uintptr_t
stack_high(void)
{
    static uintptr_t high;
    if (!high) {
        high = get_max_stack();
    }
    return high;
}

static uintptr_t
stack_low(void)
{
    uintptr_t low = (uintptr_t) &low;
    return low;
}

static bool
in_stack(void *p)
{
    uintptr_t address = (uintptr_t) p;
    return address >= stack_low() && address < stack_high();
}

void
backtrace_capture(struct backtrace *backtrace)
{
    void **frame;
    size_t n;

    n = 0;
    for (frame = __builtin_frame_address(1);
         frame != NULL && in_stack(frame) && frame[0] != NULL
             && n < BACKTRACE_MAX_FRAMES;
         frame = frame[0])
    {
        backtrace->frames[n++] = (uintptr_t) frame[1];
    }
    backtrace->n_frames = n;
}
#else  /* !HAVE_BACKTRACE && !__GNUC__ */
void
backtrace_capture(struct backtrace *backtrace)
{
    backtrace->n_frames = 0;
}
#endif
