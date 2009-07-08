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

#include <config.h>
#include "backtrace.h"
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include "compiler.h"

#define THIS_MODULE VLM_backtrace
#include "vlog.h"

static uintptr_t UNUSED
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
            if (sscanf(line, "%*"SCNxPTR"-%"SCNxPTR, &end) != 1) {
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
#ifdef __i386__
    uintptr_t low;
    asm("movl %%esp,%0" : "=g" (low));
    return low;
#else
    /* This causes a warning in GCC that cannot be disabled, so use it only on
     * non-x86. */
    int dummy;
    return (uintptr_t) &dummy;
#endif
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
