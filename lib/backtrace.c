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

#include "backtrace.h"

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
