/*
 * Copyright (c) 2009 Nicira, Inc.
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

#ifndef BACKTRACE_H
#define BACKTRACE_H 1

#include <stdint.h>

#define BACKTRACE_MAX_FRAMES 31

struct backtrace {
    int n_frames;
    uintptr_t frames[BACKTRACE_MAX_FRAMES];
};

void backtrace_capture(struct backtrace *);

#endif /* backtrace.h */
