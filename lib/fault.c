/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "fault.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_fault

static void
fault_handler(int sig_nr)
{
    VLOG_EMER("Caught signal %d.", sig_nr);
    log_backtrace();
    fflush(stdout);
    fflush(stderr);

    signal(sig_nr, SIG_DFL);
    raise(sig_nr);
}

void
log_backtrace(void)
{
    /* During the loop:

       frame[0] points to the next frame.
       frame[1] points to the return address. */
    void **frame;
    for (frame = __builtin_frame_address(0);
         frame != NULL && frame[0] != NULL;
         frame = frame[0]) {
        Dl_info addrinfo;
        if (!dladdr(frame[1], &addrinfo) || !addrinfo.dli_sname) {
            fprintf(stderr, "  0x%08"PRIxPTR"\n", (uintptr_t) frame[1]);
        } else {
            fprintf(stderr, "  0x%08"PRIxPTR" (%s+0x%tx)\n",
                    (uintptr_t) frame[1], addrinfo.dli_sname,
                    (char *) frame[1] - (char *) addrinfo.dli_saddr); 
        }
    }
    fflush(stderr);
}

void
register_fault_handlers(void)
{
    signal(SIGABRT, fault_handler);
    signal(SIGBUS, fault_handler);
    signal(SIGFPE, fault_handler);
    signal(SIGILL, fault_handler);
    signal(SIGSEGV, fault_handler);
}
