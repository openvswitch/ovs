/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

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

void
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
            fprintf(stderr, "  0x%08"PRIxPTR" (%s+0x%x)\n",
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
