/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
