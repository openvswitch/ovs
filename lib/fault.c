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
