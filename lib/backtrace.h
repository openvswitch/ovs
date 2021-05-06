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
#include "openvswitch/dynamic-string.h"

#ifdef HAVE_UNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

/* log_backtrace() will save the backtrace of a running program
 * into the log at the DEBUG level.
 *
 * To use it, insert the following code to where backtrace is
 * desired:
 *       #include "backtrace.h"
 *
 *       log_backtrace();                           <-- plain
 *       log_backtrace_msg("your message");         <-- with a message
 *
 *
 * A typical log will look like the following. The hex numbers listed after
 * "backtrace" are the addresses of the backtrace.
 *
 * 2014-03-13T23:18:11.979Z|00002|backtrace(revalidator_6)|ERR|lib/dpif-netdev.c:1312: (backtrace: 0x00521f57 0x00460365 0x00463ea4 0x0046470b 0x0043b32d 0x0043bac3 0x0043bae2 0x0043943b 0x004c22b3 0x2b5b3ac94e9a 0x2b5b3b4a33fd)
 *
 * The following bash command can be used to  view backtrace in
 * a more readable form.
 * addr2line -p -e vswitchd/ovs-vswitchd <cut-and-paste back traces>
 *
 * An typical run and output will look like:
 * addr2line -p -e vswitchd/ovs-vswitchd  0x00521f57 0x00460365 0x00463ea4
 * 0x0046470b 0x0043b32d 0x0043bac3 0x0043bae2 0x0043943b 0x004c22b3
 * 0x2b5b3ac94e9a 0x2b5b3b4a33fd
 *
 * openvswitch/lib/backtrace.c:33
 * openvswitch/lib/dpif-netdev.c:1312
 * openvswitch/lib/dpif.c:937
 * openvswitch/lib/dpif.c:1258
 * openvswitch/ofproto/ofproto-dpif-upcall.c:1440
 * openvswitch/ofproto/ofproto-dpif-upcall.c:1595
 * openvswitch/ofproto/ofproto-dpif-upcall.c:160
 * openvswitch/ofproto/ofproto-dpif-upcall.c:717
 * openvswitch/lib/ovs-thread.c:268
 * ??:0
 * ??:0
 */

#define log_backtrace() log_backtrace_at(NULL, OVS_SOURCE_LOCATOR);
#define log_backtrace_msg(msg) log_backtrace_at(msg, OVS_SOURCE_LOCATOR);

#define BACKTRACE_MAX_FRAMES 31

struct backtrace {
    int n_frames;
    uintptr_t frames[BACKTRACE_MAX_FRAMES];
};

#ifdef HAVE_UNWIND
#define UNW_MAX_DEPTH 32
#define UNW_MAX_FUNCN 32
#define UNW_MAX_BUF \
    (UNW_MAX_DEPTH * sizeof(struct unw_backtrace))

struct unw_backtrace {
    char func[UNW_MAX_FUNCN];
    unw_word_t ip;
    unw_word_t offset;
};
#endif

void backtrace_capture(struct backtrace *);
void log_backtrace_at(const char *msg, const char *where);
void log_received_backtrace(int fd);

#endif /* backtrace.h */
