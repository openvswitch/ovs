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
 * into the log at the ERROR level.
 *
 * To use it, insert the following code to where backtrace is
 * desired:
 *       #include "backtrace.h"
 *
 *       log_backtrace();                           <-- plain
 *       log_backtrace_msg("your message");         <-- with a message
 *
 *
 * A typical backtrace will look like the following example:
 * /lib64/libopenvswitch-3.1.so.0(backtrace_capture+0x1e) [0x7fc5db298dfe]
 * /lib64/libopenvswitch-3.1.so.0(log_backtrace_at+0x57) [0x7fc5db2999e7]
 * /lib64/libovsdb-3.1.so.0(ovsdb_txn_complete+0x7b) [0x7fc5db56247b]
 * /lib64/libovsdb-3.1.so.0(ovsdb_txn_propose_commit_block+0x8d)
 * [0x7fc5db563a8d]
 * ovsdb-server(+0xa661) [0x562cfce2e661]
 * ovsdb-server(+0x7e39) [0x562cfce2be39]
 * /lib64/libc.so.6(+0x27b4a) [0x7fc5db048b4a]
 * /lib64/libc.so.6(__libc_start_main+0x8b) [0x7fc5db048c0b]
 * ovsdb-server(+0x8c35) [0x562cfce2cc35]
 *
 * GDB can be used to view the exact line of the code for particular backtrace.
 * One thing to keep in mind is that the lines in source files might not
 * 100% correspond with the backtrace due to various optimizations as LTO etc.
 * (The effect can be seen in this example).
 *
 * Assuming that debuginfo for the library or binary is installed load it to
 * GDB:
 * $ gdb ovsdb-server
 * (gdb) list *(+0x7e39)
 * 0x7e39 is in main (ovsdb/ovsdb-server.c:278).
 * (gdb) list *(+0xa661)
 * 0xa661 is in commit_txn (ovsdb/ovsdb-server.c:1173)
 *
 * $ gdb /lib64/libovsdb-3.1.so.0
 * (gdb) list *(ovsdb_txn_propose_commit_block+0x8d)
 * 0x3aa8d is in ovsdb_txn_propose_commit_block (ovsdb/transaction.c:1328)
 * (gdb) list *(ovsdb_txn_complete+0x7b)
 * 0x3947b is in ovsdb_txn_complete (./include/openvswitch/list.h:321)
 *
 * $ gdb /lib64/libopenvswitch-3.1.so.0
 * (gdb) list *(log_backtrace_at+0x57)
 * 0x999e7 is in log_backtrace_at (lib/backtrace.c:77)
 * (gdb) list *(backtrace_capture+0x1e)
 * 0x98dfe is in backtrace_capture (lib/backtrace.c:35)
 */

#define log_backtrace() log_backtrace_at(NULL, OVS_SOURCE_LOCATOR);
#define log_backtrace_msg(msg) log_backtrace_at(msg, OVS_SOURCE_LOCATOR);

#define BACKTRACE_MAX_FRAMES 31
#define BACKTRACE_DUMP_MSG "SIGSEGV detected, backtrace:\n"

struct backtrace {
    int n_frames;
    void *frames[BACKTRACE_MAX_FRAMES];
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
void backtrace_format(struct ds *, const struct backtrace *,
                      const char *delimiter);
void log_received_backtrace(int fd);

#endif /* backtrace.h */
