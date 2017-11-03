/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2017 Nicira, Inc.
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

/* High-level wrapper around the "poll" system call.
 *
 * The intended usage is for each thread's main loop to go about its business
 * servicing whatever events it needs to.  Then, when it runs out of immediate
 * tasks, it calls each subordinate module's "wait" function, which in turn
 * calls one (or more) of the functions poll_fd_wait(), poll_immediate_wake(),
 * and poll_timer_wait() to register to be awakened when the appropriate event
 * occurs.  Then the main loop calls poll_block(), which blocks until one of
 * the registered events happens.
 *
 *
 * Thread-safety
 * =============
 *
 * The poll set is per-thread, so all functions in this module are thread-safe.
 */
#ifndef POLL_LOOP_H
#define POLL_LOOP_H 1

#ifndef _WIN32
#include <poll.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif


/* Schedule events to wake up the following poll_block().
 *
 * The poll_loop logs the 'where' argument to each function at "debug" level
 * when an event causes a wakeup.  Each of these ways to schedule an event has
 * a function and a macro wrapper.  The macro version automatically supplies
 * the source code location of the caller.  The function version allows the
 * caller to supply a location explicitly, which is useful if the caller's own
 * caller would be more useful in log output.  See timer_wait_at() for an
 * example. */
void poll_fd_wait_at(int fd, short int events, const char *where);
#define poll_fd_wait(fd, events) poll_fd_wait_at(fd, events, OVS_SOURCE_LOCATOR)

#ifdef _WIN32
void poll_wevent_wait_at(HANDLE wevent, const char *where);
#define poll_wevent_wait(wevent) poll_wevent_wait_at(wevent, OVS_SOURCE_LOCATOR)
#endif /* _WIN32 */

void poll_timer_wait_at(long long int msec, const char *where);
#define poll_timer_wait(msec) poll_timer_wait_at(msec, OVS_SOURCE_LOCATOR)

void poll_timer_wait_until_at(long long int msec, const char *where);
#define poll_timer_wait_until(msec)             \
    poll_timer_wait_until_at(msec, OVS_SOURCE_LOCATOR)

void poll_immediate_wake_at(const char *where);
#define poll_immediate_wake() poll_immediate_wake_at(OVS_SOURCE_LOCATOR)

/* Wait until an event occurs. */
void poll_block(void);

#ifdef  __cplusplus
}
#endif

#endif /* poll-loop.h */
