/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
 * Intended usage is for the program's main loop to go about its business
 * servicing whatever events it needs to.  Then, when it runs out of immediate
 * tasks, it calls each subordinate module's "wait" function, which in turn
 * calls one (or more) of the functions poll_fd_wait(), poll_immediate_wake(),
 * and poll_timer_wait() to register to be awakened when the appropriate event
 * occurs.  Then the main loop calls poll_block(), which blocks until one of
 * the registered events happens. */

#ifndef POLL_LOOP_H
#define POLL_LOOP_H 1

#include <poll.h>
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct poll_waiter;

/* Schedule events to wake up the following poll_block().
 *
 * The poll_loop logs the 'where' argument to each function at "debug" level
 * when an event causes a wakeup.  Ordinarily, it is automatically filled in
 * with the location in the source of the call, and caller should therefore
 * omit it.  But, if the function you are implementing is very generic, so that
 * its location in the source would not be very helpful for debugging, you can
 * avoid the macro expansion and pass a different argument, e.g.:
 *      (poll_fd_wait)(fd, events, where);
 * See timer_wait() for an example.
 */
struct poll_waiter *poll_fd_wait(int fd, short int events, const char *where);
#define poll_fd_wait(fd, events) poll_fd_wait(fd, events, SOURCE_LOCATOR)

void poll_timer_wait(long long int msec, const char *where);
#define poll_timer_wait(msec) poll_timer_wait(msec, SOURCE_LOCATOR)

void poll_timer_wait_until(long long int msec, const char *where);
#define poll_timer_wait_until(msec) poll_timer_wait_until(msec, SOURCE_LOCATOR)

void poll_immediate_wake(const char *where);
#define poll_immediate_wake() poll_immediate_wake(SOURCE_LOCATOR)

/* Wait until an event occurs. */
void poll_block(void);

/* Cancel a file descriptor callback or event. */
void poll_cancel(struct poll_waiter *);

#ifdef  __cplusplus
}
#endif

#endif /* poll-loop.h */
