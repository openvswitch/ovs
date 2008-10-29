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

/* High-level wrapper around the "poll" system call.
 *
 * Intended usage is for the program's main loop to go about its business
 * servicing whatever events it needs to.  Then, when it runs out of immediate
 * tasks, it calls each subordinate module's "wait" function, which in turn
 * calls one (or more) of the functions poll_fd_wait(), poll_immediate_wake(),
 * and poll_timer_wait() to register to be awakened when the appropriate event
 * occurs.  Then the main loop calls poll_block(), which blocks until one of
 * the registered events happens.
 *
 * There is also some support for autonomous subroutines that are executed by
 * poll_block() when a file descriptor becomes ready.  To prevent these
 * routines from starving if events are continuously ready, the application
 * should bound the amount of work it does between poll_block() calls. */

#ifndef POLL_LOOP_H
#define POLL_LOOP_H 1

#include <poll.h>

struct poll_waiter;

/* Schedule events to wake up the following poll_block(). */
struct poll_waiter *poll_fd_wait(int fd, short int events);
void poll_timer_wait(int msec);
void poll_immediate_wake(void);

/* Wait until an event occurs. */
void poll_block(void);

/* Autonomous function callbacks. */
typedef void poll_fd_func(int fd, short int revents, void *aux);
struct poll_waiter *poll_fd_callback(int fd, short int events,
                                     poll_fd_func *, void *aux);

/* Cancel a file descriptor callback or event. */
void poll_cancel(struct poll_waiter *);

#endif /* poll-loop.h */
