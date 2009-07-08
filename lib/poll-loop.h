/*
 * Copyright (c) 2008 Nicira Networks.
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
