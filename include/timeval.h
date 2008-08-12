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

#ifndef TIMEVAL_H
#define TIMEVAL_H 1

#include <time.h>
#include "type-props.h"
#include "util.h"

struct pollfd;

/* POSIX allows floating-point time_t, but we don't support it. */
BUILD_ASSERT_DECL(TYPE_IS_INTEGER(time_t));

/* We do try to cater to unsigned time_t, but I want to know about it if we
 * ever encounter such a platform. */
BUILD_ASSERT_DECL(TYPE_IS_SIGNED(time_t));

#define TIME_MAX TYPE_MAXIMUM(time_t)
#define TIME_MIN TYPE_MINIMUM(time_t)

/* Interval between updates to the time reported by time_gettimeofday(), in ms.
 * This should not be adjusted much below 10 ms or so with the current
 * implementation, or too much time will be wasted in signal handlers and calls
 * to time(0). */
#define TIME_UPDATE_INTERVAL 100

void time_init(void);
void time_refresh(void);
time_t time_now(void);
long long int time_msec(void);
void time_alarm(unsigned int secs);
int time_poll(struct pollfd *, int n_pollfds, int timeout);

#endif /* timeval.h */
