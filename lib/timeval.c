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
#include "timeval.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include "fatal-signal.h"
#include "util.h"

/* Initialized? */
static bool inited;

/* Has a timer tick occurred? */
static volatile sig_atomic_t tick;

/* The current time, as of the last refresh. */
static struct timeval now;

/* Time at which to die with SIGALRM (if not TIME_MIN). */
static time_t deadline = TIME_MIN;

static void sigalrm_handler(int);
static void refresh_if_ticked(void);
static time_t time_add(time_t, time_t);
static void block_sigalrm(sigset_t *);
static void unblock_sigalrm(const sigset_t *);

/* Initializes the timetracking module. */
void
time_init(void)
{
    struct sigaction sa;
    struct itimerval itimer;

    if (inited) {
        return;
    }

    inited = true;
    gettimeofday(&now, NULL);
    tick = false;

    /* Set up signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &sa, NULL)) {
        ofp_fatal(errno, "sigaction(SIGALRM) failed");
    }

    /* Set up periodic timer. */
    itimer.it_interval.tv_sec = 0;
    itimer.it_interval.tv_usec = TIME_UPDATE_INTERVAL * 1000;
    itimer.it_value = itimer.it_interval;
    if (setitimer(ITIMER_REAL, &itimer, NULL)) {
        ofp_fatal(errno, "setitimer failed");
    }
}

/* Forces a refresh of the current time from the kernel.  It is not usually
 * necessary to call this function, since the time will be refreshed
 * automatically at least every TIME_UPDATE_INTERVAL milliseconds. */
void
time_refresh(void)
{
    gettimeofday(&now, NULL);
    tick = false;
}

/* Returns the current time, in seconds. */
time_t
time_now(void)
{
    refresh_if_ticked();
    return now.tv_sec;
}

/* Returns the current time, in ms (within TIME_UPDATE_INTERVAL ms). */
long long int
time_msec(void)
{
    refresh_if_ticked();
    return (long long int) now.tv_sec * 1000 + now.tv_usec / 1000;
}

/* Configures the program to die with SIGALRM 'secs' seconds from now, if
 * 'secs' is nonzero, or disables the feature if 'secs' is zero. */
void
time_alarm(unsigned int secs)
{
    sigset_t oldsigs;

    time_init();
    block_sigalrm(&oldsigs);
    deadline = secs ? time_add(time_now(), secs) : TIME_MIN;
    unblock_sigalrm(&oldsigs);
}

/* Like poll(), except:
 *
 *      - On error, returns a negative error code (instead of setting errno).
 *
 *      - If interrupted by a signal, retries automatically until the original
 *        'timeout' expires.  (Because of this property, this function will
 *        never return -EINTR.)
 *
 *      - As a side effect, refreshes the current time (like time_refresh()).
 */
int
time_poll(struct pollfd *pollfds, int n_pollfds, int timeout)
{
    long long int start;
    sigset_t oldsigs;
    bool blocked;
    int retval;

    time_refresh();
    start = time_msec();
    blocked = false;
    for (;;) {
        int time_left;
        if (timeout > 0) {
            long long int elapsed = time_msec() - start;
            time_left = timeout >= elapsed ? timeout - elapsed : 0;
        } else {
            time_left = timeout;
        }

        retval = poll(pollfds, n_pollfds, time_left);
        if (retval < 0) {
            retval = -errno;
        }
        if (retval != -EINTR) {
            break;
        }

        if (!blocked && deadline == TIME_MIN) {
            block_sigalrm(&oldsigs);
            blocked = true;
        }
        time_refresh();
    }
    if (blocked) {
        unblock_sigalrm(&oldsigs);
    }
    return retval;
}

/* Returns the sum of 'a' and 'b', with saturation on overflow or underflow. */
static time_t
time_add(time_t a, time_t b)
{
    return (a >= 0
            ? (b > TIME_MAX - a ? TIME_MAX : a + b)
            : (b < TIME_MIN - a ? TIME_MIN : a + b));
}

static void
sigalrm_handler(int sig_nr)
{
    tick = true;
    if (deadline != TIME_MIN && time(0) > deadline) {
        fatal_signal_handler(sig_nr);
    }
}

static void
refresh_if_ticked(void)
{
    assert(inited);
    if (tick) {
        time_refresh();
    }
}

static void
block_sigalrm(sigset_t *oldsigs)
{
    sigset_t sigalrm;
    sigemptyset(&sigalrm);
    sigaddset(&sigalrm, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &sigalrm, oldsigs)) {
        ofp_fatal(errno, "sigprocmask");
    }
}

static void
unblock_sigalrm(const sigset_t *oldsigs)
{
    if (sigprocmask(SIG_SETMASK, oldsigs, NULL)) {
        ofp_fatal(errno, "sigprocmask");
    }
}
