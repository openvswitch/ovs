/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#include <config.h>
#include "timeval.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "coverage.h"
#include "fatal-signal.h"
#include "util.h"

#include "vlog.h"
#define THIS_MODULE VLM_timeval

/* Initialized? */
static bool inited;

/* Has a timer tick occurred? */
static volatile sig_atomic_t tick;

/* The current time, as of the last refresh. */
static struct timeval now;

/* Time at which to die with SIGALRM (if not TIME_MIN). */
static time_t deadline = TIME_MIN;

static void set_up_timer(void);
static void sigalrm_handler(int);
static void refresh_if_ticked(void);
static time_t time_add(time_t, time_t);
static void block_sigalrm(sigset_t *);
static void unblock_sigalrm(const sigset_t *);
static void log_poll_interval(long long int last_wakeup,
                              const struct rusage *last_rusage);
static long long int timeval_to_msec(const struct timeval *);

/* Initializes the timetracking module. */
void
time_init(void)
{
    struct sigaction sa;
    if (inited) {
        return;
    }

    coverage_init();

    inited = true;
    gettimeofday(&now, NULL);
    tick = false;

    /* Set up signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &sa, NULL)) {
        ovs_fatal(errno, "sigaction(SIGALRM) failed");
    }

    /* Set up periodic signal. */
    set_up_timer();
}

static void
set_up_timer(void)
{
    struct itimerval itimer;

    itimer.it_interval.tv_sec = 0;
    itimer.it_interval.tv_usec = TIME_UPDATE_INTERVAL * 1000;
    itimer.it_value = itimer.it_interval;
    if (setitimer(ITIMER_REAL, &itimer, NULL)) {
        ovs_fatal(errno, "setitimer failed");
    }
}

/* Set up the interval timer, to ensure that time advances even without calling
 * time_refresh().
 *
 * A child created with fork() does not inherit the parent's interval timer, so
 * this function needs to be called from the child after fork(). */
void
time_postfork(void)
{
    set_up_timer();
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
    return timeval_to_msec(&now);
}

/* Stores the current time, accurate within TIME_UPDATE_INTERVAL ms, into
 * '*tv'. */
void
time_timeval(struct timeval *tv)
{
    refresh_if_ticked();
    *tv = now;
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
    static long long int last_wakeup;
    static struct rusage last_rusage;
    long long int start;
    sigset_t oldsigs;
    bool blocked;
    int retval;

    time_refresh();
    log_poll_interval(last_wakeup, &last_rusage);
    coverage_clear();
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
        time_refresh();
        if (retval != -EINTR) {
            break;
        }

        if (!blocked && deadline == TIME_MIN) {
            block_sigalrm(&oldsigs);
            blocked = true;
        }
    }
    if (blocked) {
        unblock_sigalrm(&oldsigs);
    }
    last_wakeup = time_msec();
    getrusage(RUSAGE_SELF, &last_rusage);
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
        ovs_fatal(errno, "sigprocmask");
    }
}

static void
unblock_sigalrm(const sigset_t *oldsigs)
{
    if (sigprocmask(SIG_SETMASK, oldsigs, NULL)) {
        ovs_fatal(errno, "sigprocmask");
    }
}

static long long int
timeval_to_msec(const struct timeval *tv)
{
    return (long long int) tv->tv_sec * 1000 + tv->tv_usec / 1000;
}

static long long int
timeval_diff_msec(const struct timeval *a, const struct timeval *b)
{
    return timeval_to_msec(a) - timeval_to_msec(b);
}

static void
log_poll_interval(long long int last_wakeup, const struct rusage *last_rusage)
{
    static unsigned int mean_interval; /* In 16ths of a millisecond. */
    static unsigned int n_samples;

    long long int now;
    unsigned int interval;      /* In 16ths of a millisecond. */

    /* Compute interval from last wakeup to now in 16ths of a millisecond,
     * capped at 10 seconds (16000 in this unit). */
    now = time_msec();
    interval = MIN(10000, now - last_wakeup) << 4;

    /* Warn if we took too much time between polls. */
    if (n_samples > 10 && interval > mean_interval * 8) {
        struct rusage rusage;

        getrusage(RUSAGE_SELF, &rusage);
        VLOG_WARN("%u ms poll interval (%lld ms user, %lld ms system) "
                  "is over %u times the weighted mean interval %u ms "
                  "(%u samples)",
                  (interval + 8) / 16,
                  timeval_diff_msec(&rusage.ru_utime, &last_rusage->ru_utime),
                  timeval_diff_msec(&rusage.ru_stime, &last_rusage->ru_stime),
                  interval / mean_interval,
                  (mean_interval + 8) / 16, n_samples);
        if (rusage.ru_minflt > last_rusage->ru_minflt
            || rusage.ru_majflt > last_rusage->ru_majflt) {
            VLOG_WARN("faults: %ld minor, %ld major",
                      rusage.ru_minflt - last_rusage->ru_minflt,
                      rusage.ru_majflt - last_rusage->ru_majflt);
        }
        if (rusage.ru_inblock > last_rusage->ru_inblock
            || rusage.ru_oublock > last_rusage->ru_oublock) {
            VLOG_WARN("disk: %ld reads, %ld writes",
                      rusage.ru_inblock - last_rusage->ru_inblock,
                      rusage.ru_oublock - last_rusage->ru_oublock);
        }
        if (rusage.ru_nvcsw > last_rusage->ru_nvcsw
            || rusage.ru_nivcsw > last_rusage->ru_nivcsw) {
            VLOG_WARN("context switches: %ld voluntary, %ld involuntary",
                      rusage.ru_nvcsw - last_rusage->ru_nvcsw,
                      rusage.ru_nivcsw - last_rusage->ru_nivcsw);
        }

        /* Care should be taken in the value chosen for logging.  Depending 
         * on the configuration, syslog can write changes synchronously, 
         * which can cause the coverage messages to take longer to log 
         * than the processing delay that triggered it. */
        coverage_log(VLL_INFO, true);
    }

    /* Update exponentially weighted moving average.  With these parameters, a
     * given value decays to 1% of its value in about 100 time steps.  */
    if (n_samples++) {
        mean_interval = (mean_interval * 122 + interval * 6 + 64) / 128;
    } else {
        mean_interval = interval;
    }
}
