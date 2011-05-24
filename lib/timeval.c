/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include "signals.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(timeval);

/* The clock to use for measuring time intervals.  This is CLOCK_MONOTONIC by
 * preference, but on systems that don't have a monotonic clock we fall back
 * to CLOCK_REALTIME. */
static clockid_t monotonic_clock;

/* Has a timer tick occurred?
 *
 * We initialize these to true to force time_init() to get called on the first
 * call to time_msec() or another function that queries the current time. */
static volatile sig_atomic_t wall_tick = true;
static volatile sig_atomic_t monotonic_tick = true;

/* The current time, as of the last refresh. */
static struct timespec wall_time;
static struct timespec monotonic_time;

/* Time at which to die with SIGALRM (if not TIME_MIN). */
static time_t deadline = TIME_MIN;

static void set_up_timer(void);
static void set_up_signal(int flags);
static void sigalrm_handler(int);
static void refresh_wall_if_ticked(void);
static void refresh_monotonic_if_ticked(void);
static time_t time_add(time_t, time_t);
static void block_sigalrm(sigset_t *);
static void unblock_sigalrm(const sigset_t *);
static void log_poll_interval(long long int last_wakeup);
static struct rusage *get_recent_rusage(void);
static void refresh_rusage(void);

/* Initializes the timetracking module.
 *
 * It is not necessary to call this function directly, because other time
 * functions will call it automatically, but it doesn't hurt. */
static void
time_init(void)
{
    static bool inited;
    if (inited) {
        return;
    }
    inited = true;

    coverage_init();

    if (!clock_gettime(CLOCK_MONOTONIC, &monotonic_time)) {
        monotonic_clock = CLOCK_MONOTONIC;
    } else {
        monotonic_clock = CLOCK_REALTIME;
        VLOG_DBG("monotonic timer not available");
    }

    set_up_signal(SA_RESTART);
    set_up_timer();
}

static void
set_up_signal(int flags)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = flags;
    xsigaction(SIGALRM, &sa, NULL);
}

/* Remove SA_RESTART from the flags for SIGALRM, so that any system call that
 * is interrupted by the periodic timer interrupt will return EINTR instead of
 * continuing after the signal handler returns.
 *
 * time_disable_restart() and time_enable_restart() may be usefully wrapped
 * around function calls that might otherwise block forever unless interrupted
 * by a signal, e.g.:
 *
 *   time_disable_restart();
 *   fcntl(fd, F_SETLKW, &lock);
 *   time_enable_restart();
 */
void
time_disable_restart(void)
{
    time_init();
    set_up_signal(0);
}

/* Add SA_RESTART to the flags for SIGALRM, so that any system call that
 * is interrupted by the periodic timer interrupt will continue after the
 * signal handler returns instead of returning EINTR. */
void
time_enable_restart(void)
{
    time_init();
    set_up_signal(SA_RESTART);
}

static void
set_up_timer(void)
{
    static timer_t timer_id;    /* "static" to avoid apparent memory leak. */
    struct itimerspec itimer;

    if (timer_create(monotonic_clock, NULL, &timer_id)) {
        VLOG_FATAL("timer_create failed (%s)", strerror(errno));
    }

    itimer.it_interval.tv_sec = 0;
    itimer.it_interval.tv_nsec = TIME_UPDATE_INTERVAL * 1000 * 1000;
    itimer.it_value = itimer.it_interval;

    if (timer_settime(timer_id, 0, &itimer, NULL)) {
        VLOG_FATAL("timer_settime failed (%s)", strerror(errno));
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
    time_init();
    set_up_timer();
}

static void
refresh_wall(void)
{
    time_init();
    clock_gettime(CLOCK_REALTIME, &wall_time);
    wall_tick = false;
}

static void
refresh_monotonic(void)
{
    time_init();

    if (monotonic_clock == CLOCK_MONOTONIC) {
        clock_gettime(monotonic_clock, &monotonic_time);
    } else {
        refresh_wall_if_ticked();
        monotonic_time = wall_time;
    }

    monotonic_tick = false;
}

/* Forces a refresh of the current time from the kernel.  It is not usually
 * necessary to call this function, since the time will be refreshed
 * automatically at least every TIME_UPDATE_INTERVAL milliseconds. */
void
time_refresh(void)
{
    wall_tick = monotonic_tick = true;
}

/* Returns a monotonic timer, in seconds. */
time_t
time_now(void)
{
    refresh_monotonic_if_ticked();
    return monotonic_time.tv_sec;
}

/* Same as time_now() except does not write to static variables, for use in
 * signal handlers.  */
static time_t
time_now_sig(void)
{
    struct timespec cur_time;

    clock_gettime(monotonic_clock, &cur_time);
    return cur_time.tv_sec;
}

/* Returns the current time, in seconds. */
time_t
time_wall(void)
{
    refresh_wall_if_ticked();
    return wall_time.tv_sec;
}

/* Returns a monotonic timer, in ms (within TIME_UPDATE_INTERVAL ms). */
long long int
time_msec(void)
{
    refresh_monotonic_if_ticked();
    return timespec_to_msec(&monotonic_time);
}

/* Returns the current time, in ms (within TIME_UPDATE_INTERVAL ms). */
long long int
time_wall_msec(void)
{
    refresh_wall_if_ticked();
    return timespec_to_msec(&wall_time);
}

/* Stores a monotonic timer, accurate within TIME_UPDATE_INTERVAL ms, into
 * '*ts'. */
void
time_timespec(struct timespec *ts)
{
    refresh_monotonic_if_ticked();
    *ts = monotonic_time;
}

/* Stores the current time, accurate within TIME_UPDATE_INTERVAL ms, into
 * '*ts'. */
void
time_wall_timespec(struct timespec *ts)
{
    refresh_wall_if_ticked();
    *ts = wall_time;
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
    long long int start;
    sigset_t oldsigs;
    bool blocked;
    int retval;

    time_refresh();
    log_poll_interval(last_wakeup);
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
    refresh_rusage();
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
    wall_tick = true;
    monotonic_tick = true;
    if (deadline != TIME_MIN && time_now_sig() > deadline) {
        fatal_signal_handler(sig_nr);
    }
}

static void
refresh_wall_if_ticked(void)
{
    if (wall_tick) {
        refresh_wall();
    }
}

static void
refresh_monotonic_if_ticked(void)
{
    if (monotonic_tick) {
        refresh_monotonic();
    }
}

static void
block_sigalrm(sigset_t *oldsigs)
{
    sigset_t sigalrm;
    sigemptyset(&sigalrm);
    sigaddset(&sigalrm, SIGALRM);
    xsigprocmask(SIG_BLOCK, &sigalrm, oldsigs);
}

static void
unblock_sigalrm(const sigset_t *oldsigs)
{
    xsigprocmask(SIG_SETMASK, oldsigs, NULL);
}

long long int
timespec_to_msec(const struct timespec *ts)
{
    return (long long int) ts->tv_sec * 1000 + ts->tv_nsec / (1000 * 1000);
}

long long int
timeval_to_msec(const struct timeval *tv)
{
    return (long long int) tv->tv_sec * 1000 + tv->tv_usec / 1000;
}

void
xgettimeofday(struct timeval *tv)
{
    if (gettimeofday(tv, NULL) == -1) {
        VLOG_FATAL("gettimeofday failed (%s)", strerror(errno));
    }
}

static long long int
timeval_diff_msec(const struct timeval *a, const struct timeval *b)
{
    return timeval_to_msec(a) - timeval_to_msec(b);
}

static void
log_poll_interval(long long int last_wakeup)
{
    static unsigned int mean_interval; /* In 16ths of a millisecond. */
    static unsigned int n_samples;

    long long int now;
    unsigned int interval;      /* In 16ths of a millisecond. */

    /* Compute interval from last wakeup to now in 16ths of a millisecond,
     * capped at 10 seconds (16000 in this unit). */
    now = time_msec();
    interval = MIN(10000, now - last_wakeup) << 4;

    /* Warn if we took too much time between polls: at least 50 ms and at least
     * 8X the mean interval. */
    if (n_samples > 10 && interval > mean_interval * 8 && interval > 50 * 16) {
        const struct rusage *last_rusage = get_recent_rusage();
        struct rusage rusage;

        getrusage(RUSAGE_SELF, &rusage);
        VLOG_WARN("%lld ms poll interval (%lld ms user, %lld ms system) "
                  "is over %u times the weighted mean interval %u ms "
                  "(%u samples)",
                  now - last_wakeup,
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

/* CPU usage tracking. */

struct cpu_usage {
    long long int when;         /* Time that this sample was taken. */
    unsigned long long int cpu; /* Total user+system CPU usage when sampled. */
};

static struct rusage recent_rusage;
static struct cpu_usage older = { LLONG_MIN, 0 };
static struct cpu_usage newer = { LLONG_MIN, 0 };
static int cpu_usage = -1;

static struct rusage *
get_recent_rusage(void)
{
    return &recent_rusage;
}

static void
refresh_rusage(void)
{
    long long int now;

    now = time_msec();
    getrusage(RUSAGE_SELF, &recent_rusage);

    if (now >= newer.when + 3 * 1000) {
        older = newer;
        newer.when = now;
        newer.cpu = (timeval_to_msec(&recent_rusage.ru_utime) +
                     timeval_to_msec(&recent_rusage.ru_stime));

        if (older.when != LLONG_MIN && newer.cpu > older.cpu) {
            unsigned int dividend = newer.cpu - older.cpu;
            unsigned int divisor = (newer.when - older.when) / 100;
            cpu_usage = divisor > 0 ? dividend / divisor : -1;
        } else {
            cpu_usage = -1;
        }
    }
}

/* Returns an estimate of this process's CPU usage, as a percentage, over the
 * past few seconds of wall-clock time.  Returns -1 if no estimate is available
 * (which will happen if the process has not been running long enough to have
 * an estimate, and can happen for other reasons as well). */
int
get_cpu_usage(void)
{
    return cpu_usage;
}
