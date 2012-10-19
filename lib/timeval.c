/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#if HAVE_EXECINFO_H
#include <execinfo.h>
#endif
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "coverage.h"
#include "dummy.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "signals.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

#ifndef HAVE_EXECINFO_H
#define HAVE_EXECINFO_H 0
#endif

VLOG_DEFINE_THIS_MODULE(timeval);

/* The clock to use for measuring time intervals.  This is CLOCK_MONOTONIC by
 * preference, but on systems that don't have a monotonic clock we fall back
 * to CLOCK_REALTIME. */
static clockid_t monotonic_clock;

/* Has a timer tick occurred? Only relevant if CACHE_TIME is true.
 *
 * We initialize these to true to force time_init() to get called on the first
 * call to time_msec() or another function that queries the current time. */
static volatile sig_atomic_t wall_tick = true;
static volatile sig_atomic_t monotonic_tick = true;

/* The current time, as of the last refresh. */
static struct timespec wall_time;
static struct timespec monotonic_time;

/* The monotonic time at which the time module was initialized. */
static long long int boot_time;

/* features for use by unit tests. */
static struct timespec warp_offset; /* Offset added to monotonic_time. */
static bool time_stopped;           /* Disables real-time updates, if true. */

/* Time in milliseconds at which to die with SIGALRM (if not LLONG_MAX). */
static long long int deadline = LLONG_MAX;

struct trace {
    void *backtrace[32]; /* Populated by backtrace(). */
    size_t n_frames;     /* Number of frames in 'backtrace'. */
};

#define MAX_TRACES 50
static struct unixctl_conn *backtrace_conn = NULL;
static struct trace *traces = NULL;
static size_t n_traces = 0;

static void set_up_timer(void);
static void set_up_signal(int flags);
static void sigalrm_handler(int);
static void refresh_wall_if_ticked(void);
static void refresh_monotonic_if_ticked(void);
static void block_sigalrm(sigset_t *);
static void unblock_sigalrm(const sigset_t *);
static void log_poll_interval(long long int last_wakeup);
static struct rusage *get_recent_rusage(void);
static void refresh_rusage(void);
static void timespec_add(struct timespec *sum,
                         const struct timespec *a, const struct timespec *b);
static void trace_run(void);
static unixctl_cb_func backtrace_cb;

/* Initializes the timetracking module, if not already initialized. */
static void
time_init(void)
{
    static bool inited;

    /* The best place to do this is probably a timeval_run() function.
     * However, none exists and this function is usually so fast that doing it
     * here seems fine for now. */
    trace_run();

    if (inited) {
        return;
    }
    inited = true;

    if (HAVE_EXECINFO_H && CACHE_TIME) {
        unixctl_command_register("backtrace", "", 0, 0, backtrace_cb, NULL);
    }

    coverage_init();

    if (!clock_gettime(CLOCK_MONOTONIC, &monotonic_time)) {
        monotonic_clock = CLOCK_MONOTONIC;
    } else {
        monotonic_clock = CLOCK_REALTIME;
        VLOG_DBG("monotonic timer not available");
    }

    set_up_signal(SA_RESTART);
    set_up_timer();

    boot_time = time_msec();
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

    if (!CACHE_TIME) {
        return;
    }

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

    if (!time_stopped) {
        if (monotonic_clock == CLOCK_MONOTONIC) {
            clock_gettime(monotonic_clock, &monotonic_time);
        } else {
            refresh_wall_if_ticked();
            monotonic_time = wall_time;
        }
        timespec_add(&monotonic_time, &monotonic_time, &warp_offset);

        monotonic_tick = false;
    }
}

/* Forces a refresh of the current time from the kernel.  It is not usually
 * necessary to call this function, since the time will be refreshed
 * automatically at least every TIME_UPDATE_INTERVAL milliseconds.  If
 * CACHE_TIME is false, we will always refresh the current time so this
 * function has no effect. */
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
    long long int now;
    long long int msecs;

    sigset_t oldsigs;

    time_init();
    time_refresh();

    now = time_msec();
    msecs = secs * 1000;

    block_sigalrm(&oldsigs);
    deadline = now < LLONG_MAX - msecs ? now + msecs : LLONG_MAX;
    unblock_sigalrm(&oldsigs);
}

/* Like poll(), except:
 *
 *      - The timeout is specified as an absolute time, as defined by
 *        time_msec(), instead of a duration.
 *
 *      - On error, returns a negative error code (instead of setting errno).
 *
 *      - If interrupted by a signal, retries automatically until the original
 *        timeout is reached.  (Because of this property, this function will
 *        never return -EINTR.)
 *
 *      - As a side effect, refreshes the current time (like time_refresh()).
 *
 * Stores the number of milliseconds elapsed during poll in '*elapsed'. */
int
time_poll(struct pollfd *pollfds, int n_pollfds, long long int timeout_when,
          int *elapsed)
{
    static long long int last_wakeup = 0;
    long long int start;
    sigset_t oldsigs;
    bool blocked;
    int retval;

    time_refresh();
    if (last_wakeup) {
        log_poll_interval(last_wakeup);
    }
    coverage_clear();
    start = time_msec();
    blocked = false;

    timeout_when = MIN(timeout_when, deadline);

    for (;;) {
        long long int now = time_msec();
        int time_left;

        if (now >= timeout_when) {
            time_left = 0;
        } else if ((unsigned long long int) timeout_when - now > INT_MAX) {
            time_left = INT_MAX;
        } else {
            time_left = timeout_when - now;
        }

        retval = poll(pollfds, n_pollfds, time_left);
        if (retval < 0) {
            retval = -errno;
        }

        time_refresh();
        if (deadline <= time_msec()) {
            fatal_signal_handler(SIGALRM);
            if (retval < 0) {
                retval = 0;
            }
            break;
        }

        if (retval != -EINTR) {
            break;
        }

        if (!blocked && CACHE_TIME && !backtrace_conn) {
            block_sigalrm(&oldsigs);
            blocked = true;
        }
    }
    if (blocked) {
        unblock_sigalrm(&oldsigs);
    }
    last_wakeup = time_msec();
    refresh_rusage();
    *elapsed = last_wakeup - start;
    return retval;
}

static void
sigalrm_handler(int sig_nr OVS_UNUSED)
{
    wall_tick = true;
    monotonic_tick = true;

#if HAVE_EXECINFO_H
    if (backtrace_conn && n_traces < MAX_TRACES) {
        struct trace *trace = &traces[n_traces++];
        trace->n_frames = backtrace(trace->backtrace,
                                    ARRAY_SIZE(trace->backtrace));
    }
#endif
}

static void
refresh_wall_if_ticked(void)
{
    if (!CACHE_TIME || wall_tick) {
        refresh_wall();
    }
}

static void
refresh_monotonic_if_ticked(void)
{
    if (!CACHE_TIME || monotonic_tick) {
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

/* Returns the monotonic time at which the "time" module was initialized, in
 * milliseconds(). */
long long int
time_boot_msec(void)
{
    time_init();
    return boot_time;
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
timespec_add(struct timespec *sum,
             const struct timespec *a,
             const struct timespec *b)
{
    struct timespec tmp;

    tmp.tv_sec = a->tv_sec + b->tv_sec;
    tmp.tv_nsec = a->tv_nsec + b->tv_nsec;
    if (tmp.tv_nsec >= 1000 * 1000 * 1000) {
        tmp.tv_nsec -= 1000 * 1000 * 1000;
        tmp.tv_sec++;
    }

    *sum = tmp;
}

static void
log_poll_interval(long long int last_wakeup)
{
    long long int interval = time_msec() - last_wakeup;

    if (interval >= 1000) {
        const struct rusage *last_rusage = get_recent_rusage();
        struct rusage rusage;

        getrusage(RUSAGE_SELF, &rusage);
        VLOG_WARN("Unreasonably long %lldms poll interval"
                  " (%lldms user, %lldms system)",
                  interval,
                  timeval_diff_msec(&rusage.ru_utime,
                                    &last_rusage->ru_utime),
                  timeval_diff_msec(&rusage.ru_stime,
                                    &last_rusage->ru_stime));
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
        coverage_log();
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

static void
trace_run(void)
{
#if HAVE_EXECINFO_H
    if (backtrace_conn && n_traces >= MAX_TRACES) {
        struct unixctl_conn *reply_conn = backtrace_conn;
        struct ds ds = DS_EMPTY_INITIALIZER;
        sigset_t oldsigs;
        size_t i;

        block_sigalrm(&oldsigs);

        for (i = 0; i < n_traces; i++) {
            struct trace *trace = &traces[i];
            char **frame_strs;
            size_t j;

            frame_strs = backtrace_symbols(trace->backtrace, trace->n_frames);

            ds_put_format(&ds, "Backtrace %zu\n", i + 1);
            for (j = 0; j < trace->n_frames; j++) {
                ds_put_format(&ds, "%s\n", frame_strs[j]);
            }
            ds_put_cstr(&ds, "\n");

            free(frame_strs);
        }

        free(traces);
        traces = NULL;
        n_traces = 0;
        backtrace_conn = NULL;

        unblock_sigalrm(&oldsigs);

        unixctl_command_reply(reply_conn, ds_cstr(&ds));
        ds_destroy(&ds);
    }
#endif
}

/* Unixctl interface. */

/* "time/stop" stops the monotonic time returned by e.g. time_msec() from
 * advancing, except due to later calls to "time/warp". */
static void
timeval_stop_cb(struct unixctl_conn *conn,
                 int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                 void *aux OVS_UNUSED)
{
    time_stopped = true;
    unixctl_command_reply(conn, NULL);
}

/* "time/warp MSECS" advances the current monotonic time by the specified
 * number of milliseconds.  Unless "time/stop" has also been executed, the
 * monotonic clock continues to tick forward at the normal rate afterward.
 *
 * Does not affect wall clock readings. */
static void
timeval_warp_cb(struct unixctl_conn *conn,
                int argc OVS_UNUSED, const char *argv[], void *aux OVS_UNUSED)
{
    struct timespec ts;
    int msecs;

    msecs = atoi(argv[1]);
    if (msecs <= 0) {
        unixctl_command_reply_error(conn, "invalid MSECS");
        return;
    }

    ts.tv_sec = msecs / 1000;
    ts.tv_nsec = (msecs % 1000) * 1000 * 1000;
    timespec_add(&warp_offset, &warp_offset, &ts);
    timespec_add(&monotonic_time, &monotonic_time, &ts);
    unixctl_command_reply(conn, "warped");
}

static void
backtrace_cb(struct unixctl_conn *conn,
             int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
             void *aux OVS_UNUSED)
{
    sigset_t oldsigs;

    assert(HAVE_EXECINFO_H && CACHE_TIME);

    if (backtrace_conn) {
        unixctl_command_reply_error(conn, "In Use");
        return;
    }
    assert(!traces);

    block_sigalrm(&oldsigs);
    backtrace_conn = conn;
    traces = xmalloc(MAX_TRACES * sizeof *traces);
    n_traces = 0;
    unblock_sigalrm(&oldsigs);
}

void
timeval_dummy_register(void)
{
    unixctl_command_register("time/stop", "", 0, 0, timeval_stop_cb, NULL);
    unixctl_command_register("time/warp", "MSECS", 1, 1,
                             timeval_warp_cb, NULL);
}
