/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include <errno.h>
#include <poll.h>
#include <pthread.h>
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
#include "hash.h"
#include "hmap.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "signals.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(timeval);

#ifdef _WIN32
typedef unsigned int clockid_t;

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 2
#endif

/* Number of 100 ns intervals from January 1, 1601 till January 1, 1970. */
static ULARGE_INTEGER unix_epoch;
#endif /* _WIN32 */

struct clock {
    clockid_t id;               /* CLOCK_MONOTONIC or CLOCK_REALTIME. */

    /* Features for use by unit tests.  Protected by 'mutex'. */
    struct ovs_mutex mutex;
    atomic_bool slow_path;             /* True if warped or stopped. */
    struct timespec warp OVS_GUARDED;  /* Offset added for unit tests. */
    bool stopped OVS_GUARDED;          /* Disable real-time updates if true. */
    struct timespec cache OVS_GUARDED; /* Last time read from kernel. */
};

/* Our clocks. */
static struct clock monotonic_clock; /* CLOCK_MONOTONIC, if available. */
static struct clock wall_clock;      /* CLOCK_REALTIME. */

/* The monotonic time at which the time module was initialized. */
static long long int boot_time;

/* True only when timeval_dummy_register() is called. */
static bool timewarp_enabled;
/* Reference to the seq struct.  Threads other than main thread can
 * wait on timewarp_seq and be waken up when time is warped. */
static struct seq *timewarp_seq;
/* Last value of 'timewarp_seq'. */
DEFINE_STATIC_PER_THREAD_DATA(uint64_t, last_seq, 0);

/* Monotonic time in milliseconds at which to die with SIGALRM (if not
 * LLONG_MAX). */
static long long int deadline = LLONG_MAX;

/* Monotonic time, in milliseconds, at which the last call to time_poll() woke
 * up. */
DEFINE_STATIC_PER_THREAD_DATA(long long int, last_wakeup, 0);

static void log_poll_interval(long long int last_wakeup);
static struct rusage *get_recent_rusage(void);
static void refresh_rusage(void);
static void timespec_add(struct timespec *sum,
                         const struct timespec *a, const struct timespec *b);

static void
init_clock(struct clock *c, clockid_t id)
{
    memset(c, 0, sizeof *c);
    c->id = id;
    ovs_mutex_init(&c->mutex);
    atomic_init(&c->slow_path, false);
    xclock_gettime(c->id, &c->cache);
    timewarp_seq = seq_create();
}

static void
do_init_time(void)
{
    struct timespec ts;

#ifdef _WIN32
    /* Calculate number of 100-nanosecond intervals till 01/01/1970. */
    SYSTEMTIME unix_epoch_st = { 1970, 1, 0, 1, 0, 0, 0, 0};
    FILETIME unix_epoch_ft;

    SystemTimeToFileTime(&unix_epoch_st, &unix_epoch_ft);
    unix_epoch.LowPart = unix_epoch_ft.dwLowDateTime;
    unix_epoch.HighPart = unix_epoch_ft.dwHighDateTime;
#endif

    coverage_init();

    init_clock(&monotonic_clock, (!clock_gettime(CLOCK_MONOTONIC, &ts)
                                  ? CLOCK_MONOTONIC
                                  : CLOCK_REALTIME));
    init_clock(&wall_clock, CLOCK_REALTIME);
    boot_time = timespec_to_msec(&monotonic_clock.cache);
}

/* Initializes the timetracking module, if not already initialized. */
static void
time_init(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, do_init_time);
}

static void
time_timespec__(struct clock *c, struct timespec *ts)
{
    bool slow_path;

    time_init();

    atomic_read_explicit(&c->slow_path, &slow_path, memory_order_relaxed);
    if (!slow_path) {
        xclock_gettime(c->id, ts);
    } else {
        struct timespec warp;
        struct timespec cache;
        bool stopped;

        ovs_mutex_lock(&c->mutex);
        stopped = c->stopped;
        warp = c->warp;
        cache = c->cache;
        ovs_mutex_unlock(&c->mutex);

        if (!stopped) {
            xclock_gettime(c->id, &cache);
        }
        timespec_add(ts, &cache, &warp);
    }
}

/* Stores a monotonic timer, accurate within TIME_UPDATE_INTERVAL ms, into
 * '*ts'. */
void
time_timespec(struct timespec *ts)
{
    time_timespec__(&monotonic_clock, ts);
}

/* Stores the current time, accurate within TIME_UPDATE_INTERVAL ms, into
 * '*ts'. */
void
time_wall_timespec(struct timespec *ts)
{
    time_timespec__(&wall_clock, ts);
}

static time_t
time_sec__(struct clock *c)
{
    struct timespec ts;

    time_timespec__(c, &ts);
    return ts.tv_sec;
}

/* Returns a monotonic timer, in seconds. */
time_t
time_now(void)
{
    return time_sec__(&monotonic_clock);
}

/* Returns the current time, in seconds. */
time_t
time_wall(void)
{
    return time_sec__(&wall_clock);
}

static long long int
time_msec__(struct clock *c)
{
    struct timespec ts;

    time_timespec__(c, &ts);
    return timespec_to_msec(&ts);
}

/* Returns a monotonic timer, in ms (within TIME_UPDATE_INTERVAL ms). */
long long int
time_msec(void)
{
    return time_msec__(&monotonic_clock);
}

/* Returns the current time, in ms (within TIME_UPDATE_INTERVAL ms). */
long long int
time_wall_msec(void)
{
    return time_msec__(&wall_clock);
}

/* Configures the program to die with SIGALRM 'secs' seconds from now, if
 * 'secs' is nonzero, or disables the feature if 'secs' is zero. */
void
time_alarm(unsigned int secs)
{
    long long int now;
    long long int msecs;

    assert_single_threaded();
    time_init();

    now = time_msec();
    msecs = secs * 1000LL;
    deadline = now < LLONG_MAX - msecs ? now + msecs : LLONG_MAX;
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
 * Stores the number of milliseconds elapsed during poll in '*elapsed'. */
int
time_poll(struct pollfd *pollfds, int n_pollfds, HANDLE *handles OVS_UNUSED,
          long long int timeout_when, int *elapsed)
{
    long long int *last_wakeup = last_wakeup_get();
    long long int start;
    bool quiescent;
    int retval = 0;

    time_init();
    coverage_clear();
    coverage_run();
    if (*last_wakeup) {
        log_poll_interval(*last_wakeup);
    }
    start = time_msec();

    timeout_when = MIN(timeout_when, deadline);
    quiescent = ovsrcu_is_quiescent();

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

        if (!quiescent) {
            if (!time_left) {
                ovsrcu_quiesce();
            } else {
                ovsrcu_quiesce_start();
            }
        }

#ifndef _WIN32
        retval = poll(pollfds, n_pollfds, time_left);
        if (retval < 0) {
            retval = -errno;
        }
#else
        if (n_pollfds > MAXIMUM_WAIT_OBJECTS) {
            VLOG_ERR("Cannot handle more than maximum wait objects\n");
        } else if (n_pollfds != 0) {
            retval = WaitForMultipleObjects(n_pollfds, handles, FALSE,
                                            time_left);
        }
        if (retval < 0) {
            /* XXX This will be replace by a win error to errno
               conversion function */
            retval = -WSAGetLastError();
            retval = -EINVAL;
        }
#endif

        if (!quiescent && time_left) {
            ovsrcu_quiesce_end();
        }

        if (deadline <= time_msec()) {
#ifndef _WIN32
            fatal_signal_handler(SIGALRM);
#else
            VLOG_ERR("wake up from WaitForMultipleObjects after deadline");
            fatal_signal_handler(SIGTERM);
#endif
            if (retval < 0) {
                retval = 0;
            }
            break;
        }

        if (retval != -EINTR) {
            break;
        }
    }
    *last_wakeup = time_msec();
    refresh_rusage();
    *elapsed = *last_wakeup - start;
    return retval;
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
 * milliseconds. */
long long int
time_boot_msec(void)
{
    time_init();
    return boot_time;
}

#ifdef _WIN32
static ULARGE_INTEGER
xgetfiletime(void)
{
    ULARGE_INTEGER current_time;
    FILETIME current_time_ft;

    /* Returns current time in UTC as a 64-bit value representing the number
     * of 100-nanosecond intervals since January 1, 1601 . */
    GetSystemTimePreciseAsFileTime(&current_time_ft);
    current_time.LowPart = current_time_ft.dwLowDateTime;
    current_time.HighPart = current_time_ft.dwHighDateTime;

    return current_time;
}

static int
clock_gettime(clock_t id, struct timespec *ts)
{
    if (id == CLOCK_MONOTONIC) {
        static LARGE_INTEGER freq;
        LARGE_INTEGER count;
        long long int ns;

        if (!freq.QuadPart) {
            /* Number of counts per second. */
            QueryPerformanceFrequency(&freq);
        }
        /* Total number of counts from a starting point. */
        QueryPerformanceCounter(&count);

        /* Total nano seconds from a starting point. */
        ns = (double) count.QuadPart / freq.QuadPart * 1000000000;

        ts->tv_sec = count.QuadPart / freq.QuadPart;
        ts->tv_nsec = ns % 1000000000;
    } else if (id == CLOCK_REALTIME) {
        ULARGE_INTEGER current_time = xgetfiletime();

        /* Time from Epoch to now. */
        ts->tv_sec = (current_time.QuadPart - unix_epoch.QuadPart) / 10000000;
        ts->tv_nsec = ((current_time.QuadPart - unix_epoch.QuadPart) %
                       10000000) * 100;
    } else {
        return -1;
    }
}
#endif /* _WIN32 */

void
xgettimeofday(struct timeval *tv)
{
#ifndef _WIN32
    if (gettimeofday(tv, NULL) == -1) {
        VLOG_FATAL("gettimeofday failed (%s)", ovs_strerror(errno));
    }
#else
    ULARGE_INTEGER current_time = xgetfiletime();

    tv->tv_sec = (current_time.QuadPart - unix_epoch.QuadPart) / 10000000;
    tv->tv_usec = ((current_time.QuadPart - unix_epoch.QuadPart) %
                   10000000) / 10;
#endif
}

void
xclock_gettime(clock_t id, struct timespec *ts)
{
    if (clock_gettime(id, ts) == -1) {
        /* It seems like a bad idea to try to use vlog here because it is
         * likely to try to check the current time. */
        ovs_abort(errno, "xclock_gettime() failed");
    }
}

/* Makes threads wait on timewarp_seq and be waken up when time is warped.
 * This function will be no-op unless timeval_dummy_register() is called. */
void
timewarp_wait(void)
{
    if (timewarp_enabled) {
        uint64_t *last_seq = last_seq_get();

        *last_seq = seq_read(timewarp_seq);
        seq_wait(timewarp_seq, *last_seq);
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

static bool
is_warped(const struct clock *c)
{
    bool warped;

    ovs_mutex_lock(&c->mutex);
    warped = monotonic_clock.warp.tv_sec || monotonic_clock.warp.tv_nsec;
    ovs_mutex_unlock(&c->mutex);

    return warped;
}

static void
log_poll_interval(long long int last_wakeup)
{
    long long int interval = time_msec() - last_wakeup;

    if (interval >= 1000 && !is_warped(&monotonic_clock)) {
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

struct cpu_tracker {
    struct cpu_usage older;
    struct cpu_usage newer;
    int cpu_usage;

    struct rusage recent_rusage;
};
DEFINE_PER_THREAD_MALLOCED_DATA(struct cpu_tracker *, cpu_tracker_var);

static struct cpu_tracker *
get_cpu_tracker(void)
{
    struct cpu_tracker *t = cpu_tracker_var_get();
    if (!t) {
        t = xzalloc(sizeof *t);
        t->older.when = LLONG_MIN;
        t->newer.when = LLONG_MIN;
        cpu_tracker_var_set_unsafe(t);
    }
    return t;
}

static struct rusage *
get_recent_rusage(void)
{
    return &get_cpu_tracker()->recent_rusage;
}

static int
getrusage_thread(struct rusage *rusage OVS_UNUSED)
{
#ifdef RUSAGE_THREAD
    return getrusage(RUSAGE_THREAD, rusage);
#else
    errno = EINVAL;
    return -1;
#endif
}

static void
refresh_rusage(void)
{
    struct cpu_tracker *t = get_cpu_tracker();
    struct rusage *recent_rusage = &t->recent_rusage;

    if (!getrusage_thread(recent_rusage)) {
        long long int now = time_msec();
        if (now >= t->newer.when + 3 * 1000) {
            t->older = t->newer;
            t->newer.when = now;
            t->newer.cpu = (timeval_to_msec(&recent_rusage->ru_utime) +
                            timeval_to_msec(&recent_rusage->ru_stime));

            if (t->older.when != LLONG_MIN && t->newer.cpu > t->older.cpu) {
                unsigned int dividend = t->newer.cpu - t->older.cpu;
                unsigned int divisor = (t->newer.when - t->older.when) / 100;
                t->cpu_usage = divisor > 0 ? dividend / divisor : -1;
            } else {
                t->cpu_usage = -1;
            }
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
    return get_cpu_tracker()->cpu_usage;
}

/* Unixctl interface. */

/* "time/stop" stops the monotonic time returned by e.g. time_msec() from
 * advancing, except due to later calls to "time/warp". */
static void
timeval_stop_cb(struct unixctl_conn *conn,
                 int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                 void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&monotonic_clock.mutex);
    atomic_store(&monotonic_clock.slow_path, true);
    monotonic_clock.stopped = true;
    xclock_gettime(monotonic_clock.id, &monotonic_clock.cache);
    ovs_mutex_unlock(&monotonic_clock.mutex);

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

    ovs_mutex_lock(&monotonic_clock.mutex);
    atomic_store(&monotonic_clock.slow_path, true);
    timespec_add(&monotonic_clock.warp, &monotonic_clock.warp, &ts);
    ovs_mutex_unlock(&monotonic_clock.mutex);
    seq_change(timewarp_seq);
    /* give threads (eg. monitor) some chances to run */
#ifndef _WIN32
    poll(NULL, 0, 10);
#else
    Sleep(10);
#endif
    unixctl_command_reply(conn, "warped");
}

void
timeval_dummy_register(void)
{
    timewarp_enabled = true;
    unixctl_command_register("time/stop", "", 0, 0, timeval_stop_cb, NULL);
    unixctl_command_register("time/warp", "MSECS", 1, 1,
                             timeval_warp_cb, NULL);
}



/* strftime() with an extension for high-resolution timestamps.  Any '#'s in
 * 'format' will be replaced by subseconds, e.g. use "%S.###" to obtain results
 * like "01.123".  */
size_t
strftime_msec(char *s, size_t max, const char *format,
              const struct tm_msec *tm)
{
    size_t n;

    /* Visual Studio 2013's behavior is to crash when 0 is passed as second
     * argument to strftime. */
    n = max ? strftime(s, max, format, &tm->tm) : 0;
    if (n) {
        char decimals[4];
        char *p;

        sprintf(decimals, "%03d", tm->msec);
        for (p = strchr(s, '#'); p; p = strchr(p, '#')) {
            char *d = decimals;
            while (*p == '#')  {
                *p++ = *d ? *d++ : '0';
            }
        }
    }

    return n;
}

struct tm_msec *
localtime_msec(long long int now, struct tm_msec *result)
{
  time_t now_sec = now / 1000;
  localtime_r(&now_sec, &result->tm);
  result->msec = now % 1000;
  return result;
}

struct tm_msec *
gmtime_msec(long long int now, struct tm_msec *result)
{
  time_t now_sec = now / 1000;
  gmtime_r(&now_sec, &result->tm);
  result->msec = now % 1000;
  return result;
}
