/* Copyright (c) 2010, 2012, 2013 Nicira, Inc.
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

#include "system-stats.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#include <unistd.h>

#include "daemon.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "json.h"
#include "latch.h"
#include "ofpbuf.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "shash.h"
#include "smap.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(system_stats);

/* #ifdefs make it a pain to maintain code: you have to try to build both ways.
 * Thus, this file tries to compile as much of the code as possible regardless
 * of the target, by writing "if (LINUX_DATAPATH)" instead of "#ifdef
 * __linux__" where this is possible. */
#ifdef LINUX_DATAPATH
#include <asm/param.h>
#else
#define LINUX_DATAPATH 0
#endif

static void
get_cpu_cores(struct smap *stats)
{
    long int n_cores = count_cpu_cores();
    if (n_cores > 0) {
        smap_add_format(stats, "cpu", "%ld", n_cores);
    }
}

static void
get_load_average(struct smap *stats OVS_UNUSED)
{
#if HAVE_GETLOADAVG
    double loadavg[3];

    if (getloadavg(loadavg, 3) == 3) {
        smap_add_format(stats, "load_average", "%.2f,%.2f,%.2f",
                        loadavg[0], loadavg[1], loadavg[2]);
    }
#endif
}

static unsigned int
get_page_size(void)
{
    static unsigned int cached;

    if (!cached) {
        long int value = sysconf(_SC_PAGESIZE);
        if (value >= 0) {
            cached = value;
        }
    }

    return cached;
}

static void
get_memory_stats(struct smap *stats)
{
    if (!LINUX_DATAPATH) {
        unsigned int pagesize = get_page_size();
#ifdef _SC_PHYS_PAGES
        long int phys_pages = sysconf(_SC_PHYS_PAGES);
#else
        long int phys_pages = 0;
#endif
#ifdef _SC_AVPHYS_PAGES
        long int avphys_pages = sysconf(_SC_AVPHYS_PAGES);
#else
        long int avphys_pages = 0;
#endif
        int mem_total, mem_used;

        if (pagesize <= 0 || phys_pages <= 0 || avphys_pages <= 0) {
            return;
        }

        mem_total = phys_pages * (pagesize / 1024);
        mem_used = (phys_pages - avphys_pages) * (pagesize / 1024);
        smap_add_format(stats, "memory", "%d,%d", mem_total, mem_used);
    } else {
        static const char file_name[] = "/proc/meminfo";
        int mem_used, mem_cache, swap_used;
        int mem_free = 0;
        int buffers = 0;
        int cached = 0;
        int swap_free = 0;
        int mem_total = 0;
        int swap_total = 0;
        struct shash dict;
        char line[128];
        FILE *stream;

        stream = fopen(file_name, "r");
        if (!stream) {
            VLOG_WARN_ONCE("%s: open failed (%s)",
                           file_name, ovs_strerror(errno));
            return;
        }

        shash_init(&dict);
        shash_add(&dict, "MemTotal", &mem_total);
        shash_add(&dict, "MemFree", &mem_free);
        shash_add(&dict, "Buffers", &buffers);
        shash_add(&dict, "Cached", &cached);
        shash_add(&dict, "SwapTotal", &swap_total);
        shash_add(&dict, "SwapFree", &swap_free);
        while (fgets(line, sizeof line, stream)) {
            char key[16];
            int value;

            if (ovs_scan(line, "%15[^:]: %u", key, &value)) {
                int *valuep = shash_find_data(&dict, key);
                if (valuep) {
                    *valuep = value;
                }
            }
        }
        fclose(stream);
        shash_destroy(&dict);

        mem_used = mem_total - mem_free;
        mem_cache = buffers + cached;
        swap_used = swap_total - swap_free;
        smap_add_format(stats, "memory", "%d,%d,%d,%d,%d",
                        mem_total, mem_used, mem_cache, swap_total, swap_used);
    }
}

/* Returns the time at which the system booted, as the number of milliseconds
 * since the epoch, or 0 if the time of boot cannot be determined. */
static long long int
get_boot_time(void)
{
    static long long int cache_expiration = LLONG_MIN;
    static long long int boot_time;

    ovs_assert(LINUX_DATAPATH);

    if (time_msec() >= cache_expiration) {
        static const char stat_file[] = "/proc/stat";
        char line[128];
        FILE *stream;

        cache_expiration = time_msec() + 5 * 1000;

        stream = fopen(stat_file, "r");
        if (!stream) {
            VLOG_ERR_ONCE("%s: open failed (%s)",
                          stat_file, ovs_strerror(errno));
            return boot_time;
        }

        while (fgets(line, sizeof line, stream)) {
            long long int btime;
            if (ovs_scan(line, "btime %lld", &btime)) {
                boot_time = btime * 1000;
                goto done;
            }
        }
        VLOG_ERR_ONCE("%s: btime not found", stat_file);
    done:
        fclose(stream);
    }
    return boot_time;
}

static unsigned long long int
ticks_to_ms(unsigned long long int ticks)
{
    ovs_assert(LINUX_DATAPATH);

#ifndef USER_HZ
#define USER_HZ 100
#endif

#if USER_HZ == 100              /* Common case. */
    return ticks * (1000 / USER_HZ);
#else  /* Alpha and some other architectures.  */
    double factor = 1000.0 / USER_HZ;
    return ticks * factor + 0.5;
#endif
}

struct raw_process_info {
    unsigned long int vsz;      /* Virtual size, in kB. */
    unsigned long int rss;      /* Resident set size, in kB. */
    long long int uptime;       /* ms since started. */
    long long int cputime;      /* ms of CPU used during 'uptime'. */
    pid_t ppid;                 /* Parent. */
    char name[18];              /* Name (surrounded by parentheses). */
};

static bool
get_raw_process_info(pid_t pid, struct raw_process_info *raw)
{
    unsigned long long int vsize, rss, start_time, utime, stime;
    long long int start_msec;
    unsigned long ppid;
    char file_name[128];
    FILE *stream;
    int n;

    ovs_assert(LINUX_DATAPATH);

    sprintf(file_name, "/proc/%lu/stat", (unsigned long int) pid);
    stream = fopen(file_name, "r");
    if (!stream) {
        VLOG_ERR_ONCE("%s: open failed (%s)",
                      file_name, ovs_strerror(errno));
        return false;
    }

    n = fscanf(stream,
               "%*d "           /* (1. pid) */
               "%17s "          /* 2. process name */
               "%*c "           /* (3. state) */
               "%lu "           /* 4. ppid */
               "%*d "           /* (5. pgid) */
               "%*d "           /* (6. sid) */
               "%*d "           /* (7. tty_nr) */
               "%*d "           /* (8. tty_pgrp) */
               "%*u "           /* (9. flags) */
               "%*u "           /* (10. min_flt) */
               "%*u "           /* (11. cmin_flt) */
               "%*u "           /* (12. maj_flt) */
               "%*u "           /* (13. cmaj_flt) */
               "%llu "          /* 14. utime */
               "%llu "          /* 15. stime */
               "%*d "           /* (16. cutime) */
               "%*d "           /* (17. cstime) */
               "%*d "           /* (18. priority) */
               "%*d "           /* (19. nice) */
               "%*d "           /* (20. num_threads) */
               "%*d "           /* (21. always 0) */
               "%llu "          /* 22. start_time */
               "%llu "          /* 23. vsize */
               "%llu "          /* 24. rss */
#if 0
               /* These are here for documentation but #if'd out to save
                * actually parsing them from the stream for no benefit. */
               "%*lu "          /* (25. rsslim) */
               "%*lu "          /* (26. start_code) */
               "%*lu "          /* (27. end_code) */
               "%*lu "          /* (28. start_stack) */
               "%*lu "          /* (29. esp) */
               "%*lu "          /* (30. eip) */
               "%*lu "          /* (31. pending signals) */
               "%*lu "          /* (32. blocked signals) */
               "%*lu "          /* (33. ignored signals) */
               "%*lu "          /* (34. caught signals) */
               "%*lu "          /* (35. whcan) */
               "%*lu "          /* (36. always 0) */
               "%*lu "          /* (37. always 0) */
               "%*d "           /* (38. exit_signal) */
               "%*d "           /* (39. task_cpu) */
               "%*u "           /* (40. rt_priority) */
               "%*u "           /* (41. policy) */
               "%*llu "         /* (42. blkio_ticks) */
               "%*lu "          /* (43. gtime) */
               "%*ld"           /* (44. cgtime) */
#endif
               , raw->name, &ppid, &utime, &stime, &start_time, &vsize, &rss);
    fclose(stream);
    if (n != 7) {
        VLOG_ERR_ONCE("%s: fscanf failed", file_name);
        return false;
    }

    start_msec = get_boot_time() + ticks_to_ms(start_time);

    raw->vsz = vsize / 1024;
    raw->rss = rss * (getpagesize() / 1024);
    raw->uptime = time_wall_msec() - start_msec;
    raw->cputime = ticks_to_ms(utime + stime);
    raw->ppid = ppid;

    return true;
}

static int
count_crashes(pid_t pid)
{
    char file_name[128];
    const char *paren;
    char line[128];
    int crashes = 0;
    FILE *stream;

    ovs_assert(LINUX_DATAPATH);

    sprintf(file_name, "/proc/%lu/cmdline", (unsigned long int) pid);
    stream = fopen(file_name, "r");
    if (!stream) {
        VLOG_WARN_ONCE("%s: open failed (%s)", file_name, ovs_strerror(errno));
        goto exit;
    }

    if (!fgets(line, sizeof line, stream)) {
        VLOG_WARN_ONCE("%s: read failed (%s)", file_name,
                       feof(stream) ? "end of file" : ovs_strerror(errno));
        goto exit_close;
    }

    paren = strchr(line, '(');
    if (paren) {
        int x;
        if (ovs_scan(paren + 1, "%d", &x)) {
            crashes = x;
        }
    }

exit_close:
    fclose(stream);
exit:
    return crashes;
}

struct process_info {
    unsigned long int vsz;      /* Virtual size, in kB. */
    unsigned long int rss;      /* Resident set size, in kB. */
    long long int booted;       /* ms since monitor started. */
    int crashes;                /* # of crashes (usually 0). */
    long long int uptime;       /* ms since last (re)started by monitor. */
    long long int cputime;      /* ms of CPU used during 'uptime'. */
};

static bool
get_process_info(pid_t pid, struct process_info *pinfo)
{
    struct raw_process_info child;

    ovs_assert(LINUX_DATAPATH);
    if (!get_raw_process_info(pid, &child)) {
        return false;
    }

    pinfo->vsz = child.vsz;
    pinfo->rss = child.rss;
    pinfo->booted = child.uptime;
    pinfo->crashes = 0;
    pinfo->uptime = child.uptime;
    pinfo->cputime = child.cputime;

    if (child.ppid) {
        struct raw_process_info parent;

        get_raw_process_info(child.ppid, &parent);
        if (!strcmp(child.name, parent.name)) {
            pinfo->booted = parent.uptime;
            pinfo->crashes = count_crashes(child.ppid);
        }
    }

    return true;
}

static void
get_process_stats(struct smap *stats)
{
    struct dirent *de;
    DIR *dir;

    dir = opendir(ovs_rundir());
    if (!dir) {
        VLOG_ERR_ONCE("%s: open failed (%s)",
                      ovs_rundir(), ovs_strerror(errno));
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        struct process_info pinfo;
        char *file_name;
        char *extension;
        char *key;
        pid_t pid;

#ifdef _DIRENT_HAVE_D_TYPE
        if (de->d_type != DT_UNKNOWN && de->d_type != DT_REG) {
            continue;
        }
#endif

        extension = strrchr(de->d_name, '.');
        if (!extension || strcmp(extension, ".pid")) {
            continue;
        }

        file_name = xasprintf("%s/%s", ovs_rundir(), de->d_name);
        pid = read_pidfile(file_name);
        free(file_name);
        if (pid < 0) {
            continue;
        }

        key = xasprintf("process_%.*s",
                        (int) (extension - de->d_name), de->d_name);
        if (!smap_get(stats, key)) {
            if (LINUX_DATAPATH && get_process_info(pid, &pinfo)) {
                smap_add_format(stats, key, "%lu,%lu,%lld,%d,%lld,%lld",
                                pinfo.vsz, pinfo.rss, pinfo.cputime,
                                pinfo.crashes, pinfo.booted, pinfo.uptime);
            } else {
                smap_add(stats, key, "");
            }
        }
        free(key);
    }

    closedir(dir);
}

static void
get_filesys_stats(struct smap *stats OVS_UNUSED)
{
#if HAVE_GETMNTENT_R && HAVE_STATVFS
    static const char file_name[] = "/etc/mtab";
    struct mntent mntent;
    struct mntent *me;
    char buf[4096];
    FILE *stream;
    struct ds s;

    stream = setmntent(file_name, "r");
    if (!stream) {
        VLOG_ERR_ONCE("%s: open failed (%s)", file_name, ovs_strerror(errno));
        return;
    }

    ds_init(&s);
    while ((me = getmntent_r(stream, &mntent, buf, sizeof buf)) != NULL) {
        unsigned long long int total, free;
        struct statvfs vfs;
        char *p;

        /* Skip non-local and read-only filesystems. */
        if (strncmp(me->mnt_fsname, "/dev", 4)
            || !strstr(me->mnt_opts, "rw")) {
            continue;
        }

        /* Given the mount point we can stat the file system. */
        if (statvfs(me->mnt_dir, &vfs) && vfs.f_flag & ST_RDONLY) {
            /* That's odd... */
            continue;
        }

        /* Now format the data. */
        if (s.length) {
            ds_put_char(&s, ' ');
        }
        for (p = me->mnt_dir; *p != '\0'; p++) {
            ds_put_char(&s, *p == ' ' || *p == ',' ? '_' : *p);
        }
        total = (unsigned long long int) vfs.f_frsize * vfs.f_blocks / 1024;
        free = (unsigned long long int) vfs.f_frsize * vfs.f_bfree / 1024;
        ds_put_format(&s, ",%llu,%llu", total, total - free);
    }
    endmntent(stream);

    if (s.length) {
        smap_add(stats, "file_systems", ds_cstr(&s));
    }
    ds_destroy(&s);
#endif  /* HAVE_GETMNTENT_R && HAVE_STATVFS */
}

#define SYSTEM_STATS_INTERVAL (5 * 1000) /* In milliseconds. */

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static struct latch latch OVS_GUARDED_BY(mutex);
static bool enabled;
static bool started OVS_GUARDED_BY(mutex);
static struct smap *system_stats OVS_GUARDED_BY(mutex);

static void *system_stats_thread_func(void *);
static void discard_stats(void);

/* Enables or disables system stats collection, according to 'enable'. */
void
system_stats_enable(bool enable)
{
    if (enabled != enable) {
        ovs_mutex_lock(&mutex);
        if (enable) {
            if (!started) {
                xpthread_create(NULL, NULL, system_stats_thread_func, NULL);
                latch_init(&latch);
                started = true;
            }
            discard_stats();
            xpthread_cond_signal(&cond);
        }
        enabled = enable;
        ovs_mutex_unlock(&mutex);
    }
}

/* Tries to obtain a new snapshot of system stats every SYSTEM_STATS_INTERVAL
 * milliseconds.
 *
 * When a new snapshot is available (which only occurs if system stats are
 * enabled), returns it as an smap owned by the caller.  The caller must use
 * both smap_destroy() and free() to completely free the returned data.
 *
 * When no new snapshot is available, returns NULL. */
struct smap *
system_stats_run(void)
{
    struct smap *stats = NULL;

    ovs_mutex_lock(&mutex);
    if (system_stats) {
        latch_poll(&latch);

        if (enabled) {
            stats = system_stats;
            system_stats = NULL;
        } else {
            discard_stats();
        }
    }
    ovs_mutex_unlock(&mutex);

    return stats;
}

/* Causes poll_block() to wake up when system_stats_run() needs to be
 * called. */
void
system_stats_wait(void)
{
    if (enabled) {
        latch_wait(&latch);
    }
}

static void
discard_stats(void) OVS_REQUIRES(mutex)
{
    if (system_stats) {
        smap_destroy(system_stats);
        free(system_stats);
        system_stats = NULL;
    }
}

static void * NO_RETURN
system_stats_thread_func(void *arg OVS_UNUSED)
{
    pthread_detach(pthread_self());

    for (;;) {
        long long int next_refresh;
        struct smap *stats;

        ovs_mutex_lock(&mutex);
        while (!enabled) {
            ovs_mutex_cond_wait(&cond, &mutex);
        }
        ovs_mutex_unlock(&mutex);

        stats = xmalloc(sizeof *stats);
        smap_init(stats);
        get_cpu_cores(stats);
        get_load_average(stats);
        get_memory_stats(stats);
        get_process_stats(stats);
        get_filesys_stats(stats);

        ovs_mutex_lock(&mutex);
        discard_stats();
        system_stats = stats;
        latch_set(&latch);
        ovs_mutex_unlock(&mutex);

        next_refresh = time_msec() + SYSTEM_STATS_INTERVAL;
        do {
            poll_timer_wait_until(next_refresh);
            poll_block();
        } while (time_msec() < next_refresh);
    }
}
