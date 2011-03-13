/* Copyright (c) 2010 Nicira Networks
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

#include <assert.h>
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
#include "shash.h"
#include "system-stats.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(system_stats);

/* #ifdefs make it a pain to maintain code: you have to try to build both ways.
 * Thus, this file tries to compile as much of the code as possible regardless
 * of the target, by writing "if (LINUX)" instead of "#ifdef __linux__" where
 * this is possible. */
#ifdef __linux__
#include <asm/param.h>
#define LINUX 1
#else
#define LINUX 0
#endif

static void
get_cpu_cores(struct shash *stats)
{
    long int n_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cores > 0) {
        shash_add(stats, "cpu", xasprintf("%ld", n_cores));
    }
}

static void
get_load_average(struct shash *stats OVS_UNUSED)
{
#if HAVE_GETLOADAVG
    double loadavg[3];

    if (getloadavg(loadavg, 3) == 3) {
        shash_add(stats, "load_average",
                  xasprintf("%.2f,%.2f,%.2f",
                            loadavg[0], loadavg[1], loadavg[2]));
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
get_memory_stats(struct shash *stats)
{
    if (!LINUX) {
        unsigned int pagesize = get_page_size();
        long int phys_pages = sysconf(_SC_PHYS_PAGES);
        long int avphys_pages = sysconf(_SC_AVPHYS_PAGES);
        int mem_total, mem_used;

        if (pagesize <= 0 || phys_pages <= 0 || avphys_pages <= 0) {
            return;
        }

        mem_total = phys_pages * (pagesize / 1024);
        mem_used = (phys_pages - avphys_pages) * (pagesize / 1024);
        shash_add(stats, "memory", xasprintf("%d,%d", mem_total, mem_used));
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
            VLOG_WARN_ONCE("%s: open failed (%s)", file_name, strerror(errno));
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

            if (sscanf(line, "%15[^:]: %u", key, &value) == 2) {
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
        shash_add(stats, "memory",
                  xasprintf("%d,%d,%d,%d,%d", mem_total, mem_used, mem_cache,
                            swap_total, swap_used));
    }
}

/* Returns the time at which the system booted, as the number of milliseconds
 * since the epoch, or 0 if the time of boot cannot be determined. */
static long long int
get_boot_time(void)
{
    static long long int cache_expiration = LLONG_MIN;
    static long long int boot_time;

    assert(LINUX);

    if (time_msec() >= cache_expiration) {
        static const char stat_file[] = "/proc/stat";
        char line[128];
        FILE *stream;

        cache_expiration = time_msec() + 5 * 1000;

        stream = fopen(stat_file, "r");
        if (!stream) {
            VLOG_ERR_ONCE("%s: open failed (%s)", stat_file, strerror(errno));
            return boot_time;
        }

        while (fgets(line, sizeof line, stream)) {
            long long int btime;
            if (sscanf(line, "btime %lld", &btime) == 1) {
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
    assert(LINUX);

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

    assert(LINUX);

    sprintf(file_name, "/proc/%lu/stat", (unsigned long int) pid);
    stream = fopen(file_name, "r");
    if (!stream) {
        VLOG_ERR_ONCE("%s: open failed (%s)", file_name, strerror(errno));
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

    assert(LINUX);

    sprintf(file_name, "/proc/%lu/cmdline", (unsigned long int) pid);
    stream = fopen(file_name, "r");
    if (!stream) {
        VLOG_WARN_ONCE("%s: open failed (%s)", file_name, strerror(errno));
        goto exit;
    }

    if (!fgets(line, sizeof line, stream)) {
        VLOG_WARN_ONCE("%s: read failed (%s)", file_name,
                       feof(stream) ? "end of file" : strerror(errno));
        goto exit_close;
    }

    paren = strchr(line, '(');
    if (paren) {
        int x;
        if (sscanf(paren + 1, "%d", &x) == 1) {
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

    assert(LINUX);
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
get_process_stats(struct shash *stats)
{
    struct dirent *de;
    DIR *dir;

    dir = opendir(ovs_rundir());
    if (!dir) {
        VLOG_ERR_ONCE("%s: open failed (%s)", ovs_rundir(), strerror(errno));
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        struct process_info pinfo;
        char *key, *value;
        char *file_name;
        char *extension;
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
        if (shash_find(stats, key)) {
            free(key);
            continue;
        }

        if (LINUX && get_process_info(pid, &pinfo)) {
            value = xasprintf("%lu,%lu,%lld,%d,%lld,%lld",
                              pinfo.vsz, pinfo.rss, pinfo.cputime,
                              pinfo.crashes, pinfo.booted, pinfo.uptime);
        } else {
            value = xstrdup("");
        }

        shash_add_nocopy(stats, key, value);
    }

    closedir(dir);
}

static void
get_filesys_stats(struct shash *stats OVS_UNUSED)
{
#if HAVE_SETMNTENT && HAVE_STATVFS
    static const char file_name[] = "/etc/mtab";
    struct mntent *me;
    FILE *stream;
    struct ds s;

    stream = setmntent(file_name, "r");
    if (!stream) {
        VLOG_ERR_ONCE("%s: open failed (%s)", file_name, strerror(errno));
        return;
    }

    ds_init(&s);
    while ((me = getmntent(stream)) != NULL) {
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
        shash_add(stats, "file_systems", ds_steal_cstr(&s));
    }
    ds_destroy(&s);
#endif  /* HAVE_SETMNTENT && HAVE_STATVFS */
}

void
get_system_stats(struct shash *stats)
{
    get_cpu_cores(stats);
    get_load_average(stats);
    get_memory_stats(stats);
    get_process_stats(stats);
    get_filesys_stats(stats);
}
