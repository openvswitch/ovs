/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "process.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "signals.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(process);

COVERAGE_DEFINE(process_start);

#ifdef __linux__
#define LINUX 1
#include <asm/param.h>
#else
#define LINUX 0
#endif

struct process {
    struct ovs_list node;
    char *name;
    pid_t pid;

    /* State. */
    bool exited;
    int status;
};

struct raw_process_info {
    unsigned long int vsz;      /* Virtual size, in kB. */
    unsigned long int rss;      /* Resident set size, in kB. */
    long long int uptime;       /* ms since started. */
    long long int cputime;      /* ms of CPU used during 'uptime'. */
    pid_t ppid;                 /* Parent. */
    char name[18];              /* Name (surrounded by parentheses). */
};

/* Pipe used to signal child termination. */
static int fds[2];

/* All processes. */
static struct ovs_list all_processes = OVS_LIST_INITIALIZER(&all_processes);

static void sigchld_handler(int signr OVS_UNUSED);

/* Initializes the process subsystem (if it is not already initialized).  Calls
 * exit() if initialization fails.
 *
 * This function may not be called after creating any additional threads.
 *
 * Calling this function is optional; it will be called automatically by
 * process_start() if necessary.  Calling it explicitly allows the client to
 * prevent the process from exiting at an unexpected time. */
void
process_init(void)
{
#ifndef _WIN32
    static bool inited;
    struct sigaction sa;

    assert_single_threaded();
    if (inited) {
        return;
    }
    inited = true;

    /* Create notification pipe. */
    xpipe_nonblocking(fds);

    /* Set up child termination signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    xsigaction(SIGCHLD, &sa, NULL);
#endif
}

char *
process_escape_args(char **argv)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    char **argp;
    for (argp = argv; *argp; argp++) {
        const char *arg = *argp;
        const char *p;
        if (argp != argv) {
            ds_put_char(&ds, ' ');
        }
        if (arg[strcspn(arg, " \t\r\n\v\\\'\"")]) {
            ds_put_char(&ds, '"');
            for (p = arg; *p; p++) {
                if (*p == '\\' || *p == '\"') {
                    ds_put_char(&ds, '\\');
                }
                ds_put_char(&ds, *p);
            }
            ds_put_char(&ds, '"');
        } else {
            ds_put_cstr(&ds, arg);
        }
    }
    return ds_cstr(&ds);
}

/* Prepare to start a process whose command-line arguments are given by the
 * null-terminated 'argv' array.  Returns 0 if successful, otherwise a
 * positive errno value. */
static int
process_prestart(char **argv)
{
    char *binary;

    process_init();

    /* Log the process to be started. */
    if (VLOG_IS_DBG_ENABLED()) {
        char *args = process_escape_args(argv);
        VLOG_DBG("starting subprocess: %s", args);
        free(args);
    }

    /* execvp() will search PATH too, but the error in that case is more
     * obscure, since it is only reported post-fork. */
    binary = process_search_path(argv[0]);
    if (!binary) {
        VLOG_ERR("%s not found in PATH", argv[0]);
        return ENOENT;
    }
    free(binary);

    return 0;
}

/* Creates and returns a new struct process with the specified 'name' and
 * 'pid'. */
static struct process *
process_register(const char *name, pid_t pid)
{
    struct process *p;
    const char *slash;

    p = xzalloc(sizeof *p);
    p->pid = pid;
    slash = strrchr(name, '/');
    p->name = xstrdup(slash ? slash + 1 : name);
    p->exited = false;

    ovs_list_push_back(&all_processes, &p->node);

    return p;
}

#ifndef _WIN32
static bool
rlim_is_finite(rlim_t limit)
{
    if (limit == RLIM_INFINITY) {
        return false;
    }

#ifdef RLIM_SAVED_CUR           /* FreeBSD 8.0 lacks RLIM_SAVED_CUR. */
    if (limit == RLIM_SAVED_CUR) {
        return false;
    }
#endif

#ifdef RLIM_SAVED_MAX           /* FreeBSD 8.0 lacks RLIM_SAVED_MAX. */
    if (limit == RLIM_SAVED_MAX) {
        return false;
    }
#endif

    return true;
}

/* Returns the maximum valid FD value, plus 1. */
static int
get_max_fds(void)
{
    static int max_fds;

    if (!max_fds) {
        struct rlimit r;
        if (!getrlimit(RLIMIT_NOFILE, &r) && rlim_is_finite(r.rlim_cur)) {
            max_fds = r.rlim_cur;
        } else {
            VLOG_WARN("failed to obtain fd limit, defaulting to 1024");
            max_fds = 1024;
        }
    }

    return max_fds;
}
#endif /* _WIN32 */

/* Starts a subprocess with the arguments in the null-terminated argv[] array.
 * argv[0] is used as the name of the process.  Searches the PATH environment
 * variable to find the program to execute.
 *
 * This function may not be called after creating any additional threads.
 *
 * All file descriptors are closed before executing the subprocess, except for
 * fds 0, 1, and 2.
 *
 * Returns 0 if successful, otherwise a positive errno value indicating the
 * error.  If successful, '*pp' is assigned a new struct process that may be
 * used to query the process's status.  On failure, '*pp' is set to NULL. */
int
process_start(char **argv, struct process **pp)
{
#ifndef _WIN32
    pid_t pid;
    int error;
    sigset_t prev_mask;

    assert_single_threaded();

    *pp = NULL;
    COVERAGE_INC(process_start);
    error = process_prestart(argv);
    if (error) {
        return error;
    }

    fatal_signal_block(&prev_mask);
    pid = fork();
    if (pid < 0) {
        VLOG_WARN("fork failed: %s", ovs_strerror(errno));
        error = errno;
    } else if (pid) {
        /* Running in parent process. */
        *pp = process_register(argv[0], pid);
        error = 0;
    } else {
        /* Running in child process. */
        int fd_max = get_max_fds();
        int fd;

        fatal_signal_fork();
        for (fd = 3; fd < fd_max; fd++) {
            close(fd);
        }
        xpthread_sigmask(SIG_SETMASK, &prev_mask, NULL);
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(\"%s\") failed: %s\n",
                argv[0], ovs_strerror(errno));
        _exit(1);
    }
    xpthread_sigmask(SIG_SETMASK, &prev_mask, NULL);
    return error;
#else
    *pp = NULL;
    return ENOSYS;
#endif
}

/* Destroys process 'p'. */
void
process_destroy(struct process *p)
{
    if (p) {
        ovs_list_remove(&p->node);
        free(p->name);
        free(p);
    }
}

/* Sends signal 'signr' to process 'p'.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
process_kill(const struct process *p, int signr)
{
#ifndef _WIN32
    return (p->exited ? ESRCH
            : !kill(p->pid, signr) ? 0
            : errno);
#else
    return ENOSYS;
#endif
}

/* Returns the pid of process 'p'. */
pid_t
process_pid(const struct process *p)
{
    return p->pid;
}

/* Returns the name of process 'p' (the name passed to process_start() with any
 * leading directories stripped). */
const char *
process_name(const struct process *p)
{
    return p->name;
}

/* Returns true if process 'p' has exited, false otherwise. */
bool
process_exited(struct process *p)
{
    return p->exited;
}

/* Returns process 'p''s exit status, as reported by waitpid(2).
 * process_status(p) may be called only after process_exited(p) has returned
 * true. */
int
process_status(const struct process *p)
{
    ovs_assert(p->exited);
    return p->status;
}

int
count_crashes(pid_t pid)
{
    char file_name[128];
    const char *paren;
    char line[128];
    int crashes = 0;
    FILE *stream;

    ovs_assert(LINUX);

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

static unsigned long long int
ticks_to_ms(unsigned long long int ticks)
{
    ovs_assert(LINUX);

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

static bool
get_raw_process_info(pid_t pid, struct raw_process_info *raw)
{
    unsigned long long int vsize, rss, start_time, utime, stime;
    long long int start_msec;
    unsigned long ppid;
    char file_name[128];
    FILE *stream;
    int n;

    ovs_assert(LINUX);

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
    raw->rss = rss * (get_page_size() / 1024);
    raw->uptime = time_wall_msec() - start_msec;
    raw->cputime = ticks_to_ms(utime + stime);
    raw->ppid = ppid;

    return true;
}

bool
get_process_info(pid_t pid, struct process_info *pinfo)
{
    struct raw_process_info child;

    ovs_assert(LINUX);
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

/* Given 'status', which is a process status in the form reported by waitpid(2)
 * and returned by process_status(), returns a string describing how the
 * process terminated.  The caller is responsible for freeing the string when
 * it is no longer needed. */
char *
process_status_msg(int status)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
#ifndef _WIN32
    if (WIFEXITED(status)) {
        ds_put_format(&ds, "exit status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        char namebuf[SIGNAL_NAME_BUFSIZE];

        ds_put_format(&ds, "killed (%s)",
                      signal_name(WTERMSIG(status), namebuf, sizeof namebuf));
    } else if (WIFSTOPPED(status)) {
        char namebuf[SIGNAL_NAME_BUFSIZE];

        ds_put_format(&ds, "stopped (%s)",
                      signal_name(WSTOPSIG(status), namebuf, sizeof namebuf));
    } else {
        ds_put_format(&ds, "terminated abnormally (%x)", status);
    }
    if (WCOREDUMP(status)) {
        ds_put_cstr(&ds, ", core dumped");
    }
#else
    ds_put_cstr(&ds, "function not supported.");
#endif
    return ds_cstr(&ds);
}

/* Executes periodic maintenance activities required by the process module. */
void
process_run(void)
{
#ifndef _WIN32
    char buf[_POSIX_PIPE_BUF];

    if (!ovs_list_is_empty(&all_processes) && read(fds[0], buf, sizeof buf) > 0) {
        struct process *p;

        LIST_FOR_EACH (p, node, &all_processes) {
            if (!p->exited) {
                int retval, status;
                do {
                    retval = waitpid(p->pid, &status, WNOHANG);
                } while (retval == -1 && errno == EINTR);
                if (retval == p->pid) {
                    p->exited = true;
                    p->status = status;
                } else if (retval < 0) {
                    VLOG_WARN("waitpid: %s", ovs_strerror(errno));
                    p->exited = true;
                    p->status = -1;
                }
            }
        }
    }
#endif
}


/* Causes the next call to poll_block() to wake up when process 'p' has
 * exited. */
void
process_wait(struct process *p)
{
#ifndef _WIN32
    if (p->exited) {
        poll_immediate_wake();
    } else {
        poll_fd_wait(fds[0], POLLIN);
    }
#else
    OVS_NOT_REACHED();
#endif
}

char *
process_search_path(const char *name)
{
    char *save_ptr = NULL;
    char *path, *dir;
    struct stat s;

    if (strchr(name, '/') || !getenv("PATH")) {
        return stat(name, &s) == 0 ? xstrdup(name) : NULL;
    }

    path = xstrdup(getenv("PATH"));
    for (dir = strtok_r(path, ":", &save_ptr); dir;
         dir = strtok_r(NULL, ":", &save_ptr)) {
        char *file = xasprintf("%s/%s", dir, name);
        if (stat(file, &s) == 0) {
            free(path);
            return file;
        }
        free(file);
    }
    free(path);
    return NULL;
}

static void
sigchld_handler(int signr OVS_UNUSED)
{
    ignore(write(fds[1], "", 1));
}
