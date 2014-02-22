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
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "signals.h"
#include "socket-util.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(process);

COVERAGE_DEFINE(process_start);

struct process {
    struct list node;
    char *name;
    pid_t pid;

    /* State. */
    bool exited;
    int status;
};

/* Pipe used to signal child termination. */
static int fds[2];

/* All processes. */
static struct list all_processes = LIST_INITIALIZER(&all_processes);

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

    list_push_back(&all_processes, &p->node);

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

    assert_single_threaded();

    *pp = NULL;
    COVERAGE_INC(process_start);
    error = process_prestart(argv);
    if (error) {
        return error;
    }

    pid = fork();
    if (pid < 0) {
        VLOG_WARN("fork failed: %s", ovs_strerror(errno));
        return errno;
    } else if (pid) {
        /* Running in parent process. */
        *pp = process_register(argv[0], pid);
        return 0;
    } else {
        /* Running in child process. */
        int fd_max = get_max_fds();
        int fd;

        fatal_signal_fork();
        for (fd = 3; fd < fd_max; fd++) {
            close(fd);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(\"%s\") failed: %s\n",
                argv[0], ovs_strerror(errno));
        _exit(1);
    }
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
        list_remove(&p->node);
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

    if (!list_is_empty(&all_processes) && read(fds[0], buf, sizeof buf) > 0) {
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
