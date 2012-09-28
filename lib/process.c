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
#include "process.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "poll-loop.h"
#include "signals.h"
#include "socket-util.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(process);

COVERAGE_DEFINE(process_run);
COVERAGE_DEFINE(process_run_capture);
COVERAGE_DEFINE(process_sigchld);
COVERAGE_DEFINE(process_start);

struct process {
    struct list node;
    char *name;
    pid_t pid;

    /* Modified by signal handler. */
    volatile bool exited;
    volatile int status;
};

/* Pipe used to signal child termination. */
static int fds[2];

/* All processes. */
static struct list all_processes = LIST_INITIALIZER(&all_processes);

static bool sigchld_is_blocked(void);
static void block_sigchld(sigset_t *);
static void unblock_sigchld(const sigset_t *);
static void sigchld_handler(int signr OVS_UNUSED);
static bool is_member(int x, const int *array, size_t);

/* Initializes the process subsystem (if it is not already initialized).  Calls
 * exit() if initialization fails.
 *
 * Calling this function is optional; it will be called automatically by
 * process_start() if necessary.  Calling it explicitly allows the client to
 * prevent the process from exiting at an unexpected time. */
void
process_init(void)
{
    static bool inited;
    struct sigaction sa;

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
 * 'pid'.
 *
 * This is racy unless SIGCHLD is blocked (and has been blocked since before
 * the fork()) that created the subprocess.  */
static struct process *
process_register(const char *name, pid_t pid)
{
    struct process *p;
    const char *slash;

    assert(sigchld_is_blocked());

    p = xzalloc(sizeof *p);
    p->pid = pid;
    slash = strrchr(name, '/');
    p->name = xstrdup(slash ? slash + 1 : name);
    p->exited = false;

    list_push_back(&all_processes, &p->node);

    return p;
}

/* Starts a subprocess with the arguments in the null-terminated argv[] array.
 * argv[0] is used as the name of the process.  Searches the PATH environment
 * variable to find the program to execute.
 *
 * All file descriptors are closed before executing the subprocess, except for
 * fds 0, 1, and 2 and the 'n_keep_fds' fds listed in 'keep_fds'.  Also, any of
 * the 'n_null_fds' fds listed in 'null_fds' are replaced by /dev/null.
 *
 * Returns 0 if successful, otherwise a positive errno value indicating the
 * error.  If successful, '*pp' is assigned a new struct process that may be
 * used to query the process's status.  On failure, '*pp' is set to NULL. */
int
process_start(char **argv,
              const int keep_fds[], size_t n_keep_fds,
              const int null_fds[], size_t n_null_fds,
              struct process **pp)
{
    sigset_t oldsigs;
    int nullfd;
    pid_t pid;
    int error;

    *pp = NULL;
    COVERAGE_INC(process_start);
    error = process_prestart(argv);
    if (error) {
        return error;
    }

    if (n_null_fds) {
        nullfd = get_null_fd();
        if (nullfd < 0) {
            return -nullfd;
        }
    } else {
        nullfd = -1;
    }

    block_sigchld(&oldsigs);
    pid = fork();
    if (pid < 0) {
        unblock_sigchld(&oldsigs);
        VLOG_WARN("fork failed: %s", strerror(errno));
        return errno;
    } else if (pid) {
        /* Running in parent process. */
        *pp = process_register(argv[0], pid);
        unblock_sigchld(&oldsigs);
        return 0;
    } else {
        /* Running in child process. */
        int fd_max = get_max_fds();
        int fd;

        fatal_signal_fork();
        unblock_sigchld(&oldsigs);
        for (fd = 0; fd < fd_max; fd++) {
            if (is_member(fd, null_fds, n_null_fds)) {
                dup2(nullfd, fd);
            } else if (fd >= 3 && fd != nullfd
                       && !is_member(fd, keep_fds, n_keep_fds)) {
                close(fd);
            }
        }
        if (nullfd >= 0
            && !is_member(nullfd, keep_fds, n_keep_fds)
            && !is_member(nullfd, null_fds, n_null_fds)) {
            close(nullfd);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(\"%s\") failed: %s\n",
                argv[0], strerror(errno));
        _exit(1);
    }
}

/* Destroys process 'p'. */
void
process_destroy(struct process *p)
{
    if (p) {
        sigset_t oldsigs;

        block_sigchld(&oldsigs);
        list_remove(&p->node);
        unblock_sigchld(&oldsigs);

        free(p->name);
        free(p);
    }
}

/* Sends signal 'signr' to process 'p'.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
process_kill(const struct process *p, int signr)
{
    return (p->exited ? ESRCH
            : !kill(p->pid, signr) ? 0
            : errno);
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
    if (p->exited) {
        return true;
    } else {
        char buf[_POSIX_PIPE_BUF];
        ignore(read(fds[0], buf, sizeof buf));
        return false;
    }
}

/* Returns process 'p''s exit status, as reported by waitpid(2).
 * process_status(p) may be called only after process_exited(p) has returned
 * true. */
int
process_status(const struct process *p)
{
    assert(p->exited);
    return p->status;
}

int
process_run(char **argv,
            const int keep_fds[], size_t n_keep_fds,
            const int null_fds[], size_t n_null_fds,
            int *status)
{
    struct process *p;
    int retval;

    COVERAGE_INC(process_run);
    retval = process_start(argv, keep_fds, n_keep_fds, null_fds, n_null_fds,
                           &p);
    if (retval) {
        *status = 0;
        return retval;
    }

    while (!process_exited(p)) {
        process_wait(p);
        poll_block();
    }
    *status = process_status(p);
    process_destroy(p);
    return 0;
}

/* Given 'status', which is a process status in the form reported by waitpid(2)
 * and returned by process_status(), returns a string describing how the
 * process terminated.  The caller is responsible for freeing the string when
 * it is no longer needed. */
char *
process_status_msg(int status)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    if (WIFEXITED(status)) {
        ds_put_format(&ds, "exit status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        ds_put_format(&ds, "killed (%s)", signal_name(WTERMSIG(status)));
    } else if (WIFSTOPPED(status)) {
        ds_put_format(&ds, "stopped (%s)", signal_name(WSTOPSIG(status)));
    } else {
        ds_put_format(&ds, "terminated abnormally (%x)", status);
    }
    if (WCOREDUMP(status)) {
        ds_put_cstr(&ds, ", core dumped");
    }
    return ds_cstr(&ds);
}

/* Causes the next call to poll_block() to wake up when process 'p' has
 * exited. */
void
process_wait(struct process *p)
{
    if (p->exited) {
        poll_immediate_wake();
    } else {
        poll_fd_wait(fds[0], POLLIN);
    }
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

/* process_run_capture() and supporting functions. */

struct stream {
    size_t max_size;
    struct ds log;
    int fds[2];
};

static int
stream_open(struct stream *s, size_t max_size)
{
    s->max_size = max_size;
    ds_init(&s->log);
    if (pipe(s->fds)) {
        VLOG_WARN("failed to create pipe: %s", strerror(errno));
        return errno;
    }
    set_nonblocking(s->fds[0]);
    return 0;
}

static void
stream_read(struct stream *s)
{
    if (s->fds[0] < 0) {
        return;
    }

    for (;;) {
        char buffer[512];
        int error;
        size_t n;

        error = read_fully(s->fds[0], buffer, sizeof buffer, &n);
        ds_put_buffer(&s->log, buffer, n);
        if (error) {
            if (error == EAGAIN || error == EWOULDBLOCK) {
                return;
            } else {
                if (error != EOF) {
                    VLOG_WARN("error reading subprocess pipe: %s",
                              strerror(error));
                }
                break;
            }
        } else if (s->log.length > s->max_size) {
            VLOG_WARN("subprocess output overflowed %zu-byte buffer",
                      s->max_size);
            break;
        }
    }
    close(s->fds[0]);
    s->fds[0] = -1;
}

static void
stream_wait(struct stream *s)
{
    if (s->fds[0] >= 0) {
        poll_fd_wait(s->fds[0], POLLIN);
    }
}

static void
stream_close(struct stream *s)
{
    ds_destroy(&s->log);
    if (s->fds[0] >= 0) {
        close(s->fds[0]);
    }
    if (s->fds[1] >= 0) {
        close(s->fds[1]);
    }
}

/* Starts the process whose arguments are given in the null-terminated array
 * 'argv' and waits for it to exit.  On success returns 0 and stores the
 * process exit value (suitable for passing to process_status_msg()) in
 * '*status'.  On failure, returns a positive errno value and stores 0 in
 * '*status'.
 *
 * If 'stdout_log' is nonnull, then the subprocess's output to stdout (up to a
 * limit of 'log_max' bytes) is captured in a memory buffer, which
 * when this function returns 0 is stored as a null-terminated string in
 * '*stdout_log'.  The caller is responsible for freeing '*stdout_log' (by
 * passing it to free()).  When this function returns an error, '*stdout_log'
 * is set to NULL.
 *
 * If 'stderr_log' is nonnull, then it is treated like 'stdout_log' except
 * that it captures the subprocess's output to stderr. */
int
process_run_capture(char **argv, char **stdout_log, char **stderr_log,
                    size_t max_log, int *status)
{
    struct stream s_stdout, s_stderr;
    sigset_t oldsigs;
    pid_t pid;
    int error;

    COVERAGE_INC(process_run_capture);
    if (stdout_log) {
        *stdout_log = NULL;
    }
    if (stderr_log) {
        *stderr_log = NULL;
    }
    *status = 0;
    error = process_prestart(argv);
    if (error) {
        return error;
    }

    error = stream_open(&s_stdout, max_log);
    if (error) {
        return error;
    }

    error = stream_open(&s_stderr, max_log);
    if (error) {
        stream_close(&s_stdout);
        return error;
    }

    block_sigchld(&oldsigs);
    pid = fork();
    if (pid < 0) {
        error = errno;

        unblock_sigchld(&oldsigs);
        VLOG_WARN("fork failed: %s", strerror(error));

        stream_close(&s_stdout);
        stream_close(&s_stderr);
        *status = 0;
        return error;
    } else if (pid) {
        /* Running in parent process. */
        struct process *p;

        p = process_register(argv[0], pid);
        unblock_sigchld(&oldsigs);

        close(s_stdout.fds[1]);
        close(s_stderr.fds[1]);
        while (!process_exited(p)) {
            stream_read(&s_stdout);
            stream_read(&s_stderr);

            stream_wait(&s_stdout);
            stream_wait(&s_stderr);
            process_wait(p);
            poll_block();
        }
        stream_read(&s_stdout);
        stream_read(&s_stderr);

        if (stdout_log) {
            *stdout_log = ds_steal_cstr(&s_stdout.log);
        }
        if (stderr_log) {
            *stderr_log = ds_steal_cstr(&s_stderr.log);
        }

        stream_close(&s_stdout);
        stream_close(&s_stderr);

        *status = process_status(p);
        process_destroy(p);
        return 0;
    } else {
        /* Running in child process. */
        int max_fds;
        int i;

        fatal_signal_fork();
        unblock_sigchld(&oldsigs);

        dup2(get_null_fd(), 0);
        dup2(s_stdout.fds[1], 1);
        dup2(s_stderr.fds[1], 2);

        max_fds = get_max_fds();
        for (i = 3; i < max_fds; i++) {
            close(i);
        }

        execvp(argv[0], argv);
        fprintf(stderr, "execvp(\"%s\") failed: %s\n",
                argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void
sigchld_handler(int signr OVS_UNUSED)
{
    struct process *p;

    COVERAGE_INC(process_sigchld);
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
                /* XXX We want to log something but we're in a signal
                 * handler. */
                p->exited = true;
                p->status = -1;
            }
        }
    }
    ignore(write(fds[1], "", 1));
}

static bool
is_member(int x, const int *array, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (array[i] == x) {
            return true;
        }
    }
    return false;
}

static bool
sigchld_is_blocked(void)
{
    sigset_t sigs;

    xsigprocmask(SIG_SETMASK, NULL, &sigs);
    return sigismember(&sigs, SIGCHLD);
}

static void
block_sigchld(sigset_t *oldsigs)
{
    sigset_t sigchld;

    sigemptyset(&sigchld);
    sigaddset(&sigchld, SIGCHLD);
    xsigprocmask(SIG_BLOCK, &sigchld, oldsigs);
}

static void
unblock_sigchld(const sigset_t *oldsigs)
{
    xsigprocmask(SIG_SETMASK, oldsigs, NULL);
}
