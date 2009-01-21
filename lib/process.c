/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
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
#include "dynamic-string.h"
#include "list.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"

#define THIS_MODULE VLM_process
#include "vlog.h"

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

static void block_sigchld(sigset_t *);
static void unblock_sigchld(const sigset_t *);
static void sigchld_handler(int signr UNUSED);
static bool is_member(int x, const int *array, size_t);
static bool find_in_path(const char *name);

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
    if (pipe(fds)) {
        ofp_fatal(errno, "could not create pipe");
    }
    set_nonblocking(fds[0]);
    set_nonblocking(fds[1]);

    /* Set up child termination signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL)) {
        ofp_fatal(errno, "sigaction(SIGCHLD) failed");
    }
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
        if (arg[strcspn(arg, " \t\r\n\v\\")]) {
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
    pid_t pid;

    *pp = NULL;
    process_init();

    if (VLOG_IS_DBG_ENABLED()) {
        char *args = process_escape_args(argv);
        VLOG_DBG("starting subprocess: %s", args);
        free(args);
    }

    /* execvp() will search PATH too, but the error in that case is more
     * obscure, since it is only reported post-fork. */
    if (!find_in_path(argv[0])) {
        VLOG_ERR("%s not found in PATH", argv[0]);
        return ENOENT;
    }

    block_sigchld(&oldsigs);
    pid = fork();
    if (pid < 0) {
        unblock_sigchld(&oldsigs);
        VLOG_WARN("fork failed: %s", strerror(errno));
        return errno;
    } else if (pid) {
        /* Running in parent process. */
        struct process *p;
        const char *slash;

        p = xcalloc(1, sizeof *p);
        p->pid = pid;
        slash = strrchr(argv[0], '/');
        p->name = xstrdup(slash ? slash + 1 : argv[0]);
        p->exited = false;

        list_push_back(&all_processes, &p->node);
        unblock_sigchld(&oldsigs);

        *pp = p;
        return 0;
    } else {
        /* Running in child process. */
        int fd_max = get_max_fds();
        int fd;

        unblock_sigchld(&oldsigs);
        for (fd = 0; fd < fd_max; fd++) {
            if (is_member(fd, null_fds, n_null_fds)) {
                int nullfd = open("/dev/null", O_RDWR);
                dup2(nullfd, fd);
                close(nullfd);
            } else if (fd >= 3 && !is_member(fd, keep_fds, n_keep_fds)) {
                close(fd);
            }
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
        read(fds[0], buf, sizeof buf);
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
    } else if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
        int signr = WIFSIGNALED(status) ? WTERMSIG(status) : WSTOPSIG(status);
        const char *name = NULL;
#ifdef HAVE_STRSIGNAL
        name = strsignal(signr);
#endif
        ds_put_format(&ds, "%s by signal %d",
                      WIFSIGNALED(status) ? "killed" : "stopped", signr);
        if (name) {
            ds_put_format(&ds, " (%s)", name);
        }
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

static void
sigchld_handler(int signr UNUSED)
{
    struct process *p;

    LIST_FOR_EACH (p, struct process, node, &all_processes) {
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
    write(fds[1], "", 1);
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

static void
block_sigchld(sigset_t *oldsigs)
{
    sigset_t sigchld;
    sigemptyset(&sigchld);
    sigaddset(&sigchld, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &sigchld, oldsigs)) {
        ofp_fatal(errno, "sigprocmask");
    }
}

static void
unblock_sigchld(const sigset_t *oldsigs)
{
    if (sigprocmask(SIG_SETMASK, oldsigs, NULL)) {
        ofp_fatal(errno, "sigprocmask");
    }
}

static bool
find_in_path(const char *name)
{
    char *save_ptr = NULL;
    char *path, *dir;
    struct stat s;

    if (strchr(name, '/') || !getenv("PATH")) {
        return stat(name, &s) == 0;
    }

    path = xstrdup(getenv("PATH"));
    for (dir = strtok_r(path, ":", &save_ptr); dir;
         dir = strtok_r(NULL, ":", &save_ptr)) {
        char *file = xasprintf("%s/%s", dir, name);
        if (stat(file, &s) == 0) {
            free(file);
            free(path);
            return true;
        }
        free(file);
    }
    free(path);
    return false;
}
