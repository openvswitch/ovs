/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include "daemon.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "command-line.h"
#include "fatal-signal.h"
#include "dirs.h"
#include "lockfile.h"
#include "process.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(daemon)

/* --detach: Should we run in the background? */
static bool detach;

/* --pidfile: Name of pidfile (null if none). */
static char *pidfile;

/* --overwrite-pidfile: Create pidfile even if one already exists and is
   locked? */
static bool overwrite_pidfile;

/* --no-chdir: Should we chdir to "/"? */
static bool chdir_ = true;

/* File descriptor used by daemonize_start() and daemonize_complete(). */
static int daemonize_fd = -1;

/* --monitor: Should a supervisory process monitor the daemon and restart it if
 * it dies due to an error signal? */
static bool monitor;

/* Returns the file name that would be used for a pidfile if 'name' were
 * provided to set_pidfile().  The caller must free the returned string. */
char *
make_pidfile_name(const char *name)
{
    return (!name
            ? xasprintf("%s/%s.pid", ovs_rundir, program_name)
            : abs_file_name(ovs_rundir, name));
}

/* Sets up a following call to daemonize() to create a pidfile named 'name'.
 * If 'name' begins with '/', then it is treated as an absolute path.
 * Otherwise, it is taken relative to RUNDIR, which is $(prefix)/var/run by
 * default.
 *
 * If 'name' is null, then program_name followed by ".pid" is used. */
void
set_pidfile(const char *name)
{
    free(pidfile);
    pidfile = make_pidfile_name(name);
}

/* Returns an absolute path to the configured pidfile, or a null pointer if no
 * pidfile is configured.  The caller must not modify or free the returned
 * string. */
const char *
get_pidfile(void)
{
    return pidfile;
}

/* Sets that we do not chdir to "/". */
void
set_no_chdir(void)
{
    chdir_ = false;
}

/* Will we chdir to "/" as part of daemonizing? */
bool
is_chdir_enabled(void)
{
    return chdir_;
}

/* Normally, die_if_already_running() will terminate the program with a message
 * if a locked pidfile already exists.  If this function is called,
 * die_if_already_running() will merely log a warning. */
void
ignore_existing_pidfile(void)
{
    overwrite_pidfile = true;
}

/* Sets up a following call to daemonize() to detach from the foreground
 * session, running this process in the background.  */
void
set_detach(void)
{
    detach = true;
}

/* Will daemonize() really detach? */
bool
get_detach(void)
{
    return detach;
}

/* Sets up a following call to daemonize() to fork a supervisory process to
 * monitor the daemon and restart it if it dies due to an error signal.  */
void
daemon_set_monitor(void)
{
    monitor = true;
}

/* If a pidfile has been configured and that pidfile already exists and is
 * locked by a running process, returns the pid of the running process.
 * Otherwise, returns 0. */
static pid_t
already_running(void)
{
    pid_t pid = 0;
    if (pidfile) {
        int fd = open(pidfile, O_RDWR);
        if (fd >= 0) {
            struct flock lck;
            lck.l_type = F_WRLCK;
            lck.l_whence = SEEK_SET;
            lck.l_start = 0;
            lck.l_len = 0;
            if (fcntl(fd, F_GETLK, &lck) != -1 && lck.l_type != F_UNLCK) {
                pid = lck.l_pid;
            }
            close(fd);
        }
    }
    return pid;
}

/* If a locked pidfile exists, issue a warning message and, unless
 * ignore_existing_pidfile() has been called, terminate the program. */
void
die_if_already_running(void)
{
    pid_t pid = already_running();
    if (pid) {
        if (!overwrite_pidfile) {
            ovs_fatal(0, "%s: already running as pid %ld",
                      get_pidfile(), (long int) pid);
        } else {
            VLOG_WARN("%s: %s already running as pid %ld",
                      get_pidfile(), program_name, (long int) pid);
        }
    }
}

/* If a pidfile has been configured, creates it and stores the running
 * process's pid in it.  Ensures that the pidfile will be deleted when the
 * process exits. */
static void
make_pidfile(void)
{
    if (pidfile) {
        /* Create pidfile via temporary file, so that observers never see an
         * empty pidfile or an unlocked pidfile. */
        long int pid = getpid();
        char *tmpfile;
        int fd;

        tmpfile = xasprintf("%s.tmp%ld", pidfile, pid);
        fatal_signal_add_file_to_unlink(tmpfile);
        fd = open(tmpfile, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (fd >= 0) {
            struct flock lck;
            lck.l_type = F_WRLCK;
            lck.l_whence = SEEK_SET;
            lck.l_start = 0;
            lck.l_len = 0;
            if (fcntl(fd, F_SETLK, &lck) != -1) {
                char *text = xasprintf("%ld\n", pid);
                if (write(fd, text, strlen(text)) == strlen(text)) {
                    fatal_signal_add_file_to_unlink(pidfile);
                    if (rename(tmpfile, pidfile) < 0) {
                        VLOG_ERR("failed to rename \"%s\" to \"%s\": %s",
                                 tmpfile, pidfile, strerror(errno));
                        fatal_signal_remove_file_to_unlink(pidfile);
                        close(fd);
                    } else {
                        /* Keep 'fd' open to retain the lock. */
                    }
                    free(text);
                } else {
                    VLOG_ERR("%s: write failed: %s", tmpfile, strerror(errno));
                    close(fd);
                }
            } else {
                VLOG_ERR("%s: fcntl failed: %s", tmpfile, strerror(errno));
                close(fd);
            }
        } else {
            VLOG_ERR("%s: create failed: %s", tmpfile, strerror(errno));
        }
        fatal_signal_remove_file_to_unlink(tmpfile);
        free(tmpfile);
    }
    free(pidfile);
    pidfile = NULL;
}

/* If configured with set_pidfile() or set_detach(), creates the pid file and
 * detaches from the foreground session.  */
void
daemonize(void)
{
    daemonize_start();
    daemonize_complete();
}

static pid_t
fork_and_wait_for_startup(int *fdp)
{
    int fds[2];
    pid_t pid;

    if (pipe(fds) < 0) {
        ovs_fatal(errno, "pipe failed");
    }

    pid = fork();
    if (pid > 0) {
        /* Running in parent process. */
        char c;

        close(fds[1]);
        fatal_signal_fork();
        if (read(fds[0], &c, 1) != 1) {
            int retval;
            int status;

            do {
                retval = waitpid(pid, &status, 0);
            } while (retval == -1 && errno == EINTR);

            if (retval == pid
                && WIFEXITED(status)
                && WEXITSTATUS(status)) {
                /* Child exited with an error.  Convey the same error to
                 * our parent process as a courtesy. */
                exit(WEXITSTATUS(status));
            }

            ovs_fatal(errno, "fork child failed to signal startup");
        }
        close(fds[0]);
        *fdp = -1;
    } else if (!pid) {
        /* Running in child process. */
        close(fds[0]);
        time_postfork();
        lockfile_postfork();
        *fdp = fds[1];
    } else {
        ovs_fatal(errno, "could not fork");
    }

    return pid;
}

static void
fork_notify_startup(int fd)
{
    if (fd != -1) {
        size_t bytes_written;
        int error;

        error = write_fully(fd, "", 1, &bytes_written);
        if (error) {
            ovs_fatal(error, "could not write to pipe");
        }

        close(fd);
    }
}

static bool
should_restart(int status)
{
    if (WIFSIGNALED(status)) {
        static const int error_signals[] = {
            SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV,
            SIGXCPU, SIGXFSZ
        };

        size_t i;

        for (i = 0; i < ARRAY_SIZE(error_signals); i++) {
            if (error_signals[i] == WTERMSIG(status)) {
                return true;
            }
        }
    }
    return false;
}

static void
monitor_daemon(pid_t daemon_pid)
{
    /* XXX Should log daemon's stderr output at startup time. */
    const char *saved_program_name;
    time_t last_restart;
    char *status_msg;

    saved_program_name = program_name;
    program_name = xasprintf("monitor(%s)", program_name);
    status_msg = xstrdup("healthy");
    last_restart = TIME_MIN;
    for (;;) {
        int retval;
        int status;

        proctitle_set("%s: monitoring pid %lu (%s)",
                      saved_program_name, (unsigned long int) daemon_pid,
                      status_msg);

        do {
            retval = waitpid(daemon_pid, &status, 0);
        } while (retval == -1 && errno == EINTR);

        if (retval == -1) {
            ovs_fatal(errno, "waitpid failed");
        } else if (retval == daemon_pid) {
            char *s = process_status_msg(status);
            free(status_msg);
            status_msg = xasprintf("pid %lu died, %s",
                                   (unsigned long int) daemon_pid, s);
            free(s);

            if (should_restart(status)) {
                if (WCOREDUMP(status)) {
                    /* Disable further core dumps to save disk space. */
                    struct rlimit r;

                    r.rlim_cur = 0;
                    r.rlim_max = 0;
                    if (setrlimit(RLIMIT_CORE, &r) == -1) {
                        VLOG_WARN("failed to disable core dumps: %s",
                                  strerror(errno));
                    }
                }

                /* Throttle restarts to no more than once every 10 seconds. */
                if (time(NULL) < last_restart + 10) {
                    VLOG_WARN("%s, waiting until 10 seconds since last "
                              "restart", status_msg);
                    for (;;) {
                        time_t now = time(NULL);
                        time_t wakeup = last_restart + 10;
                        if (now >= wakeup) {
                            break;
                        }
                        sleep(wakeup - now);
                    }
                }
                last_restart = time(NULL);

                VLOG_ERR("%s, restarting", status_msg);
                daemon_pid = fork_and_wait_for_startup(&daemonize_fd);
                if (!daemon_pid) {
                    break;
                }
            } else {
                VLOG_INFO("%s, exiting", status_msg);
                exit(0);
            }
        }
    }
    free(status_msg);

    /* Running in new daemon process. */
    proctitle_restore();
    free((char *) program_name);
    program_name = saved_program_name;
}

/* Close stdin, stdout, stderr.  If we're started from e.g. an SSH session,
 * then this keeps us from holding that session open artificially. */
static void
close_standard_fds(void)
{
    int null_fd = get_null_fd();
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
    }
}

/* If daemonization is configured, then starts daemonization, by forking and
 * returning in the child process.  The parent process hangs around until the
 * child lets it know either that it completed startup successfully (by calling
 * daemon_complete()) or that it failed to start up (by exiting with a nonzero
 * exit code). */
void
daemonize_start(void)
{
    daemonize_fd = -1;

    if (detach) {
        if (fork_and_wait_for_startup(&daemonize_fd) > 0) {
            /* Running in parent process. */
            exit(0);
        }
        /* Running in daemon or monitor process. */
    }

    if (monitor) {
        int saved_daemonize_fd = daemonize_fd;
        pid_t daemon_pid;

        daemon_pid = fork_and_wait_for_startup(&daemonize_fd);
        if (daemon_pid > 0) {
            /* Running in monitor process. */
            fork_notify_startup(saved_daemonize_fd);
            close_standard_fds();
            monitor_daemon(daemon_pid);
        }
        /* Running in daemon process. */
    }

    make_pidfile();

    /* Make sure that the unixctl commands for vlog get registered in a
     * daemon, even before the first log message. */
    vlog_init();
}

/* If daemonization is configured, then this function notifies the parent
 * process that the child process has completed startup successfully. */
void
daemonize_complete(void)
{
    fork_notify_startup(daemonize_fd);

    if (detach) {
        setsid();
        if (chdir_) {
            ignore(chdir("/"));
        }
        close_standard_fds();
    }
}

void
daemon_usage(void)
{
    printf(
        "\nDaemon options:\n"
        "  --detach                run in background as daemon\n"
        "  --no-chdir              do not chdir to '/'\n"
        "  --pidfile[=FILE]        create pidfile (default: %s/%s.pid)\n"
        "  --overwrite-pidfile     with --pidfile, start even if already "
                                   "running\n",
        ovs_rundir, program_name);
}

/* Opens and reads a PID from 'pidfile'.  Returns the nonnegative PID if
 * successful, otherwise a negative errno value. */
pid_t
read_pidfile(const char *pidfile)
{
    char line[128];
    struct flock lck;
    FILE *file;
    int error;

    file = fopen(pidfile, "r");
    if (!file) {
        error = errno;
        VLOG_WARN("%s: open: %s", pidfile, strerror(error));
        goto error;
    }

    lck.l_type = F_WRLCK;
    lck.l_whence = SEEK_SET;
    lck.l_start = 0;
    lck.l_len = 0;
    if (fcntl(fileno(file), F_GETLK, &lck)) {
        error = errno;
        VLOG_WARN("%s: fcntl: %s", pidfile, strerror(error));
        goto error;
    }
    if (lck.l_type == F_UNLCK) {
        error = ESRCH;
        VLOG_WARN("%s: pid file is not locked", pidfile);
        goto error;
    }

    if (!fgets(line, sizeof line, file)) {
        if (ferror(file)) {
            error = errno;
            VLOG_WARN("%s: read: %s", pidfile, strerror(error));
        } else {
            error = ESRCH;
            VLOG_WARN("%s: read: unexpected end of file", pidfile);
        }
        goto error;
    }

    if (lck.l_pid != strtoul(line, NULL, 10)) {
        error = ESRCH;
        VLOG_WARN("l_pid (%ld) != %s pid (%s)",
                   (long int) lck.l_pid, pidfile, line);
        goto error;
    }

    fclose(file);
    return lck.l_pid;

error:
    if (file) {
        fclose(file);
    }
    return -error;
}
