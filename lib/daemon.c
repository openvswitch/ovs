/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
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
#include "daemon.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "dirs.h"
#include "util.h"

#define THIS_MODULE VLM_daemon
#include "vlog.h"

/* Should we run in the background? */
static bool detach;

/* Name of pidfile (null if none). */
static char *pidfile;

/* Create pidfile even if one already exists and is locked? */
static bool force;

/* Returns the file name that would be used for a pidfile if 'name' were
 * provided to set_pidfile().  The caller must free the returned string. */
char *
make_pidfile_name(const char *name) 
{
    return (!name ? xasprintf("%s/%s.pid", ofp_rundir, program_name)
            : *name == '/' ? xstrdup(name)
            : xasprintf("%s/%s", ofp_rundir, name));
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

/* Normally, die_if_already_running() will terminate the program with a message
 * if a locked pidfile already exists.  If this function is called,
 * die_if_already_running() will merely log a warning. */
void
ignore_existing_pidfile(void)
{
    force = true;
}

/* Sets up a following call to daemonize() to detach from the foreground
 * session, running this process in the background.  */
void
set_detach(void)
{
    detach = true;
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
        if (!force) {
            ofp_fatal(0, "%s: already running as pid %ld",
                      get_pidfile(), (long int) pid);
        } else {
            VLOG_WARN("%s: %s already running as pid %ld",
                      get_pidfile(), program_name, (long int) pid);
        }
    }
}

/* If a pidfile has been configured, creates it and stores the running process'
 * pid init.  Ensures that the pidfile will be deleted when the process
 * exits. */
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
    if (detach) {
        char c = 0;
        int fds[2];
        if (pipe(fds) < 0) {
            ofp_fatal(errno, "pipe failed");
        }

        switch (fork()) {
        default:
            /* Parent process: wait for child to create pidfile, then exit. */
            close(fds[1]);
            fatal_signal_fork();
            if (read(fds[0], &c, 1) != 1) {
                ofp_fatal(errno, "daemon child failed to signal startup");
            }
            exit(0);

        case 0:
            /* Child process. */
            close(fds[0]);
            make_pidfile();
            write(fds[1], &c, 1);
            close(fds[1]);
            setsid();
            chdir("/");
            break;

        case -1:
            /* Error. */
            ofp_fatal(errno, "could not fork");
            break;
        }
    } else {
        make_pidfile();
    }
}

void
daemon_usage(void)
{
    printf(
        "\nDaemon options:\n"
        "  -D, --detach            run in background as daemon\n"
        "  -P, --pidfile[=FILE]    create pidfile (default: %s/%s.pid)\n"
        "  -f, --force             with -P, start even if already running\n",
        ofp_rundir, program_name);
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
