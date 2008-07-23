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
#include "util.h"

#define THIS_MODULE VLM_daemon
#include "vlog.h"

/* Should we run in the background? */
static bool detach;

/* Name of pidfile (null if none). */
static char *pidfile;

/* Returns the file name that would be used for a pidfile if 'name' were
 * provided to set_pidfile().  The caller must free the returned string. */
char *
make_pidfile_name(const char *name) 
{
    return (!name ? xasprintf("%s/%s.pid", RUNDIR, program_name)
            : *name == '/' ? xstrdup(name)
            : xasprintf("%s/%s", RUNDIR, name));
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

/* Sets up a following call to daemonize() to detach from the foreground
 * session, running this process in the background.  */
void
set_detach(void)
{
    detach = true;
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
            if (fcntl(fd, F_SETLK, &lck) >= 0) {
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
            fatal(errno, "pipe failed");
        }

        switch (fork()) {
        default:
            /* Parent process: wait for child to create pidfile, then exit. */
            close(fds[1]);
            fatal_signal_fork();
            read(fds[0], &c, 1);
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
            fatal(errno, "could not fork");
            break;
        }
    } else {
        make_pidfile();
    }
}

