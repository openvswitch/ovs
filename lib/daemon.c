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

/* Sets up a following call to daemonize() to create a pidfile named 'name'.
 * If 'name' begins with '/', then it is treated as an absolute path.
 * Otherwise, it is taken relative to RUNDIR, which is $(prefix)/var/run by
 * default. */
void
set_pidfile(const char *name)
{
    free(pidfile);
    pidfile = *name == '/' ? xstrdup(name) : xasprintf("%s/%s", RUNDIR, name);
}

/* Sets up a following call to daemonize() to detach from the foreground
 * session, running this process in the background.  */
void
set_detach(void)
{
    detach = true;
}

/* If a pidfile has been configured, creates it and stores 'pid' in it.  It is
 * the caller's responsibility to make sure that the pidfile will eventually
 * be deleted. */
static void
make_pidfile(pid_t pid)
{
    if (pidfile) {
        FILE *file;

        file = fopen(pidfile, "w");
        if (file) {
            fprintf(file, "%ld\n", (long int) pid);
            fclose(file);
        } else {
            VLOG_ERR("failed to create \"%s\": %s", pidfile, strerror(errno));
        }
        free(pidfile);
        pidfile = NULL;
    }
}

/* If configured with set_pidfile() or set_detach(), creates the pid file and
 * detaches from the foreground session.  */
void
daemonize(void)
{
    if (detach) {
        pid_t pid;

        /* Fork and exit from the parent. */
        pid = fork();
        if (pid < 0) {
            fatal(errno, "could not fork");
        } else if (pid) {
            fatal_signal_fork();
            make_pidfile(pid);
            exit(0);
        }

        if (pidfile) {
            fatal_signal_add_file_to_unlink(pidfile);
        }
        setsid();
        chdir("/");
    } else {
        if (pidfile) {
            fatal_signal_add_file_to_unlink(pidfile);
        }
        make_pidfile(getpid());
    }
}

