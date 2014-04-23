/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "daemon-private.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(daemon);

/* For each of the standard file descriptors, whether to replace it by
 * /dev/null (if false) or keep it for the daemon to use (if true). */
static bool save_fds[3];

/* Will daemonize() really detach? */
bool
get_detach(void)
{
    return detach;
}

/* If configured with set_pidfile() or set_detach(), creates the pid file and
 * detaches from the foreground session.  */
void
daemonize(void)
{
    daemonize_start();
    daemonize_complete();
}

/* Sets up a following call to daemonize() to create a pidfile named 'name'.
 * If 'name' begins with '/' (or contains ':' in windows), then it is treated
 * as an absolute path. Otherwise, it is taken relative to RUNDIR,
 * which is $(prefix)/var/run by default.
 *
 * If 'name' is null, then program_name followed by ".pid" is used. */
void
set_pidfile(const char *name)
{
    assert_single_threaded();
    free(pidfile);
    pidfile = make_pidfile_name(name);
}

/* A daemon doesn't normally have any use for the file descriptors for stdin,
 * stdout, and stderr after it detaches.  To keep these file descriptors from
 * e.g. holding an SSH session open, by default detaching replaces each of
 * these file descriptors by /dev/null.  But a few daemons expect the user to
 * redirect stdout or stderr to a file, in which case it is desirable to keep
 * these file descriptors.  This function, therefore, disables replacing 'fd'
 * by /dev/null when the daemon detaches. */
void
daemon_save_fd(int fd)
{
    ovs_assert(fd == STDIN_FILENO ||
               fd == STDOUT_FILENO ||
               fd == STDERR_FILENO);
    save_fds[fd] = true;
}

/* Returns a readable and writable fd for /dev/null, if successful, otherwise
 * a negative errno value.  The caller must not close the returned fd (because
 * the same fd will be handed out to subsequent callers). */
static int
get_null_fd(void)
{
    static int null_fd;
#ifndef _WIN32
    char *device = "/dev/null";
#else
    char *device = "nul";
#endif

    if (!null_fd) {
        null_fd = open(device, O_RDWR);
        if (null_fd < 0) {
            int error = errno;
            VLOG_ERR("could not open %s: %s", device, ovs_strerror(error));
            null_fd = -error;
        }
    }

    return null_fd;
}

/* Close standard file descriptors (except any that the client has requested we
 * leave open by calling daemon_save_fd()).  If we're started from e.g. an SSH
 * session, then this keeps us from holding that session open artificially. */
void
close_standard_fds(void)
{
    int null_fd = get_null_fd();
    if (null_fd >= 0) {
        int fd;

        for (fd = 0; fd < 3; fd++) {
            if (!save_fds[fd]) {
                dup2(null_fd, fd);
            }
        }
    }

    /* Disable logging to stderr to avoid wasting CPU time. */
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_OFF);
}
