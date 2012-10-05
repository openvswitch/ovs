/*
 * Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#include "timeval.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "command-line.h"
#include "daemon.h"
#include "util.h"

#undef NDEBUG
#include <assert.h>

static long long int
gettimeofday_in_msec(void)
{
    struct timeval tv;

    xgettimeofday(&tv);
    return timeval_to_msec(&tv);
}

static void
do_test(void)
{
    /* Wait until we are awakened by a signal (typically EINTR due to the
     * setitimer()).  Then ensure that, if time has really advanced by
     * TIME_UPDATE_INTERVAL, then time_msec() reports that it advanced.
     */
    long long int start_time_msec, start_time_wall;
    long long int start_gtod;

    start_time_msec = time_msec();
    start_time_wall = time_wall_msec();
    start_gtod = gettimeofday_in_msec();
    for (;;) {
        /* Wait up to 1 second.  Using select() to do the timeout avoids
         * interfering with the interval timer. */
        struct timeval timeout;
        int retval;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        retval = select(0, NULL, NULL, NULL, &timeout);
        if (retval != -1) {
            ovs_fatal(0, "select returned %d", retval);
        } else if (errno != EINTR) {
            ovs_fatal(errno, "select reported unexpected error");
        }

        if (gettimeofday_in_msec() - start_gtod >= TIME_UPDATE_INTERVAL) {
            /* gettimeofday() and time_msec() have different granularities in
             * their time sources.  Depending on the rounding used this could
             * result in a slight difference, so we allow for 1 ms of slop. */
            assert(time_msec() - start_time_msec >= TIME_UPDATE_INTERVAL - 1);
            assert(time_wall_msec() - start_time_wall >=
                                                      TIME_UPDATE_INTERVAL - 1);
            break;
        }
    }
}

static void
usage(void)
{
    ovs_fatal(0, "usage: %s TEST, where TEST is \"plain\" or \"daemon\"",
              program_name);
}

int
main(int argc, char *argv[])
{
    proctitle_init(argc, argv);
    set_program_name(argv[0]);

    if (argc != 2) {
        usage();
    } else if (!strcmp(argv[1], "plain")) {
        /* If we're not caching time there isn't much to test and SIGALRM won't
         * be around to pull us out of the select() call, so just skip out */
        if (!CACHE_TIME) {
            exit (77);
        }

        do_test();
    } else if (!strcmp(argv[1], "daemon")) {
        /* Test that time still advances even in a daemon.  This is an
         * interesting test because fork() cancels the interval timer. */
        char cwd[1024], *pidfile;
        FILE *success;

        if (!CACHE_TIME) {
            exit (77);
        }

        assert(getcwd(cwd, sizeof cwd) == cwd);

        unlink("test-timeval.success");

        /* Daemonize, with a pidfile in the current directory. */
        set_detach();
        pidfile = xasprintf("%s/test-timeval.pid", cwd);
        set_pidfile(pidfile);
        free(pidfile);
        set_no_chdir();
        daemonize();

        /* Run the test. */
        do_test();

        /* Report success by writing out a file, since the ultimate invoker of
         * test-timeval can't wait on the daemonized process. */
        success = fopen("test-timeval.success", "w");
        if (!success) {
            ovs_fatal(errno, "test-timeval.success: create failed");
        }
        fprintf(success, "success\n");
        fclose(success);
    } else {
        usage();
    }

    return 0;
}
