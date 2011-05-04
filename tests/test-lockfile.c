/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#include "lockfile.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "process.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

#undef NDEBUG
#include <assert.h>

struct test {
    const char *name;
    void (*function)(void);
};

static const struct test tests[];

static void
run_lock_and_unlock(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    lockfile_unlock(lockfile);
}

static void
run_lock_and_unlock_twice(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    lockfile_unlock(lockfile);

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    lockfile_unlock(lockfile);
}

static void
run_lock_blocks_same_process(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    assert(lockfile_lock("file", 0, &lockfile) == EDEADLK);
    lockfile_unlock(lockfile);
}

static void
run_lock_blocks_same_process_twice(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    assert(lockfile_lock("file", 0, &lockfile) == EDEADLK);
    assert(lockfile_lock("file", 0, &lockfile) == EDEADLK);
    lockfile_unlock(lockfile);
}

static enum { PARENT, CHILD }
do_fork(void)
{
    switch (fork()) {
    case 0:
        time_postfork();
        lockfile_postfork();
        return CHILD;

    default:
        return PARENT;

    case -1:
        /* Error. */
        ovs_fatal(errno, "fork failed");
    }
}

static void
run_lock_blocks_other_process(void)
{
    /* Making this static prevents a memory leak warning from valgrind for the
     * parent process, which cannot easily unlock (and free) 'lockfile' because
     * it can only do so after the child has exited, and it's the caller of
     * this function that does the wait() call. */
    static struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    if (do_fork() == CHILD) {
        lockfile_unlock(lockfile);
        assert(lockfile_lock("file", 0, &lockfile) == EAGAIN);
        exit(11);
    }
}

static void
run_lock_twice_blocks_other_process(void)
{
    struct lockfile *lockfile, *dummy;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    assert(lockfile_lock("file", 0, &dummy) == EDEADLK);
    if (do_fork() == CHILD) {
        assert(lockfile_lock("file", 0, &dummy) == EAGAIN);
        exit(11);
    }
}

static void
run_lock_and_unlock_allows_other_process(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);
    lockfile_unlock(lockfile);

    if (do_fork() == CHILD) {
        assert(lockfile_lock("file", 0, &lockfile) == 0);
        exit(11);
    }
}

static void
run_lock_timeout_gets_the_lock(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);

    if (do_fork() == CHILD) {
        lockfile_unlock(lockfile);
        assert(lockfile_lock("file", TIME_UPDATE_INTERVAL * 3,
                             &lockfile) == 0);
        exit(11);
    } else {
        long long int now = time_msec();
        while (time_msec() < now + TIME_UPDATE_INTERVAL) {
            pause();
        }
        lockfile_unlock(lockfile);
    }
}

static void
run_lock_timeout_runs_out(void)
{
    struct lockfile *lockfile;

    assert(lockfile_lock("file", 0, &lockfile) == 0);

    if (do_fork() == CHILD) {
        lockfile_unlock(lockfile);
        assert(lockfile_lock("file", TIME_UPDATE_INTERVAL,
                             &lockfile) == ETIMEDOUT);
        exit(11);
    } else {
        long long int now = time_msec();
        while (time_msec() < now + TIME_UPDATE_INTERVAL * 3) {
            pause();
        }
        lockfile_unlock(lockfile);
    }
}

static void
run_lock_multiple(void)
{
    struct lockfile *a, *b, *c, *dummy;

    assert(lockfile_lock("a", 0, &a) == 0);
    assert(lockfile_lock("b", 0, &b) == 0);
    assert(lockfile_lock("c", 0, &c) == 0);

    lockfile_unlock(a);
    assert(lockfile_lock("a", 0, &a) == 0);
    assert(lockfile_lock("a", 0, &dummy) == EDEADLK);
    lockfile_unlock(a);

    lockfile_unlock(b);
    assert(lockfile_lock("a", 0, &a) == 0);

    lockfile_unlock(c);
    lockfile_unlock(a);
}

static void
run_help(void)
{
    size_t i;

    printf("usage: %s TESTNAME\n"
           "where TESTNAME is one of the following:\n",
           program_name);
    for (i = 0; tests[i].name; i++) {
        fprintf(stderr, "\t%s\n", tests[i].name);
    }
}

static const struct test tests[] = {
#define TEST(NAME) { #NAME, run_##NAME }
    TEST(lock_and_unlock),
    TEST(lock_and_unlock_twice),
    TEST(lock_blocks_same_process),
    TEST(lock_blocks_same_process_twice),
    TEST(lock_blocks_other_process),
    TEST(lock_twice_blocks_other_process),
    TEST(lock_and_unlock_allows_other_process),
    TEST(lock_timeout_gets_the_lock),
    TEST(lock_timeout_runs_out),
    TEST(lock_multiple),
    TEST(help),
    { NULL, NULL }
#undef TEST
};

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_lockfile;
    size_t i;

    set_program_name(argv[0]);
    vlog_set_levels(&VLM_lockfile, VLF_ANY_FACILITY, VLL_ERR);

    if (argc != 2) {
        ovs_fatal(0, "exactly one argument required; use \"%s help\" for help",
                  program_name);
        return 1;
    }

    for (i = 0; tests[i].name; i++) {
        if (!strcmp(argv[1], tests[i].name)) {
            int n_children;
            int status;

            (tests[i].function)();

            n_children = 0;
            while (wait(&status) > 0) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 11) {
                    n_children++;
                } else {
                    ovs_fatal(0, "child exited in unexpected way: %s",
                              process_status_msg(status));
                }
            }
            if (errno != ECHILD) {
                ovs_fatal(errno, "wait");
            }

            printf("%s: success (%d child%s)\n",
                   tests[i].name, n_children, n_children != 1 ? "ren" : "");
            exit(0);
        }
    }
    ovs_fatal(0, "unknown test \"%s\"; use \"%s help\" for help",
              argv[1], program_name);
}

