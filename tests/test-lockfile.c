/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2014 Nicira, Inc.
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
#undef NDEBUG
#include "lockfile.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ovstest.h"
#include "process.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

struct test {
    const char *name;
    void (*function)(void);
};

static void run_help(void);

#define CHECK(A, B) check(A, B, #A, #B, __FILE__, __LINE__)
static void
check(int a, int b,
      const char *a_string, const char *b_string, const char *file, int line)
{
    if (a != b) {
        fprintf(stderr, "%s:%d: expected %s == %s but %d != %d\n",
                file, line, a_string, b_string, a, b);
        fflush(stderr);
        abort();
    }
}

static void
run_lock_and_unlock(void)
{
    struct lockfile *lockfile;

    CHECK(lockfile_lock("file", &lockfile), 0);
    lockfile_unlock(lockfile);
}

static void
run_lock_and_unlock_twice(void)
{
    struct lockfile *lockfile;

    CHECK(lockfile_lock("file", &lockfile), 0);
    lockfile_unlock(lockfile);

    CHECK(lockfile_lock("file", &lockfile), 0);
    lockfile_unlock(lockfile);
}

static void
run_lock_blocks_same_process(void)
{
    struct lockfile *lockfile;

    CHECK(lockfile_lock("file", &lockfile), 0);
    CHECK(lockfile_lock("file", &lockfile), EDEADLK);
    lockfile_unlock(lockfile);
}

static void
run_lock_blocks_same_process_twice(void)
{
    struct lockfile *lockfile;

    CHECK(lockfile_lock("file", &lockfile), 0);
    CHECK(lockfile_lock("file", &lockfile), EDEADLK);
    CHECK(lockfile_lock("file", &lockfile), EDEADLK);
    lockfile_unlock(lockfile);
}

#ifndef _WIN32
static enum { PARENT, CHILD }
do_fork(void)
{
    switch (fork()) {
    case 0:
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

    CHECK(lockfile_lock("file", &lockfile), 0);
    if (do_fork() == CHILD) {
        lockfile_unlock(lockfile);
        CHECK(lockfile_lock("file", &lockfile), EAGAIN);
        exit(11);
    }
}

static void
run_lock_twice_blocks_other_process(void)
{
    struct lockfile *lockfile, *dummy;

    CHECK(lockfile_lock("file", &lockfile), 0);
    CHECK(lockfile_lock("file", &dummy), EDEADLK);
    if (do_fork() == CHILD) {
        CHECK(lockfile_lock("file", &dummy), EAGAIN);
        exit(11);
    }
}

static void
run_lock_and_unlock_allows_other_process(void)
{
    struct lockfile *lockfile;

    CHECK(lockfile_lock("file", &lockfile), 0);
    lockfile_unlock(lockfile);

    if (do_fork() == CHILD) {
        CHECK(lockfile_lock("file", &lockfile), 0);
        exit(11);
    }
}

/* Checks that locking a dangling symlink works OK.  (It used to hang.) */
static void
run_lock_symlink(void)
{
    struct lockfile *a, *b, *dummy;
    struct stat s;

    /* Create a symlink .a.~lock~ pointing to .b.~lock~. */
    CHECK(symlink(".b.~lock~", ".a.~lock~"), 0);
    CHECK(lstat(".a.~lock~", &s), 0);
    CHECK(S_ISLNK(s.st_mode) != 0, 1);
    CHECK(stat(".a.~lock~", &s), -1);
    CHECK(errno, ENOENT);
    CHECK(stat(".b.~lock~", &s), -1);
    CHECK(errno, ENOENT);

    CHECK(lockfile_lock("a", &a), 0);
    CHECK(lockfile_lock("a", &dummy), EDEADLK);
    CHECK(lockfile_lock("b", &dummy), EDEADLK);
    lockfile_unlock(a);

    CHECK(lockfile_lock("b", &b), 0);
    CHECK(lockfile_lock("b", &dummy), EDEADLK);
    CHECK(lockfile_lock("a", &dummy), EDEADLK);
    lockfile_unlock(b);

    CHECK(lstat(".a.~lock~", &s), 0);
    CHECK(S_ISLNK(s.st_mode) != 0, 1);
    CHECK(stat(".a.~lock~", &s), 0);
    CHECK(S_ISREG(s.st_mode) != 0, 1);
    CHECK(stat(".b.~lock~", &s), 0);
    CHECK(S_ISREG(s.st_mode) != 0, 1);
}

/* Checks that locking a file that is itself a symlink yields a lockfile in the
 * directory that the symlink points to, named for the target of the
 * symlink.
 *
 * (That is, if "a" is a symlink to "dir/b", then "a"'s lockfile is named
 * "dir/.b.~lock".) */
static void
run_lock_symlink_to_dir(void)
{
    struct lockfile *a, *dummy;
    struct stat s;

    /* Create a symlink "a" pointing to "dir/b". */
    CHECK(mkdir("dir", 0700), 0);
    CHECK(symlink("dir/b", "a"), 0);
    CHECK(lstat("a", &s), 0);
    CHECK(S_ISLNK(s.st_mode) != 0, 1);

    /* Lock 'a'. */
    CHECK(lockfile_lock("a", &a), 0);
    CHECK(lstat("dir/.b.~lock~", &s), 0);
    CHECK(S_ISREG(s.st_mode) != 0, 1);
    CHECK(lstat(".a.~lock~", &s), -1);
    CHECK(errno, ENOENT);
    CHECK(lockfile_lock("dir/b", &dummy), EDEADLK);

    lockfile_unlock(a);
}
#endif /* _WIN32 */

static void
run_lock_multiple(void)
{
    struct lockfile *a, *b, *c, *dummy;

    CHECK(lockfile_lock("a", &a), 0);
    CHECK(lockfile_lock("b", &b), 0);
    CHECK(lockfile_lock("c", &c), 0);

    lockfile_unlock(a);
    CHECK(lockfile_lock("a", &a), 0);
    CHECK(lockfile_lock("a", &dummy), EDEADLK);
    lockfile_unlock(a);

    lockfile_unlock(b);
    CHECK(lockfile_lock("a", &a), 0);

    lockfile_unlock(c);
    lockfile_unlock(a);
}


static const struct test tests[] = {
#define TEST(NAME) { #NAME, run_##NAME }
    TEST(lock_and_unlock),
    TEST(lock_and_unlock_twice),
    TEST(lock_blocks_same_process),
    TEST(lock_blocks_same_process_twice),
#ifndef _WIN32
    TEST(lock_blocks_other_process),
    TEST(lock_twice_blocks_other_process),
    TEST(lock_and_unlock_allows_other_process),
    TEST(lock_symlink),
    TEST(lock_symlink_to_dir),
#endif /* _WIN32 */
    TEST(lock_multiple),
    TEST(help),
    { NULL, NULL }
#undef TEST
};

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

static void
test_lockfile_main(int argc, char *argv[])
{
    size_t i;

    set_program_name(argv[0]);
    vlog_set_pattern(VLF_CONSOLE, "%c|%p|%m");
    vlog_set_levels(NULL, VLF_SYSLOG, VLL_OFF);

    if (argc != 2) {
        ovs_fatal(0, "exactly one argument required; use \"%s help\" for help",
                  program_name);
    }

    for (i = 0; tests[i].name; i++) {
        if (!strcmp(argv[1], tests[i].name)) {
            int n_children;
            int status;

            (tests[i].function)();

            n_children = 0;
#ifndef _WIN32
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
#endif /* _WIN32 */

            printf("%s: success (%d child%s)\n",
                   tests[i].name, n_children, n_children != 1 ? "ren" : "");
            exit(0);
        }
    }
    ovs_fatal(0, "unknown test \"%s\"; use \"%s help\" for help",
              argv[1], program_name);
}

OVSTEST_REGISTER("test-lockfile", test_lockfile_main);
