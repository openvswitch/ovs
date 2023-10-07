/*
 * Copyright (C) 2023 Hewlett Packard Enterprise Development LP
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "byteq.h"
#include "ovstest.h"
#include "util.h"

static void test_byteq_main(int argc, char *argv[]);
static void test_byteq_put_get(void);
static void test_byteq_putn_get(void);
static void test_byteq_put_string(void);
static void test_byteq_write_read(void);

#define SIZE 256

static void
test_byteq_put_get(void)
{
    struct byteq bq;
    uint8_t buffer[SIZE];
    const char *input = "Open vSwitch";
    const int input_len = strlen(input);

    byteq_init(&bq, buffer, SIZE);
    for (int i = 0; i < input_len; i++) {
        byteq_put(&bq, input[i]);
    }
    for (int i = 0; i < input_len; i++) {
        ovs_assert(byteq_get(&bq) == input[i]);
    }
}

static void
test_byteq_putn_get(void)
{
    struct byteq bq;
    uint8_t buffer[SIZE];
    const char *input = "Open vSwitch";
    const int input_len = strlen(input);

    byteq_init(&bq, buffer, SIZE);
    byteq_putn(&bq, input, input_len);
    for (int i = 0; i < input_len; i++) {
        ovs_assert(byteq_get(&bq) == input[i]);
    }
}

static void
test_byteq_put_string(void)
{
    struct byteq bq;
    uint8_t buffer[SIZE];
    const char *input = "Open vSwitch";
    const int input_len = strlen(input);

    byteq_init(&bq, buffer, SIZE);
    byteq_put_string(&bq, input);
    for (int i = 0; i < input_len; i++) {
        ovs_assert(byteq_get(&bq) == input[i]);
    }
}

static void
test_byteq_write_read(void)
{
#ifndef _WIN32
    int fd[2];
    pid_t childpid;
    int rc;
    struct byteq bq;
    uint8_t buffer[SIZE];
    const char *input = "Open vSwitch";
    const int input_len = strlen(input);

    byteq_init(&bq, buffer, SIZE);
    byteq_put_string(&bq, input);

    rc = pipe(fd);
    ovs_assert(rc == 0);

    /* Flush stdout */
    fflush(stdout);

    childpid = fork();
    ovs_assert(childpid != -1);
    if (childpid == 0) {
        /* Child process closes stdout */
        close(STDOUT_FILENO);
        /* Child process closes up input side of pipe */
        close(fd[0]);
        rc = byteq_write(&bq, fd[1]);
        ovs_assert(rc == 0);
        exit(0);
    } else {
        /* Parent process closes up output side of pipe */
        close(fd[1]);
        rc = byteq_read(&bq, fd[0]);
        ovs_assert(rc == EOF);
        for (int i = 0; i < input_len; i++) {
            ovs_assert(byteq_get(&bq) == input[i]);
        }
    }
#endif /* _WIN32 */
}

static void
run_test(void (*function)(void))
{
    function();
    printf(".");
}

static void
test_byteq_main(int argc, char *argv[])
{
    if (argc != 2) {
        ovs_fatal(0, "exactly one argument required\n"
                     "the argument must be one of the following:\n"
                     "\tbasic\n"
                     "\twrite_read\n");
    }

    if (strcmp(argv[1], "write_read") == 0) {
        run_test(test_byteq_write_read);
        printf("\n");
    } else if (strcmp(argv[1], "basic") == 0) {
        run_test(test_byteq_put_get);
        run_test(test_byteq_putn_get);
        run_test(test_byteq_put_string);
        printf("\n");
    } else {
        ovs_fatal(0, "invalid argument\n"
                     "the argument must be one of the following:\n"
                     "\tbasic\n"
                     "\twrite_read\n");
    }
}

OVSTEST_REGISTER("test-byteq", test_byteq_main);
