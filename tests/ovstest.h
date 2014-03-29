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

#ifndef OVSTEST_H
#define OVSTEST_H

/* Overview
 * ========
 *
 * OVS tests directory contains many small test programs. One down side
 * of building them as individual programs is that they all have to be
 * linked whenever a library function is modified.
 *
 * ovstest is an attempt to improve the overall build time by linking
 * all test programs into a single program, ovs-test. Regardless of
 * the number of test programs, linking will be done only once to produce
 * ovstest.
 *
 * With ovs-test, each test programs now becomes a sub program of ovstest.
 * For example, 'mytest' program, can now be invoked as 'ovs mytest'.
 *
 * 'ovstest --help' will list all test programs can be invoked.
 *
 * The Usage comment section below documents how a new test program can
 * be added to ovs-test.
 */

typedef void (*ovstest_func)(int argc, char *argv[]);

void
ovstest_register(const char *test_name, ovstest_func f,
                  const struct command * sub_commands);

/* Usage
 * =====
 *
 * For each test sub program, its 'main' program should be named as
 * '<test_name>_main()'.
 *
 * OVSTEST_REGISTER register the sub program with ovs-test top level
 * command line parser. <test_name> is expected as argv[1] when invoking
 * ovs-test.
 *
 * In case the test program has sub commands, its command array can be
 * passed in  as <sub_command>. Otherwise, NULL can be used instead.
 *
 * Example:
 * ----------
 *
 * Suppose the test program is called my-test.c
 * ...
 *
 * static void
 * my_test_main(int argc, char *argv[])
 * {
 *   ....
 * }
 *
 * // The last parameter is NULL in case my-test.c does
 * // not have sub commands. Otherwise, its command
 * // array can replace the NULL here.
 *
 * OVSTEST_REGISTER("my-test", my_test_main, NULL);
 */

#define OVSTEST_REGISTER(name, function, sub_commands) \
    OVS_CONSTRUCTOR(register_##function) { \
        ovstest_register(name, function, sub_commands); \
    }

#endif
