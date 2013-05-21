/*
 * Copyright (c) 2008, 2009, 2010 Nicira, Inc.
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

#ifndef COMMAND_LINE_H
#define COMMAND_LINE_H 1

/* Utilities for command-line parsing. */

#include "compiler.h"

struct option;

struct command {
    const char *name;
    int min_args;
    int max_args;
    void (*handler)(int argc, char *argv[]);
};

char *long_options_to_short_options(const struct option *options);
void run_command(int argc, char *argv[], const struct command[]);

void proctitle_init(int argc, char **argv);
#if defined(__FreeBSD__) || defined(__NetBSD__)
#define proctitle_set setproctitle
#else
void proctitle_set(const char *, ...)
    PRINTF_FORMAT(1, 2);
#endif
void proctitle_restore(void);

#endif /* command-line.h */
