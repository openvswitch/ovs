/*
 * Copyright (c) 2008, 2009, 2011, 2013 Nicira, Inc.
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

#ifndef PROCESS_H
#define PROCESS_H 1

#include <stdbool.h>
#include <sys/types.h>

struct process;

/* Starting and monitoring subprocesses.
 *
 * process_init() and process_start() may safely be called only from a
 * single-threaded parent process.  The parent process may safely create
 * additional threads afterward, as long as the remaining functions in this
 * group are called only from a single thread at any given time. */
void process_init(void);
int process_start(char **argv, struct process **);
void process_destroy(struct process *);
int process_kill(const struct process *, int signr);
pid_t process_pid(const struct process *);
const char *process_name(const struct process *);
bool process_exited(struct process *);
int process_status(const struct process *);
void process_run(void);
void process_wait(struct process *);

/* These functions are thread-safe. */
char *process_status_msg(int);
char *process_escape_args(char **argv);
char *process_search_path(const char *);

#endif /* process.h */
