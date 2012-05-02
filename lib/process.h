/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
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
void process_init(void);
char *process_escape_args(char **argv);
int process_start(char **argv,
                  const int *keep_fds, size_t n_keep_fds,
                  const int *null_fds, size_t n_null_fds,
                  struct process **);
void process_destroy(struct process *);
int process_kill(const struct process *, int signr);

int process_run(char **argv,
                const int *keep_fds, size_t n_keep_fds,
                  const int *null_fds, size_t n_null_fds,
                int *status);

pid_t process_pid(const struct process *);
const char *process_name(const struct process *);
bool process_exited(struct process *);
int process_status(const struct process *);
char *process_status_msg(int);

void process_wait(struct process *);

char *process_search_path(const char *);

int process_run_capture(char **argv, char **stdout_log, char **stderr_log,
                        size_t max_log, int *status);

#endif /* process.h */
