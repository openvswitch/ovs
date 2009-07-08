/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

#endif /* process.h */
