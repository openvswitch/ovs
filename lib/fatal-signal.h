/*
 * Copyright (c) 2008, 2009, 2010, 2013 Nicira, Inc.
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

#ifndef FATAL_SIGNAL_H
#define FATAL_SIGNAL_H 1

#include <stdbool.h>

/* Basic interface. */
void fatal_signal_init(void);
void fatal_signal_add_hook(void (*hook_cb)(void *aux),
                           void (*cancel_cb)(void *aux), void *aux,
                           bool run_at_exit);
void fatal_signal_fork(void);
void fatal_signal_run(void);
void fatal_signal_wait(void);
void fatal_ignore_sigpipe(void);

/* Convenience functions for unlinking files upon termination.
 *
 * These functions also unlink the files upon normal process termination via
 * exit(). */
void fatal_signal_add_file_to_unlink(const char *);
void fatal_signal_remove_file_to_unlink(const char *);
int fatal_signal_unlink_file_now(const char *);

/* Interface for other code that catches one of our signals and needs to pass
 * it through. */
void fatal_signal_handler(int sig_nr);

#endif /* fatal-signal.h */
