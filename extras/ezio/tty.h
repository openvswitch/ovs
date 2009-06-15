/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
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

#ifndef TTY_H
#define TTY_H 1

#include <termios.h>

int tty_lock(const char *dev_name);
int tty_set_raw_mode(int fd, speed_t);
int tty_open_master_pty(void);
int tty_fork_child(int master_fd, char *argv[]);
int tty_set_window_size(int fd, int n_rows, int n_columns);

#endif /* tty.h */
