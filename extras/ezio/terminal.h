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

#ifndef TERMINAL_H
#define TERMINAL_H 1

#include <stdbool.h>
#include <stdint.h>

struct ezio;

struct terminal *terminal_create(void);
void terminal_destroy(struct terminal *);
int terminal_run(struct terminal *, struct ezio *, int input_fd);
void terminal_wait(struct terminal *, int input_fd);

#endif /* terminal.h */
