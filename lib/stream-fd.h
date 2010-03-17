/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef STREAM_FD_H
#define STREAM_FD_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct stream;
struct pstream;
struct sockaddr;

int new_fd_stream(const char *name, int fd, int connect_status,
                      char *unlink_path, struct stream **streamp);
int new_fd_pstream(const char *name, int fd,
                   int (*accept_cb)(int fd, const struct sockaddr *,
                                    size_t sa_len, struct stream **),
                   char *unlink_path,
                   struct pstream **pstreamp);

#endif /* stream-fd.h */
