/*
 * Copyright (c) 2008, 2009, 2012, 2014 Nicira, Inc.
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
 *
 * Note on windows platform, stream fd can only handle sockets, on unix any
 * fd is acceptable.
 */

#ifndef STREAM_FD_H
#define STREAM_FD_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct stream;
struct pstream;
struct sockaddr_storage;

int new_fd_stream(const char *name, int fd, int connect_status,
                  struct stream **streamp);
int new_fd_pstream(const char *name, int fd,
                   int (*accept_cb)(int fd, const struct sockaddr_storage *ss,
                                    size_t ss_len, struct stream **),
                   int (*set_dscp_cb)(int fd, uint8_t dscp),
                   char *unlink_path,
                   struct pstream **pstreamp);

#endif /* stream-fd.h */
