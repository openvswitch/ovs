/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "openvswitch/types.h"

int set_nonblocking(int fd);
int get_max_fds(void);

int lookup_ip(const char *host_name, struct in_addr *address);
int lookup_ipv6(const char *host_name, struct in6_addr *address);

int lookup_hostname(const char *host_name, struct in_addr *);

int get_socket_error(int sock);
int check_connection_completion(int fd);
int drain_rcvbuf(int fd);
void drain_fd(int fd, size_t n_packets);
int make_unix_socket(int style, bool nonblock, bool passcred,
                     const char *bind_path, const char *connect_path);
int get_unix_name_len(socklen_t sun_len);
ovs_be32 guess_netmask(ovs_be32 ip);
int get_null_fd(void);

bool inet_parse_active(const char *target, uint16_t default_port,
                       struct sockaddr_in *sinp);
int inet_open_active(int style, const char *target, uint16_t default_port,
                    struct sockaddr_in *sinp, int *fdp);

bool inet_parse_passive(const char *target, uint16_t default_port,
                        struct sockaddr_in *sinp);
int inet_open_passive(int style, const char *target, int default_port,
                      struct sockaddr_in *sinp);

int read_fully(int fd, void *, size_t, size_t *bytes_read);
int write_fully(int fd, const void *, size_t, size_t *bytes_written);

int fsync_parent_dir(const char *file_name);
int get_mtime(const char *file_name, struct timespec *mtime);

void xpipe(int fds[2]);

char *describe_fd(int fd);

#endif /* socket-util.h */
