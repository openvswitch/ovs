/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "openvswitch/types.h"
#include <netinet/in_systm.h>
#include <netinet/ip.h>

int set_nonblocking(int fd);
void xset_nonblocking(int fd);
int set_dscp(int fd, uint8_t dscp);

int get_max_fds(void);

int lookup_ip(const char *host_name, struct in_addr *address);
int lookup_ipv6(const char *host_name, struct in6_addr *address);

int lookup_hostname(const char *host_name, struct in_addr *);

int get_socket_rcvbuf(int sock);
int check_connection_completion(int fd);
int drain_rcvbuf(int fd);
void drain_fd(int fd, size_t n_packets);
int make_unix_socket(int style, bool nonblock,
                     const char *bind_path, const char *connect_path);
int get_unix_name_len(socklen_t sun_len);
ovs_be32 guess_netmask(ovs_be32 ip);
int get_null_fd(void);

bool inet_parse_active(const char *target, uint16_t default_port,
                       struct sockaddr_in *sinp);
int inet_open_active(int style, const char *target, uint16_t default_port,
		     struct sockaddr_in *sinp, int *fdp, uint8_t dscp);

bool inet_parse_passive(const char *target, int default_port,
                        struct sockaddr_in *sinp);
int inet_open_passive(int style, const char *target, int default_port,
                      struct sockaddr_in *sinp, uint8_t dscp);

int read_fully(int fd, void *, size_t, size_t *bytes_read);
int write_fully(int fd, const void *, size_t, size_t *bytes_written);

int fsync_parent_dir(const char *file_name);
int get_mtime(const char *file_name, struct timespec *mtime);

void xpipe(int fds[2]);
void xpipe_nonblocking(int fds[2]);

char *describe_fd(int fd);

/* Default value of dscp bits for connection between controller and manager.
 * Value of IPTOS_PREC_INTERNETCONTROL = 0xc0 which is defined
 * in <netinet/ip.h> is used. */
#define DSCP_DEFAULT (IPTOS_PREC_INTERNETCONTROL >> 2)

/* Maximum number of fds that we support sending or receiving at one time
 * across a Unix domain socket. */
#define SOUTIL_MAX_FDS 8

/* Iovecs. */
size_t iovec_len(const struct iovec *iovs, size_t n_iovs);
bool iovec_is_empty(const struct iovec *iovs, size_t n_iovs);

/* Functions particularly useful for Unix domain sockets. */
void xsocketpair(int domain, int type, int protocol, int fds[2]);
int send_iovec_and_fds(int sock,
                       const struct iovec *iovs, size_t n_iovs,
                       const int fds[], size_t n_fds);
int send_iovec_and_fds_fully(int sock,
                             const struct iovec *iovs, size_t n_iovs,
                             const int fds[], size_t n_fds,
                             size_t skip_bytes, size_t *bytes_sent);
int send_iovec_and_fds_fully_block(int sock,
                                   const struct iovec *iovs, size_t n_iovs,
                                   const int fds[], size_t n_fds);
int recv_data_and_fds(int sock,
                      void *data, size_t size,
                      int fds[SOUTIL_MAX_FDS], size_t *n_fdsp);

/* Helpers for calling ioctl() on an AF_INET socket. */
struct ifreq;
int af_inet_ioctl(unsigned long int command, const void *arg);
int af_inet_ifreq_ioctl(const char *name, struct ifreq *,
                        unsigned long int cmd, const char *cmd_name);

#endif /* socket-util.h */
