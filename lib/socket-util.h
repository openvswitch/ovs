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

#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>

int set_nonblocking(int fd);
int get_max_fds(void);
int lookup_ip(const char *host_name, struct in_addr *address);
int get_socket_error(int sock);
int check_connection_completion(int fd);
int drain_rcvbuf(int fd);
void drain_fd(int fd, size_t n_packets);
int make_unix_socket(int style, bool nonblock, bool passcred,
                     const char *bind_path, const char *connect_path);
int get_unix_name_len(socklen_t sun_len);
uint32_t guess_netmask(uint32_t ip);

int read_fully(int fd, void *, size_t, size_t *bytes_read);
int write_fully(int fd, const void *, size_t, size_t *bytes_written);

#endif /* socket-util.h */
