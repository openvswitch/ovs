/*
 * Copyright (c) 2008 Nicira Networks.
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

#ifndef VCONN_STREAM_H
#define VCONN_STREAM_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vconn;
struct pvconn;
struct sockaddr;

int new_stream_vconn(const char *name, int fd, int connect_status,
                     uint32_t ip, bool reconnectable, struct vconn **vconnp);
int new_pstream_pvconn(const char *name, int fd,
                      int (*accept_cb)(int fd, const struct sockaddr *,
                                       size_t sa_len, struct vconn **),
                      struct pvconn **pvconnp);

#endif /* vconn-stream.h */
