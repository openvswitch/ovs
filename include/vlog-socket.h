/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef VLOG_SOCKET_H
#define VLOG_SOCKET_H 1

/* Server for Vlog control connection. */
struct vlog_server;
int vlog_server_listen(const char *path, struct vlog_server **);
void vlog_server_close(struct vlog_server *);
int vlog_server_get_fd(const struct vlog_server *);
void vlog_server_poll(struct vlog_server *);

/* Client for Vlog control connection. */
struct vlog_client;
int vlog_client_connect(const char *path, struct vlog_client **);
void vlog_client_close(struct vlog_client *);
int vlog_client_send(struct vlog_client *, const char *request);
int vlog_client_recv(struct vlog_client *, char **reply);
int vlog_client_transact(struct vlog_client *,
                         const char *request, char **reply);
const char *vlog_client_target(const struct vlog_client *);

#endif /* vlog-socket.h */
