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

#ifndef UNIXCTL_H
#define UNIXCTL_H 1

/* Server for Unix domain socket control connection. */
struct unixctl_server;
int unixctl_server_create(const char *path, struct unixctl_server **);
void unixctl_server_run(struct unixctl_server *);
void unixctl_server_wait(struct unixctl_server *);
void unixctl_server_destroy(struct unixctl_server *);

/* Client for Unix domain socket control connection. */
struct unixctl_client;
int unixctl_client_create(const char *path, struct unixctl_client **);
void unixctl_client_destroy(struct unixctl_client *);
int unixctl_client_transact(struct unixctl_client *,
                            const char *request,
                            int *reply_code, char **reply_body);
const char *unixctl_client_target(const struct unixctl_client *);

/* Command registration. */
struct unixctl_conn;
void unixctl_command_register(const char *name,
                              void (*cb)(struct unixctl_conn *,
                                         const char *args));
void unixctl_command_reply(struct unixctl_conn *, int code,
                           const char *body);

#endif /* unixctl.h */
