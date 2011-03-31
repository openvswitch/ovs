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

#include <config.h>
#include "unixctl.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "coverage.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "list.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "shash.h"
#include "socket-util.h"
#include "svec.h"
#include "util.h"
#include "vlog.h"

#ifndef SCM_CREDENTIALS
#include <time.h>
#endif

VLOG_DEFINE_THIS_MODULE(unixctl);

COVERAGE_DEFINE(unixctl_received);
COVERAGE_DEFINE(unixctl_replied);

struct unixctl_command {
    unixctl_cb_func *cb;
    void *aux;
};

struct unixctl_conn {
    struct list node;
    int fd;

    enum { S_RECV, S_PROCESS, S_SEND } state;
    struct ofpbuf in;
    struct ds out;
    size_t out_pos;
};

/* Server for control connection. */
struct unixctl_server {
    char *path;
    int fd;
    struct list conns;
};

/* Client for control connection. */
struct unixctl_client {
    char *connect_path;
    char *bind_path;
    FILE *stream;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

static struct shash commands = SHASH_INITIALIZER(&commands);

static void
unixctl_help(struct unixctl_conn *conn, const char *args OVS_UNUSED,
             void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct shash_node *node;
    struct svec names;
    const char *name;
    size_t i;

    ds_put_cstr(&ds, "The available commands are:\n");

    svec_init(&names);
    SHASH_FOR_EACH (node, &commands) {
        svec_add(&names, node->name);
    }
    svec_sort(&names);

    SVEC_FOR_EACH (i, name, &names) {
        ds_put_format(&ds, "\t%s\n", name);
    }
    svec_destroy(&names);

    unixctl_command_reply(conn, 214, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
unixctl_command_register(const char *name, unixctl_cb_func *cb, void *aux)
{
    struct unixctl_command *command;

    assert(!shash_find_data(&commands, name)
           || shash_find_data(&commands, name) == cb);
    command = xmalloc(sizeof *command);
    command->cb = cb;
    command->aux = aux;
    shash_add(&commands, name, command);
}

static const char *
translate_reply_code(int code)
{
    switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 211: return "System Status";
    case 214: return "Help";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    case 501: return "Invalid Argument";
    case 503: return "Service Unavailable";
    default: return "Unknown";
    }
}

void
unixctl_command_reply(struct unixctl_conn *conn,
                      int code, const char *body)
{
    struct ds *out = &conn->out;

    COVERAGE_INC(unixctl_replied);
    assert(conn->state == S_PROCESS);
    conn->state = S_SEND;
    conn->out_pos = 0;

    ds_clear(out);
    ds_put_format(out, "%03d %s\n", code, translate_reply_code(code));
    if (body) {
        const char *p;
        for (p = body; *p != '\0'; ) {
            size_t n = strcspn(p, "\n");

            if (*p == '.') {
                ds_put_char(out, '.');
            }
            ds_put_buffer(out, p, n);
            ds_put_char(out, '\n');
            p += n;
            if (*p == '\n') {
                p++;
            }
        }
    }
    ds_put_cstr(out, ".\n");
}

/* Creates a unixctl server listening on 'path', which may be:
 *
 *      - NULL, in which case <rundir>/<program>.<pid>.ctl is used.
 *
 *      - "none", in which case the function will return successfully but
 *        no socket will actually be created.
 *
 *      - A name that does not start with '/', in which case it is put in
 *        <rundir>.
 *
 *      - An absolute path (starting with '/') that gives the exact name of
 *        the Unix domain socket to listen on.
 *
 * A program that (optionally) daemonizes itself should call this function
 * *after* daemonization, so that the socket name contains the pid of the
 * daemon instead of the pid of the program that exited.  (Otherwise,
 * "ovs-appctl --target=<program>" will fail.)
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*serverp' to the new unixctl_server (or to NULL if 'path' was "none"),
 * otherwise to NULL. */
int
unixctl_server_create(const char *path, struct unixctl_server **serverp)
{
    struct unixctl_server *server;
    int error;

    if (path && !strcmp(path, "none")) {
        *serverp = NULL;
        return 0;
    }

    unixctl_command_register("help", unixctl_help, NULL);

    server = xmalloc(sizeof *server);
    list_init(&server->conns);

    if (path) {
        server->path = abs_file_name(ovs_rundir(), path);
    } else {
        server->path = xasprintf("%s/%s.%ld.ctl", ovs_rundir(),
                                 program_name, (long int) getpid());
    }

    server->fd = make_unix_socket(SOCK_STREAM, true, false, server->path,
                                  NULL);
    if (server->fd < 0) {
        error = -server->fd;
        ovs_error(error, "could not initialize control socket %s",
                  server->path);
        goto error;
    }

    if (chmod(server->path, S_IRUSR | S_IWUSR) < 0) {
        error = errno;
        ovs_error(error, "failed to chmod control socket %s", server->path);
        goto error;
    }

    if (listen(server->fd, 10) < 0) {
        error = errno;
        ovs_error(error, "Failed to listen on control socket %s",
                  server->path);
        goto error;
    }

    *serverp = server;
    return 0;

error:
    if (server->fd >= 0) {
        close(server->fd);
    }
    free(server->path);
    free(server);
    *serverp = NULL;
    return error;
}

static void
new_connection(struct unixctl_server *server, int fd)
{
    struct unixctl_conn *conn;

    set_nonblocking(fd);

    conn = xmalloc(sizeof *conn);
    list_push_back(&server->conns, &conn->node);
    conn->fd = fd;
    conn->state = S_RECV;
    ofpbuf_init(&conn->in, 128);
    ds_init(&conn->out);
    conn->out_pos = 0;
}

static int
run_connection_output(struct unixctl_conn *conn)
{
    while (conn->out_pos < conn->out.length) {
        size_t bytes_written;
        int error;

        error = write_fully(conn->fd, conn->out.string + conn->out_pos,
                            conn->out.length - conn->out_pos, &bytes_written);
        conn->out_pos += bytes_written;
        if (error) {
            return error;
        }
    }
    conn->state = S_RECV;
    return 0;
}

static void
process_command(struct unixctl_conn *conn, char *s)
{
    struct unixctl_command *command;
    size_t name_len;
    char *name, *args;

    COVERAGE_INC(unixctl_received);
    conn->state = S_PROCESS;

    name = s;
    name_len = strcspn(name, " ");
    args = name + name_len;
    args += strspn(args, " ");
    name[name_len] = '\0';

    command = shash_find_data(&commands, name);
    if (command) {
        command->cb(conn, args, command->aux);
    } else {
        char *msg = xasprintf("\"%s\" is not a valid command", name);
        unixctl_command_reply(conn, 400, msg);
        free(msg);
    }
}

static int
run_connection_input(struct unixctl_conn *conn)
{
    for (;;) {
        size_t bytes_read;
        char *newline;
        int error;

        newline = memchr(conn->in.data, '\n', conn->in.size);
        if (newline) {
            char *command = conn->in.data;
            size_t n = newline - command + 1;

            if (n > 0 && newline[-1] == '\r') {
                newline--;
            }
            *newline = '\0';

            process_command(conn, command);

            ofpbuf_pull(&conn->in, n);
            if (!conn->in.size) {
                ofpbuf_clear(&conn->in);
            }
            return 0;
        }

        ofpbuf_prealloc_tailroom(&conn->in, 128);
        error = read_fully(conn->fd, ofpbuf_tail(&conn->in),
                           ofpbuf_tailroom(&conn->in), &bytes_read);
        conn->in.size += bytes_read;
        if (conn->in.size > 65536) {
            VLOG_WARN_RL(&rl, "excess command length, killing connection");
            return EPROTO;
        }
        if (error) {
            if (error == EAGAIN || error == EWOULDBLOCK) {
                if (!bytes_read) {
                    return EAGAIN;
                }
            } else {
                if (error != EOF || conn->in.size != 0) {
                    VLOG_WARN_RL(&rl, "read failed: %s",
                                 (error == EOF
                                  ? "connection dropped mid-command"
                                  : strerror(error)));
                }
                return error;
            }
        }
    }
}

static int
run_connection(struct unixctl_conn *conn)
{
    int old_state;
    do {
        int error;

        old_state = conn->state;
        switch (conn->state) {
        case S_RECV:
            error = run_connection_input(conn);
            break;

        case S_PROCESS:
            error = 0;
            break;

        case S_SEND:
            error = run_connection_output(conn);
            break;

        default:
            NOT_REACHED();
        }
        if (error) {
            return error;
        }
    } while (conn->state != old_state);
    return 0;
}

static void
kill_connection(struct unixctl_conn *conn)
{
    list_remove(&conn->node);
    ofpbuf_uninit(&conn->in);
    ds_destroy(&conn->out);
    close(conn->fd);
    free(conn);
}

void
unixctl_server_run(struct unixctl_server *server)
{
    struct unixctl_conn *conn, *next;
    int i;

    if (!server) {
        return;
    }

    for (i = 0; i < 10; i++) {
        int fd = accept(server->fd, NULL, NULL);
        if (fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                VLOG_WARN_RL(&rl, "accept failed: %s", strerror(errno));
            }
            break;
        }
        new_connection(server, fd);
    }

    LIST_FOR_EACH_SAFE (conn, next, node, &server->conns) {
        int error = run_connection(conn);
        if (error && error != EAGAIN) {
            kill_connection(conn);
        }
    }
}

void
unixctl_server_wait(struct unixctl_server *server)
{
    struct unixctl_conn *conn;

    if (!server) {
        return;
    }

    poll_fd_wait(server->fd, POLLIN);
    LIST_FOR_EACH (conn, node, &server->conns) {
        if (conn->state == S_RECV) {
            poll_fd_wait(conn->fd, POLLIN);
        } else if (conn->state == S_SEND) {
            poll_fd_wait(conn->fd, POLLOUT);
        }
    }
}

/* Destroys 'server' and stops listening for connections. */
void
unixctl_server_destroy(struct unixctl_server *server)
{
    if (server) {
        struct unixctl_conn *conn, *next;

        LIST_FOR_EACH_SAFE (conn, next, node, &server->conns) {
            kill_connection(conn);
        }

        close(server->fd);
        fatal_signal_unlink_file_now(server->path);
        free(server->path);
        free(server);
    }
}

/* Connects to a Vlog server socket.  'path' should be the name of a Vlog
 * server socket.  If it does not start with '/', it will be prefixed with
 * the rundir (e.g. /usr/local/var/run/openvswitch).
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*clientp' to the new unixctl_client, otherwise to NULL. */
int
unixctl_client_create(const char *path, struct unixctl_client **clientp)
{
    static int counter;
    struct unixctl_client *client;
    int error;
    int fd = -1;

    /* Determine location. */
    client = xmalloc(sizeof *client);
    client->connect_path = abs_file_name(ovs_rundir(), path);
    client->bind_path = xasprintf("/tmp/vlog.%ld.%d",
                                  (long int) getpid(), counter++);

    /* Open socket. */
    fd = make_unix_socket(SOCK_STREAM, false, false,
                          client->bind_path, client->connect_path);
    if (fd < 0) {
        error = -fd;
        goto error;
    }

    /* Bind socket to stream. */
    client->stream = fdopen(fd, "r+");
    if (!client->stream) {
        error = errno;
        VLOG_WARN("%s: fdopen failed (%s)",
                  client->connect_path, strerror(error));
        goto error;
    }
    *clientp = client;
    return 0;

error:
    if (fd >= 0) {
        close(fd);
    }
    free(client->connect_path);
    free(client->bind_path);
    free(client);
    *clientp = NULL;
    return error;
}

/* Destroys 'client'. */
void
unixctl_client_destroy(struct unixctl_client *client)
{
    if (client) {
        fatal_signal_unlink_file_now(client->bind_path);
        free(client->bind_path);
        free(client->connect_path);
        fclose(client->stream);
        free(client);
    }
}

/* Sends 'request' to the server socket and waits for a reply.  Returns 0 if
 * successful, otherwise to a positive errno value.  If successful, sets
 * '*reply' to the reply, which the caller must free, otherwise to NULL. */
int
unixctl_client_transact(struct unixctl_client *client,
                        const char *request,
                        int *reply_code, char **reply_body)
{
    struct ds line = DS_EMPTY_INITIALIZER;
    struct ds reply = DS_EMPTY_INITIALIZER;
    int error;

    /* Send 'request' to server.  Add a new-line if 'request' didn't end in
     * one. */
    fputs(request, client->stream);
    if (request[0] == '\0' || request[strlen(request) - 1] != '\n') {
        putc('\n', client->stream);
    }
    if (ferror(client->stream)) {
        VLOG_WARN("error sending request to %s: %s",
                  client->connect_path, strerror(errno));
        return errno;
    }

    /* Wait for response. */
    *reply_code = -1;
    for (;;) {
        const char *s;

        error = ds_get_line(&line, client->stream);
        if (error) {
            VLOG_WARN("error reading reply from %s: %s",
                      client->connect_path,
                      ovs_retval_to_string(error));
            goto error;
        }

        s = ds_cstr(&line);
        if (*reply_code == -1) {
            if (!isdigit((unsigned char)s[0])
                    || !isdigit((unsigned char)s[1])
                    || !isdigit((unsigned char)s[2])) {
                VLOG_WARN("reply from %s does not start with 3-digit code",
                          client->connect_path);
                error = EPROTO;
                goto error;
            }
            sscanf(s, "%3d", reply_code);
        } else {
            if (s[0] == '.') {
                if (s[1] == '\0') {
                    break;
                }
                s++;
            }
            ds_put_cstr(&reply, s);
            ds_put_char(&reply, '\n');
        }
    }
    *reply_body = ds_cstr(&reply);
    ds_destroy(&line);
    return 0;

error:
    ds_destroy(&line);
    ds_destroy(&reply);
    *reply_code = 0;
    *reply_body = NULL;
    return error == EOF ? EPROTO : error;
}

/* Returns the path of the server socket to which 'client' is connected.  The
 * caller must not modify or free the returned string. */
const char *
unixctl_client_target(const struct unixctl_client *client)
{
    return client->connect_path;
}
