/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "vlog-socket.h"
#include <ctype.h>
#include <errno.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "daemon.h"
#include "fatal-signal.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"

#ifndef SCM_CREDENTIALS
#include <time.h>
#endif

#define THIS_MODULE VLM_vlog_socket
#include "vlog.h"

/* Server for Vlog control connection. */
struct vlog_server {
    struct poll_waiter *waiter;
    char *path;
    int fd;
};

static void poll_server(int fd, short int events, void *server_);

/* Start listening for connections from clients and processing their
 * requests.  'path' may be:
 *
 *      - NULL, in which case the default socket path is used.  (Only one
 *        Vlog_server_socket per process can use the default path.)
 *
 *      - A name that does not start with '/', in which case it is appended to
 *        the default socket path.
 *
 *      - An absolute path (starting with '/') that gives the exact name of
 *        the Unix domain socket to listen on.
 *
 * A program that (optionally) daemonizes itself should call this function
 * *after* daemonization, so that the socket name contains the pid of the
 * daemon instead of the pid of the program that exited.  (Otherwise, "vlogconf
 * --target <program>.pid" will fail.)
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*serverp' to the new vlog_server, otherwise to NULL. */
int
vlog_server_listen(const char *path, struct vlog_server **serverp)
{
    struct vlog_server *server = xmalloc(sizeof *server);

    if (path && path[0] == '/') {
        server->path = xstrdup(path);
    } else {
        server->path = xasprintf("/tmp/vlogs.%ld%s",
                                 (long int) getpid(), path ? path : "");
    }

    server->fd = make_unix_socket(SOCK_DGRAM, true, true, server->path, NULL);
    if (server->fd < 0) {
        int fd = server->fd;
        fprintf(stderr, "Could not initialize vlog configuration socket: %s\n",
                strerror(-server->fd));
        free(server->path);
        free(server);
        if (serverp) {
            *serverp = NULL; 
        }
        return fd;
    }

    server->waiter = poll_fd_callback(server->fd, POLLIN, poll_server, server);

    if (serverp) {
        *serverp = server; 
    }
    return 0;
}

/* Destroys 'server' and stops listening for connections. */
void
vlog_server_close(struct vlog_server *server)
{
    if (server) {
        poll_cancel(server->waiter);
        close(server->fd);
        unlink(server->path);
        fatal_signal_remove_file_to_unlink(server->path);
        free(server->path);
        free(server);
    }
}

static int
recv_with_creds(const struct vlog_server *server,
                char *cmd_buf, size_t cmd_buf_size,
                struct sockaddr_un *un, socklen_t *un_len)
{
#ifdef SCM_CREDENTIALS
    /* Read a message and control messages from 'fd'.  */
    char cred_buf[CMSG_SPACE(sizeof(struct ucred))];
    ssize_t n;
    struct iovec iov;
    struct msghdr msg;
    struct ucred* cred;
    struct cmsghdr* cmsg;

    iov.iov_base = cmd_buf;
    iov.iov_len = cmd_buf_size - 1;

    memset(&msg, 0, sizeof msg);
    msg.msg_name = un;
    msg.msg_namelen = sizeof *un;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cred_buf;
    msg.msg_controllen = sizeof cred_buf;

    n = recvmsg(server->fd, &msg, 0);
    *un_len = msg.msg_namelen;
    if (n < 0) {
        return errno;
    }
    cmd_buf[n] = '\0';

    /* Ensure that the message has credentials ensuring that it was sent
     * from the same user who started us, or by root. */
    cred = NULL;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET
            && cmsg->cmsg_type == SCM_CREDENTIALS) {
            cred = (struct ucred *) CMSG_DATA(cmsg);
        } else if (cmsg->cmsg_level == SOL_SOCKET
                   && cmsg->cmsg_type == SCM_RIGHTS) {
            /* Anyone can send us fds.  If we don't close them, then that's
             * a DoS: the sender can overflow our fd table. */
            int* fds = (int *) CMSG_DATA(cmsg);
            size_t n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof *fds;
            size_t i;
            for (i = 0; i < n_fds; i++) {
                close(fds[i]);
            }
        }
    }
    if (!cred) {
        fprintf(stderr, "vlog: config message lacks credentials\n");
        return -1;
    } else if (cred->uid && cred->uid != getuid()) {
        fprintf(stderr, "vlog: config message uid=%ld is not 0 or %ld\n",
                (long int) cred->uid, (long int) getuid());
        return -1;
    }

    return 0;
#else /* !SCM_CREDENTIALS */
    socklen_t len;
    ssize_t n;
    struct stat s;
    time_t recent;

    /* Receive a message. */
    len = sizeof *un;
    n = recvfrom(server->fd, cmd_buf, cmd_buf_size - 1, 0,
                 (struct sockaddr *) un, &len);
    *un_len = len;
    if (n < 0) {
        return errno;
    }
    cmd_buf[n] = '\0';

    len -= offsetof(struct sockaddr_un, sun_path);
    un->sun_path[len] = '\0';
    if (stat(un->sun_path, &s) < 0) {
        fprintf(stderr, "vlog: config message from inaccessible socket: %s\n",
                strerror(errno));
        return -1;
    }
    if (!S_ISSOCK(s.st_mode)) {
        fprintf(stderr, "vlog: config message not from a socket\n");
        return -1;
    }
    recent = time_now() - 30;
    if (s.st_atime < recent || s.st_ctime < recent || s.st_mtime < recent) {
        fprintf(stderr, "vlog: config socket too old\n");
        return -1;
    }
    if (s.st_uid && s.st_uid != getuid()) {
        fprintf(stderr, "vlog: config message uid=%ld is not 0 or %ld\n",
                (long int) s.st_uid, (long int) getuid());
        return -1;
    }
    return 0;
#endif /* !SCM_CREDENTIALS */
}

/* Processes incoming requests for 'server'. */
static void
poll_server(int fd UNUSED, short int events, void *server_)
{
    struct vlog_server *server = server_;
    for (;;) {
        char cmd_buf[512];
        struct sockaddr_un un;
        socklen_t un_len;
        char *reply;
        int error;

        error = recv_with_creds(server, cmd_buf, sizeof cmd_buf, &un, &un_len);
        if (error > 0) {
            if (error != EAGAIN && error != EWOULDBLOCK) {
                fprintf(stderr, "vlog: reading configuration socket: %s",
                        strerror(errno));
            }
            break;
        } else if (error < 0) {
            continue;
        }

        /* Process message and send reply. */
        if (!strncmp(cmd_buf, "set ", 4)) {
            char *msg = vlog_set_levels_from_string(cmd_buf + 4);
            reply = msg ? msg : xstrdup("ack");
        } else if (!strcmp(cmd_buf, "list")) {
            reply = vlog_get_levels();
        } else if (!strcmp(cmd_buf, "reopen")) {
            int error = vlog_reopen_log_file();
            reply = (error
                     ? xasprintf("could not reopen log file \"%s\": %s",
                                 vlog_get_log_file(), strerror(error))
                     : xstrdup("ack"));
        } else {
            reply = xstrdup("nak");
        }
        sendto(server->fd, reply, strlen(reply), 0,
               (struct sockaddr*) &un, un_len);
        free(reply);
    }
    server->waiter = poll_fd_callback(server->fd, POLLIN, poll_server, server);
}

/* Client for Vlog control connection. */

struct vlog_client {
    char *connect_path;
    char *bind_path;
    int fd;
};

/* Connects to a Vlog server socket.  'path' may be:
 *
 *      - A string that starts with a PID.  If a non-null, non-absolute name
 *        was passed to Vlog_server_socket::listen(), then it must follow the
 *        PID in 'path'.
 *
 *      - An absolute path (starting with '/') to a Vlog server socket or a
 *        pidfile.  If it is a pidfile, the pidfile will be read and translated
 *        into a Vlog server socket file name.
 *
 *      - A relative path, which is translated into a pidfile name and then
 *        treated as above.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*clientp' to the new vlog_client, otherwise to NULL. */
int
vlog_client_connect(const char *path, struct vlog_client **clientp)
{
    static int counter;
    struct vlog_client *client;
    struct stat s;
    int error;

    client = xmalloc(sizeof *client);
    if (path[0] == '/') {
        client->connect_path = xstrdup(path);
    } else if (isdigit((unsigned char) path[0])) {
        client->connect_path = xasprintf("/tmp/vlogs.%s", path);
    } else {
        client->connect_path = make_pidfile_name(path);
    }
    client->bind_path = NULL;

    if (stat(client->connect_path, &s)) {
        error = errno;
        VLOG_WARN("could not stat \"%s\": %s",
                  client->connect_path, strerror(error));
        goto error;
    } else if (S_ISREG(s.st_mode)) {
        pid_t pid = read_pidfile(client->connect_path);
        if (pid < 0) {
            error = -pid;
            VLOG_WARN("could not read pidfile \"%s\": %s",
                      client->connect_path, strerror(error));
            goto error;
        }
        free(client->connect_path);
        client->connect_path = xasprintf("/tmp/vlogs.%ld", (long int) pid);
    }
    client->bind_path = xasprintf("/tmp/vlog.%ld.%d",
                                  (long int) getpid(), counter++);
    client->fd = make_unix_socket(SOCK_DGRAM, false, false,
                                  client->bind_path, client->connect_path);
    if (client->fd < 0) {
        error = -client->fd;
        goto error;
    }
    *clientp = client;
    return 0;

error:
    free(client->connect_path);
    free(client->bind_path);
    free(client);
    *clientp = NULL;
    return error;
}

/* Destroys 'client'. */
void
vlog_client_close(struct vlog_client *client)
{
    if (client) {
        unlink(client->bind_path);
        fatal_signal_remove_file_to_unlink(client->bind_path);
        free(client->bind_path);
        free(client->connect_path);
        close(client->fd);
        free(client);
    }
}

/* Sends 'request' to the server socket that 'client' is connected to.  Returns
 * 0 if successful, otherwise a positive errno value. */
int
vlog_client_send(struct vlog_client *client, const char *request)
{
#ifdef SCM_CREDENTIALS
    struct ucred cred;
    struct iovec iov;
    char buf[CMSG_SPACE(sizeof cred)];
    struct msghdr msg;
    struct cmsghdr* cmsg;
    ssize_t nbytes;

    cred.pid = getpid();
    cred.uid = getuid();
    cred.gid = getgid();

    iov.iov_base = (void*) request;
    iov.iov_len = strlen(request);

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof buf;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof cred);
    memcpy(CMSG_DATA(cmsg), &cred, sizeof cred);
    msg.msg_controllen = cmsg->cmsg_len;

    nbytes = sendmsg(client->fd, &msg, 0);
#else /* !SCM_CREDENTIALS */
    ssize_t nbytes = send(client->fd, request, strlen(request), 0);
#endif /* !SCM_CREDENTIALS */
    if (nbytes > 0) {
        return nbytes == strlen(request) ? 0 : ENOBUFS;
    } else {
        return errno;
    }
}

/* Attempts to receive a response from the server socket that 'client' is
 * connected to.  Returns 0 if successful, otherwise a positive errno value.
 * If successful, sets '*reply' to the reply, which the caller must free,
 * otherwise to NULL. */
int
vlog_client_recv(struct vlog_client *client, char **reply)
{
    struct pollfd pfd;
    int nfds;
    char buffer[65536];
    ssize_t nbytes;

    *reply = NULL;

    pfd.fd = client->fd;
    pfd.events = POLLIN;
    nfds = time_poll(&pfd, 1, 1000);
    if (nfds == 0) {
        return ETIMEDOUT;
    } else if (nfds < 0) {
        return -nfds;
    }

    nbytes = read(client->fd, buffer, sizeof buffer - 1);
    if (nbytes < 0) {
        return errno;
    } else {
        buffer[nbytes] = '\0';
        *reply = xstrdup(buffer);
        return 0;
    }
}

/* Sends 'request' to the server socket and waits for a reply.  Returns 0 if
 * successful, otherwise to a positive errno value.  If successful, sets
 * '*reply' to the reply, which the caller must free, otherwise to NULL. */
int
vlog_client_transact(struct vlog_client *client,
                     const char *request, char **reply)
{
    int i;

    /* Retry up to 3 times. */
    for (i = 0; i < 3; ++i) {
        int error = vlog_client_send(client, request);
        if (error) {
            *reply = NULL;
            return error;
        }
        error = vlog_client_recv(client, reply);
        if (error != ETIMEDOUT) {
            return error;
        }
    }
    *reply = NULL;
    return ETIMEDOUT;
}

/* Returns the path of the server socket to which 'client' is connected.  The
 * caller must not modify or free the returned string. */
const char *
vlog_client_target(const struct vlog_client *client)
{
    return client->connect_path;
}
