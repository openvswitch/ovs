/*
 * Copyright (c) 2014, 2016 Nicira, Inc.
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
#include "socket-util.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "random.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(socket_util_unix);

/* #ifdefs make it a pain to maintain code: you have to try to build both ways.
 * Thus, this file compiles all of the code regardless of the target, by
 * writing "if (LINUX)" instead of "#ifdef __linux__". */
#ifdef __linux__
#define LINUX 1
#else
#define LINUX 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

/* Maximum length of the sun_path member in a struct sockaddr_un, excluding
 * space for a null terminator. */
#define MAX_UN_LEN (sizeof(((struct sockaddr_un *) 0)->sun_path) - 1)

void
xpipe(int fds[2])
{
    if (pipe(fds)) {
        VLOG_FATAL("failed to create pipe (%s)", ovs_strerror(errno));
    }
}

void
xpipe_nonblocking(int fds[2])
{
    xpipe(fds);
    xset_nonblocking(fds[0]);
    xset_nonblocking(fds[1]);
}

/* Drain all the data currently in the receive queue of a datagram socket (and
 * possibly additional data).  There is no way to know how many packets are in
 * the receive queue, but we do know that the total number of bytes queued does
 * not exceed the receive buffer size, so we pull packets until none are left
 * or we've read that many bytes. */
int
drain_rcvbuf(int fd)
{
    int rcvbuf;

    rcvbuf = get_socket_rcvbuf(fd);
    if (rcvbuf < 0) {
        return -rcvbuf;
    }

    while (rcvbuf > 0) {
        /* In Linux, specifying MSG_TRUNC in the flags argument causes the
         * datagram length to be returned, even if that is longer than the
         * buffer provided.  Thus, we can use a 1-byte buffer to discard the
         * incoming datagram and still be able to account how many bytes were
         * removed from the receive buffer.
         *
         * On other Unix-like OSes, MSG_TRUNC has no effect in the flags
         * argument. */
        char buffer[LINUX ? 1 : 2048];
        ssize_t n_bytes = recv(fd, buffer, sizeof buffer,
                               MSG_TRUNC | MSG_DONTWAIT);
        if (n_bytes <= 0 || n_bytes >= rcvbuf) {
            break;
        }
        rcvbuf -= n_bytes;
    }
    return 0;
}

/* Attempts to shorten 'name' by opening a file descriptor for the directory
 * part of the name and indirecting through /proc/self/fd/<dirfd>/<basename>.
 * On systems with Linux-like /proc, this works as long as <basename> isn't too
 * long.
 *
 * On success, returns 0 and stores the short name in 'short_name' and a
 * directory file descriptor to eventually be closed in '*dirfpd'. */
static int
shorten_name_via_proc(const char *name, char short_name[MAX_UN_LEN + 1],
                      int *dirfdp)
{
    char *dir, *base;
    int dirfd;
    int len;

    if (!LINUX) {
        return ENAMETOOLONG;
    }

    dir = dir_name(name);
    dirfd = open(dir, O_DIRECTORY | O_RDONLY);
    if (dirfd < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        int error = errno;

        VLOG_WARN_RL(&rl, "%s: open failed (%s)", dir, ovs_strerror(error));
        free(dir);

        return error;
    }
    free(dir);

    base = base_name(name);
    len = snprintf(short_name, MAX_UN_LEN + 1,
                   "/proc/self/fd/%d/%s", dirfd, base);
    free(base);

    if (len >= 0 && len <= MAX_UN_LEN) {
        *dirfdp = dirfd;
        return 0;
    } else {
        close(dirfd);
        return ENAMETOOLONG;
    }
}

/* Attempts to shorten 'name' by creating a symlink for the directory part of
 * the name and indirecting through <symlink>/<basename>.  This works on
 * systems that support symlinks, as long as <basename> isn't too long.
 *
 * On success, returns 0 and stores the short name in 'short_name' and the
 * symbolic link to eventually delete in 'linkname'. */
static int
shorten_name_via_symlink(const char *name, char short_name[MAX_UN_LEN + 1],
                         char linkname[MAX_UN_LEN + 1])
{
    char *abs, *dir, *base;
    const char *tmpdir;
    int error;
    int i;

    abs = abs_file_name(NULL, name);
    dir = dir_name(abs);
    base = base_name(abs);
    free(abs);

    tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL) {
        tmpdir = "/tmp";
    }

    for (i = 0; i < 1000; i++) {
        int len;

        len = snprintf(linkname, MAX_UN_LEN + 1,
                       "%s/ovs-un-c-%"PRIu32, tmpdir, random_uint32());
        error = (len < 0 || len > MAX_UN_LEN ? ENAMETOOLONG
                 : symlink(dir, linkname) ? errno
                 : 0);
        if (error != EEXIST) {
            break;
        }
    }

    if (!error) {
        int len;

        fatal_signal_add_file_to_unlink(linkname);

        len = snprintf(short_name, MAX_UN_LEN + 1, "%s/%s", linkname, base);
        if (len < 0 || len > MAX_UN_LEN) {
            fatal_signal_unlink_file_now(linkname);
            error = ENAMETOOLONG;
        }
    }

    if (error) {
        linkname[0] = '\0';
    }
    free(dir);
    free(base);

    return error;
}

/* Stores in '*un' a sockaddr_un that refers to file 'name'.  Stores in
 * '*un_len' the size of the sockaddr_un.
 *
 * Returns 0 on success, otherwise a positive errno value.
 *
 * Uses '*dirfdp' and 'linkname' to store references to data when the caller no
 * longer needs to use 'un'.  On success, freeing these references with
 * free_sockaddr_un() is mandatory to avoid a leak; on failure, freeing them is
 * unnecessary but harmless. */
static int
make_sockaddr_un(const char *name, struct sockaddr_un *un, socklen_t *un_len,
                 int *dirfdp, char linkname[MAX_UN_LEN + 1])
{
    char short_name[MAX_UN_LEN + 1];

    *dirfdp = -1;
    linkname[0] = '\0';
    if (strlen(name) > MAX_UN_LEN) {
        /* 'name' is too long to fit in a sockaddr_un.  Try a workaround. */
        int error = shorten_name_via_proc(name, short_name, dirfdp);
        if (error == ENAMETOOLONG) {
            error = shorten_name_via_symlink(name, short_name, linkname);
        }
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

            VLOG_WARN_RL(&rl, "Unix socket name %s is longer than maximum "
                         "%"PRIuSIZE" bytes", name, MAX_UN_LEN);
            return error;
        }

        name = short_name;
    }

    un->sun_family = AF_UNIX;
    ovs_strzcpy(un->sun_path, name, sizeof un->sun_path);
    *un_len = (offsetof(struct sockaddr_un, sun_path)
                + strlen (un->sun_path) + 1);
    return 0;
}

/* Clean up after make_sockaddr_un(). */
static void
free_sockaddr_un(int dirfd, const char *linkname)
{
    if (dirfd >= 0) {
        close(dirfd);
    }
    if (linkname[0]) {
        fatal_signal_unlink_file_now(linkname);
    }
}

/* Binds Unix domain socket 'fd' to a file with permissions 0700. */
static int bind_unix_socket(int fd, struct sockaddr *sun, socklen_t sun_len)
{
    const mode_t mode = 0770;    /* Allow both user and group access. */

    if (LINUX) {
        /* On Linux, the fd's permissions become the file's permissions.
         * fchmod() does not affect other files, like umask() does. */
        if (fchmod(fd, mode)) {
            return errno;
        }

        /* Must be after fchmod(). */
        if (bind(fd, sun, sun_len)) {
            return errno;
        }
        return 0;
    } else {
        /* On FreeBSD and NetBSD, only the umask affects permissions.  The
         * umask is process-wide rather than thread-specific, so we have to use
         * a subprocess for safety. */
        pid_t pid = fork();

        if (!pid) {
            umask(mode ^ 0777);
            _exit(bind(fd, sun, sun_len) ? errno : 0);
        } else if (pid > 0) {
            int status;
            int error;

            do {
                error = waitpid(pid, &status, 0) < 0 ? errno : 0;
            } while (error == EINTR);

            return (error ? error
                    : WIFEXITED(status) ? WEXITSTATUS(status)
                    : WIFSIGNALED(status) ? EINTR
                    : ECHILD /* WTF? */);
        } else {
            return errno;
        }
    }
}

/* Creates a Unix domain socket in the given 'style' (either SOCK_DGRAM or
 * SOCK_STREAM) that is bound to '*bind_path' (if 'bind_path' is non-null) and
 * connected to '*connect_path' (if 'connect_path' is non-null).  If 'nonblock'
 * is true, the socket is made non-blocking.
 *
 * Returns the socket's fd if successful, otherwise a negative errno value. */
int
make_unix_socket(int style, bool nonblock,
                 const char *bind_path, const char *connect_path)
{
    int error;
    int fd;

    fd = socket(PF_UNIX, style, 0);
    if (fd < 0) {
        return -errno;
    }

    /* Set nonblocking mode right away, if we want it.  This prevents blocking
     * in connect(), if connect_path != NULL.  (In turn, that's a corner case:
     * it will only happen if style is SOCK_STREAM or SOCK_SEQPACKET, and only
     * if a backlog of un-accepted connections has built up in the kernel.)  */
    if (nonblock) {
        error = set_nonblocking(fd);
        if (error) {
            goto error;
        }
    }

    if (bind_path) {
        char linkname[MAX_UN_LEN + 1];
        struct sockaddr_un un;
        socklen_t un_len;
        int dirfd;

        if (unlink(bind_path) && errno != ENOENT) {
            VLOG_WARN("unlinking \"%s\": %s\n",
                      bind_path, ovs_strerror(errno));
        }
        fatal_signal_add_file_to_unlink(bind_path);

        error = make_sockaddr_un(bind_path, &un, &un_len, &dirfd, linkname);
        if (!error) {
            error = bind_unix_socket(fd, (struct sockaddr *) &un, un_len);
        }
        free_sockaddr_un(dirfd, linkname);

        if (error) {
            goto error;
        }
    }

    if (connect_path) {
        char linkname[MAX_UN_LEN + 1];
        struct sockaddr_un un;
        socklen_t un_len;
        int dirfd;

        error = make_sockaddr_un(connect_path, &un, &un_len, &dirfd, linkname);
        if (!error
            && connect(fd, (struct sockaddr*) &un, un_len)
            && errno != EINPROGRESS) {
            error = errno;
        }
        free_sockaddr_un(dirfd, linkname);

        if (error) {
            goto error;
        }
    }

    return fd;

error:
    if (error == EAGAIN) {
        error = EPROTO;
    }
    if (bind_path) {
        fatal_signal_unlink_file_now(bind_path);
    }
    close(fd);
    return -error;
}

int
get_unix_name_len(const struct sockaddr_un *sun, socklen_t sun_len)
{
    return (sun_len > offsetof(struct sockaddr_un, sun_path) &&
            sun->sun_path[0] != 0
            ? sun_len - offsetof(struct sockaddr_un, sun_path)
            : 0);
}

/* Calls ioctl() on an AF_INET sock, passing the specified 'command' and
 * 'arg'.  Returns 0 if successful, otherwise a positive errno value. */
int
af_inet_ioctl(unsigned long int command, const void *arg)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int sock;

    if (ovsthread_once_start(&once)) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            int error = sock_errno();
            VLOG_ERR("failed to create inet socket: %s", sock_strerror(error));
            sock = -error;
        }
        ovsthread_once_done(&once);
    }

    return (sock < 0 ? -sock
            : ioctl(sock, command, arg) == -1 ? errno
            : 0);
}

int
af_inet_ifreq_ioctl(const char *name, struct ifreq *ifr, unsigned long int cmd,
                    const char *cmd_name)
{
    int error;

    ovs_strzcpy(ifr->ifr_name, name, sizeof ifr->ifr_name);
    error = af_inet_ioctl(cmd, ifr);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_DBG_RL(&rl, "%s: ioctl(%s) failed: %s", name, cmd_name,
                    ovs_strerror(error));
    }
    return error;
}
