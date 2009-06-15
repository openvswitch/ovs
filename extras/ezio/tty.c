/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
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
#include "extras/ezio/tty.h"
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "socket-util.h"
#include "util.h"

#define THIS_MODULE VLM_tty
#include "vlog.h"

/* Get major() and minor() macros. */
#if MAJOR_IN_MKDEV
#  include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
#else
#  include <sys/types.h>
#  ifndef major
#    define major(dev) (((dev) >> 8) & 0xff)
#    define minor(dev) ((dev) & 0xff)
#  endif
#endif

static int
fcntl_lock(int fd)
{
    struct flock l;
    memset(&l, 0, sizeof l);
    l.l_type = F_WRLCK;
    l.l_whence = SEEK_SET;
    l.l_start = 0;
    l.l_len = 0;
    return fcntl(fd, F_SETLK, &l) == -1 ? errno : 0;
}

static int
remove_lockfile(const char *name)
{
    char buffer[BUFSIZ];
    ssize_t n;
    pid_t pid;
    int fd;

    /* Remove existing lockfile. */
    fd = open(name, O_RDWR);
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0;
        } else {
            VLOG_ERR("%s: open: %s", name, strerror(errno));
            return errno;
        }
    }

    /* Read lockfile. */
    n = read(fd, buffer, sizeof buffer - 1);
    if (n < 0) {
        int error = errno;
        VLOG_ERR("%s: read: %s", name, strerror(error));
        close(fd);
        return error;
    }
    buffer[n] = '\0';
    if (n == 4 && memchr(buffer, '\0', n)) {
        int32_t x;
        memcpy(&x, buffer, sizeof x);
        pid = x;
    } else if (n >= 0) {
        pid = strtol(buffer, NULL, 10);
    }
    if (pid <= 0) {
        close(fd);
        VLOG_WARN("%s: format not recognized, treating as locked.", name);
        return EACCES;
    }

    /* Is lockfile fresh? */
    if (strstr(buffer, "fcntl")) {
        int retval = fcntl_lock(fd);
        if (retval) {
            close(fd);
            VLOG_ERR("%s: device is locked (via fcntl): %s",
                     name, strerror(retval));
            return retval;
        } else {
            VLOG_WARN("%s: removing stale lockfile (checked via fcntl)", name);
        }
    } else {
        if (!(kill(pid, 0) < 0 && errno == ESRCH)) {
            close(fd);
            VLOG_ERR("%s: device is locked (without fcntl)", name);
            return EACCES;
        } else {
            VLOG_WARN("%s: removing stale lockfile (without fcntl)", name);
        }
    }
    close(fd);

    /* Remove stale lockfile. */
    if (unlink(name)) {
        VLOG_ERR("%s: unlink: %s", name, strerror(errno));
        return errno;
    }
    return 0;
}

static int
create_lockfile(const char *name)
{
    const char *username;
    char buffer[BUFSIZ];
    struct passwd *pwd;
    mode_t old_umask;
    uid_t uid;
    int fd;

    /* Create file. */
    old_umask = umask(022);
    fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) {
        int error = errno;
        VLOG_ERR("%s: create: %s", name, strerror(error));
        umask(old_umask);
        return error;
    }
    umask(old_umask);

    /* Lock file. */
    if (fcntl_lock(fd)) {
        int error = errno;
        close(fd);
        VLOG_ERR("%s: cannot lock: %s", name, strerror(error));
        return error;
    }

    /* Write to file. */
    uid = getuid();
    pwd = getpwuid(uid);
    username = pwd ? pwd->pw_name : "unknown";
    snprintf(buffer, sizeof buffer, "%10ld %s %.20s fcntl\n",
             (long int) getpid(), program_name, username);
    if (write(fd, buffer, strlen(buffer)) != strlen(buffer)) {
        int error = errno;
        VLOG_ERR("%s: write: %s", name, strerror(error));
        close(fd);
        unlink(name);
        return error;
    }

    /* We intentionally do not close 'fd', to avoid releasing the fcntl lock.
     * The asssumption here is that we never unlock a tty. */
    fatal_signal_add_file_to_unlink(name);

    return 0;
}

static int
do_lock(char *name)
{
    int retval = remove_lockfile(name);
    if (!retval) {
        retval = create_lockfile(name);
    }
    free(name);
    return retval;
}

int
tty_lock(const char *dev_name)
{
    struct stat s;
    char *name;
    int retval;

    /* Check that the lockfile directory exists. */
    if (stat(TTY_LOCK_DIR, &s)) {
        VLOG_ERR("%s: stat: %s", TTY_LOCK_DIR, strerror(errno));
        return errno;
    }

    /* First lock by device number. */
    if (stat(dev_name, &s)) {
        VLOG_ERR("%s: stat: %s", dev_name, strerror(errno));
        return errno;
    }
    retval = do_lock(xasprintf("%s/LK.%03d.%03d.%03d", TTY_LOCK_DIR,
                               major(s.st_dev),
                               major(s.st_rdev), minor(s.st_rdev)));
    if (retval) {
        return retval;
    }

    /* Then lock by device name. */
    if (!strncmp(dev_name, "/dev/", 5)) {
        char *cp;

        name = xasprintf("%s/%s", TTY_LOCK_DIR, dev_name + 5);
        for (cp = name + strlen(dev_name) + 1; *cp; cp++) {
            if (*cp == '/') {
                *cp = '_';
            }
        }
    } else {
        char *slash = strrchr(dev_name, '/');
        name = xasprintf ("%s/%s", TTY_LOCK_DIR, slash ? slash + 1 : dev_name);
    }
    return do_lock(name);
}

struct saved_termios {
    int fd;
    struct termios tios;
};

static void
restore_termios(void *s_)
{
    struct saved_termios *s = s_;
    tcsetattr(s->fd, TCSAFLUSH, &s->tios);
}

int
tty_set_raw_mode(int fd, speed_t speed)
{
    if (isatty(fd)) {
        struct termios tios;
        struct saved_termios *s;

        if (tcgetattr(fd, &tios) < 0) {
            return errno;
        }

        s = xmalloc(sizeof *s);
        s->fd = dup(fd);
        if (s->fd < 0) {
            int error = errno;
            VLOG_WARN("dup failed: %s", strerror(error));
            free(s);
            return errno;
        }
        s->tios = tios;
        fatal_signal_add_hook(restore_termios, s, true);

        tios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                          | INLCR | IGNCR | ICRNL | IXON);
        tios.c_oflag &= ~OPOST;
        tios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        tios.c_cflag &= ~(CSIZE | PARENB);
        tios.c_cflag |= CS8;
        if (speed != B0) {
            cfsetispeed(&tios, speed);
            cfsetospeed(&tios, speed);
        }
        if (tcsetattr(fd, TCSAFLUSH, &tios) < 0) {
            return errno;
        }
    }
    return set_nonblocking(fd);
}

int
tty_open_master_pty(void)
{
    int retval;
    int fd;

    fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0) {
        int error = errno;
        VLOG_WARN("posix_openpt failed: %s", strerror(error));
        close(fd);
        return -error;
    }

    if (grantpt(fd) < 0) {
        int error = errno;
        VLOG_WARN("grantpt failed: %s", strerror(error));
        close(fd);
        return -error;
    }

    if (unlockpt(fd) < 0) {
        int error = errno;
        VLOG_WARN("unlockpt failed: %s", strerror(error));
        close(fd);
        return -error;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        VLOG_WARN("set_nonblocking failed: %s", strerror(retval));
        close(fd);
        return retval;
    }

    return fd;
}

int
tty_fork_child(int master_fd, char *argv[])
{
    int retval = fork();
    if (!retval) {
        char *slave_name;
        int slave_fd;
        int fd;

        /* Running in child process. */
        fatal_signal_fork();

        /* Open pty slave as controlling terminal. */
        setsid();
        slave_name = ptsname(master_fd);
        if (slave_name == NULL) {
            ovs_fatal(errno, "ptsname");
        }
        slave_fd = open(slave_name, O_RDWR);
        if (isastream(slave_fd)
            && (ioctl(slave_fd, I_PUSH, "ptem") < 0
                || ioctl(slave_fd, I_PUSH, "ldterm") < 0)) {
            ovs_fatal(errno, "STREAMS ioctl");
        }

        /* Make pty slave stdin, stdout. */
        if (dup2(slave_fd, STDIN_FILENO) < 0
            || dup2(slave_fd, STDOUT_FILENO) < 0
            || dup2(slave_fd, STDERR_FILENO) < 0) {
            ovs_fatal(errno, "dup2");
        }

        /* Close other file descriptors. */
        for (fd = 3; fd < 20; fd++) {
            close(fd);
        }

        /* Set terminal type. */
        setenv("TERM", "ezio3", true);

        /* Invoke subprocess. */
        execvp(argv[0], argv);
        ovs_fatal(errno, "execvp");
    } else if (retval > 0) {
        /* Running in parent process. */
        return 0;
    } else {
        /* Fork failed. */
        VLOG_WARN("fork failed: %s", strerror(errno));
        return errno;
    }
}

int
tty_set_window_size(int fd UNUSED, int rows UNUSED, int columns UNUSED)
{
#ifdef TIOCGWINSZ
    struct winsize win;
    win.ws_row = rows;
    win.ws_col = columns;
    win.ws_xpixel = 0;
    win.ws_ypixel = 0;
    if (ioctl(fd, TIOCSWINSZ, &win) == -1) {
        return errno;
    }
#else
#error
#endif
    return 0;
}
