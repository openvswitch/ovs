/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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
#include "daemon.h"
#include "daemon-private.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#if HAVE_LIBCAPNG
#include <cap-ng.h>
#endif
#include "command-line.h"
#include "fatal-signal.h"
#include "dirs.h"
#include "lockfile.h"
#include "ovs-thread.h"
#include "process.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(daemon_unix);

#ifdef __linux__
#define LINUX 1
#else
#define LINUX 0
#endif

#if HAVE_LIBCAPNG
#define LIBCAPNG 1
#else
#define LIBCAPNG 0
#endif

/* --detach: Should we run in the background? */
bool detach;                    /* Was --detach specified? */
static bool detached;           /* Have we already detached? */

/* --pidfile: Name of pidfile (null if none). */
char *pidfile;

/* Device and inode of pidfile, so we can avoid reopening it. */
static dev_t pidfile_dev;
static ino_t pidfile_ino;

/* --overwrite-pidfile: Create pidfile even if one already exists and is
   locked? */
static bool overwrite_pidfile;

/* --no-chdir: Should we chdir to "/"? */
static bool chdir_ = true;

/* File descriptor used by daemonize_start() and daemonize_complete(). */
static int daemonize_fd = -1;

/* --monitor: Should a supervisory process monitor the daemon and restart it if
 * it dies due to an error signal? */
static bool monitor;

/* --user: Only root can use this option. Switch to new uid:gid after
 * initially running as root.  */
static bool switch_user = false;
static uid_t uid;
static gid_t gid;
static char *user = NULL;
static void daemon_become_new_user__(bool access_datapath);

static void check_already_running(void);
static int lock_pidfile(FILE *, int command);
static pid_t fork_and_clean_up(void);
static void daemonize_post_detach(void);

/* Returns the file name that would be used for a pidfile if 'name' were
 * provided to set_pidfile().  The caller must free the returned string. */
char *
make_pidfile_name(const char *name)
{
    return (!name
            ? xasprintf("%s/%s.pid", ovs_rundir(), program_name)
            : abs_file_name(ovs_rundir(), name));
}

/* Sets that we do not chdir to "/". */
void
set_no_chdir(void)
{
    chdir_ = false;
}

/* Normally, daemonize() or damonize_start() will terminate the program with a
 * message if a locked pidfile already exists.  If this function is called, an
 * existing pidfile will be replaced, with a warning. */
void
ignore_existing_pidfile(void)
{
    overwrite_pidfile = true;
}

/* Sets up a following call to daemonize() to detach from the foreground
 * session, running this process in the background.  */
void
set_detach(void)
{
    detach = true;
}

/* Sets up a following call to daemonize() to fork a supervisory process to
 * monitor the daemon and restart it if it dies due to an error signal.  */
void
daemon_set_monitor(void)
{
    monitor = true;
}

/* If a pidfile has been configured, creates it and stores the running
 * process's pid in it.  Ensures that the pidfile will be deleted when the
 * process exits. */
static void
make_pidfile(void)
{
    long int pid = getpid();
    struct stat s;
    char *tmpfile;
    FILE *file;
    int error;

    /* Create a temporary pidfile. */
    if (overwrite_pidfile) {
        tmpfile = xasprintf("%s.tmp%ld", pidfile, pid);
        fatal_signal_add_file_to_unlink(tmpfile);
    } else {
        /* Everyone shares the same file which will be treated as a lock.  To
         * avoid some uncomfortable race conditions, we can't set up the fatal
         * signal unlink until we've acquired it. */
        tmpfile = xasprintf("%s.tmp", pidfile);
    }

    file = fopen(tmpfile, "a+");
    if (!file) {
        VLOG_FATAL("%s: create failed (%s)", tmpfile, ovs_strerror(errno));
    }

    error = lock_pidfile(file, F_SETLK);
    if (error) {
        /* Looks like we failed to acquire the lock.  Note that, if we failed
         * for some other reason (and '!overwrite_pidfile'), we will have
         * left 'tmpfile' as garbage in the file system. */
        VLOG_FATAL("%s: fcntl(F_SETLK) failed (%s)", tmpfile,
                   ovs_strerror(error));
    }

    if (!overwrite_pidfile) {
        /* We acquired the lock.  Make sure to clean up on exit, and verify
         * that we're allowed to create the actual pidfile. */
        fatal_signal_add_file_to_unlink(tmpfile);
        check_already_running();
    }

    if (fstat(fileno(file), &s) == -1) {
        VLOG_FATAL("%s: fstat failed (%s)", tmpfile, ovs_strerror(errno));
    }

    if (ftruncate(fileno(file), 0) == -1) {
        VLOG_FATAL("%s: truncate failed (%s)", tmpfile, ovs_strerror(errno));
    }

    fprintf(file, "%ld\n", pid);
    if (fflush(file) == EOF) {
        VLOG_FATAL("%s: write failed (%s)", tmpfile, ovs_strerror(errno));
    }

    error = rename(tmpfile, pidfile);

    /* Due to a race, 'tmpfile' may be owned by a different process, so we
     * shouldn't delete it on exit. */
    fatal_signal_remove_file_to_unlink(tmpfile);

    if (error < 0) {
        VLOG_FATAL("failed to rename \"%s\" to \"%s\" (%s)",
                   tmpfile, pidfile, ovs_strerror(errno));
    }

    /* Ensure that the pidfile will get deleted on exit. */
    fatal_signal_add_file_to_unlink(pidfile);

    /* Clean up.
     *
     * We don't close 'file' because its file descriptor must remain open to
     * hold the lock. */
    pidfile_dev = s.st_dev;
    pidfile_ino = s.st_ino;
    free(tmpfile);
}

/* Calls fork() and on success returns its return value.  On failure, logs an
 * error and exits unsuccessfully.
 *
 * Post-fork, but before returning, this function calls a few other functions
 * that are generally useful if the child isn't planning to exec a new
 * process. */
static pid_t
fork_and_clean_up(void)
{
    pid_t pid = xfork();
    if (pid > 0) {
        /* Running in parent process. */
        fatal_signal_fork();
    } else if (!pid) {
        /* Running in child process. */
        lockfile_postfork();
    }
    return pid;
}

/* Forks, then:
 *
 *   - In the parent, waits for the child to signal that it has completed its
 *     startup sequence.  Then stores -1 in '*fdp' and returns the child's
 *     pid in '*child_pid' argument.
 *
 *   - In the child, stores a fd in '*fdp' and returns 0 through '*child_pid'
 *     argument.  The caller should pass the fd to fork_notify_startup() after
 *     it finishes its startup sequence.
 *
 * Returns 0 on success.  If something goes wrong and child process was not
 * able to signal its readiness by calling fork_notify_startup(), then this
 * function returns -1. However, even in case of failure it still sets child
 * process id in '*child_pid'. */
static int
fork_and_wait_for_startup(int *fdp, pid_t *child_pid)
{
    int fds[2];
    pid_t pid;
    int ret = 0;

    xpipe(fds);

    pid = fork_and_clean_up();
    if (pid > 0) {
        /* Running in parent process. */
        size_t bytes_read;
        char c;

        close(fds[1]);
        if (read_fully(fds[0], &c, 1, &bytes_read) != 0) {
            int retval;
            int status;

            do {
                retval = waitpid(pid, &status, 0);
            } while (retval == -1 && errno == EINTR);

            if (retval == pid) {
                if (WIFEXITED(status) && WEXITSTATUS(status)) {
                    /* Child exited with an error.  Convey the same error
                     * to our parent process as a courtesy. */
                    exit(WEXITSTATUS(status));
                } else {
                    char *status_msg = process_status_msg(status);
                    VLOG_ERR("fork child died before signaling startup (%s)",
                             status_msg);
                    ret = -1;
                }
            } else if (retval < 0) {
                VLOG_FATAL("waitpid failed (%s)", ovs_strerror(errno));
            } else {
                OVS_NOT_REACHED();
            }
        }
        close(fds[0]);
        *fdp = -1;
    } else if (!pid) {
        /* Running in child process. */
        close(fds[0]);
        *fdp = fds[1];
    }
    *child_pid = pid;
    return ret;
}

static void
fork_notify_startup(int fd)
{
    if (fd != -1) {
        size_t bytes_written;
        int error;

        error = write_fully(fd, "", 1, &bytes_written);
        if (error) {
            VLOG_FATAL("pipe write failed (%s)", ovs_strerror(error));
        }

        close(fd);
    }
}

static bool
should_restart(int status)
{
    if (WIFSIGNALED(status)) {
        static const int error_signals[] = {
            /* This list of signals is documented in daemon.man.  If you
             * change the list, update the documentation too. */
            SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV,
            SIGXCPU, SIGXFSZ
        };

        size_t i;

        for (i = 0; i < ARRAY_SIZE(error_signals); i++) {
            if (error_signals[i] == WTERMSIG(status)) {
                return true;
            }
        }
    }
    return false;
}

static void
monitor_daemon(pid_t daemon_pid)
{
    /* XXX Should log daemon's stderr output at startup time. */
    time_t last_restart;
    char *status_msg;
    int crashes;
    bool child_ready = true;

    set_subprogram_name("monitor");
    status_msg = xstrdup("healthy");
    last_restart = TIME_MIN;
    crashes = 0;
    for (;;) {
        int retval;
        int status;

        ovs_cmdl_proctitle_set("monitoring pid %lu (%s)",
                               (unsigned long int) daemon_pid, status_msg);

        if (child_ready) {
            int error;
            do {
                retval = waitpid(daemon_pid, &status, 0);
                error = retval == -1 ? errno : 0;
            } while (error == EINTR);
            vlog_reopen_log_file();
            if (error) {
                VLOG_FATAL("waitpid failed (%s)", ovs_strerror(error));
            }
        }

        if (!child_ready || retval == daemon_pid) {
            char *s = process_status_msg(status);
            if (should_restart(status)) {
                free(status_msg);
                status_msg = xasprintf("%d crashes: pid %lu died, %s",
                                       ++crashes,
                                       (unsigned long int) daemon_pid, s);
                free(s);

                if (WCOREDUMP(status)) {
                    /* Disable further core dumps to save disk space. */
                    struct rlimit r;

                    r.rlim_cur = 0;
                    r.rlim_max = 0;
                    if (setrlimit(RLIMIT_CORE, &r) == -1) {
                        VLOG_WARN("failed to disable core dumps: %s",
                                  ovs_strerror(errno));
                    }
                }

                /* Throttle restarts to no more than once every 10 seconds. */
                if (time(NULL) < last_restart + 10) {
                    VLOG_WARN("%s, waiting until 10 seconds since last "
                              "restart", status_msg);
                    for (;;) {
                        time_t now = time(NULL);
                        time_t wakeup = last_restart + 10;
                        if (now >= wakeup) {
                            break;
                        }
                        xsleep(wakeup - now);
                    }
                }
                last_restart = time(NULL);

                VLOG_ERR("%s, restarting", status_msg);
                child_ready = !fork_and_wait_for_startup(&daemonize_fd,
                                                         &daemon_pid);
                if (child_ready && !daemon_pid) {
                    /* Child process needs to break out of monitoring
                     * loop. */
                    break;
                }
            } else {
                VLOG_INFO("pid %lu died, %s, exiting",
                          (unsigned long int) daemon_pid, s);
                free(s);
                exit(0);
            }
        }
    }
    free(status_msg);

    /* Running in new daemon process. */
    ovs_cmdl_proctitle_restore();
    set_subprogram_name("");
}

/* If daemonization is configured, then starts daemonization, by forking and
 * returning in the child process.  The parent process hangs around until the
 * child lets it know either that it completed startup successfully (by calling
 * daemon_complete()) or that it failed to start up (by exiting with a nonzero
 * exit code). */
void
daemonize_start(bool access_datapath)
{
    assert_single_threaded();
    daemonize_fd = -1;

    if (switch_user) {
        daemon_become_new_user__(access_datapath);
        switch_user = false;
    }

    if (detach) {
        pid_t pid;

        if (fork_and_wait_for_startup(&daemonize_fd, &pid)) {
            VLOG_FATAL("could not detach from foreground session");
        }
        if (pid > 0) {
            /* Running in parent process. */
            exit(0);
        }

        /* Running in daemon or monitor process. */
        setsid();
    }

    if (monitor) {
        int saved_daemonize_fd = daemonize_fd;
        pid_t daemon_pid;

        if (fork_and_wait_for_startup(&daemonize_fd, &daemon_pid)) {
            VLOG_FATAL("could not initiate process monitoring");
        }
        if (daemon_pid > 0) {
            /* Running in monitor process. */
            fork_notify_startup(saved_daemonize_fd);
            if (detach) {
                close_standard_fds();
            }
            monitor_daemon(daemon_pid);
        }
        /* Running in daemon process. */
    }

    forbid_forking("running in daemon process");

    if (pidfile) {
        make_pidfile();
    }

    /* Make sure that the unixctl commands for vlog get registered in a
     * daemon, even before the first log message. */
    vlog_init();
}

/* If daemonization is configured, then this function notifies the parent
 * process that the child process has completed startup successfully.  It also
 * call daemonize_post_detach().
 *
 * Calling this function more than once has no additional effect. */
void
daemonize_complete(void)
{
    if (pidfile) {
        free(pidfile);
        pidfile = NULL;
    }

    if (!detached) {
        detached = true;

        fork_notify_startup(daemonize_fd);
        daemonize_fd = -1;
        daemonize_post_detach();
    }
}

/* If daemonization is configured, then this function does traditional Unix
 * daemonization behavior: join a new session, chdir to the root (if not
 * disabled), and close the standard file descriptors.
 *
 * It only makes sense to call this function as part of an implementation of a
 * special daemon subprocess.  A normal daemon should just call
 * daemonize_complete(). */
static void
daemonize_post_detach(void)
{
    if (detach) {
        if (chdir_) {
            ignore(chdir("/"));
        }
        close_standard_fds();
    }
}

void
daemon_usage(void)
{
    printf(
        "\nDaemon options:\n"
        "  --detach                run in background as daemon\n"
        "  --monitor               creates a process to monitor this daemon\n"
        "  --user=username[:group] changes the effective daemon user:group\n"
        "  --no-chdir              do not chdir to '/'\n"
        "  --pidfile[=FILE]        create pidfile (default: %s/%s.pid)\n"
        "  --overwrite-pidfile     with --pidfile, start even if already "
                                   "running\n",
        ovs_rundir(), program_name);
}

static int
lock_pidfile__(FILE *file, int command, struct flock *lck)
{
    int error;

    lck->l_type = F_WRLCK;
    lck->l_whence = SEEK_SET;
    lck->l_start = 0;
    lck->l_len = 0;
    lck->l_pid = 0;

    do {
        error = fcntl(fileno(file), command, lck) == -1 ? errno : 0;
    } while (error == EINTR);
    return error;
}

static int
lock_pidfile(FILE *file, int command)
{
    struct flock lck;

    return lock_pidfile__(file, command, &lck);
}

static pid_t
read_pidfile__(const char *pidfile_, bool delete_if_stale)
{
    struct stat s, s2;
    struct flock lck;
    char line[128];
    FILE *file;
    int error;

    if ((pidfile_ino || pidfile_dev)
        && !stat(pidfile_, &s)
        && s.st_ino == pidfile_ino && s.st_dev == pidfile_dev) {
        /* It's our own pidfile.  We can't afford to open it, because closing
         * *any* fd for a file that a process has locked also releases all the
         * locks on that file.
         *
         * Fortunately, we know the associated pid anyhow: */
        return getpid();
    }

    file = fopen(pidfile_, "r+");
    if (!file) {
        if (errno == ENOENT && delete_if_stale) {
            return 0;
        }
        error = errno;
        VLOG_WARN("%s: open: %s", pidfile_, ovs_strerror(error));
        goto error;
    }

    error = lock_pidfile__(file, F_GETLK, &lck);
    if (error) {
        VLOG_WARN("%s: fcntl: %s", pidfile_, ovs_strerror(error));
        goto error;
    }
    if (lck.l_type == F_UNLCK) {
        /* pidfile exists but it isn't locked by anyone.  We need to delete it
         * so that a new pidfile can go in its place.  But just calling
         * unlink(pidfile) makes a nasty race: what if someone else unlinks it
         * before we do and then replaces it by a valid pidfile?  We'd unlink
         * their valid pidfile.  We do a little dance to avoid the race, by
         * locking the invalid pidfile.  Only one process can have the invalid
         * pidfile locked, and only that process has the right to unlink it. */
        if (!delete_if_stale) {
            error = ESRCH;
            VLOG_DBG("%s: pid file is stale", pidfile_);
            goto error;
        }

        /* Get the lock. */
        error = lock_pidfile(file, F_SETLK);
        if (error) {
            /* We lost a race with someone else doing the same thing. */
            VLOG_WARN("%s: lost race to lock pidfile", pidfile_);
            goto error;
        }

        /* Is the file we have locked still named 'pidfile_'? */
        if (stat(pidfile_, &s) || fstat(fileno(file), &s2)
            || s.st_ino != s2.st_ino || s.st_dev != s2.st_dev) {
            /* No.  We lost a race with someone else who got the lock before
             * us, deleted the pidfile, and closed it (releasing the lock). */
            error = EALREADY;
            VLOG_WARN("%s: lost race to delete pidfile", pidfile_);
            goto error;
        }

        /* We won the right to delete the stale pidfile. */
        if (unlink(pidfile_)) {
            error = errno;
            VLOG_WARN("%s: failed to delete stale pidfile (%s)",
                      pidfile_, ovs_strerror(error));
            goto error;
        }
        VLOG_DBG("%s: deleted stale pidfile", pidfile_);
        fclose(file);
        return 0;
    }

    if (!fgets(line, sizeof line, file)) {
        if (ferror(file)) {
            error = errno;
            VLOG_WARN("%s: read: %s", pidfile_, ovs_strerror(error));
        } else {
            error = ESRCH;
            VLOG_WARN("%s: read: unexpected end of file", pidfile_);
        }
        goto error;
    }

    if (lck.l_pid != strtoul(line, NULL, 10)) {
        /* The process that has the pidfile locked is not the process that
         * created it.  It must be stale, with the process that has it locked
         * preparing to delete it. */
        error = ESRCH;
        VLOG_WARN("%s: stale pidfile for pid %s being deleted by pid %ld",
                  pidfile_, line, (long int) lck.l_pid);
        goto error;
    }

    fclose(file);
    return lck.l_pid;

error:
    if (file) {
        fclose(file);
    }
    return -error;
}

/* Opens and reads a PID from 'pidfile_'.  Returns the positive PID if
 * successful, otherwise a negative errno value. */
pid_t
read_pidfile(const char *pidfile_)
{
    return read_pidfile__(pidfile_, false);
}

/* Checks whether a process with the given 'pidfile' is already running and,
 * if so, aborts.  If 'pidfile' is stale, deletes it. */
static void
check_already_running(void)
{
    long int pid = read_pidfile__(pidfile, true);
    if (pid > 0) {
        VLOG_FATAL("%s: already running as pid %ld, aborting", pidfile, pid);
    } else if (pid < 0) {
        VLOG_FATAL("%s: pidfile check failed (%s), aborting",
                   pidfile, ovs_strerror(-pid));
    }
}


/* stub functions for non-windows platform. */

void
service_start(int *argc OVS_UNUSED, char **argv[] OVS_UNUSED)
{
}

void
service_stop(void)
{
}

bool
should_service_stop(void)
{
    return false;
}


static bool
gid_matches(gid_t expected, gid_t value)
{
    return expected == -1 || expected == value;
}

static bool
gid_verify(gid_t gid_)
{
    gid_t r, e;

    r = getgid();
    e = getegid();
    return (gid_matches(gid_, r) &&
            gid_matches(gid_, e));
}

static void
daemon_switch_group(gid_t gid_)
{
    if ((setgid(gid_) == -1) || !gid_verify(gid_)) {
        VLOG_FATAL("%s: fail to switch group to gid as %d, aborting",
                   pidfile, gid_);
    }
}

static bool
uid_matches(uid_t expected, uid_t value)
{
    return expected == -1 || expected == value;
}

static bool
uid_verify(const uid_t uid_)
{
    uid_t r, e;

    r = getuid();
    e = geteuid();
    return (uid_matches(uid_, r) &&
            uid_matches(uid_, e));
}

static void
daemon_switch_user(const uid_t uid_, const char *user_)
{
    if ((setuid(uid_) == -1) || !uid_verify(uid_)) {
        VLOG_FATAL("%s: fail to switch user to %s, aborting",
                   pidfile, user_);
    }
}

/* Use portable Unix APIs to switch uid:gid, when datapath
 * access is not required.  On Linux systems, all capabilities
 * will be dropped.  */
static void
daemon_become_new_user_unix(void)
{
    /* "Setuid Demystified" by Hao Chen, etc outlines some caveats of
     * around unix system call setuid() and friends. This implementation
     * mostly follow the advice given by the paper.  The paper is
     * published in 2002, so things could have changed.  */

    /* Change both real and effective uid and gid will permanently
     * drop the process' privilege.  "Setuid Demystified" suggested
     * that calling getuid() after each setuid() call to verify they
     * are actually set, because checking return code alone is not
     * sufficient.  */
    daemon_switch_group(gid);
    if (user && initgroups(user, gid) == -1) {
        VLOG_FATAL("%s: fail to add supplementary group gid %d, "
                   "aborting", pidfile, gid);
    }
    daemon_switch_user(uid, user);
}

/* Linux specific implementation of daemon_become_new_user()
 * using libcap-ng.   */
static void
daemon_become_new_user_linux(bool access_datapath OVS_UNUSED)
{
#if defined __linux__ &&  HAVE_LIBCAPNG
    int ret;

    ret = capng_get_caps_process();

    if (!ret) {
        if (capng_have_capabilities(CAPNG_SELECT_CAPS) > CAPNG_NONE) {
            const capng_type_t cap_sets = CAPNG_EFFECTIVE|CAPNG_PERMITTED;

            capng_clear(CAPNG_SELECT_BOTH);

            ret = capng_update(CAPNG_ADD, cap_sets, CAP_IPC_LOCK)
                  || capng_update(CAPNG_ADD, cap_sets, CAP_NET_BIND_SERVICE);

            if (access_datapath && !ret) {
                ret = capng_update(CAPNG_ADD, cap_sets, CAP_NET_ADMIN)
                      || capng_update(CAPNG_ADD, cap_sets, CAP_NET_RAW);
            }
        } else {
            ret = -1;
        }
    }

    if (!ret) {
        /* CAPNG_INIT_SUPP_GRP will be a better choice than
         * CAPNG_DROP_SUPP_GRP. However this enum value is only defined
         * with libcap-ng higher than version 0.7.4, which is not wildly
         * available on many Linux distributions yet. Taking a more
         * conservative approach to make sure OVS behaves consistently.
         *
         * XXX We may change this for future OVS releases.
         */
        ret = capng_change_id(uid, gid, CAPNG_DROP_SUPP_GRP
                              | CAPNG_CLEAR_BOUNDING);
    }

    if (ret) {
        VLOG_FATAL("%s: libcap-ng fail to switch to user and group "
                   "%d:%d, aborting", pidfile, uid, gid);
    }
#endif
}

static void
daemon_become_new_user__(bool access_datapath)
{
    /* If vlog file has been created, change its owner to the non-root user
     * as specifed by the --user option.  */
    vlog_change_owner_unix(uid, gid);

    if (LINUX) {
        if (LIBCAPNG) {
            daemon_become_new_user_linux(access_datapath);
        } else {
            VLOG_FATAL("%s: fail to downgrade user using libcap-ng. "
                       "(libcap-ng is not configured at compile time), "
                       "aborting.", pidfile);
        }
    } else {
        daemon_become_new_user_unix();
    }
}

/* Noramlly, user switch is embedded within daemonize_start().
 * However, there in case the user switch needs to be done
 * before daemonize_start(), the following API can be used.  */
void
daemon_become_new_user(bool access_datapath)
{
    assert_single_threaded();
    if (switch_user) {
        daemon_become_new_user__(access_datapath);
        /* daemonize_start() should not switch user again. */
        switch_user = false;
    }
}

/* Return the maximun suggested buffer size for both getpwname_r()
 * and getgrnam_r().
 *
 * This size may still not be big enough. in case getpwname_r()
 * and friends return ERANGE, a larger buffer should be supplied to
 * retry. (The man page did not specify the max size to stop at, we
 * will keep trying with doubling the buffer size for each round until
 * the size wrapps around size_t.  */
static size_t
get_sysconf_buffer_size(void)
{
    size_t bufsize, pwd_bs = 0, grp_bs = 0;
    const size_t default_bufsize = 1024;

    errno = 0;
    if ((pwd_bs = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
        if (errno) {
            VLOG_FATAL("%s: Read initial passwordd struct size "
                       "failed (%s), aborting. ", pidfile,
                       ovs_strerror(errno));
        }
    }

    if ((grp_bs = sysconf(_SC_GETGR_R_SIZE_MAX)) == -1) {
        if (errno) {
            VLOG_FATAL("%s: Read initial group struct size "
                       "failed (%s), aborting. ", pidfile,
                       ovs_strerror(errno));
        }
    }

    bufsize = MAX(pwd_bs, grp_bs);
    return bufsize ? bufsize : default_bufsize;
}

/* Try to double the size of '*buf', return true
 * if successful, and '*sizep' will be updated with
 * the new size. Otherwise, return false.  */
static bool
enlarge_buffer(char **buf, size_t *sizep)
{
    size_t newsize = *sizep * 2;

    if (newsize > *sizep) {
        *buf = xrealloc(*buf, newsize);
        *sizep = newsize;
        return true;
    }

    return false;
}

/* Parse and sanity check user_spec.
 *
 * If successful, set global variables 'uid' and 'gid'
 * with the parsed results. Global variable 'user'
 * will be pointing to a string that stores the name
 * of the user to be switched into.
 *
 * Also set 'switch_to_new_user' to true, The actual
 * user switching is done as soon as daemonize_start()
 * is called. I/O access before calling daemonize_start()
 * will still be with root's credential.  */
void
daemon_set_new_user(const char *user_spec)
{
    char *pos = strchr(user_spec, ':');
    size_t init_bufsize, bufsize;

    init_bufsize = get_sysconf_buffer_size();
    uid = getuid();
    gid = getgid();

    if (geteuid() || uid) {
        VLOG_FATAL("%s: only root can use --user option", pidfile);
    }

    user_spec += strspn(user_spec, " \t\r\n");
    size_t len = pos ? pos - user_spec : strlen(user_spec);
    char *buf;
    struct passwd pwd, *res;
    int e;

    bufsize = init_bufsize;
    buf = xmalloc(bufsize);
    if (len) {
        user = xmemdup0(user_spec, len);

        while ((e = getpwnam_r(user, &pwd, buf, bufsize, &res)) == ERANGE) {
            if (!enlarge_buffer(&buf, &bufsize)) {
                break;
            }
        }

        if (e != 0) {
            VLOG_FATAL("%s: Failed to retrive user %s's uid (%s), aborting.",
                       pidfile, user, ovs_strerror(e));
        }
        if (res == NULL) {
            VLOG_FATAL("%s: user %s not found, aborting.", pidfile, user);
        }
    } else {
        /* User name is not specified, use current user.  */
        while ((e = getpwuid_r(uid, &pwd, buf, bufsize, &res)) == ERANGE) {
            if (!enlarge_buffer(&buf, &bufsize)) {
                break;
            }
        }

        if (e != 0) {
            VLOG_FATAL("%s: Failed to retrive current user's name "
                       "(%s), aborting.", pidfile, ovs_strerror(e));
        }
        user = xstrdup(pwd.pw_name);
    }

    uid = pwd.pw_uid;
    gid = pwd.pw_gid;
    free(buf);

    if (pos) {
        char *grpstr = pos + 1;
        grpstr += strspn(grpstr, " \t\r\n");

        if (*grpstr) {
            struct group grp, *gres;

            bufsize = init_bufsize;
            buf = xmalloc(bufsize);
            while ((e = getgrnam_r(grpstr, &grp, buf, bufsize, &gres))
                         == ERANGE) {
                if (!enlarge_buffer(&buf, &bufsize)) {
                    break;
                }
            }

            if (e) {
                VLOG_FATAL("%s: Failed to get group entry for %s, "
                           "(%s), aborting.", pidfile, grpstr,
                           ovs_strerror(e));
            }
            if (gres == NULL) {
                VLOG_FATAL("%s: group %s not found, aborting.", pidfile,
                           grpstr);
            }

            if (gid != grp.gr_gid) {
                char **mem;

                for (mem = grp.gr_mem; *mem; ++mem) {
                    if (!strcmp(*mem, user)) {
                        break;
                    }
                }

                if (!*mem) {
                    VLOG_FATAL("%s: Invalid --user option %s (user %s is "
                               "not in group %s), aborting.", pidfile,
                               user_spec, user, grpstr);
                }
                gid = grp.gr_gid;
            }
            free(buf);
        }
    }

    switch_user = true;
}
