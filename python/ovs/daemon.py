# Copyright (c) 2010, 2011 Nicira Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import fcntl
import logging
import os
import resource
import signal
import sys
import time

import ovs.dirs
import ovs.fatal_signal
#import ovs.lockfile
import ovs.process
import ovs.socket_util
import ovs.timeval
import ovs.util

# --detach: Should we run in the background?
_detach = False

# --pidfile: Name of pidfile (null if none).
_pidfile = None

# Our pidfile's inode and device, if we have created one.
_pidfile_dev = None
_pidfile_ino = None

# --overwrite-pidfile: Create pidfile even if one already exists and is locked?
_overwrite_pidfile = False

# --no-chdir: Should we chdir to "/"?
_chdir = True

# --monitor: Should a supervisory process monitor the daemon and restart it if
# it dies due to an error signal?
_monitor = False

# File descriptor used by daemonize_start() and daemonize_complete().
_daemonize_fd = None

RESTART_EXIT_CODE = 5

def make_pidfile_name(name):
    """Returns the file name that would be used for a pidfile if 'name' were
    provided to set_pidfile()."""
    if name is None or name == "":
        return "%s/%s.pid" % (ovs.dirs.RUNDIR, ovs.util.PROGRAM_NAME)
    else:
        return ovs.util.abs_file_name(ovs.dirs.RUNDIR, name)

def set_pidfile(name):
    """Sets up a following call to daemonize() to create a pidfile named
    'name'.  If 'name' begins with '/', then it is treated as an absolute path.
    Otherwise, it is taken relative to ovs.util.RUNDIR, which is
    $(prefix)/var/run by default.
    
    If 'name' is null, then ovs.util.PROGRAM_NAME followed by ".pid" is
    used."""
    global _pidfile
    _pidfile = make_pidfile_name(name)

def get_pidfile():
    """Returns an absolute path to the configured pidfile, or None if no
    pidfile is configured.  The caller must not modify or free the returned
    string."""
    return _pidfile

def set_no_chdir():
    """Sets that we do not chdir to "/"."""
    global _chdir
    _chdir = False

def is_chdir_enabled():
    """Will we chdir to "/" as part of daemonizing?"""
    return _chdir

def ignore_existing_pidfile():
    """Normally, daemonize() or daemonize_start() will terminate the program
    with a message if a locked pidfile already exists.  If this function is
    called, an existing pidfile will be replaced, with a warning."""
    global _overwrite_pidfile
    _overwrite_pidfile = True

def set_detach():
    """Sets up a following call to daemonize() to detach from the foreground
    session, running this process in the background."""
    global _detach
    _detach = True

def get_detach():
    """Will daemonize() really detach?"""
    return _detach

def set_monitor():
    """Sets up a following call to daemonize() to fork a supervisory process to
    monitor the daemon and restart it if it dies due to an error signal."""
    global _monitor
    _monitor = True

def _fatal(msg):
    logging.error(msg)
    sys.stderr.write("%s\n" % msg)
    sys.exit(1)

def _make_pidfile():
    """If a pidfile has been configured, creates it and stores the running
    process's pid in it.  Ensures that the pidfile will be deleted when the
    process exits."""
    pid = os.getpid()

    # Create a temporary pidfile.
    tmpfile = "%s.tmp%d" % (_pidfile, pid)
    ovs.fatal_signal.add_file_to_unlink(tmpfile)
    try:
        # This is global to keep Python from garbage-collecting and
        # therefore closing our file after this function exits.  That would
        # unlock the lock for us, and we don't want that.
        global file

        file = open(tmpfile, "w")
    except IOError, e:
        _fatal("%s: create failed (%s)" % (tmpfile, e.strerror))

    try:
        s = os.fstat(file.fileno())
    except IOError, e:
        _fatal("%s: fstat failed (%s)" % (tmpfile, e.strerror))

    try:
        file.write("%s\n" % pid)
        file.flush()
    except OSError, e:
        _fatal("%s: write failed: %s" % (tmpfile, e.strerror))

    try:
        fcntl.lockf(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        _fatal("%s: fcntl failed: %s" % (tmpfile, e.strerror))

    # Rename or link it to the correct name.
    if _overwrite_pidfile:
        try:
            os.rename(tmpfile, _pidfile)
        except OSError, e:
            _fatal("failed to rename \"%s\" to \"%s\" (%s)"
                   % (tmpfile, _pidfile, e.strerror))
    else:
        while True:
            try:
                os.link(tmpfile, _pidfile)
                error = 0
            except OSError, e:
                error = e.errno
            if error == errno.EEXIST:
                _check_already_running()
            elif error != errno.EINTR:
                break
        if error:
            _fatal("failed to link \"%s\" as \"%s\" (%s)"
                   % (tmpfile, _pidfile, os.strerror(error)))


    # Ensure that the pidfile will get deleted on exit.
    ovs.fatal_signal.add_file_to_unlink(_pidfile)

    # Delete the temporary pidfile if it still exists.
    if not _overwrite_pidfile:
        error = ovs.fatal_signal.unlink_file_now(tmpfile)
        if error:
            _fatal("%s: unlink failed (%s)" % (tmpfile, os.strerror(error)))

    _pidfile_dev = s.st_dev
    _pidfile_ino = s.st_ino

def daemonize():
    """If configured with set_pidfile() or set_detach(), creates the pid file
    and detaches from the foreground session."""
    daemonize_start()
    daemonize_complete()

def _waitpid(pid, options):
    while True:
        try:
            return os.waitpid(pid, options)
        except OSError, e:
            if e.errno == errno.EINTR:
                pass
            return -e.errno, 0

def _fork_and_wait_for_startup():
    try:
        rfd, wfd = os.pipe()
    except OSError, e:
        sys.stderr.write("pipe failed: %s\n" % os.strerror(e.errno))
        sys.exit(1)

    try:
        pid = os.fork()
    except OSError, e:
        sys.stderr.write("could not fork: %s\n" % os.strerror(e.errno))
        sys.exit(1)

    if pid > 0:
        # Running in parent process.
        os.close(wfd)
        ovs.fatal_signal.fork()
        while True:
            try:
                s = os.read(rfd, 1)
                error = 0
            except OSError, e:
                s = ""
                error = e.errno
            if error != errno.EINTR:
                break
        if len(s) != 1:
            retval, status = _waitpid(pid, 0)
            if (retval == pid and
                os.WIFEXITED(status) and os.WEXITSTATUS(status)):
                # Child exited with an error.  Convey the same error to
                # our parent process as a courtesy.
                sys.exit(os.WEXITSTATUS(status))
            else:
                sys.stderr.write("fork child failed to signal startup\n")
                sys.exit(1)

        os.close(rfd)
    else:
        # Running in parent process.
        os.close(rfd)
        ovs.timeval.postfork()
        #ovs.lockfile.postfork()

        global _daemonize_fd
        _daemonize_fd = wfd
    return pid

def _fork_notify_startup(fd):
    if fd is not None:
        error, bytes_written = ovs.socket_util.write_fully(fd, "0")
        if error:
            sys.stderr.write("could not write to pipe\n")
            sys.exit(1)
        os.close(fd)

def _should_restart(status):
    global RESTART_EXIT_CODE

    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == RESTART_EXIT_CODE:
        return True

    if os.WIFSIGNALED(status):
        for signame in ("SIGABRT", "SIGALRM", "SIGBUS", "SIGFPE", "SIGILL",
                        "SIGPIPE", "SIGSEGV", "SIGXCPU", "SIGXFSZ"):
            if (signame in signal.__dict__ and
                os.WTERMSIG(status) == signal.__dict__[signame]):
                return True
    return False

def _monitor_daemon(daemon_pid):
    # XXX should log daemon's stderr output at startup time
    # XXX should use setproctitle module if available
    last_restart = None
    while True:
        retval, status = _waitpid(daemon_pid, 0)
        if retval < 0:
            sys.stderr.write("waitpid failed\n")
            sys.exit(1)
        elif retval == daemon_pid:
            status_msg = ("pid %d died, %s"
                          % (daemon_pid, ovs.process.status_msg(status)))
            
            if _should_restart(status):
                if os.WCOREDUMP(status):
                    # Disable further core dumps to save disk space.
                    try:
                        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    except resource.error:
                        logging.warning("failed to disable core dumps")

                # Throttle restarts to no more than once every 10 seconds.
                if (last_restart is not None and
                    ovs.timeval.msec() < last_restart + 10000):
                    logging.warning("%s, waiting until 10 seconds since last "
                                    "restart" % status_msg)
                    while True:
                        now = ovs.timeval.msec()
                        wakeup = last_restart + 10000
                        if now > wakeup:
                            break
                        print "sleep %f" % ((wakeup - now) / 1000.0)
                        time.sleep((wakeup - now) / 1000.0)
                last_restart = ovs.timeval.msec()

                logging.error("%s, restarting" % status_msg)
                daemon_pid = _fork_and_wait_for_startup()
                if not daemon_pid:
                    break
            else:
                logging.info("%s, exiting" % status_msg)
                sys.exit(0)

   # Running in new daemon process.

def _close_standard_fds():
    """Close stdin, stdout, stderr.  If we're started from e.g. an SSH session,
    then this keeps us from holding that session open artificially."""
    null_fd = ovs.socket_util.get_null_fd()
    if null_fd >= 0:
        os.dup2(null_fd, 0)
        os.dup2(null_fd, 1)
        os.dup2(null_fd, 2)

def daemonize_start():
    """If daemonization is configured, then starts daemonization, by forking
    and returning in the child process.  The parent process hangs around until
    the child lets it know either that it completed startup successfully (by
    calling daemon_complete()) or that it failed to start up (by exiting with a
    nonzero exit code)."""
    
    if _detach:
        if _fork_and_wait_for_startup() > 0:
            # Running in parent process.
            sys.exit(0)
        # Running in daemon or monitor process.

    if _monitor:
        saved_daemonize_fd = _daemonize_fd
        daemon_pid = _fork_and_wait_for_startup()
        if daemon_pid > 0:
            # Running in monitor process.
            _fork_notify_startup(saved_daemonize_fd)
            _close_standard_fds()
            _monitor_daemon(daemon_pid)
        # Running in daemon process
    
    if _pidfile:
        _make_pidfile()

def daemonize_complete():
    """If daemonization is configured, then this function notifies the parent
    process that the child process has completed startup successfully."""
    _fork_notify_startup(_daemonize_fd)

    if _detach:
        os.setsid()
        if _chdir:
            os.chdir("/")
        _close_standard_fds()

def usage():
    sys.stdout.write("""
Daemon options:
   --detach                run in background as daemon
   --no-chdir              do not chdir to '/'
   --pidfile[=FILE]        create pidfile (default: %s/%s.pid)
   --overwrite-pidfile     with --pidfile, start even if already running
""" % (ovs.dirs.RUNDIR, ovs.util.PROGRAM_NAME))

def __read_pidfile(pidfile, delete_if_stale):
    if _pidfile_dev is not None:
        try:
            s = os.stat(pidfile)
            if s.st_ino == _pidfile_ino and s.st_dev == _pidfile_dev:
                # It's our own pidfile.  We can't afford to open it,
                # because closing *any* fd for a file that a process
                # has locked also releases all the locks on that file.
                #
                # Fortunately, we know the associated pid anyhow.
                return os.getpid()
        except OSError:
            pass

    try:
        file = open(pidfile, "r+")
    except IOError, e:
        if e.errno == errno.ENOENT and delete_if_stale:
            return 0
        logging.warning("%s: open: %s" % (pidfile, e.strerror))
        return -e.errno

    # Python fcntl doesn't directly support F_GETLK so we have to just try
    # to lock it.
    try:
        fcntl.lockf(file, fcntl.LOCK_EX | fcntl.LOCK_NB)

        # pidfile exists but wasn't locked by anyone.  Now we have the lock.
        if not delete_if_stale:
            file.close()
            logging.warning("%s: pid file is stale" % pidfile)
            return -errno.ESRCH

        # Is the file we have locked still named 'pidfile'?
        try:
            raced = False
            s = os.stat(pidfile)
            s2 = os.fstat(file.fileno())
            if s.st_ino != s2.st_ino or s.st_dev != s2.st_dev:
                raced = True
        except IOError:
            raced = True
        if raced:
            logging.warning("%s: lost race to delete pidfile" % pidfile)
            return -errno.ALREADY

        # We won the right to delete the stale pidfile.
        try:
            os.unlink(pidfile)
        except IOError, e:
            logging.warning("%s: failed to delete stale pidfile"
                            % (pidfile, e.strerror))
            return -e.errno

        logging.debug("%s: deleted stale pidfile" % pidfile)
        file.close()
        return 0
    except IOError, e:
        if e.errno not in [errno.EACCES, errno.EAGAIN]:
            logging.warn("%s: fcntl: %s" % (pidfile, e.strerror))
            return -e.errno

    # Someone else has the pidfile locked.
    try:
        try:
            return int(file.readline())
        except IOError, e:
            logging.warning("%s: read: %s" % (pidfile, e.strerror))
            return -e.errno
        except ValueError:
            logging.warning("%s does not contain a pid" % pidfile)
            return -errno.EINVAL
    finally:
        try:
            file.close()
        except IOError:
            pass

def read_pidfile(pidfile):
    """Opens and reads a PID from 'pidfile'.  Returns the positive PID if
    successful, otherwise a negative errno value."""
    return __read_pidfile(pidfile, False)

def _check_already_running():
    pid = __read_pidfile(_pidfile, True)
    if pid > 0:
        _fatal("%s: already running as pid %d, aborting" % (_pidfile, pid))
    elif pid < 0:
        _fatal("%s: pidfile check failed (%s), aborting"
               % (_pidfile, os.strerror(pid)))

# XXX Python's getopt does not support options with optional arguments, so we
# have to separate --pidfile (with no argument) from --pidfile-name (with an
# argument).  Need to write our own getopt I guess.
LONG_OPTIONS = ["detach", "no-chdir", "pidfile", "pidfile-name=",
                "overwrite-pidfile", "monitor"]

def parse_opt(option, arg):
    if option == '--detach':
        set_detach()
    elif option == '--no-chdir':
        set_no_chdir()
    elif option == '--pidfile':
        set_pidfile(None)
    elif option == '--pidfile-name':
        set_pidfile(arg)
    elif option == '--overwrite-pidfile':
        ignore_existing_pidfile()
    elif option == '--monitor':
        set_monitor()
    else:
        return False
    return True
