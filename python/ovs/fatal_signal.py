# Copyright (c) 2010, 2011 Nicira, Inc.
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

import atexit
import os
import signal
import sys

import ovs.vlog

_hooks = []
vlog = ovs.vlog.Vlog("fatal-signal")


def add_hook(hook, cancel, run_at_exit):
    _init()
    _hooks.append((hook, cancel, run_at_exit))


def fork():
    """Clears all of the fatal signal hooks without executing them.  If any of
    the hooks passed a 'cancel' function to add_hook(), then those functions
    will be called, allowing them to free resources, etc.

    Following a fork, one of the resulting processes can call this function to
    allow it to terminate without calling the hooks registered before calling
    this function.  New hooks registered after calling this function will take
    effect normally."""
    global _hooks
    for hook, cancel, run_at_exit in _hooks:
        if cancel:
            cancel()

    _hooks = []


_added_hook = False
_files = {}


def add_file_to_unlink(file):
    """Registers 'file' to be unlinked when the program terminates via
    sys.exit() or a fatal signal."""
    global _added_hook
    if not _added_hook:
        _added_hook = True
        add_hook(_unlink_files, _cancel_files, True)
    _files[file] = None


def add_file_to_close_and_unlink(file, fd=None):
    """Registers 'file' to be unlinked when the program terminates via
    sys.exit() or a fatal signal and the 'fd' to be closed. On Windows a file
    cannot be removed while it is open for writing."""
    global _added_hook
    if not _added_hook:
        _added_hook = True
        add_hook(_unlink_files, _cancel_files, True)
    _files[file] = fd


def remove_file_to_unlink(file):
    """Unregisters 'file' from being unlinked when the program terminates via
    sys.exit() or a fatal signal."""
    if file in _files:
        del _files[file]


def unlink_file_now(file):
    """Like fatal_signal_remove_file_to_unlink(), but also unlinks 'file'.
    Returns 0 if successful, otherwise a positive errno value."""
    error = _unlink(file)
    if error:
        vlog.warn("could not unlink \"%s\" (%s)" % (file, os.strerror(error)))
    remove_file_to_unlink(file)
    return error


def _unlink_files():
    for file_ in _files:
        if sys.platform == "win32" and _files[file_]:
            _files[file_].close()
        _unlink(file_)


def _cancel_files():
    global _added_hook
    global _files
    _added_hook = False
    _files = {}


def _unlink(file_):
    try:
        os.unlink(file_)
        return 0
    except OSError as e:
        return e.errno


def _signal_handler(signr, _):
    _call_hooks(signr)

    # Re-raise the signal with the default handling so that the program
    # termination status reflects that we were killed by this signal.
    signal.signal(signr, signal.SIG_DFL)
    os.kill(os.getpid(), signr)


def _atexit_handler():
    _call_hooks(0)


recurse = False


def _call_hooks(signr):
    global recurse
    if recurse:
        return
    recurse = True

    for hook, cancel, run_at_exit in _hooks:
        if signr != 0 or run_at_exit:
            hook()


_inited = False


def _init():
    global _inited
    if not _inited:
        _inited = True
        if sys.platform == "win32":
            signals = [signal.SIGTERM, signal.SIGINT]
        else:
            signals = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP,
                       signal.SIGALRM]

        for signr in signals:
            if signal.getsignal(signr) == signal.SIG_DFL:
                signal.signal(signr, _signal_handler)
        atexit.register(_atexit_handler)


def signal_alarm(timeout):
    if sys.platform == "win32":
        import os
        import time
        import threading

        class Alarm (threading.Thread):
            def __init__(self, timeout):
                super(Alarm, self).__init__()
                self.timeout = timeout
                self.setDaemon(True)

            def run(self):
                time.sleep(self.timeout)
                os._exit(1)

        alarm = Alarm(timeout)
        alarm.start()
    else:
        signal.alarm(timeout)
