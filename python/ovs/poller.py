# Copyright (c) 2010, 2015 Nicira, Inc.
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
import os

import select
import socket
import sys

import ovs.timeval
import ovs.vlog

if sys.platform == "win32":
    import ovs.winutils as winutils

try:
    from OpenSSL import SSL
except ImportError:
    SSL = None

try:
    import eventlet.patcher

    def _using_eventlet_green_select():
        return eventlet.patcher.is_monkey_patched(select)
except:
    def _using_eventlet_green_select():
        return False

vlog = ovs.vlog.Vlog("poller")

POLLIN = 0x001
POLLOUT = 0x004
POLLERR = 0x008
POLLHUP = 0x010
POLLNVAL = 0x020


# eventlet/gevent doesn't support select.poll. If select.poll is used,
# python interpreter is blocked as a whole instead of switching from the
# current thread that is about to block to other runnable thread.
# So emulate select.poll by select.select because using python means that
# performance isn't so important.
class _SelectSelect(object):
    """ select.poll emulation by using select.select.
    Only register and poll are needed at the moment.
    """
    def __init__(self):
        self.rlist = []
        self.wlist = []
        self.xlist = []

    def register(self, fd, events):
        if isinstance(fd, socket.socket):
            fd = fd.fileno()
        if SSL and isinstance(fd, SSL.Connection):
            fd = fd.fileno()

        if sys.platform != 'win32':
            # Skip this on Windows, it also register events
            assert isinstance(fd, int)
        if events & POLLIN:
            self.rlist.append(fd)
            events &= ~POLLIN
        if events & POLLOUT:
            self.wlist.append(fd)
            events &= ~POLLOUT
        if events:
            self.xlist.append(fd)

    def poll(self, timeout):
        # XXX workaround a bug in eventlet
        # see https://github.com/eventlet/eventlet/pull/25
        if timeout == 0 and _using_eventlet_green_select():
            timeout = 0.1
        if sys.platform == 'win32':
            events = self.rlist + self.wlist + self.xlist
            if not events:
                return []
            if len(events) > winutils.win32event.MAXIMUM_WAIT_OBJECTS:
                raise WindowsError("Cannot handle more than maximum wait"
                                   "objects\n")

            # win32event.INFINITE timeout is -1
            # timeout must be an int number, expressed in ms
            if timeout == 0.1:
                timeout = 100
            else:
                timeout = int(timeout)

            # Wait until any of the events is set to signaled
            try:
                retval = winutils.win32event.WaitForMultipleObjects(
                    events,
                    False,  # Wait all
                    timeout)
            except winutils.pywintypes.error:
                    return [(0, POLLERR)]

            if retval == winutils.winerror.WAIT_TIMEOUT:
                return []

            if events[retval] in self.rlist:
                revent = POLLIN
            elif events[retval] in self.wlist:
                revent = POLLOUT
            else:
                revent = POLLERR

            return [(events[retval], revent)]
        else:
            if timeout == -1:
                # epoll uses -1 for infinite timeout, select uses None.
                timeout = None
            else:
                timeout = float(timeout) / 1000
            rlist, wlist, xlist = select.select(self.rlist,
                                                self.wlist,
                                                self.xlist,
                                                timeout)
            events_dict = {}
            for fd in rlist:
                events_dict[fd] = events_dict.get(fd, 0) | POLLIN
            for fd in wlist:
                events_dict[fd] = events_dict.get(fd, 0) | POLLOUT
            for fd in xlist:
                events_dict[fd] = events_dict.get(fd, 0) | (POLLERR |
                                                            POLLHUP |
                                                            POLLNVAL)
            return list(events_dict.items())


SelectPoll = _SelectSelect
# If eventlet/gevent isn't used, we can use select.poll by replacing
# _SelectPoll with select.poll class
# _SelectPoll = select.poll


class Poller(object):
    """High-level wrapper around the "poll" system call.

    Intended usage is for the program's main loop to go about its business
    servicing whatever events it needs to.  Then, when it runs out of immediate
    tasks, it calls each subordinate module or object's "wait" function, which
    in turn calls one (or more) of the functions Poller.fd_wait(),
    Poller.immediate_wake(), and Poller.timer_wait() to register to be awakened
    when the appropriate event occurs.  Then the main loop calls
    Poller.block(), which blocks until one of the registered events happens."""

    def __init__(self):
        self.__reset()

    def fd_wait(self, fd, events):
        """Registers 'fd' as waiting for the specified 'events' (which should
        be select.POLLIN or select.POLLOUT or their bitwise-OR).  The following
        call to self.block() will wake up when 'fd' becomes ready for one or
        more of the requested events.

        The event registration is one-shot: only the following call to
        self.block() is affected.  The event will need to be re-registered
        after self.block() is called if it is to persist.

        'fd' may be an integer file descriptor or an object with a fileno()
        method that returns an integer file descriptor."""
        self.poll.register(fd, events)

    def __timer_wait(self, msec):
        if self.timeout < 0 or msec < self.timeout:
            self.timeout = msec

    def timer_wait(self, msec):
        """Causes the following call to self.block() to block for no more than
        'msec' milliseconds.  If 'msec' is nonpositive, the following call to
        self.block() will not block at all.

        The timer registration is one-shot: only the following call to
        self.block() is affected.  The timer will need to be re-registered
        after self.block() is called if it is to persist."""
        if msec <= 0:
            self.immediate_wake()
        else:
            self.__timer_wait(msec)

    def timer_wait_until(self, msec):
        """Causes the following call to self.block() to wake up when the
        current time, as returned by ovs.timeval.msec(), reaches 'msec' or
        later.  If 'msec' is earlier than the current time, the following call
        to self.block() will not block at all.

        The timer registration is one-shot: only the following call to
        self.block() is affected.  The timer will need to be re-registered
        after self.block() is called if it is to persist."""
        now = ovs.timeval.msec()
        if msec <= now:
            self.immediate_wake()
        else:
            self.__timer_wait(msec - now)

    def immediate_wake(self):
        """Causes the following call to self.block() to wake up immediately,
        without blocking."""
        self.timeout = 0

    def block(self):
        """Blocks until one or more of the events registered with
        self.fd_wait() occurs, or until the minimum duration registered with
        self.timer_wait() elapses, or not at all if self.immediate_wake() has
        been called."""
        try:
            try:
                events = self.poll.poll(self.timeout)
                self.__log_wakeup(events)
            except OSError as e:
                """ On Windows, the select function from poll raises OSError
                exception if the polled array is empty."""
                if e.errno != errno.EINTR:
                    vlog.err("poll: %s" % os.strerror(e.errno))
            except select.error as e:
                # XXX rate-limit
                error, msg = e
                if error != errno.EINTR:
                    vlog.err("poll: %s" % e[1])
        finally:
            self.__reset()

    def __log_wakeup(self, events):
        if not events:
            vlog.dbg("%d-ms timeout" % self.timeout)
        else:
            for fd, revents in events:
                if revents != 0:
                    s = ""
                    if revents & POLLIN:
                        s += "[POLLIN]"
                    if revents & POLLOUT:
                        s += "[POLLOUT]"
                    if revents & POLLERR:
                        s += "[POLLERR]"
                    if revents & POLLHUP:
                        s += "[POLLHUP]"
                    if revents & POLLNVAL:
                        s += "[POLLNVAL]"
                    vlog.dbg("%s on fd %d" % (s, fd))

    def __reset(self):
        self.poll = SelectPoll()
        self.timeout = -1
