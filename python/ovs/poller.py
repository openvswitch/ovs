# Copyright (c) 2010 Nicira, Inc.
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
import ovs.timeval
import ovs.vlog
import select
import socket

try:
    import eventlet.patcher

    def _using_eventlet_green_select():
        return eventlet.patcher.is_monkey_patched(select)
except:
    def _using_eventlet_green_select():
        return False

vlog = ovs.vlog.Vlog("poller")


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
        assert isinstance(fd, int)
        if events & select.POLLIN:
            self.rlist.append(fd)
            events &= ~select.POLLIN
        if events & select.POLLOUT:
            self.wlist.append(fd)
            events &= ~select.POLLOUT
        if events:
            self.xlist.append(fd)

    def poll(self, timeout):
        if timeout == -1:
            # epoll uses -1 for infinite timeout, select uses None.
            timeout = None
        else:
            timeout = float(timeout) / 1000
        # XXX workaround a bug in eventlet
        # see https://github.com/eventlet/eventlet/pull/25
        if timeout == 0 and _using_eventlet_green_select():
            timeout = 0.1

        rlist, wlist, xlist = select.select(self.rlist, self.wlist, self.xlist,
                                            timeout)
        # collections.defaultdict is introduced by python 2.5 and
        # XenServer uses python 2.4. We don't use it for XenServer.
        # events_dict = collections.defaultdict(int)
        # events_dict[fd] |= event
        events_dict = {}
        for fd in rlist:
            events_dict[fd] = events_dict.get(fd, 0) | select.POLLIN
        for fd in wlist:
            events_dict[fd] = events_dict.get(fd, 0) | select.POLLOUT
        for fd in xlist:
            events_dict[fd] = events_dict.get(fd, 0) | (select.POLLERR |
                                                        select.POLLHUP |
                                                        select.POLLNVAL)
        return events_dict.items()


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
            except select.error, e:
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
                    if revents & select.POLLIN:
                        s += "[POLLIN]"
                    if revents & select.POLLOUT:
                        s += "[POLLOUT]"
                    if revents & select.POLLERR:
                        s += "[POLLERR]"
                    if revents & select.POLLHUP:
                        s += "[POLLHUP]"
                    if revents & select.POLLNVAL:
                        s += "[POLLNVAL]"
                    vlog.dbg("%s on fd %d" % (s, fd))

    def __reset(self):
        self.poll = SelectPoll()
        self.timeout = -1
