# Copyright (c) 2010 Nicira Networks
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
import logging
import select
import ovs.timeval

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
        """Causes the following call to self.block() to wake up when the current
        time, as returned by ovs.timeval.msec(), reaches 'msec' or later.  If
        'msec' is earlier than the current time, the following call to
        self.block() will not block at all.

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
                    logging.error("poll: %s" % e[1])
        finally:
            self.__reset()

    def __log_wakeup(self, events):
        if not events:
            logging.debug("%d-ms timeout" % self.timeout)
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
                    logging.debug("%s on fd %d" % (s, fd))

    def __reset(self):
        self.poll = select.poll()
        self.timeout = -1            

