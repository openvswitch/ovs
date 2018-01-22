# Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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

import os

import ovs.util
import ovs.vlog

# Values returned by Reconnect.run()
CONNECT = 'connect'
DISCONNECT = 'disconnect'
PROBE = 'probe'

EOF = ovs.util.EOF
vlog = ovs.vlog.Vlog("reconnect")


class Reconnect(object):
    """A finite-state machine for connecting and reconnecting to a network
    resource with exponential backoff.  It also provides optional support for
    detecting a connection on which the peer is no longer responding.

    The library does not implement anything networking related, only an FSM for
    networking code to use.

    Many Reconnect methods take a "now" argument.  This makes testing easier
    since there is no hidden state.  When not testing, just pass the return
    value of ovs.time.msec().  (Perhaps this design should be revisited
    later.)"""

    class Void(object):
        name = "VOID"
        is_connected = False

        @staticmethod
        def deadline(fsm):
            return None

        @staticmethod
        def run(fsm, now):
            return None

    class Listening(object):
        name = "LISTENING"
        is_connected = False

        @staticmethod
        def deadline(fsm):
            return None

        @staticmethod
        def run(fsm, now):
            return None

    class Backoff(object):
        name = "BACKOFF"
        is_connected = False

        @staticmethod
        def deadline(fsm):
            return fsm.state_entered + fsm.backoff

        @staticmethod
        def run(fsm, now):
            return CONNECT

    class ConnectInProgress(object):
        name = "CONNECTING"
        is_connected = False

        @staticmethod
        def deadline(fsm):
            return fsm.state_entered + max(1000, fsm.backoff)

        @staticmethod
        def run(fsm, now):
            return DISCONNECT

    class Active(object):
        name = "ACTIVE"
        is_connected = True

        @staticmethod
        def deadline(fsm):
            if fsm.probe_interval:
                base = max(fsm.last_activity, fsm.state_entered)
                return base + fsm.probe_interval
            return None

        @staticmethod
        def run(fsm, now):
            vlog.dbg("%s: idle %d ms, sending inactivity probe"
                     % (fsm.name,
                        now - max(fsm.last_activity, fsm.state_entered)))
            fsm._transition(now, Reconnect.Idle)
            return PROBE

    class Idle(object):
        name = "IDLE"
        is_connected = True

        @staticmethod
        def deadline(fsm):
            if fsm.probe_interval:
                return fsm.state_entered + fsm.probe_interval
            return None

        @staticmethod
        def run(fsm, now):
            vlog.err("%s: no response to inactivity probe after %.3g "
                     "seconds, disconnecting"
                      % (fsm.name, (now - fsm.state_entered) / 1000.0))
            return DISCONNECT

    class Reconnect(object):
        name = "RECONNECT"
        is_connected = False

        @staticmethod
        def deadline(fsm):
            return fsm.state_entered

        @staticmethod
        def run(fsm, now):
            return DISCONNECT

    def __init__(self, now):
        """Creates and returns a new reconnect FSM with default settings.  The
        FSM is initially disabled.  The caller will likely want to call
        self.enable() and self.set_name() on the returned object."""

        self.name = "void"
        self.min_backoff = 1000
        self.max_backoff = 8000
        self.probe_interval = 5000
        self.passive = False
        self.info_level = vlog.info

        self.state = Reconnect.Void
        self.state_entered = now
        self.backoff = 0
        self.last_activity = now
        self.last_connected = None
        self.last_disconnected = None
        self.max_tries = None
        self.backoff_free_tries = 0

        self.creation_time = now
        self.n_attempted_connections = 0
        self.n_successful_connections = 0
        self.total_connected_duration = 0
        self.seqno = 0

    def set_quiet(self, quiet):
        """If 'quiet' is true, this object will log informational messages at
        debug level, by default keeping them out of log files.  This is
        appropriate if the connection is one that is expected to be
        short-lived, so that the log messages are merely distracting.

        If 'quiet' is false, this object logs informational messages at info
        level.  This is the default.

        This setting has no effect on the log level of debugging, warning, or
        error messages."""
        if quiet:
            self.info_level = vlog.dbg
        else:
            self.info_level = vlog.info

    def get_name(self):
        return self.name

    def set_name(self, name):
        """Sets this object's name to 'name'.  If 'name' is None, then "void"
        is used instead.

        The name is used in log messages."""
        if name is None:
            self.name = "void"
        else:
            self.name = name

    def get_min_backoff(self):
        """Return the minimum number of milliseconds to back off between
        consecutive connection attempts.  The default is 1000 ms."""
        return self.min_backoff

    def get_max_backoff(self):
        """Return the maximum number of milliseconds to back off between
        consecutive connection attempts.  The default is 8000 ms."""
        return self.max_backoff

    def get_probe_interval(self):
        """Returns the "probe interval" in milliseconds.  If this is zero, it
        disables the connection keepalive feature.  If it is nonzero, then if
        the interval passes while the FSM is connected and without
        self.activity() being called, self.run() returns ovs.reconnect.PROBE.
        If the interval passes again without self.activity() being called,
        self.run() returns ovs.reconnect.DISCONNECT."""
        return self.probe_interval

    def set_max_tries(self, max_tries):
        """Limits the maximum number of times that this object will ask the
        client to try to reconnect to 'max_tries'.  None (the default) means an
        unlimited number of tries.

        After the number of tries has expired, the FSM will disable itself
        instead of backing off and retrying."""
        self.max_tries = max_tries

    def get_max_tries(self):
        """Returns the current remaining number of connection attempts,
        None if the number is unlimited."""
        return self.max_tries

    def set_backoff(self, min_backoff, max_backoff):
        """Configures the backoff parameters for this FSM.  'min_backoff' is
        the minimum number of milliseconds, and 'max_backoff' is the maximum,
        between connection attempts.

        'min_backoff' must be at least 1000, and 'max_backoff' must be greater
        than or equal to 'min_backoff'."""
        self.min_backoff = max(min_backoff, 1000)
        if self.max_backoff:
            self.max_backoff = max(max_backoff, 1000)
        else:
            self.max_backoff = 8000
        if self.min_backoff > self.max_backoff:
            self.max_backoff = self.min_backoff

        if (self.state == Reconnect.Backoff and
            self.backoff > self.max_backoff):
                self.backoff = self.max_backoff

    def set_backoff_free_tries(self, backoff_free_tries):
        """Sets the number of connection attempts that will be made without
        backoff to 'backoff_free_tries'.  Values 0 and 1 both
        represent a single attempt."""
        self.backoff_free_tries = backoff_free_tries

    def set_probe_interval(self, probe_interval):
        """Sets the "probe interval" to 'probe_interval', in milliseconds.  If
        this is zero, it disables the connection keepalive feature.  If it is
        nonzero, then if the interval passes while this FSM is connected and
        without self.activity() being called, self.run() returns
        ovs.reconnect.PROBE.  If the interval passes again without
        self.activity() being called, self.run() returns
        ovs.reconnect.DISCONNECT.

        If 'probe_interval' is nonzero, then it will be forced to a value of at
        least 1000 ms."""
        if probe_interval:
            self.probe_interval = max(1000, probe_interval)
        else:
            self.probe_interval = 0

    def is_passive(self):
        """Returns true if 'fsm' is in passive mode, false if 'fsm' is in
        active mode (the default)."""
        return self.passive

    def set_passive(self, passive, now):
        """Configures this FSM for active or passive mode.  In active mode (the
        default), the FSM is attempting to connect to a remote host.  In
        passive mode, the FSM is listening for connections from a remote
        host."""
        if self.passive != passive:
            self.passive = passive

            if ((passive and self.state in (Reconnect.ConnectInProgress,
                                            Reconnect.Reconnect)) or
                (not passive and self.state == Reconnect.Listening
                 and self.__may_retry())):
                self._transition(now, Reconnect.Backoff)
                self.backoff = 0

    def is_enabled(self):
        """Returns true if this FSM has been enabled with self.enable().
        Calling another function that indicates a change in connection state,
        such as self.disconnected() or self.force_reconnect(), will also enable
        a reconnect FSM."""
        return self.state != Reconnect.Void

    def enable(self, now):
        """If this FSM is disabled (the default for newly created FSMs),
        enables it, so that the next call to reconnect_run() for 'fsm' will
        return ovs.reconnect.CONNECT.

        If this FSM is not disabled, this function has no effect."""
        if self.state == Reconnect.Void and self.__may_retry():
            self._transition(now, Reconnect.Backoff)
            self.backoff = 0

    def disable(self, now):
        """Disables this FSM.  Until 'fsm' is enabled again, self.run() will
        always return 0."""
        if self.state != Reconnect.Void:
            self._transition(now, Reconnect.Void)

    def force_reconnect(self, now):
        """If this FSM is enabled and currently connected (or attempting to
        connect), forces self.run() to return ovs.reconnect.DISCONNECT the next
        time it is called, which should cause the client to drop the connection
        (or attempt), back off, and then reconnect."""
        if self.state in (Reconnect.ConnectInProgress,
                          Reconnect.Active,
                          Reconnect.Idle):
            self._transition(now, Reconnect.Reconnect)

    def disconnected(self, now, error):
        """Tell this FSM that the connection dropped or that a connection
        attempt failed.  'error' specifies the reason: a positive value
        represents an errno value, EOF indicates that the connection was closed
        by the peer (e.g. read() returned 0), and 0 indicates no specific
        error.

        The FSM will back off, then reconnect."""
        if self.state not in (Reconnect.Backoff, Reconnect.Void):
            # Report what happened
            if self.state in (Reconnect.Active, Reconnect.Idle):
                if error > 0:
                    vlog.warn("%s: connection dropped (%s)"
                              % (self.name, os.strerror(error)))
                elif error == EOF:
                    self.info_level("%s: connection closed by peer"
                                    % self.name)
                else:
                    self.info_level("%s: connection dropped" % self.name)
            elif self.state == Reconnect.Listening:
                if error > 0:
                    vlog.warn("%s: error listening for connections (%s)"
                              % (self.name, os.strerror(error)))
                else:
                    self.info_level("%s: error listening for connections"
                                    % self.name)
            elif self.backoff < self.max_backoff:
                if self.passive:
                    type_ = "listen"
                else:
                    type_ = "connection"
                if error > 0:
                    vlog.warn("%s: %s attempt failed (%s)"
                              % (self.name, type_, os.strerror(error)))
                else:
                    self.info_level("%s: %s attempt timed out"
                                    % (self.name, type_))

            if (self.state in (Reconnect.Active, Reconnect.Idle)):
                self.last_disconnected = now

            if not self.__may_retry():
                self._transition(now, Reconnect.Void)
                return

            # Back off
            if self.backoff_free_tries > 1:
                self.backoff_free_tries -= 1
                self.backoff = 0
            elif (self.state in (Reconnect.Active, Reconnect.Idle) and
                (self.last_activity - self.last_connected >= self.backoff or
                 self.passive)):
                if self.passive:
                    self.backoff = 0
                else:
                    self.backoff = self.min_backoff
            else:
                if self.backoff < self.min_backoff:
                    self.backoff = self.min_backoff
                elif self.backoff < self.max_backoff / 2:
                    self.backoff *= 2
                    if self.passive:
                        action = "trying to listen again"
                    else:
                        action = "reconnect"
                    self.info_level("%s: waiting %.3g seconds before %s"
                                    % (self.name, self.backoff / 1000.0,
                                       action))
                else:
                    if self.backoff < self.max_backoff:
                        if self.passive:
                            action = "try to listen"
                        else:
                            action = "reconnect"
                        self.info_level("%s: continuing to %s in the "
                                        "background but suppressing further "
                                        "logging" % (self.name, action))
                    self.backoff = self.max_backoff
            self._transition(now, Reconnect.Backoff)

    def connecting(self, now):
        """Tell this FSM that a connection or listening attempt is in progress.

        The FSM will start a timer, after which the connection or listening
        attempt will be aborted (by returning ovs.reconnect.DISCONNECT from
        self.run())."""
        if self.state != Reconnect.ConnectInProgress:
            if self.passive:
                self.info_level("%s: listening..." % self.name)
            elif self.backoff < self.max_backoff:
                self.info_level("%s: connecting..." % self.name)
            self._transition(now, Reconnect.ConnectInProgress)

    def listening(self, now):
        """Tell this FSM that the client is listening for connection attempts.
        This state last indefinitely until the client reports some change.

        The natural progression from this state is for the client to report
        that a connection has been accepted or is in progress of being
        accepted, by calling self.connecting() or self.connected().

        The client may also report that listening failed (e.g. accept()
        returned an unexpected error such as ENOMEM) by calling
        self.listen_error(), in which case the FSM will back off and eventually
        return ovs.reconnect.CONNECT from self.run() to tell the client to try
        listening again."""
        if self.state != Reconnect.Listening:
            self.info_level("%s: listening..." % self.name)
            self._transition(now, Reconnect.Listening)

    def listen_error(self, now, error):
        """Tell this FSM that the client's attempt to accept a connection
        failed (e.g. accept() returned an unexpected error such as ENOMEM).

        If the FSM is currently listening (self.listening() was called), it
        will back off and eventually return ovs.reconnect.CONNECT from
        self.run() to tell the client to try listening again.  If there is an
        active connection, this will be delayed until that connection drops."""
        if self.state == Reconnect.Listening:
            self.disconnected(now, error)

    def connected(self, now):
        """Tell this FSM that the connection was successful.

        The FSM will start the probe interval timer, which is reset by
        self.activity().  If the timer expires, a probe will be sent (by
        returning ovs.reconnect.PROBE from self.run().  If the timer expires
        again without being reset, the connection will be aborted (by returning
        ovs.reconnect.DISCONNECT from self.run()."""
        if not self.state.is_connected:
            self.connecting(now)

            self.info_level("%s: connected" % self.name)
            self._transition(now, Reconnect.Active)
            self.last_connected = now

    def connect_failed(self, now, error):
        """Tell this FSM that the connection attempt failed.

        The FSM will back off and attempt to reconnect."""
        self.connecting(now)
        self.disconnected(now, error)

    def activity(self, now):
        """Tell this FSM that some activity occurred on the connection.  This
        resets the probe interval timer, so that the connection is known not to
        be idle."""
        if self.state != Reconnect.Active:
            self._transition(now, Reconnect.Active)
        self.last_activity = now

    def _transition(self, now, state):
        if self.state == Reconnect.ConnectInProgress:
            self.n_attempted_connections += 1
            if state == Reconnect.Active:
                self.n_successful_connections += 1

        connected_before = self.state.is_connected
        connected_now = state.is_connected
        if connected_before != connected_now:
            if connected_before:
                self.total_connected_duration += now - self.last_connected
            self.seqno += 1

        vlog.dbg("%s: entering %s" % (self.name, state.name))
        self.state = state
        self.state_entered = now

    def run(self, now):
        """Assesses whether any action should be taken on this FSM.  The return
        value is one of:

            - None: The client need not take any action.

            - Active client, ovs.reconnect.CONNECT: The client should start a
              connection attempt and indicate this by calling
              self.connecting().  If the connection attempt has definitely
              succeeded, it should call self.connected().  If the connection
              attempt has definitely failed, it should call
              self.connect_failed().

              The FSM is smart enough to back off correctly after successful
              connections that quickly abort, so it is OK to call
              self.connected() after a low-level successful connection
              (e.g. connect()) even if the connection might soon abort due to a
              failure at a high-level (e.g. SSL negotiation failure).

            - Passive client, ovs.reconnect.CONNECT: The client should try to
              listen for a connection, if it is not already listening.  It
              should call self.listening() if successful, otherwise
              self.connecting() or reconnected_connect_failed() if the attempt
              is in progress or definitely failed, respectively.

              A listening passive client should constantly attempt to accept a
              new connection and report an accepted connection with
              self.connected().

            - ovs.reconnect.DISCONNECT: The client should abort the current
              connection or connection attempt or listen attempt and call
              self.disconnected() or self.connect_failed() to indicate it.

            - ovs.reconnect.PROBE: The client should send some kind of request
              to the peer that will elicit a response, to ensure that the
              connection is indeed in working order.  (This will only be
              returned if the "probe interval" is nonzero--see
              self.set_probe_interval())."""

        deadline = self.state.deadline(self)
        if deadline is not None and now >= deadline:
            return self.state.run(self, now)
        else:
            return None

    def wait(self, poller, now):
        """Causes the next call to poller.block() to wake up when self.run()
        should be called."""
        timeout = self.timeout(now)
        if timeout is not None and timeout >= 0:
            poller.timer_wait(timeout)

    def timeout(self, now):
        """Returns the number of milliseconds after which self.run() should be
        called if nothing else notable happens in the meantime, or None if this
        is currently unnecessary."""
        deadline = self.state.deadline(self)
        if deadline is not None:
            remaining = deadline - now
            return max(0, remaining)
        else:
            return None

    def is_connected(self):
        """Returns True if this FSM is currently believed to be connected, that
        is, if self.connected() was called more recently than any call to
        self.connect_failed() or self.disconnected() or self.disable(), and
        False otherwise."""
        return self.state.is_connected

    def get_last_connect_elapsed(self, now):
        """Returns the number of milliseconds since 'fsm' was last connected
        to its peer. Returns None if never connected."""
        if self.last_connected:
            return now - self.last_connected
        else:
            return None

    def get_last_disconnect_elapsed(self, now):
        """Returns the number of milliseconds since 'fsm' was last disconnected
        from its peer. Returns None if never disconnected."""
        if self.last_disconnected:
            return now - self.last_disconnected
        else:
            return None

    def get_stats(self, now):
        class Stats(object):
            pass
        stats = Stats()
        stats.creation_time = self.creation_time
        stats.last_connected = self.last_connected
        stats.last_disconnected = self.last_disconnected
        stats.last_activity = self.last_activity
        stats.backoff = self.backoff
        stats.seqno = self.seqno
        stats.is_connected = self.is_connected()
        stats.msec_since_connect = self.get_last_connect_elapsed(now)
        stats.msec_since_disconnect = self.get_last_disconnect_elapsed(now)
        stats.total_connected_duration = self.total_connected_duration
        if self.is_connected():
            stats.total_connected_duration += (
                    self.get_last_connect_elapsed(now))
        stats.n_attempted_connections = self.n_attempted_connections
        stats.n_successful_connections = self.n_successful_connections
        stats.state = self.state.name
        stats.state_elapsed = now - self.state_entered
        return stats

    def __may_retry(self):
        if self.max_tries is None:
            return True
        elif self.max_tries > 0:
            self.max_tries -= 1
            return True
        else:
            return False
