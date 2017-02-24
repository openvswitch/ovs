# Copyright (c) 2012 Nicira, Inc.
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

import copy
import errno
import os
import sys

import ovs.dirs
import ovs.jsonrpc
import ovs.stream
import ovs.unixctl
import ovs.util
import ovs.version
import ovs.vlog

import six
from six.moves import range

Message = ovs.jsonrpc.Message
vlog = ovs.vlog.Vlog("unixctl_server")
strtypes = six.string_types


class UnixctlConnection(object):
    def __init__(self, rpc):
        assert isinstance(rpc, ovs.jsonrpc.Connection)
        self._rpc = rpc
        self._request_id = None

    def run(self):
        self._rpc.run()
        error = self._rpc.get_status()
        if error or self._rpc.get_backlog():
            return error

        for _ in range(10):
            if error or self._request_id:
                break

            error, msg = self._rpc.recv()
            if msg:
                if msg.type == Message.T_REQUEST:
                    self._process_command(msg)
                else:
                    # XXX: rate-limit
                    vlog.warn("%s: received unexpected %s message"
                              % (self._rpc.name,
                                 Message.type_to_string(msg.type)))
                    error = errno.EINVAL

            if not error:
                error = self._rpc.get_status()

        return error

    def reply(self, body):
        self._reply_impl(True, body)

    def reply_error(self, body):
        self._reply_impl(False, body)

    # Called only by unixctl classes.
    def _close(self):
        self._rpc.close()
        self._request_id = None

    def _wait(self, poller):
        self._rpc.wait(poller)
        if not self._rpc.get_backlog():
            self._rpc.recv_wait(poller)

    def _reply_impl(self, success, body):
        assert isinstance(success, bool)
        assert body is None or isinstance(body, strtypes)

        assert self._request_id is not None

        if body is None:
            body = ""

        if body and not body.endswith("\n"):
            body += "\n"

        if success:
            reply = Message.create_reply(body, self._request_id)
        else:
            reply = Message.create_error(body, self._request_id)

        self._rpc.send(reply)
        self._request_id = None

    def _process_command(self, request):
        assert isinstance(request, ovs.jsonrpc.Message)
        assert request.type == ovs.jsonrpc.Message.T_REQUEST

        self._request_id = request.id

        error = None
        params = request.params
        method = request.method
        command = ovs.unixctl.commands.get(method)
        if command is None:
            error = '"%s" is not a valid command' % method
        elif len(params) < command.min_args:
            error = '"%s" command requires at least %d arguments' \
                    % (method, command.min_args)
        elif len(params) > command.max_args:
            error = '"%s" command takes at most %d arguments' \
                    % (method, command.max_args)
        else:
            for param in params:
                if not isinstance(param, strtypes):
                    error = '"%s" command has non-string argument' % method
                    break

            if error is None:
                unicode_params = [six.text_type(p) for p in params]
                command.callback(self, unicode_params, command.aux)

        if error:
            self.reply_error(error)


def _unixctl_version(conn, unused_argv, version):
    assert isinstance(conn, UnixctlConnection)
    version = "%s (Open vSwitch) %s" % (ovs.util.PROGRAM_NAME, version)
    conn.reply(version)


class UnixctlServer(object):
    def __init__(self, listener):
        assert isinstance(listener, ovs.stream.PassiveStream)
        self._listener = listener
        self._conns = []

    def run(self):
        for _ in range(10):
            error, stream = self._listener.accept()
            if sys.platform == "win32" and error == errno.WSAEWOULDBLOCK:
                # WSAEWOULDBLOCK would be the equivalent on Windows
                # for EAGAIN on Unix.
                error = errno.EAGAIN
            if not error:
                rpc = ovs.jsonrpc.Connection(stream)
                self._conns.append(UnixctlConnection(rpc))
            elif error == errno.EAGAIN:
                break
            else:
                # XXX: rate-limit
                vlog.warn("%s: accept failed: %s" % (self._listener.name,
                                                     os.strerror(error)))

        for conn in copy.copy(self._conns):
            error = conn.run()
            if error and error != errno.EAGAIN:
                conn._close()
                self._conns.remove(conn)

    def wait(self, poller):
        self._listener.wait(poller)
        for conn in self._conns:
            conn._wait(poller)

    def close(self):
        for conn in self._conns:
            conn._close()
        self._conns = None

        self._listener.close()
        self._listener = None

    @staticmethod
    def create(path, version=None):
        """Creates a new UnixctlServer which listens on a unixctl socket
        created at 'path'.  If 'path' is None, the default path is chosen.
        'version' contains the version of the server as reported by the unixctl
        version command.  If None, ovs.version.VERSION is used."""

        assert path is None or isinstance(path, strtypes)

        if path is not None:
            path = "punix:%s" % ovs.util.abs_file_name(ovs.dirs.RUNDIR, path)
        else:
            if sys.platform == "win32":
                path = "punix:%s/%s.ctl" % (ovs.dirs.RUNDIR,
                                            ovs.util.PROGRAM_NAME)
            else:
                path = "punix:%s/%s.%d.ctl" % (ovs.dirs.RUNDIR,
                                               ovs.util.PROGRAM_NAME,
                                               os.getpid())

        if version is None:
            version = ovs.version.VERSION

        error, listener = ovs.stream.PassiveStream.open(path)
        if error:
            ovs.util.ovs_error(error, "could not initialize control socket %s"
                               % path)
            return error, None

        ovs.unixctl.command_register("version", "", 0, 0, _unixctl_version,
                                     version)

        return 0, UnixctlServer(listener)


class UnixctlClient(object):
    def __init__(self, conn):
        assert isinstance(conn, ovs.jsonrpc.Connection)
        self._conn = conn

    def transact(self, command, argv):
        assert isinstance(command, strtypes)
        assert isinstance(argv, list)
        for arg in argv:
            assert isinstance(arg, strtypes)

        request = Message.create_request(command, argv)
        error, reply = self._conn.transact_block(request)

        if error:
            vlog.warn("error communicating with %s: %s"
                      % (self._conn.name, os.strerror(error)))
            return error, None, None

        if reply.error is not None:
            return 0, str(reply.error), None
        else:
            assert reply.result is not None
            return 0, None, str(reply.result)

    def close(self):
        self._conn.close()
        self.conn = None

    @staticmethod
    def create(path):
        assert isinstance(path, str)

        unix = "unix:%s" % ovs.util.abs_file_name(ovs.dirs.RUNDIR, path)
        error, stream = ovs.stream.Stream.open_block(
            ovs.stream.Stream.open(unix))

        if error:
            vlog.warn("failed to connect to %s" % path)
            return error, None

        return 0, UnixctlClient(ovs.jsonrpc.Connection(stream))
