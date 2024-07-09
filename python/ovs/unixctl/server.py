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

import argparse
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


Message = ovs.jsonrpc.Message
vlog = ovs.vlog.Vlog("unixctl_server")


class UnixctlConnection(object):
    def __init__(self, rpc):
        assert isinstance(rpc, ovs.jsonrpc.Connection)
        self._rpc = rpc
        self._request_id = None
        self._fmt = ovs.unixctl.UnixctlOutputFormat.TEXT

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
        assert body is None or isinstance(body, str)

        if body is None:
            body = ""

        if self._fmt == ovs.unixctl.UnixctlOutputFormat.JSON:
            body = {
                "reply-format": "plain",
                "reply": body
            }

        return self._reply_impl_json(True, body)

    def reply_json(self, body):
        self._reply_impl_json(True, body)

    def reply_error(self, body):
        assert body is None or isinstance(body, str)

        if body is None:
            body = ""

        return self._reply_impl_json(False, body)

    # Called only by unixctl classes.
    def _close(self):
        self._rpc.close()
        self._request_id = None

    def _wait(self, poller):
        self._rpc.wait(poller)
        if not self._rpc.get_backlog():
            self._rpc.recv_wait(poller)

    def _reply_impl_json(self, success, body):
        assert isinstance(success, bool)

        assert self._request_id is not None

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
                if not isinstance(param, str):
                    error = '"%s" command has non-string argument' % method
                    break

            if error is None:
                unicode_params = [str(p) for p in params]
                command.callback(self, unicode_params, command.aux)

        if error:
            self.reply_error(error)


def _unixctl_version(conn, unused_argv, version):
    assert isinstance(conn, UnixctlConnection)
    version = "%s (Open vSwitch) %s" % (ovs.util.PROGRAM_NAME, version)
    conn.reply(version)


def _unixctl_set_options(conn, argv, unused_aux):
    assert isinstance(conn, UnixctlConnection)

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", default="text",
                        choices=[fmt.name.lower()
                                 for fmt in ovs.unixctl.UnixctlOutputFormat],
                        type=str.lower)

    try:
        args = parser.parse_args(args=argv)
    except argparse.ArgumentError as e:
        conn.reply_error(str(e))
        return

    conn._fmt = ovs.unixctl.UnixctlOutputFormat[args.format.upper()]
    conn.reply(None)


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

        assert path is None or isinstance(path, str)

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

        ovs.unixctl.command_register("set-options", "[--format text|json]", 1,
                                     2, _unixctl_set_options, None)

        return 0, UnixctlServer(listener)
