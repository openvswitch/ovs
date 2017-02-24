# Copyright (c) 2011, 2012 Nicira, Inc.
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

import ovs.jsonrpc
import ovs.stream
import ovs.util

import six

vlog = ovs.vlog.Vlog("unixctl_client")
strtypes = six.string_types


class UnixctlClient(object):
    def __init__(self, conn):
        assert isinstance(conn, ovs.jsonrpc.Connection)
        self._conn = conn

    def transact(self, command, argv):
        assert isinstance(command, strtypes)
        assert isinstance(argv, list)
        for arg in argv:
            assert isinstance(arg, strtypes)

        request = ovs.jsonrpc.Message.create_request(command, argv)
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
