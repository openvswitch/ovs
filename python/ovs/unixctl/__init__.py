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

import sys

import ovs.util

commands = {}


class _UnixctlCommand(object):
    def __init__(self, usage, min_args, max_args, callback, aux):
        self.usage = usage
        self.min_args = min_args
        self.max_args = max_args
        self.callback = callback
        self.aux = aux


def _unixctl_help(conn, unused_argv, unused_aux):
    reply = "The available commands are:\n"
    command_names = sorted(commands.keys())
    for name in command_names:
        reply += "  "
        usage = commands[name].usage
        if usage:
            reply += "%-23s %s" % (name, usage)
        else:
            reply += name
        reply += "\n"
    conn.reply(reply)


def command_register(name, usage, min_args, max_args, callback, aux):
    """ Registers a command with the given 'name' to be exposed by the
    UnixctlServer. 'usage' describes the arguments to the command; it is used
    only for presentation to the user in "help" output.

    'callback' is called when the command is received.  It is passed a
    UnixctlConnection object, the list of arguments as unicode strings, and
    'aux'.  Normally 'callback' should reply by calling
    UnixctlConnection.reply() or UnixctlConnection.reply_error() before it
    returns, but if the command cannot be handled immediately, then it can
    defer the reply until later.  A given connection can only process a single
    request at a time, so a reply must be made eventually to avoid blocking
    that connection."""

    assert isinstance(name, str)
    assert isinstance(usage, str)
    assert isinstance(min_args, int)
    assert isinstance(max_args, int)
    assert callable(callback)

    if name not in commands:
        commands[name] = _UnixctlCommand(usage, min_args, max_args, callback,
                                         aux)


def socket_name_from_target(target):
    assert isinstance(target, str)

    """ On Windows an absolute path contains ':' ( i.e: C:\\ ) """
    if target.startswith('/') or target.find(':') > -1:
        return 0, target

    pidfile_name = "%s/%s.pid" % (ovs.dirs.RUNDIR, target)
    pid = ovs.daemon.read_pidfile(pidfile_name)
    if pid < 0:
        return -pid, "cannot read pidfile \"%s\"" % pidfile_name

    if sys.platform == "win32":
        return 0, "%s/%s.ctl" % (ovs.dirs.RUNDIR, target)
    else:
        return 0, "%s/%s.%d.ctl" % (ovs.dirs.RUNDIR, target, pid)


command_register("help", "", 0, 0, _unixctl_help, None)
