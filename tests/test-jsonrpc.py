# Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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
import errno
import os
import sys

import ovs.daemon
import ovs.json
import ovs.jsonrpc
import ovs.poller
import ovs.stream


def handle_rpc(rpc, msg):
    done = False
    reply = None

    if msg.type == ovs.jsonrpc.Message.T_REQUEST:
        if msg.method == "echo":
            reply = ovs.jsonrpc.Message.create_reply(msg.params, msg.id)
        else:
            reply = ovs.jsonrpc.Message.create_error(
                {"error": "unknown method"}, msg.id)
            sys.stderr.write("unknown request %s" % msg.method)
    elif msg.type == ovs.jsonrpc.Message.T_NOTIFY:
        if msg.method == "shutdown":
            done = True
        else:
            rpc.error(errno.ENOTTY)
            sys.stderr.write("unknown notification %s" % msg.method)
    else:
        rpc.error(errno.EPROTO)
        sys.stderr.write("unsolicited JSON-RPC reply or error\n")

    if reply:
        rpc.send(reply)
    return done


def do_listen(name):
    if sys.platform != 'win32' or (
            ovs.daemon._detach and ovs.daemon._detached):
        # On Windows the child is a new process created which should be the
        # one that creates the PassiveStream. Without this check, the new
        # child process will create a new PassiveStream overwriting the one
        # that the parent process created.
        error, pstream = ovs.stream.PassiveStream.open(name)
        if error:
            sys.stderr.write("could not listen on \"%s\": %s\n"
                             % (name, os.strerror(error)))
            sys.exit(1)

    ovs.daemon.daemonize()

    rpcs = []
    done = False
    while True:
        # Accept new connections.
        error, stream = pstream.accept()
        if stream:
            rpcs.append(ovs.jsonrpc.Connection(stream))
        elif error != errno.EAGAIN:
            sys.stderr.write("PassiveStream.accept() failed\n")
            sys.exit(1)

        # Service existing connections.
        dead_rpcs = []
        for rpc in rpcs:
            rpc.run()

            error = 0
            if not rpc.get_backlog():
                error, msg = rpc.recv()
                if not error:
                    if handle_rpc(rpc, msg):
                        done = True

            error = rpc.get_status()
            if error:
                rpc.close()
                dead_rpcs.append(rpc)
        rpcs = [rpc for rpc in rpcs if rpc not in dead_rpcs]

        if done and not rpcs:
            break

        poller = ovs.poller.Poller()
        pstream.wait(poller)
        for rpc in rpcs:
            rpc.wait(poller)
            if not rpc.get_backlog():
                rpc.recv_wait(poller)
        poller.block()
    pstream.close()


def do_request(name, method, params_string):
    params = ovs.json.from_string(params_string)
    msg = ovs.jsonrpc.Message.create_request(method, params)
    s = msg.is_valid()
    if s:
        sys.stderr.write("not a valid JSON-RPC request: %s\n" % s)
        sys.exit(1)

    error, stream = ovs.stream.Stream.open_block(ovs.stream.Stream.open(name))
    if error:
        sys.stderr.write("could not open \"%s\": %s\n"
                         % (name, os.strerror(error)))
        sys.exit(1)

    rpc = ovs.jsonrpc.Connection(stream)

    error = rpc.send(msg)
    if error:
        sys.stderr.write("could not send request: %s\n" % os.strerror(error))
        sys.exit(1)

    error, msg = rpc.recv_block()
    if error:
        sys.stderr.write("error waiting for reply: %s\n" % os.strerror(error))
        sys.exit(1)

    print(ovs.json.to_string(msg.to_json()))

    rpc.close()


def do_notify(name, method, params_string):
    params = ovs.json.from_string(params_string)
    msg = ovs.jsonrpc.Message.create_notify(method, params)
    s = msg.is_valid()
    if s:
        sys.stderr.write("not a valid JSON-RPC notification: %s\n" % s)
        sys.exit(1)

    error, stream = ovs.stream.Stream.open_block(ovs.stream.Stream.open(name))
    if error:
        sys.stderr.write("could not open \"%s\": %s\n"
                         % (name, os.strerror(error)))
        sys.exit(1)

    rpc = ovs.jsonrpc.Connection(stream)

    error = rpc.send_block(msg)
    if error:
        sys.stderr.write("could not send notification: %s\n"
                         % os.strerror(error))
        sys.exit(1)

    rpc.close()


def main(argv):

    parser = argparse.ArgumentParser(
            description="JSON-RPC test utility for Python.",
            formatter_class=argparse.RawDescriptionHelpFormatter)

    commands = {"listen": (do_listen, 1),
                "request": (do_request, 3),
                "notify": (do_notify, 3),
                "help": (parser.print_help, (0,))}

    group_description = """\
listen LOCAL             listen for connections on LOCAL
request REMOTE METHOD PARAMS   send request, print reply
notify REMOTE METHOD PARAMS  send notification and exit
""" + ovs.stream.usage("JSON-RPC")

    group = parser.add_argument_group(title="Commands",
                                      description=group_description)
    group.add_argument('command', metavar="COMMAND", nargs=1,
                        choices=commands, help="Command to use.")
    group.add_argument('command_args', metavar="ARG", nargs='*',
                       help="Arguments to COMMAND.")

    ovs.daemon.add_args(parser)
    args = parser.parse_args()
    ovs.daemon.handle_args(args)

    command_name = args.command[0]
    args = args.command_args
    if command_name not in commands:
        sys.stderr.write("%s: unknown command \"%s\" "
                         "(use --help for help)\n" % (argv[0], command_name))
        sys.exit(1)

    func, n_args = commands[command_name]
    if type(n_args) == tuple:
        if len(args) < n_args[0]:
            sys.stderr.write("%s: \"%s\" requires at least %d arguments but "
                             "only %d provided\n"
                             % (argv[0], command_name, n_args, len(args)))
            sys.exit(1)
    elif type(n_args) == int:
        if len(args) != n_args:
            sys.stderr.write("%s: \"%s\" requires %d arguments but %d "
                             "provided\n"
                             % (argv[0], command_name, n_args, len(args)))
            sys.exit(1)
    else:
        assert False

    func(*args)


if __name__ == '__main__':
    main(sys.argv)
