# Copyright (c) 2009, 2010, 2011 Nicira Networks
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
import getopt
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
        rpcs = [rpc for rpc in rpcs if not rpc in dead_rpcs]

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
    
    print ovs.json.to_string(msg.to_json())

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
    try:
        options, args = getopt.gnu_getopt(
            argv[1:], 'h', ["help"] + ovs.daemon.LONG_OPTIONS)
    except getopt.GetoptError, geo:
        sys.stderr.write("%s: %s\n" % (ovs.util.PROGRAM_NAME, geo.msg))
        sys.exit(1)

    for key, value in options:
        if key in ['h', '--help']:
            usage()
        elif not ovs.daemon.parse_opt(key, value):
            sys.stderr.write("%s: unhandled option %s\n"
                             % (ovs.util.PROGRAM_NAME, key))
            sys.exit(1)

    commands = {"listen": (do_listen, 1),
                "request": (do_request, 3),
                "notify": (do_notify, 3),
                "help": (usage, (0,))}

    command_name = args[0]
    args = args[1:]
    if not command_name in commands:
        sys.stderr.write("%s: unknown command \"%s\" "
                         "(use --help for help)\n" % (argv0, command_name))
        sys.exit(1)

    func, n_args = commands[command_name]
    if type(n_args) == tuple:
        if len(args) < n_args[0]:
            sys.stderr.write("%s: \"%s\" requires at least %d arguments but "
                             "only %d provided\n"
                             % (argv0, command_name, n_args, len(args)))
            sys.exit(1)
    elif type(n_args) == int:
        if len(args) != n_args:
            sys.stderr.write("%s: \"%s\" requires %d arguments but %d "
                             "provided\n"
                             % (argv0, command_name, n_args, len(args)))
            sys.exit(1)
    else:
        assert False

    func(*args)

def usage():
    sys.stdout.write("""\
%s: JSON-RPC test utility for Python
usage: %s [OPTIONS] COMMAND [ARG...]
  listen LOCAL             listen for connections on LOCAL
  request REMOTE METHOD PARAMS   send request, print reply
  notify REMOTE METHOD PARAMS  send notification and exit
""" % (ovs.util.PROGRAM_NAME, ovs.util.PROGRAM_NAME))
    ovs.stream.usage("JSON-RPC", True, True, True)
    ovs.daemon.usage()
    sys.stdout.write("""
Other options:
  -h, --help              display this help message
""")
    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)

