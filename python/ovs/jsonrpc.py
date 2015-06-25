# Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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

import ovs.json
import ovs.poller
import ovs.reconnect
import ovs.stream
import ovs.timeval
import ovs.util
import ovs.vlog

EOF = ovs.util.EOF
vlog = ovs.vlog.Vlog("jsonrpc")


class Message(object):
    T_REQUEST = 0               # Request.
    T_NOTIFY = 1                # Notification.
    T_REPLY = 2                 # Successful reply.
    T_ERROR = 3                 # Error reply.

    __types = {T_REQUEST: "request",
               T_NOTIFY: "notification",
               T_REPLY: "reply",
               T_ERROR: "error"}

    def __init__(self, type_, method, params, result, error, id):
        self.type = type_
        self.method = method
        self.params = params
        self.result = result
        self.error = error
        self.id = id

    _next_id = 0

    @staticmethod
    def _create_id():
        this_id = Message._next_id
        Message._next_id += 1
        return this_id

    @staticmethod
    def create_request(method, params):
        return Message(Message.T_REQUEST, method, params, None, None,
                       Message._create_id())

    @staticmethod
    def create_notify(method, params):
        return Message(Message.T_NOTIFY, method, params, None, None,
                       None)

    @staticmethod
    def create_reply(result, id):
        return Message(Message.T_REPLY, None, None, result, None, id)

    @staticmethod
    def create_error(error, id):
        return Message(Message.T_ERROR, None, None, None, error, id)

    @staticmethod
    def type_to_string(type_):
        return Message.__types[type_]

    def __validate_arg(self, value, name, must_have):
        if (value is not None) == (must_have != 0):
            return None
        else:
            type_name = Message.type_to_string(self.type)
            if must_have:
                verb = "must"
            else:
                verb = "must not"
            return "%s %s have \"%s\"" % (type_name, verb, name)

    def is_valid(self):
        if self.params is not None and type(self.params) != list:
            return "\"params\" must be JSON array"

        pattern = {Message.T_REQUEST: 0x11001,
                   Message.T_NOTIFY:  0x11000,
                   Message.T_REPLY:   0x00101,
                   Message.T_ERROR:   0x00011}.get(self.type)
        if pattern is None:
            return "invalid JSON-RPC message type %s" % self.type

        return (
            self.__validate_arg(self.method, "method", pattern & 0x10000) or
            self.__validate_arg(self.params, "params", pattern & 0x1000) or
            self.__validate_arg(self.result, "result", pattern & 0x100) or
            self.__validate_arg(self.error, "error", pattern & 0x10) or
            self.__validate_arg(self.id, "id", pattern & 0x1))

    @staticmethod
    def from_json(json):
        if type(json) != dict:
            return "message is not a JSON object"

        # Make a copy to avoid modifying the caller's dict.
        json = dict(json)

        if "method" in json:
            method = json.pop("method")
            if type(method) not in [str, unicode]:
                return "method is not a JSON string"
        else:
            method = None

        params = json.pop("params", None)
        result = json.pop("result", None)
        error = json.pop("error", None)
        id_ = json.pop("id", None)
        if len(json):
            return "message has unexpected member \"%s\"" % json.popitem()[0]

        if result is not None:
            msg_type = Message.T_REPLY
        elif error is not None:
            msg_type = Message.T_ERROR
        elif id_ is not None:
            msg_type = Message.T_REQUEST
        else:
            msg_type = Message.T_NOTIFY

        msg = Message(msg_type, method, params, result, error, id_)
        validation_error = msg.is_valid()
        if validation_error is not None:
            return validation_error
        else:
            return msg

    def to_json(self):
        json = {}

        if self.method is not None:
            json["method"] = self.method

        if self.params is not None:
            json["params"] = self.params

        if self.result is not None or self.type == Message.T_ERROR:
            json["result"] = self.result

        if self.error is not None or self.type == Message.T_REPLY:
            json["error"] = self.error

        if self.id is not None or self.type == Message.T_NOTIFY:
            json["id"] = self.id

        return json

    def __str__(self):
        s = [Message.type_to_string(self.type)]
        if self.method is not None:
            s.append("method=\"%s\"" % self.method)
        if self.params is not None:
            s.append("params=" + ovs.json.to_string(self.params))
        if self.result is not None:
            s.append("result=" + ovs.json.to_string(self.result))
        if self.error is not None:
            s.append("error=" + ovs.json.to_string(self.error))
        if self.id is not None:
            s.append("id=" + ovs.json.to_string(self.id))
        return ", ".join(s)


class Connection(object):
    def __init__(self, stream):
        self.name = stream.name
        self.stream = stream
        self.status = 0
        self.input = ""
        self.output = ""
        self.parser = None
        self.received_bytes = 0

    def close(self):
        self.stream.close()
        self.stream = None

    def run(self):
        if self.status:
            return

        while len(self.output):
            retval = self.stream.send(self.output)
            if retval >= 0:
                self.output = self.output[retval:]
            else:
                if retval != -errno.EAGAIN:
                    vlog.warn("%s: send error: %s" %
                              (self.name, os.strerror(-retval)))
                    self.error(-retval)
                break

    def wait(self, poller):
        if not self.status:
            self.stream.run_wait(poller)
            if len(self.output):
                self.stream.send_wait(poller)

    def get_status(self):
        return self.status

    def get_backlog(self):
        if self.status != 0:
            return 0
        else:
            return len(self.output)

    def get_received_bytes(self):
        return self.received_bytes

    def __log_msg(self, title, msg):
        if vlog.dbg_is_enabled():
            vlog.dbg("%s: %s %s" % (self.name, title, msg))

    def send(self, msg):
        if self.status:
            return self.status

        self.__log_msg("send", msg)

        was_empty = len(self.output) == 0
        self.output += ovs.json.to_string(msg.to_json())
        if was_empty:
            self.run()
        return self.status

    def send_block(self, msg):
        error = self.send(msg)
        if error:
            return error

        while True:
            self.run()
            if not self.get_backlog() or self.get_status():
                return self.status

            poller = ovs.poller.Poller()
            self.wait(poller)
            poller.block()

    def recv(self):
        if self.status:
            return self.status, None

        while True:
            if not self.input:
                error, data = self.stream.recv(4096)
                if error:
                    if error == errno.EAGAIN:
                        return error, None
                    else:
                        # XXX rate-limit
                        vlog.warn("%s: receive error: %s"
                                  % (self.name, os.strerror(error)))
                        self.error(error)
                        return self.status, None
                elif not data:
                    self.error(EOF)
                    return EOF, None
                else:
                    self.input += data
                    self.received_bytes += len(data)
            else:
                if self.parser is None:
                    self.parser = ovs.json.Parser()
                self.input = self.input[self.parser.feed(self.input):]
                if self.parser.is_done():
                    msg = self.__process_msg()
                    if msg:
                        return 0, msg
                    else:
                        return self.status, None

    def recv_block(self):
        while True:
            error, msg = self.recv()
            if error != errno.EAGAIN:
                return error, msg

            self.run()

            poller = ovs.poller.Poller()
            self.wait(poller)
            self.recv_wait(poller)
            poller.block()

    def transact_block(self, request):
        id_ = request.id

        error = self.send(request)
        reply = None
        while not error:
            error, reply = self.recv_block()
            if (reply
                and (reply.type == Message.T_REPLY
                     or reply.type == Message.T_ERROR)
                and reply.id == id_):
                break
        return error, reply

    def __process_msg(self):
        json = self.parser.finish()
        self.parser = None
        if type(json) in [str, unicode]:
            # XXX rate-limit
            vlog.warn("%s: error parsing stream: %s" % (self.name, json))
            self.error(errno.EPROTO)
            return

        msg = Message.from_json(json)
        if not isinstance(msg, Message):
            # XXX rate-limit
            vlog.warn("%s: received bad JSON-RPC message: %s"
                      % (self.name, msg))
            self.error(errno.EPROTO)
            return

        self.__log_msg("received", msg)
        return msg

    def recv_wait(self, poller):
        if self.status or self.input:
            poller.immediate_wake()
        else:
            self.stream.recv_wait(poller)

    def error(self, error):
        if self.status == 0:
            self.status = error
            self.stream.close()
            self.output = ""


class Session(object):
    """A JSON-RPC session with reconnection."""

    def __init__(self, reconnect, rpc):
        self.reconnect = reconnect
        self.rpc = rpc
        self.stream = None
        self.pstream = None
        self.seqno = 0

    @staticmethod
    def open(name):
        """Creates and returns a Session that maintains a JSON-RPC session to
        'name', which should be a string acceptable to ovs.stream.Stream or
        ovs.stream.PassiveStream's initializer.

        If 'name' is an active connection method, e.g. "tcp:127.1.2.3", the new
        session connects and reconnects, with back-off, to 'name'.

        If 'name' is a passive connection method, e.g. "ptcp:", the new session
        listens for connections to 'name'.  It maintains at most one connection
        at any given time.  Any new connection causes the previous one (if any)
        to be dropped."""
        reconnect = ovs.reconnect.Reconnect(ovs.timeval.msec())
        reconnect.set_name(name)
        reconnect.enable(ovs.timeval.msec())

        if ovs.stream.PassiveStream.is_valid_name(name):
            reconnect.set_passive(True, ovs.timeval.msec())

        if not ovs.stream.stream_or_pstream_needs_probes(name):
            reconnect.set_probe_interval(0)

        return Session(reconnect, None)

    @staticmethod
    def open_unreliably(jsonrpc):
        reconnect = ovs.reconnect.Reconnect(ovs.timeval.msec())
        reconnect.set_quiet(True)
        reconnect.set_name(jsonrpc.name)
        reconnect.set_max_tries(0)
        reconnect.connected(ovs.timeval.msec())
        return Session(reconnect, jsonrpc)

    def close(self):
        if self.rpc is not None:
            self.rpc.close()
            self.rpc = None
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.pstream is not None:
            self.pstream.close()
            self.pstream = None

    def __disconnect(self):
        if self.rpc is not None:
            self.rpc.error(EOF)
            self.rpc.close()
            self.rpc = None
            self.seqno += 1
        elif self.stream is not None:
            self.stream.close()
            self.stream = None
            self.seqno += 1

    def __connect(self):
        self.__disconnect()

        name = self.reconnect.get_name()
        if not self.reconnect.is_passive():
            error, self.stream = ovs.stream.Stream.open(name)
            if not error:
                self.reconnect.connecting(ovs.timeval.msec())
            else:
                self.reconnect.connect_failed(ovs.timeval.msec(), error)
        elif self.pstream is not None:
            error, self.pstream = ovs.stream.PassiveStream.open(name)
            if not error:
                self.reconnect.listening(ovs.timeval.msec())
            else:
                self.reconnect.connect_failed(ovs.timeval.msec(), error)

        self.seqno += 1

    def run(self):
        if self.pstream is not None:
            error, stream = self.pstream.accept()
            if error == 0:
                if self.rpc or self.stream:
                    # XXX rate-limit
                    vlog.info("%s: new connection replacing active "
                              "connection" % self.reconnect.get_name())
                    self.__disconnect()
                self.reconnect.connected(ovs.timeval.msec())
                self.rpc = Connection(stream)
            elif error != errno.EAGAIN:
                self.reconnect.listen_error(ovs.timeval.msec(), error)
                self.pstream.close()
                self.pstream = None

        if self.rpc:
            backlog = self.rpc.get_backlog()
            self.rpc.run()
            if self.rpc.get_backlog() < backlog:
                # Data previously caught in a queue was successfully sent (or
                # there's an error, which we'll catch below).
                #
                # We don't count data that is successfully sent immediately as
                # activity, because there's a lot of queuing downstream from
                # us, which means that we can push a lot of data into a
                # connection that has stalled and won't ever recover.
                self.reconnect.activity(ovs.timeval.msec())

            error = self.rpc.get_status()
            if error != 0:
                self.reconnect.disconnected(ovs.timeval.msec(), error)
                self.__disconnect()
        elif self.stream is not None:
            self.stream.run()
            error = self.stream.connect()
            if error == 0:
                self.reconnect.connected(ovs.timeval.msec())
                self.rpc = Connection(self.stream)
                self.stream = None
            elif error != errno.EAGAIN:
                self.reconnect.connect_failed(ovs.timeval.msec(), error)
                self.stream.close()
                self.stream = None

        action = self.reconnect.run(ovs.timeval.msec())
        if action == ovs.reconnect.CONNECT:
            self.__connect()
        elif action == ovs.reconnect.DISCONNECT:
            self.reconnect.disconnected(ovs.timeval.msec(), 0)
            self.__disconnect()
        elif action == ovs.reconnect.PROBE:
            if self.rpc:
                request = Message.create_request("echo", [])
                request.id = "echo"
                self.rpc.send(request)
        else:
            assert action == None

    def wait(self, poller):
        if self.rpc is not None:
            self.rpc.wait(poller)
        elif self.stream is not None:
            self.stream.run_wait(poller)
            self.stream.connect_wait(poller)
        if self.pstream is not None:
            self.pstream.wait(poller)
        self.reconnect.wait(poller, ovs.timeval.msec())

    def get_backlog(self):
        if self.rpc is not None:
            return self.rpc.get_backlog()
        else:
            return 0

    def get_name(self):
        return self.reconnect.get_name()

    def send(self, msg):
        if self.rpc is not None:
            return self.rpc.send(msg)
        else:
            return errno.ENOTCONN

    def recv(self):
        if self.rpc is not None:
            received_bytes = self.rpc.get_received_bytes()
            error, msg = self.rpc.recv()
            if received_bytes != self.rpc.get_received_bytes():
                # Data was successfully received.
                #
                # Previously we only counted receiving a full message as
                # activity, but with large messages or a slow connection that
                # policy could time out the session mid-message.
                self.reconnect.activity(ovs.timeval.msec())

            if not error:
                if msg.type == Message.T_REQUEST and msg.method == "echo":
                    # Echo request.  Send reply.
                    self.send(Message.create_reply(msg.params, msg.id))
                elif msg.type == Message.T_REPLY and msg.id == "echo":
                    # It's a reply to our echo request.  Suppress it.
                    pass
                else:
                    return msg
        return None

    def recv_wait(self, poller):
        if self.rpc is not None:
            self.rpc.recv_wait(poller)

    def is_alive(self):
        if self.rpc is not None or self.stream is not None:
            return True
        else:
            max_tries = self.reconnect.get_max_tries()
            return max_tries is None or max_tries > 0

    def is_connected(self):
        return self.rpc is not None

    def get_seqno(self):
        return self.seqno

    def force_reconnect(self):
        self.reconnect.force_reconnect(ovs.timeval.msec())
