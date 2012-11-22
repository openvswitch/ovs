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

import errno
import os
import socket

import ovs.poller
import ovs.socket_util
import ovs.vlog

vlog = ovs.vlog.Vlog("stream")


def stream_or_pstream_needs_probes(name):
    """ 1 if the stream or pstream specified by 'name' needs periodic probes to
    verify connectivity.  For [p]streams which need probes, it can take a long
    time to notice the connection was dropped.  Returns 0 if probes aren't
    needed, and -1 if 'name' is invalid"""

    if PassiveStream.is_valid_name(name) or Stream.is_valid_name(name):
        # Only unix and punix are supported currently.
        return 0
    else:
        return -1


class Stream(object):
    """Bidirectional byte stream.  Currently only Unix domain sockets
    are implemented."""

    # States.
    __S_CONNECTING = 0
    __S_CONNECTED = 1
    __S_DISCONNECTED = 2

    # Kinds of events that one might wait for.
    W_CONNECT = 0               # Connect complete (success or failure).
    W_RECV = 1                  # Data received.
    W_SEND = 2                  # Send buffer room available.

    _SOCKET_METHODS = {}

    @staticmethod
    def register_method(method, cls):
        Stream._SOCKET_METHODS[method + ":"] = cls

    @staticmethod
    def _find_method(name):
        for method, cls in Stream._SOCKET_METHODS.items():
            if name.startswith(method):
                return cls
        return None

    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a stream name in the form "TYPE:ARGS" and
        TYPE is a supported stream type (currently only "unix:" and "tcp:"),
        otherwise False."""
        return bool(Stream._find_method(name))

    def __init__(self, socket, name, status):
        self.socket = socket
        self.name = name
        if status == errno.EAGAIN:
            self.state = Stream.__S_CONNECTING
        elif status == 0:
            self.state = Stream.__S_CONNECTED
        else:
            self.state = Stream.__S_DISCONNECTED

        self.error = 0

    # Default value of dscp bits for connection between controller and manager.
    # Value of IPTOS_PREC_INTERNETCONTROL = 0xc0 which is defined
    # in <netinet/ip.h> is used.
    IPTOS_PREC_INTERNETCONTROL = 0xc0
    DSCP_DEFAULT = IPTOS_PREC_INTERNETCONTROL >> 2

    @staticmethod
    def open(name, dscp=DSCP_DEFAULT):
        """Attempts to connect a stream to a remote peer.  'name' is a
        connection name in the form "TYPE:ARGS", where TYPE is an active stream
        class's name and ARGS are stream class-specific.  Currently the only
        supported TYPEs are "unix" and "tcp".

        Returns (error, stream): on success 'error' is 0 and 'stream' is the
        new Stream, on failure 'error' is a positive errno value and 'stream'
        is None.

        Never returns errno.EAGAIN or errno.EINPROGRESS.  Instead, returns 0
        and a new Stream.  The connect() method can be used to check for
        successful connection completion."""
        cls = Stream._find_method(name)
        if not cls:
            return errno.EAFNOSUPPORT, None

        suffix = name.split(":", 1)[1]
        error, sock = cls._open(suffix, dscp)
        if error:
            return error, None
        else:
            status = ovs.socket_util.check_connection_completion(sock)
            return 0, Stream(sock, name, status)

    @staticmethod
    def _open(suffix, dscp):
        raise NotImplementedError("This method must be overrided by subclass")

    @staticmethod
    def open_block((error, stream)):
        """Blocks until a Stream completes its connection attempt, either
        succeeding or failing.  (error, stream) should be the tuple returned by
        Stream.open().  Returns a tuple of the same form.

        Typical usage:
        error, stream = Stream.open_block(Stream.open("unix:/tmp/socket"))"""

        if not error:
            while True:
                error = stream.connect()
                if error != errno.EAGAIN:
                    break
                stream.run()
                poller = ovs.poller.Poller()
                stream.run_wait(poller)
                stream.connect_wait(poller)
                poller.block()
            assert error != errno.EINPROGRESS

        if error and stream:
            stream.close()
            stream = None
        return error, stream

    def close(self):
        self.socket.close()

    def __scs_connecting(self):
        retval = ovs.socket_util.check_connection_completion(self.socket)
        assert retval != errno.EINPROGRESS
        if retval == 0:
            self.state = Stream.__S_CONNECTED
        elif retval != errno.EAGAIN:
            self.state = Stream.__S_DISCONNECTED
            self.error = retval

    def connect(self):
        """Tries to complete the connection on this stream.  If the connection
        is complete, returns 0 if the connection was successful or a positive
        errno value if it failed.  If the connection is still in progress,
        returns errno.EAGAIN."""

        if self.state == Stream.__S_CONNECTING:
            self.__scs_connecting()

        if self.state == Stream.__S_CONNECTING:
            return errno.EAGAIN
        elif self.state == Stream.__S_CONNECTED:
            return 0
        else:
            assert self.state == Stream.__S_DISCONNECTED
            return self.error

    def recv(self, n):
        """Tries to receive up to 'n' bytes from this stream.  Returns a
        (error, string) tuple:

            - If successful, 'error' is zero and 'string' contains between 1
              and 'n' bytes of data.

            - On error, 'error' is a positive errno value.

            - If the connection has been closed in the normal fashion or if 'n'
              is 0, the tuple is (0, "").

        The recv function will not block waiting for data to arrive.  If no
        data have been received, it returns (errno.EAGAIN, "") immediately."""

        retval = self.connect()
        if retval != 0:
            return (retval, "")
        elif n == 0:
            return (0, "")

        try:
            return (0, self.socket.recv(n))
        except socket.error, e:
            return (ovs.socket_util.get_exception_errno(e), "")

    def send(self, buf):
        """Tries to send 'buf' on this stream.

        If successful, returns the number of bytes sent, between 1 and
        len(buf).  0 is only a valid return value if len(buf) is 0.

        On error, returns a negative errno value.

        Will not block.  If no bytes can be immediately accepted for
        transmission, returns -errno.EAGAIN immediately."""

        retval = self.connect()
        if retval != 0:
            return -retval
        elif len(buf) == 0:
            return 0

        try:
            return self.socket.send(buf)
        except socket.error, e:
            return -ovs.socket_util.get_exception_errno(e)

    def run(self):
        pass

    def run_wait(self, poller):
        pass

    def wait(self, poller, wait):
        assert wait in (Stream.W_CONNECT, Stream.W_RECV, Stream.W_SEND)

        if self.state == Stream.__S_DISCONNECTED:
            poller.immediate_wake()
            return

        if self.state == Stream.__S_CONNECTING:
            wait = Stream.W_CONNECT
        if wait == Stream.W_RECV:
            poller.fd_wait(self.socket, ovs.poller.POLLIN)
        else:
            poller.fd_wait(self.socket, ovs.poller.POLLOUT)

    def connect_wait(self, poller):
        self.wait(poller, Stream.W_CONNECT)

    def recv_wait(self, poller):
        self.wait(poller, Stream.W_RECV)

    def send_wait(self, poller):
        self.wait(poller, Stream.W_SEND)

    def __del__(self):
        # Don't delete the file: we might have forked.
        self.socket.close()


class PassiveStream(object):
    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a passive stream name in the form
        "TYPE:ARGS" and TYPE is a supported passive stream type (currently only
        "punix:"), otherwise False."""
        return name.startswith("punix:")

    def __init__(self, sock, name, bind_path):
        self.name = name
        self.socket = sock
        self.bind_path = bind_path

    @staticmethod
    def open(name):
        """Attempts to start listening for remote stream connections.  'name'
        is a connection name in the form "TYPE:ARGS", where TYPE is an passive
        stream class's name and ARGS are stream class-specific.  Currently the
        only supported TYPE is "punix".

        Returns (error, pstream): on success 'error' is 0 and 'pstream' is the
        new PassiveStream, on failure 'error' is a positive errno value and
        'pstream' is None."""
        if not PassiveStream.is_valid_name(name):
            return errno.EAFNOSUPPORT, None

        bind_path = name[6:]
        error, sock = ovs.socket_util.make_unix_socket(socket.SOCK_STREAM,
                                                       True, bind_path, None)
        if error:
            return error, None

        try:
            sock.listen(10)
        except socket.error, e:
            vlog.err("%s: listen: %s" % (name, os.strerror(e.error)))
            sock.close()
            return e.error, None

        return 0, PassiveStream(sock, name, bind_path)

    def close(self):
        """Closes this PassiveStream."""
        self.socket.close()
        if self.bind_path is not None:
            ovs.fatal_signal.unlink_file_now(self.bind_path)
            self.bind_path = None

    def accept(self):
        """Tries to accept a new connection on this passive stream.  Returns
        (error, stream): if successful, 'error' is 0 and 'stream' is the new
        Stream object, and on failure 'error' is a positive errno value and
        'stream' is None.

        Will not block waiting for a connection.  If no connection is ready to
        be accepted, returns (errno.EAGAIN, None) immediately."""

        while True:
            try:
                sock, addr = self.socket.accept()
                ovs.socket_util.set_nonblocking(sock)
                return 0, Stream(sock, "unix:%s" % addr, 0)
            except socket.error, e:
                error = ovs.socket_util.get_exception_errno(e)
                if error != errno.EAGAIN:
                    # XXX rate-limit
                    vlog.dbg("accept: %s" % os.strerror(error))
                return error, None

    def wait(self, poller):
        poller.fd_wait(self.socket, ovs.poller.POLLIN)

    def __del__(self):
        # Don't delete the file: we might have forked.
        self.socket.close()


def usage(name):
    return """
Active %s connection methods:
  unix:FILE               Unix domain socket named FILE
  tcp:IP:PORT             TCP socket to IP with port no of PORT

Passive %s connection methods:
  punix:FILE              Listen on Unix domain socket FILE""" % (name, name)


class UnixStream(Stream):
    @staticmethod
    def _open(suffix, dscp):
        connect_path = suffix
        return  ovs.socket_util.make_unix_socket(socket.SOCK_STREAM,
                                                 True, None, connect_path)
Stream.register_method("unix", UnixStream)


class TCPStream(Stream):
    @staticmethod
    def _open(suffix, dscp):
        error, sock = ovs.socket_util.inet_open_active(socket.SOCK_STREAM,
                                                       suffix, 0, dscp)
        if not error:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return error, sock
Stream.register_method("tcp", TCPStream)
