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
import sys

import ovs.poller
import ovs.socket_util
import ovs.vlog

import six

try:
    from OpenSSL import SSL
except ImportError:
    SSL = None

if sys.platform == 'win32':
    import ovs.winutils as winutils
    import pywintypes
    import win32event
    import win32file
    import win32pipe

vlog = ovs.vlog.Vlog("stream")


def stream_or_pstream_needs_probes(name):
    """ True if the stream or pstream specified by 'name' needs periodic probes
    to verify connectivity.  For [p]streams which need probes, it can take a
    long time to notice the connection was dropped.  Returns False if probes
    aren't needed, and None if 'name' is invalid"""

    cls = Stream._find_method(name)
    if cls:
        return cls.needs_probes()
    elif PassiveStream.is_valid_name(name):
        return PassiveStream.needs_probes(name)
    else:
        return None


class Stream(object):
    """Bidirectional byte stream.  Unix domain sockets, tcp and ssl
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

    _SSL_private_key_file = None
    _SSL_certificate_file = None
    _SSL_ca_cert_file = None

    # Windows only
    _write = None                # overlapped for write operation
    _read = None                 # overlapped for read operation
    _write_pending = False
    _read_pending = False
    _retry_connect = False

    @staticmethod
    def register_method(method, cls):
        Stream._SOCKET_METHODS[method + ":"] = cls

    @staticmethod
    def _find_method(name):
        for method, cls in six.iteritems(Stream._SOCKET_METHODS):
            if name.startswith(method):
                return cls
        return None

    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a stream name in the form "TYPE:ARGS" and
        TYPE is a supported stream type ("unix:", "tcp:" and "ssl:"),
        otherwise False."""
        return bool(Stream._find_method(name))

    def __init__(self, socket, name, status, pipe=None, is_server=False):
        self.socket = socket
        self.pipe = pipe
        if sys.platform == 'win32':
            self._read = pywintypes.OVERLAPPED()
            self._read.hEvent = winutils.get_new_event()
            self._write = pywintypes.OVERLAPPED()
            self._write.hEvent = winutils.get_new_event()
            if pipe is not None:
                # Flag to check if fd is a server HANDLE.  In the case of a
                # server handle we have to issue a disconnect before closing
                # the actual handle.
                self._server = is_server
                suffix = name.split(":", 1)[1]
                suffix = ovs.util.abs_file_name(ovs.dirs.RUNDIR, suffix)
                self._pipename = winutils.get_pipe_name(suffix)

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
        class's name and ARGS are stream class-specific.  The supported TYPEs
        include "unix", "tcp", and "ssl".

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
        if name.startswith("unix:"):
            suffix = ovs.util.abs_file_name(ovs.dirs.RUNDIR, suffix)
            if sys.platform == 'win32':
                pipename = winutils.get_pipe_name(suffix)

                if len(suffix) > 255:
                    # Return invalid argument if the name is too long
                    return errno.ENOENT, None

                try:
                    # In case of "unix:" argument, the assumption is that
                    # there is a file created in the path (suffix).
                    open(suffix, 'r').close()
                except:
                    return errno.ENOENT, None

                try:
                    npipe = winutils.create_file(pipename)
                    try:
                        winutils.set_pipe_mode(npipe,
                                               win32pipe.PIPE_READMODE_BYTE)
                    except pywintypes.error as e:
                        return errno.ENOENT, None
                except pywintypes.error as e:
                    if e.winerror == winutils.winerror.ERROR_PIPE_BUSY:
                        # Pipe is busy, set the retry flag to true and retry
                        # again during the connect function.
                        Stream.retry_connect = True
                        return 0, cls(None, name, errno.EAGAIN,
                                      pipe=win32file.INVALID_HANDLE_VALUE,
                                      is_server=False)
                    return errno.ENOENT, None
                return 0, cls(None, name, 0, pipe=npipe, is_server=False)

        error, sock = cls._open(suffix, dscp)
        if error:
            return error, None
        else:
            status = ovs.socket_util.check_connection_completion(sock)
            return 0, cls(sock, name, status)

    @staticmethod
    def _open(suffix, dscp):
        raise NotImplementedError("This method must be overrided by subclass")

    @staticmethod
    def open_block(error_stream):
        """Blocks until a Stream completes its connection attempt, either
        succeeding or failing.  (error, stream) should be the tuple returned by
        Stream.open().  Returns a tuple of the same form.

        Typical usage:
        error, stream = Stream.open_block(Stream.open("unix:/tmp/socket"))"""

        # Py3 doesn't support tuple parameter unpacking - PEP 3113
        error, stream = error_stream
        if not error:
            while True:
                error = stream.connect()
                if sys.platform == 'win32' and error == errno.WSAEWOULDBLOCK:
                    # WSAEWOULDBLOCK would be the equivalent on Windows
                    # for EAGAIN on Unix.
                    error = errno.EAGAIN
                if error != errno.EAGAIN:
                    break
                stream.run()
                poller = ovs.poller.Poller()
                stream.run_wait(poller)
                stream.connect_wait(poller)
                poller.block()
            if stream.socket is not None:
                assert error != errno.EINPROGRESS

        if error and stream:
            stream.close()
            stream = None
        return error, stream

    def close(self):
        if self.socket is not None:
            self.socket.close()
        if self.pipe is not None:
            if self._server:
                # Flush the pipe to allow the client to read the pipe
                # before disconnecting.
                win32pipe.FlushFileBuffers(self.pipe)
                win32pipe.DisconnectNamedPipe(self.pipe)
            winutils.close_handle(self.pipe, vlog.warn)
            winutils.close_handle(self._read.hEvent, vlog.warn)
            winutils.close_handle(self._write.hEvent, vlog.warn)

    def __scs_connecting(self):
        if self.socket is not None:
            retval = ovs.socket_util.check_connection_completion(self.socket)
            assert retval != errno.EINPROGRESS
        elif sys.platform == 'win32':
            if self.retry_connect:
                try:
                    self.pipe = winutils.create_file(self._pipename)
                    self._retry_connect = False
                    retval = 0
                except pywintypes.error as e:
                    if e.winerror == winutils.winerror.ERROR_PIPE_BUSY:
                        retval = errno.EAGAIN
                    else:
                        self._retry_connect = False
                        retval = errno.ENOENT
            else:
                # If retry_connect is false, it means it's already
                # connected so we can set the value of retval to 0
                retval = 0

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

        if sys.platform == 'win32' and self.socket is None:
            return self.__recv_windows(n)

        try:
            return (0, self.socket.recv(n))
        except socket.error as e:
            return (ovs.socket_util.get_exception_errno(e), "")

    def __recv_windows(self, n):
        if self._read_pending:
            try:
                nBytesRead = winutils.get_overlapped_result(self.pipe,
                                                            self._read,
                                                            False)
                self._read_pending = False
            except pywintypes.error as e:
                if e.winerror == winutils.winerror.ERROR_IO_INCOMPLETE:
                    # The operation is still pending, try again
                    self._read_pending = True
                    return (errno.EAGAIN, "")
                elif e.winerror in winutils.pipe_disconnected_errors:
                    # If the pipe was disconnected, return 0.
                    return (0, "")
                else:
                    return (errno.EINVAL, "")
        else:
            (errCode, self._read_buffer) = winutils.read_file(self.pipe,
                                                              n,
                                                              self._read)
            if errCode:
                if errCode == winutils.winerror.ERROR_IO_PENDING:
                    self._read_pending = True
                    return (errno.EAGAIN, "")
                elif errCode in winutils.pipe_disconnected_errors:
                    # If the pipe was disconnected, return 0.
                    return (0, "")
                else:
                    return (errCode, "")

            try:
                nBytesRead = winutils.get_overlapped_result(self.pipe,
                                                            self._read,
                                                            False)
                winutils.win32event.SetEvent(self._read.hEvent)
            except pywintypes.error as e:
                if e.winerror in winutils.pipe_disconnected_errors:
                    # If the pipe was disconnected, return 0.
                    return (0, "")
                else:
                    return (e.winerror, "")

        recvBuffer = self._read_buffer[:nBytesRead]
        # recvBuffer will have the type memoryview in Python3.
        # We can use bytes to convert it to type bytes which works on
        # both Python2 and Python3.
        return (0, bytes(recvBuffer))

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

        # Python 3 has separate types for strings and bytes.  We must have
        # bytes here.
        if six.PY3 and not isinstance(buf, bytes):
            buf = bytes(buf, 'utf-8')
        elif six.PY2:
            buf = buf.encode('utf-8')

        if sys.platform == 'win32' and self.socket is None:
            return self.__send_windows(buf)

        try:
            return self.socket.send(buf)
        except socket.error as e:
            return -ovs.socket_util.get_exception_errno(e)

    def __send_windows(self, buf):
        if self._write_pending:
            try:
                nBytesWritten = winutils.get_overlapped_result(self.pipe,
                                                               self._write,
                                                               False)
                self._write_pending = False
            except pywintypes.error as e:
                if e.winerror == winutils.winerror.ERROR_IO_INCOMPLETE:
                    # The operation is still pending, try again
                    self._read_pending = True
                    return -errno.EAGAIN
                elif e.winerror in winutils.pipe_disconnected_errors:
                    # If the pipe was disconnected, return connection reset.
                    return -errno.ECONNRESET
                else:
                    return -errno.EINVAL
        else:
            (errCode, nBytesWritten) = winutils.write_file(self.pipe,
                                                           buf,
                                                           self._write)
            if errCode:
                if errCode == winutils.winerror.ERROR_IO_PENDING:
                    self._write_pending = True
                    return -errno.EAGAIN
                if (not nBytesWritten and
                        errCode in winutils.pipe_disconnected_errors):
                    # If the pipe was disconnected, return connection reset.
                    return -errno.ECONNRESET
        return nBytesWritten

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

        if sys.platform == 'win32':
            self.__wait_windows(poller, wait)
            return

        if wait == Stream.W_RECV:
            poller.fd_wait(self.socket, ovs.poller.POLLIN)
        else:
            poller.fd_wait(self.socket, ovs.poller.POLLOUT)

    def __wait_windows(self, poller, wait):
        if self.socket is not None:
            if wait == Stream.W_RECV:
                read_flags = (win32file.FD_READ |
                              win32file.FD_ACCEPT |
                              win32file.FD_CLOSE)
                try:
                    win32file.WSAEventSelect(self.socket,
                                             self._read.hEvent,
                                             read_flags)
                except pywintypes.error as e:
                    vlog.err("failed to associate events with socket: %s"
                             % e.strerror)
                poller.fd_wait(self._read.hEvent, ovs.poller.POLLIN)
            else:
                write_flags = (win32file.FD_WRITE |
                               win32file.FD_CONNECT |
                               win32file.FD_CLOSE)
                try:
                    win32file.WSAEventSelect(self.socket,
                                             self._write.hEvent,
                                             write_flags)
                except pywintypes.error as e:
                    vlog.err("failed to associate events with socket: %s"
                             % e.strerror)
                poller.fd_wait(self._write.hEvent, ovs.poller.POLLOUT)
        else:
            if wait == Stream.W_RECV:
                if self._read:
                    poller.fd_wait(self._read.hEvent, ovs.poller.POLLIN)
            elif wait == Stream.W_SEND:
                if self._write:
                    poller.fd_wait(self._write.hEvent, ovs.poller.POLLOUT)
            elif wait == Stream.W_CONNECT:
                return

    def connect_wait(self, poller):
        self.wait(poller, Stream.W_CONNECT)

    def recv_wait(self, poller):
        self.wait(poller, Stream.W_RECV)

    def send_wait(self, poller):
        if sys.platform == 'win32':
            poller.fd_wait(self.connect.hEvent, ovs.poller.POLLIN)
        self.wait(poller, Stream.W_SEND)

    def __del__(self):
        # Don't delete the file: we might have forked.
        if self.socket is not None:
            self.socket.close()
        if self.pipe is not None:
            # Check if there are any remaining valid handles and close them
            if self.pipe:
                winutils.close_handle(self.pipe)
            if self._read.hEvent:
                winutils.close_handle(self._read.hEvent)
            if self._write.hEvent:
                winutils.close_handle(self._write.hEvent)

    @staticmethod
    def ssl_set_private_key_file(file_name):
        Stream._SSL_private_key_file = file_name

    @staticmethod
    def ssl_set_certificate_file(file_name):
        Stream._SSL_certificate_file = file_name

    @staticmethod
    def ssl_set_ca_cert_file(file_name):
        Stream._SSL_ca_cert_file = file_name


class PassiveStream(object):
    # Windows only
    connect = None                  # overlapped for read operation
    connect_pending = False

    @staticmethod
    def needs_probes(name):
        return False if name.startswith("punix:") else True

    @staticmethod
    def is_valid_name(name):
        """Returns True if 'name' is a passive stream name in the form
        "TYPE:ARGS" and TYPE is a supported passive stream type (currently
        "punix:" or "ptcp"), otherwise False."""
        return name.startswith("punix:") | name.startswith("ptcp:")

    def __init__(self, sock, name, bind_path, pipe=None):
        self.name = name
        self.pipe = pipe
        self.socket = sock
        if pipe is not None:
            self.connect = pywintypes.OVERLAPPED()
            self.connect.hEvent = winutils.get_new_event(bManualReset=True)
            self.connect_pending = False
            suffix = name.split(":", 1)[1]
            suffix = ovs.util.abs_file_name(ovs.dirs.RUNDIR, suffix)
            self._pipename = winutils.get_pipe_name(suffix)

        self.bind_path = bind_path

    @staticmethod
    def open(name):
        """Attempts to start listening for remote stream connections.  'name'
        is a connection name in the form "TYPE:ARGS", where TYPE is an passive
        stream class's name and ARGS are stream class-specific. Currently the
        supported values for TYPE are "punix" and "ptcp".

        Returns (error, pstream): on success 'error' is 0 and 'pstream' is the
        new PassiveStream, on failure 'error' is a positive errno value and
        'pstream' is None."""
        if not PassiveStream.is_valid_name(name):
            return errno.EAFNOSUPPORT, None

        bind_path = name[6:]
        if name.startswith("punix:"):
            bind_path = ovs.util.abs_file_name(ovs.dirs.RUNDIR, bind_path)
            if sys.platform != 'win32':
                error, sock = ovs.socket_util.make_unix_socket(
                    socket.SOCK_STREAM, True, bind_path, None)
                if error:
                    return error, None
            else:
                # Branch used only on Windows
                try:
                    open(bind_path, 'w').close()
                except:
                    return errno.ENOENT, None

                pipename = winutils.get_pipe_name(bind_path)
                if len(pipename) > 255:
                    # Return invalid argument if the name is too long
                    return errno.ENOENT, None

                npipe = winutils.create_named_pipe(pipename)
                if not npipe:
                    return errno.ENOENT, None
                return 0, PassiveStream(None, name, bind_path, pipe=npipe)

        elif name.startswith("ptcp:"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote = name.split(':')
            sock.bind((remote[1], int(remote[2])))

        else:
            raise Exception('Unknown connection string')

        try:
            sock.listen(10)
        except socket.error as e:
            vlog.err("%s: listen: %s" % (name, os.strerror(e.error)))
            sock.close()
            return e.error, None

        return 0, PassiveStream(sock, name, bind_path)

    def close(self):
        """Closes this PassiveStream."""
        if self.socket is not None:
            self.socket.close()
        if self.pipe is not None:
            winutils.close_handle(self.pipe, vlog.warn)
            winutils.close_handle(self.connect.hEvent, vlog.warn)
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
        if sys.platform == 'win32' and self.socket is None:
            return self.__accept_windows()
        while True:
            try:
                sock, addr = self.socket.accept()
                ovs.socket_util.set_nonblocking(sock)
                if (sys.platform != 'win32' and sock.family == socket.AF_UNIX):
                    return 0, Stream(sock, "unix:%s" % addr, 0)
                return 0, Stream(sock, 'ptcp:%s:%s' % (addr[0],
                                                       str(addr[1])), 0)
            except socket.error as e:
                error = ovs.socket_util.get_exception_errno(e)
                if sys.platform == 'win32' and error == errno.WSAEWOULDBLOCK:
                    # WSAEWOULDBLOCK would be the equivalent on Windows
                    # for EAGAIN on Unix.
                    error = errno.EAGAIN
                if error != errno.EAGAIN:
                    # XXX rate-limit
                    vlog.dbg("accept: %s" % os.strerror(error))
                return error, None

    def __accept_windows(self):
        if self.connect_pending:
            try:
                winutils.get_overlapped_result(self.pipe, self.connect, False)
            except pywintypes.error as e:
                if e.winerror == winutils.winerror.ERROR_IO_INCOMPLETE:
                    # The operation is still pending, try again
                    self.connect_pending = True
                    return errno.EAGAIN, None
                else:
                    if self.pipe:
                        win32pipe.DisconnectNamedPipe(self.pipe)
                    return errno.EINVAL, None
            self.connect_pending = False

        error = winutils.connect_named_pipe(self.pipe, self.connect)
        if error:
            if error == winutils.winerror.ERROR_IO_PENDING:
                self.connect_pending = True
                return errno.EAGAIN, None
            elif error != winutils.winerror.ERROR_PIPE_CONNECTED:
                if self.pipe:
                    win32pipe.DisconnectNamedPipe(self.pipe)
                self.connect_pending = False
                return errno.EINVAL, None
            else:
                win32event.SetEvent(self.connect.hEvent)

        npipe = winutils.create_named_pipe(self._pipename)
        if not npipe:
            return errno.ENOENT, None

        old_pipe = self.pipe
        self.pipe = npipe
        winutils.win32event.ResetEvent(self.connect.hEvent)
        return 0, Stream(None, self.name, 0, pipe=old_pipe)

    def wait(self, poller):
        if sys.platform != 'win32' or self.socket is not None:
            poller.fd_wait(self.socket, ovs.poller.POLLIN)
        else:
            poller.fd_wait(self.connect.hEvent, ovs.poller.POLLIN)

    def __del__(self):
        # Don't delete the file: we might have forked.
        if self.socket is not None:
            self.socket.close()
        if self.pipe is not None:
            # Check if there are any remaining valid handles and close them
            if self.pipe:
                winutils.close_handle(self.pipe)
            if self._connect.hEvent:
                winutils.close_handle(self._read.hEvent)


def usage(name):
    return """
Active %s connection methods:
  unix:FILE               Unix domain socket named FILE
  tcp:IP:PORT             TCP socket to IP with port no of PORT
  ssl:IP:PORT             SSL socket to IP with port no of PORT

Passive %s connection methods:
  punix:FILE              Listen on Unix domain socket FILE""" % (name, name)


class UnixStream(Stream):
    @staticmethod
    def needs_probes():
        return False

    @staticmethod
    def _open(suffix, dscp):
        connect_path = suffix
        return ovs.socket_util.make_unix_socket(socket.SOCK_STREAM,
                                                True, None, connect_path)


Stream.register_method("unix", UnixStream)


class TCPStream(Stream):
    @staticmethod
    def needs_probes():
        return True

    @staticmethod
    def _open(suffix, dscp):
        error, sock = ovs.socket_util.inet_open_active(socket.SOCK_STREAM,
                                                       suffix, 0, dscp)
        if not error:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return error, sock


Stream.register_method("tcp", TCPStream)


class SSLStream(Stream):
    @staticmethod
    def needs_probes():
        return True

    @staticmethod
    def verify_cb(conn, cert, errnum, depth, ok):
        return ok

    @staticmethod
    def _open(suffix, dscp):
        error, sock = TCPStream._open(suffix, dscp)
        if error:
            return error, None

        # Create an SSL context
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, SSLStream.verify_cb)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        # If the client has not set the SSL configuration files
        # exception would be raised.
        ctx.use_privatekey_file(Stream._SSL_private_key_file)
        ctx.use_certificate_file(Stream._SSL_certificate_file)
        ctx.load_verify_locations(Stream._SSL_ca_cert_file)

        ssl_sock = SSL.Connection(ctx, sock)
        ssl_sock.set_connect_state()
        return error, ssl_sock

    def connect(self):
        retval = super(SSLStream, self).connect()

        if retval:
            return retval

        # TCP Connection is successful. Now do the SSL handshake
        try:
            self.socket.do_handshake()
        except SSL.WantReadError:
            return errno.EAGAIN
        except SSL.SysCallError as e:
            return ovs.socket_util.get_exception_errno(e)

        return 0

    def recv(self, n):
        try:
            return super(SSLStream, self).recv(n)
        except SSL.WantReadError:
            return (errno.EAGAIN, "")
        except SSL.SysCallError as e:
            return (ovs.socket_util.get_exception_errno(e), "")
        except SSL.ZeroReturnError:
            return (0, "")

    def send(self, buf):
        try:
            if isinstance(buf, six.text_type):
                # Convert to byte stream if the buffer is string type/unicode.
                # pyopenssl version 0.14 expects the buffer to be byte string.
                buf = buf.encode('utf-8')
            return super(SSLStream, self).send(buf)
        except SSL.WantWriteError:
            return -errno.EAGAIN
        except SSL.SysCallError as e:
            return -ovs.socket_util.get_exception_errno(e)


if SSL:
    # Register SSL only if the OpenSSL module is available
    Stream.register_method("ssl", SSLStream)
