# Copyright (c) 2010, 2012, 2014, 2015 Nicira, Inc.
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
import os.path
import random
import select
import socket
import sys

import ovs.fatal_signal
import ovs.poller
import ovs.vlog

vlog = ovs.vlog.Vlog("socket_util")


def make_short_name(long_name):
    if long_name is None:
        return None
    long_name = os.path.abspath(long_name)
    long_dirname = os.path.dirname(long_name)
    tmpdir = os.getenv('TMPDIR', '/tmp')
    for x in xrange(0, 1000):
        link_name = \
            '%s/ovs-un-py-%d-%d' % (tmpdir, random.randint(0, 10000), x)
        try:
            os.symlink(long_dirname, link_name)
            ovs.fatal_signal.add_file_to_unlink(link_name)
            return os.path.join(link_name, os.path.basename(long_name))
        except OSError, e:
            if e.errno != errno.EEXIST:
                break
    raise Exception("Failed to create temporary symlink")


def free_short_name(short_name):
    if short_name is None:
        return
    link_name = os.path.dirname(short_name)
    ovs.fatal_signal.unlink_file_now(link_name)


def make_unix_socket(style, nonblock, bind_path, connect_path, short=False):
    """Creates a Unix domain socket in the given 'style' (either
    socket.SOCK_DGRAM or socket.SOCK_STREAM) that is bound to 'bind_path' (if
    'bind_path' is not None) and connected to 'connect_path' (if 'connect_path'
    is not None).  If 'nonblock' is true, the socket is made non-blocking.

    Returns (error, socket): on success 'error' is 0 and 'socket' is a new
    socket object, on failure 'error' is a positive errno value and 'socket' is
    None."""

    try:
        sock = socket.socket(socket.AF_UNIX, style)
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        if nonblock:
            set_nonblocking(sock)
        if bind_path is not None:
            # Delete bind_path but ignore ENOENT.
            try:
                os.unlink(bind_path)
            except OSError, e:
                if e.errno != errno.ENOENT:
                    return e.errno, None

            ovs.fatal_signal.add_file_to_unlink(bind_path)
            sock.bind(bind_path)

            try:
                if sys.hexversion >= 0x02060000:
                    os.fchmod(sock.fileno(), 0700)
                else:
                    os.chmod("/dev/fd/%d" % sock.fileno(), 0700)
            except OSError, e:
                pass
        if connect_path is not None:
            try:
                sock.connect(connect_path)
            except socket.error, e:
                if get_exception_errno(e) != errno.EINPROGRESS:
                    raise
        return 0, sock
    except socket.error, e:
        sock.close()
        if (bind_path is not None and
            os.path.exists(bind_path)):
            ovs.fatal_signal.unlink_file_now(bind_path)
        eno = ovs.socket_util.get_exception_errno(e)
        if (eno == "AF_UNIX path too long" and
            os.uname()[0] == "Linux"):
            short_connect_path = None
            short_bind_path = None
            connect_dirfd = None
            bind_dirfd = None
            # Try workaround using /proc/self/fd
            if connect_path is not None:
                dirname = os.path.dirname(connect_path)
                basename = os.path.basename(connect_path)
                try:
                    connect_dirfd = os.open(dirname, os.O_DIRECTORY | os.O_RDONLY)
                except OSError, err:
                    return get_exception_errno(err), None
                short_connect_path = "/proc/self/fd/%d/%s" % (connect_dirfd, basename)

            if bind_path is not None:
                dirname = os.path.dirname(bind_path)
                basename = os.path.basename(bind_path)
                try:
                    bind_dirfd = os.open(dirname, os.O_DIRECTORY | os.O_RDONLY)
                except OSError, err:
                    return get_exception_errno(err), None
                short_bind_path = "/proc/self/fd/%d/%s" % (bind_dirfd, basename)

            try:
                return make_unix_socket(style, nonblock, short_bind_path, short_connect_path)
            finally:
                if connect_dirfd is not None:
                    os.close(connect_dirfd)
                if bind_dirfd is not None:
                    os.close(bind_dirfd)
        elif (eno == "AF_UNIX path too long"):
            if short:
                return get_exception_errno(e), None
            short_bind_path = None
            try:
                short_bind_path = make_short_name(bind_path)
                short_connect_path = make_short_name(connect_path)
            except:
                free_short_name(short_bind_path)
                return errno.ENAMETOOLONG, None
            try:
                return make_unix_socket(style, nonblock, short_bind_path,
                                        short_connect_path, short=True)
            finally:
                free_short_name(short_bind_path)
                free_short_name(short_connect_path)
        else:
            return get_exception_errno(e), None


def check_connection_completion(sock):
    p = ovs.poller.SelectPoll()
    p.register(sock, ovs.poller.POLLOUT)
    pfds = p.poll(0)
    if len(pfds) == 1:
        revents = pfds[0][1]
        if revents & ovs.poller.POLLERR:
            try:
                # The following should raise an exception.
                socket.send("\0", socket.MSG_DONTWAIT)

                # (Here's where we end up if it didn't.)
                # XXX rate-limit
                vlog.err("poll return POLLERR but send succeeded")
                return errno.EPROTO
            except socket.error, e:
                return get_exception_errno(e)
        else:
            return 0
    else:
        return errno.EAGAIN


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
    except socket.error:
        return False

    return True


def inet_parse_active(target, default_port):
    address = target.split(":")
    if len(address) >= 2:
        host_name = ":".join(address[0:-1]).lstrip('[').rstrip(']')
        port = int(address[-1])
    else:
        if default_port:
            port = default_port
        else:
            raise ValueError("%s: port number must be specified" % target)
        host_name = address[0]
    if not host_name:
        raise ValueError("%s: bad peer name format" % target)
    return (host_name, port)


def inet_open_active(style, target, default_port, dscp):
    address = inet_parse_active(target, default_port)
    try:
        is_addr_inet = is_valid_ipv4_address(address[0])
        if is_addr_inet:
            sock = socket.socket(socket.AF_INET, style, 0)
            family = socket.AF_INET
        else:
            sock = socket.socket(socket.AF_INET6, style, 0)
            family = socket.AF_INET6
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        set_nonblocking(sock)
        set_dscp(sock, family, dscp)
        try:
            sock.connect(address)
        except socket.error, e:
            if get_exception_errno(e) != errno.EINPROGRESS:
                raise
        return 0, sock
    except socket.error, e:
        sock.close()
        return get_exception_errno(e), None


def get_exception_errno(e):
    """A lot of methods on Python socket objects raise socket.error, but that
    exception is documented as having two completely different forms of
    arguments: either a string or a (errno, string) tuple.  We only want the
    errno."""
    if type(e.args) == tuple:
        return e.args[0]
    else:
        return errno.EPROTO


null_fd = -1


def get_null_fd():
    """Returns a readable and writable fd for /dev/null, if successful,
    otherwise a negative errno value.  The caller must not close the returned
    fd (because the same fd will be handed out to subsequent callers)."""
    global null_fd
    if null_fd < 0:
        try:
            null_fd = os.open("/dev/null", os.O_RDWR)
        except OSError, e:
            vlog.err("could not open /dev/null: %s" % os.strerror(e.errno))
            return -e.errno
    return null_fd


def write_fully(fd, buf):
    """Returns an (error, bytes_written) tuple where 'error' is 0 on success,
    otherwise a positive errno value, and 'bytes_written' is the number of
    bytes that were written before the error occurred.  'error' is 0 if and
    only if 'bytes_written' is len(buf)."""
    bytes_written = 0
    if len(buf) == 0:
        return 0, 0
    while True:
        try:
            retval = os.write(fd, buf)
            assert retval >= 0
            if retval == len(buf):
                return 0, bytes_written + len(buf)
            elif retval == 0:
                vlog.warn("write returned 0")
                return errno.EPROTO, bytes_written
            else:
                bytes_written += retval
                buf = buf[:retval]
        except OSError, e:
            return e.errno, bytes_written


def set_nonblocking(sock):
    try:
        sock.setblocking(0)
    except socket.error, e:
        vlog.err("could not set nonblocking mode on socket: %s"
                 % os.strerror(get_exception_errno(e)))


def set_dscp(sock, family, dscp):
    if dscp > 63:
        raise ValueError("Invalid dscp %d" % dscp)

    val = dscp << 2
    if family == socket.AF_INET:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, val)
        except socket.error, e:
            raise
    elif family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, val)
        except socket.error, e:
            raise
    else:
        raise
