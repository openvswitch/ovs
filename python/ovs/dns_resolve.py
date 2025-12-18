# Copyright (c) 2023 Red Hat, Inc.
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

import collections
import enum
import functools
import ipaddress
import os
import time
import typing

try:
    import unbound  # type: ignore
except ImportError:
    pass

import ovs.vlog

vlog = ovs.vlog.Vlog("dns_resolve")

RESOLVE_UNUSED_TIMEOUT = 300  # Seconds.


class ReqState(enum.Enum):
    INVALID = 0
    PENDING = 1
    GOOD_UNUSED = 2
    GOOD = 3
    ERROR = 4


class DNSRequest:
    def __init__(self, name: str):
        self.name: str = name
        self.state: ReqState = ReqState.INVALID
        self.time: typing.Optional[float] = None
        # set by DNSResolver._callback
        self.result: typing.Optional[str] = None
        self.ttl: typing.Optional[float] = None

    @property
    def expired(self):
        ttl = self.ttl
        # When we just sent a request, but didn't look at the response yet,
        # it's not caching, but a "transaction in progress" situation, so we
        # can use the response even with TTL of 0 and more than 1 second
        # passed.  Allow such values to be accessed for at least
        # RESOLVE_UNUSED_TIMEOUT seconds without considering them stale.
        # This is necessary in case of large backoff intervals on connections
        # or if the process is doing some other work not looking at the
        # response for longer than TTL.
        if self.state == ReqState.GOOD_UNUSED:
            ttl = max(ttl, RESOLVE_UNUSED_TIMEOUT)
            # Not a "transaction in progress" anymore, normal caching rules
            # should apply from this point forward.
            self.state = ReqState.GOOD

        return time.time() > self.time + ttl

    @property
    def is_valid(self):
        return (self.state in [ReqState.GOOD_UNUSED, ReqState.GOOD]
                and not self.expired)

    def __str__(self):
        return (f"DNSRequest(name={self.name}, state={self.state}, "
                f"time={self.time}, result={self.result})")


class DefaultReqDict(collections.defaultdict):
    def __init__(self):
        super().__init__(DNSRequest)

    def __missing__(self, key):
        ret = self.default_factory(key)
        self[key] = ret
        return ret


class UnboundException(Exception):
    def __init__(self, message, errno):
        try:
            msg = f"{message}: {unbound.ub_strerror(errno)}"
        except NameError:
            msg = message
        super().__init__(msg)


def dns_enabled(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.dns_enabled:
            return func(self, *args, **kwargs)
        vlog.err("DNS support requires the python unbound library")
    return wrapper


class DNSResolver:
    def __init__(self, is_daemon: bool = False):
        """Create a resolver instance

        If is_daemon is true, set the resolver to handle requests
        asynchronously. The following environment variables are processed:

        OVS_UNBOUND_CONF: The filename for an unbound.conf file
        OVS_RESOLV_CONF: A filename to override the system default resolv.conf
        OVS_HOSTS_FILE: A filename to override the system default hosts file

        In the event that the unbound library is missing or fails to initialize
        DNS lookup support will be disabled and the resolve() method will
        return None.
        """
        self._is_daemon = is_daemon
        try:
            self._ctx = unbound.ub_ctx()
            self.dns_enabled = True
        except Exception:
            # The unbound docs mention that this could thrown an exception
            # but do not specify what exception that is. This can also
            # happen with a missing unbound library.
            self.dns_enabled = False
            vlog.err("Failed to initialize the unbound library")
            return

        # NOTE(twilson) This cache, like the C version, can grow without bound
        # and has no cleanup or aging mechanism. Given our usage patterns, this
        # should not be a problem. But this should not be used to resolve an
        # unbounded list of addresses in a long-running daemon.
        self._requests = DefaultReqDict()

        self._ub_call(self._set_unbound_conf)

        # NOTE(twilson) The C version disables DNS in this case. I didn't do
        # that here since it could still be useful to resolve addresses from
        # /etc/hosts even w/o resolv.conf
        self._ub_call(self._set_resolv_conf)
        self._ub_call(self._set_hosts_file)

        self._ctx.set_async(True)  # Sets threaded behavior for resolve_async()

    def _ub_call(self, fn, *args, **kwargs):
        """Convert UnboundExceptions into vlog warnings"""
        try:
            return fn(*args, **kwargs)
        except UnboundException as e:
            vlog.warn(e)

    @dns_enabled
    def _set_unbound_conf(self):
        ub_cfg = os.getenv("OVS_UNBOUND_CONF")
        if ub_cfg:
            retval = self._ctx.config(ub_cfg)
            if retval != 0:
                raise UnboundException(
                    "Failed to set libunbound context config", retval)

    @dns_enabled
    def _set_resolv_conf(self):
        filename = os.getenv("OVS_RESOLV_CONF")
        # The C lib checks that the file exists and also sets filename to
        # /etc/resolv.conf on non-Windows, but resolvconf already does this.
        retval = self._ctx.resolvconf(filename)
        if retval != 0:
            location = filename or "system default nameserver"
            raise UnboundException(location, retval)

    @dns_enabled
    def _set_hosts_file(self):
        # The C lib doesn't have the ability to set a hosts file, but it is
        # useful to have, especially for writing tests that don't rely on
        # network connectivity. hosts(None) uses /etc/hosts.
        filename = os.getenv("OVS_HOSTS_FILE")
        retval = self._ctx.hosts(filename)
        if retval != 0:
            location = filename or "system default hosts file"
            raise UnboundException(location, retval)

    @dns_enabled
    def _callback(self, req: DNSRequest, err: int, result):
        if err != 0 or (result.qtype == unbound.RR_TYPE_AAAA
                        and not result.havedata):
            req.state = ReqState.ERROR
            vlog.warn(f"{req.name}: failed to resolve")
            return
        if result.qtype == unbound.RR_TYPE_A and not result.havedata:
            self._resolve_async(req, unbound.RR_TYPE_AAAA)
            return
        try:
            ip_str = next(iter(result.data.as_raw_data()))
            ip = ipaddress.ip_address(ip_str)  # test if IP is valid
            # NOTE (twilson) For some reason, accessing result data outside of
            # _callback causes a segfault. So just grab and store what we need.
            req.result = str(ip)
            req.ttl = result.ttl
            req.state = ReqState.GOOD_UNUSED
            req.time = time.time()
        except (ValueError, StopIteration):
            req.state = ReqState.ERROR
            vlog.err(f"{req.name}: failed to resolve")

    @dns_enabled
    def _resolve_sync(self, name: str) -> typing.Optional[str]:
        for qtype in (unbound.RR_TYPE_A, unbound.RR_TYPE_AAAA):
            err, result = self._ctx.resolve(name, qtype)
            if err != 0:
                return None
            if not result.havedata:
                continue
            try:
                ip = ipaddress.ip_address(
                    next(iter(result.data.as_raw_data())))
            except (ValueError, StopIteration):
                return None
            return str(ip)

        return None

    @dns_enabled
    def _resolve_async(self, req: DNSRequest, qtype) -> None:
        err, _ = self._ctx.resolve_async(req.name, req, self._callback,
                                         qtype)
        if err != 0:
            req.state = ReqState.ERROR
            return None

        req.state = ReqState.PENDING
        return None

    @dns_enabled
    def resolve(self, name: str) -> typing.Optional[str]:
        """Resolve a host name to an IP address

        If the resolver is set to handle requests asynchronously, resolve()
        should be recalled until it returns a non-None result. Errors will be
        logged.

        :param name: The host name to resolve
        :returns: The IP address or None on error or not (yet) found
        """
        if not self._is_daemon:
            return self._resolve_sync(name)
        retval = self._ctx.process()
        if retval != 0:
            vlog.err(f"dns-resolve error: {unbound.ub_strerror(retval)}")
            return None
        req = self._requests[name]  # Creates a DNSRequest if not found
        if req.is_valid:
            return req.result
        elif req.state != ReqState.PENDING:
            self._resolve_async(req, unbound.RR_TYPE_A)
        return None


_global_resolver: typing.Optional[DNSResolver] = None


def init(is_daemon: bool = False) -> DNSResolver:
    """Initialize a global DNSResolver

    See DNSResolver.__init__ for more details
    """
    global _global_resolver
    _global_resolver = DNSResolver(is_daemon)
    return _global_resolver


def resolve(name: str) -> typing.Optional[str]:
    """Resolve a host name to an IP address

    If a DNSResolver instance has not been instantiated, or if it has been
    created with is_daemon=False, resolve() will synchronously resolve the
    hostname. If DNSResolver has been initialized with is_daemon=True, it
    will instead resolve asynchornously and resolve() will return None until
    the hostname has been resolved.

    :param name: The host name to resolve
    :returns: The IP address or None on error or not (yet) found
    """
    if _global_resolver is None:
        init()

    # mypy doesn't understand that init() sets _global_resolver, so ignore type
    return _global_resolver.resolve(name)  # type: ignore


def destroy():
    """Destroy the global DNSResolver

    This destroys the global DNSResolver instance and any outstanding
    asynchronouse requests.
    """
    global _global_resolver
    del _global_resolver
    _global_resolver = None  # noqa: F841
