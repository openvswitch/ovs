import contextlib
import ipaddress
import sys
import time
from unittest import mock

import pytest

from ovs import dns_resolve
from ovs import socket_util


skip_no_unbound = pytest.mark.skipif("unbound" not in dns_resolve.__dict__,
                                     reason="Unbound not installed")

HOSTS = [("192.0.2.1", "fake.ip4.domain", "192.0.2.1"),
         ("2001:db8:2::1", "fake.ip6.domain", "2001:db8:2::1"),
         ("192.0.2.2", "fake.both.domain", "192.0.2.2"),
         ("2001:db8:2::2", "fake.both.domain", "192.0.2.2")]


def _tmp_file(path, content):
    path.write_text(content)
    assert content == path.read_text()
    return path


@pytest.fixture(params=[False, True], ids=["not_daemon", "daemon"])
def resolver_factory(monkeypatch, tmp_path, hosts_file, request):
    # Allow delaying the instantiation of the DNSResolver
    def resolver_factory():
        with monkeypatch.context() as m:
            m.setenv("OVS_HOSTS_FILE", str(hosts_file))
            # Test with both is_daemon False and True
            resolver = dns_resolve.init(request.param)
            assert resolver._is_daemon == request.param
            return resolver

    return resolver_factory


@contextlib.contextmanager
def DNSResolver(*args, **kwargs):
    """Clean up after returning a dns_resolver.DNSResolver"""
    resolver = dns_resolve.init(*args, **kwargs)
    try:
        yield resolver
    finally:
        dns_resolve.destroy()
        assert dns_resolve._global_resolver is None


@pytest.fixture
def unbound_conf(tmp_path):
    path = tmp_path / "unbound.conf"
    content = """
    server:
        verbosity: 1
    """
    return _tmp_file(path, content)


@pytest.fixture
def resolv_conf(tmp_path):
    path = tmp_path / "resolv.conf"
    content = "nameserver 127.0.0.1"
    return _tmp_file(path, content)


@pytest.fixture
def hosts_file(tmp_path):
    path = tmp_path / "hosts"
    content = "\n".join(f"{ip}\t{host}" for ip, host, _ in HOSTS)
    return _tmp_file(path, content)


@pytest.fixture
def missing_file(tmp_path):
    f = tmp_path / "missing_file"
    assert not f.exists()
    return f


@pytest.fixture(params=[False, True], ids=["with unbound", "without unbound"])
def missing_unbound(monkeypatch, request):
    if request.param:
        if "unbound" in dns_resolve.__dict__:
            monkeypatch.setitem(sys.modules, 'unbound', None)
            monkeypatch.delitem(dns_resolve.__dict__, "unbound")
    elif "unbound" not in dns_resolve.__dict__:
        pytest.skip("Unbound not installed")
    return request.param


def test_missing_unbound(missing_unbound, resolver_factory):
    resolver = resolver_factory()  # Dont fail even w/o unbound
    assert resolver.dns_enabled == (not missing_unbound)


def test_DNSRequest_defaults():
    req = dns_resolve.DNSRequest(HOSTS[0][1])
    assert HOSTS[0][1] == req.name
    assert req.state == dns_resolve.ReqState.INVALID
    assert req.time == req.result == req.ttl is None
    assert str(req)


def _resolve(resolver, host, fn=dns_resolve.resolve):
    """Handle sync/async lookups, giving up if more than 1 second has passed"""

    timeout = 1
    start = time.time()
    name = fn(host)
    if resolver and resolver._is_daemon:
        while name is None:
            name = fn(host)
            if name:
                break
            time.sleep(0.01)
            end = time.time()
            if end - start > timeout:
                break
    if name:
        return name
    raise LookupError(f"{host} not found")


@pytest.mark.parametrize("ip,host,expected", HOSTS)
def test_resolve_addresses(missing_unbound, resolver_factory, ip, host,
                           expected):
    resolver = resolver_factory()
    if missing_unbound:
        with pytest.raises(LookupError):
            _resolve(resolver, host)
    else:
        result = _resolve(resolver, host)
        assert ipaddress.ip_address(expected) == ipaddress.ip_address(result)


@pytest.mark.parametrize("ip,host,expected", HOSTS)
def test_resolve_without_init(monkeypatch, missing_unbound, ip, host, expected,
                              hosts_file):
    # make sure we don't have a global resolver
    dns_resolve.destroy()
    with monkeypatch.context() as m:
        m.setenv("OVS_HOSTS_FILE", str(hosts_file))
        if missing_unbound:
            with pytest.raises(LookupError):
                _resolve(None, host)
        else:
            res = _resolve(None, host)
            assert dns_resolve._global_resolver is not None
            assert dns_resolve._global_resolver._is_daemon is False
            assert ipaddress.ip_address(expected) == ipaddress.ip_address(res)


def test_resolve_unknown_host(missing_unbound, resolver_factory):
    resolver = resolver_factory()
    with pytest.raises(LookupError):
        _resolve(resolver, "fake.notadomain")


@skip_no_unbound
def test_resolve_process_error():
    with DNSResolver(True) as resolver:
        with mock.patch.object(resolver._ctx, "process", return_value=-1):
            assert resolver.resolve("fake.domain") is None


@skip_no_unbound
def test_resolve_resolve_error():
    with DNSResolver(False) as resolver:
        with mock.patch.object(resolver._ctx, "resolve",
                               return_value=(-1, None)):
            assert resolver.resolve("fake.domain") is None


@skip_no_unbound
def test_resolve_resolve_async_error():
    with DNSResolver(True) as resolver:
        with mock.patch.object(resolver._ctx, "resolve_async",
                               return_value=(-1, None)):
            with pytest.raises(LookupError):
                _resolve(resolver, "fake.domain")


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("unbound_conf", False)])
def test_set_unbound_conf(monkeypatch, missing_unbound, resolver_factory,
                          request, file, raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_UNBOUND_CONF", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_unbound_conf() is None
        return
    with mock.patch.object(resolver._ctx, "config",
                           side_effect=resolver._ctx.config) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_unbound_conf()
        else:
            resolver._set_unbound_conf()
        if file:
            c.assert_called_once_with(file)
        else:
            c.assert_not_called()


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("resolv_conf", False)])
def test_resolv_conf(monkeypatch, missing_unbound, resolver_factory, request,
                     file, raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_RESOLV_CONF", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_resolv_conf() is None
        return
    with mock.patch.object(resolver._ctx, "resolvconf",
                           side_effect=resolver._ctx.resolvconf) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_resolv_conf()
        else:
            resolver._set_resolv_conf()
        c.assert_called_once_with(file)


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("hosts_file", False)])
def test_hosts(monkeypatch, missing_unbound, resolver_factory, request, file,
               raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_HOSTS_FILE", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_hosts_file() is None
        return
    with mock.patch.object(resolver._ctx, "hosts",
                           side_effect=resolver._ctx.hosts) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_hosts_file()
        else:
            resolver._set_hosts_file()
        c.assert_called_once_with(file)


def test_UnboundException(missing_unbound):
    with pytest.raises(dns_resolve.UnboundException):
        raise dns_resolve.UnboundException("Fake exception", -1)


@skip_no_unbound
@pytest.mark.parametrize("ip,host,expected", HOSTS)
def test_inet_parse_active(resolver_factory, ip, host, expected):
    resolver = resolver_factory()

    def fn(name):
        # Return the same thing _resolve() would so we can call
        # this multiple times for the is_daemon=True case
        return socket_util.inet_parse_active(f"{name}:6640", 6640,
                                             raises=False)[0] or None

    # parsing IPs still works
    IP = _resolve(resolver, ip, fn)
    assert ipaddress.ip_address(ip) == ipaddress.ip_address(IP)
    # parsing hosts works
    IP = _resolve(resolver, host, fn)
    assert ipaddress.ip_address(IP) == ipaddress.ip_address(expected)
