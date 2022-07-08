import pytest

from ovs.flow.filter import OFFilter
from ovs.flow.ofp import OFPFlow
from ovs.flow.odp import ODPFlow


@pytest.mark.parametrize(
    "expr,flow,expected,match",
    [
        (
            "nw_src=192.168.1.1 && tcp_dst=80",
            OFPFlow(
                "nw_src=192.168.1.1,tcp_dst=80 actions=drop"
            ),
            True,
            ["nw_src", "tcp_dst"],
        ),
        (
            "nw_src=192.168.1.2 || tcp_dst=80",
            OFPFlow(
                "nw_src=192.168.1.1,tcp_dst=80 actions=drop"
            ),
            True,
            ["nw_src", "tcp_dst"],
        ),
        (
            "nw_src=192.168.1.1 || tcp_dst=90",
            OFPFlow(
                "nw_src=192.168.1.1,tcp_dst=80 actions=drop"
            ),
            True,
            ["nw_src", "tcp_dst"],
        ),
        (
            "nw_src=192.168.1.2 && tcp_dst=90",
            OFPFlow(
                "nw_src=192.168.1.1,tcp_dst=80 actions=drop"
            ),
            False,
            ["nw_src", "tcp_dst"],
        ),
        (
            "nw_src=192.168.1.1",
            OFPFlow(
                "nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"
            ),
            False,
            ["nw_src"],
        ),
        (
            "nw_src~=192.168.1.1",
            OFPFlow(
                "nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"
            ),
            True,
            ["nw_src"],
        ),
        (
            "nw_src~=192.168.1.1/30",
            OFPFlow(
                "nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"
            ),
            True,
            ["nw_src"],
        ),
        (
            "nw_src~=192.168.1.0/16",
            OFPFlow(
                "nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"
            ),
            False,
            ["nw_src"],
        ),
        (
            "nw_src~=192.168.1.0/16",
            OFPFlow(
                "nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"
            ),
            False,
            ["nw_src"],
        ),
        (
            "n_bytes=100",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            True,
            ["n_bytes"],
        ),
        (
            "n_bytes>10",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            True,
            ["n_bytes"],
        ),
        (
            "n_bytes>100",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            False,
            ["n_bytes"],
        ),
        (
            "n_bytes<100",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            False,
            ["n_bytes"],
        ),
        (
            "n_bytes<1000",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            True,
            ["n_bytes"],
        ),
        (
            "n_bytes>0 && drop=true",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=drop"  # noqa: E501
            ),
            True,
            ["n_bytes", "drop"],
        ),
        (
            "n_bytes>0 && drop=true",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=2"  # noqa: E501
            ),
            False,
            ["n_bytes"],
        ),
        (
            "n_bytes>10 && !output.port=3",
            OFPFlow(
                "n_bytes=100 priority=100,nw_src=192.168.1.0/24,tcp_dst=80 actions=2"  # noqa: E501
            ),
            True,
            ["n_bytes", "output"],
        ),
        (
            "dl_src=00:11:22:33:44:55",
            OFPFlow(
                "n_bytes=100 priority=100,dl_src=00:11:22:33:44:55,nw_src=192.168.1.0/24,tcp_dst=80 actions=2"   # noqa: E501
            ),
            True,
            ["dl_src"],
        ),
        (
            "dl_src~=00:11:22:33:44:55",
            OFPFlow(
                "n_bytes=100 priority=100,dl_src=00:11:22:33:44:55/ff:ff:ff:ff:ff:00,nw_src=192.168.1.0/24,tcp_dst=80 actions=2"  # noqa: E501
            ),
            True,
            ["dl_src"],
        ),
        (
            "dl_src~=00:11:22:33:44:66",
            OFPFlow(
                "n_bytes=100 priority=100,dl_src=00:11:22:33:44:55/ff:ff:ff:ff:ff:00,nw_src=192.168.1.0/24,tcp_dst=80 actions=2"  # noqa: E501
            ),
            True,
            ["dl_src"],
        ),
        (
            "dl_src~=00:11:22:33:44:66 && tp_dst=1000",
            OFPFlow(
                "n_bytes=100 priority=100,dl_src=00:11:22:33:44:55/ff:ff:ff:ff:ff:00,nw_src=192.168.1.0/24,tp_dst=0x03e8/0xfff8 actions=2"  # noqa: E501
            ),
            False,
            ["dl_src", "tp_dst"],
        ),
        (
            "dl_src~=00:11:22:33:44:66 && tp_dst~=1000",
            OFPFlow(
                "n_bytes=100 priority=100,dl_src=00:11:22:33:44:55/ff:ff:ff:ff:ff:00,nw_src=192.168.1.0/24,tp_dst=0x03e8/0xfff8 actions=2"  # noqa: E501
            ),
            True,
            ["dl_src", "tp_dst"],
        ),
        (
            "encap",
            ODPFlow(
                "encap(eth_type(0x0800),ipv4(src=10.76.23.240/255.255.255.248,dst=10.76.23.106,proto=17,tos=0/0,ttl=64,frag=no)) actions:drop"  # noqa: E501
            ),
            True,
            ["encap"],
        ),
        (
            "encap.ipv4.src=10.76.23.240",
            ODPFlow(
                "encap(eth_type(0x0800),ipv4(src=10.76.23.240/255.255.255.248,dst=10.76.23.106,proto=17,tos=0/0,ttl=64,frag=no)) actions:drop"  # noqa: E501
            ),
            False,
            ["encap"],
        ),
        (
            "encap.ipv4.src~=10.76.23.240",
            ODPFlow(
                "encap(eth_type(0x0800),ipv4(src=10.76.23.240/255.255.255.248,dst=10.76.23.106,proto=17,tos=0/0,ttl=64,frag=no)) actions:drop"  # noqa: E501
            ),
            True,
            ["encap"],
        ),
    ],
)
def test_filter(expr, flow, expected, match):
    ffilter = OFFilter(expr)
    result = ffilter.evaluate(flow)
    if expected:
        assert result
    else:
        assert not result

    assert [kv.key for kv in result.kv] == match
