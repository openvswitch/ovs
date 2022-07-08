from netaddr import IPAddress
import pytest

from ovs.flow.decoders import decode_ip_port_range


@pytest.mark.parametrize(
    "input_string,expected",
    [
        (
            "192.168.0.0-192.168.0.200:1000-2000",
            {
                "addrs": {
                    "start": IPAddress("192.168.0.0"),
                    "end": IPAddress("192.168.0.200"),
                },
                "ports": {
                    "start": 1000,
                    "end": 2000,
                },
            },
        ),
        (
            "192.168.0.0-192.168.0.200",
            {
                "addrs": {
                    "start": IPAddress("192.168.0.0"),
                    "end": IPAddress("192.168.0.200"),
                },
            },
        ),
        (
            "192.168.0.0-192.168.0.200:2000",
            {
                "addrs": {
                    "start": IPAddress("192.168.0.0"),
                    "end": IPAddress("192.168.0.200"),
                },
                "ports": {
                    "start": 2000,
                    "end": 2000,
                },
            },
        ),
        (
            "192.168.0.1:1000-2000",
            {
                "addrs": {
                    "start": IPAddress("192.168.0.1"),
                    "end": IPAddress("192.168.0.1"),
                },
                "ports": {
                    "start": 1000,
                    "end": 2000,
                },
            },
        ),
        (
            "[fe80:0000:0000:0000:0204:61ff:fe9d:f150]-[fe80:0000:0000:0000:0204:61ff:fe9d:f15f]:255",  # noqa: E501
            {
                "addrs": {
                    "start": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f150"
                    ),
                    "end": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f15f"
                    ),
                },
                "ports": {
                    "start": 255,
                    "end": 255,
                },
            },
        ),
        (
            "[fe80::204:61ff:254.157.241.86]-[fe80::204:61ff:254.157.241.100]:255-300",  # noqa: E501
            {
                "addrs": {
                    "start": IPAddress("fe80::204:61ff:254.157.241.86"),
                    "end": IPAddress("fe80::204:61ff:254.157.241.100"),
                },
                "ports": {
                    "start": 255,
                    "end": 300,
                },
            },
        ),
        (
            "[fe80::f150]-[fe80::f15f]:255-300",
            {
                "addrs": {
                    "start": IPAddress("fe80::f150"),
                    "end": IPAddress("fe80::f15f"),
                },
                "ports": {
                    "start": 255,
                    "end": 300,
                },
            },
        ),
        (
            "fe80:0000:0000:0000:0204:61ff:fe9d:f150-fe80:0000:0000:0000:0204:61ff:fe9d:f15f",  # noqa: E501
            {
                "addrs": {
                    "start": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f150"
                    ),
                    "end": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f15f"
                    ),
                },
            },
        ),
        (
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156",
            {
                "addrs": {
                    "start": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f156"
                    ),
                    "end": IPAddress(
                        "fe80:0000:0000:0000:0204:61ff:fe9d:f156"
                    ),
                },
            },
        ),
    ],
)
def test_decode_ip_port_range(input_string, expected):
    assert expected == decode_ip_port_range(input_string)
