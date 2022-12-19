import netaddr
import pytest

from ovs.flow.ofp import OFPFlow
from ovs.flow.kv import KeyValue
from ovs.flow.decoders import EthMask, IPMask, decode_mask


@pytest.mark.parametrize(
    "input_string,expected",
    [
        (
            "actions=local,3,4,5,output:foo",
            [
                KeyValue("output", {"port": "local"}),
                KeyValue("output", {"port": 3}),
                KeyValue("output", {"port": 4}),
                KeyValue("output", {"port": 5}),
                KeyValue("output", {"port": "foo"}),
            ],
        ),
        (
            "actions=controller,controller:200",
            [
                KeyValue("output", "controller"),
                KeyValue("controller", {"max_len": 200}),
            ],
        ),
        (
            "actions=enqueue(foo,42),enqueue:foo:42,enqueue(bar,4242)",
            [
                KeyValue("enqueue", {"port": "foo", "queue": 42}),
                KeyValue("enqueue", {"port": "foo", "queue": 42}),
                KeyValue("enqueue", {"port": "bar", "queue": 4242}),
            ],
        ),
        (
            "actions=bundle(eth_src,0,hrw,ofport,members:4,8)",
            [
                KeyValue(
                    "bundle",
                    {
                        "fields": "eth_src",
                        "basis": 0,
                        "algorithm": "hrw",
                        "members": [4, 8],
                    },
                ),
            ],
        ),
        (
            "actions=bundle_load(eth_src,0,hrw,ofport,reg0,members:4,8)",
            [
                KeyValue(
                    "bundle_load",
                    {
                        "fields": "eth_src",
                        "basis": 0,
                        "algorithm": "hrw",
                        "dst": "reg0",
                        "members": [4, 8],
                    },
                ),
            ],
        ),
        (
            "actions=group:3",
            [KeyValue("group", 3)],
        ),
        (
            "actions=strip_vlan",
            [KeyValue("strip_vlan", True)],
        ),
        (
            "actions=pop_vlan",
            [KeyValue("pop_vlan", True)],
        ),
        (
            "actions=push_vlan:0x8100",
            [KeyValue("push_vlan", 0x8100)],
        ),
        (
            "actions=push_mpls:0x8848",
            [KeyValue("push_mpls", 0x8848)],
        ),
        (
            "actions=pop_mpls:0x8848",
            [KeyValue("pop_mpls", 0x8848)],
        ),
        (
            "actions=pop_mpls:0x8848",
            [KeyValue("pop_mpls", 0x8848)],
        ),
        (
            "actions=encap(nsh(md_type=2,tlv(0x1000,10,0x12345678)))",
            [
                KeyValue(
                    "encap",
                    {
                        "header": "nsh",
                        "props": {
                            "md_type": 2,
                            "tlv": {
                                "class": 0x1000,
                                "type": 10,
                                "value": 0x12345678,
                            },
                        },
                    },
                )
            ],
        ),
        (
            "actions=encap(ethernet)",
            [
                KeyValue(
                    "encap",
                    {"header": "ethernet"},
                )
            ],
        ),
        (
            "actions=encap(mpls)",
            [
                KeyValue(
                    "encap",
                    {"header": "mpls"},
                )
            ],
        ),
        (
            "actions=load:0x001122334455->eth_src",
            [
                KeyValue(
                    "load",
                    {"value": 0x001122334455, "dst": {"field": "eth_src"}},
                )
            ],
        ),
        (
            "actions=load:1->eth_src[1]",
            [
                KeyValue(
                    "load",
                    {
                        "value": 1,
                        "dst": {"field": "eth_src", "start": 1, "end": 1},
                    },
                )
            ],
        ),
        (
            "actions=learn(load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[])",
            [
                KeyValue(
                    "learn",
                    [
                        {
                            "load": {
                                "src": {"field": "NXM_NX_TUN_ID"},
                                "dst": {"field": "NXM_NX_TUN_ID"},
                            }
                        }
                    ],
                ),
            ],
        ),
        (
            "actions=set_field:00:11:22:33:44:55->eth_src",
            [
                KeyValue(
                    "set_field",
                    {
                        "value": {"eth_src": EthMask("00:11:22:33:44:55")},
                        "dst": {"field": "eth_src"},
                    },
                )
            ],
        ),
        (
            "actions=set_field:01:00:00:00:00:00/01:00:00:00:00:00->eth_src",
            [
                KeyValue(
                    "set_field",
                    {
                        "value": {
                            "eth_src": EthMask(
                                "01:00:00:00:00:00/01:00:00:00:00:00"
                            )
                        },
                        "dst": {"field": "eth_src"},
                    },
                )
            ],
        ),
        (
            "actions=set_field:0x10ff->vlan_vid",
            [
                KeyValue(
                    "set_field",
                    {
                        "value": {"vlan_vid": decode_mask(13)("0x10ff")},
                        "dst": {"field": "vlan_vid"},
                    },
                )
            ],
        ),
        (
            "actions=move:reg0[0..5]->reg1[16..31]",
            [
                KeyValue(
                    "move",
                    {
                        "src": {"field": "reg0", "start": 0, "end": 5},
                        "dst": {"field": "reg1", "start": 16, "end": 31},
                    },
                )
            ],
        ),
        (
            "actions=mod_dl_dst:00:11:22:33:44:55",
            [KeyValue("mod_dl_dst", EthMask("00:11:22:33:44:55"))],
        ),
        (
            "actions=mod_nw_dst:192.168.1.1",
            [KeyValue("mod_nw_dst", IPMask("192.168.1.1"))],
        ),
        (
            "actions=mod_nw_dst:fe80::ec17:7bff:fe61:7aac",
            [KeyValue("mod_nw_dst", IPMask("fe80::ec17:7bff:fe61:7aac"))],
        ),
        (
            "actions=dec_ttl,dec_ttl(1,2,3)",
            [KeyValue("dec_ttl", True), KeyValue("dec_ttl", [1, 2, 3])],
        ),
        (
            "actions=set_mpls_label:0x100,set_mpls_tc:2,set_mpls_ttl:10",
            [
                KeyValue("set_mpls_label", 0x100),
                KeyValue("set_mpls_tc", 2),
                KeyValue("set_mpls_ttl", 10),
            ],
        ),
        (
            "actions=check_pkt_larger(100)->reg0[10]",
            [
                KeyValue(
                    "check_pkt_larger",
                    {
                        "pkt_len": 100,
                        "dst": {"field": "reg0", "start": 10, "end": 10},
                    },
                ),
            ],
        ),
        (
            "actions=pop_queue,set_tunnel:0x10,set_tunnel64:0x65000,set_queue=3",  # noqa: E501
            [
                KeyValue("pop_queue", True),
                KeyValue("set_tunnel", 0x10),
                KeyValue("set_tunnel64", 0x65000),
                KeyValue("set_queue", 3),
            ],
        ),
        (
            "actions=ct(zone=10,table=2,nat(snat=192.168.0.0-192.168.0.200:1000-2000,random))",  # noqa: E501
            [
                KeyValue(
                    "ct",
                    {
                        "zone": 10,
                        "table": 2,
                        "nat": {
                            "type": "snat",
                            "addrs": {
                                "start": netaddr.IPAddress("192.168.0.0"),
                                "end": netaddr.IPAddress("192.168.0.200"),
                            },
                            "ports": {
                                "start": 1000,
                                "end": 2000,
                            },
                            "random": True,
                        },
                    },
                )
            ],
        ),
        (
            "actions=ct(commit,zone=NXM_NX_REG13[0..15],table=2,exec(load:0->NXM_NX_CT_LABEL[0]))",  # noqa: E501
            [
                KeyValue(
                    "ct",
                    {
                        "commit": True,
                        "zone": {
                            "field": "NXM_NX_REG13",
                            "start": 0,
                            "end": 15,
                        },
                        "table": 2,
                        "exec": [
                            {
                                "load": {
                                    "value": 0,
                                    "dst": {
                                        "field": "NXM_NX_CT_LABEL",
                                        "start": 0,
                                        "end": 0,
                                    },
                                },
                            },
                        ],
                    },
                )
            ],
        ),
        (
            "actions=load:0x1->NXM_NX_REG10[7],learn(table=69,delete_learned,cookie=0xda6f52b0,OXM_OF_METADATA[],eth_type=0x800,NXM_OF_IP_SRC[],ip_dst=172.30.204.105,nw_proto=6,NXM_OF_TCP_SRC[]=NXM_OF_TCP_DST[],load:0x1->NXM_NX_REG10[7])",  # noqa: E501
            [
                KeyValue(
                    "load",
                    {
                        "value": 1,
                        "dst": {"field": "NXM_NX_REG10", "start": 7, "end": 7},
                    },
                ),
                KeyValue(
                    "learn",
                    [
                        {"table": 69},
                        {"delete_learned": True},
                        {"cookie": 3664728752},
                        {"OXM_OF_METADATA[]": {"field": "OXM_OF_METADATA"}},
                        {"eth_type": 2048},
                        {"NXM_OF_IP_SRC[]": {"field": "NXM_OF_IP_SRC"}},
                        {"ip_dst": IPMask("172.30.204.105/32")},
                        {"nw_proto": 6},
                        {"NXM_OF_TCP_SRC[]": {"field": "NXM_OF_TCP_DST"}},
                        {
                            "load": {
                                "value": 1,
                                "dst": {
                                    "field": "NXM_NX_REG10",
                                    "start": 7,
                                    "end": 7,
                                },
                            }
                        },
                    ],
                ),
            ],
        ),
        (
            "actions=resubmit(,8),resubmit:3,resubmit(1,2,ct)",
            [
                KeyValue("resubmit", {"port": "", "table": 8}),
                KeyValue("resubmit", {"port": 3}),
                KeyValue("resubmit", {"port": 1, "table": 2, "ct": True}),
            ],
        ),
        (
            "actions=clone(ct_clear,load:0->NXM_NX_REG11[],load:0->NXM_NX_REG12[],load:0->NXM_NX_REG13[],load:0x1d->NXM_NX_REG13[],load:0x1f->NXM_NX_REG11[],load:0x1c->NXM_NX_REG12[],load:0x11->OXM_OF_METADATA[],load:0x2->NXM_NX_REG14[],load:0->NXM_NX_REG10[],load:0->NXM_NX_REG15[],load:0->NXM_NX_REG0[],load:0->NXM_NX_REG1[],load:0->NXM_NX_REG2[],load:0->NXM_NX_REG3[],load:0->NXM_NX_REG4[],load:0->NXM_NX_REG5[],load:0->NXM_NX_REG6[],load:0->NXM_NX_REG7[],load:0->NXM_NX_REG8[],load:0->NXM_NX_REG9[],resubmit(,8))",  # noqa: E501
            [
                KeyValue(
                    "clone",
                    [
                        {"ct_clear": True},
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG11"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG12"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG13"},
                            }
                        },
                        {
                            "load": {
                                "value": 29,
                                "dst": {"field": "NXM_NX_REG13"},
                            }
                        },
                        {
                            "load": {
                                "value": 31,
                                "dst": {"field": "NXM_NX_REG11"},
                            }
                        },
                        {
                            "load": {
                                "value": 28,
                                "dst": {"field": "NXM_NX_REG12"},
                            }
                        },
                        {
                            "load": {
                                "value": 17,
                                "dst": {"field": "OXM_OF_METADATA"},
                            }
                        },
                        {
                            "load": {
                                "value": 2,
                                "dst": {"field": "NXM_NX_REG14"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG10"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG15"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG0"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG1"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG2"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG3"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG4"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG5"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG6"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG7"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG8"},
                            }
                        },
                        {
                            "load": {
                                "value": 0,
                                "dst": {"field": "NXM_NX_REG9"},
                            }
                        },
                        {"resubmit": {"port": "", "table": 8}},
                    ],
                )
            ],
        ),
        (
            "actions=conjunction(1234, 1/2),note:00.00.11.22.33.ff,sample(probability=123,collector_set_id=0x123,obs_domain_id=0x123,obs_point_id=0x123,sampling_port=inport0,ingress)",  # noqa: E501
            [
                KeyValue("conjunction", {"id": 1234, "k": 1, "n": 2}),
                KeyValue("note", "00.00.11.22.33.ff"),
                KeyValue(
                    "sample",
                    {
                        "probability": 123,
                        "collector_set_id": 0x123,
                        "obs_domain_id": 0x123,
                        "obs_point_id": 0x123,
                        "sampling_port": "inport0",
                        "ingress": True,
                    },
                ),
            ],
        ),
    ],
)
def test_act(input_string, expected):
    ofp = OFPFlow(input_string)
    actions = ofp.actions_kv
    for i in range(len(expected)):
        assert expected[i].key == actions[i].key
        assert expected[i].value == actions[i].value

        # Assert positions relative to action string are OK.
        apos = ofp.section("actions").pos
        astring = ofp.section("actions").string

        kpos = actions[i].meta.kpos
        kstr = actions[i].meta.kstring
        vpos = actions[i].meta.vpos
        vstr = actions[i].meta.vstring
        assert astring[kpos : kpos + len(kstr)] == kstr
        if vpos != -1:
            assert astring[vpos : vpos + len(vstr)] == vstr

        # Assert astring meta is correct.
        assert input_string[apos : apos + len(astring)] == astring
