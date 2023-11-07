import pytest

from ovs.flow.kv import KVParser, KVDecoders, KeyValue
from ovs.flow.decoders import decode_default

decoders = KVDecoders(default=lambda k, v: (k, decode_default(v)))


@pytest.mark.parametrize(
    "input_data,expected",
    [
        (
            (
                "cookie=0x0, duration=147566.365s, table=0, n_packets=39, n_bytes=2574, idle_age=65534, hard_age=65534",  # noqa: E501
                decoders,
            ),
            [
                KeyValue("cookie", 0),
                KeyValue("duration", "147566.365s"),
                KeyValue("table", 0),
                KeyValue("n_packets", 39),
                KeyValue("n_bytes", 2574),
                KeyValue("idle_age", 65534),
                KeyValue("hard_age", 65534),
            ],
        ),
        (
            (
                "load:0x4->NXM_NX_REG13[],load:0x9->NXM_NX_REG11[],load:0x8->NXM_NX_REG12[],load:0x1->OXM_OF_METADATA[],load:0x1->NXM_NX_REG14[],mod_dl_src:0a:58:a9:fe:00:02,resubmit(,8)",  # noqa: E501
                decoders,
            ),
            [
                KeyValue("load", "0x4->NXM_NX_REG13[]"),
                KeyValue("load", "0x9->NXM_NX_REG11[]"),
                KeyValue("load", "0x8->NXM_NX_REG12[]"),
                KeyValue("load", "0x1->OXM_OF_METADATA[]"),
                KeyValue("load", "0x1->NXM_NX_REG14[]"),
                KeyValue("mod_dl_src", "0a:58:a9:fe:00:02"),
                KeyValue("resubmit", ",8"),
            ],
        ),
        (("l1(l2(l3(l4())))", decoders), [KeyValue("l1", "l2(l3(l4()))")]),
        (
            ("l1(l2(l3(l4()))),foo:bar", decoders),
            [KeyValue("l1", "l2(l3(l4()))"), KeyValue("foo", "bar")],
        ),
        (
            ("enqueue:1:2,output=2", decoders),
            [KeyValue("enqueue", "1:2"), KeyValue("output", 2)],
        ),
        (
            ("value_to_reg(100)->someReg[10],foo:bar", decoders),
            [
                KeyValue("value_to_reg", "(100)->someReg[10]"),
                KeyValue("foo", "bar"),
            ],
        ),
    ],
)
def test_kv_parser(input_data, expected):
    input_string = input_data[0]
    decoders = input_data[1]
    tparser = KVParser(input_string, decoders)
    tparser.parse()
    result = tparser.kv()
    assert len(expected) == len(result)
    for i in range(0, len(result)):
        assert result[i].key == expected[i].key
        assert result[i].value == expected[i].value
        kpos = result[i].meta.kpos
        kstr = result[i].meta.kstring
        vpos = result[i].meta.vpos
        vstr = result[i].meta.vstring
        assert input_string[kpos : kpos + len(kstr)] == kstr
        if vpos != -1:
            assert input_string[vpos : vpos + len(vstr)] == vstr
