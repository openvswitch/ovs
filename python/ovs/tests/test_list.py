import pytest

from ovs.flow.list import ListParser, ListDecoders
from ovs.flow.kv import KeyValue


@pytest.mark.parametrize(
    "input_data,expected",
    [
        (
            ("field1,field2,3,nested:value", None, [","]),
            [
                KeyValue("elem_0", "field1"),
                KeyValue("elem_1", "field2"),
                KeyValue("elem_2", 3),
                KeyValue("elem_3", "nested:value"),
            ],
        ),
        (
            (
                "field1,field2,3,nested:value",
                ListDecoders(
                    [
                        ("key1", str),
                        ("key2", str),
                        ("key3", int),
                        ("key4", lambda x: x.split(":"), [","]),
                    ]
                ),
                [","],
            ),
            [
                KeyValue("key1", "field1"),
                KeyValue("key2", "field2"),
                KeyValue("key3", 3),
                KeyValue("key4", ["nested", "value"]),
            ],
        ),
        (
            ("field1:field2:3", None, [":"]),
            [
                KeyValue("elem_0", "field1"),
                KeyValue("elem_1", "field2"),
                KeyValue("elem_2", 3),
            ],
        ),
    ],
)
def test_kv_parser(input_data, expected):
    input_string = input_data[0]
    decoders = input_data[1]
    delims = input_data[2]
    tparser = ListParser(input_string, decoders, delims)
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
