"""Defines decoders for OpenFlow actions.
"""
from ovs.flow.decoders import (
    decode_default,
    decode_time,
    decode_flag,
    decode_int,
)
from ovs.flow.kv import (
    nested_kv_decoder,
    KVDecoders,
    KeyValue,
    KVParser,
    ParseError,
)
from ovs.flow.list import nested_list_decoder, ListDecoders
from ovs.flow.ofp_fields import field_decoders, field_aliases


def decode_output(value):
    """Decodes the output value.

    Does not support field specification.
    """
    if len(value.split(",")) > 1:
        return nested_kv_decoder(
            KVDecoders({"port": decode_default, "max_len": decode_int})
        )(value)
    try:
        return {"port": int(value)}
    except ValueError:
        return {"port": value.strip('"')}


def decode_controller(value):
    """Decodes the controller action."""
    if not value:
        return KeyValue("output", "controller")
    else:
        # Try controller:max_len
        try:
            max_len = int(value)
            return {
                "max_len": max_len,
            }
        except ValueError:
            pass
        # controller(key[=val], ...)
        return nested_kv_decoder(
            KVDecoders(
                {
                    "max_len": decode_int,
                    "reason": decode_default,
                    "id": decode_int,
                    "userdata": decode_default,
                    "pause": decode_flag,
                }
            )
        )(value)


def decode_bundle_load(value):
    return decode_bundle(value, True)


def decode_bundle(value, load=False):
    """Decode bundle action."""
    result = {}
    keys = ["fields", "basis", "algorithm", "ofport"]
    if load:
        keys.append("dst")

    for key in keys:
        parts = value.partition(",")
        nvalue = parts[0]
        value = parts[2]
        if key == "ofport":
            continue
        result[key] = decode_default(nvalue)

    # Handle members:
    mvalues = value.split("members:")
    result["members"] = [int(port) for port in mvalues[1].split(",")]
    return result


def decode_encap(value):
    """Decodes encap action. Examples:
    encap(ethernet)
    encap(nsh(md_type=2,tlv(0x1000,10,0x12345678)))

    The generated dict has the following keys: "header", "props", e.g:
        {
            "header": "ethernet",
        }
        {
            "header": "nsh",
            "props": {
                "md_type": 2,
                "tlv": {
                    "class": 0x100,
                    "type": 10,
                    "value": 0x123456
                }
            }
        }
    """

    def free_hdr_decoder(free_val):
        if free_val not in ["ethernet", "mpls", "mpls_mc", "nsh"]:
            raise ValueError(
                "Malformed encap action. Unkown header: {}".format(free_val)
            )
        return "header", free_val

    parser = KVParser(
        value,
        KVDecoders(
            {
                "nsh": nested_kv_decoder(
                    KVDecoders(
                        {
                            "md_type": decode_default,
                            "tlv": nested_list_decoder(
                                ListDecoders(
                                    [
                                        ("class", decode_int),
                                        ("type", decode_int),
                                        ("value", decode_int),
                                    ]
                                )
                            ),
                        }
                    )
                ),
            },
            default_free=free_hdr_decoder,
        ),
    )
    parser.parse()
    if len(parser.kv()) > 1:
        raise ValueError("Malformed encap action: {}".format(value))

    result = {}
    if parser.kv()[0].key == "header":
        result["header"] = parser.kv()[0].value
    elif parser.kv()[0].key == "nsh":
        result["header"] = "nsh"
        result["props"] = parser.kv()[0].value

    return result


def decode_field(value):
    """Decodes a field as defined in the 'Field Specification' of the actions
    man page:
    http://www.openvswitch.org/support/dist-docs/ovs-actions.7.txt."""
    parts = value.strip("]\n\r").split("[")
    if (
        parts[0] not in field_decoders.keys()
        and parts[0] not in field_aliases.keys()
    ):
        raise ParseError("Field not supported: {}".format(parts[0]))

    result = {
        "field": parts[0],
    }

    if len(parts) > 1 and parts[1]:
        field_range = parts[1].split("..")
        start = field_range[0]
        end = field_range[1] if len(field_range) > 1 else start
        if start:
            result["start"] = int(start)
        if end:
            result["end"] = int(end)

    return result


def decode_load_field(value):
    """Decodes LOAD actions such as: 'load:value->dst'."""
    parts = value.split("->")
    if len(parts) != 2:
        raise ValueError("Malformed load action : %s" % value)

    # If the load action is performed within a learn() action,
    # The value can be specified as another field.
    try:
        return {"value": int(parts[0], 0), "dst": decode_field(parts[1])}
    except ValueError:
        return {"src": decode_field(parts[0]), "dst": decode_field(parts[1])}


def decode_set_field(field_decoders, value):
    """Decodes SET_FIELD actions such as: 'set_field:value/mask->dst'.

    The value is decoded by field_decoders which is a KVDecoders instance.
    Args:
        field_decoders(KVDecoders): The KVDecoders to be used to decode the
            field.
    """
    parts = value.split("->")
    if len(parts) != 2:
        raise ValueError("Malformed set_field action : %s" % value)

    val = parts[0]
    dst = parts[1]

    val_result = field_decoders.decode(dst, val)

    return {
        "value": {val_result[0]: val_result[1]},
        "dst": decode_field(dst),
    }


def decode_move_field(value):
    """Decodes MOVE actions such as 'move:src->dst'."""
    parts = value.split("->")
    if len(parts) != 2:
        raise ValueError("Malformed move action : %s" % value)

    return {
        "src": decode_field(parts[0]),
        "dst": decode_field(parts[1]),
    }


def decode_dec_ttl(value):
    """Decodes dec_ttl and dec_ttl(id, id[2], ...) actions."""
    if not value:
        return True
    return [int(idx) for idx in value.split(",")]


def decode_chk_pkt_larger(value):
    """Decodes 'check_pkt_larger(pkt_len)->dst' actions."""
    parts = value.split("->")
    if len(parts) != 2:
        raise ValueError("Malformed check_pkt_larger action : %s" % value)

    pkt_len = int(parts[0].strip("()"))
    dst = decode_field(parts[1])
    return {"pkt_len": pkt_len, "dst": dst}


# CT decoders
def decode_zone(value):
    """Decodes the value of the 'zone' keyword (part of the ct action)."""
    try:
        return int(value, 0)
    except ValueError:
        pass
    return decode_field(value)


def decode_learn(action_decoders):
    """Create the decoder to be used to decode the 'learn' action.

    The learn action has two added complexities:
    1) It can hold any valid action key-value. Therefore we must take
    the precalculated action_decoders and use them. That's why we require
    them as argument.

    2) The way fields can be specified is augmented. Not only we have
    'field=value', but we also have:
        - 'field=_src_' (where _src_ is another field name)
        - and just 'field'
    For this we need to create a wrapper of field_decoders that, for each
    "field=X" key-value we check if X is a field_name or if it's actually
    a value that we need to send to the appropriate field_decoder to
    process.

    Args:
        action_decoders (dict): Dictionary of decoders to be used in nested
            action decoding.
    """

    def learn_field_decoding_kv(key, value):
        """Decodes a key, value pair from the learn action.
        The key must be a decodable field. The value can be either a value
        in the format defined for the field or another field.
        """
        key_field = decode_field(key)
        try:
            return key, decode_field(value)
        except ParseError:
            return key, field_decoders.get(key_field.get("field"))(value)

    def learn_field_decoding_free(key):
        """Decodes the free fields found in the learn action.
        Free fields indicate that the filed is to be copied from the original.
        In order to express that in a dictionary, return the fieldspec as
        value. So, the free fild NXM_OF_IP_SRC[], is encoded as:
            "NXM_OF_IP_SRC[]": {
                "field": "NXM_OF_IP_SRC"
            }
        That way we also ensure the actual free key is correct.
        """
        key_field = decode_field(key)
        return key, key_field

    learn_decoders = {
        **action_decoders,
        "idle_timeout": decode_time,
        "hard_timeout": decode_time,
        "fin_idle_timeout": decode_time,
        "fin_hard_timeout": decode_time,
        "priority": decode_int,
        "cookie": decode_int,
        "send_flow_rem": decode_flag,
        "table": decode_int,
        "delete_learned": decode_flag,
        "limit": decode_int,
        "result_dst": decode_field,
    }

    learn_decoder = KVDecoders(
        learn_decoders,
        default=learn_field_decoding_kv,
        default_free=learn_field_decoding_free,
    )

    return nested_kv_decoder(learn_decoder, is_list=True)
