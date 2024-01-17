""" Defines an Open vSwitch Datapath Flow.
"""
import re
from functools import partial

from ovs.flow.flow import Flow, Section

from ovs.flow.kv import (
    KVParser,
    KVDecoders,
    nested_kv_decoder,
    decode_nested_kv,
)
from ovs.flow.decoders import (
    decode_default,
    decode_time,
    decode_int,
    decode_mask,
    Mask8,
    Mask16,
    Mask32,
    Mask64,
    Mask128,
    IPMask,
    EthMask,
    decode_free_output,
    decode_flag,
    decode_nat,
)


class ODPFlow(Flow):
    """ODPFLow represents a Open vSwitch Datapath flow.

    Attributes:
        ufid: The UFID section with only one key-value, with keyword "ufid".
        info: The info section.
        match: The match section.
        actions: The actions section.
        id: The id object given at construction time.

    """

    """
    These class variables are used to cache the KVDecoders instances. This
    will speed up subsequent flow parsings.
    """
    _info_decoders = None
    _match_decoders = None
    _action_decoders = None

    @staticmethod
    def info_decoders():
        """Return the KVDecoders instance to parse the info section.

        Uses the cached version if available.
        """
        if not ODPFlow._info_decoders:
            ODPFlow._info_decoders = ODPFlow._gen_info_decoders()
        return ODPFlow._info_decoders

    @staticmethod
    def match_decoders():
        """Return the KVDecoders instance to parse the match section.

        Uses the cached version if available.
        """
        if not ODPFlow._match_decoders:
            ODPFlow._match_decoders = ODPFlow._gen_match_decoders()
        return ODPFlow._match_decoders

    @staticmethod
    def action_decoders():
        """Return the KVDecoders instance to parse the actions section.

        Uses the cached version if available.
        """
        if not ODPFlow._action_decoders:
            ODPFlow._action_decoders = ODPFlow._gen_action_decoders()
        return ODPFlow._action_decoders

    def __init__(self, odp_string, id=None):
        """Parse a odp flow string.

        The string is expected to have the following format:
             [ufid], [match] [flow data] actions:[actions]

        Args:
            odp_string (str): A datapath flow string.

        Returns:
            A ODPFlow instance.
        """
        sections = []

        # If UFID present, parse it and add it to it's own section.
        ufid_pos = odp_string.find("ufid:")
        if ufid_pos >= 0:
            ufid_string = odp_string[
                ufid_pos : (odp_string[ufid_pos:].find(",") + 1)
            ]
            ufid_parser = KVParser(
                ufid_string, KVDecoders({"ufid": decode_default})
            )
            ufid_parser.parse()
            if len(ufid_parser.kv()) != 1:
                raise ValueError("malformed odp flow: %s" % odp_string)
            sections.append(
                Section("ufid", ufid_pos, ufid_string, ufid_parser.kv())
            )

        action_pos = odp_string.find("actions:")
        if action_pos < 0:
            raise ValueError("malformed odp flow: %s" % odp_string)

        # rest of the string is between ufid and actions
        rest = odp_string[
            (ufid_pos + len(ufid_string) if ufid_pos >= 0 else 0) : action_pos
        ]

        action_pos += 8  # len("actions:")
        actions = odp_string[action_pos:]

        field_parts = rest.lstrip(" ").partition(" ")

        if len(field_parts) != 3:
            raise ValueError("malformed odp flow: %s" % odp_string)

        match = field_parts[0]
        info = field_parts[2]

        iparser = KVParser(info, ODPFlow.info_decoders())
        iparser.parse()
        isection = Section(
            name="info",
            pos=odp_string.find(info),
            string=info,
            data=iparser.kv(),
        )
        sections.append(isection)

        mparser = KVParser(match, ODPFlow.match_decoders())
        mparser.parse()
        msection = Section(
            name="match",
            pos=odp_string.find(match),
            string=match,
            data=mparser.kv(),
        )
        sections.append(msection)

        aparser = KVParser(actions, ODPFlow.action_decoders())
        aparser.parse()
        asection = Section(
            name="actions",
            pos=action_pos,
            string=actions,
            data=aparser.kv(),
            is_list=True,
        )
        sections.append(asection)

        super(ODPFlow, self).__init__(sections, odp_string, id)

    def __str__(self):
        if self._orig:
            return self._orig
        else:
            return self.to_string()

    def to_string(self):
        """Return a text representation of the flow."""
        string = "ufid: {}".format(self.ufid) if self.ufid else ""
        string += "Info: {} | ".format(self.info)
        string += "Match : {} | ".format(self.match)
        string += "Actions: {}".format(self.actions)
        return string

    @staticmethod
    def _gen_info_decoders():
        """Generate the info KVDecoders."""
        return KVDecoders(ODPFlow._info_decoders_args())

    @staticmethod
    def _info_decoders_args():
        """Generate the decoder args for the info KVDecoders."""
        return {
            "packets": decode_int,
            "bytes": decode_int,
            "used": decode_time,
            "flags": decode_default,
            "dp": decode_default,
        }

    @staticmethod
    def _gen_action_decoders():
        """Generate the action KVDecoders."""
        return KVDecoders(
            ODPFlow._action_decoders_args(), default_free=decode_free_output
        )

    @staticmethod
    def _action_decoders_args():
        """Generate the arguments for the action KVDecoders."""
        _decoders = {
            "drop": decode_flag,
            "meter": decode_int,
            "lb_output": decode_int,
            "trunc": decode_int,
            "recirc": decode_int,
            "userspace": nested_kv_decoder(
                KVDecoders(
                    {
                        "pid": decode_int,
                        "sFlow": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "vid": decode_int,
                                    "pcp": decode_int,
                                    "output": decode_int,
                                }
                            )
                        ),
                        "slow_path": decode_default,
                        "flow_sample": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "probability": decode_int,
                                    "collector_set_id": decode_int,
                                    "obs_domain_id": decode_int,
                                    "obs_point_id": decode_int,
                                    "output_port": decode_default,
                                    "ingress": decode_flag,
                                    "egress": decode_flag,
                                }
                            )
                        ),
                        "ipfix": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "output_port": decode_default,
                                }
                            )
                        ),
                        "controller": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "reason": decode_int,
                                    "dont_send": decode_int,
                                    "continuation": decode_int,
                                    "recirc_id": decode_int,
                                    "rule_cookie": decode_int,
                                    "controller_id": decode_int,
                                    "max_len": decode_int,
                                }
                            )
                        ),
                        "userdata": decode_default,
                        "actions": decode_flag,
                        "tunnel_out_port": decode_default,
                        "push_eth": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "src": EthMask,
                                    "dst": EthMask,
                                    "type": decode_int,
                                }
                            )
                        ),
                        "pop_eth": decode_flag,
                    }
                )
            ),
            "set": nested_kv_decoder(
                KVDecoders(ODPFlow._field_decoders_args())
            ),
            "push_vlan": nested_kv_decoder(
                KVDecoders(
                    {
                        "vid": decode_int,
                        "pcp": decode_int,
                        "cfi": decode_int,
                        "tpid": decode_int,
                    }
                )
            ),
            "pop_vlan": decode_flag,
            "push_nsh": nested_kv_decoder(
                KVDecoders(
                    {
                        "flags": decode_int,
                        "ttl": decode_int,
                        "mdtype": decode_int,
                        "np": decode_int,
                        "spi": decode_int,
                        "si": decode_int,
                        "c1": decode_int,
                        "c2": decode_int,
                        "c3": decode_int,
                        "c4": decode_int,
                        "md2": decode_int,
                    }
                )
            ),
            "pop_nsh": decode_flag,
            "tnl_pop": decode_int,
            "pop_mpls": KVDecoders({"eth_type": decode_int}),
            **dict.fromkeys(
                ["push_mpls", "add_mpls"],
                nested_kv_decoder(
                    KVDecoders(
                        {
                            "label": decode_int,
                            "tc": decode_int,
                            "ttl": decode_int,
                            "bos": decode_int,
                            "eth_type": decode_int,
                        }
                    )
                ),
            ),
            "ct_clear": decode_flag,
            "ct": nested_kv_decoder(
                KVDecoders(
                    {
                        "commit": decode_flag,
                        "force_commit": decode_flag,
                        "zone": decode_int,
                        "mark": Mask32,
                        "label": Mask128,
                        "helper": decode_default,
                        "timeout": decode_default,
                        "nat": decode_nat,
                    }
                )
            ),
            **ODPFlow._tnl_action_decoder_args(),
            "hash": nested_kv_decoder(
                KVDecoders(
                    {
                        "l4": decode_int,
                        "sym_l4": decode_int,
                    }
                )
            ),
        }

        _decoders["sample"] = nested_kv_decoder(
            KVDecoders(
                {
                    "sample": (lambda x: float(x.strip("%"))),
                    "actions": nested_kv_decoder(
                        KVDecoders(
                            decoders=_decoders,
                            default_free=decode_free_output,
                        ),
                        is_list=True,
                    ),
                }
            )
        )

        _decoders["clone"] = nested_kv_decoder(
            KVDecoders(decoders=_decoders, default_free=decode_free_output),
            is_list=True,
        )

        return {
            **_decoders,
            "check_pkt_len": nested_kv_decoder(
                KVDecoders(
                    {
                        "size": decode_int,
                        "gt": nested_kv_decoder(
                            KVDecoders(
                                decoders=_decoders,
                                default_free=decode_free_output,
                            )
                        ),
                        "le": nested_kv_decoder(
                            KVDecoders(
                                decoders=_decoders,
                                default_free=decode_free_output,
                            )
                        ),
                    }
                )
            ),
        }

    @staticmethod
    def _tnl_action_decoder_args():
        """Generate the decoder arguments for the tunnel actions."""
        return {
            "tnl_push": nested_kv_decoder(
                KVDecoders(
                    {
                        "tnl_port": decode_default,
                        "header": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "size": decode_int,
                                    "type": decode_int,
                                    "eth": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "src": EthMask,
                                                "dst": EthMask,
                                                "dl_type": decode_int,
                                            }
                                        )
                                    ),
                                    "ipv4": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "src": IPMask,
                                                "dst": IPMask,
                                                "proto": decode_int,
                                                "tos": decode_int,
                                                "ttl": decode_int,
                                                "frag": decode_int,
                                            }
                                        )
                                    ),
                                    "ipv6": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "src": IPMask,
                                                "dst": IPMask,
                                                "label": decode_int,
                                                "proto": decode_int,
                                                "tclass": decode_int,
                                                "hlimit": decode_int,
                                            }
                                        )
                                    ),
                                    "udp": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "src": decode_int,
                                                "dst": decode_int,
                                                "csum": Mask16,
                                            }
                                        )
                                    ),
                                    "vxlan": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "flags": decode_int,
                                                "vni": decode_int,
                                            }
                                        )
                                    ),
                                    "geneve": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "oam": decode_flag,
                                                "crit": decode_flag,
                                                "vni": decode_int,
                                                "options": partial(
                                                    decode_geneve, False
                                                ),
                                            }
                                        )
                                    ),
                                    "gre": decode_tnl_gre,
                                    "erspan": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "ver": decode_int,
                                                "sid": decode_int,
                                                "idx": decode_int,
                                                "dir": decode_int,
                                                "hwid": decode_int,
                                            }
                                        )
                                    ),
                                    "gtpu": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "flags": decode_int,
                                                "msgtype": decode_int,
                                                "teid": decode_int,
                                            }
                                        )
                                    ),
                                    "srv6": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "segments_left": decode_int,
                                                "segs": decode_default,
                                            }
                                        )
                                    ),
                                }
                            )
                        ),
                        "out_port": decode_default,
                    }
                )
            )
        }

    @staticmethod
    def _gen_match_decoders():
        """Generate the match KVDecoders."""
        return KVDecoders(ODPFlow._match_decoders_args())

    @staticmethod
    def _match_decoders_args():
        """Generate the arguments for the match KVDecoders."""
        return {
            **ODPFlow._field_decoders_args(),
            "encap": nested_kv_decoder(
                KVDecoders(ODPFlow._field_decoders_args())
            ),
        }

    @staticmethod
    def _field_decoders_args():
        """Generate the decoder arguments for the match fields."""
        return {
            "skb_priority": Mask32,
            "skb_mark": Mask32,
            "recirc_id": decode_int,
            "dp_hash": Mask32,
            "ct_state": decode_default,
            "ct_zone": Mask16,
            "ct_mark": Mask32,
            "ct_label": Mask128,
            "ct_tuple4": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": IPMask,
                        "dst": IPMask,
                        "proto": Mask8,
                        "tp_src": Mask16,
                        "tp_dst": Mask16,
                    }
                )
            ),
            "ct_tuple6": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": IPMask,
                        "dst": IPMask,
                        "proto": Mask8,
                        "tcp_src": Mask16,
                        "tcp_dst": Mask16,
                    }
                )
            ),
            "tunnel": nested_kv_decoder(
                KVDecoders(
                    {
                        "tun_id": Mask64,
                        "src": IPMask,
                        "dst": IPMask,
                        "ipv6_src": IPMask,
                        "ipv6_dst": IPMask,
                        "tos": Mask8,
                        "ttl": Mask8,
                        "tp_src": Mask16,
                        "tp_dst": Mask16,
                        "erspan": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "ver": Mask8,
                                    "idx": Mask32,
                                    "sid": decode_int,
                                    "dir": Mask8,
                                    "hwid": Mask8,
                                }
                            )
                        ),
                        "vxlan": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "flags": decode_int,
                                    "vni": decode_int,
                                    "gbp": nested_kv_decoder(
                                        KVDecoders(
                                            {
                                                "id": Mask16,
                                                "flags": Mask8,
                                            }
                                        )
                                    ),
                                }
                            )
                        ),
                        "geneve": partial(decode_geneve, True),
                        "gtpu": nested_kv_decoder(
                            KVDecoders(
                                {
                                    "flags": Mask8,
                                    "msgtype": Mask8,
                                }
                            )
                        ),
                        "flags": decode_default,
                    }
                )
            ),
            "in_port": decode_default,
            "eth": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": EthMask,
                        "dst": EthMask,
                    }
                )
            ),
            "vlan": nested_kv_decoder(
                KVDecoders(
                    {
                        "vid": Mask16,
                        "pcp": Mask16,
                        "cfi": Mask16,
                    }
                )
            ),
            "eth_type": Mask16,
            "mpls": nested_kv_decoder(
                KVDecoders(
                    {
                        "label": Mask32,
                        "tc": Mask32,
                        "ttl": Mask32,
                        "bos": Mask32,
                    }
                )
            ),
            "ipv4": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": IPMask,
                        "dst": IPMask,
                        "proto": Mask8,
                        "tos": Mask8,
                        "ttl": Mask8,
                        "frag": decode_default,
                    }
                )
            ),
            "ipv6": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": IPMask,
                        "dst": IPMask,
                        "label": decode_mask(20),
                        "proto": Mask8,
                        "tclass": Mask8,
                        "hlimit": Mask8,
                        "frag": decode_default,
                    }
                )
            ),
            "tcp": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": Mask16,
                        "dst": Mask16,
                    }
                )
            ),
            "tcp_flags": decode_default,
            "udp": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": Mask16,
                        "dst": Mask16,
                    }
                )
            ),
            "sctp": nested_kv_decoder(
                KVDecoders(
                    {
                        "src": Mask16,
                        "dst": Mask16,
                    }
                )
            ),
            "icmp": nested_kv_decoder(
                KVDecoders(
                    {
                        "type": Mask8,
                        "code": Mask8,
                    }
                )
            ),
            "icmpv6": nested_kv_decoder(
                KVDecoders(
                    {
                        "type": Mask8,
                        "code": Mask8,
                    }
                )
            ),
            "arp": nested_kv_decoder(
                KVDecoders(
                    {
                        "sip": IPMask,
                        "tip": IPMask,
                        "op": Mask16,
                        "sha": EthMask,
                        "tha": EthMask,
                    }
                )
            ),
            "nd": nested_kv_decoder(
                KVDecoders(
                    {
                        "target": IPMask,
                        "sll": EthMask,
                        "tll": EthMask,
                    }
                )
            ),
            "nd_ext": nested_kv_decoder(
                KVDecoders(
                    {
                        "nd_reserved": Mask32,
                        "nd_options_type": Mask8,
                    }
                )
            ),
            "packet_type": nested_kv_decoder(
                KVDecoders(
                    {
                        "ns": Mask16,
                        "id": Mask16,
                    }
                )
            ),
            "nsh": nested_kv_decoder(
                KVDecoders(
                    {
                        "flags": Mask8,
                        "mdtype": Mask8,
                        "np": Mask8,
                        "spi": Mask32,
                        "si": Mask8,
                        "c1": Mask32,
                        "c2": Mask32,
                        "c3": Mask32,
                        "c4": Mask32,
                    }
                )
            ),
        }


def decode_geneve(mask, value):
    """Decode geneve options.
    Used for both tnl_push(header(geneve(options()))) action and
    tunnel(geneve()) match.

    It has the following format:

    {class=0xffff,type=0x80,len=4,0xa}

    Args:
        mask (bool): Whether masking is supported.
        value (str): The value to decode.
    """
    if mask:
        decoders = {
            "class": Mask16,
            "type": Mask8,
            "len": Mask8,
        }

        def free_decoder(value):
            return "data", Mask128(value)

    else:
        decoders = {
            "class": decode_int,
            "type": decode_int,
            "len": decode_int,
        }

        def free_decoder(value):
            return "data", decode_int(value)

    result = []
    for opts in re.findall(r"{.*?}", value):
        result.append(
            decode_nested_kv(
                KVDecoders(decoders=decoders, default_free=free_decoder),
                opts.strip("{}"),
            )
        )
    return result


def decode_tnl_gre(value):
    """
    Decode tnl_push(header(gre())) action.

    It has the following format:

    gre((flags=0x2000,proto=0x6558),key=0x1e241))

    Args:
        value (str): The value to decode.
    """
    return decode_nested_kv(
        KVDecoders(
            {
                "flags": decode_int,
                "proto": decode_int,
                "key": decode_int,
                "csum": decode_int,
                "seq": decode_int,
            }
        ),
        value.replace("(", "").replace(")", ""),
    )
