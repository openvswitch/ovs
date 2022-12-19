"""Defines the parsers needed to parse ofproto flows.
"""

import functools

from ovs.flow.kv import KVParser, KVDecoders, nested_kv_decoder
from ovs.flow.ofp_fields import field_decoders
from ovs.flow.flow import Flow, Section
from ovs.flow.list import ListDecoders, nested_list_decoder
from ovs.flow.decoders import (
    decode_default,
    decode_flag,
    decode_int,
    decode_time,
    decode_mask,
    IPMask,
    EthMask,
    decode_free_output,
    decode_nat,
)
from ovs.flow.ofp_act import (
    decode_output,
    decode_field,
    decode_controller,
    decode_bundle,
    decode_bundle_load,
    decode_encap,
    decode_load_field,
    decode_set_field,
    decode_move_field,
    decode_dec_ttl,
    decode_chk_pkt_larger,
    decode_zone,
    decode_learn,
)


class OFPFlow(Flow):
    """OFPFLow represents an OpenFlow Flow.

    Attributes:
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
        if not OFPFlow._info_decoders:
            OFPFlow._info_decoders = OFPFlow._gen_info_decoders()
        return OFPFlow._info_decoders

    @staticmethod
    def match_decoders():
        """Return the KVDecoders instance to parse the match section.

        Uses the cached version if available.
        """
        if not OFPFlow._match_decoders:
            OFPFlow._match_decoders = OFPFlow._gen_match_decoders()
        return OFPFlow._match_decoders

    @staticmethod
    def action_decoders():
        """Return the KVDecoders instance to parse the actions section.

        Uses the cached version if available.
        """
        if not OFPFlow._action_decoders:
            OFPFlow._action_decoders = OFPFlow._gen_action_decoders()
        return OFPFlow._action_decoders

    def __init__(self, ofp_string, id=None):
        """Create a OFPFlow from a flow string.

        The string is expected to have the followoing format:

            [flow data] [match] actions=[actions]

        Args:
            ofp_string(str): An OpenFlow flow string.
            id(Any): Optional; any object used to uniquely identify this flow
                from the rest.

        Returns
            An OFPFlow with the content of the flow string or None if there is
            no flow information but the string is expected to be found in a
            flow dump.

        Raises
            ValueError if the string is malformed.
            ParseError if an error in parsing occurs.
        """
        if " reply " in ofp_string:
            return None

        sections = list()
        parts = ofp_string.split("actions=")
        if len(parts) != 2:
            raise ValueError("malformed ofproto flow: %s" % ofp_string)

        actions = parts[1]

        field_parts = parts[0].rstrip(" ").rpartition(" ")
        if len(field_parts) != 3:
            raise ValueError("malformed ofproto flow: %s" % ofp_string)

        info = field_parts[0]
        match = field_parts[2]

        iparser = KVParser(info, OFPFlow.info_decoders())
        iparser.parse()
        isection = Section(
            name="info",
            pos=ofp_string.find(info),
            string=info,
            data=iparser.kv(),
        )
        sections.append(isection)

        mparser = KVParser(match, OFPFlow.match_decoders())
        mparser.parse()
        msection = Section(
            name="match",
            pos=ofp_string.find(match),
            string=match,
            data=mparser.kv(),
        )
        sections.append(msection)

        aparser = KVParser(actions, OFPFlow.action_decoders())
        aparser.parse()
        asection = Section(
            name="actions",
            pos=ofp_string.find(actions),
            string=actions,
            data=aparser.kv(),
            is_list=True,
        )
        sections.append(asection)

        super(OFPFlow, self).__init__(sections, ofp_string, id)

    def __str__(self):
        if self._orig:
            return self._orig
        else:
            return self.to_string()

    def to_string(self):
        """Return a text representation of the flow."""
        string = "Info: {} | ".format(self.info)
        string += "Match : {} | ".format(self.match)
        string += "Actions: {}".format(self.actions)
        return string

    @staticmethod
    def _gen_info_decoders():
        """Generate the info KVDecoders."""
        args = {
            "table": decode_int,
            "duration": decode_time,
            "n_packet": decode_int,
            "n_bytes": decode_int,
            "cookie": decode_int,
            "idle_timeout": decode_time,
            "hard_timeout": decode_time,
            "hard_age": decode_time,
        }
        return KVDecoders(args)

    @staticmethod
    def _gen_match_decoders():
        """Generate the match KVDecoders."""
        args = {
            **OFPFlow._field_decoder_args(),
            **OFPFlow._extra_match_decoder_args(),
        }

        return KVDecoders(args)

    @staticmethod
    def _extra_match_decoder_args():
        """Returns the extra KVDecoder arguments needed to decode the match
        part of a flow (apart from the fields)."""
        return {
            "priority": decode_int,
        }

    @staticmethod
    def _field_decoder_args():
        """Returns the KVDecoder arguments needed to decode match fields."""
        shorthands = [
            "eth",
            "ip",
            "ipv6",
            "icmp",
            "icmp6",
            "tcp",
            "tcp6",
            "udp",
            "udp6",
            "sctp",
            "arp",
            "rarp",
            "mpls",
            "mplsm",
        ]

        fields = {**field_decoders, **{key: decode_flag for key in shorthands}}

        # vlan_vid field is special. Although it is technically 12 bit wide,
        # bit 12 is allowed to be set to 1 to indicate that the vlan header is
        # present (see section VLAN FIELDS in
        # http://www.openvswitch.org/support/dist-docs/ovs-fields.7.txt)
        # Therefore, override the generated vlan_vid field size.
        fields["vlan_vid"] = decode_mask(13)
        return fields

    @staticmethod
    def _gen_action_decoders():
        """Generate the actions decoders."""

        actions = {
            **OFPFlow._output_actions_decoders_args(),
            **OFPFlow._encap_actions_decoders_args(),
            **OFPFlow._field_action_decoders_args(),
            **OFPFlow._meta_action_decoders_args(),
            **OFPFlow._fw_action_decoders_args(),
            **OFPFlow._control_action_decoders_args(),
            **OFPFlow._other_action_decoders_args(),
            **OFPFlow._instruction_action_decoders_args(),
        }
        clone_actions = OFPFlow._clone_actions_decoders_args(actions)
        actions.update(clone_actions)
        return KVDecoders(actions, default_free=decode_free_output,
                          ignore_case=True)

    @staticmethod
    def _output_actions_decoders_args():
        """Returns the decoder arguments for the output actions."""
        return {
            "output": decode_output,
            "drop": decode_flag,
            "controller": decode_controller,
            "enqueue": nested_list_decoder(
                ListDecoders([("port", decode_default), ("queue", int)]),
                delims=[",", ":"],
            ),
            "bundle": decode_bundle,
            "bundle_load": decode_bundle_load,
            "group": decode_default,
        }

    @staticmethod
    def _encap_actions_decoders_args():
        """Returns the decoders arguments for the encap actions."""

        return {
            "pop_vlan": decode_flag,
            "strip_vlan": decode_flag,
            "push_vlan": decode_default,
            "pop_mpls": decode_int,
            "push_mpls": decode_int,
            "decap": decode_flag,
            "encap": decode_encap,
        }

    @staticmethod
    def _field_action_decoders_args():
        """Returns the decoders arguments for field-modification actions."""
        # Field modification actions
        field_default_decoders = [
            "set_mpls_label",
            "set_mpls_tc",
            "set_mpls_ttl",
            "mod_nw_tos",
            "mod_nw_ecn",
            "mod_tp_src",
            "mod_tp_dst",
        ]
        return {
            "load": decode_load_field,
            "set_field": functools.partial(
                decode_set_field, KVDecoders(OFPFlow._field_decoder_args())
            ),
            "move": decode_move_field,
            "mod_dl_dst": EthMask,
            "mod_dl_src": EthMask,
            "mod_nw_dst": IPMask,
            "mod_nw_src": IPMask,
            "mod_nw_ttl": decode_int,
            "mod_vlan_vid": decode_int,
            "set_vlan_vid": decode_int,
            "mod_vlan_pcp": decode_int,
            "set_vlan_pcp": decode_int,
            "dec_ttl": decode_dec_ttl,
            "dec_mpls_ttl": decode_flag,
            "dec_nsh_ttl": decode_flag,
            "delete_field": decode_field,
            "check_pkt_larger": decode_chk_pkt_larger,
            **{field: decode_default for field in field_default_decoders},
        }

    @staticmethod
    def _meta_action_decoders_args():
        """Returns the decoders arguments for the metadata actions."""
        meta_default_decoders = ["set_tunnel", "set_tunnel64", "set_queue"]
        return {
            "pop_queue": decode_flag,
            **{field: decode_default for field in meta_default_decoders},
        }

    @staticmethod
    def _fw_action_decoders_args():
        """Returns the decoders arguments for the firewalling actions."""
        return {
            "ct": nested_kv_decoder(
                KVDecoders(
                    {
                        "commit": decode_flag,
                        "zone": decode_zone,
                        "table": decode_int,
                        "nat": decode_nat,
                        "force": decode_flag,
                        "exec": nested_kv_decoder(
                            KVDecoders(
                                {
                                    **OFPFlow._encap_actions_decoders_args(),
                                    **OFPFlow._field_action_decoders_args(),
                                    **OFPFlow._meta_action_decoders_args(),
                                }
                            ),
                            is_list=True,
                        ),
                        "alg": decode_default,
                    }
                )
            ),
            "ct_clear": decode_flag,
            "fin_timeout": nested_kv_decoder(
                KVDecoders(
                    {
                        "idle_timeout": decode_time,
                        "hard_timeout": decode_time,
                    }
                )
            ),
            # learn moved to _clone actions.
        }

    @staticmethod
    def _control_action_decoders_args():
        return {
            "resubmit": nested_list_decoder(
                ListDecoders(
                    [
                        ("port", decode_default),
                        ("table", decode_int),
                        ("ct", decode_flag),
                    ]
                )
            ),
            "push": decode_field,
            "pop": decode_field,
            "exit": decode_flag,
            "multipath": nested_list_decoder(
                ListDecoders(
                    [
                        ("fields", decode_default),
                        ("basis", decode_int),
                        ("algorithm", decode_default),
                        ("n_links", decode_int),
                        ("arg", decode_int),
                        ("dst", decode_field),
                    ]
                )
            ),
        }

    @staticmethod
    def _clone_actions_decoders_args(action_decoders):
        """Generate the decoder arguments for the clone actions.

        Args:
            action_decoders (dict): The decoders of the supported nested
            actions.
        """
        return {
            "learn": decode_learn(action_decoders),
            "clone": nested_kv_decoder(
                KVDecoders(action_decoders, ignore_case=True), is_list=True
            ),
            "write_actions": nested_kv_decoder(
                KVDecoders(action_decoders, ignore_case=True), is_list=True
            ),
        }

    @staticmethod
    def _other_action_decoders_args():
        """Generate the decoder arguments for other actions
        (see man(7) ovs-actions)."""
        return {
            "conjunction": nested_list_decoder(
                ListDecoders(
                    [("id", decode_int), ("k", decode_int), ("n", decode_int)]
                ),
                delims=[",", "/"],
            ),
            "note": decode_default,
            "sample": nested_kv_decoder(
                KVDecoders(
                    {
                        "probability": decode_int,
                        "collector_set_id": decode_int,
                        "obs_domain_id": decode_int,
                        "obs_point_id": decode_int,
                        "sampling_port": decode_default,
                        "ingress": decode_flag,
                        "egress": decode_flag,
                    }
                )
            ),
        }

    @staticmethod
    def _instruction_action_decoders_args():
        """Generate the decoder arguments for instruction actions
        (see man(7) ovs-actions)."""
        return {
            "meter": decode_int,
            "clear_actions": decode_flag,
            # write_actions moved to _clone actions
            "write_metadata": decode_mask(64),
            "goto_table": decode_int,
        }
