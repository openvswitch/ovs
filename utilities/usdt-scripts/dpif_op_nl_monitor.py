#!/usr/bin/env python3
#
# Copyright (c) 2022 Red Hat, Inc.
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
#
# Script information:
# -------------------
# dpif_nl_exec_monitor.py uses the dpif_netlink_operate__:op_flow_execute USDT
# probe to receive all DPIF_OP_EXECUTE operations that are queued for
# transmission over the netlink socket. It will do some basic decoding, and if
# requested a packet dump. Note that there are also options to obtain
# additional information for the DPIF_OP_FLOW_* operations.
#
# Here is an example:
#
#   # ./dpif_op_nl_monitor.py --packet-decode decode --trace-exec-op
#   Display DPIF_OP_EXECUTE operations being queued for transmission...
#   TIME               CPU  COMM             PID        NL_SIZE
#   Display DPIF operations being queued for transmission onto the netlink...
#   TIME               CPU  COMM             PID        NL_SIZE    DPIF_...
#   2162030.641541513  5    handler4         2951007    164        DPIF_...
#      nlmsghdr  : len = 0, type = 36, flags = 1, seq = 0, pid = 0
#      genlmsghdr: cmd = DPIF_OP_EXECUTE, version = 1, reserved = 0
#      ovs_header: dp_ifindex = 21
#        > Decode OVS_PACKET_ATTR_* TLVs:
#        nla_len 46, nla_type OVS_PACKET_ATTR_PACKET[1], data: 00 00 00...
#        nla_len 20, nla_type OVS_PACKET_ATTR_KEY[2], data: 08 00 02 00...
#            > Decode OVS_KEY_ATTR_* TLVs:
#            nla_len 8, nla_type OVS_KEY_ATTR_PRIORITY[2], data: 00 00...
#            nla_len 8, nla_type OVS_KEY_ATTR_SKB_MARK[15], data: 00 00...
#        nla_len 88, nla_type OVS_PACKET_ATTR_ACTIONS[3], data: 4c 00 03...
#            > Decode OVS_ACTION_ATTR_* TLVs:
#            nla_len 76, nla_type OVS_ACTION_ATTR_SET[3], data: 48 00...
#                    > Decode OVS_TUNNEL_KEY_ATTR_* TLVs:
#                    nla_len 12, nla_type OVS_TUNNEL_KEY_ATTR_ID[0], data:...
#                    nla_len 20, nla_type OVS_TUNNEL_KEY_ATTR_IPV6_DST[13], ...
#                    nla_len 5, nla_type OVS_TUNNEL_KEY_ATTR_TTL[4], data: 40
#                    nla_len 4, nla_type OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT...
#                    nla_len 4, nla_type OVS_TUNNEL_KEY_ATTR_CSUM[6], data:
#                    nla_len 6, nla_type OVS_TUNNEL_KEY_ATTR_TP_DST[10],...
#                    nla_len 12, nla_type OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS...
#            nla_len 8, nla_type OVS_ACTION_ATTR_OUTPUT[1], data: 02 00 00 00
#        - Dumping OVS_PACKET_ATR_PACKET data:
#        ###[ Ethernet ]###
#          dst       = 00:00:00:00:ec:01
#          src       = 04:f4:bc:28:57:00
#          type      = IPv4
#        ###[ IP ]###
#             version   = 4
#             ihl       = 5
#             tos       = 0x0
#             len       = 50
#             id        = 0
#             flags     =
#             frag      = 0
#             ttl       = 127
#             proto     = icmp
#             chksum    = 0x2767
#             src       = 10.0.0.1
#             dst       = 10.0.0.100
#             \options   \
#        ###[ ICMP ]###
#                type      = echo-request
#                code      = 0
#                chksum    = 0xf7f3
#                id        = 0x0
#                seq       = 0xc
#
# The example above dumps the full netlink and packet decode. However options
# exist to disable this. For a complete list of options, please use the
# '--help' or '-h' argument.
#

from bcc import BPF, USDT, USDTException
from os.path import exists
from scapy.all import hexdump, wrpcap
from scapy.layers.l2 import Ether

import argparse
import psutil
import re
import struct
import sys
import time

#
# Actual eBPF source code
#
ebpf_source = """
#include <linux/sched.h>

#define MAX_NLMSG <MAX_NLMSG_VAL>

struct event_t {
    u32 cpu;
    u32 pid;
    u64 ts;
    u32 nl_size;
    char comm[TASK_COMM_LEN];
    u8 nl_msg[MAX_NLMSG];
};

struct ofpbuf {
    void *base;
    void *data;
    uint32_t size;

    /* The actual structure is longer, but we are only interested in the
     * first couple of entries. */
};

BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);

static int trace_event(struct ofpbuf *nlbuf)
{
    uint32_t size;

    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        uint32_t type = 0;
        uint64_t *value = dropcnt.lookup(&type);
        if (value)
            __sync_fetch_and_add(value, 1);

        return 1;
    }

    event->ts = bpf_ktime_get_ns();
    event->cpu =  bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->nl_size = nlbuf->size;
    if (event->nl_size > MAX_NLMSG)
        size = MAX_NLMSG;
    else
        size = event->nl_size;

    bpf_probe_read(&event->nl_msg, size, nlbuf->data);

    events.ringbuf_submit(event, 0);
    return 0;
}

#if <ENABLE_OP_EXECUTE>
int trace__op_execute(struct pt_regs *ctx) {
    struct ofpbuf nlbuf;

    bpf_usdt_readarg_p(5, ctx, &nlbuf, sizeof(nlbuf));
    return trace_event(&nlbuf);
};
#endif

#if <ENABLE_OP_FLOW_PUT>
int trace__op_flow_put(struct pt_regs *ctx) {
    struct ofpbuf nlbuf;

    bpf_usdt_readarg_p(4, ctx, &nlbuf, sizeof(nlbuf));
    return trace_event(&nlbuf);
};
#endif

#if <ENABLE_OP_FLOW_DEL>
int trace__op_flow_del(struct pt_regs *ctx) {
    struct ofpbuf nlbuf;

    bpf_usdt_readarg_p(4, ctx, &nlbuf, sizeof(nlbuf));
    return trace_event(&nlbuf);
};
#endif

#if <ENABLE_OP_FLOW_GET>
int trace__op_flow_get(struct pt_regs *ctx) {
    struct ofpbuf nlbuf;

    bpf_usdt_readarg_p(4, ctx, &nlbuf, sizeof(nlbuf));
    return trace_event(&nlbuf);
};
#endif
"""


#
# print_event()
#
def print_event(ctx, data, size):
    event = b["events"].event(data)

    if event.nl_size < options.nlmsg_size:
        nl_size = event.nl_size
    else:
        nl_size = options.nlmsg_size

    print("{:<18.9f} {:<4} {:<16} {:<10} {:<10} {}".
          format(event.ts / 1000000000,
                 event.cpu,
                 event.comm.decode("utf-8"),
                 event.pid,
                 event.nl_size,
                 get_ovs_dpif_op_str(get_cmd_type_from_nlm(
                     bytes(event.nl_msg)[:nl_size]))))

    #
    # Dumping the netlink message data if requested.
    #
    if options.nlmsg_decode == "hex":
        #
        # Abuse scapy's hex dump to dump flow key
        #
        print(re.sub("^", " " * 4,
                     hexdump(Ether(bytes(event.nl_msg)[:nl_size]), dump=True),
                     flags=re.MULTILINE))

    if options.nlmsg_decode == "nlraw":
        decode_result = decode_nlm(bytes(event.nl_msg)[:nl_size], dump=True)
    else:
        decode_result = decode_nlm(bytes(event.nl_msg)[:nl_size], dump=False)

    #
    # Decode packet only if there is data
    #
    if "OVS_PACKET_ATTR_PACKET" not in decode_result:
        return

    pkt_data = decode_result["OVS_PACKET_ATTR_PACKET"]
    indent = 4 if options.nlmsg_decode != "nlraw" else 6

    if options.packet_decode != "none":
        print("{}- Dumping OVS_PACKET_ATR_PACKET data:".format(" " * indent))

    if options.packet_decode == "hex":
        print(re.sub("^", " " * indent, hexdump(pkt_data, dump=True),
                     flags=re.MULTILINE))

    packet = Ether(pkt_data)
    if options.packet_decode == "decode":
        print(re.sub("^", " " * indent, packet.show(dump=True),
                     flags=re.MULTILINE))

    if options.pcap is not None:
        wrpcap(options.pcap, packet, append=True)


#
# decode_nlm_tlvs()
#
def decode_nlm_tlvs(tlvs, header=None, indent=4, dump=True,
                    attr_to_str_func=None, decode_tree=None):
    bytes_left = len(tlvs)
    result = {}

    if dump:
        print("{}{}".format(" " * indent, header))

    while bytes_left:
        if bytes_left < 4:
            if dump:
                print("{}WARN: decode truncated; can't read header".format(
                    " " * indent))
            break

        nla_len, nla_type = struct.unpack("=HH", tlvs[:4])

        if nla_len < 4:
            if dump:
                print("{}WARN: decode truncated; nla_len < 4".format(
                    " " * indent))
            break

        nla_data = tlvs[4:nla_len]
        trunc = ""

        if attr_to_str_func is None:
            nla_type_name = "type_{}".format(nla_type)
        else:
            nla_type_name = attr_to_str_func(nla_type)

        if nla_len > bytes_left:
            trunc = "..."
            nla_data = nla_data[:(bytes_left - 4)]
        else:
            result[nla_type_name] = nla_data

        if dump:
            print("{}nla_len {}, nla_type {}[{}], data: {}{}".format(
                " " * indent, nla_len, nla_type_name, nla_type,
                "".join("{:02x} ".format(b) for b in nla_data), trunc))

            #
            # If we have the full data, try to decode further
            #
            if trunc == "" and decode_tree is not None \
               and nla_type_name in decode_tree:
                node = decode_tree[nla_type_name]
                decode_nlm_tlvs(nla_data,
                                header=node["header"],
                                indent=indent + node["indent"], dump=True,
                                attr_to_str_func=node["attr_str_func"],
                                decode_tree=node["decode_tree"])

        if trunc != "":
            if dump:
                print("{}WARN: decode truncated; nla_len > msg_len[{}] ".
                      format(" " * indent, bytes_left))
            break

        # update next offset, but make sure it's aligned correctly
        next_offset = (nla_len + 3) & ~(3)
        tlvs = tlvs[next_offset:]
        bytes_left -= next_offset

    return result


#
# get_cmd_type_from_nlm()
#
def get_cmd_type_from_nlm(nlm):
    # The netlink message consists of at least a 'struct nlmsghdr' (16-bytes)
    # followed by a 'struct genlmsghdr'. The first byte of the genlmsghdr
    # structure contains the command. Which is what we will extract here.
    if len(nlm) < 17:
        return -1

    return nlm[16]


#
# decode_nlm()
#
def decode_nlm(msg, indent=4, dump=True):
    result = {}

    #
    # Decode 'struct nlmsghdr'
    #
    if dump:
        print("{}nlmsghdr  : len = {}, type = {}, flags = {}, seq = {}, "
              "pid = {}".format(" " * indent,
                                *struct.unpack("=IHHII", msg[:16])))

    msg = msg[16:]

    #
    # Decode 'struct genlmsghdr'
    #
    cmd, version, reserved = struct.unpack("=BBH", msg[:4])

    if dump:
        print("{}genlmsghdr: cmd = {}, version = {}, reserved = {}".format(
            " " * indent, get_ovs_dpif_op_str(cmd), version, reserved))

    msg = msg[4:]

    #
    # Decode 'struct ovs_header'
    #
    if dump:
        print("{}ovs_header: dp_ifindex = {}".format(
            " " * indent, *struct.unpack("=I", msg[:4])))

    msg = msg[4:]

    #
    # Decode TLVs
    #
    nl_key_attr = {
        "header": "> Decode OVS_KEY_ATTR_* TLVs:",
        "indent": 4,
        "attr_str_func": get_ovs_key_attr_str,
        "decode_tree": {
            "OVS_KEY_ATTR_ENCAP": {
                "header": "> Decode OVS_KEY_ATTR_* TLVs:",
                "indent": 4,
                "attr_str_func": get_ovs_key_attr_str,
                "decode_tree": {
                    "OVS_KEY_ATTR_ENCAP": {
                        "header": "> Decode OVS_KEY_ATTR_* TLVs:",
                        "indent": 4,
                        "attr_str_func": get_ovs_key_attr_str,
                        "decode_tree": None,
                    },
                },
            },
        }
    }

    nl_action_attr = {
        "header": "> Decode OVS_ACTION_ATTR_* TLVs:",
        "indent": 4,
        "attr_str_func": get_ovs_action_attr_str,
        "decode_tree": {
            "OVS_ACTION_ATTR_SET": {
                "header": "> Decode OVS_KEY_ATTR_* TLVs:",
                "indent": 4,
                "attr_str_func": get_ovs_key_attr_str,
                "decode_tree": {
                    "OVS_KEY_ATTR_TUNNEL": {
                        "header": "> Decode OVS_TUNNEL_KEY_ATTR_* TLVs:",
                        "indent": 4,
                        "attr_str_func": get_ovs_tunnel_key_attr_str,
                        "decode_tree": None,
                    },
                },
            },
        },
    }

    nl_attr_tree_exec = {
        "OVS_PACKET_ATTR_KEY": nl_key_attr,
        "OVS_PACKET_ATTR_ACTIONS": nl_action_attr,
    }

    nl_attr_tree_put = {
        "OVS_FLOW_ATTR_KEY": nl_key_attr,
        "OVS_FLOW_ATTR_MASK": nl_key_attr,
        "OVS_FLOW_ATTR_ACTIONS": nl_action_attr,
    }

    if get_ovs_dpif_op_str(cmd) == "DPIF_OP_EXECUTE":
        result = decode_nlm_tlvs(msg, indent=indent + 2, dump=dump,
                                 header="> Decode OVS_PACKET_ATTR_* TLVs:",
                                 attr_to_str_func=get_ovs_pkt_attr_str,
                                 decode_tree=nl_attr_tree_exec)
    else:
        result = decode_nlm_tlvs(msg, indent=indent + 2, dump=dump,
                                 header="> Decode OVS_FLOW_ATTR_* TLVs:",
                                 attr_to_str_func=get_ovs_flow_attr_str,
                                 decode_tree=nl_attr_tree_put)
    return result


#
# get_ovs_flow_attr_str()
#
def get_ovs_flow_attr_str(attr):
    ovs_flow_attr = ["OVS_FLOW_ATTR_UNSPEC",
                     "OVS_FLOW_ATTR_KEY",
                     "OVS_FLOW_ATTR_ACTIONS",
                     "OVS_FLOW_ATTR_STATS",
                     "OVS_FLOW_ATTR_TCP_FLAGS",
                     "OVS_FLOW_ATTR_USED",
                     "OVS_FLOW_ATTR_CLEAR",
                     "OVS_FLOW_ATTR_MASK",
                     "OVS_FLOW_ATTR_PROBE",
                     "OVS_FLOW_ATTR_UFID",
                     "OVS_FLOW_ATTR_UFID_FLAGS",
                     "OVS_FLOW_ATTR_PAD"]
    if attr < 0 or attr >= len(ovs_flow_attr):
        return "<UNKNOWN:{}>".format(attr)

    return ovs_flow_attr[attr]


#
# get_ovs_pkt_attr_str()
#
def get_ovs_pkt_attr_str(attr):
    ovs_pkt_attr = ["OVS_PACKET_ATTR_UNSPEC",
                    "OVS_PACKET_ATTR_PACKET",
                    "OVS_PACKET_ATTR_KEY",
                    "OVS_PACKET_ATTR_ACTIONS",
                    "OVS_PACKET_ATTR_USERDATA",
                    "OVS_PACKET_ATTR_EGRESS_TUN_KEY",
                    "OVS_PACKET_ATTR_UNUSED1",
                    "OVS_PACKET_ATTR_UNUSED2",
                    "OVS_PACKET_ATTR_PROBE",
                    "OVS_PACKET_ATTR_MRU",
                    "OVS_PACKET_ATTR_LEN",
                    "OVS_PACKET_ATTR_HASH"]
    if attr < 0 or attr >= len(ovs_pkt_attr):
        return "<UNKNOWN:{}>".format(attr)

    return ovs_pkt_attr[attr]


#
# get_ovs_key_attr_str()
#
def get_ovs_key_attr_str(attr):
    ovs_key_attr = ["OVS_KEY_ATTR_UNSPEC",
                    "OVS_KEY_ATTR_ENCAP",
                    "OVS_KEY_ATTR_PRIORITY",
                    "OVS_KEY_ATTR_IN_PORT",
                    "OVS_KEY_ATTR_ETHERNET",
                    "OVS_KEY_ATTR_VLAN",
                    "OVS_KEY_ATTR_ETHERTYPE",
                    "OVS_KEY_ATTR_IPV4",
                    "OVS_KEY_ATTR_IPV6",
                    "OVS_KEY_ATTR_TCP",
                    "OVS_KEY_ATTR_UDP",
                    "OVS_KEY_ATTR_ICMP",
                    "OVS_KEY_ATTR_ICMPV6",
                    "OVS_KEY_ATTR_ARP",
                    "OVS_KEY_ATTR_ND",
                    "OVS_KEY_ATTR_SKB_MARK",
                    "OVS_KEY_ATTR_TUNNEL",
                    "OVS_KEY_ATTR_SCTP",
                    "OVS_KEY_ATTR_TCP_FLAGS",
                    "OVS_KEY_ATTR_DP_HASH",
                    "OVS_KEY_ATTR_RECIRC_ID",
                    "OVS_KEY_ATTR_MPLS",
                    "OVS_KEY_ATTR_CT_STATE",
                    "OVS_KEY_ATTR_CT_ZONE",
                    "OVS_KEY_ATTR_CT_MARK",
                    "OVS_KEY_ATTR_CT_LABELS",
                    "OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4",
                    "OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6",
                    "OVS_KEY_ATTR_NSH"]

    if attr < 0 or attr >= len(ovs_key_attr):
        return "<UNKNOWN:{}>".format(attr)

    return ovs_key_attr[attr]


#
# get_ovs_action_attr_str()
#
def get_ovs_action_attr_str(attr):
    ovs_action_attr = ["OVS_ACTION_ATTR_UNSPEC",
                       "OVS_ACTION_ATTR_OUTPUT",
                       "OVS_ACTION_ATTR_USERSPACE",
                       "OVS_ACTION_ATTR_SET",
                       "OVS_ACTION_ATTR_PUSH_VLAN",
                       "OVS_ACTION_ATTR_POP_VLAN",
                       "OVS_ACTION_ATTR_SAMPLE",
                       "OVS_ACTION_ATTR_RECIRC",
                       "OVS_ACTION_ATTR_HASH",
                       "OVS_ACTION_ATTR_PUSH_MPLS",
                       "OVS_ACTION_ATTR_POP_MPLS",
                       "OVS_ACTION_ATTR_SET_MASKED",
                       "OVS_ACTION_ATTR_CT",
                       "OVS_ACTION_ATTR_TRUNC",
                       "OVS_ACTION_ATTR_PUSH_ETH",
                       "OVS_ACTION_ATTR_POP_ETH",
                       "OVS_ACTION_ATTR_CT_CLEAR",
                       "OVS_ACTION_ATTR_PUSH_NSH",
                       "OVS_ACTION_ATTR_POP_NSH",
                       "OVS_ACTION_ATTR_METER",
                       "OVS_ACTION_ATTR_CLONE",
                       "OVS_ACTION_ATTR_CHECK_PKT_LEN",
                       "OVS_ACTION_ATTR_ADD_MPLS",
                       "OVS_ACTION_ATTR_DEC_TTL",
                       "OVS_ACTION_ATTR_DROP",
                       "OVS_ACTION_ATTR_PSAMPLE",
                       "OVS_ACTION_ATTR_TUNNEL_PUSH",
                       "OVS_ACTION_ATTR_TUNNEL_POP",
                       "OVS_ACTION_ATTR_LB_OUTPUT"]
    if attr < 0 or attr >= len(ovs_action_attr):
        return "<UNKNOWN:{}>".format(attr)

    return ovs_action_attr[attr]


#
# get_ovs_tunnel_key_attr_str()
#
def get_ovs_tunnel_key_attr_str(attr):
    ovs_tunnel_key_attr = ["OVS_TUNNEL_KEY_ATTR_ID",
                           "OVS_TUNNEL_KEY_ATTR_IPV4_SRC",
                           "OVS_TUNNEL_KEY_ATTR_IPV4_DST",
                           "OVS_TUNNEL_KEY_ATTR_TOS",
                           "OVS_TUNNEL_KEY_ATTR_TTL",
                           "OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT",
                           "OVS_TUNNEL_KEY_ATTR_CSUM",
                           "OVS_TUNNEL_KEY_ATTR_OAM",
                           "OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS",
                           "OVS_TUNNEL_KEY_ATTR_TP_SRC",
                           "OVS_TUNNEL_KEY_ATTR_TP_DST",
                           "OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS",
                           "OVS_TUNNEL_KEY_ATTR_IPV6_SRC",
                           "OVS_TUNNEL_KEY_ATTR_IPV6_DST",
                           "OVS_TUNNEL_KEY_ATTR_PAD",
                           "OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS",
                           "OVS_TUNNEL_KEY_ATTR_GTPU_OPTS"]
    if attr < 0 or attr >= len(ovs_tunnel_key_attr):
        return "<UNKNOWN:{}>".format(attr)

    return ovs_tunnel_key_attr[attr]


#
# get_ovs_dpif_op_str()
#
def get_ovs_dpif_op_str(op):
    ovs_dpif_ops = ["DPIF_OP_UNSPEC",
                    "DPIF_OP_FLOW_PUT",
                    "DPIF_OP_FLOW_DEL",
                    "DPIF_OP_EXECUTE",
                    "DPIF_OP_FLOW_GET"]

    if op < 0 or op >= len(ovs_dpif_ops):
        return "<UNKNOWN:{}>".format(op)

    return ovs_dpif_ops[op]


#
# buffer_size_type()
#
def buffer_size_type(astr, min=64, max=2048):
    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            "value not in range {}-{}".format(min, max))


#
# next_power_of_two()
#
def next_power_of_two(val):
    np = 1
    while np < val:
        np *= 2
    return np


#
# main()
#
def main():
    #
    # Don't like these globals, but ctx passing does not seem to work with the
    # existing open_ring_buffer() API :(
    #
    global b
    global options

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs="?")
    parser.add_argument("-d", "--packet-decode",
                        help="Display packet content in selected mode, "
                        "default none",
                        choices=["none", "hex", "decode"], default="none")
    parser.add_argument("-n", "--nlmsg-decode",
                        help="Display netlink message content in selected mode"
                        ", default nlraw",
                        choices=["none", "hex", "nlraw"], default="nlraw")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitch's PID",
                        type=int, default=None)
    parser.add_argument("-s", "--nlmsg-size",
                        help="Set maximum netlink message size to capture, "
                        "default 512", type=buffer_size_type, default=512,
                        metavar="[64-2048]")
    parser.add_argument("--trace-del-op",
                        help="Monitor DPIF_OP_FLOW_DEL messages",
                        action="store_true")
    parser.add_argument("--trace-exec-op",
                        help="Monitor DPIF_OP_EXECUTE messages",
                        action="store_true")
    parser.add_argument("--trace-get-op",
                        help="Monitor DPIF_OP_FLOW_GET messages",
                        action="store_true")
    parser.add_argument("--trace-put-op",
                        help="Monitor DPIF_OP_FLOW_PUT messages",
                        action="store_true")
    parser.add_argument("-w", "--pcap", metavar="PCAP_FILE",
                        help="Write execute packets to specified pcap file",
                        type=str, default=None)

    options = parser.parse_args()

    #
    # Verify arguments.
    #
    if (not options.trace_del_op and not options.trace_exec_op
       and not options.trace_get_op and not options.trace_put_op):
        print("ERROR: At least on of the '--trace-*-op' arguments should be "
              "specified!")
        sys.exit(-1)

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if options.pid is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if options.pid is not None:
                    print("ERROR: Multiple ovs-vswitchd daemons running, "
                          "use the -p option!")
                    sys.exit(-1)

                options.pid = proc.pid

    #
    # Error checking on input parameters
    #
    if options.pid is None:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(-1)

    if options.pcap is not None:
        if exists(options.pcap):
            print("ERROR: Destination capture file \"{}\" already exists!".
                  format(options.pcap))
            sys.exit(-1)

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Attach the usdt probe
    #
    u = USDT(pid=int(options.pid))
    try:
        if options.trace_exec_op:
            u.enable_probe(probe="dpif_netlink_operate__:op_flow_execute",
                           fn_name="trace__op_execute")
        if options.trace_put_op:
            u.enable_probe(probe="dpif_netlink_operate__:op_flow_put",
                           fn_name="trace__op_flow_put")
        if options.trace_del_op:
            u.enable_probe(probe="dpif_netlink_operate__:op_flow_del",
                           fn_name="trace__op_flow_del")
        if options.trace_get_op:
            u.enable_probe(probe="dpif_netlink_operate__:op_flow_get",
                           fn_name="trace__op_flow_get")
    except USDTException as e:
        print("ERROR: {}".format(
            (re.sub("^", " " * 7, str(e), flags=re.MULTILINE)).strip().
            replace("--with-dtrace or --enable-dtrace",
                    "--enable-usdt-probes")))
        sys.exit(-1)

    #
    # Uncomment to see how arguments are decoded.
    #   print(u.get_text())
    #

    #
    # Attach probe to running process
    #
    source = ebpf_source.replace("<MAX_NLMSG_VAL>", str(options.nlmsg_size))
    source = source.replace("<BUFFER_PAGE_CNT>",
                            str(options.buffer_page_count))

    source = source.replace("<ENABLE_OP_FLOW_DEL>",
                            "1" if options.trace_del_op else "0")
    source = source.replace("<ENABLE_OP_EXECUTE>",
                            "1" if options.trace_exec_op else "0")
    source = source.replace("<ENABLE_OP_FLOW_GET>",
                            "1" if options.trace_get_op else "0")
    source = source.replace("<ENABLE_OP_FLOW_PUT>",
                            "1" if options.trace_put_op else "0")

    b = BPF(text=source, usdt_contexts=[u], debug=options.debug)

    #
    # Print header
    #
    print("Display DPIF operations being queued for transmission onto the "
          "netlink socket.")
    print("{:<18} {:<4} {:<16} {:<10} {:<10} {}".format(
        "TIME", "CPU", "COMM", "PID", "NL_SIZE", "DPIF_OPERATION"))

    #
    # Dump out all events
    #
    b["events"].open_ring_buffer(print_event)
    while 1:
        try:
            b.ring_buffer_poll()
            time.sleep(0.5)
        except KeyboardInterrupt:
            break

    dropcnt = b.get_table("dropcnt")
    for k in dropcnt.keys():
        count = dropcnt.sum(k).value
        if k.value == 0 and count > 0:
            print("\nWARNING: Not all upcalls were captured, {} were dropped!"
                  "\n         Increase the BPF ring buffer size with the "
                  "--buffer-page-count option.".format(count))


#
# Start main() as the default entry point...
#
if __name__ == "__main__":
    main()
