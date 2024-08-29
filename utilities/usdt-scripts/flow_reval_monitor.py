#!/usr/bin/env python3
#
# Copyright (c) 2022-2024 Redhat, Inc.
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
# flow_reval_monitor.py uses the dpif_netlink_operate:flow_put and
# revalidator:flow_result USDT probes to monitor flow lifetimes and
# expiration events. By default, this will show all flow_put and flow
# expiration events, along with their reasons. This will look like so:
#
# TID        TIME               UFID                               EVENT/REASON
# 71828 1549.119959874 39f0f28f-33... Insert (put) flow to ovs kernel module.
# 71828 1549.420877223 850db41c-47... Insert (put) flow to ovs kernel module.
# 71828 1550.476923456 5bacfca9-fe... Insert (put) flow to ovs kernel module.
# 71832      1559.650192299     850db41c-47... Idle flow timed out
# 71832      1561.153332825     39f0f28f-33... Idle flow timed out
# 71832      1572.684316304     5bacfca9-fe... Idle flow timed out
#
# Flow key data can be printed using the --flow-keys option.  This will
# print the equivalent datapath flow string.
#
# When filtering flows, the syntax is the same as used by
# `ovs-appctl dpctl/add-flow`.
#
# For a complete list of options, please use the '--help' or '-h' argument.
#
# Examples:
#
# To use the script on a running ovs-vswitchd to see flow keys and expiration
# events for flows with an ipv4 source of 192.168.10.10:
# $ ./flow_reval_monitor.py --flow-keys --filter-flows \
#   "ipv4(src=192.168.10.10)"
# TIME               UFID                                          EVENT/REASON
# 105082.457322742   ufid:f76fc899-376d-466b-bc74-0000b933eb97     flow_put
# ufid:f76fc899-376d-466b-bc74-0000b933eb97 has the following flow information:
#     in_port(2),
#     eth(src=0e:04:47:fc:74:51, dst=da:dc:c5:69:05:d7), \
#     eth_type(0x800), \
#     ipv4(src=192.168.10.10, dst=192.168.10.30, proto=1, tos=0, ttl=64,[...]),
#     icmp(type=8, code=0)
# 105092.635450202   ufid:f76fc899-376d-466b-bc74-0000b933eb97   Flow timed out
#
# Notes:
#   1) No options are needed to attach when there is a single running instance
#      of ovs-vswitchd.
#   2) If you're using the flow filtering option, it will only track flows that
#      have been upcalled since the script began running.
#   3) When using the flow filtering option, the key size will likely need to
#      be expanded to match on all the fields in the message.  The default is
#      kept small to keep the buffer copy sizes down when displaying
#      flows (-k), but is hardcoded to 2048 when an actual filter (-l) is
#      applied
#   4) The flow filtering format is a simplified form of the ODP syntax, and
#      does not support masked matches, which means you will need to filter
#      on exact details.  The fields present are dependent on how the
#      classifier and OFP rules form the ODP rules - not all fields may be
#      present in a particular flow.
#   5) The flow_put filtering only happens for flows installed into the ovs
#      kernel module.  This means flows taking the HW offload path (ie: tc),
#      or on DPDK side won't get matched.

try:
    from bcc import BPF
    from bcc import USDT
    from bcc import USDTException
except ModuleNotFoundError:
    print("ERROR: Can't find the BPF Compiler Collection Tools.")
    print("Please install them before running this script.")
    exit(1)

from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import argparse
import psutil
import re
import struct
import subprocess
import sys

#
# eBPF source code
#
bpf_src = """
#include <linux/sched.h>

#define MAX_KEY      <MAX_KEY_VAL>
#define FLOW_FILTER  <FILTER_BOOL>

enum probe { <EVENT_ENUM> };

<OVS_INCLUDE_DEFINITIONS>

struct event_t {
    u64 ts;
    u32 pid;
    u32 result;
    u32 reason;
    u32 ufid[4];
    u64 key_size;
    unsigned char key[MAX_KEY];
    enum probe probe;
};

BPF_HASH(watchlist, ovs_u128);
BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_COUNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);

/* Hack to make a 'static' like storage object. */
BPF_TABLE("percpu_array", uint32_t, struct udpif_key, udpk, 1);

static struct event_t *get_event(enum probe p) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        dropcnt.increment(0);
        return NULL;
    }

    event->probe = p;
    event->ts = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid();

    return event;
}

static int emit_flow_result(struct udpif_key *ukey, ovs_u128 ufid,
                            u32 result, u32 reason) {
    struct event_t *event = NULL;
    u64 *ufid_present = NULL;

    ufid_present = watchlist.lookup(&ufid);
    if (FLOW_FILTER && !ufid_present) {
        return 0;
    }

    event = get_event(FLOW_RESULT);
    if (!event) {
        /* If we can't reserve the space in the ring buffer, return 1. */
        return 1;
    }

    event->result = result;
    event->reason = reason;
    bpf_probe_read(&event->ufid, sizeof ufid, &ufid);
    events.ringbuf_submit(event, 0);

    return 0;
}

int usdt__flow_result(struct pt_regs *ctx) {
    struct udpif_key *ukey = NULL;
    u32 reason = 0;
    u32 result = 0;
    ovs_u128 ufid;
    u32 zero = 0;

    ukey = udpk.lookup(&zero);
    if (!ukey) {
        return 1;
    }
    bpf_usdt_readarg_p(2, ctx, ukey, sizeof(struct udpif_key));
    bpf_usdt_readarg(3, ctx, &result);
    bpf_usdt_readarg(4, ctx, &reason);
    ufid = ukey->ufid;

    return emit_flow_result(ukey, ufid, result, reason);
}

int usdt__flow_sweep_result(struct pt_regs *ctx) {
    struct udpif_key *ukey = NULL;
    u32 reason = 0;
    u32 result = 0;
    ovs_u128 ufid;
    u32 zero = 0;

    ukey = udpk.lookup(&zero);
    if (!ukey) {
        return 1;
    }
    bpf_usdt_readarg_p(2, ctx, ukey, sizeof(struct udpif_key));
    bpf_usdt_readarg(3, ctx, &result);
    bpf_usdt_readarg(4, ctx, &reason);
    ufid = ukey->ufid;

    return emit_flow_result(ukey, ufid, result, reason);
}

int usdt__op_flow_put(struct pt_regs *ctx) {
    struct dpif_flow_put put;
    ovs_u128 ufid;

    struct event_t *event = get_event(OP_FLOW_PUT);
    if (!event) {
        /* If we can't reserve the space in the ring buffer, return 1. */
        return 1;
    }

    bpf_usdt_readarg_p(2, ctx, &put, sizeof put);
    bpf_probe_read(&event->ufid, sizeof event->ufid, put.ufid);
    bpf_probe_read(&ufid, sizeof ufid, &event->ufid);
    if (put.key_len > MAX_KEY) {
        put.key_len = MAX_KEY;
    }
    event->key_size = put.key_len;
    bpf_probe_read(&event->key, put.key_len, put.key);
    event->reason = 0;
    events.ringbuf_submit(event, 0);

    watchlist.increment(ufid);
    return 0;
}
"""

Event = IntEnum("Event", ["OP_FLOW_PUT", "FLOW_RESULT"], start=0)
RevalResult = IntEnum(
    "reval_result",
    [
        "UKEY_KEEP",
        "UKEY_DELETE",
        "UKEY_MODIFY",
    ],
    start=0,
)

#
# The below FdrReasons and FdrReasonStrings definitions can be found in the
# ofproto/ofproto-dpif-upcall.c file.  Please keep them in sync.
#
FdrReasons = IntEnum(
    "flow_del_reason",
    [
        "FDR_NONE",
        "FDR_AVOID_CACHING",
        "FDR_BAD_ODP_FIT",
        "FDR_FLOW_IDLE",
        "FDR_FLOW_LIMIT",
        "FDR_FLOW_WILDCARDED",
        "FDR_NO_OFPROTO",
        "FDR_PURGE",
        "FDR_TOO_EXPENSIVE",
        "FDR_UPDATE_FAIL",
        "FDR_XLATION_ERROR",
        "FDR_FLOW_MISSING_DP"
    ],
    start=0,
)

FdrReasonStrings = {
    FdrReasons.FDR_NONE: "No delete reason specified",
    FdrReasons.FDR_AVOID_CACHING: "Cache avoidance flag set",
    FdrReasons.FDR_BAD_ODP_FIT: "Bad ODP flow fit",
    FdrReasons.FDR_FLOW_IDLE: "Flow idle timeout",
    FdrReasons.FDR_FLOW_LIMIT: "Kill all flows condition reached",
    FdrReasons.FDR_FLOW_WILDCARDED: "Flow needs a narrower wildcard mask",
    FdrReasons.FDR_NO_OFPROTO: "Bridge not found",
    FdrReasons.FDR_PURGE: "User requested flow deletion",
    FdrReasons.FDR_TOO_EXPENSIVE: "Too expensive to revalidate",
    FdrReasons.FDR_UPDATE_FAIL: "Datapath update failed",
    FdrReasons.FDR_XLATION_ERROR: "Flow translation error",
    FdrReasons.FDR_FLOW_MISSING_DP: "Flow is missing from the datapath"
}


def err(msg, code=-1):
    """Prints an error to stderr and exits"""

    print(msg, file=sys.stderr)
    sys.exit(code)


def run_program(command):
    """Invokes a new process and returns stdout.  Note that this will honor
    the PATH environment variable, so best to use it sparingly, or with a
    full path to binary."""

    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf8",
            check=True,
        )

    except subprocess.CalledProcessError as perror:
        return perror.returncode, perror.stdout

    return 0, process.stdout


def get_ovs_definitions(objects, pahole="pahole", pid=None):
    """Uses `pahole` or similar utility to pull object definitions from a
    running OVS process.  The objects argument can either be a string
    or can be a list of strings.  Optionally, pass a specific `pahole`
    binary to use rather than the default.  PID needs to be set."""

    if pid is None:
        raise ValueError("A valid pid value should be supplied!")

    if not isinstance(objects, list):
        objects = [objects]

    if len(objects) == 0:
        raise ValueError("Must supply at least one object!")

    vswitchd = Path(f"/proc/{pid}/exe").resolve()

    object_str = ",".join(objects)

    def run_pahole(debug_file):
        """Helper designed for running pahole, or something with compatible
        output"""

        error, result = run_program(
            [pahole, "-C", object_str, "--compile", debug_file]
        )

        if error:
            if f"pahole: {debug_file}: Invalid argument" not in result:
                err(
                    "ERROR: Pahole failed to get ovs-vswitchd data "
                    "structures!\n{}".format(
                        re.sub(
                            "^", " " * 7, result.rstrip(), flags=re.MULTILINE
                        )
                    )
                )

            return None

        if bool(re.search("pahole: type .* not found", result)):
            return None

        return result

    def run_readelf(bin_file):
        """Helper designed for running readelf or something with compatible
        output"""

        error, result = run_program(
            ["readelf", "-n", "--debug-dump=links", bin_file]
        )

        if error:
            err(
                "ERROR: Failed 'readelf' on \"{}\"!\n{}".format(
                    bin_file, re.sub("^", " " * 7, result, flags=re.MULTILINE)
                )
            )

        return result

    def get_debug_file(bin_file):
        """Runs readelf against the binary, and attempts to find the associated
        debuginfo file."""
        elf_result = run_readelf(bin_file)
        match = re.search("Build ID: ([0-9a-fA-F]+)", elf_result)
        if not match:
            err("ERROR: Can't find build ID to read debug symbols!")

        dbg_file = "/usr/lib/debug/.build-id/{}/{}.debug".format(
            match.group(1)[:2], match.group(1)[2:]
        )

        return dbg_file

    def get_from_shared_library(debug_file):
        ovs_libs = [
            "libofproto",
            "libopenvswitch",
            "libovsdb",
            "libsflow",
            "libvtep",
        ]
        error, ldd_result = run_program(["ldd", debug_file])

        if error:
            err(
                "ERROR: Failed 'ldd' on \"{}\"!\n{}".format(
                    debug_file,
                    re.sub("^", " " * 7, ldd_result, flags=re.MULTILINE),
                )
            )

        for lib in ovs_libs:
            match = re.search(
                r"^\s*{}.* => (.*) \(.*\)$".format(lib),
                ldd_result,
                flags=re.MULTILINE,
            )
            if match is None:
                continue

            result = run_pahole(match.group(1))
            if result is None:
                result = run_pahole(get_debug_file(match.group(1)))

            if result:
                return result

        return None

    #
    # First try to find the debug data as part of the executable.
    #
    result = run_pahole(vswitchd)

    if result is None:
        print(f'INFO: Failed to find debug info in "{vswitchd}"!')

        #
        # Get additional .debug information if available.
        #
        dbg_file = get_debug_file(vswitchd)
        result = run_pahole(dbg_file)
        if result is None:
            print(f'INFO: Failed to find debug info in "{dbg_file}"!')

        #
        # Try to get information from shared libraries if used.
        #
        result = get_from_shared_library(vswitchd)

    if result is None:
        err(f"ERROR: Failed to find needed data structures through {pahole}")

    #
    # We need an empty _Atomic definition to avoid compiler complaints.
    #
    result = "#define _Atomic\n" + result

    #
    # Remove the uint64_t definition as it conflicts with the kernel one.
    #
    result = re.sub("^typedef.*uint64_t;$", "", result, flags=re.MULTILINE)

    return result


def buffer_size_type(astr, min=64, max=2048):
    """Checks whether a string passed in is a number between min and max."""

    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            "value not in range {}-{}".format(min, max)
        )


def format_ufid(ufid):
    """Formats a UFID object into a human readable form.  If ufid is None,
    prints "ufid:none" instead."""
    if ufid is None:
        return "ufid:none"

    return "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}".format(
        ufid[0],
        ufid[1] >> 16,
        ufid[1] & 0xFFFF,
        ufid[2] >> 16,
        ufid[2] & 0,
        ufid[3],
    )


def find_and_delete_from_watchlist(event):
    """If the event ufid is in the watchlist, delete it"""

    for k, _ in b["watchlist"].items():
        key_ufid = struct.unpack("=IIII", k)
        if key_ufid == tuple(event.ufid):
            key = (b["watchlist"].Key * 1)(k)
            b["watchlist"].items_delete_batch(key)
            break


def handle_flow_put(event):
    """Event handler for the `flow_put` action.  This function will try
    to populate the watchlist based on the vswitchd emitting a put event
    to push an ODP flow key with associated actions into the kernel module"""

    if args.flow_keys or args.filter_flows is not None:
        key = decode_key(bytes(event.key)[: event.key_size])
        flow_dict, flow_str = parse_flow_dict(key)
        # For each attribute that we're watching.
        if args.filter_flows is not None:
            if not compare_flow_to_target(args.filter_flows, flow_dict):
                find_and_delete_from_watchlist(event)
                return

    print(
        "{:<10} {:<18.9f} {:<36} {}".format(
            event.pid,
            event.ts / 1000000000,
            format_ufid(event.ufid),
            "Insert (put) flow to ovs kernel module.",
        )
    )

    if args.flow_keys and len(flow_str):
        flow_str_fields = flow_str.split("), ")
        flow_str = "    "
        curlen = 4
        for field in flow_str_fields:
            if curlen + len(field) > 79:
                flow_str += "\n    "
                curlen = 4
            if field[-1] != ")":
                field += ")"
            flow_str += field + ", "
            curlen += len(field) + 2

        print(" - It holds the following key information:")
        print(flow_str)


def compare_flow_to_target(target, flow):
    """Routine to compare two flow keys"""

    for key in target:
        if key not in flow:
            return False
        elif target[key] is True:
            continue
        elif target[key] == flow[key]:
            continue
        elif isinstance(target[key], dict) and isinstance(flow[key], dict):
            return compare_flow_to_target(target[key], flow[key])
        else:
            return False
    return True


#
# parse_flow_str()
#
def parse_flow_str(flow_str):
    """Loosely parses an ODP flow key into a dict for further processing"""

    f_list = [i.strip(", ") for i in flow_str.split(")")]
    if f_list[-1] == "":
        f_list = f_list[:-1]
    flow_dict = {}
    for e in f_list:
        split_list = e.split("(")
        k = split_list[0]
        if len(split_list) == 1:
            flow_dict[k] = True
        elif split_list[1].count("=") == 0:
            flow_dict[k] = split_list[1]
        else:
            sub_dict = {}
            sublist = [i.strip() for i in split_list[1].split(",")]
            for subkey in sublist:
                brk = subkey.find("=")
                sub_dict[subkey[:brk]] = subkey[brk + 1 :]
            flow_dict[k] = sub_dict
    return flow_dict


def print_expiration(event):
    """Prints a UFID eviction with a reason."""
    ufid_str = format_ufid(event.ufid)

    try:
        reason = FdrReasonStrings[event.reason]
    except KeyError:
        reason = f"Unknown reason '{event.reason}'"

    print(
        "{:<10} {:<18.9f} {:<36} {:<17}".format(
            event.pid,
            event.ts / 1000000000,
            ufid_str,
            reason,
        )
    )


def decode_key(msg):
    """Decodes netlink OVS key attribute."""
    bytes_left = len(msg)
    result = {}
    while bytes_left:
        if bytes_left < 4:
            break
        nla_len, nla_type = struct.unpack("=HH", msg[:4])
        if nla_len < 4:
            break
        nla_data = msg[4:nla_len]
        if nla_len > bytes_left:
            nla_data = nla_data[: (bytes_left - 4)]
            break
        else:
            result[get_ovs_key_attr_str(nla_type)] = nla_data
        next_offset = (nla_len + 3) & (~3)
        msg = msg[next_offset:]
        bytes_left -= next_offset
    if bytes_left:
        print(f"INFO: Buffer truncated with {bytes_left} bytes left.")
    return result


#
# get_ovs_key_attr_str()
#
def get_ovs_key_attr_str(attr):
    ovs_key_attr = [
        "OVS_KEY_ATTR_UNSPEC",
        "encap",
        "skb_priority",
        "in_port",
        "eth",
        "vlan",
        "eth_type",
        "ipv4",
        "ipv6",
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "arp",
        "nd",
        "skb_mark",
        "tunnel",
        "sctp",
        "tcp_flags",
        "dp_hash",
        "recirc_id",
        "mpls",
        "ct_state",
        "ct_zone",
        "ct_mark",
        "ct_label",
        "ct_tuple4",
        "ct_tuple6",
        "nsh",
    ]

    if attr < 0 or attr > len(ovs_key_attr):
        return "<UNKNOWN>: {}".format(attr)
    return ovs_key_attr[attr]


def parse_flow_dict(key_dict, decode=True):
    """Processes a flow key dict (see `parse_flow_str` or `decode_key`) and
    returns a tuple of both the final flow key dict, and a string that
    represents and ODP-like representation.  Attempts to decode the actual
    data values if `decode` is true.  Otherwise, this can be for a loose form
    of validation.  Throws a KeyError when it encounters an unknown flow
    key."""

    ret_str = ""
    parseable = {}
    skip = ["nsh", "tunnel", "mpls", "vlan"]
    need_byte_swap = ["ct_label"]
    ipv4addrs = ["ct_tuple4", "tunnel", "ipv4", "arp"]
    ipv6addrs = ["ipv6", "nd", "ct_tuple6"]
    macs = {"eth": [0, 1], "arp": [3, 4], "nd": [1, 2]}
    fields = [
        ("OVS_KEY_ATTR_UNSPEC"),
        ("encap",),
        ("skb_priority", "<I"),
        ("in_port", "<I"),
        ("eth", "!6s6s", "src", "dst"),
        ("vlan",),
        ("eth_type", "!H"),
        ("ipv4", "!4s4s4B", "src", "dst", "proto", "tos", "ttl", "frag"),
        (
            "ipv6",
            "!16s16s4s4B",
            "src",
            "dst",
            "label",
            "proto",
            "tclass",
            "hlimit",
            "frag",
        ),
        ("tcp", "!2H", "src", "dst"),
        ("udp", "!2H", "src", "dst"),
        ("icmp", "!2B", "type", "code"),
        ("icmpv6", "!2B", "type", "code"),
        ("arp", "!4s4sH6s6s", "sip", "tip", "op", "sha", "tha"),
        ("nd", "!16s6s6s", "target", "sll", "tll"),
        ("skb_mark", "<I"),
        ("tunnel",),
        ("sctp", "!2H", "src", "dst"),
        ("tcp_flags", "!H"),
        ("dp_hash", "<I"),
        ("recirc_id", "<I"),
        ("mpls",),
        ("ct_state", "<I"),
        ("ct_zone", "<H"),
        ("ct_mark", "<I"),
        ("ct_label", "!16s"),
        ("ct_tuple4", "!4s4s2HB", "src", "dst", "tp_src", "tp_dst", "proto"),
        ("ct_tuple6", "!16s16sB2H", "src", "dst", "proto", "tp_src", "tp_dst"),
        ("nsh",),
    ]
    for k, v in key_dict.items():
        s = ""
        if k in skip:
            continue
        if decode and int.from_bytes(v, "big") == 0:
            parseable[k] = "0"
            continue
        if decode and k in need_byte_swap:
            v = int.from_bytes(v, "little").to_bytes(len(v), "big")
        attr = -1
        found = False
        for f in fields:
            if k == f[0]:
                attr = fields.index(f)
                found = True
                break
        if not found:
            raise KeyError("Invalid flow field '%s'" % k)
        if decode and len(fields[attr]) > 1:
            data = list(
                struct.unpack(
                    fields[attr][1], v[: struct.calcsize(fields[attr][1])]
                )
            )
            if k in ipv4addrs:
                if data[0].count(0) < 4:
                    data[0] = str(IPv4Address(data[0]))
                else:
                    data[0] = b"\x00"
                if data[1].count(0) < 4:
                    data[1] = str(IPv4Address(data[1]))
                else:
                    data[1] = b"\x00"
            if k in ipv6addrs:
                if data[0].count(0) < 16:
                    data[0] = str(IPv6Address(data[0]))
                else:
                    data[0] = b"\x00"
                if data[1].count(0) < len(data[1]):
                    data[1] = str(IPv6Address(data[1]))
                else:
                    data[1] = b"\x00"
            if k in macs.keys():
                for e in macs[k]:
                    if data[e].count(0) == 6:
                        mac_str = b"\x00"
                    else:
                        mac_str = ":".join(["%02x" % i for i in data[e]])
                    data[e] = mac_str
        if decode and len(fields[attr]) > 2:
            field_dict = dict(zip(fields[attr][2:], data))
            s = ", ".join(k + "=" + str(v) for k, v in field_dict.items())
        elif decode and k != "eth_type":
            s = str(data[0])
            field_dict = s
        else:
            if decode:
                s = hex(data[0])
            field_dict = s
        ret_str += k + "(" + s + "), "
        parseable[k] = field_dict
    ret_str = ret_str[:-2]
    return (parseable, ret_str)


def handle_event(ctx, data, size):
    """Dispatches to the correct event handler based on the event probe
    type.

    Once we grab the event, we have three cases.
      1. It's a revalidator probe and the reason is nonzero: A flow is expiring
      2. It's a revalidator probe and the reason is zero: flow revalidated
      3. It's a flow_put probe.

    We will ignore case 2, and report all others.
    """

    event = b["events"].event(data)
    if event.probe == Event.OP_FLOW_PUT:
        handle_flow_put(event)
    elif (
        event.probe == Event.FLOW_RESULT
        and event.result == RevalResult.UKEY_DELETE
    ):
        print_expiration(event)


def main():
    #
    # Don't like these globals, but ctx passing does not work with the existing
    # open_ring_buffer() API :(
    #
    global b
    global args

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--buffer-page-count",
        help="Number of BPF ring buffer pages, default 1024",
        type=int,
        default=1024,
        metavar="NUMBER",
    )
    parser.add_argument(
        "-f",
        "--flow-key-size",
        help="Set maximum flow key size to capture, "
        "default 128 - see notes",
        type=buffer_size_type,
        default=128,
        metavar="[128-2048]",
    )
    parser.add_argument(
        "-k",
        "--flow-keys",
        help="Print flow keys as flow strings",
        action="store_true",
    )
    parser.add_argument(
        "-l",
        "--filter-flows",
        metavar="FLOW_STRING",
        help="Filter flows that match the specified " "ODP-like flow",
        type=str,
        default=None,
        nargs="*",
    )
    parser.add_argument(
        "-P",
        "--pahole",
        metavar="PAHOLE",
        help="Pahole executable to use, default pahole",
        type=str,
        default="pahole",
    )
    parser.add_argument(
        "-p",
        "--pid",
        metavar="VSWITCHD_PID",
        help="ovs-vswitchd's PID",
        type=int,
        default=None,
    )
    parser.add_argument(
        "-D",
        "--debug",
        help="Enable eBPF debugging",
        type=int,
        const=0x3F,
        default=0,
        nargs="?",
    )
    args = parser.parse_args()

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if args.pid is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if args.pid is not None:
                    err(
                        "Error: Multiple ovs-vswitchd daemons running, "
                        "use the -p option!"
                    )

                args.pid = proc.pid
    #
    # Error checking on input parameters
    #
    if args.pid is None:
        err("ERROR: Failed to find ovs-vswitchd's PID!")

    #
    # Attach the USDT probes
    #
    try:
        u = USDT(pid=int(args.pid))
        u.enable_probe(probe="op_flow_put", fn_name="usdt__op_flow_put")
        u.enable_probe(probe="flow_result", fn_name="usdt__flow_result")
        u.enable_probe(
            probe="flow_sweep_result", fn_name="usdt__flow_sweep_result"
        )
    except USDTException as e:
        err("Failed to attach probes due to:\n" + str(e))

    #
    # Attach the probes to the running process
    #
    source = bpf_src.replace(
        "<BUFFER_PAGE_COUNT>", str(args.buffer_page_count)
    )

    source = source.replace(
        "<OVS_INCLUDE_DEFINITIONS>",
        get_ovs_definitions(
            ["udpif_key", "ovs_u128", "dpif_flow_put"],
            pid=args.pid,
            pahole=args.pahole,
        ),
    )

    if args.filter_flows is None:
        filter_bool = 0

        # Set the key size based on what the user wanted
        source = source.replace("<MAX_KEY_VAL>", str(args.flow_key_size))
    else:
        filter_bool = 1
        args.filter_flows = parse_flow_str(args.filter_flows[0])

        # Run through the parser to make sure we only filter on fields we
        # understand
        parse_flow_dict(args.filter_flows, False)

        # This is hardcoded here because it doesn't make sense to shrink the
        # size, since the flow key might be missing fields that are matched in
        # the flow filter.
        source = source.replace("<MAX_KEY_VAL>", "2048")

    source = source.replace("<FILTER_BOOL>", str(filter_bool))

    source = source.replace(
        "<EVENT_ENUM>",
        "\n".join([f"{event.name} = {event.value}," for event in Event]),
    )

    b = BPF(text=source, usdt_contexts=[u], debug=args.debug)

    #
    # Print header
    #
    print(
        "{:<10} {:<18} {:<36} {:<17}".format(
            "TID", "TIME", "UFID", "EVENT/REASON"
        )
    )

    #
    # Dump out all events.
    #
    b["events"].open_ring_buffer(handle_event)
    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            break

    dropcnt = b.get_table("dropcnt")
    for k in dropcnt.keys():
        count = dropcnt.sum(k).value
        if k.value == 0 and count > 0:
            print(
                "\n# WARNING: Not all flow operations were captured, {} were"
                " dropped!\n#          Increase the BPF ring buffer size "
                "with the --buffer-page-count option.".format(count)
            )


#
# Start main() as the default entry point
#
if __name__ == "__main__":
    main()
