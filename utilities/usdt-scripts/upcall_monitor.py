#!/usr/bin/env python3
#
# Copyright (c) 2021 Red Hat, Inc.
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
# upcall_monitor.py uses the dpif_recv:recv_upcall USDT to receive all upcall
# packets sent by the kernel to ovs-vswitchd. By default, it will show all
# upcall events, which looks something like this:
#
# TIME               CPU  COMM      PID      PORT_NAME                TYPE ..
# 5952147.003848809  2    handler4  1381158  eth0 (system@ovs-system)  0
# 5952147.003879643  2    handler4  1381158  eth0 (system@ovs-system)  0
# 5952147.003914924  2    handler4  1381158  eth0 (system@ovs-system)  0
#
# Also, upcalls dropped by the kernel (e.g: because the netlink buffer is full)
# are reported. This requires the kernel version to be greater or equal to
# 5.14.
# In addition, the packet and flow key data can be dumped. This can be done
# using the --packet-decode and --flow-key decode options (see below).
#
# Note that by default only 64 bytes of the packet and flow key are retrieved.
# If you would like to capture all or more of the packet and/or flow key data,
# the ----packet-size and --flow-key-size options can be used.
#
# If required, the received packets can also be stored in a pcap file using the
# --pcap option.
#
# The following are the available options:
#
#    usage: upcall_monitor.py [-h] [-D [DEBUG]] [-d {none,hex,decode}]
#                             [-f [64-2048]] [-k {none,hex,nlraw}]
#                             [-p VSWITCHD_PID] [-s [64-2048]] [-w PCAP_FILE]
#
#    optional arguments:
#      -h, --help            show this help message and exit
#      -D [DEBUG], --debug [DEBUG]
#                            Enable eBPF debugging
#      -d {none,hex,decode}, --packet-decode {none,hex,decode}
#                            Display packet content in selected mode,
#                            default none
#      -f [64-2048], --flow-key-size [64-2048]
#                            Set maximum flow key size to capture, default 64
#      -k {none,hex,nlraw}, --flow-key-decode {none,hex,nlraw}
#                            Display flow-key content in selected mode, default
#                            none
#      -p VSWITCHD_PID, --pid VSWITCHD_PID
#                            ovs-vswitch's PID
#      -s [64-2048], --packet-size [64-2048]
#                            Set maximum packet size to capture, default 64
#      -w PCAP_FILE, --pcap PCAP_FILE
#                            Write upcall packets to specified pcap file.
#      -r, --result {error,ok,any}
#                            Display only events with the given result,
#                            default: any
#
# The following is an example of how to use the script on the running
# ovs-vswitchd process with a packet and flow key dump enabled:
#
#  $ ./upcall_monitor.py --packet-decode decode --flow-key-decode nlraw \
#      --packet-size 128 --flow-key-size 256
#  TIME               CPU  COMM             PID        PORT_NAME          ...
#  5953013.333214231  2    handler4         1381158    system@ovs-system  ...
#    Flow key size 132 bytes, size captured 132 bytes.
#      nla_len 8, nla_type OVS_KEY_ATTR_RECIRC_ID[20], data: 00 00 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_DP_HASH[19], data: 00 00 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_PRIORITY[2], data: 00 00 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_IN_PORT[3], data: 02 00 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_SKB_MARK[15], data: 00 00 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_CT_STATE[22], data: 00 00 00 00
#      nla_len 6, nla_type OVS_KEY_ATTR_CT_ZONE[23], data: 00 00
#      nla_len 8, nla_type OVS_KEY_ATTR_CT_MARK[24], data: 00 00 00 00
#      nla_len 20, nla_type OVS_KEY_ATTR_CT_LABELS[25], data: 00 00 00 00 ...
#      nla_len 16, nla_type OVS_KEY_ATTR_ETHERNET[4], data: 04 f4 bc 28 57 ...
#      nla_len 6, nla_type OVS_KEY_ATTR_ETHERTYPE[6], data: 08 00
#      nla_len 16, nla_type OVS_KEY_ATTR_IPV4[7], data: 01 01 01 64 01 01 ...
#      nla_len 6, nla_type OVS_KEY_ATTR_ICMP[11], data: 00 00
#    1: Receive dp_port 2, packet size 98 bytes, size captured 98 bytes.
#      ###[ Ethernet ]###
#        dst       = 3c:fd:fe:9e:7f:68
#        src       = 04:f4:bc:28:57:01
#        type      = IPv4
#      ###[ IP ]###
#           version   = 4
#           ihl       = 5
#           tos       = 0x0
#           len       = 84
#           id        = 41404
#           flags     = DF
#           frag      = 0
#           ttl       = 64
#           proto     = icmp
#           chksum    = 0x940c
#           src       = 1.1.1.100
#           dst       = 1.1.1.123
#           \options   \
#      ###[ ICMP ]###
#              type      = echo-reply
#              code      = 0
#              chksum    = 0x2f55
#              id        = 0x90e6
#              seq       = 0x1
#      ###[ Raw ]###
#                 load      = 'GBTa\x00\x00\x00\x00\xd8L\r\x00\x00\x00\x00\...
#

from bcc import BPF, USDT, USDTException
from os.path import exists, join
from scapy.all import hexdump, wrpcap
from scapy.layers.l2 import Ether

from usdt_lib import DpPortMapping

import argparse
import psutil
import re
import struct
import sys

#
# Actual eBPF source code
#
ebpf_source = """
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#define MAX_PACKET <MAX_PACKET_VAL>
#define MAX_KEY    <MAX_KEY_VAL>

struct event_t {
    int result;
    u32 cpu;
    u32 pid;
    u32 upcall_type;
    u64 ts;
    u32 pkt_size;
    u64 key_size;
    char comm[TASK_COMM_LEN];
    char dpif_name[32];
    char dev_name[16];
    unsigned char pkt[MAX_PACKET];
    unsigned char key[MAX_KEY];
};
BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);

static
void report_missed_event() {
    uint32_t type = 0;
    uint64_t *value = dropcnt.lookup(&type);
    if (value)
        __sync_fetch_and_add(value, 1);
}

#if <INSTALL_OVS_UPCALL_RECV_PROBE>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    uint64_t size;

    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        report_missed_event();
        return 1;
    }

    event->ts = bpf_ktime_get_ns();
    event->cpu =  bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid();
    event->result = 0;
    event->dev_name[0] = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_usdt_readarg(1, ctx, &addr);
    bpf_probe_read_str(&event->dpif_name, sizeof(event->dpif_name),
                       (void *)addr);

    bpf_usdt_readarg(2, ctx, &event->upcall_type);
    bpf_usdt_readarg(4, ctx, &event->pkt_size);
    bpf_usdt_readarg(6, ctx, &event->key_size);

    if (event->pkt_size > MAX_PACKET)
        size = MAX_PACKET;
    else
        size = event->pkt_size;
    bpf_usdt_readarg(3, ctx, &addr);
    bpf_probe_read(&event->pkt, size, (void *)addr);

    if (event->key_size > MAX_KEY)
        size = MAX_KEY;
    else
        size = event->key_size;
    bpf_usdt_readarg(5, ctx, &addr);
    bpf_probe_read(&event->key, size, (void *)addr);

    events.ringbuf_submit(event, 0);
    return 0;
};
#endif

#if <INSTALL_OVS_UPCALL_DROP_PROBE>
struct inflight_upcall {
    u32 cpu;
    u32 upcall_type;
    u64 ts;
    struct sk_buff *skb;
    char dpif_name[32];
};
BPF_HASH(inflight_upcalls, u64, struct inflight_upcall);

TRACEPOINT_PROBE(openvswitch, ovs_dp_upcall)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct inflight_upcall upcall = {};

    upcall.cpu = bpf_get_smp_processor_id();
    upcall.ts = bpf_ktime_get_ns();
    upcall.upcall_type = args->upcall_cmd;
    upcall.skb = args->skbaddr;
    TP_DATA_LOC_READ_CONST(&upcall.dpif_name, dp_name,
                           sizeof(upcall.dpif_name));

    inflight_upcalls.insert(&pid, &upcall);
    return 0;
}

int kretprobe__ovs_dp_upcall(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    struct inflight_upcall *upcall;
    int ret = PT_REGS_RC(ctx);
    struct net_device *dev;
    u64 size;

    upcall = inflight_upcalls.lookup(&pid);
    inflight_upcalls.delete(&pid);
    if (!upcall)
        return 0;

    /* Successfull upcalls are reported in the USDT probe. */
    if (!ret)
        return 0;

    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) {
        report_missed_event();
        return 1;
    }

    event->ts = upcall->ts;
    event->cpu = upcall->cpu;
    event->pid = pid;
    event->result = ret;
    __builtin_memcpy(&event->dpif_name, &upcall->dpif_name, 32);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->pkt_size = upcall->skb->len;
    event->upcall_type = upcall->upcall_type;
    event->key_size = 0;
    bpf_probe_read(&dev, sizeof(upcall->skb->dev),
                   ((char *)upcall->skb + offsetof(struct sk_buff, dev)));
    bpf_probe_read_kernel(&event->dev_name, 16, dev->name);

    size = upcall->skb->len - upcall->skb->data_len;
    if (size > MAX_PACKET)
        size = MAX_PACKET;

    bpf_probe_read_kernel(event->pkt, size, upcall->skb->data);
    events.ringbuf_submit(event, 0);
    return 0;
}
#endif
"""


#
# print_key()
#
def print_key(event, decode_dump):
    if event.key_size < options.flow_key_size:
        key_len = event.key_size
    else:
        key_len = options.flow_key_size

    if not key_len:
        return

    if options.flow_key_decode != 'none':
        print("  Flow key size {} bytes, size captured {} bytes.".
              format(event.key_size, key_len))

    if options.flow_key_decode == 'hex':
        #
        # Abuse scapy's hex dump to dump flow key
        #
        print(re.sub('^', ' ' * 4, hexdump(Ether(bytes(event.key)[:key_len]),
                                           dump=True),
                     flags=re.MULTILINE))

    if options.flow_key_decode == "nlraw":
        for line in decode_dump:
            print(line)


#
# print_event()
#
def print_event(ctx, data, size):
    event = b["events"].event(data)
    dp = event.dpif_name.decode("utf-8")

    nla, key_dump = decode_nlm(
        bytes(event.key)[: min(event.key_size, options.flow_key_size)]
    )
    if event.dev_name:
        port = event.dev_name.decode("utf-8")
    elif "OVS_KEY_ATTR_IN_PORT" in nla:
        port_no = struct.unpack("=I", nla["OVS_KEY_ATTR_IN_PORT"])[0]
        port = dp_map.get_port_name(dp.partition("@")[-1], port_no)
        if not port:
            port = str(port_no)
    else:
        port = "Unknown"

    print(
        "{:<18.9f} {:<4} {:<16} {:<10} {:<40} {:<4} {:<10} {:<12} {:<8}".
        format(
            event.ts / 1000000000,
            event.cpu,
            event.comm.decode("utf-8"),
            event.pid,
            "{} ({})".format(port, dp),
            event.upcall_type,
            event.pkt_size,
            event.key_size,
            event.result,
        )
    )

    #
    # Dump flow key information
    #
    print_key(event, key_dump)

    #
    # Decode packet only if there is data
    #
    if event.pkt_size <= 0:
        return

    pkt_id = get_pkt_id()

    if event.pkt_size < options.packet_size:
        pkt_len = event.pkt_size
        pkt_data = bytes(event.pkt)[:event.pkt_size]
    else:
        pkt_len = options.packet_size
        pkt_data = bytes(event.pkt)

    if options.packet_decode != 'none' or options.pcap is not None:
        print("  {}: Receive dp_port {}, packet size {} bytes, size "
              "captured {} bytes.".format(pkt_id, port, event.pkt_size,
                                          pkt_len))

    if options.packet_decode == 'hex':
        print(re.sub('^', ' ' * 4, hexdump(pkt_data, dump=True),
                     flags=re.MULTILINE))

    packet = Ether(pkt_data)
    packet.wirelen = event.pkt_size

    if options.packet_decode == 'decode':
        print(re.sub('^', ' ' * 4, packet.show(dump=True), flags=re.MULTILINE))

    if options.pcap is not None:
        wrpcap(options.pcap, packet, append=True, snaplen=options.packet_size)


#
# decode_nlm()
#
def decode_nlm(msg, indent=4):
    bytes_left = len(msg)
    result = {}
    dump = []

    while bytes_left:
        if bytes_left < 4:
            dump.append(
                "{}WARN: decode truncated; can't read header".format(
                    " " * indent
                )
            )
            break

        nla_len, nla_type = struct.unpack("=HH", msg[:4])

        if nla_len < 4:
            dump.append(
                "{}WARN: decode truncated; nla_len < 4".format(" " * indent)
            )
            break

        nla_data = msg[4:nla_len]
        trunc = ""

        if nla_len > bytes_left:
            trunc = "..."
            nla_data = nla_data[:(bytes_left - 4)]
        else:
            result[get_ovs_key_attr_str(nla_type)] = nla_data

        dump.append(
            "{}nla_len {}, nla_type {}[{}], data: {}{}".format(
                ' ' * indent, nla_len, get_ovs_key_attr_str(nla_type),
                nla_type,
                "".join("{:02x} ".format(b) for b in nla_data), trunc)
        )

        if trunc != "":
            dump.append(
                "{}WARN: decode truncated; nla_len > msg_len[{}] ".format(
                    " " * indent, bytes_left
                )
            )
            break

        # update next offset, but make sure it's aligned correctly
        next_offset = (nla_len + 3) & ~(3)
        msg = msg[next_offset:]
        bytes_left -= next_offset

    return result, dump


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

    if attr < 0 or attr > len(ovs_key_attr):
        return "<UNKNOWN>"

    return ovs_key_attr[attr]


#
# get_pkt_id()
#
def get_pkt_id():
    if not hasattr(get_pkt_id, "counter"):
        get_pkt_id.counter = 0
    get_pkt_id.counter += 1
    return get_pkt_id.counter


#
# buffer_size_type()
#
def buffer_size_type(astr, min=64, max=2048):
    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            'value not in range {}-{}'.format(min, max))


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
    global dp_map

    dp_map = DpPortMapping()

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs='?')
    parser.add_argument('-d', '--packet-decode',
                        help='Display packet content in selected mode, '
                        'default none',
                        choices=['none', 'hex', 'decode'], default='none')
    parser.add_argument("-f", "--flow-key-size",
                        help="Set maximum flow key size to capture, "
                        "default 64", type=buffer_size_type, default=64,
                        metavar="[64-2048]")
    parser.add_argument('-k', '--flow-key-decode',
                        help='Display flow-key content in selected mode, '
                        'default none',
                        choices=['none', 'hex', 'nlraw'], default='none')
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitch's PID",
                        type=int, default=None)
    parser.add_argument("-s", "--packet-size",
                        help="Set maximum packet size to capture, "
                        "default 64", type=buffer_size_type, default=64,
                        metavar="[64-2048]")
    parser.add_argument("-w", "--pcap", metavar="PCAP_FILE",
                        help="Write upcall packets to specified pcap file.",
                        type=str, default=None)
    parser.add_argument("-r", "--result",
                        help="Display only events with the given result, "
                        "default: any",
                        choices=["error", "ok", "any"], default="any")

    options = parser.parse_args()

    #
    # Check if current kernel supports error reporting.
    #
    tracefs_paths = ("/sys/kernel/debug/tracing/", "/sys/kernel/tracing/")
    upcall_tp_found = False
    for tracefs in tracefs_paths:
        if exists(join(tracefs, "events/openvswitch/ovs_dp_upcall")):
            upcall_tp_found = True
            break

    if not upcall_tp_found:
        if options.result == "error":
            print("ERROR: Monitoring error upcalls is not supported by the "
                  "running kernel (or the tracefs is not mounted).")
            sys.exit(-1)
        if options.result == "any":
            print("WARN: Monitoring error upcalls is not supported by the "
                  "running kernel (or the tracefs is not mounted). "
                  "Only successful ones will be monitored.")
            options.result = "ok"

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if options.pid is None:
        for proc in psutil.process_iter():
            if 'ovs-vswitchd' in proc.name():
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
    usdt = []
    if options.result in ["ok", "any"]:
        u = USDT(pid=int(options.pid))
        try:
            u.enable_probe(probe="recv_upcall", fn_name="do_trace")
            usdt.append(u)
        except USDTException as e:
            print("ERROR: {}"
                  "ovs-vswitchd!".format(
                      (re.sub('^', ' ' * 7, str(e), flags=re.MULTILINE)).
                      strip().replace("--with-dtrace or --enable-dtrace",
                                      "--enable-usdt-probes")))
            sys.exit(-1)

    #
    # Uncomment to see how arguments are decoded.
    #       print(u.get_text())
    #

    #
    # Attach probe to running process
    #
    source = ebpf_source.replace("<MAX_PACKET_VAL>", str(options.packet_size))
    source = source.replace("<MAX_KEY_VAL>", str(options.flow_key_size))
    source = source.replace("<BUFFER_PAGE_CNT>",
                            str(options.buffer_page_count))
    source = source.replace("<INSTALL_OVS_UPCALL_RECV_PROBE>", "1"
                            if options.result in ["ok", "any"] else "0")
    source = source.replace("<INSTALL_OVS_UPCALL_DROP_PROBE>", "1"
                            if options.result in ["error", "any"] else "0")

    b = BPF(text=source, usdt_contexts=usdt, debug=options.debug)

    #
    # Print header
    #
    print("{:<18} {:<4} {:<16} {:<10} {:<40} {:<4} {:<10} {:<12} {:<8}".format(
        "TIME", "CPU", "COMM", "PID", "PORT_NAME", "TYPE", "PKT_LEN",
        "FLOW_KEY_LEN", "RESULT"))

    #
    # Dump out all events
    #
    b['events'].open_ring_buffer(print_event)
    while 1:
        try:
            b.ring_buffer_poll()
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
if __name__ == '__main__':
    main()
