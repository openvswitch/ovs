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
# upcall_cost.py uses various user space and kernel space probes to determine
# the costs (in time) for handling the first packet in user space. It
# calculates the following costs:
#
# - Time it takes from the kernel sending the upcall till it's received by the
#   ovs-vswitchd process.
# - Time it takes from ovs-vswitchd sending the execute actions command till
#   the kernel receives it.
# - The total time it takes from the kernel to sent the upcall until it
#   receives the packet execute command.
# - The total time of the above, minus the time it takes for the actual lookup.
#
# In addition, it will also report the number of packets batched, as OVS will
# first try to read UPCALL_MAX_BATCH(64) packets from kernel space and then
# does the flow lookups and execution. So the smaller the batch size, the more
# realistic are the cost estimates.
#
# The script does not need any options to attach to a running instance of
# ovs-vswitchd. However, it's recommended always run the script with the
# --write-events option. This way, if something does go wrong, the collected
# data is saved. Use the --help option to see all the available options.
#
# Note: In addition to the bcc tools for your specific setup, you need the
#       following Python packages:
#         pip install alive-progress halo psutil scapy strenum text_histogram3
#

try:
    from bcc import BPF, USDT, USDTException
except ModuleNotFoundError:
    print("WARNING: Can't find the BPF Compiler Collection (BCC) tools!")
    print("         This is NOT problem if you analyzing previously collected"
          " data.\n")
from alive_progress import alive_bar
from collections import namedtuple
from halo import Halo
from scapy.all import TCP, UDP
from scapy.layers.l2 import Ether
from strenum import StrEnum
from text_histogram3 import histogram
from time import process_time

from usdt_lib import DpPortMapping

import argparse
import ast
import psutil
import re
import struct
import sys

#
# Global definitions
#
DP_TUNNEL_PORT = -1


#
# Actual eBPF source code
#
ebpf_source = """
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <uapi/linux/bpf.h>

#define MAX_PACKET <MAX_PACKET_VAL>
#define MAX_KEY    <MAX_KEY_VAL>

enum {
    EVENT_RECV_UPCALL = 0,
    EVENT_DP_UPCALL,
    EVENT_OP_FLOW_PUT,
    EVENT_OP_FLOW_EXECUTE,
    EVENT_OVS_PKT_EXEC,
    _EVENT_MAX_EVENT
};

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

struct event_t {
    u32 event;
    u32 cpu;
    u32 pid;
    u32 upcall_type;
    u64 ts;
    u32 pkt_frag_size;
    u32 pkt_size;
    u64 key_size;
    char comm[TASK_COMM_LEN];
    char dpif_name[32];
    char dev_name[16];
    unsigned char pkt[MAX_PACKET];
    unsigned char key[MAX_KEY];
};

BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, _EVENT_MAX_EVENT);

static struct event_t *init_event(u32 type)
{
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        uint64_t *value = dropcnt.lookup(&type);
        if (value)
            __sync_fetch_and_add(value, 1);

        return NULL;
    }

    event->event = type;
    event->ts = bpf_ktime_get_ns();
    event->cpu =  bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    return event;
}

int trace__recv_upcall(struct pt_regs *ctx) {
    uint32_t upcall_type;
    uint64_t addr;
    uint64_t size;

    bpf_usdt_readarg(2, ctx, &upcall_type);
    if (upcall_type != 0)
        return 0;

    struct event_t *event = init_event(EVENT_RECV_UPCALL);
    if (!event)
        return 1;

    bpf_usdt_readarg(1, ctx, &addr);
    bpf_probe_read_str(&event->dpif_name, sizeof(event->dpif_name),
                       (void *)addr);

    event->upcall_type = upcall_type;
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


int trace__op_flow_put(struct pt_regs *ctx) {
    uint64_t addr;
    uint64_t size;

    struct event_t *event = init_event(EVENT_OP_FLOW_PUT);
    if (!event) {
        return 1;
    }

    events.ringbuf_submit(event, 0);
    return 0;
};


int trace__op_flow_execute(struct pt_regs *ctx) {
    uint64_t addr;
    uint64_t size;

    struct event_t *event = init_event(EVENT_OP_FLOW_EXECUTE);
    if (!event) {
        return 1;
    }

    bpf_usdt_readarg(4, ctx, &event->pkt_size);

    if (event->pkt_size > MAX_PACKET)
        size = MAX_PACKET;
    else
        size = event->pkt_size;
    bpf_usdt_readarg(3, ctx, &addr);
    bpf_probe_read(&event->pkt, size, (void *)addr);

    events.ringbuf_submit(event, 0);
    return 0;
};


TRACEPOINT_PROBE(openvswitch, ovs_dp_upcall) {
    uint64_t size;
    struct sk_buff *skb = args->skbaddr;

    if (args->upcall_cmd != 1 || skb == NULL || skb->data == NULL)
        return 0;

    struct event_t *event = init_event(EVENT_DP_UPCALL);
    if (!event) {
        return 1;
    }

    event->upcall_type = args->upcall_cmd;
    event->pkt_size = args->len;

    TP_DATA_LOC_READ_CONST(&event->dpif_name, dp_name,
                           sizeof(event->dpif_name));
    TP_DATA_LOC_READ_CONST(&event->dev_name, dev_name,
                           sizeof(event->dev_name));

    if (skb->data_len != 0) {
        event->pkt_frag_size = (skb->len - skb->data_len) & 0xfffffff;
        size = event->pkt_frag_size;
    } else {
        event->pkt_frag_size = 0;
        size = event->pkt_size;
    }

    /* Prevent clang from using register mirroring (or any optimization) on
     * the 'size' variable. */
    barrier_var(size);

    if (size > MAX_PACKET)
        size = MAX_PACKET;
    bpf_probe_read_kernel(event->pkt, size, skb->data);

    events.ringbuf_submit(event, 0);
    return 0;
}

int kprobe__ovs_packet_cmd_execute(struct pt_regs *ctx, struct sk_buff *skb)
{
    uint64_t size;

    if (skb == NULL || skb->data == NULL)
        return 0;

    struct event_t *event = init_event(EVENT_OVS_PKT_EXEC);
    if (!event) {
        return 1;
    }

    events.ringbuf_submit(event, 0);
    return 0;
}
"""


#
# Event types
#
class EventType(StrEnum):
    RECV_UPCALL = 'dpif_recv__recv_upcall'
    DP_UPCALL = 'openvswitch__dp_upcall'
    OP_FLOW_PUT = 'dpif_netlink_operate__op_flow_put'
    OP_FLOW_EXECUTE = 'dpif_netlink_operate__op_flow_execute'
    OVS_PKT_EXEC = 'ktrace__ovs_packet_cmd_execute'

    def short_name(name, length=22):
        if len(name) < length:
            return name

        return '..' + name[-(length - 2):]

    def from_trace(trace_event):
        if trace_event == 0:
            return EventType.RECV_UPCALL
        elif trace_event == 1:
            return EventType.DP_UPCALL
        elif trace_event == 2:
            return EventType.OP_FLOW_PUT
        elif trace_event == 3:
            return EventType.OP_FLOW_EXECUTE
        elif trace_event == 4:
            return EventType.OVS_PKT_EXEC

        raise ValueError


#
# Simple event class
#
class Event(object):
    def __init__(self, ts, pid, comm, cpu, event_type):
        self.ts = ts
        self.pid = pid
        self.comm = comm
        self.cpu = cpu
        self.event_type = event_type

    def __str__(self):
        return "[{:<22}] {:<16} {:8} [{:03}] {:18.9f}".format(
            EventType.short_name(self.event_type),
            self.comm,
            self.pid,
            self.cpu,
            self.ts / 1000000000)

    def __repr__(self):
        more = ""
        if self.__class__.__name__ != "Event":
            more = ", ..."

        return "{}({}, {}, {}, {}, {}{})".format(self.__class__.__name__,
                                                 self.ts, self.pid,
                                                 self.comm, self.cpu,
                                                 self.event_type, more)

    def handle_event(event):
        event = Event(event.ts, event.pid, event.comm.decode("utf-8"),
                      event.cpu, EventType.from_trace(event.event))

        if not options.quiet:
            print(event)

        return event

    def get_event_header_str():
        return "{:<24} {:<16} {:>8}  {:<3}  {:<18}  {}".format(
            "EVENT", "COMM", "PID", "CPU", "TIME",
            "EVENT DATA[dpif_name/dp_port/pkt_len/pkt_frag_len]")


#
# dp_upcall event class
#
class DpUpcall(Event):
    def __init__(self, ts, pid, comm, cpu, dpif_name, port, pkt, pkt_len,
                 pkt_frag_len):
        super(DpUpcall, self).__init__(ts, pid, comm, cpu, EventType.DP_UPCALL)
        self.dpif_name = dpif_name
        self.dp_port = dp_map.get(dpif_name, port)
        if self.dp_port is None:
            #
            # As we only identify interfaces at startup, new interfaces could
            # have been added, causing the lookup to fail. Just something to
            # keep in mind when running this in a dynamic environment.
            #
            raise LookupError("Can't find datapath port mapping!")
        self.pkt = pkt
        self.pkt_len = pkt_len
        self.pkt_frag_len = pkt_frag_len

    def __str__(self):
        return "[{:<22}] {:<16} {:8} [{:03}] {:18.9f}: " \
               "{:<17} {:4} {:4} {:4}".format(self.event_type,
                                              self.comm,
                                              self.pid,
                                              self.cpu,
                                              self.ts / 1000000000,
                                              self.dpif_name,
                                              self.dp_port,
                                              self.pkt_len,
                                              self.pkt_frag_len)

    def handle_event(event):
        if event.pkt_size < options.packet_size:
            pkt_len = event.pkt_size
        else:
            pkt_len = options.packet_size

        pkt_data = bytes(event.pkt)[:pkt_len]

        if len(pkt_data) <= 0 or event.pkt_size == 0:
            return

        try:
            event = DpUpcall(event.ts, event.pid, event.comm.decode("utf-8"),
                             event.cpu, event.dpif_name.decode("utf-8"),
                             event.dev_name.decode("utf-8"),
                             pkt_data,
                             event.pkt_size,
                             event.pkt_frag_size)
        except LookupError:
            #
            # If we can't do the port lookup, ignore this event.
            #
            return None

        if not options.quiet:
            print(event)

        return event


#
# recv_upcall event class
#
class RecvUpcall(Event):
    def __init__(self, ts, pid, comm, cpu, dpif_name, key, pkt, pkt_len):
        super(RecvUpcall, self).__init__(ts, pid, comm, cpu,
                                         EventType.RECV_UPCALL)

        if dpif_name.startswith("system@"):
            dpif_name = dpif_name[len("system@"):]
        self.dpif_name = dpif_name

        nla = RecvUpcall.decode_nlm(key, dump=False)
        if "OVS_KEY_ATTR_IN_PORT" in nla:
            self.dp_port = struct.unpack('=L', nla["OVS_KEY_ATTR_IN_PORT"])[0]
        elif "OVS_KEY_ATTR_TUNNEL" in nla:
            self.dp_port = DP_TUNNEL_PORT
        else:
            self.dp_port = RecvUpcall.get_system_dp_port(self.dpif_name)

        if self.dp_port is None:
            raise LookupError("Can't find RecvUpcall dp port mapping!")

        self.pkt = pkt
        self.pkt_len = pkt_len

    def __str__(self):
        return "[{:<22}] {:<16} {:8} [{:03}] {:18.9f}: {:<17} {:4} {:4}". \
            format(
                self.event_type,
                self.comm,
                self.pid,
                self.cpu,
                self.ts / 1000000000,
                self.dpif_name,
                self.dp_port,
                self.pkt_len)

    def get_system_dp_port(dpif_name):
        return dp_map.get_map().get(dpif_name, {}).get("ovs-system", None)

    def decode_nlm(msg, indent=4, dump=True):
        bytes_left = len(msg)
        result = {}

        while bytes_left:
            if bytes_left < 4:
                if dump:
                    print("{}WARN: decode truncated; can't read header".format(
                        ' ' * indent))
                break

            nla_len, nla_type = struct.unpack("=HH", msg[:4])

            if nla_len < 4:
                if dump:
                    print("{}WARN: decode truncated; nla_len < 4".format(
                        ' ' * indent))
                break

            nla_data = msg[4:nla_len]
            trunc = ""

            if nla_len > bytes_left:
                trunc = "..."
                nla_data = nla_data[:(bytes_left - 4)]
                if RecvUpcall.get_ovs_key_attr_str(nla_type) == \
                   "OVS_KEY_ATTR_TUNNEL":
                    #
                    # If we have truncated tunnel information, we still would
                    # like to know. This is due to the special tunnel handling
                    # needed for port matching.
                    #
                    result[RecvUpcall.get_ovs_key_attr_str(nla_type)] = bytes()
            else:
                result[RecvUpcall.get_ovs_key_attr_str(nla_type)] = nla_data

            if dump:
                print("{}nla_len {}, nla_type {}[{}], data: {}{}".format(
                    ' ' * indent, nla_len,
                    RecvUpcall.get_ovs_key_attr_str(nla_type),
                    nla_type,
                    "".join("{:02x} ".format(b) for b in nla_data), trunc))

            if trunc != "":
                if dump:
                    print("{}WARN: decode truncated; nla_len > msg_len[{}] ".
                          format(' ' * indent, bytes_left))
                break

            # Update next offset, but make sure it's aligned correctly.
            next_offset = (nla_len + 3) & ~(3)
            msg = msg[next_offset:]
            bytes_left -= next_offset

        return result

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

    def handle_event(event):
        #
        # For us, only upcalls with a packet, flow_key, and upcall_type
        # DPIF_UC_MISS are of interest.
        #
        if event.pkt_size <= 0 or event.key_size <= 0 or \
           event.upcall_type != 0:
            return

        if event.key_size < options.flow_key_size:
            key_len = event.key_size
        else:
            key_len = options.flow_key_size

        if event.pkt_size < options.packet_size:
            pkt_len = event.pkt_size
        else:
            pkt_len = options.packet_size

        try:
            event = RecvUpcall(event.ts, event.pid, event.comm.decode("utf-8"),
                               event.cpu, event.dpif_name.decode("utf-8"),
                               bytes(event.key)[:key_len],
                               bytes(event.pkt)[:pkt_len],
                               event.pkt_size)
        except LookupError:
            return None

        if not options.quiet:
            print(event)

        return event


#
# op_flow_execute event class
#
class OpFlowExecute(Event):
    def __init__(self, ts, pid, comm, cpu, pkt, pkt_len):
        super(OpFlowExecute, self).__init__(ts, pid, comm, cpu,
                                            EventType.OP_FLOW_EXECUTE)
        self.pkt = pkt
        self.pkt_len = pkt_len

    def __str__(self):
        return "[{:<22}] {:<16} {:8} [{:03}] {:18.9f}: " \
               "{:<17} {:4} {:4}".format(EventType.short_name(self.event_type),
                                         self.comm,
                                         self.pid,
                                         self.cpu,
                                         self.ts / 1000000000,
                                         "",
                                         "",
                                         self.pkt_len)

    def handle_event(event):
        if event.pkt_size < options.packet_size:
            pkt_len = event.pkt_size
        else:
            pkt_len = options.packet_size

        pkt_data = bytes(event.pkt)[:pkt_len]

        if len(pkt_data) <= 0 or event.pkt_size == 0:
            return

        event = OpFlowExecute(event.ts, event.pid, event.comm.decode("utf-8"),
                              event.cpu, pkt_data, event.pkt_size)

        if not options.quiet:
            print(event)

        return event


#
# event_to_dict()
#
def event_to_dict(event):
    event_dict = {}

    for field, _ in event._fields_:
        if isinstance(getattr(event, field), (int, bytes)):
            event_dict[field] = getattr(event, field)
        else:
            if (field == "key" and event.key_size == 0) or \
               (field == "pkt" and event.pkt_size == 0):
                data = bytes()
            else:
                data = bytes(getattr(event, field))

            event_dict[field] = data

    return event_dict


#
# receive_event_bcc()
#
def receive_event_bcc(ctx, data, size):
    global events_received
    events_received += 1

    event = b['events'].event(data)

    if export_file is not None:
        export_file.write("event = {}\n".format(event_to_dict(event)))

    receive_event(event)


#
# receive_event()
#
def receive_event(event):
    global event_count

    if event.event == 0:
        trace_event = RecvUpcall.handle_event(event)
    elif event.event == 1:
        trace_event = DpUpcall.handle_event(event)
    elif event.event == 2:
        trace_event = Event.handle_event(event)
    elif event.event == 3:
        trace_event = OpFlowExecute.handle_event(event)
    elif event.event == 4:
        trace_event = Event.handle_event(event)

    try:
        event_count['total'][EventType.from_trace(event.event)] += 1
    except KeyError:
        event_count['total'][EventType.from_trace(event.event)] = 1
        event_count['valid'][EventType.from_trace(event.event)] = 0

    if trace_event is not None:
        event_count['valid'][EventType.from_trace(event.event)] += 1
        trace_data.append(trace_event)


#
# collect_event_sets()
#
def collect_event_sets(events, collect_stats=False, profile=False,
                       spinner=False):
    t1_time = 0

    def t1_start():
        nonlocal t1_time
        t1_time = process_time()

    def t1_stop(description):
        print("* PROFILING: {:<50}: {:.06f} seconds".format(
            description, process_time() - t1_time))

    warn_parcial_match = False
    warn_frag = False

    if profile:
        t1_start()
    #
    # First let's create a dict of per handler thread events.
    #
    threads = {}
    threads_result = {}
    for idx, event in enumerate(events):
        if event.event_type == EventType.DP_UPCALL:
            continue
        if event.pid not in threads:
            threads[event.pid] = []
        threads[event.pid].append([idx, event])

    if profile:
        t1_stop("Creating per thread dictionary")
        t1_start()
    #
    # Now spit them in per upcall sets, but remember that
    # RecvUpcall event can be batched.
    #
    batch_stats = []
    for thread, items in threads.items():
        thread_set = []
        batch = []
        ovs_pkt_exec_set = []
        batching = True
        collecting = 0
        has_flow_put = False
        has_flow_exec = False

        def next_batch():
            nonlocal batching, batch, collecting, has_flow_put, has_flow_exec
            nonlocal ovs_pkt_exec_set, thread_set

            if len(batch) > 0:
                #
                # If we are done with the batch, see if we need to match up
                # any batched OVS_PKT_EXEC events.
                #
                for event in batch:
                    if len(ovs_pkt_exec_set) <= 0:
                        break
                    if any(isinstance(item,
                                      OpFlowExecute) for item in event[2]):
                        event[2].append(ovs_pkt_exec_set.pop(0))
                #
                # Append the batch to the thread-specific set.
                #
                thread_set = thread_set + batch
                if collect_stats:
                    batch_stats.append(len(batch))
            batching = True
            batch = []
            ovs_pkt_exec_set = []
            has_flow_put = False
            has_flow_exec = False
            collecting = 0

        def next_batch_set():
            nonlocal has_flow_put, has_flow_exec, collecting
            has_flow_put = False
            has_flow_exec = False
            collecting += 1

        for item in items:
            idx, event = item

            if batching:
                if event.event_type == EventType.RECV_UPCALL:
                    batch.append(item + [[]])
                elif len(batch) > 0:
                    batching = False
                    collecting = 0
                else:
                    continue

            if not batching:
                if event.event_type == EventType.RECV_UPCALL:
                    next_batch()
                    batch.append(item + [[]])
                else:
                    if event.event_type == EventType.OP_FLOW_PUT:
                        if has_flow_put:
                            next_batch_set()
                            if collecting >= len(batch):
                                next_batch()
                                continue

                        batch[collecting][2].append(item[1])
                        has_flow_put = True

                    elif event.event_type == EventType.OP_FLOW_EXECUTE:
                        if has_flow_exec:
                            next_batch_set()
                            if collecting >= len(batch):
                                next_batch()
                                continue

                        if (event.pkt_len == batch[collecting][1].pkt_len
                           and event.pkt == batch[collecting][1].pkt):
                            batch[collecting][2].append(item[1])
                            has_flow_put = True
                            has_flow_exec = True
                        else:
                            #
                            # If we end up here it could be that an upcall in a
                            # batch did not generate an EXECUTE and we are out
                            # of sync. Try to match it to the next batch entry.
                            #
                            next_idx = collecting + 1
                            while True:
                                if next_idx >= len(batch):
                                    next_batch()
                                    break
                                if (event.pkt_len == batch[next_idx][1].pkt_len
                                   and event.pkt == batch[next_idx][1].pkt):

                                    batch[next_idx][2] = batch[collecting][2]
                                    batch[collecting][2] = []
                                    collecting = next_idx
                                    batch[collecting][2].append(item[1])
                                    has_flow_put = True
                                    has_flow_exec = True
                                    break

                                next_idx += 1

                    elif event.event_type == EventType.OVS_PKT_EXEC:
                        #
                        # The OVS_PKT_EXEC might also be batched, so we keep
                        # them in a separate list and assign them to the
                        # correct set when completing the set.
                        #
                        ovs_pkt_exec_set.append(item[1])
                        continue

                    if collecting >= len(batch):
                        next_batch()
        next_batch()
        threads_result[thread] = thread_set

    if profile:
        t1_stop("Creating upcall sets")
        t1_start()

    #
    # Move thread results from list to dictionary
    #
    thread_stats = {}
    for thread, sets in threads_result.items():
        if len(sets) > 0:
            thread_stats[sets[0][1].comm] = len(sets)

        threads_result[thread] = {}
        for upcall in sets:
            threads_result[thread][upcall[0]] = [upcall[1]] + upcall[2]

    if profile:
        t1_stop("Moving upcall list to dictionary")
        t1_start()

    if options.debug & 0x4000000 != 0:
        print()
        for thread, sets in threads_result.items():
            for idx, idx_set in sets.items():
                print("DBG: {}".format(idx_set))

    #
    # Create two lists on with DP_UPCALLs and RECV_UPCALLs
    #
    dp_upcall_list = []
    recv_upcall_list = []
    for idx, event in enumerate(events):
        if event.event_type == EventType.DP_UPCALL:
            dp_upcall_list.append([idx, event])
        elif event.event_type == EventType.RECV_UPCALL:
            recv_upcall_list.append([idx, event])

    if profile:
        t1_stop("Creating DP_UPCALL and RECV_UPCALL lists")
        t1_start()

    if options.debug & 0x4000000 != 0:
        print()
        for dp_upcall in dp_upcall_list:
            print("DBG: {}".format(dp_upcall))
        print()
        for recv_upcall in recv_upcall_list:
            print("DBG: {}".format(recv_upcall))

    #
    # Now find the matching DP_UPCALL and RECV_UPCALL events
    #
    event_sets = []
    if spinner:
        print()
    with alive_bar(len(dp_upcall_list),
                   title="- Matching DP_UPCALLs to RECV_UPCALLs",
                   spinner=None, disable=not spinner) as bar:

        for (idx, event) in dp_upcall_list:
            remove_indexes = []
            this_set = None
            #
            # TODO: This part needs some optimization, as it's slow in the
            #       PVP test scenario. This is because a lot of DP_UPCALLS
            #       will not have a matching RECV_UPCALL leading to walking
            #       the entire recv_upcall_list list.
            #
            #       Probably some dictionary, but in the PVP scenario packets
            #       come from a limited set of ports, and the length is all the
            #       same. So we do need the key to be recv.dport +
            #       len(recv.pkt) + recv.pkt, however, the recv.pkt compare
            #       needs to happen on  min(len(event.pkt), len(recv.pkt)).
            #
            for idx_in_list, (idx_recv, recv) in enumerate(recv_upcall_list):
                match = False

                if idx_recv < idx:
                    remove_indexes.append(idx_in_list)
                    continue
                #
                # If the RecvUpcall is a tunnel port, we can not map it to
                # the correct tunnel. For now, we assume the first matching
                # packet is the correct one. For more details see the OVS
                # ukey_to_flow_netdev() function.
                #
                if (event.dp_port == recv.dp_port or
                    recv.dp_port == DP_TUNNEL_PORT) \
                   and event.pkt_len == recv.pkt_len:

                    compare_len = min(len(event.pkt), len(recv.pkt))

                    if len(event.pkt) != len(recv.pkt) \
                       and event.pkt_frag_len == 0:
                        warn_parcial_match = True
                    elif event.pkt_frag_len != 0:
                        warn_frag = True
                        compare_len = min(compare_len, event.pkt_frag_len)

                    if event.pkt[:compare_len] == recv.pkt[:compare_len]:
                        match = True
                    else:
                        #
                        # There are still some corner cases due to the fact
                        # the kernel dp_upcall tracepoint is hit before the
                        # packet is prepared/modified for upcall pass on.
                        # Example cases are packet checksum update, VLAN
                        # insertion, etc., etc. For now, we try to handle the
                        # checksum part, but we might need to add more
                        # exceptions in the future.
                        #
                        diff_bytes = sum(i != j for i, j in zip(
                            event.pkt[:compare_len], recv.pkt[:compare_len]))

                        if diff_bytes <= 2 and compare_len > 56:
                            # This could be a TCP or UDP checksum
                            event_pkt = Ether(bytes(event.pkt)[:compare_len])
                            recv_pkt = Ether(bytes(recv.pkt)[:compare_len])
                            if (event_pkt.haslayer(TCP) and
                                recv_pkt.haslayer(TCP)) or (
                                    event_pkt.haslayer(UDP) and
                                    recv_pkt.haslayer(UDP)):

                                if event_pkt.haslayer(TCP):
                                    event_chksum = event_pkt[TCP].chksum
                                    recv_chksum = recv_pkt[TCP].chksum
                                else:
                                    event_chksum = event_pkt[UDP].chksum
                                    recv_chksum = recv_pkt[UDP].chksum

                                if event_chksum & 0xff != recv_chksum & 0xff:
                                    diff_bytes -= 1
                                if event_chksum & 0xff00 != \
                                   recv_chksum & 0xff00:
                                    diff_bytes -= 1

                        if diff_bytes == 0:
                            match = True

                    if match:
                        this_set = {event.event_type: event}
                        for sevent in threads_result[recv.pid][idx_recv]:
                            this_set[sevent.event_type] = sevent
                        event_sets.append(this_set)
                        remove_indexes.append(idx_in_list)

                        if options.debug & 0x4000000 != 0:
                            print("DBG: Matched DpUpcall({:6}) => "
                                  "RecvUpcall({:6})".format(idx, idx_recv))

                        break

                    elif options.debug & 0x8000000 != 0:
                        print("DBG: COMPARE DpUpcall({:6}) != "
                              "RecvUpcall({:6})".format(idx, idx_recv))
                        event_pkt = Ether(bytes(event.pkt)[:compare_len])
                        recv_pkt = Ether(bytes(recv.pkt)[:compare_len])
                        print(re.sub('^', 'DBG:' + ' ' * 4,
                                     event_pkt.show(dump=True),
                                     flags=re.MULTILINE))
                        print(re.sub('^', 'DBG:' + ' ' * 4,
                                     recv_pkt.show(dump=True),
                                     flags=re.MULTILINE))

                elif options.debug & 0x8000000 != 0:
                    print("DBG: COMPATE DpUpcall({:6}) != "
                          "RecvUpcall({:6}) -> port {}, {} -> "
                          "len = {}, {}".format(idx, idx_recv,
                                                event.dp_port,
                                                recv.dp_port,
                                                event.pkt_len,
                                                recv.pkt_len))

            bar()
            for remove_idx in sorted(remove_indexes, reverse=True):
                del recv_upcall_list[remove_idx]

    if profile:
        t1_stop("Matching DP_UPCALLs to a set")

    if warn_parcial_match:
        print("WARNING: Packets not fully captured for matching!\n         "
              "Increase the packet buffer with the '--packet-size' option.")
    if warn_frag:
        print("WARNING: SKB from kernel had fragments, we could only copy/"
              "compare the first part!")

    if collect_stats:
        return event_sets, batch_stats, thread_stats

    return event_sets


#
# unit_test()
#
def unit_test():
    pkt1 = b'\x01\x02\x03\x04\x05'
    pkt2 = b'\x01\x02\x03\x04\x06'
    pkt3 = b'\x01\x02\x03\x04\x07'
    key = b'\x08\x00\x03\x00\x01\x00\x00\x00'  # Port 1
    #
    # Basic test with all events in line
    #
    t1_events = [DpUpcall(1, 100, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 RecvUpcall(2, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 Event(3, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(4, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(5, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t1_result = [{EventType.DP_UPCALL: t1_events[0],
                  EventType.RECV_UPCALL: t1_events[1],
                  EventType.OP_FLOW_PUT: t1_events[2],
                  EventType.OP_FLOW_EXECUTE: t1_events[3],
                  EventType.OVS_PKT_EXEC: t1_events[4]}]
    #
    # Basic test with missing flow put
    #
    t2_events = [DpUpcall(1, 100, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 RecvUpcall(2, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 OpFlowExecute(4, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(5, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t2_result = [{EventType.DP_UPCALL: t2_events[0],
                  EventType.RECV_UPCALL: t2_events[1],
                  EventType.OP_FLOW_EXECUTE: t2_events[2],
                  EventType.OVS_PKT_EXEC: t2_events[3]}]
    #
    # Test with RecvUpcall's being batched
    #
    t3_events = [DpUpcall(1, 101, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 DpUpcall(2, 102, "ping", 2, "system", 1, pkt2, len(pkt2), 0),
                 DpUpcall(3, 101, "ping", 3, "system", 1, pkt3, len(pkt3), 0),
                 RecvUpcall(4, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 RecvUpcall(5, 1, "hndl", 1, "systen", key, pkt3, len(pkt3)),
                 RecvUpcall(6, 1, "hndl", 1, "systen", key, pkt2, len(pkt2)),
                 Event(7, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(8, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(9, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(10, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(11, 1, "hndl", 1, pkt3, len(pkt3)),
                 Event(12, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(13, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(14, 1, "hndl", 1, pkt2, len(pkt2)),
                 Event(15, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t3_result = [{EventType.DP_UPCALL: t3_events[0],
                  EventType.RECV_UPCALL: t3_events[3],
                  EventType.OP_FLOW_PUT: t3_events[6],
                  EventType.OP_FLOW_EXECUTE: t3_events[7],
                  EventType.OVS_PKT_EXEC: t3_events[8]},
                 {EventType.DP_UPCALL: t3_events[1],
                  EventType.RECV_UPCALL: t3_events[5],
                  EventType.OP_FLOW_PUT: t3_events[12],
                  EventType.OP_FLOW_EXECUTE: t3_events[13],
                  EventType.OVS_PKT_EXEC: t3_events[14]},
                 {EventType.DP_UPCALL: t3_events[2],
                  EventType.RECV_UPCALL: t3_events[4],
                  EventType.OP_FLOW_PUT: t3_events[9],
                  EventType.OP_FLOW_EXECUTE: t3_events[10],
                  EventType.OVS_PKT_EXEC: t3_events[11]}]
    #
    # Test with RecvUpcall's single + batch
    #
    t4_events = [DpUpcall(1, 100, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 RecvUpcall(2, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 Event(3, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(4, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(5, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 DpUpcall(6, 101, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 DpUpcall(7, 102, "ping", 2, "system", 1, pkt2, len(pkt2), 0),
                 DpUpcall(8, 101, "ping", 3, "system", 1, pkt3, len(pkt3), 0),
                 RecvUpcall(9, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 RecvUpcall(10, 1, "hndl", 1, "systen", key, pkt3, len(pkt3)),
                 RecvUpcall(11, 1, "hndl", 1, "systen", key, pkt2, len(pkt2)),
                 Event(12, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(13, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(14, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(15, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(16, 1, "hndl", 1, pkt3, len(pkt3)),
                 Event(17, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(18, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(14, 1, "hndl", 1, pkt2, len(pkt2)),
                 Event(19, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t4_result = [{EventType.DP_UPCALL: t4_events[0],
                  EventType.RECV_UPCALL: t4_events[1],
                  EventType.OP_FLOW_PUT: t4_events[2],
                  EventType.OP_FLOW_EXECUTE: t4_events[3],
                  EventType.OVS_PKT_EXEC: t4_events[4]},
                 {EventType.DP_UPCALL: t4_events[5],
                  EventType.RECV_UPCALL: t4_events[8],
                  EventType.OP_FLOW_PUT: t4_events[11],
                  EventType.OP_FLOW_EXECUTE: t4_events[12],
                  EventType.OVS_PKT_EXEC: t4_events[13]},
                 {EventType.DP_UPCALL: t4_events[6],
                  EventType.RECV_UPCALL: t4_events[10],
                  EventType.OP_FLOW_PUT: t4_events[17],
                  EventType.OP_FLOW_EXECUTE: t4_events[18],
                  EventType.OVS_PKT_EXEC: t4_events[19]},
                 {EventType.DP_UPCALL: t4_events[7],
                  EventType.RECV_UPCALL: t4_events[9],
                  EventType.OP_FLOW_PUT: t4_events[14],
                  EventType.OP_FLOW_EXECUTE: t4_events[15],
                  EventType.OVS_PKT_EXEC: t4_events[16]}]
    #
    # Test with two threads interleaved
    #
    t5_events = [DpUpcall(1, 100, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 DpUpcall(2, 100, "ping", 1, "system", 1, pkt2, len(pkt2), 0),
                 RecvUpcall(3, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 RecvUpcall(4, 2, "hndl", 2, "systen", key, pkt2, len(pkt2)),
                 Event(5, 2, "hndl", 2, EventType.OP_FLOW_PUT),
                 Event(6, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(7, 2, "hndl", 1, pkt2, len(pkt2)),
                 OpFlowExecute(8, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(9, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(10, 2, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t5_result = [{EventType.DP_UPCALL: t5_events[0],
                  EventType.RECV_UPCALL: t5_events[2],
                  EventType.OP_FLOW_PUT: t5_events[5],
                  EventType.OP_FLOW_EXECUTE: t5_events[7],
                  EventType.OVS_PKT_EXEC: t5_events[8]},
                 {EventType.DP_UPCALL: t5_events[1],
                  EventType.RECV_UPCALL: t5_events[3],
                  EventType.OP_FLOW_PUT: t5_events[4],
                  EventType.OP_FLOW_EXECUTE: t5_events[6],
                  EventType.OVS_PKT_EXEC: t5_events[9]}]
    #
    # Test batch with missing events
    #
    t6_events = [DpUpcall(1, 101, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 DpUpcall(2, 102, "ping", 2, "system", 1, pkt2, len(pkt2), 0),
                 RecvUpcall(3, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 RecvUpcall(4, 1, "hndl", 1, "systen", key, pkt2, len(pkt2)),
                 Event(5, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(6, 1, "hndl", 1, pkt2, len(pkt2)),
                 Event(7, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t6_result = [{EventType.DP_UPCALL: t6_events[0],
                  EventType.RECV_UPCALL: t6_events[2]},
                 {EventType.DP_UPCALL: t6_events[1],
                  EventType.RECV_UPCALL: t6_events[3],
                  EventType.OP_FLOW_PUT: t6_events[4],
                  EventType.OP_FLOW_EXECUTE: t6_events[5],
                  EventType.OVS_PKT_EXEC: t6_events[6]}]
    #
    # Test with RecvUpcall's and OVS_PKT_EXEC being batched
    #
    t7_events = [DpUpcall(1, 101, "ping", 1, "system", 1, pkt1, len(pkt1), 0),
                 DpUpcall(2, 102, "ping", 2, "system", 1, pkt2, len(pkt2), 0),
                 DpUpcall(3, 101, "ping", 3, "system", 1, pkt3, len(pkt3), 0),
                 RecvUpcall(4, 1, "hndl", 1, "systen", key, pkt1, len(pkt1)),
                 RecvUpcall(5, 1, "hndl", 1, "systen", key, pkt2, len(pkt2)),
                 RecvUpcall(6, 1, "hndl", 1, "systen", key, pkt3, len(pkt3)),
                 Event(7, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(8, 1, "hndl", 1, pkt1, len(pkt1)),
                 Event(9, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(10, 1, "hndl", 1, pkt2, len(pkt2)),
                 Event(11, 1, "hndl", 1, EventType.OP_FLOW_PUT),
                 OpFlowExecute(12, 1, "hndl", 1, pkt3, len(pkt3)),
                 Event(13, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(14, 1, "hndl", 1, EventType.OVS_PKT_EXEC),
                 Event(15, 1, "hndl", 1, EventType.OVS_PKT_EXEC)]
    t7_result = [{EventType.DP_UPCALL: t7_events[0],
                  EventType.RECV_UPCALL: t7_events[3],
                  EventType.OP_FLOW_PUT: t7_events[6],
                  EventType.OP_FLOW_EXECUTE: t7_events[7],
                  EventType.OVS_PKT_EXEC: t7_events[12]},
                 {EventType.DP_UPCALL: t7_events[1],
                  EventType.RECV_UPCALL: t7_events[4],
                  EventType.OP_FLOW_PUT: t7_events[8],
                  EventType.OP_FLOW_EXECUTE: t7_events[9],
                  EventType.OVS_PKT_EXEC: t7_events[13]},
                 {EventType.DP_UPCALL: t7_events[2],
                  EventType.RECV_UPCALL: t7_events[5],
                  EventType.OP_FLOW_PUT: t7_events[10],
                  EventType.OP_FLOW_EXECUTE: t7_events[11],
                  EventType.OVS_PKT_EXEC: t7_events[14]}]
    #
    # Actual test sets
    #
    test_set = [["Simple single event", t1_events, t1_result],
                ["Single event, missing flow_put", t2_events, t2_result],
                ["Batched events", t3_events, t3_result],
                ["Single + batched events", t4_events, t4_result],
                ["Two sets, different threads", t5_events, t5_result],
                ["Batch with missing exec", t6_events, t6_result],
                ["Batched events including exec", t7_events, t7_result]]

    print("Running some simple unit tests:")

    for test in test_set:
        print("- {:<32}  ".format(test[0]), end="")
        result = collect_event_sets(test[1][:])
        if result == test[2]:
            print("PASS")
        else:
            print("FAIL")
            print("  OUTPUT  :")
            for event_set in result:
                hdr = "    - "
                for event_type, event in event_set.items():
                    print("{} {:<16}: {}".format(hdr, event_type.name, event))
                    hdr = "      "
            print("  EXPECTED:")
            for event_set in test[2]:
                hdr = "    - "
                for event_type, event in event_set.items():
                    print("{} {:<16}: {}".format(hdr, event_type.name, event))
                    hdr = "      "


#
# show_key_value()
#
def show_key_value(data_set, description=None):
    if description is not None:
        print("\n=> {}:".format(description))

    for k, v in data_set.items():
        print("  {:36}: {:>10}".format(str(k), str(v)))


#
# show_batch_histogram()
#
def show_batch_histogram(data_set, description=None):
    nr_of_buckets = 64

    if description is not None:
        print("\n=> {}:".format(description))

    if len(data_set) == 0:
        print("# NumSamples = 0")
        return

    min_val = nr_of_buckets
    max_val = 0
    entries = 0
    high_buckets = 0
    buckets = [0] * nr_of_buckets

    for entry in data_set:
        min_val = min(min_val, entry)
        max_val = max(max_val, entry)
        if entry == 0:
            continue
        elif entry > nr_of_buckets:
            high_buckets += 1
        else:
            buckets[entry - 1] += 1

        entries += 1

    if max(buckets + [high_buckets]) > 4:
        scale = int(max(buckets + [high_buckets]) / 4)
    else:
        scale = 1

    print("# NumSamples = {}; Min = {}; Max = {}".format(entries, min_val,
                                                         max_val))
    print("# each ∎ represents a count of {}".format(scale))

    for idx in range(int(nr_of_buckets / 2)):
        idx_2nd = idx + int(nr_of_buckets / 2)
        print("{:5} [{:8}]: {:22}  {:5} [{:8}]: {:22}".format(
            idx + 1, buckets[idx], "∎" * int(buckets[idx] / scale),
            idx_2nd + 1, buckets[idx_2nd],
            "∎" * int(buckets[idx_2nd] / scale)))

    if high_buckets > 0:
        print("{:>5} [{:8}]: {:22}".format(">" + str(nr_of_buckets),
                                           high_buckets,
                                           "∎" * int(high_buckets / scale)))


#
# show_histogram()
#
def show_histogram(data_set, description=None, options=None,
                   minimum=None, maximum=None, buckets=None, custbuckets=None):
    if description is not None:
        print("\n=> {}:".format(description))

    if options is not None:
        if buckets is None:
            buckets = options.histogram_buckets
        if options is not None and options.sets:
            print(data_set)

    if len(data_set) == 0:
        print("# NumSamples = 0")
    elif len(data_set) == 1:
        print("# NumSamples = 1; Min = {0:.4f}; Max = {0:.4f}".
              format(data_set[0]))
    elif len(set(data_set)) == 1 and maximum is None and minimum is None and \
            custbuckets is None:
        histogram(data_set, buckets=buckets, minimum=list(set(data_set))[0],
                  maximum=list(set(data_set))[0] + 1)
    else:
        histogram(data_set, buckets=buckets,
                  minimum=minimum, maximum=maximum, custbuckets=custbuckets)


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
    global trace_data
    global events_received
    global event_count
    global export_file
    global dp_map

    dp_map = DpPortMapping()

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("-b", "--histogram-buckets",
                        help="Number of buckets per histogram, default 20",
                        type=int, default=20, metavar="BUCKETS")
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=lambda x: int(x, 0), const=0x3f, default=0,
                        nargs='?')
    parser.add_argument("-f", "--flow-key-size",
                        help="Set maximum flow key size to capture, "
                        "default 64", type=buffer_size_type, default=64,
                        metavar="[64-2048]")
    parser.add_argument("--handler-filter",
                        help="Post processing handler thread filter",
                        type=str, default=None, metavar="HANDLERS")
    parser.add_argument("-P", "--packet-size",
                        help="Set maximum packet size to capture, "
                        "default 256", type=buffer_size_type, default=256,
                        metavar="[64-2048]")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitch's PID",
                        type=int, default=None)
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Do not show individual events")
    parser.add_argument("-r", "--read-events",
                        help="Read events from FILE instead of installing "
                        "tracepoints", type=str, default=None, metavar="FILE")
    parser.add_argument("--sets", action="store_true",
                        help="Dump content of data sets")
    parser.add_argument("-s", "--stop",
                        help="Stop after receiving EVENTS number of trace "
                        "events",
                        type=int, default=0, metavar="EVENTS")
    parser.add_argument("--unit-test", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("-w", "--write-events",
                        help="Write events to FILE",
                        type=str, default=None, metavar="FILE")

    options = parser.parse_args()

    if options.unit_test:
        unit_test()
        sys.exit(0)

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if options.pid is None and options.read_events is None:
        for proc in psutil.process_iter():
            if 'ovs-vswitchd' in proc.name():
                if options.pid is not None:
                    print("ERROR: Multiple ovs-vswitchd daemons running, "
                          "use the -p option!")
                    sys.exit(-1)

                options.pid = proc.pid

    #
    # Error checking on input parameters.
    #
    if options.pid is None and options.read_events is None:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(-1)

    if options.read_events is not None and options.write_events is not None:
        print("ERROR: Either supply the read or write events option, "
              "not both!")
        sys.exit(-1)

    if options.handler_filter is not None and options.read_events is None:
        print("ERROR: The --handler-filter option is only valid with the "
              "--read-events option!")
        sys.exit(-1)

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Open write handle if needed.
    #
    if options.write_events is not None:
        try:
            export_file = open(options.write_events, "w")
        except (FileNotFoundError, IOError, PermissionError) as e:
            print("ERROR: Can't create export file \"{}\": {}".format(
                options.write_events, e.strerror))
            sys.exit(-1)
    else:
        export_file = None

    trace_data = []
    event_count = {'total': {}, 'valid': {}, 'miss': {}}
    if options.read_events is None:
        #
        # Prepare the datapath port mapping cache
        #
        dp_port_map = dp_map.get_map()
        if export_file is not None:
            export_file.write("dp_port_map = {}\n".format(dp_port_map))

        #
        # Attach the usdt probe
        #
        u = USDT(pid=int(options.pid))
        try:
            u.enable_probe(probe="recv_upcall", fn_name="trace__recv_upcall")
            u.enable_probe(probe="op_flow_put", fn_name="trace__op_flow_put")
            u.enable_probe(probe="op_flow_execute",
                           fn_name="trace__op_flow_execute")
        except USDTException as e:
            print("ERROR: {}"
                  "ovs-vswitchd!".format(
                      (re.sub('^', ' ' * 7, str(e),
                              flags=re.MULTILINE)).strip().
                      replace("--with-dtrace or --enable-dtrace",
                              "--enable-usdt-probes")))
            sys.exit(-1)

        #
        # Uncomment to see how arguments are decoded.
        #   print(u.get_text())
        #
        print("- Compiling eBPF programs...")

        #
        # Attach probes to the running process
        #
        source = ebpf_source.replace("<MAX_PACKET_VAL>",
                                     str(options.packet_size))
        source = source.replace("<MAX_KEY_VAL>", str(options.flow_key_size))
        source = source.replace("<BUFFER_PAGE_CNT>",
                                str(options.buffer_page_count))

        b = BPF(text=source, usdt_contexts=[u], debug=options.debug & 0xffffff)

        #
        # Dump out all events
        #
        print("- Capturing events [Press ^C to stop]...")
        events_received = 0

        if not options.quiet:
            print("\n" + Event.get_event_header_str())

        b['events'].open_ring_buffer(receive_event_bcc)
        while 1:
            try:
                b.ring_buffer_poll()
                if options.stop != 0 and events_received >= options.stop:
                    break
            except KeyboardInterrupt:
                break

        dropcnt = b.get_table("dropcnt")
        export_misses = {}
        for k in dropcnt.keys():
            event = EventType.from_trace(k.value)
            count = dropcnt.sum(k).value
            if count > 0:
                if event not in event_count['total']:
                    event_count['total'][event] = 0
                    event_count['valid'][event] = 0
                event_count['miss'][event] = count
                export_misses[k.value] = count

        if options.write_events is not None:
            if sum(event_count['miss'].values()) > 0:
                export_file.write("event_miss = {}\n".format(export_misses))

            export_file.close()

        print()
    else:
        #
        # Here we are requested to read event from an event export
        #
        thread_filter = None
        if options.handler_filter is not None:
            thread_filter = options.handler_filter.split(',')

        try:
            dp_port_mapping_valid = False
            with open(options.read_events, 'r') as fd:
                events_received = 0

                if options.quiet:
                    spinner = Halo(spinner="dots", color="cyan",
                                   text="Reading events from \"{}\"...".format(
                                       options.read_events))
                    spinner.start()
                else:
                    print("- Reading events from \"{}\"...".format(
                        options.read_events))

                if not options.quiet:
                    print("\n" + Event.get_event_header_str())

                for entry in fd:
                    if options.stop != 0 and events_received >= options.stop:
                        break

                    entry.rstrip()
                    if entry.startswith('dp_port_map = {'):
                        if not dp_port_mapping_valid:
                            dp_port_mapping_valid = True
                            dp_map.set_map(ast.literal_eval(entry[14:]))
                    elif (entry.startswith('event = {') and
                          dp_port_mapping_valid):
                        event = ast.literal_eval(entry[8:])
                        event = namedtuple("EventObject",
                                           event.keys())(*event.values())

                        if thread_filter is not None \
                           and EventType.from_trace(event.event) != \
                           EventType.DP_UPCALL \
                           and event.comm.decode("utf-8") not in thread_filter:
                            # Skip none filtered threads
                            continue

                        if len(event.pkt) > 0:
                            options.packet_size = len(event.pkt)
                        if len(event.key) > 0:
                            options.flow_key_size = len(event.key)
                        receive_event(event)
                        events_received += 1
                    elif entry.startswith('event_miss = {'):
                        misses = ast.literal_eval(entry[13:])
                        for e, count in misses.items():
                            event = EventType.from_trace(e)
                            if count > 0:
                                if event not in event_count['total']:
                                    event_count['total'][event] = 0
                                    event_count['valid'][event] = 0
                                event_count['miss'][event] = count

            if options.quiet:
                spinner.stop()
                print("- Reading events from \"{}\"...".format(
                    options.read_events))

        except (FileNotFoundError, PermissionError):
            print("ERROR: Can't open file \"{}\" for reading!".format(
                options.read_events))
            sys.exit(-1)

    #
    # Start analyzing the data
    #
    print("- Analyzing results ({} events)...".format(len(trace_data)))

    if events_received > 0:
        if sum(event_count['miss'].values()) > 0:
            print("\nWARNING: Not all events were captured!\n         "
                  "Increase the BPF ring buffer size with the "
                  "--buffer-page-count option.")

        print("\n=> Events received per type (usable/total) [missed events]:")
        for event, total in sorted(event_count['total'].items()):
            miss = event_count['miss'][event] if event in event_count['miss'] \
                else 0
            print("  {:36}: {:10}/{:10} [{:10}]".format(
                event, event_count['valid'][event], total, miss))

    collection, batch_stats, thread_stats = collect_event_sets(
        trace_data, collect_stats=True, spinner=True)

    if len(collection) <= 0:
        print("No upcall data sets where found!!")
        sys.exit(0)

    print("\n- Analyzing {} event sets...".format(len(collection)))

    if options.debug & 0x1000000 != 0:
        for upcall in collection:
            print("DBG: {}{}{}{}{}".format(
                "U" if EventType.DP_UPCALL in upcall else "-",
                "u" if EventType.RECV_UPCALL in upcall else "-",
                "p" if EventType.OP_FLOW_PUT in upcall else "-",
                "e" if EventType.OP_FLOW_EXECUTE in upcall else "-",
                "E" if EventType.OVS_PKT_EXEC in upcall else "-"))
            if options.debug & 0x2000000 != 0:
                try:
                    print("DBG:  - {}".format(upcall[EventType.DP_UPCALL]))
                    print("DBG:  - {}".format(upcall[EventType.RECV_UPCALL]))
                    print("DBG:  - {}".format(upcall[EventType.OP_FLOW_PUT]))
                    print("DBG:  - {}".format(
                        upcall[EventType.OP_FLOW_EXECUTE]))
                    print("DBG:  - {}".format(upcall[EventType.OVS_PKT_EXEC]))
                except LookupError:
                    continue

    show_key_value(thread_stats, description="Upcalls handled per thread")
    show_batch_histogram(batch_stats,
                         description="Histogram of upcalls per batch")

    kernel_to_vswitchd = []
    kernel_to_kernel_exec = []
    vswitchd_to_kernel = []
    time_minus_lookup = []
    for upcall in collection:
        kernel_to_vswitchd.append((upcall[EventType.RECV_UPCALL].ts -
                                   upcall[EventType.DP_UPCALL].ts) /
                                  1000)

        if EventType.OP_FLOW_PUT in upcall and \
           EventType.OVS_PKT_EXEC in upcall:
            time_minus_lookup.append(
                ((upcall[EventType.OVS_PKT_EXEC].ts -
                  upcall[EventType.DP_UPCALL].ts) -
                 (upcall[EventType.OP_FLOW_PUT].ts -
                  upcall[EventType.RECV_UPCALL].ts)) / 1000)

        if EventType.OP_FLOW_EXECUTE in upcall and \
           EventType.OVS_PKT_EXEC in upcall:
            vswitchd_to_kernel.append((upcall[EventType.OVS_PKT_EXEC].ts
                                       - upcall[EventType.OP_FLOW_EXECUTE].ts)
                                      / 1000)

        if EventType.OVS_PKT_EXEC in upcall:
            kernel_to_kernel_exec.append((upcall[EventType.OVS_PKT_EXEC].ts -
                                          upcall[EventType.DP_UPCALL].ts) /
                                         1000)

    show_histogram(kernel_to_vswitchd,
                   description="Kernel upcall action to vswitchd receive "
                   "(microseconds)",
                   options=options)
    show_histogram(vswitchd_to_kernel,
                   description="vswitchd execute to kernel receive "
                   "(microseconds)",
                   options=options)
    show_histogram(time_minus_lookup,
                   description="Upcall overhead (total time minus lookup) "
                   "(microseconds)",
                   options=options)
    show_histogram(kernel_to_kernel_exec,
                   description="Kernel upcall to kernel packet execute "
                   "(microseconds)",
                   options=options)


#
# Start main() as the default entry point...
#
if __name__ == '__main__':
    main()
