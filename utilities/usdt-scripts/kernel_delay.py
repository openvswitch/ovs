#!/usr/bin/env python3
#
# Copyright (c) 2022,2023 Red Hat, Inc.
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
#
# Script information:
# -------------------
# This script allows a developer to quickly identify if the issue at hand
# might be related to the kernel running out of resources or if it really is
# an Open vSwitch issue.
#
# For documentation see the kernel_delay.rst file.
#
#
# Dependencies:
# -------------
#  You need to install the BCC package for your specific platform or build it
#  yourself using the following instructions:
#    https://raw.githubusercontent.com/iovisor/bcc/master/INSTALL.md
#
#  Python needs the following additional packages installed:
#    - pytz
#    - psutil
#
#  You can either install your distribution specific package or use pip:
#    pip install pytz psutil
#
import argparse
import datetime
import os
import pytz
import psutil
import re
import sys
import time

import ctypes as ct

try:
    from bcc import BPF, USDT, USDTException
    from bcc.syscall import syscalls, syscall_name
except ModuleNotFoundError:
    print("ERROR: Can't find the BPF Compiler Collection (BCC) tools!")
    sys.exit(os.EX_OSFILE)

from enum import IntEnum


#
# Actual eBPF source code
#
EBPF_SOURCE = """
#include <linux/irq.h>
#include <linux/sched.h>

#define MONITOR_PID <MONITOR_PID>

enum {
<EVENT_ENUM>
};

struct event_t {
    u64 ts;
    u32 tid;
    u32 id;

    int user_stack_id;
    int kernel_stack_id;

    u32 syscall;
    u64 entry_ts;
};

BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_STACK_TRACE(stack_traces, <STACK_TRACE_SIZE>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);
BPF_TABLE("percpu_array", uint32_t, uint64_t, trigger_miss, 1);

BPF_ARRAY(capture_on, u64, 1);
static inline bool capture_enabled(u64 pid_tgid) {
    int key = 0;
    u64 *ret;

    if ((pid_tgid >> 32) != MONITOR_PID)
        return false;

    ret = capture_on.lookup(&key);
    return ret && *ret == 1;
}

static inline bool capture_enabled__() {
    int key = 0;
    u64 *ret;

    ret = capture_on.lookup(&key);
    return ret && *ret == 1;
}

static struct event_t *get_event(uint32_t id) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        dropcnt.increment(0);
        return NULL;
    }

    event->id = id;
    event->ts = bpf_ktime_get_ns();
    event->tid = bpf_get_current_pid_tgid();

    return event;
}

static int start_trigger() {
    int key = 0;
    u64 *val = capture_on.lookup(&key);

    /* If the value is -1 we can't start as we are still processing the
     * results in userspace. */
    if (!val || *val != 0) {
        trigger_miss.increment(0);
        return 0;
    }

    struct event_t *event = get_event(EVENT_START_TRIGGER);
    if (event) {
       events.ringbuf_submit(event, 0);
       *val = 1;
    } else {
        trigger_miss.increment(0);
    }
    return 0;
}

static int stop_trigger() {
    int key = 0;
    u64 *val = capture_on.lookup(&key);

    if (!val || *val != 1)
        return 0;

    struct event_t *event = get_event(EVENT_STOP_TRIGGER);

    if (event)
       events.ringbuf_submit(event, 0);

    if (val)
        *val = -1;

    return 0;
}

<START_TRIGGER>
<STOP_TRIGGER>


/*
 * For the syscall monitor the following probes get installed.
 */
struct syscall_data_t {
    u64 count;
    u64 total_ns;
    u64 worst_ns;
};

struct syscall_data_key_t {
    u32 pid;
    u32 tid;
    u32 syscall;
};

BPF_HASH(syscall_start, u64, u64);
BPF_HASH(syscall_data, struct syscall_data_key_t, struct syscall_data_t);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
       return 0;

    u64 t = bpf_ktime_get_ns();
    syscall_start.update(&pid_tgid, &t);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct syscall_data_t *val, zero = {};
    struct syscall_data_key_t key;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
       return 0;

    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    key.syscall = args->id;

    u64 *start_ns = syscall_start.lookup(&pid_tgid);

    if (!start_ns)
        return 0;

    val = syscall_data.lookup_or_try_init(&key, &zero);
    if (val) {
        u64 delta = bpf_ktime_get_ns() - *start_ns;
        val->count++;
        val->total_ns += delta;
        if (delta > val->worst_ns)
            val->worst_ns = delta;

        if (<SYSCALL_TRACE_EVENTS>) {
            struct event_t *event = get_event(EVENT_SYSCALL);
            if (event) {
                event->syscall = args->id;
                event->entry_ts = *start_ns;
                if (<STACK_TRACE_ENABLED>) {
                    event->user_stack_id = stack_traces.get_stackid(
                        args, BPF_F_USER_STACK);
                    event->kernel_stack_id = stack_traces.get_stackid(
                        args, 0);
                }
                events.ringbuf_submit(event, 0);
            }
        }
    }
    return 0;
}


/*
 * For measuring the thread stopped time, we need the following.
 */
struct stop_time_data_t {
    u64 count;
    u64 total_ns;
    u64 worst_ns;
};

struct pid_tid_key_t {
    u32  pid;
    u32  tid;
};

BPF_HASH(stop_start, u64, u64);
BPF_HASH(stop_data, struct pid_tid_key_t, struct stop_time_data_t);

static inline void thread_handle_stopped_run(u32 pid, u32 tgid, u64 ktime)
{
    u64 pid_tgid = (u64) tgid << 32 | pid;
    u64 *start_ns = stop_start.lookup(&pid_tgid);

    if (!start_ns || *start_ns == 0)
        return;

    struct stop_time_data_t *val, zero = {};
    struct pid_tid_key_t key = { .pid = tgid,
                                 .tid = pid };

    val = stop_data.lookup_or_try_init(&key, &zero);
    if (val) {
        u64 delta = ktime - *start_ns;
        val->count++;
        val->total_ns += delta;
        if (delta > val->worst_ns)
            val->worst_ns = delta;
    }
    *start_ns = 0;
}


/*
 * For measuring the thread run time, we need the following.
 */
struct run_time_data_t {
    u64 count;
    u64 total_ns;
    u64 max_ns;
    u64 min_ns;
};

BPF_HASH(run_start, u64, u64);
BPF_HASH(run_data, struct pid_tid_key_t, struct run_time_data_t);

static inline void thread_start_run(u64 pid_tgid, u64 ktime)
{
    run_start.update(&pid_tgid, &ktime);
}

static inline void thread_stop_run(u32 pid, u32 tgid, u64 ktime)
{
    u64 pid_tgid = (u64) tgid << 32 | pid;
    u64 *start_ns = run_start.lookup(&pid_tgid);

    if (!start_ns || *start_ns == 0)
        return;

    struct run_time_data_t *val, zero = {};
    struct pid_tid_key_t key = { .pid = tgid,
                                 .tid = pid };

    val = run_data.lookup_or_try_init(&key, &zero);
    if (val) {
        u64 delta = ktime - *start_ns;
        val->count++;
        val->total_ns += delta;
        if (delta > val->max_ns)
            val->max_ns = delta;
        if (val->min_ns == 0 || delta < val->min_ns)
            val->min_ns = delta;
    }
    *start_ns = 0;
}


/*
 * For measuring the thread-ready delay, we need the following.
 */
struct ready_data_t {
    u64 count;
    u64 total_ns;
    u64 worst_ns;
};

BPF_HASH(ready_start, u64, u64);
BPF_HASH(ready_data, struct pid_tid_key_t, struct ready_data_t);

static inline int sched_wakeup__(u32 pid, u32 tgid)
{
    u64 pid_tgid = (u64) tgid << 32 | pid;

    if (!capture_enabled(pid_tgid))
        return 0;

    u64 t = bpf_ktime_get_ns();
    ready_start.update(&pid_tgid, &t);

    thread_handle_stopped_run(pid, tgid, t);
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    struct task_struct *t = (struct task_struct *)ctx->args[0];
    return sched_wakeup__(t->pid, t->tgid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    struct task_struct *t = (struct task_struct *)ctx->args[0];
    return sched_wakeup__(t->pid, t->tgid);
}

RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    u64 ktime = 0;

    if (!capture_enabled__())
        return 0;

    if (prev->tgid == MONITOR_PID) {
        u64 prev_pid_tgid = (u64)next->tgid << 32 | next->pid;
        ktime = bpf_ktime_get_ns();

        if (prev-><STATE_FIELD> == TASK_RUNNING)
            ready_start.update(&prev_pid_tgid, &ktime);

        if (prev-><STATE_FIELD> & __TASK_STOPPED)
            stop_start.update(&prev_pid_tgid, &ktime);

        thread_stop_run(prev->pid, prev->tgid, ktime);
    }

    if (next->tgid != MONITOR_PID)
        return 0;

    if (ktime == 0)
        ktime = bpf_ktime_get_ns();

    u64 pid_tgid = (u64)next->tgid << 32 | next->pid;
    u64 *start_ns = ready_start.lookup(&pid_tgid);

    if (start_ns && *start_ns != 0) {

        struct ready_data_t *val, zero = {};
        struct pid_tid_key_t key = { .pid = next->tgid,
                                     .tid = next->pid };

        val = ready_data.lookup_or_try_init(&key, &zero);
        if (val) {
            u64 delta = ktime - *start_ns;
            val->count++;
            val->total_ns += delta;
            if (delta > val->worst_ns)
                val->worst_ns = delta;
        }
        *start_ns = 0;
    }

    thread_start_run(pid_tgid, ktime);
    return 0;
}


/*
 * For measuring the hard irq time, we need the following.
 */
struct hardirq_start_data_t {
    u64  start_ns;
    char irq_name[32];
};

struct hardirq_data_t {
    u64 count;
    u64 total_ns;
    u64 worst_ns;
};

struct hardirq_data_key_t {
    u32 pid;
    u32 tid;
    char irq_name[32];
};

BPF_HASH(hardirq_start, u64, struct hardirq_start_data_t);
BPF_HASH(hardirq_data, struct hardirq_data_key_t, struct hardirq_data_t);

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
        return 0;

    struct hardirq_start_data_t data = {};

    data.start_ns = bpf_ktime_get_ns();
    TP_DATA_LOC_READ_STR(&data.irq_name, name, sizeof(data.irq_name));
    hardirq_start.update(&pid_tgid, &data);
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
        return 0;

    struct hardirq_start_data_t *data;
    data = hardirq_start.lookup(&pid_tgid);
    if (!data || data->start_ns == 0)
        return 0;

    if (args->ret != IRQ_NONE) {
        struct hardirq_data_t *val, zero = {};
        struct hardirq_data_key_t key = { .pid = pid_tgid >> 32,
                                          .tid = (u32)pid_tgid };

        bpf_probe_read_kernel(&key.irq_name, sizeof(key.irq_name),
                              data->irq_name);
        val = hardirq_data.lookup_or_try_init(&key, &zero);
        if (val) {
            u64 delta = bpf_ktime_get_ns() - data->start_ns;
            val->count++;
            val->total_ns += delta;
            if (delta > val->worst_ns)
                val->worst_ns = delta;
        }
    }

    data->start_ns = 0;
    return 0;
}


/*
 * For measuring the soft irq time, we need the following.
 */
struct softirq_start_data_t {
    u64 start_ns;
    u32 vec_nr;
};

struct softirq_data_t {
    u64 count;
    u64 total_ns;
    u64 worst_ns;
};

struct softirq_data_key_t {
    u32 pid;
    u32 tid;
    u32 vec_nr;
};

BPF_HASH(softirq_start, u64, struct softirq_start_data_t);
BPF_HASH(softirq_data, struct softirq_data_key_t, struct softirq_data_t);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
        return 0;

    struct softirq_start_data_t data = {};

    data.start_ns = bpf_ktime_get_ns();
    data.vec_nr = args->vec;
    softirq_start.update(&pid_tgid, &data);
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!capture_enabled(pid_tgid))
        return 0;

    struct softirq_start_data_t *data;
    data = softirq_start.lookup(&pid_tgid);
    if (!data || data->start_ns == 0)
        return 0;

    struct softirq_data_t *val, zero = {};
    struct softirq_data_key_t key = { .pid = pid_tgid >> 32,
                                      .tid = (u32)pid_tgid,
                                      .vec_nr = data->vec_nr};

    val = softirq_data.lookup_or_try_init(&key, &zero);
    if (val) {
        u64 delta = bpf_ktime_get_ns() - data->start_ns;
        val->count++;
        val->total_ns += delta;
        if (delta > val->worst_ns)
            val->worst_ns = delta;
    }

    data->start_ns = 0;
    return 0;
}
"""


#
# time_ns()
#
try:
    from time import time_ns
except ImportError:
    # For compatibility with Python <= v3.6.
    def time_ns():
        now = datetime.datetime.now()
        return int(now.timestamp() * 1e9)


#
# Probe class to use for the start/stop triggers
#
class Probe(object):
    '''
    The goal for this object is to support as many as possible
    probe/events as supported by BCC. See
       https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events--arguments
    '''
    def __init__(self, probe, pid=None):
        self.pid = pid
        self.text_probe = probe
        self._parse_text_probe()

    def __str__(self):
        if self.probe_type == "usdt":
            return "[{}]; {}:{}:{}".format(self.text_probe, self.probe_type,
                                           self.usdt_provider, self.usdt_probe)
        elif self.probe_type == "trace":
            return "[{}]; {}:{}:{}".format(self.text_probe, self.probe_type,
                                           self.trace_system, self.trace_event)
        elif self.probe_type == "kprobe" or self.probe_type == "kretprobe":
            return "[{}]; {}:{}".format(self.text_probe, self.probe_type,
                                        self.kprobe_function)
        elif self.probe_type == "uprobe" or self.probe_type == "uretprobe":
            return "[{}]; {}:{}".format(self.text_probe, self.probe_type,
                                        self.uprobe_function)
        else:
            return "[{}] <{}:unknown probe>".format(self.text_probe,
                                                    self.probe_type)

    def _raise(self, error):
        raise ValueError("[{}]; {}".format(self.text_probe, error))

    def _verify_kprobe_probe(self):
        # Nothing to verify for now, just return.
        return

    def _verify_trace_probe(self):
        # Nothing to verify for now, just return.
        return

    def _verify_uprobe_probe(self):
        # Nothing to verify for now, just return.
        return

    def _verify_usdt_probe(self):
        if not self.pid:
            self._raise("USDT probes need a valid PID.")

        usdt = USDT(pid=self.pid)

        for probe in usdt.enumerate_probes():
            if probe.provider.decode("utf-8") == self.usdt_provider and \
               probe.name.decode("utf-8") == self.usdt_probe:
                return

        self._raise("Can't find UDST probe '{}:{}'".format(self.usdt_provider,
                                                           self.usdt_probe))

    def _parse_text_probe(self):
        '''
        The text probe format is defined as follows:
          <probe_type>:<probe_specific>

        Types:
          USDT:      u|usdt:<provider>:<probe>
          TRACE:     t|trace:<system>:<event>
          KPROBE:    k|kprobe:<kernel_function>
          KRETPROBE: kr|kretprobe:<kernel_function>
          UPROBE:    up|uprobe:<function>
          URETPROBE: ur|uretprobe:<function>
        '''
        args = self.text_probe.split(":")
        if len(args) <= 1:
            self._raise("Can't extract probe type.")

        if args[0] not in ["k", "kprobe", "kr", "kretprobe", "t", "trace",
                           "u", "usdt", "up", "uprobe", "ur", "uretprobe"]:
            self._raise("Invalid probe type '{}'".format(args[0]))

        self.probe_type = "kprobe" if args[0] == "k" else args[0]
        self.probe_type = "kretprobe" if args[0] == "kr" else self.probe_type
        self.probe_type = "trace" if args[0] == "t" else self.probe_type
        self.probe_type = "usdt" if args[0] == "u" else self.probe_type
        self.probe_type = "uprobe" if args[0] == "up" else self.probe_type
        self.probe_type = "uretprobe" if args[0] == "ur" else self.probe_type

        if self.probe_type == "usdt":
            if len(args) != 3:
                self._raise("Invalid number of arguments for USDT")

            self.usdt_provider = args[1]
            self.usdt_probe = args[2]
            self._verify_usdt_probe()

        elif self.probe_type == "trace":
            if len(args) != 3:
                self._raise("Invalid number of arguments for TRACE")

            self.trace_system = args[1]
            self.trace_event = args[2]
            self._verify_trace_probe()

        elif self.probe_type == "kprobe" or self.probe_type == "kretprobe":
            if len(args) != 2:
                self._raise("Invalid number of arguments for K(RET)PROBE")
            self.kprobe_function = args[1]
            self._verify_kprobe_probe()

        elif self.probe_type == "uprobe" or self.probe_type == "uretprobe":
            if len(args) != 2:
                self._raise("Invalid number of arguments for U(RET)PROBE")
            self.uprobe_function = args[1]
            self._verify_uprobe_probe()

    def _get_kprobe_c_code(self, function_name, function_content):
        #
        # The kprobe__* do not require a function name, so it's
        # ignored in the code generation.
        #
        return """
int {}__{}(struct pt_regs *ctx) {{
    {}
}}
""".format(self.probe_type, self.kprobe_function, function_content)

    def _get_trace_c_code(self, function_name, function_content):
        #
        # The TRACEPOINT_PROBE() do not require a function name, so it's
        # ignored in the code generation.
        #
        return """
TRACEPOINT_PROBE({},{}) {{
    {}
}}
""".format(self.trace_system, self.trace_event, function_content)

    def _get_uprobe_c_code(self, function_name, function_content):
        return """
int {}(struct pt_regs *ctx) {{
    {}
}}
""".format(function_name, function_content)

    def _get_usdt_c_code(self, function_name, function_content):
        return """
int {}(struct pt_regs *ctx) {{
    {}
}}
""".format(function_name, function_content)

    def get_c_code(self, function_name, function_content):
        if self.probe_type == "kprobe" or self.probe_type == "kretprobe":
            return self._get_kprobe_c_code(function_name, function_content)
        elif self.probe_type == "trace":
            return self._get_trace_c_code(function_name, function_content)
        elif self.probe_type == "uprobe" or self.probe_type == "uretprobe":
            return self._get_uprobe_c_code(function_name, function_content)
        elif self.probe_type == "usdt":
            return self._get_usdt_c_code(function_name, function_content)

        return ""

    def probe_name(self):
        if self.probe_type == "kprobe" or self.probe_type == "kretprobe":
            return "{}".format(self.kprobe_function)
        elif self.probe_type == "trace":
            return "{}:{}".format(self.trace_system,
                                  self.trace_event)
        elif self.probe_type == "uprobe" or self.probe_type == "uretprobe":
            return "{}".format(self.uprobe_function)
        elif self.probe_type == "usdt":
            return "{}:{}".format(self.usdt_provider,
                                  self.usdt_probe)

        return ""


#
# event_to_dict()
#
def event_to_dict(event):
    return dict([(field, getattr(event, field))
                 for (field, _) in event._fields_
                 if isinstance(getattr(event, field), (int, bytes))])


#
# Event enum
#
Event = IntEnum("Event", ["SYSCALL", "START_TRIGGER", "STOP_TRIGGER"],
                start=0)


#
# process_event()
#
def process_event(ctx, data, size):
    global start_trigger_ts
    global stop_trigger_ts

    event = bpf["events"].event(data)
    if event.id == Event.SYSCALL:
        syscall_events.append({"tid": event.tid,
                               "ts_entry": event.entry_ts,
                               "ts_exit": event.ts,
                               "syscall": event.syscall,
                               "user_stack_id": event.user_stack_id,
                               "kernel_stack_id": event.kernel_stack_id})
    elif event.id == Event.START_TRIGGER:
        #
        # This event would have started the trigger already, so all we need to
        # do is record the start timestamp.
        #
        start_trigger_ts = event.ts

    elif event.id == Event.STOP_TRIGGER:
        #
        # This event would have stopped the trigger already, so all we need to
        # do is record the start timestamp.
        stop_trigger_ts = event.ts


#
# next_power_of_two()
#
def next_power_of_two(val):
    np = 1
    while np < val:
        np *= 2
    return np


#
# unsigned_int()
#
def unsigned_int(value):
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if value < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


#
# unsigned_nonzero_int()
#
def unsigned_nonzero_int(value):
    value = unsigned_int(value)
    if value == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return value


#
# get_thread_name()
#
def get_thread_name(pid, tid):
    try:
        with open(f"/proc/{pid}/task/{tid}/comm", encoding="utf8") as f:
            return f.readline().strip("\n")
    except FileNotFoundError:
        pass

    return f"<unknown:{pid}/{tid}>"


#
# get_vec_nr_name()
#
def get_vec_nr_name(vec_nr):
    known_vec_nr = ["hi", "timer", "net_tx", "net_rx", "block", "irq_poll",
                    "tasklet", "sched", "hrtimer", "rcu"]

    if vec_nr < 0 or vec_nr > len(known_vec_nr):
        return f"<unknown:{vec_nr}>"

    return known_vec_nr[vec_nr]


#
# start/stop/reset capture
#
def start_capture():
    bpf["capture_on"][ct.c_int(0)] = ct.c_int(1)


def stop_capture(force=False):
    if force:
        bpf["capture_on"][ct.c_int(0)] = ct.c_int(0xffff)
    else:
        bpf["capture_on"][ct.c_int(0)] = ct.c_int(0)


def capture_running():
    return bpf["capture_on"][ct.c_int(0)].value == 1


def reset_capture():
    bpf["syscall_start"].clear()
    bpf["syscall_data"].clear()
    bpf["run_start"].clear()
    bpf["run_data"].clear()
    bpf["ready_start"].clear()
    bpf["ready_data"].clear()
    bpf["hardirq_start"].clear()
    bpf["hardirq_data"].clear()
    bpf["softirq_start"].clear()
    bpf["softirq_data"].clear()
    bpf["stack_traces"].clear()
    bpf["stop_start"].clear()
    bpf["stop_data"].clear()


#
# Display timestamp
#
def print_timestamp(msg):
    ltz = datetime.datetime.now()
    utc = ltz.astimezone(pytz.utc)
    time_string = "{} @{} ({} UTC)".format(
        msg, ltz.isoformat(), utc.strftime("%H:%M:%S"))
    print(time_string)


#
# process_results()
#
def process_results(syscall_events=None, trigger_delta=None):
    if trigger_delta:
        print_timestamp("# Triggered sample dump, stop-start delta {:,} ns".
                        format(trigger_delta))
    else:
        print_timestamp("# Sample dump")

    #
    # First get a list of all threads we need to report on.
    #
    threads_syscall = {k.tid for k, _ in bpf["syscall_data"].items()
                       if k.syscall != 0xffffffff}

    threads_run = {k.tid for k, _ in bpf["run_data"].items()
                   if k.pid != 0xffffffff}

    threads_ready = {k.tid for k, _ in bpf["ready_data"].items()
                     if k.pid != 0xffffffff}

    threads_stopped = {k.tid for k, _ in bpf["stop_data"].items()
                       if k.pid != 0xffffffff}

    threads_hardirq = {k.tid for k, _ in bpf["hardirq_data"].items()
                       if k.pid != 0xffffffff}

    threads_softirq = {k.tid for k, _ in bpf["softirq_data"].items()
                       if k.pid != 0xffffffff}

    threads = sorted(threads_syscall | threads_run | threads_ready |
                     threads_stopped | threads_hardirq | threads_softirq,
                     key=lambda x: get_thread_name(options.pid, x))

    #
    # Print header...
    #
    print("{:10} {:16} {}".format("TID", "THREAD", "<RESOURCE SPECIFIC>"))
    print("{:10} {:16} {}".format("-" * 10, "-" * 16, "-" * 76))
    indent = 28 * " "

    #
    # Print all events/statistics per threads.
    #
    poll_id = [k for k, v in syscalls.items() if v == b"poll"][0]
    for thread in threads:

        if thread != threads[0]:
            print("")

        #
        # SYSCALL_STATISTICS
        #
        print("{:10} {:16} {}\n{}{:20} {:>6}  {:>10}  {:>16}  {:>16}".format(
            thread, get_thread_name(options.pid, thread),
            "[SYSCALL STATISTICS]", indent,
            "NAME", "NUMBER", "COUNT", "TOTAL ns", "MAX ns"))

        total_count = 0
        total_ns = 0
        for k, v in sorted(filter(lambda t: t[0].tid == thread,
                                  bpf["syscall_data"].items()),
                           key=lambda kv: -kv[1].total_ns):

            print("{}{:20.20} {:6}  {:10}  {:16,}  {:16,}".format(
                indent, syscall_name(k.syscall).decode("utf-8"), k.syscall,
                v.count, v.total_ns, v.worst_ns))
            if k.syscall != poll_id:
                total_count += v.count
                total_ns += v.total_ns

        if total_count > 0:
            print("{}{:20.20} {:6}  {:10}  {:16,}".format(
                indent, "TOTAL( - poll):", "", total_count, total_ns))

        #
        # THREAD RUN STATISTICS
        #
        for k, v in filter(lambda t: t[0].tid == thread,
                           bpf["run_data"].items()):

            print("\n{:10} {:16} {}\n{}{:10}  {:>16}  {:>16}  {:>16}".format(
                "", "", "[THREAD RUN STATISTICS]", indent,
                "SCHED_CNT", "TOTAL ns", "MIN ns", "MAX ns"))

            print("{}{:10}  {:16,}  {:16,}  {:16,}".format(
                indent, v.count, v.total_ns, v.min_ns, v.max_ns))
            break

        #
        # THREAD READY STATISTICS
        #
        for k, v in filter(lambda t: t[0].tid == thread,
                           bpf["ready_data"].items()):

            print("\n{:10} {:16} {}\n{}{:10}  {:>16}  {:>16}".format(
                "", "", "[THREAD READY STATISTICS]", indent,
                "SCHED_CNT", "TOTAL ns", "MAX ns"))

            print("{}{:10}  {:16,}  {:16,}".format(
                indent, v.count, v.total_ns, v.worst_ns))
            break

        #
        # THREAD STOPPED STATISTICS
        #
        for k, v in filter(lambda t: t[0].tid == thread,
                           bpf["stop_data"].items()):

            print("\n{:10} {:16} {}\n{}{:10}  {:>16}  {:>16}".format(
                "", "", "[THREAD STOPPED STATISTICS]", indent,
                "STOP_CNT", "TOTAL ns", "MAX ns"))

            print("{}{:10}  {:16,}  {:16,}".format(
                indent, v.count, v.total_ns, v.worst_ns))
            break

        #
        # HARD IRQ STATISTICS
        #
        total_ns = 0
        total_count = 0
        header_printed = False
        for k, v in sorted(filter(lambda t: t[0].tid == thread,
                                  bpf["hardirq_data"].items()),
                           key=lambda kv: -kv[1].total_ns):

            if not header_printed:
                print("\n{:10} {:16} {}\n{}{:20}  {:>10}  {:>16}  {:>16}".
                      format("", "", "[HARD IRQ STATISTICS]", indent,
                             "NAME", "COUNT", "TOTAL ns", "MAX ns"))
                header_printed = True

            print("{}{:20.20}  {:10}  {:16,}  {:16,}".format(
                indent, k.irq_name.decode("utf-8"),
                v.count, v.total_ns, v.worst_ns))

            total_count += v.count
            total_ns += v.total_ns

        if total_count > 0:
            print("{}{:20.20}  {:10}  {:16,}".format(
                indent, "TOTAL:", total_count, total_ns))

        #
        # SOFT IRQ STATISTICS
        #
        total_ns = 0
        total_count = 0
        header_printed = False
        for k, v in sorted(filter(lambda t: t[0].tid == thread,
                                  bpf["softirq_data"].items()),
                           key=lambda kv: -kv[1].total_ns):

            if not header_printed:
                print("\n{:10} {:16} {}\n"
                      "{}{:20} {:>7}  {:>10}  {:>16}  {:>16}".
                      format("", "", "[SOFT IRQ STATISTICS]", indent,
                             "NAME", "VECT_NR", "COUNT", "TOTAL ns", "MAX ns"))
                header_printed = True

            print("{}{:20.20} {:>7}  {:10}  {:16,}  {:16,}".format(
                indent, get_vec_nr_name(k.vec_nr), k.vec_nr,
                v.count, v.total_ns, v.worst_ns))

            total_count += v.count
            total_ns += v.total_ns

        if total_count > 0:
            print("{}{:20.20} {:7}  {:10}  {:16,}".format(
                indent, "TOTAL:", "", total_count, total_ns))

    #
    # Print events
    #
    lost_stack_traces = 0
    if syscall_events:
        stack_traces = bpf.get_table("stack_traces")

        print("\n\n# SYSCALL EVENTS:"
              "\n{}{:>19} {:>19} {:>10} {:16} {:>10}  {}".format(
                  2 * " ", "ENTRY (ns)", "EXIT (ns)", "TID", "COMM",
                  "DELTA (us)", "SYSCALL"))
        print("{}{:19} {:19} {:10} {:16} {:10}  {}".format(
            2 * " ", "-" * 19, "-" * 19, "-" * 10, "-" * 16,
            "-" * 10, "-" * 16))
        for event in syscall_events:
            print("{}{:19} {:19} {:10} {:16} {:10,}  {}".format(
                " " * 2,
                event["ts_entry"], event["ts_exit"], event["tid"],
                get_thread_name(options.pid, event["tid"]),
                int((event["ts_exit"] - event["ts_entry"]) / 1000),
                syscall_name(event["syscall"]).decode("utf-8")))
            #
            # Not sure where to put this, but I'll add some info on stack
            # traces here... Userspace stack traces are very limited due to
            # the fact that bcc does not support dwarf backtraces. As OVS
            # gets compiled without frame pointers we will not see much.
            # If however, OVS does get built with frame pointers, we should not
            # use the BPF_STACK_TRACE_BUILDID as it does not seem to handle
            # the debug symbols correctly. Also, note that for kernel
            # traces you should not use BPF_STACK_TRACE_BUILDID, so two
            # buffers are needed.
            #
            # Some info on manual dwarf walk support:
            #   https://github.com/iovisor/bcc/issues/3515
            #   https://github.com/iovisor/bcc/pull/4463
            #
            if options.stack_trace_size == 0:
                continue

            if event["kernel_stack_id"] < 0 or event["user_stack_id"] < 0:
                lost_stack_traces += 1

            kernel_stack = stack_traces.walk(event["kernel_stack_id"]) \
                if event["kernel_stack_id"] >= 0 else []
            user_stack = stack_traces.walk(event["user_stack_id"]) \
                if event["user_stack_id"] >= 0 else []

            for addr in kernel_stack:
                print("{}{}".format(
                    " " * 10,
                    bpf.ksym(addr, show_module=True,
                             show_offset=True).decode("utf-8", "replace")))

            for addr in user_stack:
                addr_str = bpf.sym(addr, options.pid, show_module=True,
                                   show_offset=True).decode("utf-8", "replace")

                if addr_str == "[unknown]":
                    addr_str += " 0x{:x}".format(addr)

                print("{}{}".format(" " * 10, addr_str))

    #
    # Print any footer messages.
    #
    if lost_stack_traces > 0:
        print("\n#WARNING: We where not able to display {} stack traces!\n"
              "#         Consider increasing the stack trace size using\n"
              "#         the '--stack-trace-size' option.\n"
              "#         Note that this can also happen due to a stack id\n"
              "#         collision.".format(lost_stack_traces))


#
# main()
#
def main():
    #
    # Don't like these globals, but ctx passing does not seem to work with the
    # existing open_ring_buffer() API :(
    #
    global bpf
    global options
    global syscall_events
    global start_trigger_ts
    global stop_trigger_ts

    start_trigger_ts = 0
    stop_trigger_ts = 0

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs="?")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitch's PID",
                        type=unsigned_int, default=None)
    parser.add_argument("-s", "--syscall-events", metavar="DURATION_NS",
                        help="Record syscall events that take longer than "
                        "DURATION_NS. Omit the duration value to record all "
                        "syscall events",
                        type=unsigned_int, const=0, default=None, nargs="?")
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=unsigned_int, default=1024, metavar="NUMBER")
    parser.add_argument("--sample-count",
                        help="Number of sample runs, default 1",
                        type=unsigned_nonzero_int, default=1, metavar="RUNS")
    parser.add_argument("--sample-interval",
                        help="Delay between sample runs, default 0",
                        type=float, default=0, metavar="SECONDS")
    parser.add_argument("--sample-time",
                        help="Sample time, default 0.5 seconds",
                        type=float, default=0.5, metavar="SECONDS")
    parser.add_argument("--skip-syscall-poll-events",
                        help="Skip poll() syscalls with --syscall-events",
                        action="store_true")
    parser.add_argument("--stack-trace-size",
                        help="Number of unique stack traces that can be "
                        "recorded, default 4096. 0 to disable",
                        type=unsigned_int, default=4096)
    parser.add_argument("--start-trigger", metavar="TRIGGER",
                        help="Start trigger, see documentation for details",
                        type=str, default=None)
    parser.add_argument("--stop-trigger", metavar="TRIGGER",
                        help="Stop trigger, see documentation for details",
                        type=str, default=None)
    parser.add_argument("--trigger-delta", metavar="DURATION_NS",
                        help="Only report event when the trigger duration > "
                             "DURATION_NS, default 0 (all events)",
                        type=unsigned_int, const=0, default=0, nargs="?")

    options = parser.parse_args()

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if not options.pid:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if options.pid:
                    print("ERROR: Multiple ovs-vswitchd daemons running, "
                          "use the -p option!")
                    sys.exit(os.EX_NOINPUT)

                options.pid = proc.pid

    #
    # Error checking on input parameters.
    #
    if not options.pid:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(os.EX_UNAVAILABLE)

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Make sure we are running as root, or else we can not attach the probes.
    #
    if os.geteuid() != 0:
        print("ERROR: We need to run as root to attached probes!")
        sys.exit(os.EX_NOPERM)

    #
    # Setup any of the start stop triggers
    #
    if options.start_trigger is not None:
        try:
            start_trigger = Probe(options.start_trigger, pid=options.pid)
        except ValueError as e:
            print(f"ERROR: Invalid start trigger {str(e)}")
            sys.exit(os.EX_CONFIG)
    else:
        start_trigger = None

    if options.stop_trigger is not None:
        try:
            stop_trigger = Probe(options.stop_trigger, pid=options.pid)
        except ValueError as e:
            print(f"ERROR: Invalid stop trigger {str(e)}")
            sys.exit(os.EX_CONFIG)
    else:
        stop_trigger = None

    #
    # Attach probe to running process.
    #
    source = EBPF_SOURCE.replace("<EVENT_ENUM>", "\n".join(
        ["    EVENT_{} = {},".format(
            event.name, event.value) for event in Event]))
    source = source.replace("<BUFFER_PAGE_CNT>",
                            str(options.buffer_page_count))
    source = source.replace("<MONITOR_PID>", str(options.pid))

    if BPF.kernel_struct_has_field(b"task_struct", b"state") == 1:
        source = source.replace("<STATE_FIELD>", "state")
    else:
        source = source.replace("<STATE_FIELD>", "__state")

    poll_id = [k for k, v in syscalls.items() if v == b"poll"][0]
    if options.syscall_events is None:
        syscall_trace_events = "false"
    elif options.syscall_events == 0:
        if not options.skip_syscall_poll_events:
            syscall_trace_events = "true"
        else:
            syscall_trace_events = f"args->id != {poll_id}"
    else:
        syscall_trace_events = "delta > {}".format(options.syscall_events)
        if options.skip_syscall_poll_events:
            syscall_trace_events += f" && args->id != {poll_id}"

    source = source.replace("<SYSCALL_TRACE_EVENTS>",
                            syscall_trace_events)

    source = source.replace("<STACK_TRACE_SIZE>",
                            str(options.stack_trace_size))

    source = source.replace("<STACK_TRACE_ENABLED>", "true"
                            if options.stack_trace_size > 0 else "false")

    #
    # Handle start/stop probes
    #
    if start_trigger:
        source = source.replace("<START_TRIGGER>",
                                start_trigger.get_c_code(
                                    "start_trigger_probe",
                                    "return start_trigger();"))
    else:
        source = source.replace("<START_TRIGGER>", "")

    if stop_trigger:
        source = source.replace("<STOP_TRIGGER>",
                                stop_trigger.get_c_code(
                                    "stop_trigger_probe",
                                    "return stop_trigger();"))
    else:
        source = source.replace("<STOP_TRIGGER>", "")

    #
    # Setup usdt or other probes that need handling trough the BFP class.
    #
    usdt = USDT(pid=int(options.pid))
    try:
        if start_trigger and start_trigger.probe_type == "usdt":
            usdt.enable_probe(probe=start_trigger.probe_name(),
                              fn_name="start_trigger_probe")
        if stop_trigger and stop_trigger.probe_type == "usdt":
            usdt.enable_probe(probe=stop_trigger.probe_name(),
                              fn_name="stop_trigger_probe")

    except USDTException as e:
        print("ERROR: {}".format(
            (re.sub("^", " " * 7, str(e), flags=re.MULTILINE)).strip().
            replace("--with-dtrace or --enable-dtrace",
                    "--enable-usdt-probes")))
        sys.exit(os.EX_OSERR)

    bpf = BPF(text=source, usdt_contexts=[usdt], debug=options.debug)

    if start_trigger:
        try:
            if start_trigger.probe_type == "uprobe":
                bpf.attach_uprobe(name=f"/proc/{options.pid}/exe",
                                  sym=start_trigger.probe_name(),
                                  fn_name="start_trigger_probe",
                                  pid=options.pid)

            if start_trigger.probe_type == "uretprobe":
                bpf.attach_uretprobe(name=f"/proc/{options.pid}/exe",
                                     sym=start_trigger.probe_name(),
                                     fn_name="start_trigger_probe",
                                     pid=options.pid)
        except Exception as e:
            print("ERROR: Failed attaching uprobe start trigger "
                  f"'{start_trigger.probe_name()}';\n         {str(e)}")
            sys.exit(os.EX_OSERR)

    if stop_trigger:
        try:
            if stop_trigger.probe_type == "uprobe":
                bpf.attach_uprobe(name=f"/proc/{options.pid}/exe",
                                  sym=stop_trigger.probe_name(),
                                  fn_name="stop_trigger_probe",
                                  pid=options.pid)

            if stop_trigger.probe_type == "uretprobe":
                bpf.attach_uretprobe(name=f"/proc/{options.pid}/exe",
                                     sym=stop_trigger.probe_name(),
                                     fn_name="stop_trigger_probe",
                                     pid=options.pid)
        except Exception as e:
            print("ERROR: Failed attaching uprobe stop trigger"
                  f"'{stop_trigger.probe_name()}';\n         {str(e)}")
            sys.exit(os.EX_OSERR)

    #
    # If no triggers are configured use the delay configuration
    #
    bpf["events"].open_ring_buffer(process_event)

    sample_count = 0
    while sample_count < options.sample_count:
        sample_count += 1
        syscall_events = []

        if not options.start_trigger:
            print_timestamp("# Start sampling")
            start_capture()
            stop_time = -1 if options.stop_trigger else \
                time_ns() + options.sample_time * 1000000000
        else:
            # For start triggers the stop time depends on the start trigger
            # time, or depends on the stop trigger if configured.
            stop_time = -1 if options.stop_trigger else 0

        while True:
            keyboard_interrupt = False
            try:
                last_start_ts = start_trigger_ts
                last_stop_ts = stop_trigger_ts

                if stop_time > 0:
                    delay = int((stop_time - time_ns()) / 1000000)
                    if delay <= 0:
                        break
                else:
                    delay = -1

                bpf.ring_buffer_poll(timeout=delay)

                if stop_time <= 0 and last_start_ts != start_trigger_ts:
                    print_timestamp(
                        "# Start sampling (trigger@{})".format(
                            start_trigger_ts))

                    if not options.stop_trigger:
                        stop_time = time_ns() + \
                            options.sample_time * 1000000000

                if last_stop_ts != stop_trigger_ts:
                    break

            except KeyboardInterrupt:
                keyboard_interrupt = True
                break

        if options.stop_trigger and not capture_running():
            print_timestamp("# Stop sampling (trigger@{})".format(
                stop_trigger_ts))
        else:
            print_timestamp("# Stop sampling")

        if stop_trigger_ts != 0 and start_trigger_ts != 0:
            trigger_delta = stop_trigger_ts - start_trigger_ts
        else:
            trigger_delta = None

        if not trigger_delta or trigger_delta >= options.trigger_delta:
            stop_capture(force=True)  # Prevent a new trigger to start.
            process_results(syscall_events=syscall_events,
                            trigger_delta=trigger_delta)
        elif trigger_delta:
            sample_count -= 1
            print_timestamp("# Sample dump skipped, delta {:,} ns".format(
                trigger_delta))

        reset_capture()
        stop_capture()

        if keyboard_interrupt:
            break

        if options.sample_interval > 0:
            time.sleep(options.sample_interval)

    #
    # Report lost events.
    #
    dropcnt = bpf.get_table("dropcnt")
    for k in dropcnt.keys():
        count = dropcnt.sum(k).value
        if k.value == 0 and count > 0:
            print("\n# WARNING: Not all events were captured, {} were "
                  "dropped!\n#          Increase the BPF ring buffer size "
                  "with the --buffer-page-count option.".format(count))

    if options.sample_count > 1:
        trigger_miss = bpf.get_table("trigger_miss")
        for k in trigger_miss.keys():
            count = trigger_miss.sum(k).value
            if k.value == 0 and count > 0:
                print("\n# WARNING: Not all start triggers were successful. "
                      "{} were missed due to\n#          slow userspace "
                      "processing!".format(count))


#
# Start main() as the default entry point...
#
if __name__ == "__main__":
    main()
