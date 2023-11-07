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
# reval_monitor.py uses various user-defined tracepoints to get all the
# revalidator-process related variables and will display them in a (dynamic)
# graph. In addition, it will also dump the data to the console
# in a CSV format. Note that all the graphical output can be disabled.
#
# All the USDT events can be saved to a file and than can be used to
# replay the trace offline and still get the plots.
#
# The script can simple be invoked without any options, and it will try
# to find the running ovs-vswitchd instance:
#
#   # ./reval_monitor.py
#   # Starting trace @2022-09-20T04:07:43.588749 (08:07:43 UTC)
#   ts_start, ts_complete, n_flows, n_reval_flows, avg_n_flows, max_n_flows,
#     flow_limit, dump_duration, poll_wait, actual_wait
#   1741367714251645, 1741367714532545, 0, 0, 0, 10000, 69000, 1, 500, 500.52
#   1741368215056961, 1741368215318223, 0, 0, 0, 10000, 69000, 1, 500, 500.55
#   1741368715865871, 1741368716107089, 0, 0, 0, 10000, 69000, 1, 500, 499.48
#   ^C# Stopping trace @2022-09-20T04:07:49.893827 (08:07:49 UTC)
#
#  IMPORTANT NOTE: This script only works when a single datapath is configured!
#  2nd IMPORTANT NOTE: ovs-vswitchd either needs to be built with debug info
#                      or the debug info package needs to be installed!
#
#  The following are the available options:
#
#    usage: reval_monitor.py [-h] [-c] [--buffer-page-count NUMBER]
#                            [-D [DEBUG]] [-g] [--no-ukey-count]
#                            [-p VSWITCHD_PID] [-P PAHOLE] [-r FILE] [-R]
#                            [-u SECONDS] [-w FILE] [-W FILE]
#
#    options:
#      -h, --help            show this help message and exit
#      -c, --compress-output
#                            Compress output, i.e. only dump changes in
#                            the dataset
#      --buffer-page-count NUMBER
#                            Number of BPF ring buffer pages, default
#                            1024
#      -D [DEBUG], --debug [DEBUG]
#                            Enable eBPF debugging
#      -g, --no-gui          Do not use the gui to display plots
#      --no-ukey-count       No revalidate_ukey() counting
#      -p VSWITCHD_PID, --pid VSWITCHD_PID
#                            ovs-vswitch's PID
#      -P PAHOLE, --pahole PAHOLE
#                            Pahole executable to use, default pahole
#      -r FILE, --read-events FILE
#                            Read events from <FILE> instead of
#                            installing tracepoints
#      -R, --no-realtime-plots
#                            Do not show realtime plot while tracing
#      -u SECONDS, --update-interval SECONDS
#                            Seconds to wait between real time update,
#                            default 1
#      -w FILE, --write-events FILE
#                            Write events to <FILE>
#      -W FILE, --write-charts FILE
#                            Write overall charts to <FILE>.png

#                            [-D [DEBUG]] [-g] [--no-ukey-count]
#                            [-p VSWITCHD_PID] [-r FILE] [-R]
#                            [-u SECONDS] [-w FILE] [-W FILE]
#
# The -g option disabled all GUI output of matplotlib, -R only disables the
# real-time plots. As real-time plots are rather slow, the -u option can be
# used to only update the graph every x seconds, which might speed up the
# processing.
#
# The --no-ukey-count option disables counting of the number of flows actually
# being revalidated against the current OpenFlow ruleset. This will not install
# the specific tracepoint which would be called for each flow being
# revalidated.
#
# What is plotted in the graphs (and dumped in the CSV output)?
# - n_flows:       Number of flows active in the system.
# - n_reval_flows: Number of flows that where revalidated against the OpenFlow
#                  ruleset.
# - dump_duration: Time it took to dump and process all flows.
# - avg_n_flows:   Average number of flows in the system.
# - max_n_flows:   Maximum number of flows in the system.
# - flow_limit:    Dynamic flow limit.
# - poll_wait:     Time requested for the poll wait.
# - actual_wait:   Time it took to be woken up.
#
# Dependencies:
#  This script needs the 'readelf' binary to be available. In addition, it also
#  needs pahole to be installed, and it needs a version that is equal or newer
#  than the following commit on the next branch:
#
#    https://git.kernel.org/pub/scm/devel/pahole/pahole.git/?h=next
#      c55b13b9d785 ("WIP: Remove DW_TAG_atomic_type when encoding BTF")
#
#  To use a locally compiled pahole the --pahole option can be used.
#  For example:
#    # ./reval_monitor.py --pahole ~/pahole/build/pahole -g
#    Starting trace @2022-12-20T14:57:26.077815 (13:57:26 UTC)
#    ts_start, ts_complete, n_flows, n_reval_flows, avg_n_flows, max_n_flows, \
#      flow_limit, dump_duration, poll_wait, actual_wait
#    4202771850983494, 4202771851472838, 0, 0, 0, 0, 10000, 1, 500, 15.06
#    4202771866531996, 4202771867713366, 0, 0, 0, 0, 10000, 1, 500, 4.23
#    4202771871941979, 4202771872749915, 0, 0, 0, 0, 10000, 1, 500, 500.02
#    4202772372770361, 4202772373531820, 0, 0, 0, 0, 10000, 1, 500, 499.96
#    4202772873487942, 4202772874514753, 0, 0, 0, 0, 10000, 1, 500, 500.01
#    4202773374528435, 4202773375695054, 0, 0, 0, 0, 10000, 1, 500, 500.01
#    4202773875701559, 4202773876880763, 0, 0, 0, 0, 10000, 1, 500, 500.04
#    4202774376925058, 4202774377905799, 0, 0, 0, 0, 10000, 1, 500, 500.03
#    ^C# Stopping trace @2022-12-20T14:57:40.391730 (13:57:40 UTC)
#

try:
    from bcc import BPF, USDT, USDTException
except ModuleNotFoundError:
    print("WARNING: Can't find the BPF Compiler Collection (BCC) tools!")
    print("         This is NOT problem if you analyzing previously collected"
          " data.\n")

from collections import namedtuple
from enum import IntEnum
from pathlib import Path

import argparse
import ast
import datetime
import re
import subprocess
import sys

import pytz
import psutil
import matplotlib.pyplot as plt

#
# Actual eBPF source code
#
EBPF_SOURCE = """
#include <linux/sched.h>

<OVS_INCLUDE_DEFINITIONS>

enum {
<EVENT_ENUM>
};

struct event_t {
    u64  ts;
    u32  pid;
    u32  id;
    u64  n_flows;
    u32  avg_n_flows;
    u32  max_n_flows;
    u32  flow_limit;
    u32  dump_duration;
    u32  poll_wait;
};


BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);

static struct event_t *get_event(uint32_t id) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        dropcnt.increment(0);
        return NULL;
    }

    event->id = id;
    event->ts = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid();

    return event;
}

int probe__start_dump(struct pt_regs *ctx) {
    struct event_t *event = get_event(EVENT_START_DUMP);
    if (!event)
        return 1;

    events.ringbuf_submit(event, 0);
    return 0;
};

int probe__sweep_done(struct pt_regs *ctx) {
    struct udpif udpif;

    bpf_usdt_readarg_p(1, ctx, &udpif, sizeof(udpif));

    struct event_t *event = get_event(EVENT_SWEEP_DONE);
    if (!event)
        return 1;

    event->avg_n_flows = udpif.avg_n_flows;
    event->max_n_flows = udpif.max_n_flows;
    event->flow_limit = udpif.flow_limit;
    event->dump_duration = udpif.dump_duration;

    bpf_usdt_readarg(2, ctx, &event->n_flows);
    bpf_usdt_readarg(3, ctx, &event->poll_wait);

    events.ringbuf_submit(event, 0);
    return 0;
};

int probe__reval_entry(struct pt_regs *ctx) {
    struct event_t *event = get_event(EVENT_REVAL_ENTRY);
    if (!event)
        return 1;

    events.ringbuf_submit(event, 0);
    return 0;
};
"""


#
# event_to_dict()
#
def event_to_dict(event):
    return dict([(field, getattr(event, field))
                 for (field, _) in event._fields_
                 if isinstance(getattr(event, field), (int, bytes))])


#
# print_csv_header()
#
def print_csv_header():
    print("ts_start, ts_complete, n_flows, n_reval_flows, avg_n_flows, "
          "max_n_flows, flow_limit, dump_duration, poll_wait, actual_wait")


#
# Event enum
#
Event = IntEnum("Event", ["START_DUMP",
                          "SWEEP_DONE",
                          "REVAL_ENTRY"], start=0)


#
# process_event()
#
def process_event(ctx, data, size):
    event = b['events'].event(data)
    _process_event(event)


def _process_event(event):
    global graph

    if export_file is not None:
        export_file.write("event = {}\n".format(event_to_dict(event)))

    if event.id == Event.START_DUMP and not state['running']:
        start = state["last_start"]
        done = state["last_done"]
        if done and start:
            actual_wait = (event.ts - done.ts) / 1000000
            csv = "{}, {}, {}, {}, {}, {}, {}, {}, {}, {:.2f}".format(
                start.ts, done.ts, done.n_flows, graph.ukey_count,
                done.avg_n_flows, done.max_n_flows, done.flow_limit,
                done.dump_duration, done.poll_wait, actual_wait)

            if graph.base_time == 0:
                graph = graph._replace(base_time=done.ts)

            graph.time.append((done.ts - graph.base_time) / 1000000000)
            graph.n_flows.append(done.n_flows)
            graph.n_reval_flows.append(graph.ukey_count)
            graph.avg_n_flows.append(done.avg_n_flows)
            graph.max_n_flows.append(done.max_n_flows)
            graph.flow_limit.append(done.flow_limit)
            graph.dump_duration.append(done.dump_duration)
            graph.poll_wait.append(done.poll_wait)
            graph.actual_wait.append(actual_wait)

            if not options.no_gui and not options.no_realtime_plots:
                updated_graph = dynamic_plot_update(
                    graph, refresh=options.update_interval)
                if updated_graph is None:
                    raise KeyboardInterrupt
                graph = updated_graph

            if options.compress_output:
                last_csv = state["last_csv"]
                if not last_csv or \
                   csv.split(",")[2:-1] != last_csv.split(",")[2:-1] or \
                   abs((event.ts - done.ts) / 1000000 - done.poll_wait) > 100:
                    print(csv)
                else:
                    state["last_not_printed_csv"] = csv

                state["last_csv"] = csv
            else:
                print(csv)

        state["last_start"] = event
        state['running'] = True
        graph = graph._replace(ukey_count=0)
    elif event.id == Event.SWEEP_DONE and state['running']:
        state["last_done"] = event
        state['running'] = False
    elif event.id == Event.REVAL_ENTRY and state['running']:
        graph = graph._replace(ukey_count=graph.ukey_count + 1)


#
# run_program()
#
def run_program(command):
    try:
        process = subprocess.run(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 encoding='utf8',
                                 check=True)

    except subprocess.CalledProcessError as perror:
        return perror.returncode, perror.stdout

    return 0, process.stdout


#
# get_ovs_definitions()
#
def get_ovs_definitions(objects, pahole="pahole", pid=None):
    if pid is None:
        raise ValueError("A valid pid value should be supplied!")

    if not isinstance(objects, list):
        objects = [objects]

    if len(objects) == 0:
        raise ValueError("Must supply at least one object!")

    vswitchd = Path("/proc/{}/exe".format(str(pid))).resolve()

    object_str = ','.join(objects)

    def run_pahole(debug_file):
        error, result = run_program([pahole, "-C", object_str, "--compile",
                                     debug_file])

        if error:
            if "pahole: {}: Invalid argument".format(debug_file) not in result:
                print("ERROR: Pahole failed to get ovs-vswitchd data "
                      "structures!\n{}".format(re.sub('^', ' ' * 7,
                                                      result.rstrip(),
                                                      flags=re.MULTILINE)))
                sys.exit(-1)

            return None

        if bool(re.search("pahole: type .* not found", result)):
            return None

        return result

    def run_readelf(bin_file):
        error, result = run_program(['readelf', "-n",
                                     "--debug-dump=links", bin_file])

        if error:
            print("ERROR: Failed 'readelf' on \"{}\"!\n{}".
                  format(bin_file, re.sub('^', ' ' * 7, result,
                                          flags=re.MULTILINE)))
            sys.exit(-1)

        return result

    def get_debug_file(bin_file):
        elf_result = run_readelf(bin_file)
        match = re.search("Build ID: ([0-9a-fA-F]+)", elf_result)
        if not match:
            print("ERROR: Can't find build ID to read debug symbols!")
            sys.exit(-1)

        dbg_file = "/usr/lib/debug/.build-id/{}/{}.debug".format(
            match.group(1)[:2], match.group(1)[2:])

        return dbg_file

    def get_from_shared_library(debug_file):
        ovs_libs = ['libofproto', 'libopenvswitch', 'libovsdb', 'libsflow',
                    'libvtep']
        error, ldd_result = run_program(['ldd', debug_file])

        if error:
            print("ERROR: Failed 'ldd' on \"{}\"!\n{}".
                  format(debug_file, re.sub('^', ' ' * 7, ldd_result,
                                            flags=re.MULTILINE)))
            sys.exit(-1)

        for lib in ovs_libs:
            match = re.search(r"^\s*{}.* => (.*) \(.*\)$".format(lib),
                              ldd_result, flags=re.MULTILINE)
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
        print("INFO: Failed to find debug info in \"{}\"!".format(vswitchd))

        #
        # Get additional .debug information if available.
        #
        dbg_file = get_debug_file(vswitchd)
        result = run_pahole(dbg_file)
        if result is None:
            print("INFO: Failed to find debug info in \"{}\"!".format(
                dbg_file))

        #
        # Try to get information from shared libraries if used.
        #
        result = get_from_shared_library(vswitchd)

    if result is None:
        print("ERROR: Failed to find needed data structures through pahole!")
        sys.exit(-1)

    #
    # We need an empty _Atomic definition to avoid compiler complaints.
    #
    result = "#define _Atomic\n" + result

    #
    # Remove the uint64_t definition as it conflicts with the kernel one.
    #
    result = re.sub("^typedef.*uint64_t;$", "", result, flags=re.MULTILINE)

    return result


#
# next_power_of_two()
#
def next_power_of_two(val):
    np = 1
    while np < val:
        np *= 2
    return np


#
# dynamic_plot_init()
#
def dynamic_plot_init(real_time=True):

    if real_time:
        lines = []
        fig, axs = plt.subplots(4, figsize=(19, 10))
        fig.suptitle('Revalidator Handling')
        for ax in axs:
            ax.grid()

        axs[0].set_ylabel("Numer of flows", weight='bold')
        axs[1].set_ylabel("Time spend (ms)", weight='bold')
        axs[2].set_ylabel("Numer of flows", weight='bold')
        axs[3].set_ylabel("Time spend (ms)", weight='bold')
        axs[3].set_xlabel("Time (seconds since start)", weight='bold')

        lines.append(axs[0].plot([], [], label="n_flows", marker='o')[0])
        lines.append(axs[0].plot([], [], label="n_reval_flows")[0])
        axs[0].legend(bbox_to_anchor=(1, 1), loc='upper left',
                      borderaxespad=0.5)
        axs[0].set_xlim(0, 30)
        axs[0].set_ylim(-4, 104)

        lines.append(axs[1].plot([], [], color="orange",
                                 label="dump_duration")[0])
        axs[1].legend(bbox_to_anchor=(1, 1),
                      loc='upper left', borderaxespad=0.5)
        axs[1].set_xlim(0, 30)
        axs[1].set_ylim(-0.4, 10.4)

        lines.append(axs[2].plot([], [], label="avg_n_flows")[0])
        lines.append(axs[2].plot([], [], label="max_n_flows")[0])
        lines.append(axs[2].plot([], [], label="flow_limit")[0])
        axs[2].legend(bbox_to_anchor=(1, 1), loc='upper left',
                      borderaxespad=0.5)
        axs[2].set_xlim(0, 30)
        axs[2].set_ylim(-600, 15600)

        lines.append(axs[3].plot([], [], label="poll_wait")[0])
        lines.append(axs[3].plot([], [], label="actual_wait")[0])
        axs[3].legend(bbox_to_anchor=(1, 1), loc='upper left',
                      borderaxespad=0.5)
        axs[3].set_xlim(0, 30)
        axs[3].set_ylim(-20, 520)

        fig.tight_layout()

        plt.ion()
        plt.show()
    else:
        fig = None
        axs = None
        lines = None

    graph_data = {"base_time": 0,
                  "l_index": 0,
                  "fig": fig,
                  "axs": axs,
                  "lines": lines,
                  "last_update": 0,
                  "ukey_count": 0,
                  "time": [],
                  "n_flows": [],
                  "n_reval_flows": [],
                  "avg_n_flows": [],
                  "max_n_flows": [],
                  "flow_limit": [],
                  "dump_duration": [],
                  "poll_wait": [],
                  "actual_wait": []}

    return namedtuple("GraphData", graph_data.keys())(*graph_data.values())


#
# dynamic_plot_update()
#
def dynamic_plot_update(graph_data, refresh=1):

    if graph_data.last_update != 0 and \
       (graph_data.time[-1] - graph_data.last_update) < refresh:
        return graph_data

    graph_data = graph_data._replace(last_update=graph_data.time[-1])

    if (graph_data.time[-1] - graph_data.time[graph_data.l_index]) > 30:
        for i in range(graph_data.l_index + 1, len(graph_data.time)):
            if (graph_data.time[-1] - graph_data.time[i]) <= 30:
                graph_data = graph_data._replace(l_index=i)
                break

    for line in graph_data.lines:
        line.set_xdata(graph_data.time[graph_data.l_index:])

    graph_data.lines[0].set_ydata(graph_data.n_flows[graph_data.l_index:])
    graph_data.lines[1].set_ydata(
        graph_data.n_reval_flows[graph_data.l_index:])
    graph_data.lines[2].set_ydata(
        graph_data.dump_duration[graph_data.l_index:])
    graph_data.lines[3].set_ydata(graph_data.avg_n_flows[graph_data.l_index:])
    graph_data.lines[4].set_ydata(graph_data.max_n_flows[graph_data.l_index:])
    graph_data.lines[5].set_ydata(graph_data.flow_limit[graph_data.l_index:])
    graph_data.lines[6].set_ydata(graph_data.poll_wait[graph_data.l_index:])
    graph_data.lines[7].set_ydata(graph_data.actual_wait[graph_data.l_index:])

    for ax in graph_data.axs:
        if graph_data.l_index == 0:
            ax.autoscale(enable=True, axis='y')
        else:
            ax.autoscale(enable=True)

        ax.relim(visible_only=True)
        ax.autoscale_view(tight=True, scalex=True, scaley=True)

    try:
        graph_data.fig.canvas.draw()
        graph_data.fig.canvas.flush_events()
    except KeyboardInterrupt:
        return None

    return graph_data


#
# show_graph()
#
def show_graph(graph_data, gui=False, file_name=None):

    if len(graph_data.time) == 0 or (not gui and file_name is None):
        return

    plt.ioff()

    fig, (nf_ax, dd_ax, f_ax, t_ax) = plt.subplots(4, figsize=(19, 10))
    fig.suptitle('Revalidator Handling')
    nf_ax.grid()
    f_ax.grid()
    dd_ax.grid()
    t_ax.grid()

    nf_ax.set_ylabel("Numer of flows", weight='bold')
    f_ax.set_ylabel("Numer of flows", weight='bold')
    dd_ax.set_ylabel("Time spend (ms)", weight='bold')
    t_ax.set_ylabel("Time spend (ms)", weight='bold')
    t_ax.set_xlabel("Time (seconds since start)", weight='bold')

    nf_ax.plot(graph_data.time, graph_data.n_flows, label="n_flows")
    nf_ax.plot(graph_data.time, graph_data.n_reval_flows,
               label="n_reval_flows")
    nf_ax.legend(bbox_to_anchor=(1, 1), loc='upper left', borderaxespad=0.5)

    dd_ax.plot(graph_data.time, graph_data.dump_duration, color="orange",
               label="dump_duration")
    dd_ax.legend(bbox_to_anchor=(1, 1), loc='upper left', borderaxespad=0.5)

    f_ax.plot(graph_data.time, graph_data.avg_n_flows, label="avg_n_flows")
    f_ax.plot(graph_data.time, graph_data.max_n_flows, label="max_n_flows")
    f_ax.plot(graph_data.time, graph_data.flow_limit, label="flow_limit")
    f_ax.legend(bbox_to_anchor=(1, 1), loc='upper left', borderaxespad=0.5)

    t_ax.plot(graph_data.time, graph_data.poll_wait, label="poll_wait")
    t_ax.plot(graph_data.time, graph_data.actual_wait, label="actual_wait")
    t_ax.legend(bbox_to_anchor=(1, 1), loc='upper left', borderaxespad=0.5)

    fig.tight_layout()

    if file_name is not None and file_name != "":
        fig.savefig(file_name + '.png')

    if gui:
        try:
            plt.show()
        except KeyboardInterrupt:
            pass

    plt.close(fig)


#
# process_events_from_file()
#
def process_events_from_file(file_name):
    try:
        with open(file_name, 'r') as fd:
            print("- Reading events from \"{}\"...".format(file_name))

            print_csv_header()
            for entry in fd:
                entry.rstrip()
                if entry.startswith('event = {'):
                    event = ast.literal_eval(entry[8:])
                    event = namedtuple("EventObject",
                                       event.keys())(*event.values())
                    try:
                        _process_event(event)
                    except KeyboardInterrupt:
                        break

    except (FileNotFoundError, PermissionError):
        print("ERROR: Can't open file \"{}\" for reading!".format(file_name))
        sys.exit(-1)

    show_graph(graph, gui=not options.no_gui, file_name=options.write_charts)


#
# main()
#
def main():
    #
    # Don't like these globals, but ctx passing does not seem to work with the
    # existing open_ring_buffer() API :(
    #
    global b
    global export_file
    global options
    global state
    global graph

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--compress-output", action="store_true",
                        help="Compress output, i.e. only dump changes in "
                        "the dataset")
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs='?')
    parser.add_argument("-g", "--no-gui", action="store_true",
                        help="Do not use the gui to display plots")
    parser.add_argument("--no-ukey-count", action="store_true",
                        help="No revalidate_ukey() counting")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitch's PID",
                        type=int, default=None)
    parser.add_argument("-P", "--pahole", metavar="PAHOLE",
                        help="Pahole executable to use, default pahole",
                        type=str, default="pahole")
    parser.add_argument("-r", "--read-events",
                        help="Read events from <FILE> instead of installing "
                        "tracepoints", type=str, default=None, metavar="FILE")
    parser.add_argument("-R", "--no-realtime-plots", action="store_true",
                        help="Do not show realtime plot while tracing")
    parser.add_argument("-u", "--update-interval",
                        help="Seconds to wait between real time update, "
                        "default 1", type=float, default=1, metavar="SECONDS")
    parser.add_argument("-w", "--write-events",
                        help="Write events to <FILE>",
                        type=str, default=None, metavar="FILE")
    parser.add_argument("-W", "--write-charts",
                        help="Write overall charts to <FILE>.png",
                        type=str, default=None, metavar="FILE")

    options = parser.parse_args()

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

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Define the state and graph.
    #
    state = {"last_start": None,
             "last_done": None,
             "running": False,
             "last_csv": None,
             "last_not_printed_csv": None}

    export_file = None

    graph = dynamic_plot_init(real_time=(not options.no_gui
                                         and not options.no_realtime_plots))

    #
    # Process events from file if required.
    #
    if options.read_events is not None:
        process_events_from_file(options.read_events)
        sys.exit(0)

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

    #
    # Attach the usdt probe.
    #
    u = USDT(pid=int(options.pid))
    try:
        u.enable_probe(probe="start_dump", fn_name="probe__start_dump")
        u.enable_probe(probe="sweep_done", fn_name="probe__sweep_done")
        if not options.no_ukey_count:
            u.enable_probe(probe="revalidate_ukey__:entry",
                           fn_name="probe__reval_entry")
    except USDTException as e:
        print("ERROR: {}".format(
            (re.sub('^', ' ' * 7, str(e), flags=re.MULTILINE)).strip().
            replace("--with-dtrace or --enable-dtrace",
                    "--enable-usdt-probes")))
        sys.exit(-1)

    #
    # Attach probe to running process.
    #
    source = EBPF_SOURCE.replace("<EVENT_ENUM>", "\n".join(
        ["    EVENT_{} = {},".format(
            event.name, event.value) for event in Event]))
    source = source.replace("<BUFFER_PAGE_CNT>",
                            str(options.buffer_page_count))
    source = source.replace("<OVS_INCLUDE_DEFINITIONS>",
                            get_ovs_definitions("udpif", pid=options.pid,
                                                pahole=options.pahole))

    b = BPF(text=source, usdt_contexts=[u], debug=options.debug)

    #
    # Print header.
    #
    ltz = datetime.datetime.now()
    utc = ltz.astimezone(pytz.utc)
    time_string = "# Starting trace @{} ({} UTC)".format(
        ltz.isoformat(), utc.strftime("%H:%M:%S"))

    if export_file is not None:
        export_file.write(time_string + "\n")

    print(time_string)
    print_csv_header()

    #
    # Process all events.
    b['events'].open_ring_buffer(process_event)
    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            break

    dropcnt = b.get_table("dropcnt")
    for k in dropcnt.keys():
        count = dropcnt.sum(k).value
        if k.value == 0 and count > 0:
            print("\n# WARNING: Not all upcalls were captured, {} were "
                  "dropped!\n#          Increase the BPF ring buffer size "
                  "with the --buffer-page-count option.".format(count))

    #
    # Display footer.
    #
    if state["last_not_printed_csv"] is not None:
        print(state["last_not_printed_csv"])

    ltz = datetime.datetime.now()
    utc = ltz.astimezone(pytz.utc)
    time_string = "# Stopping trace @{} ({} UTC)".format(
        ltz.isoformat(), utc.strftime("%H:%M:%S"))

    if export_file is not None:
        export_file.write(time_string + "\n")

    print(time_string)

    #
    # Close event file is used.
    #
    if options.write_events is not None:
        export_file.close()

    #
    # Do final graph if requested.
    #
    show_graph(graph, gui=not options.no_gui, file_name=options.write_charts)


#
# Start main() as the default entry point...
#
if __name__ == '__main__':
    main()
