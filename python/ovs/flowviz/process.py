# Copyright (c) 2023 Red Hat, Inc.
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

import sys
import json
import click

from ovs.flow.decoders import FlowEncoder
from ovs.flow.odp import ODPFlow
from ovs.flow.ofp import OFPFlow

from ovs.flowviz.console import (
    ConsoleFormatter,
    default_highlight,
    file_header,
    heat_pallete,
)
from ovs.flowviz.format import FlowStyle


class FileProcessor(object):
    """Base class for file-based Flow processing. It is able to create flows
    from strings found in a file (or stdin).

    The process of parsing the flows is extendable in many ways by deriving
    this class.

    When process() is called, the base class will:
        - call self.start_file() for each new file that get's processed
        - call self.start_thread() for each thread (Datapath flow only)
        - apply the filter defined in opts if provided (can be optionally
            disabled)
        - call self.process_flow() for after the flow has been filtered
        - call self.stop_thread() after the thread block has been processed
            (Datapath flow only)
        - call self.stop_file() after the file has been processed entirely

    In the case of stdin, the filename and file alias is 'stdin'.

    Args:
        opts (dict): Options dictionary
        flow_type (str): ["ofp", "odp"]
    """

    def __init__(self, opts, flow_type):
        self.opts = opts
        assert flow_type in ["ofp", "odp"]
        self.flow_type = flow_type
        self.current_thread = None

    # Methods that must be implemented by derived classes.
    def init(self):
        """Called before the flow processing begins."""
        pass

    def start_file(self, alias, filename):
        """Called before the processing of a file begins.
        Args:
            alias(str): The alias name of the filename
            filename(str): The filename string
        """
        pass

    def start_thread(self, thread):
        """Called before the processing of a thread block begins.
        Args:
            thread(str): The thread name ("main" or "pmd at cpu core $N")
        """
        raise NotImplementedError

    def process_flow(self, flow, name):
        """Called for built flow (after filtering).
        Args:
            flow(Flow): The OpenFlow or Datapath flow.
            name(str): The name of the file from which the flow comes
        """
        raise NotImplementedError

    def stop_thread(self, thread):
        """Called after the processing of a thread ends.
        Args:
            thread(str): The thread name ("main" or "pmd at cpu core $N")
        """
        raise NotImplementedError

    def stop_file(self, alias, filename):
        """Called after the processing of a file ends.
        Args:
            alias(str): The alias name of the filename
            filename(str): The filename string
        """
        pass

    def end(self):
        """Called after the processing ends."""
        pass

    def process_line(self, line, idx):
        if self.flow_type == "odp":
            next_thread = self.current_thread
            if line.startswith("flow-dump from the main thread"):
                next_thread = "main"
            elif line.startswith("flow-dump from pmd on cpu core"):
                next_thread = line.removeprefix("flow-dump from ").strip("\n")

            if next_thread != self.current_thread:
                if self.current_thread:
                    self.stop_thread(self.current_thread)
                self.start_thread(next_thread)
                self.current_thread = next_thread
                return None

            return ODPFlow(line, idx)

        elif self.flow_type == "ofp":
            # Skip strings commonly found in OpenFlow flow dumps.
            if " reply " in line:
                return None

            return OFPFlow(line, idx)

    def process(self, do_filter=True):
        idx = 0
        filenames = self.opts.get("filename")
        filt = self.opts.get("filter") if do_filter else None
        self.init()
        if filenames:
            for alias, filename in filenames:
                try:
                    with open(filename) as f:
                        self.start_file(alias, filename)
                        for line in f:
                            flow = self.process_line(line, idx)
                            idx += 1
                            if not flow or (filt and not filt.evaluate(flow)):
                                continue
                            self.process_flow(flow, alias)
                        if self.current_thread:
                            self.stop_thread(self.current_thread)
                        self.stop_file(alias, filename)
                except IOError as e:
                    raise click.BadParameter(
                        "Failed to read from file {} ({}): {}".format(
                            filename, e.errno, e.strerror
                        )
                    )
        else:
            data = sys.stdin.read()
            self.start_file("stdin", "stdin")
            for line in data.split("\n"):
                line = line.strip()
                if line:
                    flow = self.process_line(line, idx)
                    idx += 1
                    if (
                        not flow
                        or not getattr(flow, "_sections", None)
                        or (filt and not filt.evaluate(flow))
                    ):
                        continue
                    self.process_flow(flow, "stdin")
            if self.current_thread:
                self.stop_thread(self.current_thread)
            self.stop_file("stdin", "stdin")
        self.end()


class JSONOpenFlowProcessor(FileProcessor):
    """A FileProcessor that prints OpenFlow flows in JSON format."""

    def __init__(self, opts):
        super().__init__(opts, "ofp")
        self.flows = dict()

    def start_file(self, name, filename):
        self.flows_list = list()

    def stop_file(self, name, filename):
        self.flows[name] = self.flows_list

    def process_flow(self, flow, name):
        self.flows_list.append(flow)

    def json_string(self):
        if len(self.flows.keys()) > 1:
            return json.dumps(
                [
                    {"name": name, "flows": [flow.dict() for flow in flows]}
                    for name, flows in self.flows.items()
                ],
                indent=4,
                cls=FlowEncoder,
            )
        return json.dumps(
            [flow.dict() for flow in self.flows_list],
            indent=4,
            cls=FlowEncoder,
        )


class JSONDatapathProcessor(FileProcessor):
    """A FileProcessor that prints Datapath flows in JSON format."""

    def __init__(self, opts):
        super().__init__(opts, "odp")
        self.data = {}
        self.thread = None
        self.file = None

    def start_file(self, name, filename):
        self.per_thread_flows = None
        self.flows_list = []

    def start_thread(self, name):
        if not self.per_thread_flows:
            self.per_thread_flows = {}

    def stop_thread(self, name):
        self.per_thread_flows[name] = self.flows_list

    def stop_file(self, name, filename):
        if self.per_thread_flows:
            self.data[name] = self.per_thread_flows
        else:
            self.data[name] = self.flows_list

    def process_flow(self, flow, name):
        self.flows_list.append(flow)

    def json_string(self):
        opts = {
            "indent": 4,
            "cls": FlowEncoder,
        }

        def thread_data(data):
            if isinstance(data, dict):
                return {
                    thread: [flow.dict() for flow in flows]
                    for thread, flows in data.items()
                }
            return [flow.dict() for flow in data]

        if len(self.data.keys()) > 1:
            jsondata = {}
            for file, file_data in self.data.items():
                jsondata[file] = thread_data(file_data)
            return json.dumps(jsondata, **opts)
        else:
            return json.dumps(
                thread_data(next(iter(self.data.values()))), **opts
            )


class ConsoleProcessor(FileProcessor):
    """A generic Console Processor that prints flows into the console"""

    def __init__(self, opts, flow_type, heat_map=[]):
        super().__init__(opts, flow_type)
        self.heat_map = heat_map
        self.console = ConsoleFormatter(opts)
        if not self.console.style and self.opts.get("highlight"):
            # Add some style to highlights or else they won't be seen.
            self.console.style = FlowStyle()
            self.console.style.set_default_value_style(
                default_highlight(), True
            )
            self.console.style.set_default_key_style(default_highlight(), True)

        self.flows = dict()  # Dict of flow-lists, one per file and thread.
        self.min_max = dict()  # Used for heat-map calculation.
        self.curr_file = None
        self.flows_list = None

    def _init_list(self):
        self.flows_list = list()
        if len(self.heat_map) > 0:
            self.min = [-1] * len(self.heat_map)
            self.max = [0] * len(self.heat_map)

    def _save_list(self, name):
        if self.flows_list:
            self.flows[name] = self.flows_list
            self.flows_list = None
            if len(self.heat_map) > 0:
                self.min_max[name] = (self.min, self.max)

    def start_file(self, name, filename):
        self._init_list()
        self.curr_file = name

    def start_thread(self, name):
        if not self.flows_list:
            self._init_list()

    def stop_thread(self, name):
        full_name = self.curr_file + f" ({name})"
        self._save_list(full_name)

    def stop_file(self, name, filename):
        self._save_list(name)

    def process_flow(self, flow, name):
        # Running calculation of min and max values for all the fields that
        # take place in the heatmap.
        for i, field in enumerate(self.heat_map):
            val = flow.info.get(field)
            if self.min[i] == -1 or val < self.min[i]:
                self.min[i] = val
            if val > self.max[i]:
                self.max[i] = val

        self.flows_list.append(flow)

    def print(self):
        for name, flows in self.flows.items():
            self.console.console.print("\n")
            self.console.console.print(file_header(name))

            if len(self.heat_map) > 0 and len(self.flows) > 0:
                for i, field in enumerate(self.heat_map):
                    (min_val, max_val) = self.min_max[name][i]
                    self.console.style.set_value_style(
                        field, heat_pallete(min_val, max_val)
                    )

            for flow in flows:
                high = None
                if self.opts.get("highlight"):
                    result = self.opts.get("highlight").evaluate(flow)
                    if result:
                        high = result.kv
                self.console.print_flow(flow, high)
