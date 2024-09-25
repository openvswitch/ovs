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

from rich.style import Style
from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from ovs.compat.sortedcontainers import SortedList
from ovs.flowviz.console import (
    ConsoleFormatter,
    ConsoleBuffer,
    hash_pallete,
    heat_pallete,
    file_header,
)
from ovs.flowviz.process import (
    FileProcessor,
)


class TreeFlow(object):
    """A flow within a Tree."""

    def __init__(self, flow, filter=None):
        self._flow = flow
        self._visible = True
        if filter:
            self._matches = filter.evaluate(flow)
        else:
            self._matches = True

    @property
    def flow(self):
        return self._flow

    @property
    def visible(self):
        return self._visible

    @visible.setter
    def visible(self, new_visible):
        self._visible = new_visible

    @property
    def matches(self):
        return self._matches


class FlowBlock(object):
    """A block of flows in a Tree. Flows are arranged together in a block
    if they have the same action.
    """

    def __init__(self, tflow):
        """Create a FlowBlock based on a flow.
        Args:
            flow: TreeFlow
        """
        self._flows = SortedList([], self.__key)
        self._next_recirc_nodes = SortedList([], key=lambda x: -x.pkts)
        self._actions = tflow.flow.actions_kv
        self._sum_pkts = tflow.flow.info.get("packets") or 0
        self._visible = False

        self._flows.add(tflow)

        self._equal_match = [
            (i, kv)
            for i, kv in enumerate(tflow.flow.match_kv)
            if kv.key not in ["in_port", "recirc_id"]
        ]

        in_port = tflow.flow.match.get("in_port")
        self._next_recirc_inport = [
            (recirc, in_port) for recirc in self._get_next_recirc(tflow.flow)
        ]

    @property
    def flows(self):
        return self._flows

    @property
    def pkts(self):
        return self._sum_pkts

    @property
    def visible(self):
        return self._visible

    @property
    def equal_match(self):
        return self._equal_match

    @property
    def next_recirc_nodes(self):
        return self._next_recirc_nodes

    def add_if_belongs(self, tflow):
        """Add TreeFlow to block if it belongs here."""
        if not self._belongs(tflow):
            return False

        to_del = []
        for i, (orig_i, kv) in enumerate(self.equal_match):
            if orig_i >= len(tflow.flow.match_kv):
                kv_i = None
            else:
                kv_i = tflow.flow.match_kv[orig_i]

            if kv_i != kv:
                to_del.append(i)

        for i in sorted(to_del, reverse=True):
            del self.equal_match[i]

        self._sum_pkts += tflow.flow.info.get("packets") or 0
        self._flows.add(tflow)
        return True

    def build(self, recirc_nodes):
        """Populates next_recirc_nodes given a dictionary of RecircNode objects
        indexed by recirc_id and in_port.
        """
        for recirc, in_port in self._next_recirc_inport:
            try:
                self._next_recirc_nodes.add(recirc_nodes[recirc][in_port])
            except KeyError:
                print(
                    f"mising [recirc_id {hex(recirc)} inport {in_port}]. "
                    "Flow tree will be incomplete.",
                    file=sys.stderr,
                )

    def compute_visible(self):
        """Determines if the block should be visible.
        A FlowBlock is visible if any of its flows is.

        If any of the nested RecircNodes is visible, all flows should be
        visible. If not, only the ones that match should.
        """
        nested_recirc_visible = False

        for recirc in self._next_recirc_nodes:
            recirc.compute_visible()
            if recirc.visible:
                nested_recirc_visible = True

        for tflow in self._flows:
            tflow.visible = True if nested_recirc_visible else tflow.matches
            if tflow.visible:
                self._visible = True

    def _belongs(self, tflow):
        if len(tflow.flow.actions_kv) != len(self._actions):
            return False
        return all(
            [a == b for a, b in zip(tflow.flow.actions_kv, self._actions)]
        )

    def __key(self, f):
        return -(f.flow.info.get("packets") or 0)

    def _get_next_recirc(self, flow):
        """Get the next recirc_ids from a Flow.

        The recirc_id is obtained from actions such as recirc, but also
        complex actions such as check_pkt_len and sample
        Args:
            flow (ODPFlow): flow to get the recirc_id from.
        Returns:
            set of next recirculation ids.
        """

        # Helper function to find a recirc in a dictionary of actions.
        def find_in_list(actions_list):
            recircs = []
            for item in actions_list:
                (action, value) = next(iter(item.items()))
                if action == "recirc":
                    recircs.append(value)
                elif action == "check_pkt_len":
                    recircs.extend(find_in_list(value.get("gt")))
                    recircs.extend(find_in_list(value.get("le")))
                elif action == "clone":
                    recircs.extend(find_in_list(value))
                elif action == "sample":
                    recircs.extend(find_in_list(value.get("actions")))
            return recircs

        recircs = []
        recircs.extend(find_in_list(flow.actions))

        return set(recircs)


class RecircNode(object):
    def __init__(self, recirc, in_port, heat_map=[]):
        self._recirc = recirc
        self._in_port = in_port
        self._visible = False
        self._sum_pkts = 0
        self._heat_map_fields = heat_map
        self._min = dict.fromkeys(self._heat_map_fields, -1)
        self._max = dict.fromkeys(self._heat_map_fields, 0)

        self._blocks = []
        self._sorted_blocks = SortedList([], key=lambda x: -x.pkts)

    @property
    def recirc(self):
        return self._recirc

    @property
    def in_port(self):
        return self._in_port

    @property
    def visible(self):
        return self._visible

    @property
    def pkts(self):
        """Returns the blocks sorted by pkts.
        Should not be called before running build()."""
        return self._sum_pkts

    @property
    def min(self):
        return self._min

    @property
    def max(self):
        return self._max

    def visible_blocks(self):
        """Returns visible blocks sorted by pkts.
        Should not be called before running build()."""
        return filter(lambda x: x.visible, self._sorted_blocks)

    def add_flow(self, tflow):
        assert tflow.flow.match.get("recirc_id") == self.recirc
        assert tflow.flow.match.get("in_port") == self.in_port

        self._sum_pkts += tflow.flow.info.get("packets") or 0

        # Accumulate minimum and maximum values for later use in heat-map.
        for field in self._heat_map_fields:
            val = tflow.flow.info.get(field)
            if self._min[field] == -1 or val < self._min[field]:
                self._min[field] = val
            if val > self._max[field]:
                self._max[field] = val

        for b in self._blocks:
            if b.add_if_belongs(tflow):
                return

        self._blocks.append(FlowBlock(tflow))

    def build(self, recirc_nodes):
        """Builds the recirculation links of nested blocks.

        Args:
            recirc_nodes: Dictionary of RecircNode objects indexed by
            recirc_id and in_port.
        """
        for block in self._blocks:
            block.build(recirc_nodes)
            self._sorted_blocks.add(block)

    def compute_visible(self):
        """Determine if the RecircNode should be visible.
        A RecircNode is visible if any of its blocks is.
        """
        for block in self._blocks:
            block.compute_visible()
            if block.visible:
                self._visible = True


class FlowTree:
    """A Flow tree is a a class that processes datapath flows into a tree based
    on recirculation ids.

    Args:
        flows (list[ODPFlow]): Optional, initial list of flows
        heat_map_fields (list[str]): Optional, info fields to calculate
        maximum and minimum values.
    """

    def __init__(self, flows=None, heat_map_fields=[]):
        self._recirc_nodes = {}
        self._all_recirc_nodes = []
        self._heat_map_fields = heat_map_fields
        if flows:
            for flow in flows:
                self.add(flow)

    @property
    def recirc_nodes(self):
        """Recirculation nodes in a double-dictionary.
        First-level key: recirc_id. Second-level key: in_port.
        """
        return self._recirc_nodes

    @property
    def all_recirc_nodes(self):
        """All Recirculation nodes in a list."""
        return self._all_recirc_nodes

    def add(self, flow, filter=None):
        """Add a flow"""
        rid = flow.match.get("recirc_id") or 0
        in_port = flow.match.get("in_port") or 0

        if not self._recirc_nodes.get(rid):
            self._recirc_nodes[rid] = {}

        if not self._recirc_nodes.get(rid).get(in_port):
            node = RecircNode(rid, in_port, heat_map=self._heat_map_fields)
            self._recirc_nodes[rid][in_port] = node
            self._all_recirc_nodes.append(node)

        self._recirc_nodes[rid][in_port].add_flow(TreeFlow(flow, filter))

    def build(self):
        """Build the flow tree."""
        for node in self._all_recirc_nodes:
            node.build(self._recirc_nodes)

        # Once recirculation links have been built. Determine what should stay
        # visible recursively starting by recirc_id = 0.
        for _, node in self._recirc_nodes.get(0).items():
            node.compute_visible()

    def min_max(self):
        """Return a dictionary, indexed by the heat_map_fields, of minimum
        and maximum values.
        """
        min_vals = {field: [] for field in self._heat_map_fields}
        max_vals = {field: [] for field in self._heat_map_fields}

        if not self._heat_map_fields:
            return None

        for node in self._all_recirc_nodes:
            if not node.visible:
                continue
            for field in self._heat_map_fields:
                min_vals[field].append(node.min[field])
                max_vals[field].append(node.max[field])

        return {
            field: (
                min(min_vals[field]) if min_vals[field] else 0,
                max(max_vals[field]) if max_vals[field] else 0,
            )
            for field in self._heat_map_fields
        }


class ConsoleTreeProcessor(FileProcessor):
    def __init__(self, opts, heat_map=[]):
        super().__init__(opts, "odp")
        self.trees = {}
        self.ofconsole = ConsoleFormatter(self.opts)
        self.style = self.ofconsole.style
        self.heat_map = heat_map
        self.tree = None
        self.curr_file = ""

        if self.style:
            # Generate a color pallete for recirc ids.
            self.recirc_style_gen = hash_pallete(
                hue=[x / 50 for x in range(0, 50)],
                saturation=[0.7],
                value=[0.8],
            )

            self.style.set_default_value_style(Style(color="grey66"))
            self.style.set_key_style("output", Style(color="green"))
            self.style.set_value_style("output", Style(color="green"))
            self.style.set_value_style("recirc", self.recirc_style_gen)
            self.style.set_value_style("recirc_id", self.recirc_style_gen)

    def start_file(self, name, filename):
        self.tree = FlowTree(heat_map_fields=self.heat_map)
        self.curr_file = name

    def start_thread(self, name):
        if not self.tree:
            self.tree = FlowTree(heat_map_fields=self.heat_map)

    def stop_thread(self, name):
        full_name = self.curr_file + f" ({name})"
        if self.tree:
            self.trees[full_name] = self.tree
            self.tree = None

    def process_flow(self, flow, name):
        self.tree.add(flow, self.opts.get("filter"))

    def process(self):
        super().process(False)

    def stop_file(self, name, filename):
        if self.tree:
            self.trees[name] = self.tree
            self.tree = None

    def print(self):
        for name, tree in self.trees.items():
            self.ofconsole.console.print("\n")
            self.ofconsole.console.print(file_header(name))

            tree.build()
            if self.style:
                min_max = tree.min_max()
                for field in self.heat_map:
                    min_val, max_val = min_max[field]
                    self.style.set_value_style(
                        field, heat_pallete(min_val, max_val)
                    )

            self.print_tree(tree)

    def print_tree(self, tree):
        root = Tree("Datapath Flows (logical)")
        # Start by shoing recirc_id = 0
        for in_port in sorted(tree.recirc_nodes[0].keys()):
            node = tree.recirc_nodes[0][in_port]
            if node.visible:
                self.print_recirc_node(root, node)

        self.ofconsole.console.print(root)

    def print_recirc_node(self, parent, node):
        if self.ofconsole.style:
            recirc_style = self.recirc_style_gen(hex(node.recirc))
        else:
            recirc_style = None

        node_text = Text(
            "[recirc_id({}) in_port({})]".format(
                hex(node.recirc), node.in_port
            ),
            style=recirc_style,
        )
        console_node = parent.add(
            Panel.fit(node_text), guide_style=recirc_style
        )

        for block in node.visible_blocks():
            self.print_block(block, console_node)

    def print_block(self, block, parent):
        # Print the flow matches and the statistics.
        flow_text = []
        omit_first = {
            "actions": "all",
        }
        omit_rest = {
            "actions": "all",
            "match": [kv.key for _, kv in block.equal_match],
        }
        for i, flow in enumerate(filter(lambda x: x.visible, block.flows)):
            omit = omit_rest if i > 0 else omit_first
            buf = ConsoleBuffer(Text())
            self.ofconsole.format_flow(buf, flow.flow, omitted=omit)
            flow_text.append(buf.text)

        # Print the action associated with the block.
        omit = {
            "match": "all",
            "info": "all",
            "ufid": "all",
            "dp_extra_info": "all",
        }
        act_buf = ConsoleBuffer(Text())
        act_buf.append_extra("actions: ", Style(bold=(self.style is not None)))

        self.ofconsole.format_flow(act_buf, block.flows[0].flow, omitted=omit)

        flows_node = parent.add(
            Panel(Group(*flow_text)), guide_style=Style(color="default")
        )
        action_node = flows_node.add(
            Panel.fit(
                act_buf.text, border_style="green" if self.style else "default"
            ),
            guide_style=Style(color="default"),
        )

        # Nested to the action, print the next recirc nodes.
        for node in block.next_recirc_nodes:
            if node.visible:
                self.print_recirc_node(action_node, node)
